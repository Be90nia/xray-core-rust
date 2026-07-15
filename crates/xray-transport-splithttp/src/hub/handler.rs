//! SplitHTTP 请求处理器。
//!
//! 对应 Go `hub.go` 的 `requestHandler.ServeHTTP`。
//! 三种模式分发：packet-up (POST+seq)、stream-up (POST 无 seq)、stream-down (GET)。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::HeaderMap;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use crate::config::{Config, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER};
use crate::upload_queue::Packet;
use crate::xpadding::{is_padding_valid, PADDING_METHOD_REPEAT_X};

use super::meta::extract_meta;
use super::{HubConnHandler, ServerConn, SessionMap};

/// 处理器上下文（每个 listener 实例一份，Arc 共享给所有连接）。
pub struct HandlerContext {
    pub config: Arc<Config>,
    pub host: String,
    pub base_path: String,
    pub local_addr: SocketAddr,
    pub sessions: Arc<SessionMap>,
    pub conn_handler: Arc<dyn HubConnHandler>,
    pub max_buffered_posts: usize,
    pub sc_max_each_post_bytes: usize,
}

const DUPLEX_BUF: usize = 64 * 1024;

/// 主请求入口。对应 Go `requestHandler.ServeHTTP`。
pub async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>> {
    // 1. Host 验证
    if !ctx.host.is_empty() {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !req_host.contains(&ctx.host) && !ctx.host.contains(req_host) {
            return status_response(StatusCode::NOT_FOUND);
        }
    }

    // 2. Path 前缀验证
    let req_path = req.uri().path();
    if !req_path.starts_with(&ctx.base_path) {
        return status_response(StatusCode::NOT_FOUND);
    }

    // 3. OPTIONS → CORS preflight
    if req.method() == Method::OPTIONS {
        return cors_response(StatusCode::OK);
    }

    // 4. 提取 session + seq
    let meta = extract_meta(&req, &ctx.config, &ctx.base_path);

    // 5. Padding 校验（仅检查 Referer header 的 x_padding，非 obfs mode）
    if !validate_padding(&req, ctx) {
        return status_response(StatusCode::BAD_REQUEST);
    }

    // 6. 分发
    let is_uplink = match *req.method() {
        Method::GET => !meta.seq_str.is_empty(),
        _ => true,
    };

    if is_uplink && !meta.session_id.is_empty() {
        if meta.seq_str.is_empty() {
            handle_stream_up(req, &meta.session_id, ctx).await
        } else {
            handle_packet_up(req, &meta.session_id, &meta.seq_str, ctx).await
        }
    } else if req.method() == Method::GET || meta.session_id.is_empty() {
        handle_stream_down(req, peer_addr, meta.session_id.as_str(), ctx).await
    } else {
        status_response(StatusCode::METHOD_NOT_ALLOWED)
    }
}

/// packet-up：POST + seq → 读 payload → push 到 UploadQueue。
async fn handle_packet_up(
    req: Request<Incoming>,
    session_id: &str,
    seq_str: &str,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>> {
    let seq: u64 = match seq_str.parse() {
        Ok(n) => n,
        Err(_) => return status_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let payload = match extract_packet_payload(req, ctx).await {
        Ok(p) => p,
        Err(st) => return status_response(st),
    };

    if payload.len() > ctx.sc_max_each_post_bytes {
        return status_response(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let session = ctx.sessions.upsert(session_id, ctx.max_buffered_posts).await;
    if session
        .upload_queue
        .push(Packet::new(payload, seq))
        .await
        .is_err()
    {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    status_response(StatusCode::OK)
}

/// stream-up：POST 无 seq → 流式 body 转为有序 packet 序列。
async fn handle_stream_up(
    req: Request<Incoming>,
    session_id: &str,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>> {
    let session = ctx.sessions.upsert(session_id, ctx.max_buffered_posts).await;
    let queue = Arc::clone(&session.upload_queue);

    // 后台任务：把 request body 切片为有序 packet，push 到 UploadQueue
    tokio::spawn(async move {
        use futures_util::TryStreamExt;
        let mut stream = req.into_body().into_data_stream();
        let mut seq = 0u64;
        while let Ok(Some(chunk)) = stream.try_next().await {
            if queue.push(Packet::new(chunk.to_vec(), seq)).await.is_err() {
                break;
            }
            seq += 1;
        }
        queue.close().await;
    });

    let mut resp = status_response(StatusCode::OK);
    resp.headers_mut()
        .insert("X-Accel-Buffering", "no".parse().unwrap());
    resp.headers_mut()
        .insert("Cache-Control", "no-store".parse().unwrap());
    resp
}

/// stream-down / stream-one：GET → 创建 ServerConn 交给 dispatcher。
async fn handle_stream_down(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    session_id: &str,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>> {
    // 上行管道：reader → dispatcher
    let (upload_tx, upload_rx) = tokio::io::duplex(DUPLEX_BUF);
    // 下行管道：dispatcher → response body
    let (dl_tx, dl_rx) = tokio::io::duplex(DUPLEX_BUF);

    let has_session = !session_id.is_empty();
    if has_session {
        // stream-down: UploadQueue → upload_tx
        let session = ctx.sessions.upsert(session_id, ctx.max_buffered_posts).await;
        session.mark_fully_connected(); // 禁用 30s reap
        let queue = Arc::clone(&session.upload_queue);
        let sessions = Arc::clone(&ctx.sessions);
        let sid = session_id.to_string();
        tokio::spawn(async move {
            forward_queue_to_writer(queue, upload_tx).await;
            sessions.remove(&sid).await;
        });
    } else {
        // stream-one: request body → upload_tx
        tokio::spawn(async move {
            use futures_util::TryStreamExt;
            let mut stream = req.into_body().into_data_stream();
            let mut tx = upload_tx;
            while let Ok(Some(chunk)) = stream.try_next().await {
                if tx.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = tx.shutdown().await;
        });
    }

    // 下行 body = ReaderStream(dl_rx) → StreamBody
    let dl_stream = ReaderStream::new(dl_rx);
    let body = StreamBody::new(dl_stream.map_ok(Frame::data)).boxed();

    // 构造 ServerConn 并交给 dispatcher
    let conn = ServerConn {
        reader: Box::new(upload_rx),
        writer: Box::new(dl_tx),
        remote_addr: peer_addr,
        local_addr: ctx.local_addr,
    };
    ctx.conn_handler.add_conn(conn);

    // 返回 streaming response（连接持续到 body stream 结束）
    let mut resp = Response::builder().status(StatusCode::OK);
    let headers = resp.headers_mut().unwrap();
    headers.insert("X-Accel-Buffering", "no".parse().unwrap());
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    if !ctx.config.no_sse_header {
        headers.insert(
            "Content-Type",
            "text/event-stream".parse().unwrap(),
        );
    }
    resp.body(body).unwrap()
}

// ===== 辅助函数 =====

/// UploadQueue → AsyncWrite（duplex 管道写端）。
async fn forward_queue_to_writer(queue: Arc<crate::UploadQueue>, mut writer: tokio::io::DuplexStream) {
    let mut buf = vec![0u8; 8192];
    loop {
        match queue.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = writer.shutdown().await;
}

/// 提取 packet-up payload（body / header / cookie / auto placement）。
async fn extract_packet_payload(
    req: Request<Incoming>,
    ctx: &HandlerContext,
) -> Result<Vec<u8>, StatusCode> {
    let placement = ctx.config.normalized_uplink_data_placement();
    let key = &ctx.config.uplink_data_key;
    let (parts, body) = req.into_parts();
    let headers = &parts.headers;

    let mut payload = Vec::new();

    if placement == PLACEMENT_AUTO || placement == PLACEMENT_HEADER {
        payload.extend_from_slice(&extract_header_payload(headers, key));
    }
    if placement == PLACEMENT_AUTO || placement == PLACEMENT_COOKIE {
        payload.extend_from_slice(&extract_cookie_payload(headers, key));
    }
    if placement == PLACEMENT_AUTO || placement == PLACEMENT_BODY {
        let bytes = body
            .collect()
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .to_bytes();
        payload.extend_from_slice(&bytes);
    }

    Ok(payload)
}

/// 从 `{key}-{i}` header 序列提取并 base64 解码。
fn extract_header_payload(headers: &HeaderMap, key: &str) -> Vec<u8> {
    let mut chunks = Vec::new();
    for i in 0.. {
        let name = format!("{key}-{i}");
        if let Some(val) = headers.get(name.as_str()) {
            if let Ok(s) = val.to_str() {
                chunks.push(s.to_string());
            }
        } else {
            break;
        }
    }
    let encoded = chunks.concat();
    if encoded.is_empty() {
        Vec::new()
    } else {
        base64url_decode(&encoded).unwrap_or_default()
    }
}

/// 从 `{key}_{i}` cookie 序列提取并 base64 解码。
fn extract_cookie_payload(headers: &HeaderMap, key: &str) -> Vec<u8> {
    let mut chunks = Vec::new();
    for i in 0.. {
        let name = format!("{key}_{i}");
        let val = cookie_get(headers, &name);
        if val.is_empty() {
            break;
        }
        chunks.push(val);
    }
    let encoded = chunks.concat();
    if encoded.is_empty() {
        Vec::new()
    } else {
        base64url_decode(&encoded).unwrap_or_default()
    }
}

/// 校验 padding（简化版：检查 Referer header 的 x_padding query）。
fn validate_padding(req: &Request<Incoming>, ctx: &HandlerContext) -> bool {
    // ponytail: 非强制 padding 校验。仅在 obfs_mode=false 时检查 Referer。
    // obfs_mode=true 时校验逻辑依赖完整 xpadding 模块，留后续。
    if ctx.config.x_padding_obfs_mode {
        return true; // 留后续实现
    }
    let referer = match req.headers().get("Referer").and_then(|v| v.to_str().ok()) {
        Some(r) => r,
        None => return true, // 无 Referer 不校验
    };
    // 提取 x_padding query value
    let padding_val = extract_query_value(referer, "x_padding");
    if padding_val.is_empty() {
        return true; // 无 padding 不校验
    }
    let range = ctx.config.get_normalized_x_padding_bytes();
    is_padding_valid(
        &padding_val,
        range.from,
        range.to,
        PADDING_METHOD_REPEAT_X,
    )
}

/// 从 URL query string 中提取指定 key 的 value。
fn extract_query_value(url: &str, key: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&') {
        if let Some(eq) = pair.find('=') {
            if &pair[..eq] == key {
                return pair[eq + 1..].to_string();
            }
        }
    }
    String::new()
}

/// 从 Cookie header 中按 name 提取 value。
fn cookie_get(headers: &HeaderMap, name: &str) -> String {
    for value in headers.get_all("cookie").iter() {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some(eq) = pair.find('=') {
                    if &pair[..eq] == name {
                        return pair[eq + 1..].to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// URL-safe base64 解码（无 padding）。对应 Go `base64.RawURLEncoding.DecodeString`。
fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn char_val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let vals = [
            char_val(bytes[i]),
            char_val(bytes[i + 1]),
            char_val(bytes[i + 2]),
            char_val(bytes[i + 3]),
        ];
        if vals.iter().any(Option::is_none) {
            return Err(());
        }
        let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];
        out.push((v[0] << 2) | (v[1] >> 4));
        out.push((v[1] << 4) | (v[2] >> 2));
        out.push((v[2] << 6) | v[3]);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem >= 2 {
        let v0 = char_val(bytes[i]).ok_or(())?;
        let v1 = char_val(bytes[i + 1]).ok_or(())?;
        out.push((v0 << 2) | (v1 >> 4));
        if rem == 3 {
            let v2 = char_val(bytes[i + 2]).ok_or(())?;
            out.push((v1 << 4) | (v2 >> 2));
        }
    } else if rem == 1 {
        return Err(());
    }
    Ok(out)
}

/// 构造空 body 状态响应。
fn status_response(status: StatusCode) -> Response<BoxBody<Bytes, io::Error>> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap()
}

/// CORS 响应（OPTIONS preflight）。
fn cors_response(status: StatusCode) -> Response<BoxBody<Bytes, io::Error>> {
    Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Access-Control-Allow-Headers", "*")
        .body(empty_body())
        .unwrap()
}

fn empty_body() -> BoxBody<Bytes, io::Error> {
    Full::new(Bytes::new())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_decode_basic() {
        // "hello" → base64url = "aGVsbG8"
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
        // "world!" → "d29ybGQh"
        assert_eq!(base64url_decode("d29ybGQh").unwrap(), b"world!");
    }

    #[test]
    fn base64url_decode_empty() {
        assert_eq!(base64url_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64url_decode_url_safe_chars() {
        // "-" and "_" are valid URL-safe chars
        let data = vec![0xffu8, 0xff, 0xff];
        let encoded = "__-w"; // base64url of [0xff, 0xff, 0xff]
        // Let me compute: 0xff = 255
        // 111111 111111 111111 → but 3 bytes = 4 base64 chars
        // Actually 3 bytes → 4 chars. 0xff_0xff_0xff
        // Byte: 11111111 11111111 11111111
        // Groups: 111111 111111 111111 111111 = 63 63 63 63
        // base64url: 63 = '_', so "____"
        assert_eq!(base64url_decode("____").unwrap(), vec![0xffu8, 0xff, 0xff]);
    }

    #[test]
    fn base64url_decode_invalid_char_returns_err() {
        assert!(base64url_decode("abc!def").is_err());
    }

    #[test]
    fn base64url_decode_single_remaining_char_is_error() {
        // 1 remaining char is invalid base64
        assert!(base64url_decode("a").is_err());
    }

    #[test]
    fn extract_query_value_finds_key() {
        assert_eq!(
            extract_query_value("https://example.com/ws?x_padding=XXXX", "x_padding"),
            "XXXX"
        );
        assert_eq!(
            extract_query_value("https://example.com/ws?a=1&b=2", "b"),
            "2"
        );
    }

    #[test]
    fn extract_query_value_missing_returns_empty() {
        assert_eq!(extract_query_value("https://example.com/ws", "x_padding"), "");
        assert_eq!(
            extract_query_value("https://example.com/ws?other=1", "x_padding"),
            ""
        );
    }

    #[test]
    fn cookie_get_finds_value() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "foo=bar; token=abc; baz=qux".parse().unwrap());
        assert_eq!(cookie_get(&headers, "token"), "abc");
        assert_eq!(cookie_get(&headers, "foo"), "bar");
        assert_eq!(cookie_get(&headers, "missing"), "");
    }

    #[test]
    fn extract_header_payload_concatenates_chunks() {
        let mut headers = HeaderMap::new();
        // "hello" → base64url = "aGVsbG8"
        // Split into 2 chunks: "aGVs" and "bG8"
        headers.insert("payload-0", "aGVs".parse().unwrap());
        headers.insert("payload-1", "bG8".parse().unwrap());
        let result = extract_header_payload(&headers, "payload");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn extract_header_payload_empty_key_returns_empty() {
        let headers = HeaderMap::new();
        assert_eq!(extract_header_payload(&headers, "nonexistent"), Vec::<u8>::new());
    }
}
