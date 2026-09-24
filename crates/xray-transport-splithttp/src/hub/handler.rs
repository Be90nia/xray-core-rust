//! SplitHTTP 请求处理器。
//!
//! 对应 Go `hub.go` 的 `requestHandler.ServeHTTP`。
//! 三种模式分发：packet-up (POST+seq)、stream-up (POST 无 seq)、stream-down (GET)。
//!
//! 请求体不钉死 hyper `Incoming`：h1/h2 路径用 `Incoming`（`Error = hyper::Error`），
//! H3 路径用 transport 层桥接体（`Error = io::Error`）。泛型 bound 只要求
//! `Data = Bytes` + 错误可转 `BoxError`（`collect` 等消费端需要）。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::HeaderMap;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio_util::io::ReaderStream;

use crate::config::{
    Config, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER,
    PLACEMENT_QUERY_IN_HEADER,
};
use crate::upload_queue::Packet;
use crate::xpadding::{generate_padding, is_padding_valid, PADDING_METHOD_REPEAT_X};

use super::meta::extract_meta;
use super::{HubConnHandler, ServerConn, ServerConnCloseSignal, SessionMap};

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

/// packet-up 单请求 liveness 兜底：body 收取 / queue push 卡死时超时回错误状态，
/// 避免整条 h2 连接静默挂死（r2lq）。
const PACKET_UP_TIMEOUT: Duration = Duration::from_secs(15);

/// 主请求入口。对应 Go `requestHandler.ServeHTTP`。
///
/// 提取 CORS header（对应 Go `WriteResponseHeader`，在每个响应上调用），
/// 再委托 [`dispatch_request`]，最后把 CORS header 追加到最终响应。
pub async fn handle_request<B>(
    req: Request<B>,
    peer_addr: SocketAddr,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let cors = ctx
        .config
        .write_response_header(req.method().as_str(), req.headers());
    let resp = dispatch_request(req, peer_addr, ctx).await;
    apply_cors_headers(resp, &cors)
}

/// 把 `(name, value)` header 对追加到响应（对应 Go `writer.Header().Set`）。
fn apply_cors_headers(
    mut resp: Response<BoxBody<Bytes, io::Error>>,
    headers: &[(String, String)],
) -> Response<BoxBody<Bytes, io::Error>> {
    let h = resp.headers_mut();
    for (name, value) in headers {
        if let (Ok(n), Ok(v)) = (name.parse::<http::HeaderName>(), value.parse()) {
            h.insert(n, v);
        }
    }
    resp
}

async fn dispatch_request<B>(
    req: Request<B>,
    peer_addr: SocketAddr,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // 1. Host 验证（H2：Go internet.IsValidHTTPHost internet.go:8-16——lowercase +
    //    剥端口 + 精确匹配；此前双向 contains 是子串匹配可绕过）。
    if !ctx.host.is_empty() {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !xray_common::protocol::http::is_valid_http_host(req_host, &ctx.host) {
            return status_response(StatusCode::NOT_FOUND);
        }
    }

    // 2. Path 前缀验证
    let req_path = req.uri().path();
    if !req_path.starts_with(&ctx.base_path) {
        return status_response(StatusCode::NOT_FOUND);
    }

    // 3. 校验通过：Go hub.go:110-131 在 CORS 之后、分发之前注入 X-Padding——
    //    之后所有响应（OPTIONS 200 / padding 400 / 分发结果）都带。
    let resp = dispatch_validated(req, peer_addr, ctx).await;
    apply_xpadding_to_response(resp, ctx)
}

/// 通过 host/path 校验后的分发。对应 Go `ServeHTTP` 的 OPTIONS / padding 校验 /
/// uplink-downlink 分发段。
async fn dispatch_validated<B>(
    req: Request<B>,
    peer_addr: SocketAddr,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // OPTIONS → CORS preflight（CORS header 由 handle_request 统一追加；
    // Go 在 padding 校验之前放行，padding 注入已在外层完成）。
    if req.method() == Method::OPTIONS {
        return status_response(StatusCode::OK);
    }

    // 4. 提取 session + seq
    let meta = extract_meta(&req, &ctx.config, &ctx.base_path);

    // 5. Padding 提取 + 校验（Go hub.go:141-148 + xpadding.go IsPaddingValid：
    //    缺失/空/超长一律 400，无豁免分支——H3b 修复）。
    let padding_value = extract_padding_value(&req, ctx);
    let range = ctx.config.get_normalized_x_padding_bytes();
    let method =
        if ctx.config.x_padding_obfs_mode { ctx.config.x_padding_method.as_str() } else { PADDING_METHOD_REPEAT_X };
    if !is_padding_valid(&padding_value, range.from, range.to, method) {
        return status_response(StatusCode::BAD_REQUEST);
    }
    // Go hub.go:217 `obfsPaddingAccepted := h.config.XPaddingObfsMode && paddingValue != ""`
    let obfs_padding_accepted = ctx.config.x_padding_obfs_mode && !padding_value.is_empty();
    let has_referer = req
        .headers()
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.is_empty());

    // 6. 分发
    let is_uplink = match *req.method() {
        Method::GET => !meta.seq_str.is_empty(),
        _ => true,
    };

    if is_uplink && !meta.session_id.is_empty() {
        if meta.seq_str.is_empty() {
            handle_stream_up(req, &meta.session_id, ctx, has_referer, obfs_padding_accepted)
                .await
        } else {
            handle_packet_up(req, &meta.session_id, &meta.seq_str, ctx).await
        }
    } else if req.method() == Method::GET || meta.session_id.is_empty() {
        handle_stream_down(req, peer_addr, meta.session_id.as_str(), ctx).await
    } else {
        status_response(StatusCode::METHOD_NOT_ALLOWED)
    }
}

/// 从请求提取 padding 值。对应 Go `Config.ExtractXPaddingFromRequest`
/// （xpadding.go:244-317）：
/// - obfs 模式：cookie(key) → header/queryInHeader → URL query(key)
/// - 非 obfs：Referer 非空取其 query 的 `x_padding`；否则取请求 URL query 的
///   `x_padding`（H3b：此前无 Referer / 无 padding 直接放行，与 Go 相反）。
fn extract_padding_value<B>(req: &Request<B>, ctx: &HandlerContext) -> String
where
    B: hyper::body::Body<Data = Bytes>,
{
    if !ctx.config.x_padding_obfs_mode {
        let referer = req.headers().get("Referer").and_then(|v| v.to_str().ok());
        match referer {
            Some(r) if !r.is_empty() => return extract_query_value(r, "x_padding"),
            _ => {
                let url = req.uri().to_string();
                return extract_query_value(&url, "x_padding");
            }
        }
    }
    extract_obfs_padding(req.headers(), req.uri(), ctx.config.as_ref())
}

/// 响应侧 X-Padding 注入。对应 Go `hub.go:110-131` +
/// `ApplyXPaddingToResponse`（xpadding.go:230-242）：每个通过 host/path 校验的
/// 响应都带（非 obfs 固定 `X-Padding` header placement；obfs 按配置 placement）。
fn apply_xpadding_to_response(
    mut resp: Response<BoxBody<Bytes, io::Error>>,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>> {
    let range = ctx.config.get_normalized_x_padding_bytes();
    let length = range.rand();
    let (placement, key, header) = if ctx.config.x_padding_obfs_mode {
        let placement = if ctx.config.x_padding_placement.is_empty() {
            PLACEMENT_QUERY_IN_HEADER
        } else {
            ctx.config.x_padding_placement.as_str()
        };
        let key =
            if ctx.config.x_padding_key.is_empty() { "x_padding" } else { ctx.config.x_padding_key.as_str() };
        let header = if ctx.config.x_padding_header.is_empty() {
            "Referer"
        } else {
            ctx.config.x_padding_header.as_str()
        };
        (placement, key, header)
    } else {
        // Go hub.go:124-130 非 obfs 固定 header placement + "X-Padding"。
        (PLACEMENT_HEADER, "x_padding", "X-Padding")
    };
    let method =
        if ctx.config.x_padding_obfs_mode { ctx.config.x_padding_method.as_str() } else { PADDING_METHOD_REPEAT_X };
    let padding = generate_padding(method, length);
    if length <= 0 || padding.is_empty() {
        return resp;
    }
    let h = resp.headers_mut();
    match placement {
        PLACEMENT_HEADER => {
            if let (Ok(name), Ok(val)) = (header.parse::<http::HeaderName>(), padding.parse()) {
                h.insert(name, val);
            }
        }
        // Go ApplyXPaddingToHeader queryInHeader 分支：RawURL 服务端未设置 →
        // url.Parse("") 得空 URL → u.RawQuery=key=padding → u.String() = "?key=padding"。
        PLACEMENT_QUERY_IN_HEADER => {
            let val = format!("?{key}={padding}");
            if let (Ok(name), Ok(val)) = (header.parse::<http::HeaderName>(), val.parse()) {
                h.insert(name, val);
            }
        }
        PLACEMENT_COOKIE => {
            let val = format!("{key}={padding}; Path=/");
            if let Ok(val) = val.parse() {
                h.insert(http::header::SET_COOKIE, val);
            }
        }
        // query placement：Go 响应侧 switch 无该分支（恒无操作）。
        _ => {}
    }
    resp
}

async fn handle_packet_up<B>(
    req: Request<B>,
    session_id: &str,
    seq_str: &str,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let seq: u64 = match seq_str.parse() {
        Ok(n) => n,
        Err(_) => return status_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let payload =
        match tokio::time::timeout(PACKET_UP_TIMEOUT, extract_packet_payload(req, ctx)).await {
            Ok(Ok(p)) => p,
            Ok(Err(st)) => return status_response(st),
            Err(_) => return status_response(StatusCode::REQUEST_TIMEOUT),
        };

    if payload.len() > ctx.sc_max_each_post_bytes {
        return status_response(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let session = ctx.sessions.upsert(session_id, ctx.max_buffered_posts).await;
    let push =
        tokio::time::timeout(PACKET_UP_TIMEOUT, session.upload_queue.push(Packet::new(payload, seq)))
            .await;
    if !matches!(push, Ok(Ok(()))) {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    status_response(StatusCode::OK)
}

async fn handle_stream_up<B>(
    req: Request<B>,
    session_id: &str,
    ctx: &HandlerContext,
    has_referer: bool,
    obfs_padding_accepted: bool,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
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

    // H3c：服务端 X 填充流（Go hub.go:219-232——Referer 非空或 obfs padding 被
    // 接受时，每 `scStreamUpServerSecs.rand()` 秒向下行写 `rand()` 个 'X'）。
    // 无填充条件时 tx 立即 drop → body 空流（行为同旧实现）。
    let sc_secs = ctx.config.normalized_sc_stream_up_server_secs();
    let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<Frame<Bytes>>>(4);
    if (has_referer || obfs_padding_accepted) && sc_secs.to > 0 {
        let range = ctx.config.get_normalized_x_padding_bytes();
        tokio::spawn(async move {
            loop {
                let n = range.rand().max(0) as usize;
                if tx.send(Ok(Frame::data(Bytes::from(vec![b'X'; n])))).await.is_err() {
                    break;
                }
                let secs = sc_secs.rand();
                if secs > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(secs as u64)).await;
                }
            }
        });
    }
    let fill_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(fill_stream).boxed();

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR));
    resp.headers_mut()
        .insert("X-Accel-Buffering", "no".parse().unwrap());
    resp.headers_mut()
        .insert("Cache-Control", "no-store".parse().unwrap());
    resp
}

async fn handle_stream_down<B>(
    req: Request<B>,
    peer_addr: SocketAddr,
    session_id: &str,
    ctx: &HandlerContext,
) -> Response<BoxBody<Bytes, io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
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
            sessions.remove(&sid).await; // 兜底（幂等）：forward 正常结束也清
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

    // 下行 body = ReaderStream(dl_rx) → StreamBody。
    // guard 随响应 body 存活：GET 响应终结（流结束或 hyper drop body）即触发
    // 会话删除——对齐 Go hub.go:352-353 `defer h.sessions.Delete(sessionId)`。
    // 同时触发 ServerConn 的 close signal：注入上行读 EOF，dispatcher 桥立即
    // 解体（对齐 Go hub.go:399 conn.Close()——conn 关闭即整个 splitConn 终结，
    // 上行 queue 消费链随之退出，不滞留至 ConnectionIdle 超时）。
    let (close_signal, conn_close_signal) = ServerConnCloseSignal::new();
    let guard = has_session.then(|| SessionDropGuard {
        sessions: Arc::clone(&ctx.sessions),
        sid: session_id.to_string(),
        close_signal: Some(close_signal),
    });
    let dl_stream = ReaderStream::new(GuardedReader { inner: dl_rx, _guard: guard });
    let body = StreamBody::new(dl_stream.map_ok(Frame::data)).boxed();

    // 构造 ServerConn 并交给 dispatcher
    let conn = ServerConn {
        reader: Box::new(upload_rx),
        writer: Box::new(dl_tx),
        remote_addr: peer_addr,
        local_addr: ctx.local_addr,
        close_signal: conn_close_signal,
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

/// GET 会话删除 guard：响应 body 终结（流结束 / hyper drop body，即客户端断开）
/// 时删除会话。对齐 Go hub.go:352-353 `defer h.sessions.Delete(sessionId)`——
/// 半开断连不再等 forward task 级联（最坏滞留至 dispatcher bridge 300s idle）。
/// `SessionMap` 是 tokio Mutex，Drop 内 spawn 异步删除。
struct SessionDropGuard {
    sessions: Arc<SessionMap>,
    sid: String,
    /// GET 断开时的连接终结信号（ServerConn 上行读注入 EOF）。
    close_signal: Option<ServerConnCloseSignal>,
}

impl Drop for SessionDropGuard {
    fn drop(&mut self) {
        if let Some(sig) = self.close_signal.take() {
            sig.close();
        }
        let sessions = Arc::clone(&self.sessions);
        let sid = std::mem::take(&mut self.sid);
        tokio::spawn(async move {
            sessions.remove(&sid).await;
        });
    }
}

/// 持有 [`SessionDropGuard`] 的 AsyncRead 包装：ReaderStream 消费完或被 drop 时，
/// guard 随之 drop 并触发会话删除。
struct GuardedReader<R> {
    inner: R,
    _guard: Option<SessionDropGuard>,
}

impl<R: AsyncRead + Unpin> AsyncRead for GuardedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// 提取 packet-up payload（body / header / cookie / auto placement）。
async fn extract_packet_payload<B>(
    req: Request<B>,
    ctx: &HandlerContext,
) -> Result<Vec<u8>, StatusCode>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + BodyExt + 'static,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
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

/// obfs 模式 padding 提取。对应 Go `Config.ExtractXPaddingFromRequest` obfs
/// 路径（xpadding.go:271-304）：cookie(key) → header（placement=header 取整值，
/// 否则按 queryInHeader 语义解析 header 值里的 query 参数）→ URL query(key)。
/// 键名/header 名缺省与客户端构造侧（`build_xpadding_config`）对称。
fn extract_obfs_padding(headers: &HeaderMap, uri: &http::Uri, cfg: &Config) -> String {
    let key = if cfg.x_padding_key.is_empty() { "x_padding" } else { cfg.x_padding_key.as_str() };
    let header = if cfg.x_padding_header.is_empty() { "Referer" } else { cfg.x_padding_header.as_str() };

    // 1. cookie(key)
    let cookie_val = cookie_get(headers, key);
    if !cookie_val.is_empty() {
        return cookie_val;
    }

    // 2. header / queryInHeader
    if let Some(val) = headers.get(header).and_then(|v| v.to_str().ok()) {
        if !val.is_empty() {
            if cfg.x_padding_placement == PLACEMENT_HEADER {
                return val.to_string();
            }
            // queryInHeader：header 值是 URL，padding 在其 query 参数里。
            let from_url = extract_query_value(val, key);
            if !from_url.is_empty() {
                return from_url;
            }
        }
    }

    // 3. URL query(key)
    if let Some(q) = uri.query() {
        let query_val = extract_query_value(q, key);
        if !query_val.is_empty() {
            return query_val;
        }
    }
    String::new()
}

/// 从 URL 或纯 query string 中提取指定 key 的 value。
/// 兼容两种输入：完整 URL（取 `?` 后段）与裸 query（无 `?` 时整串即 query）。
fn extract_query_value(url: &str, key: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or(url);
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

    fn obfs_cfg(placement: &str, key: &str, header: &str) -> Config {
        Config {
            x_padding_obfs_mode: true,
            x_padding_placement: placement.into(),
            x_padding_key: key.into(),
            x_padding_header: header.into(),
            ..Config::default()
        }
    }

    #[test]
    fn extract_obfs_padding_from_cookie() {
        let cfg = obfs_cfg("cookie", "XPad", "Referer");
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "sid=1; XPad=COOKIE_VAL".parse().unwrap());
        let uri = "http://h/path".parse().unwrap();
        assert_eq!(extract_obfs_padding(&headers, &uri, &cfg), "COOKIE_VAL");
    }

    #[test]
    fn extract_obfs_padding_from_header_whole_value() {
        let cfg = obfs_cfg("header", "x_padding", "X-Padding");
        let mut headers = HeaderMap::new();
        headers.insert("X-Padding", "XXXXX".parse().unwrap());
        let uri = "http://h/path".parse().unwrap();
        assert_eq!(extract_obfs_padding(&headers, &uri, &cfg), "XXXXX");
    }

    #[test]
    fn extract_obfs_padding_query_in_header() {
        // 默认 placement（空 = 非 header 分支）+ 默认 Referer：header 值是
        // URL，padding 在其 query 参数（queryInHeader 语义）。
        let cfg = obfs_cfg("", "", "");
        let mut headers = HeaderMap::new();
        headers.insert("Referer", "https://ref.example/page?x_padding=QQ".parse().unwrap());
        let uri = "http://h/path".parse().unwrap();
        assert_eq!(extract_obfs_padding(&headers, &uri, &cfg), "QQ");
    }

    #[test]
    fn extract_obfs_padding_from_uri_query() {
        let cfg = obfs_cfg("", "", "");
        let headers = HeaderMap::new();
        let uri = "http://h/path?x_padding=QQQ&other=1".parse().unwrap();
        assert_eq!(extract_obfs_padding(&headers, &uri, &cfg), "QQQ");
    }

    #[test]
    fn extract_obfs_padding_missing_returns_empty() {
        let cfg = obfs_cfg("", "", "");
        let headers = HeaderMap::new();
        let uri = "http://h/path".parse().unwrap();
        assert_eq!(extract_obfs_padding(&headers, &uri, &cfg), "");
    }

    #[test]
    fn extract_query_value_accepts_bare_query() {
        assert_eq!(extract_query_value("a=1&x_padding=X&b=2", "x_padding"), "X");
        assert_eq!(extract_query_value("https://h/p?x_padding=Y", "x_padding"), "Y");
    }

    #[test]
    fn obfs_padding_length_rejects_out_of_range() {
        // 服务端 obfs 校验语义：padding 值经 is_padding_valid 长度门。
        let cfg = obfs_cfg("", "", "");
        let range = cfg.get_normalized_x_padding_bytes();
        assert!(is_padding_valid(&"X".repeat(200), range.from, range.to, &cfg.x_padding_method));
        assert!(!is_padding_valid(&"X".repeat(10_000), range.from, range.to, &cfg.x_padding_method));
        // 空 padding（无值）→ false → 400（Go hub.go:141-148 无条件校验）。
        assert!(!is_padding_valid("", range.from, range.to, &cfg.x_padding_method));
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

    #[test]
    fn apply_cors_headers_merges_into_response() {
        let resp = status_response(StatusCode::OK);
        let cors = vec![
            ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
            ("Access-Control-Allow-Methods".to_string(), "POST".to_string()),
        ];
        let merged = apply_cors_headers(resp, &cors);
        assert_eq!(merged.status(), StatusCode::OK);
        assert_eq!(
            merged.headers().get("Access-Control-Allow-Origin").unwrap(),
            "*"
        );
        assert_eq!(
            merged.headers().get("Access-Control-Allow-Methods").unwrap(),
            "POST"
        );
    }

    #[test]
    fn apply_cors_headers_skips_invalid_header_name() {
        let resp = status_response(StatusCode::OK);
        let cors = vec![("invalid header with space".to_string(), "v".to_string())];
        let merged = apply_cors_headers(resp, &cors);
        // 无效 header name 被跳过，不影响响应
        assert_eq!(merged.status(), StatusCode::OK);
    }

    struct NoopConnHandler;
    impl HubConnHandler for NoopConnHandler {
        fn add_conn(&self, _conn: ServerConn) {}
    }

    fn make_ctx(host: &str) -> HandlerContext {
        HandlerContext {
            config: Arc::new(Config::default()),
            host: host.into(),
            base_path: String::new(),
            local_addr: "127.0.0.1:1".parse().unwrap(),
            sessions: Arc::new(SessionMap::new()),
            conn_handler: Arc::new(NoopConnHandler),
            max_buffered_posts: 16,
            sc_max_each_post_bytes: 1024 * 1024,
        }
    }

    fn plain_request(
        method: Method,
        uri: &str,
        host: &str,
        referer: Option<String>,
    ) -> Request<Full<Bytes>> {
        let mut b = Request::builder().method(method).uri(uri).header("Host", host);
        if let Some(r) = referer {
            b = b.header("Referer", r);
        }
        b.body(Full::new(Bytes::new())).unwrap()
    }

    // ===== H2：Host 校验（Go IsValidHTTPHost 精确匹配语义）=====

    /// H2 回归：双向 contains 子串匹配下 `notevil.example.com` 绕过
    /// `evil.example.com` 拦截；精确匹配后必须 404。旧实现此测试失败。
    #[tokio::test]
    async fn h2_substring_host_bypass_blocked() {
        let ctx = make_ctx("evil.example.com");
        let req = plain_request(Method::OPTIONS, "/x", "notevil.example.com", None);
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "substring host must NOT pass");
    }

    /// H2 回归：带端口/大小写 Host 过闸（Go lowercase + SplitHostPort 剥端口）。
    /// 旧实现 `c.host == req_host` 对 `Example.com:8443` 误 404。
    #[tokio::test]
    async fn h2_host_with_port_and_case_passes() {
        let ctx = make_ctx("example.com");
        let req = plain_request(Method::OPTIONS, "/x", "Example.com:8443", None);
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND, "port/case variants must pass host gate");
    }

    // ===== H3：X-Padding 三重偏离 =====

    /// H3a 回归：通过 host/path 校验的响应必带 X-Padding（Go hub.go:110-131 每
    /// 响应注入；旧实现响应永无 padding——JA4H 级指纹）。OPTIONS 200 也带。
    #[tokio::test]
    async fn h3a_response_carries_x_padding_header() {
        let ctx = make_ctx("");
        let req = plain_request(Method::OPTIONS, "/x", "h", None);
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let pad = resp.headers().get("X-Padding").expect("X-Padding must be present");
        let n = pad.to_str().unwrap().len();
        let range = ctx.config.get_normalized_x_padding_bytes();
        assert!(
            n >= range.from as usize && n <= range.to as usize,
            "padding len {n} must be within [{}, {}]", range.from, range.to
        );
    }

    /// H3b 回归：非 obfs 无 Referer 且 URL 无 x_padding → 400（Go
    /// IsPaddingValid 空值即 false；旧实现放行裸请求直达业务层）。
    #[tokio::test]
    async fn h3b_missing_padding_rejected() {
        let ctx = make_ctx("");
        // OPTIONS 在 padding 校验之前放行（Go 同），用 GET 验证 padding 门。
        let req = Request::builder().method(Method::GET).uri("/x").header("Host", "h")
            .body(Full::new(Bytes::new())).unwrap();
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "missing padding must be 400");
    }

    /// H3b 对照：Referer 携带合法长度 padding → 通过 padding 门（进到分发层，
    /// 非 400）。
    #[tokio::test]
    async fn h3b_valid_referer_padding_passes() {
        let ctx = make_ctx("");
        let referer = format!("https://ref.example/page?x_padding={}", "X".repeat(200));
        let req = plain_request(Method::GET, "/x", "h", Some(referer));
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST, "valid padding must pass gate");
    }

    /// H3b 边界：Referer 存在但无 x_padding 参数 → 空值 → 400（Go 无豁免）。
    #[tokio::test]
    async fn h3b_referer_without_padding_rejected() {
        let ctx = make_ctx("");
        let req = plain_request(Method::GET, "/x", "h", Some("https://ref.example/page".into()));
        let resp = dispatch_request(req, "127.0.0.1:2".parse().unwrap(), &ctx).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 票 ikzy：GET 响应 body drop（客户端断开 / 流结束）即删会话，
    /// 对齐 Go hub.go:352-353 defer——不等 forward task 级联。
    #[tokio::test]
    async fn get_body_drop_removes_session_immediately() {
        let ctx = HandlerContext {
            config: Arc::new(Config::default()),
            host: String::new(),
            base_path: String::new(),
            local_addr: "127.0.0.1:1".parse().unwrap(),
            sessions: Arc::new(SessionMap::new()),
            conn_handler: Arc::new(NoopConnHandler),
            max_buffered_posts: 16,
            sc_max_each_post_bytes: 1024 * 1024,
        };

        let req = Request::builder()
            .method(Method::GET)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp =
            handle_stream_down(req, "127.0.0.1:2".parse().unwrap(), "sess-ikzy", &ctx).await;
        assert!(
            ctx.sessions.get("sess-ikzy").await.is_some(),
            "GET must register session"
        );

        // 模拟 hyper 终结 GET：drop 响应（body → ReaderStream → GuardedReader → guard）
        drop(resp);
        for _ in 0..100 {
            if ctx.sessions.get("sess-ikzy").await.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            ctx.sessions.get("sess-ikzy").await.is_none(),
            "GET body drop must remove session immediately (Go hub.go:352-353 defer)"
        );
    }
}
