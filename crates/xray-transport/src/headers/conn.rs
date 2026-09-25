//! # Header 连接包装 + 装配（4t8）
//!
//! 对应 Go `transport/internet/headers/http/http.go:159-308`：
//! - `Conn`（http.go:159-236）→ [`HeaderConn`]：异步连接包装—— 读侧首次读消费对端 header（可选校验
//!   URI），写侧首写注入己方 header， shutdown 前若响应未发且请求无效则写 400/404 错误响应。
//! - `Authenticator.Client(conn)`（http.go:284-298）→ [`HeaderConn::client`]
//! - `Authenticator.Server(conn)`（http.go:300-308）→ [`HeaderConn::server`]
//!
//! 装配（Go `tcp/dialer.go:104-115` 出站 / `tcp/hub.go:85-95,125-127` 入站）：
//! [`auth_from_json`] 从 `tcpSettings.header` JSON 构建 authenticator，
//! 出站 [`wrap_client`]（TLS 包装后）、入站 [`wrap_server`]（accept 后）。
//!
//! JSON 构建对应 Go `infra/conf/transport_internet.go:47-50`（tcpHeaderLoader：
//! `"none"` → NoOp identity，`"http"` → Authenticator）+
//! `infra/conf/transport_authenticators.go`（request/response 覆盖式合并）。
//!
//! noop 兜底：`type:"none"` / 无 `header` 字段 → 返回 `None` 不包装
//! （Go `noop.NoOpConnectionHeader.Client/Server` 直接返回原 conn，noop.go:25-31）。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    connection::Connection,
    headers::{
        authenticator::{
            HeaderAuthenticator, HeaderConfig, HeaderError, RequestConfig, ResponseConfig,
        },
        http::{
            HeaderReader, HttpAuthenticator, default_resp_400, default_resp_404, render_response,
        },
    },
};

/// Header 包装连接。对应 Go `http.Conn`（http.go:159-236）。
///
/// 泛型 `C` 通常为 `Box<dyn Connection>`；对回环测试可直接包装具体连接。
pub struct HeaderConn<C> {
    inner: C,
    /// `Some` = 首读前需消费对端 header（Go `oneTimeReader` + `HeaderReader`）。
    reader: Option<HeaderReader>,
    /// 期待的请求 URI 列表（空 = 不校验，client 模式 / server 未配置 request）。
    expected_uris: Vec<String>,
    /// header 后首段 payload 回放（Go `readBuffer`）。
    replay: Option<Vec<u8>>,
    /// 读侧错误原因（Go `errReason`，shutdown 时决定 400/404）。
    err_reason: Option<HeaderError>,
    /// 待发 header 前缀 + 已发偏移（Go `oneTimeWriter` + `HeaderWriter`）。
    prefix: Option<(Vec<u8>, usize)>,
    /// 关闭时若 header 未发则写错误响应（server=true；Go `errorWriter` 非 NoOp）。
    error_on_close: bool,
    /// 错误响应是否已开始写（防 shutdown 中途 Pending 后重置进度）。
    close_error_sent: bool,
}

impl<C> HeaderConn<C> {
    /// 客户端包装。对应 Go `Authenticator.Client`（http.go:284-298）：
    /// - `config.request` 存在 → 读侧消费对端（server 发来的 response）header，不校验；
    /// - `config.response` 存在 → 写侧首写注入 request header；
    /// - 关闭时不写错误响应（三个 error writer 均 NoOp）。
    pub fn client(inner: C, auth: &HttpAuthenticator) -> Self {
        let (has_request, has_response) = (auth.request().is_some(), auth.response().is_some());
        let header = has_response.then(|| auth.client_header()).filter(|h| !h.is_empty());
        Self {
            inner,
            reader: has_request.then(HeaderReader::new),
            expected_uris: Vec::new(),
            replay: None,
            err_reason: None,
            prefix: header.map(|h| (h, 0)),
            error_on_close: false,
            close_error_sent: false,
        }
    }

    /// 服务端包装。对应 Go `Authenticator.Server`（http.go:300-308）：
    /// - 读侧总是消费 client 的 request header；`config.request` 存在时校验 URI；
    /// - 写侧首写注入 response header；
    /// - 关闭时若响应未发：PathMismatch → 404，其余 → 400 （Go `errorMismatchWriter=resp404` /
    ///   `errorWriter=errorTooLongWriter=resp400`）。
    pub fn server(inner: C, auth: &HttpAuthenticator) -> Self {
        let header = auth.server_header();
        Self {
            inner,
            reader: Some(HeaderReader::new()),
            expected_uris: auth.expected_request_uris(),
            replay: None,
            err_reason: None,
            prefix: (!header.is_empty()).then_some((header, 0)),
            error_on_close: true,
            close_error_sent: false,
        }
    }
}

impl<C: Connection + Unpin> AsyncRead for HeaderConn<C> {
    /// 对应 Go `Conn.Read`（http.go:182-203）：one-time 读对端 header，
    /// 回放其后 payload，之后透传。
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. 回放 header 后的 payload（Go readBuffer）。
        if this.replay.is_some() {
            let data = this.replay.take().expect("checked");
            let n = buf.remaining().min(data.len());
            buf.put_slice(&data[..n]);
            if n < data.len() {
                this.replay = Some(data[n..].to_vec());
            }
            return Poll::Ready(Ok(()));
        }

        // 2. 消费对端 header（Go oneTimeReader.Read）。
        if let Some(rdr) = &mut this.reader {
            loop {
                let before = buf.filled().len();
                match Pin::new(&mut this.inner).poll_read(cx, buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if buf.filled().len() == before {
                            // EOF 前未见 header 终结符（Go: readRequest 返回 err）。
                            this.reader = None;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof before header ending",
                            )));
                        }
                        match rdr.feed(buf.filled_mut(), &this.expected_uris) {
                            Ok(Some(body)) => {
                                this.reader = None;
                                buf.clear(); // 刚读的字节已被消费进 body。
                                if body.is_empty() {
                                    // header 后无残留 payload：本次直接透传 inner。
                                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                                }
                                let n = buf.remaining().min(body.len());
                                buf.put_slice(&body[..n]);
                                if n < body.len() {
                                    this.replay = Some(body[n..].to_vec());
                                }
                                return Poll::Ready(Ok(()));
                            },
                            Ok(None) => {
                                buf.clear(); // 字节已被 reader 消费，等下一轮。
                            },
                            Err(e) => {
                                this.err_reason = Some(e.clone());
                                this.reader = None;
                                return Poll::Ready(Err(to_io_err(&e)));
                            },
                        }
                    },
                }
            }
        }

        // 3. 透传。
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<C: Connection + Unpin> AsyncWrite for HeaderConn<C> {
    /// 对应 Go `Conn.Write`（http.go:206-216）：首写先发完 header 前缀再发 payload。
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((hdr, off)) = &mut this.prefix {
            while *off < hdr.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &hdr[*off..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "header prefix write zero",
                        )));
                    },
                    Poll::Ready(Ok(n)) => *off += n,
                }
            }
            this.prefix = None;
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    /// 对应 Go `Conn.Close`（http.go:219-236）：响应未发且请求无效时
    /// 先写错误响应（404=Mismatch / 400=其余）再关闭。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.error_on_close && !this.close_error_sent && this.prefix.is_some() {
            this.close_error_sent = true;
            let resp = match &this.err_reason {
                Some(HeaderError::PathMismatch) => render_response(&default_resp_404()),
                _ => render_response(&default_resp_400()),
            };
            this.prefix = Some((resp, 0));
        }
        if let Some((hdr, off)) = &mut this.prefix {
            while *off < hdr.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &hdr[*off..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "close error-response write zero",
                        )));
                    },
                    Poll::Ready(Ok(n)) => *off += n,
                }
            }
            this.prefix = None;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<C: Connection> Connection for HeaderConn<C> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    fn close_read(&mut self) -> io::Result<()> {
        self.inner.close_read()
    }

    fn close_write(&mut self) -> io::Result<()> {
        self.inner.close_write()
    }
}

fn to_io_err(e: &HeaderError) -> io::Error {
    match e {
        HeaderError::TooLong => io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        HeaderError::PathMismatch => io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        HeaderError::Io(msg) => io::Error::new(io::ErrorKind::InvalidData, msg.clone()),
    }
}

// ===== 装配 =====

/// 出站装配：`Box<dyn Connection>` → client 包装（Go `tcp/dialer.go:114` `conn =
/// auth.Client(conn)`）。
pub fn wrap_client(conn: Box<dyn Connection>, auth: &HttpAuthenticator) -> Box<dyn Connection> {
    Box::new(HeaderConn::client(conn, auth))
}

/// 入站装配：`Box<dyn Connection>` → server 包装（Go `tcp/hub.go:126` `conn =
/// v.authConfig.Server(conn)`）。
pub fn wrap_server(conn: Box<dyn Connection>, auth: &HttpAuthenticator) -> Box<dyn Connection> {
    Box::new(HeaderConn::server(conn, auth))
}

// ===== JSON 构建 =====

/// 从 `tcpSettings.header` JSON 构建 HTTP header authenticator。
///
/// 对应 Go `tcpHeaderLoader`（transport_internet.go:47-50）：
/// - 无 `header` 字段 / `null` → `Ok(None)`（不包装，Go HeaderSettings=nil）；
/// - `type:"none"` → `Ok(None)`（NoOp identity，noop.go:25-31 直接返回原 conn）；
/// - `type:"http"` → 构建（默认 Chrome 伪装 + 覆盖式合并，transport_authenticators.go）；
/// - 其他 type / 缺 type → `Err`（Go loader `unknown type`）。
pub fn auth_from_json(
    transport_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<HttpAuthenticator>>> {
    let Some(tj) = transport_json else { return Ok(None) };
    let Some(header) = tj.get("header").filter(|v| v.is_object()) else {
        return Ok(None);
    };
    let ty = header.get("type").and_then(serde_json::Value::as_str);
    match ty {
        Some("none") => Ok(None),
        Some("http") => Ok(Some(Arc::new(HttpAuthenticator::new(build_header_config(header)?)))),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TCP header config: unknown header type {:?}", other),
        )),
    }
}

/// `header` JSON → [`HeaderConfig`]。对应 Go
/// `conf.Authenticator.Build`（transport_authenticators.go:193-208）： request/response 均以 Chrome
/// 默认起步，JSON 字段**覆盖式**合并 （Go 语义：`headers` 给了就整体替换默认 12/5
/// 个，非逐项合并）。
fn build_header_config(header: &serde_json::Value) -> io::Result<HeaderConfig> {
    let mut request = RequestConfig::chrome_default();
    if let Some(rj) = header.get("request").filter(|v| v.is_object()) {
        apply_request_overrides(&mut request, rj)?;
    }
    let mut response = ResponseConfig::chrome_default();
    if let Some(rj) = header.get("response").filter(|v| v.is_object()) {
        apply_response_overrides(&mut response, rj)?;
    }
    Ok(HeaderConfig { request: Some(request), response: Some(response) })
}

/// Go `AuthenticatorRequest.Build` 覆盖逻辑（transport_authenticators.go:90-115）。
fn apply_request_overrides(req: &mut RequestConfig, json: &serde_json::Value) -> io::Result<()> {
    if let Some(v) = json.get("version").and_then(serde_json::Value::as_str) {
        if !v.is_empty() {
            req.version = Some(v.to_string());
        }
    }
    if let Some(m) = json.get("method").and_then(serde_json::Value::as_str) {
        if !m.is_empty() {
            req.method = Some(m.to_string());
        }
    }
    if let Some(paths) = string_list(json.get("path")) {
        if !paths.is_empty() {
            req.uri = paths;
        }
    }
    apply_header_map_override(&mut req.header, json.get("headers"))?;
    Ok(())
}

/// Go `AuthenticatorResponse.Build` 覆盖逻辑（transport_authenticators.go:153-183）。
fn apply_response_overrides(resp: &mut ResponseConfig, json: &serde_json::Value) -> io::Result<()> {
    if let Some(v) = json.get("version").and_then(serde_json::Value::as_str) {
        if !v.is_empty() {
            resp.version = Some(v.to_string());
        }
    }
    // Go 157-168：status/reason 任一非空 → 两者都设（缺省补 "200"/"OK"）。
    let status = json.get("status").and_then(serde_json::Value::as_str);
    let reason = json.get("reason").and_then(serde_json::Value::as_str);
    if status.is_some_and(|s| !s.is_empty()) || reason.is_some_and(|s| !s.is_empty()) {
        resp.status = Some(status.filter(|s| !s.is_empty()).unwrap_or("200").to_string());
        resp.reason = Some(reason.filter(|s| !s.is_empty()).unwrap_or("OK").to_string());
    }
    apply_header_map_override(&mut resp.header, json.get("headers"))?;
    Ok(())
}

/// Go 102-115/170-183：`headers` map 非空 → 整体替换；key 排序；value null → 错误。
fn apply_header_map_override(
    target: &mut Vec<crate::headers::authenticator::HeaderNameValues>,
    headers: Option<&serde_json::Value>,
) -> io::Result<()> {
    let Some(hj) = headers.filter(|v| v.is_object()) else {
        return Ok(());
    };
    let map = hj.as_object().expect("checked is_object");
    if map.is_empty() {
        return Ok(());
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    let mut entries = Vec::with_capacity(keys.len());
    for k in keys {
        let values = string_list(map.get(k)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TCP header config: empty HTTP header value: {k}"),
            )
        })?;
        entries.push(crate::headers::authenticator::HeaderNameValues::new(k, values));
    }
    *target = entries;
    Ok(())
}

/// Go `StringList`：JSON 里可为单字符串或字符串数组；null/其他 → `None`（调用方报错）。
fn string_list(v: Option<&serde_json::Value>) -> Option<Vec<String>> {
    match v? {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(a) => {
            Some(a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::connection::DuplexConnection;

    /// 构造一对 (client 侧, server 侧) Connection 用于回环测试。
    fn duplex_pair() -> (DuplexConnection, DuplexConnection) {
        let (a, b) = tokio::io::duplex(4096);
        (DuplexConnection::new(a), DuplexConnection::new(b))
    }

    fn auth() -> HttpAuthenticator {
        HttpAuthenticator::new(HeaderConfig {
            request: Some(RequestConfig::chrome_default()),
            response: Some(ResponseConfig::chrome_default()),
        })
    }

    /// Go http_test.go::TestHTTPAuthenticator 的 Rust 对应：
    /// client↔server 双向包装，payload 双向透传，header 双向被吞。
    #[tokio::test]
    async fn client_server_roundtrip_strips_headers() {
        let (raw_client, raw_server) = duplex_pair();
        let mut client = HeaderConn::client(raw_client, &auth());
        let mut server = HeaderConn::server(raw_server, &auth());

        client.write_all(b"ping").await.expect("client write");
        // 流语义（Go http_test 用 io.ReadFull）：单次 read 不保证全量。
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.expect("server read（吞 request header）");
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.expect("server write（注入 response header）");
        client.read_exact(&mut buf).await.expect("client read（吞 response header）");
        assert_eq!(&buf, b"pong");
    }

    /// 服务端校验 URI：错误 path → read 报错 + shutdown 写 404
    /// （Go: ErrHeaderMisMatch → errorMismatchWriter=resp404，http.go:225-229）。
    #[tokio::test]
    async fn server_rejects_wrong_path_and_writes_404() {
        let (raw_client, raw_server) = duplex_pair();
        let mut server = HeaderConn::server(raw_server, &auth());

        // client 不包装：直接手发一个 path 不匹配的假 header。
        let mut raw_client = raw_client;
        raw_client
            .write_all(b"GET /wrong-path HTTP/1.1\r\nHost: x\r\n\r\npayload")
            .await
            .expect("raw write");

        let mut buf = [0u8; 16];
        let err = server.read(&mut buf).await.expect_err("path 不匹配应报错");
        assert!(err.to_string().contains("mismatch"), "错误应为 mismatch，实际 {err}");

        // shutdown 应写 404 再关。
        server.shutdown().await.expect("shutdown");
        let mut resp = Vec::new();
        raw_client.read_to_end(&mut resp).await.expect("read 404");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 404"), "应写 404，实际 {text:?}");
    }

    /// 请求 path 正确但 server 从未 read 就 shutdown → 写默认 400
    /// （Go: errReason 未设 → errorWriter=resp400）。
    #[tokio::test]
    async fn server_close_without_read_writes_400() {
        let (raw_client, raw_server) = duplex_pair();
        let mut server = HeaderConn::server(raw_server, &auth());
        let mut raw_client = raw_client;

        server.shutdown().await.expect("shutdown");
        let mut resp = Vec::new();
        raw_client.read_to_end(&mut resp).await.expect("read 400");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 400"), "应写 400，实际 {text:?}");
    }

    /// header 超过 8192 无终结符 → TooLong（Go ErrHeaderToLong，http.go:26,98-100）。
    #[tokio::test]
    async fn server_rejects_overlong_header() {
        let (raw_client, raw_server) = duplex_pair();
        let mut server = HeaderConn::server(raw_server, &auth());

        let junk = vec![b'a'; 9000];
        // 写端 spawn：9000 字节超过 duplex(4096) 容量，单 task 顺序执行会死锁。
        let writer = tokio::spawn(async move {
            let mut raw_client = raw_client;
            raw_client.write_all(&junk).await.expect("raw write");
        });
        let mut buf = [0u8; 16];
        let err = server.read(&mut buf).await.expect_err("超长应报错");
        writer.abort();
        assert!(err.to_string().contains("long"), "错误应为 too long，实际 {err}");
    }

    /// HeaderConfig 空（request/response 都 None）→ client 完全透传
    /// （Go http.go:285-287 入口判空直接返回原 conn 的等价行为）。
    #[tokio::test]
    async fn empty_config_client_passthrough() {
        let (raw_client, raw_server) = duplex_pair();
        let noop_auth = HttpAuthenticator::new(HeaderConfig::default());
        let mut client = HeaderConn::client(raw_client, &noop_auth);
        let mut raw_server = raw_server;

        client.write_all(b"bare").await.expect("write");
        let mut buf = [0u8; 8];
        let n = raw_server.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"bare", "无配置时字节应原样到达");
    }

    // ===== auth_from_json =====

    #[test]
    fn auth_json_none_and_missing() {
        assert!(auth_from_json(None).unwrap().is_none(), "无 transport_json");
        assert!(
            auth_from_json(Some(&serde_json::json!({"tcpSettings": {}}))).unwrap().is_none(),
            "无 header 字段"
        );
        assert!(
            auth_from_json(Some(&serde_json::json!({"header": null}))).unwrap().is_none(),
            "header null"
        );
        assert!(
            auth_from_json(Some(&serde_json::json!({"header": {"type": "none"}})))
                .unwrap()
                .is_none(),
            "type none → noop 兜底不包装"
        );
    }

    #[test]
    fn auth_json_unknown_type_errors() {
        assert!(auth_from_json(Some(&serde_json::json!({"header": {"type": "srtp"}}))).is_err());
        assert!(auth_from_json(Some(&serde_json::json!({"header": {}}))).is_err());
    }

    #[test]
    fn auth_json_http_full_override() {
        let auth = auth_from_json(Some(&serde_json::json!({
            "header": {
                "type": "http",
                "request": {
                    "version": "1.0",
                    "method": "POST",
                    "path": ["/upload", "/submit"],
                    "headers": {"X-Custom": ["a", "b"], "Accept": "*/*"}
                },
                "response": {
                    "version": "1.1",
                    "status": "204",
                    "reason": "No Content"
                }
            }
        })))
        .unwrap()
        .expect("type http → Some");

        let client = auth.client_header();
        let text = String::from_utf8_lossy(&client);
        assert!(
            text.starts_with("POST /") && text.contains(" HTTP/1.0\r\n"),
            "首行应为 POST <随机path> HTTP/1.0，实际 {text:?}"
        );
        assert!(text.contains("X-Custom: "), "自定义 header 应存在");
        assert!(text.contains("Accept: */*"), "单字符串 value 应支持");
        assert!(!text.contains("User-Agent"), "headers 覆盖应整体替换默认 12 个");

        let server = auth.server_header();
        let text = String::from_utf8_lossy(&server);
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"), "响应首行应 204，实际 {text:?}");
        assert_eq!(auth.expected_request_uris(), vec!["/upload", "/submit"]);
    }

    #[test]
    fn auth_json_default_is_chrome() {
        let auth = auth_from_json(Some(&serde_json::json!({"header": {"type": "http"}})))
            .unwrap()
            .expect("type http");
        let client = auth.client_header();
        let text = String::from_utf8_lossy(&client);
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "默认 GET / HTTP/1.1");
        assert!(text.contains("User-Agent: Mozilla/5.0"), "默认 Chrome UA");
        assert!(text.contains("Host: www."), "默认随机 Host");
    }

    #[test]
    fn auth_json_header_null_value_errors() {
        let r = auth_from_json(Some(&serde_json::json!({
            "header": {"type": "http", "request": {"headers": {"X-Bad": null}}}
        })));
        assert!(r.is_err(), "null value 应报错（Go empty HTTP header value）");
    }
}
