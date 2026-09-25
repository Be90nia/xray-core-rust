//! HTTP proxy 服务端切片2——HTTP CONNECT 隧道 + Proxy-Authorization 认证。
//!
//! 对应 Go `proxy/http/server.go` 的 `Process` + `handleConnect` + `parseBasicAuth`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 inbound HTTP CONNECT 请求解析 + 认证 + 200 响应。
//! 普通 HTTP 代理（`handlePlainHTTP`）+ keep-alive 循环 + 100 Continue + dispatch
//! 留切片3（依赖 dispatcher + outbound manager）。

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
    task::JoinHandle,
};
use tracing::{info, warn};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};

use crate::{
    config::ServerConfig,
    error::{HttpProxyError, Result},
};

/// HTTP 握手结果——包含解析出的目标、方法、请求行 target 和 headers。
///
/// CONNECT 隧道只需 `dest` + `method`；plain HTTP 代理需要 `target` + `headers`
/// 重建转发请求（对应 Go `handlePlainHTTP`）。
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// 解析出的目标地址（CONNECT 从 authority，plain HTTP 从 Host header）。
    pub dest: Destination,
    /// HTTP 方法（大写）。
    pub method: String,
    /// 请求行 target 字段（CONNECT = `host:port`，plain HTTP = 绝对 URL 或路径）。
    pub target: String,
    /// 解析出的 headers（key 全小写）。
    pub headers: HashMap<String, String>,
}

/// Hop-by-hop headers（RFC 7230 §6.1）+ 代理专有 header——转发时移除。
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// 从请求行 target 提取 path（含 query）。
///
/// `http://example.com/path?q=1` → `/path?q=1`
/// `/path` → `/path`（透明代理）
/// `example.com:8080/path` → `/path`（无 scheme）
/// `example.com` → `/`（无 path）
pub fn extract_request_path(target: &str) -> String {
    let after_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    match after_scheme.find('/') {
        Some(slash) => after_scheme[slash..].to_string(),
        None => "/".to_string(),
    }
}

/// 构建转发给目标服务器的 HTTP 请求（request line + headers）。
///
/// 移除 hop-by-hop headers，强制 `Connection: close`。
/// 对应 Go `handlePlainHTTP` 中 `request.Header.Set("Connection", "close")` + `request.Write`。
pub fn build_forwarded_request(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");
    for (key, value) in headers {
        if HOP_BY_HOP_HEADERS.contains(&key.as_str()) {
            continue;
        }
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"connection: close\r\n\r\n");
    buf
}

/// HTTP proxy inbound 服务器。
///
/// 切片2：listen + accept + HTTP CONNECT handshake + 认证。
pub struct HttpServer {
    tag: String,
    config: ServerConfig,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消 accept().
    slot: Mutex<Option<(Arc<TcpListener>, JoinHandle<()>)>>,
}

impl HttpServer {
    /// 构造 HTTP 代理服务端。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: ServerConfig) -> Self {
        Self { tag: tag.into(), config, slot: Mutex::new(None) }
    }
}

#[async_trait]
impl InboundHandler for HttpServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| InboundError::ListenError(format!("invalid addr: {e}")))?;
        let listener = Arc::new(
            TcpListener::bind(addr)
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "HTTP proxy server started");

        let tag = self.tag.clone();
        let config = self.config.clone();
        let listener_clone = Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener_clone.accept().await {
                    Ok((mut stream, peer)) => {
                        let tag = tag.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            match http_server_handshake(&mut stream, &config).await {
                                Ok(hs) => {
                                    info!(
                                        tag = %tag,
                                        peer = %peer,
                                        method = %hs.method,
                                        dest = ?hs.dest,
                                        "HTTP proxy handshake succeeded"
                                    );
                                    // 切片3: dispatch to outbound handler
                                },
                                Err(e) => {
                                    warn!(
                                        tag = %tag,
                                        peer = %peer,
                                        error = %e,
                                        "HTTP proxy handshake failed"
                                    );
                                },
                            }
                        });
                    },
                    Err(e) => {
                        warn!(tag = %tag, error = %e, "accept failed");
                        break;
                    },
                }
            }
        });

        *self.slot.lock().await = Some((listener, handle));
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        if let Some((_listener, handle)) = self.slot.lock().await.take() {
            handle.abort();
            info!(tag = %self.tag, "HTTP proxy server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0 让调用方用 bound_port().await
        0
    }
}

/// HTTP proxy 服务端握手。解析请求行 + 认证 + 解析目标。
///
/// 返回 [`HandshakeResult`]（含 dest、method、target、headers）。
/// CONNECT → 回 `200 Connection established`；非 CONNECT → 不回响应（由调用方处理 plain HTTP
/// 转发）。
///
/// ## 流程
///
/// 1. 读 HTTP/1.1 请求行（`METHOD TARGET HTTP/1.1\r\n`）
/// 2. 读 headers 直到空行（`\r\n`）
/// 3. 如配置了 accounts：校验 `Proxy-Authorization: Basic <base64>`
/// 4. 解析 dest：CONNECT 的 target（`host:port`）或 Host header
/// 5. CONNECT → 回 `HTTP/1.1 200 Connection established\r\n\r\n`
pub async fn http_server_handshake<RW>(
    stream: &mut RW,
    config: &ServerConfig,
) -> Result<HandshakeResult>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 1. 读请求行
    let request_line = read_http_line(stream).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(HttpProxyError::InvalidRequest(format!(
            "malformed request line: {request_line:?}"
        )));
    }
    let method = parts[0].to_ascii_uppercase();
    let target = parts[1].to_string();

    // 2. 读 headers（最多 [`MAX_HTTP_HEADER_LINES`] 行，防无界头部注入；
    // Go http.ReadRequest 语义下请求行+headers 共享 1MB 总预算，此处按行数收紧）
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_lines = 0usize;
    loop {
        let line = read_http_line(stream).await?;
        if line.is_empty() {
            break;
        }
        header_lines += 1;
        if header_lines > MAX_HTTP_HEADER_LINES {
            return Err(HttpProxyError::InvalidRequest(format!(
                "too many HTTP header lines (>{MAX_HTTP_HEADER_LINES})"
            )));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // 3. 认证（如配置了 accounts）
    if !config.accounts.is_empty() {
        let auth_ok = headers
            .get("proxy-authorization")
            .and_then(|v| parse_basic_auth(v))
            .map(|(user, pass)| config.has_account(&user, &pass))
            .unwrap_or(false);
        if !auth_ok {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")
                .await?;
            return Err(HttpProxyError::AuthFailed(
                "invalid or missing Proxy-Authorization".into(),
            ));
        }
    }

    // 4. 解析 dest
    let dest = if method == "CONNECT" {
        parse_host_port(&target, 443)?
    } else {
        // 普通 HTTP 代理从 Host header 提取 dest
        let host = headers
            .get("host")
            .ok_or_else(|| HttpProxyError::InvalidRequest("missing Host header".into()))?;
        parse_host_port(host, 80)?
    };
    // 4.5 透明代理检查（对应 Go handlePlainHTTP proxy/http/server.go:209：
    // `!AllowTransparent && request.URL.Host == ""` → 400 Bad Request）。
    // target 非绝对 URI（无 scheme）等价 Go `request.URL.Host == ""`。
    if method != "CONNECT" && !config.allow_transparent && !target.contains("://") {
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\n\
                  Proxy-Connection: close\r\n\
                  Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        return Err(HttpProxyError::InvalidRequest(
            "origin-form request target requires allowTransparent".into(),
        ));
    }

    // 5. 回 200（CONNECT）
    if method == "CONNECT" {
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    }

    Ok(HandshakeResult { dest, method, target, headers })
}

/// 单行（请求行/头部行）字节上限。Go `http.ReadRequest` 对请求行+headers 共享
/// `DefaultMaxHeaderBytes`(1MB) 总预算；本实现逐字节读行，按 16KB/行收紧
/// （正常 HTTP 头远低于此），防御恶意无界行撑爆内存。
const MAX_HTTP_LINE_BYTES: usize = 16 * 1024;
/// 请求头最大行数（不含请求行）。Go 无显式行数限制（受 1MB 总预算约束）；
/// 此处 128 行等价收紧，防慢速逐行注入。
const MAX_HTTP_HEADER_LINES: usize = 128;
/// 读一行 HTTP header（到 `\r\n`，返回不含 `\r\n` 的内容）。
async fn read_http_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut prev_was_cr = false;
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await.map_err(HttpProxyError::Io)?;
        if n == 0 {
            if buf.is_empty() {
                return Err(HttpProxyError::InvalidRequest("connection closed".into()));
            }
            break;
        }
        if prev_was_cr && byte[0] == b'\n' {
            break;
        }
        prev_was_cr = byte[0] == b'\r';
        if !prev_was_cr {
            buf.push(byte[0]);
            if buf.len() > MAX_HTTP_LINE_BYTES {
                return Err(HttpProxyError::InvalidRequest(format!(
                    "http header line exceeds {MAX_HTTP_LINE_BYTES} bytes"
                )));
            }
        }
    }
    String::from_utf8(buf)
        .map_err(|e| HttpProxyError::InvalidRequest(format!("non-utf8 header: {e}")))
}

/// 解析 `host:port` 字符串为 [`Destination`]。无端口时用 `default_port`。
fn parse_host_port(host_port: &str, default_port: u16) -> Result<Destination> {
    // 处理 IPv6 [::1]:443 格式
    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let ipv6_str = &rest[..end];
            let ip: Ipv6Addr = ipv6_str
                .parse()
                .map_err(|_| HttpProxyError::InvalidRequest(format!("invalid IPv6: {ipv6_str}")))?;
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return Ok(Destination::tcp(Address::IPv6(ip), Port::new(port)));
        }
    }

    // 普通 host:port
    let (host, port) = match host_port.rfind(':') {
        Some(idx) => {
            let h = &host_port[..idx];
            let p_str = &host_port[idx + 1..];
            // p_str 可能是端口号，也可能是 IPv6 的一部分（如 ::1 无方括号）
            match p_str.parse::<u16>() {
                Ok(port) => (h, port),
                Err(_) => (host_port, default_port),
            }
        },
        None => (host_port, default_port),
    };

    let address = parse_host_to_address(host)?;
    Ok(Destination::tcp(address, Port::new(port)))
}

/// 把 host 字符串转换为 [`Address`]。按 IPv4 → IPv6 → Domain 顺序尝试。
fn parse_host_to_address(host: &str) -> Result<Address> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Address::IPv4(ip));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok(Address::IPv6(ip));
    }
    if host.is_empty() {
        return Err(HttpProxyError::InvalidRequest("empty host".into()));
    }
    Ok(Address::Domain(host.to_string()))
}

/// 解析 `Proxy-Authorization: Basic <base64>` header 值为 (username, password)。
///
/// 对应 Go `parseBasicAuth`。返回 `None` 表示格式不合法。
fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    const PREFIX: &str = "Basic ";
    let rest = header_value.strip_prefix(PREFIX)?;
    let decoded = base64_decode(rest)?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let sep = decoded_str.find(':')?;
    Some((decoded_str[..sep].to_string(), decoded_str[sep + 1..].to_string()))
}

/// 手写 base64 解码（标准编码，含 padding）。对应 Go `base64.StdEncoding.DecodeString`。
///
/// 避免 crate 级 base64 依赖（ponytail：15 行手写 < 加 Cargo.toml 依赖）。
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        let val = TABLE.iter().position(|&t| t == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    // ===== base64 / parse_host_port 纯函数测试 =====

    #[test]
    fn base64_decode_vectors() {
        assert_eq!(base64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(base64_decode("YWJjZA=="), Some(b"abcd".to_vec()));
        assert_eq!(base64_decode(""), Some(vec![]));
        assert_eq!(base64_decode("!!!"), None);
    }

    #[test]
    fn parse_basic_auth_roundtrip() {
        let (u, p) = parse_basic_auth("Basic dXNlcjpwYXNz").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
        assert!(parse_basic_auth("basic xyz").is_none());
        assert!(parse_basic_auth("Basic bm9jb2xvbg==").is_none()); // no colon
    }

    #[test]
    fn parse_host_port_variants() {
        let d = parse_host_port("example.com:443", 80).unwrap();
        assert_eq!(d.port().value(), 443);

        let d = parse_host_port("example.com", 8080).unwrap();
        assert_eq!(d.port().value(), 8080);

        let d = parse_host_port("1.2.3.4:80", 443).unwrap();
        assert!(matches!(d.address(), Address::IPv4(_)));
        assert_eq!(d.port().value(), 80);

        let d = parse_host_port("[::1]:443", 80).unwrap();
        assert!(matches!(d.address(), Address::IPv6(_)));
        assert_eq!(d.port().value(), 443);

        assert!(parse_host_port("", 80).is_err());
    }

    // ===== TCP 端到端 handshake 测试 =====

    /// 简化 helper：bind TCP listener, client 发请求字节, server 跑 handshake, 返回 (response_str,
    /// result)
    async fn tcp_handshake(
        request: &[u8],
        config: ServerConfig,
    ) -> (String, std::result::Result<HandshakeResult, HttpProxyError>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            http_server_handshake(&mut stream, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.flush().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut response = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_millis(100), client.read(&mut response))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        response.truncate(n);

        let result = server.await.unwrap();
        (String::from_utf8_lossy(&response).to_string(), result)
    }

    #[tokio::test]
    async fn handshake_connect_no_auth_200() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "CONNECT");
        assert_eq!(hs.dest.port().value(), 443);
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_valid_auth_200() {
        let req =
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("user".into(), "pass".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        result.unwrap();
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_invalid_auth_407() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic d3Jvbmc6Y3JlZHM=\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("user".into(), "pass".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        assert!(result.is_err());
        assert!(resp.contains("407"), "got: {resp}");
        assert!(resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn handshake_rejects_oversized_line() {
        // 请求行超长（> MAX_HTTP_LINE_BYTES）→ InvalidRequest。Go http.ReadRequest
        // 以 DefaultMaxHeaderBytes(1MB) 总预算拒绝超界流量，此处按 16KB/行收紧。
        let mut req = b"CONNECT ".to_vec();
        req.extend(std::iter::repeat_n(b'a', MAX_HTTP_LINE_BYTES + 1));
        req.extend_from_slice(b":443 HTTP/1.1\r\n\r\n");
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_err(), "oversized request line must be rejected");
    }

    #[tokio::test]
    async fn handshake_rejects_too_many_header_lines() {
        // 129 个 header 行（> MAX_HTTP_HEADER_LINES）→ InvalidRequest。
        // Go 无显式行数限制（1MB 总预算约束），此处按 128 行收紧。
        let mut req = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HTTP_HEADER_LINES {
            req.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_err(), "too many header lines must be rejected");
    }

    #[tokio::test]
    async fn handshake_connect_missing_auth_407() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("admin".into(), "secret".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        assert!(result.is_err());
        assert!(resp.contains("407"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_ipv4_dest() {
        let req = b"CONNECT 1.2.3.4:8080 HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert!(matches!(hs.dest.address(), Address::IPv4(_)));
        assert_eq!(hs.dest.port().value(), 8080);
    }

    #[tokio::test]
    async fn handshake_connect_ipv6_dest() {
        let req = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert!(matches!(hs.dest.address(), Address::IPv6(_)));
        assert_eq!(hs.dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_connect_default_port_443() {
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_get_extracts_host_port_80() {
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert!(matches!(hs.dest.address(), Address::Domain(_)));
        assert_eq!(hs.dest.port().value(), 80);
    }

    // ===== plain HTTP proxy 辅助函数测试 =====

    #[test]
    fn extract_request_path_absolute_url() {
        assert_eq!(extract_request_path("http://example.com/path?q=1"), "/path?q=1");
        assert_eq!(extract_request_path("https://example.com/"), "/");
        assert_eq!(extract_request_path("http://example.com:8080/deep/path"), "/deep/path");
    }

    #[test]
    fn extract_request_path_no_path() {
        assert_eq!(extract_request_path("http://example.com"), "/");
        assert_eq!(extract_request_path("example.com:8080"), "/");
    }

    #[test]
    fn extract_request_path_transparent() {
        assert_eq!(extract_request_path("/index.html"), "/index.html");
        assert_eq!(extract_request_path("/"), "/");
    }

    #[test]
    fn build_forwarded_request_strips_hop_by_hop() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), "example.com".into());
        headers.insert("proxy-connection".into(), "keep-alive".into());
        headers.insert("connection".into(), "keep-alive".into());
        headers.insert("user-agent".into(), "curl/8.0".into());
        headers.insert("proxy-authorization".into(), "Basic abc".into());

        let req = build_forwarded_request("GET", "/path", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(req_str.contains("host: example.com"));
        assert!(req_str.contains("user-agent: curl/8.0"));
        assert!(!req_str.contains("proxy-connection"));
        assert!(!req_str.contains("proxy-authorization"));
        assert!(req_str.contains("connection: close\r\n\r\n"));
    }

    #[test]
    fn build_forwarded_request_post() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), "api.example.com".into());
        headers.insert("content-length".into(), "42".into());

        let req = build_forwarded_request("POST", "/submit", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.starts_with("POST /submit HTTP/1.1\r\n"));
        assert!(req_str.contains("content-length: 42"));
    }

    #[tokio::test]
    async fn handshake_get_returns_target_and_headers() {
        let req = b"GET http://example.com/page?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.target, "http://example.com/page?q=1");
        assert_eq!(hs.headers.get("host").unwrap(), "example.com");
        assert_eq!(hs.headers.get("user-agent").unwrap(), "test");
    }

    // ===== allowTransparent（透明代理）分支 =====

    #[tokio::test]
    async fn handshake_origin_form_rejected_without_allow_transparent() {
        // origin-form（相对路径 target）在非透明模式下 400，对齐 Go
        // proxy/http/server.go:209 `!AllowTransparent && request.URL.Host == ""`。
        let req = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        assert!(result.is_err(), "origin-form should be rejected");
        assert!(resp.contains("400"), "got: {resp}");
        assert!(resp.contains("Connection: close"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_origin_form_allowed_with_transparent() {
        // allowTransparent=true 放行 origin-form，dest 从 Host header 解析。
        let req = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let cfg = ServerConfig { allow_transparent: true, ..Default::default() };
        let (_, result) = tcp_handshake(req, cfg).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.target, "/path?q=1");
        assert!(matches!(hs.dest.address(), Address::Domain(_)));
    }

    #[tokio::test]
    async fn handshake_absolute_url_unaffected_by_transparent_flag() {
        // 绝对 URI（代理正规形态）不受 allowTransparent 影响。
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        assert!(result.is_ok());
        assert!(!resp.contains("400"), "got: {resp}");
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop abort，端口释放
        let server = HttpServer::new("test-close", ServerConfig::default());
        server.start().await.unwrap();
        let port = server
            .slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        assert!(port > 0, "server should bind to a port");

        server.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await;
        if let Ok(Ok(_)) = result {
            panic!("listener should be closed after close()");
        }
    }
}
