//! HTTP proxy 服务端切片2——HTTP CONNECT 隧道 + Proxy-Authorization 认证。
//!
//! 对应 Go `proxy/http/server.go` 的 `Process` + `handleConnect` + `parseBasicAuth`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 inbound HTTP CONNECT 请求解析 + 认证 + 200 响应。
//! 普通 HTTP 代理（`handlePlainHTTP`）+ keep-alive 循环 + 100 Continue + dispatch
//! 留切片3（依赖 dispatcher + outbound manager）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::config::ServerConfig;
use crate::error::{HttpProxyError, Result};

/// HTTP proxy inbound 服务器。
///
/// 切片2：listen + accept + HTTP CONNECT handshake + 认证。
pub struct HttpServer {
    tag: String,
    config: ServerConfig,
    listener: Arc<Mutex<Option<Arc<TcpListener>>>>,
}

impl HttpServer {
    /// 构造 HTTP 代理服务端。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: ServerConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
            listener: Arc::new(Mutex::new(None)),
        }
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
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "HTTP proxy server started");
        *self.listener.lock().await = Some(Arc::new(listener));

        // spawn accept loop
        let tag = self.tag.clone();
        let config = self.config.clone();
        let listener_clone = self.listener.clone();
        tokio::spawn(async move {
            loop {
                // 修复死锁：先 clone Arc<TcpListener>，drop guard，再 accept
                let listener = {
                    let guard = listener_clone.lock().await;
                    match guard.as_ref() {
                        Some(l) => Arc::clone(l),
                        None => break,
                    }
                };
                let accept_result = listener.accept().await;

                match accept_result {
                    Ok((mut stream, peer)) => {
                        let tag = tag.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            match http_server_handshake(&mut stream, &config).await {
                                Ok((dest, method)) => {
                                    info!(
                                        tag = %tag,
                                        peer = %peer,
                                        method = %method,
                                        dest = ?dest,
                                        "HTTP proxy handshake succeeded"
                                    );
                                    // 切片3: dispatch to outbound handler
                                }
                                Err(e) => {
                                    warn!(
                                        tag = %tag,
                                        peer = %peer,
                                        error = %e,
                                        "HTTP proxy handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!(tag = %tag, error = %e, "accept failed");
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        let mut guard = self.listener.lock().await;
        if let Some(listener) = guard.take() {
            drop(listener);
            info!(tag = %self.tag, "HTTP proxy server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0 让调用方用 bound_port().await
        0
    }
}

/// HTTP proxy 服务端握手。解析 CONNECT 请求 + 认证 + 回 200/407。
///
/// 返回 `(Destination, method)`。method 是 `"CONNECT"` 或其他 HTTP method。
///
/// ## 流程
///
/// 1. 读 HTTP/1.1 请求行（`METHOD TARGET HTTP/1.1\r\n`）
/// 2. 读 headers 直到空行（`\r\n`）
/// 3. 如配置了 accounts：校验 `Proxy-Authorization: Basic <base64>`
/// 4. 解析 dest：CONNECT 的 target（`host:port`）或 Host header
/// 5. CONNECT → 回 `HTTP/1.1 200 Connection established\r\n\r\n`
///    非 CONNECT → 不回响应（切片3 处理 plain HTTP 转发）
pub async fn http_server_handshake<RW>(
    stream: &mut RW,
    config: &ServerConfig,
) -> Result<(Destination, String)>
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
    let target = parts[1];

    // 2. 读 headers
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let line = read_http_line(stream).await?;
        if line.is_empty() {
            break;
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
        parse_host_port(target, 443)?
    } else {
        // 切片3: 普通 HTTP 代理从 Host header 提取 dest
        let host = headers
            .get("host")
            .ok_or_else(|| HttpProxyError::InvalidRequest("missing Host header".into()))?;
        parse_host_port(host, 80)?
    };

    // 5. 回 200（CONNECT）
    if method == "CONNECT" {
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
    }

    Ok((dest, method))
}

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
        }
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
    Some((
        decoded_str[..sep].to_string(),
        decoded_str[sep + 1..].to_string(),
    ))
}

/// 手写 base64 解码（标准编码，含 padding）。对应 Go `base64.StdEncoding.DecodeString`。
///
/// 避免 crate 级 base64 依赖（ponytail：15 行手写 < 加 Cargo.toml 依赖）。
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    use super::*;
    use crate::config::Account;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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

    /// 简化 helper：bind TCP listener, client 发请求字节, server 跑 handshake, 返回 (response_str, result)
    async fn tcp_handshake(
        request: &[u8],
        config: ServerConfig,
    ) -> (String, std::result::Result<(Destination, String), HttpProxyError>) {
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
        let (dest, method) = result.unwrap();
        assert_eq!(method, "CONNECT");
        assert_eq!(dest.port().value(), 443);
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_valid_auth_200() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
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
        let (dest, _) = result.unwrap();
        assert!(matches!(dest.address(), Address::IPv4(_)));
        assert_eq!(dest.port().value(), 8080);
    }

    #[tokio::test]
    async fn handshake_connect_ipv6_dest() {
        let req = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let (dest, _) = result.unwrap();
        assert!(matches!(dest.address(), Address::IPv6(_)));
        assert_eq!(dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_connect_default_port_443() {
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let (dest, _) = result.unwrap();
        assert_eq!(dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_get_extracts_host_port_80() {
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let (dest, method) = result.unwrap();
        assert_eq!(method, "GET");
        assert!(matches!(dest.address(), Address::Domain(_)));
        assert_eq!(dest.port().value(), 80);
    }
}
