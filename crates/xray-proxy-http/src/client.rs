//! HTTP CONNECT 代理客户端 → DialBridge 适配器。
//!
//! HTTP CONNECT 代理：TCP connect 到上游代理 → 发 CONNECT 请求 →
//! 读 200 OK 响应 → 返回连接（代理隧道已建立，双向透传）。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, dial},
};

use crate::config::Account;
/// HTTP outbound 配置。
#[derive(Debug, Clone)]
pub struct HttpOutboundConfig {
    /// 上游 HTTP 代理服务器地址。
    pub server_address: Address,
    /// 上游 HTTP 代理服务器端口。
    pub server_port: Port,
    /// 可选认证（username + password）。
    pub auth: Option<Account>,
    /// 可选 streamSettings（TLS/WS/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
    /// 6a5v：servers`0`.headers 解析为 CONNECT 请求附加 header。
    /// 保留插入序（HashMap 默认无序——这里改 Vec 保序）。
    pub headers: Vec<(String, String)>,
}

impl HttpOutboundConfig {
    /// 构造配置（无认证，raw TCP）。
    #[must_use]
    pub fn new(server_address: Address, server_port: Port) -> Self {
        Self { server_address, server_port, auth: None, stream_settings: None, headers: Vec::new() }
    }

    /// 设置认证（builder 风格）。
    #[must_use]
    pub fn with_auth(mut self, auth: Account) -> Self {
        self.auth = Some(auth);
        self
    }

    /// 设置 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 6a5v：附加单个 header（builder 风格，重复 key 顺序追加）。
    #[must_use]
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.push((key, value));
        self
    }
}

/// 解析 HTTP outbound settings JSON → HttpOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 8080, "users": [{ "user": "u", "pass": "p"
/// }] }] }`
pub fn parse_http_config(data: &[u8]) -> Result<HttpOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers.first().ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    // users[0] 可选
    let auth =
        first.get("users").and_then(|v| v.as_array()).and_then(|arr| arr.first()).and_then(|u| {
            let user = u.get("user")?.as_str()?.to_string();
            let pass = u.get("pass")?.as_str()?.to_string();
            Some(Account::new(user, pass))
        });
    let mut config = HttpOutboundConfig::new(Address::Domain(address.to_string()), Port::new(port));
    if let Some(a) = auth {
        config = config.with_auth(a);
    }
    // 6a5v：解析 servers[0].headers（HTTP header map），追加到 CONNECT 请求。
    // 此前整段丢弃 → 伪装头/认证相关 header 静默无效。Go v26 outbound http
    // 也消费此字段（http dialer → req.Header）。
    if let Some(headers_v) = first.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in headers_v {
            if let Some(v_str) = v.as_str() {
                config = config.with_header(k.clone(), v_str.to_string());
            }
        }
    }
    Ok(config)
}
/// 构造 HTTP CONNECT 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<HttpOutboundConfig>`，每次调用：
/// 1. dial 到 HTTP 代理服务器
/// 2. 发送 CONNECT 请求（含可选 Proxy-Authorization）
/// 3. 读响应直到找到空行（`\r\n\r\n`），检查 200 OK
/// 4. 返回连接（隧道已建立，双向透传）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_http_dial_fn(config: Arc<HttpOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_host = dest.address().to_string();
        let target_port = dest.port().value();
        Box::pin(async move {
            // 拨号到上游 HTTP 代理
            use xray_common::net::{address::Address, destination::Destination, network::Network};
            let server_addr = match &config.server_address {
                Address::Domain(d) => d.clone(),
                Address::IPv4(ip) => ip.to_string(),
                Address::IPv6(ip) => ip.to_string(),
            };
            let server_dest =
                Destination::new(config.server_address.clone(), config.server_port, Network::TCP);
            let sockopt =
                config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("http dial proxy ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("http dial proxy (tcp): {e}"))?,
            };
            drop(server_addr);

            // 2. 构造 CONNECT 请求
            let host_port = format!("{target_host}:{target_port}");
            let mut request = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
            if let Some(auth) = &config.auth {
                // ponytail: base64 编码认证，用标准库（RFC 7617 Basic auth）
                let credentials = format!("{}:{}", auth.username, auth.password);

                // 简洁实现：用 base64 crate 或手工；此处借用 xray-tls 的 base64 实用函数
                let encoded = base64_encode(&credentials);
                request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
                drop(credentials);
            }
            // Go client.go:223 `utils.TryDefaultHeadersWith(header, "nav")`：
            // UA 缺省/枚举时补整套浏览器导航伪装头（不覆盖用户自定义头）；
            // Go client.go:226 补 `Proxy-Connection: Keep-Alive`（0w9l：原先
            // 两者皆缺，CONNECT 指纹与 Go 客户端可辨）。
            let mut headers = config.headers.clone();
            xray_common::browser::try_default_headers_with(&mut headers, "nav");
            for (k, v) in &headers {
                request.push_str(&format!("{k}: {v}\r\n"));
            }
            request.push_str("Proxy-Connection: Keep-Alive\r\n");
            request.push_str("\r\n");
            // 3. 发送请求
            conn.write_all(request.as_bytes())
                .await
                .map_err(|e| format!("http write CONNECT: {e}"))?;
            conn.flush().await.map_err(|e| format!("http flush CONNECT: {e}"))?;

            // 4. 读响应头（直到空行 `\r\n\r\n`）
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            let mut found_end = false;
            while !found_end && total < buf.len() {
                let n = match conn.read(&mut buf[total..]).await {
                    Ok(n) => n,
                    // z9n4：读响应头失败的可观测日志。
                    Err(e) => {
                        tracing::warn!(
                            target: "xray.http.outbound",
                            proxy = %format!("{}:{}", server_dest.address(), server_dest.port()),
                            target = %host_port,
                            error = %e,
                            "http CONNECT proxy read response header failed"
                        );
                        return Err(format!("http read response: {e}"));
                    },
                };
                if n == 0 {
                    // z9n4：代理在响应前 EOF（连接 reset / 401 challenge 等场景）。
                    tracing::warn!(
                        target: "xray.http.outbound",
                        proxy = %format!("{}:{}", server_dest.address(), server_dest.port()),
                        target = %host_port,
                        "http CONNECT proxy closed connection before response"
                    );
                    return Err("http proxy closed connection before response".to_string());
                }
                total += n;
                // 检查是否收到完整响应头（`\r\n\r\n`）
                for i in 0..total.saturating_sub(3) {
                    if buf[i] == b'\r'
                        && buf[i + 1] == b'\n'
                        && buf[i + 2] == b'\r'
                        && buf[i + 3] == b'\n'
                    {
                        found_end = true;
                        break;
                    }
                }
            }
            // 5. 解析响应行（第一行：`HTTP/1.x STATUS_CODE ...`）
            let header_end = buf[..total]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(total);
            let first_line_end =
                buf[..header_end].iter().position(|&b| b == b'\r').unwrap_or(header_end);
            let first_line = std::str::from_utf8(&buf[..first_line_end])
                .map_err(|e| format!("http response not UTF-8: {e}"))?;
            // 6a5v：状态码必须**严格等于 200**（第二字段），而非 contains("200")。
            // contains 误判形如 "HTTP/1.1 2100 OK" 或 "HTTP/1.1 2000 ..." 这种首行
            // 恰含 "200" 的非 200 响应 → 误建隧道。Go http.Header.Get("Status") 路径
            // 按 HTTP/1.x SPEC 解析三位状态码。
            let mut parts = first_line.split_ascii_whitespace();
            let _version = parts.next();
            let status = parts.next().unwrap_or("");
            if status != "200" {
                return Err(format!("http CONNECT proxy returned non-200: {first_line}"));
            }
            Ok(conn)
        })
    })
}

/// Base64 编码（RFC 4648）——不依赖 base64 crate，最小实现。
fn base64_encode(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    #[allow(clippy::manual_div_ceil)] // base64 4/3 容量公式，保持可读
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_construction() {
        let cfg =
            HttpOutboundConfig::new(Address::new_domain("proxy.example.com"), Port::new(8080));
        assert_eq!(cfg.server_port.value(), 8080);
        assert!(cfg.auth.is_none());
    }

    #[test]
    fn config_with_auth() {
        let cfg =
            HttpOutboundConfig::new(Address::new_domain("proxy.example.com"), Port::new(8080))
                .with_auth(Account::new("user", "pass"));
        assert!(cfg.auth.is_some());
        assert_eq!(cfg.auth.as_ref().map(|a| &a.username), Some(&"user".to_string()));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let cfg = Arc::new(HttpOutboundConfig::new(
            Address::new_domain("proxy.example.com"),
            Port::new(8080),
        ));
        let _dial = make_http_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(""), "");
        assert_eq!(base64_encode("f"), "Zg==");
        assert_eq!(base64_encode("fo"), "Zm8=");
        assert_eq!(base64_encode("foo"), "Zm9v");
        assert_eq!(base64_encode("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn parse_http_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "proxy.example.com",
                "port": 8080,
                "users": [{ "user": "alice", "pass": "secret" }]
            }]
        }"#;
        let config = parse_http_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 8080);
        assert!(config.auth.is_some());
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "proxy.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_http_config_no_auth() {
        let data = r#"{
            "servers": [{
                "address": "proxy.example.com",
                "port": 3128
            }]
        }"#;
        let config = parse_http_config(data.as_bytes()).unwrap();
        assert!(config.auth.is_none());
    }

    #[test]
    fn parse_http_config_missing_servers_fails() {
        let result = parse_http_config(b"{}");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_request_carries_chrome_masquerade_and_proxy_connection() {
        // 0w9l（Go client.go:223/226）：CONNECT 无 UA 时补整套 chrome 导航伪装头
        //（TryDefaultHeadersWith "nav"）+ Proxy-Connection: Keep-Alive。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let inspector = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut req: Vec<u8> = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
            String::from_utf8(req).unwrap()
        });

        let cfg = Arc::new(HttpOutboundConfig::new(
            Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(port),
        ));
        let dial_fn = make_http_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(443));
        let _conn = dial_fn(&dest).await.expect("tunnel established");
        drop(_conn);

        let request = inspector.await.unwrap();
        assert!(
            request.starts_with("CONNECT target.example.com:443 HTTP/1.1\r\n"),
            "bad request line: {request}"
        );
        assert!(request.contains("Proxy-Connection: Keep-Alive"), "{request}");
        assert!(request.contains("Sec-Fetch-Mode: navigate"), "{request}");
        assert!(request.contains("Sec-Fetch-Dest: document"), "{request}");
        assert!(request.contains("Sec-Fetch-Site: none"), "{request}");
        assert!(request.contains("Sec-Fetch-User: ?1"), "{request}");
        assert!(request.contains("Upgrade-Insecure-Requests: 1"), "{request}");
        assert!(request.contains("Priority: u=0, i"), "{request}");
        let ua_line = request
            .lines()
            .find(|l| l.starts_with("User-Agent: "))
            .expect("UA header must be present");
        assert!(ua_line.contains("Chrome/"), "UA must masquerade as Chrome: {ua_line}");
    }
}
