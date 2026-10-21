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
    /// h2 CONNECT（Go proxy/http/client.go:34-46/270-330）：true 时用 HTTP/2 发
    /// CONNECT 建隧道；false 走 HTTP/1.1 文本 CONNECT。
    pub h2: bool,
}

impl HttpOutboundConfig {
    /// 构造配置（无认证，raw TCP）。
    #[must_use]
    pub fn new(server_address: Address, server_port: Port) -> Self {
        Self {
            server_address,
            server_port,
            auth: None,
            stream_settings: None,
            headers: Vec::new(),
            h2: false,
        }
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
    // h2 CONNECT 开关（缺失=false；Go 侧按 TLS ALPN 协商分流 h1/h2，此处显式配置）。
    config.h2 = first.get("h2").and_then(|v| v.as_bool()).unwrap_or(false);
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
/// 配置 `h2=true` 时整体走 `establish_h2_tunnel`（HTTP/2 CONNECT 隧道）。
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
            if config.h2 {
                return establish_h2_tunnel(Arc::clone(&config), target_host, target_port).await;
            }
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
            // Go client.go:157-186 fillRequestHeader：config header 值先按模板
            // 渲染（{{.Source}}/{{.Target}} 子集），再补默认头——TryDefaultHeadersWith
            // 追加项不参与渲染。
            let template_source = template_source_value();
            let template_target = format!("tcp:{target_host}:{target_port}");
            let mut headers: Vec<(String, String)> = config
                .headers
                .iter()
                .map(|(k, v)| {
                    (k.clone(), render_header_value(v, &template_source, &template_target))
                })
                .collect();
            xray_common::browser::try_default_headers_with(&mut headers, "nav");
            for (k, v) in &headers {
                request.push_str(&format!("{k}: {v}\r\n"));
            }
            request.push_str("Proxy-Connection: Keep-Alive\r\n");
            request.push_str("\r\n");

            // bd cjwc G5（Go proxy/http/client.go:103-119 `retry.ExponentialBackoff(
            // 5, 100).On(setUpHTTPTunnel...)`）：重试「建隧道」的连接级失败——dial
            // 拒绝 / 写请求失败 / 响应前 EOF·reset。well-formed 非 200 响应属
            // 响应内容性失败，不重试——状态码检查留在重试环外（契约收紧：Go 对
            // 非 200 同样重试，此处按票 cjwc 契约收敛）。
            let (conn, buf, total) = xray_transport::retry::exponential_backoff(
                5,
                100,
                || async {
                    let mut conn: Box<dyn Connection> = match &config.stream_settings {
                        Some(s) => dial(&server_dest, s, &sockopt)
                            .await
                            .map_err(|e| format!("http dial proxy ({}): {e}", s.protocol))?,
                        None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                            .await
                            .map_err(|e| format!("http dial proxy (tcp): {e}"))?,
                    };
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
                    Ok((conn, buf, total))
                },
            )
            .await
            .map_err(|e| format!("http dial proxy: retries exhausted: {e}"))?;
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

/// h2 CONNECT 隧道：h2 客户端直驱 → CONNECT 请求 → SendStream/RecvStream
/// 适配成 [`Connection`]。
///
/// 对齐 Go proxy/http/client.go `connectHTTP2` + `newHTTP2Conn`/`http2Conn`：
/// `send_request(CONNECT, eos=false)` 的 SendStream = 写端，200 响应的
/// RecvStream = 读端。不走 hyper 客户端——hyper 1.x 对 CONNECT 不 poll 请求
/// body（`proto/h2/client.rs` 仅 `!f.is_connect` 才 PipeToSendStream），隧道
/// 上行无法接线；h2 crate 是 workspace 既有依赖，且与 Go `http2.ClientConn`
/// 同层（Go 同样绕过 net/http 直接 RoundTrip）。
/// 请求头同 Go h2 路径（Proxy-Authorization + config.headers + nav 伪装），
/// 不发 `Proxy-Connection`（连接性头 h2 禁传，Go 仅 connectHTTP1 设置）。
/// h2 流控窗口对齐 splithttp dialer（缺省 2MB 窗在长肥管道成吞吐钉）。
///
/// 失败语义（bd cjwc G5 同 HTTP/1.1 路径）：连接级失败（dial/handshake/
/// send_request 传输错误）走 `exponential_backoff(5, 100)`；非 200 属响应性
/// 失败，不重试。
///
/// Go 还按 destination 缓存 h2 ClientConn（cachedH2Conns）复用连接；此处每次
/// 拨号新建 h2 连接（池化留待框架层统一处理）。
async fn establish_h2_tunnel(
    config: Arc<HttpOutboundConfig>,
    target_host: String,
    target_port: u16,
) -> Result<Box<dyn Connection>, String> {
    use xray_common::net::network::Network;

    let server_dest =
        Destination::new(config.server_address.clone(), config.server_port, Network::TCP);
    let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
    let host_port = format!("{target_host}:{target_port}");

    let (send_stream, response, remote_addr, local_addr) =
        xray_transport::retry::exponential_backoff(5, 100, || async {
            let conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("http dial proxy ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("http dial proxy (tcp): {e}"))?,
            };
            let remote_addr = conn.remote_addr().ok().flatten();
            let local_addr = conn.local_addr().ok().flatten();

            let mut builder = h2::client::Builder::new();
            builder
                .initial_window_size(32 * 1024 * 1024)
                .initial_connection_window_size(32 * 1024 * 1024);
            let (mut h2, conn_driver) = builder
                .handshake::<Box<dyn Connection>, bytes::Bytes>(conn)
                .await
                .map_err(|e| format!("h2 handshake: {e}"))?;
            tokio::spawn(async move {
                if let Err(e) = conn_driver.await {
                    tracing::debug!(
                        target: "xray.http.outbound",
                        error = %e,
                        "h2 connection driver ended"
                    );
                }
            });

            let mut req_builder =
                http::Request::builder().method(http::Method::CONNECT).uri(host_port.as_str());
            let headers = req_builder
                .headers_mut()
                .ok_or_else(|| format!("h2 CONNECT invalid authority: {host_port}"))?;
            if let Some(auth) = &config.auth {
                let credentials = format!("{}:{}", auth.username, auth.password);
                let value =
                    http::HeaderValue::from_str(&format!("Basic {}", base64_encode(&credentials)))
                        .map_err(|e| format!("h2 Proxy-Authorization encode: {e}"))?;
                headers.insert(http::header::PROXY_AUTHORIZATION, value);
            }
            // Go fillRequestHeader 同 h1 路径：config header 值先渲染再补默认头。
            let template_source = template_source_value();
            let template_target = format!("tcp:{target_host}:{target_port}");
            let mut config_headers: Vec<(String, String)> = config
                .headers
                .iter()
                .map(|(k, v)| {
                    (k.clone(), render_header_value(v, &template_source, &template_target))
                })
                .collect();
            xray_common::browser::try_default_headers_with(&mut config_headers, "nav");
            for (k, v) in &config_headers {
                let name = http::HeaderName::from_bytes(k.as_bytes())
                    .map_err(|e| format!("h2 header name '{k}': {e}"))?;
                let value = http::HeaderValue::from_str(v)
                    .map_err(|e| format!("h2 header '{k}' value '{v}': {e}"))?;
                headers.insert(name, value);
            }
            let request =
                req_builder.body(()).map_err(|e| format!("h2 build CONNECT request: {e}"))?;

            // eos=false：CONNECT 双向隧道，END_STREAM 由 poll_shutdown 发出
            // （Go：req.Body = io.Pipe，Close 时 pipe 写端关闭同语义）。
            let (response, send_stream) =
                h2.send_request(request, false).map_err(|e| format!("h2 send CONNECT: {e}"))?;
            let response = response.await.map_err(|e| format!("h2 CONNECT response: {e}"))?;
            Ok::<_, String>((send_stream, response, remote_addr, local_addr))
        })
        .await
        .map_err(|e| format!("http dial proxy: retries exhausted: {e}"))?;

    if response.status() != http::StatusCode::OK {
        return Err(format!("http CONNECT proxy returned non-200: {}", response.status()));
    }

    Ok(Box::new(H2TunnelConn {
        send_stream,
        recv_stream: response.into_body(),
        read_buf: None,
        remote_addr,
        local_addr,
    }))
}

/// h2 CONNECT 隧道连接（Go proxy/http/client.go `http2Conn` 同构）：
/// 读 = RecvStream（响应方向），写 = SendStream（请求方向）。
struct H2TunnelConn {
    send_stream: h2::SendStream<bytes::Bytes>,
    recv_stream: h2::RecvStream,
    /// poll_data 返回的 chunk 超出调用方 ReadBuf 时的存量。
    read_buf: Option<bytes::Bytes>,
    remote_addr: Option<std::net::SocketAddr>,
    local_addr: Option<std::net::SocketAddr>,
}

impl tokio::io::AsyncRead for H2TunnelConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        if let Some(chunk) = this.read_buf.take() {
            if !chunk.is_empty() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                this.read_buf = if n < chunk.len() { Some(chunk.slice(n..)) } else { None };
                return std::task::Poll::Ready(Ok(()));
            }
        }
        match this.recv_stream.poll_data(cx) {
            std::task::Poll::Ready(Some(Ok(chunk))) => {
                // 立即归还接收窗：不释放则窗口耗尽服务端停发（h2 背压正确映射）。
                let _ = this.recv_stream.flow_control().release_capacity(chunk.len());
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.read_buf = Some(chunk.slice(n..));
                }
                std::task::Poll::Ready(Ok(()))
            },
            // None = 服务端 END_STREAM = 隧道读向关闭；写向独立存活（半关语义，
            // 同 Go http2Conn：resp.Body 读尽不断 pipe 写端）。
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
            },
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for H2TunnelConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        // reserve_capacity 是流式需求量；Pending 时未消费 buf 任何字节，
        // 调用方以原 buf 重试即可（tokio AsyncWrite 契约），容量到位由
        // poll_capacity 唤醒——h2 流控窗耗尽时写端自然背压。
        this.send_stream.reserve_capacity(buf.len());
        match this.send_stream.poll_capacity(cx) {
            std::task::Poll::Ready(Some(Ok(cap))) => {
                let n = cap.min(buf.len());
                let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                this.send_stream.send_data(chunk, false).map_err(std::io::Error::other)?;
                std::task::Poll::Ready(Ok(n))
            },
            // None = 流已被 reset/关闭
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2 send stream closed",
            ))),
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
            },
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // DATA 帧在 reserve/send 时已入 h2 栈，无独立 flush 语义。
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 半关：空 DATA + END_STREAM（Go http2Conn.Close 的 pipe 写端关闭同语义）。
        let this = &mut *self;
        this.send_stream.send_data(bytes::Bytes::new(), true).map_err(std::io::Error::other)?;
        std::task::Poll::Ready(Ok(()))
    }
}

impl Connection for H2TunnelConn {
    fn remote_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(self.remote_addr)
    }

    fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(self.local_addr)
    }
}

/// 渲染 header 值：支持 `{{.Source}}` / `{{ .Source }}` / `{{.Target}}` / `{{ .Target }}`。
///
/// Go `text/template` 的刻意子集（proxy/http/client.go:167-205 fillRequestHeader
/// 只传 `Source`/`Target` 两个字段）：仅替换这两个动作，其余占位符（`{{.Foo}}`、
/// 管道/函数/条件等）原样保留——Go 对未知字段 Execute 会报错断连，这里刻意更
/// 宽容：非法模板不应让带自定义头的配置整体不可用。
fn render_header_value(v: &str, source: &str, target: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        match after[..end].trim() {
            ".Source" => out.push_str(source),
            ".Target" => out.push_str(target),
            _ => out.push_str(&rest[start..start + end + 4]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// `{{.Source}}` 的渲染值，对齐 Go `Destination.String()`（`tcp:` 前缀 +
/// IPv6 方括号）。Go 的 Source 来自 inbound（client.go:177-181），dial 层拿不到
/// 端口，PM 裁决取 task-local `DIAL_SRC`（sendThrough 源 IP）且端口段固定 0；
/// 无 DIAL_SRC 时降级 Go 同款 `net.TCPDestination(net.AnyIP, 0)` = `tcp:0.0.0.0:0`。
fn template_source_value() -> String {
    use std::net::IpAddr;
    let ip = xray_transport::system_dialer::DIAL_SRC
        .try_with(|v| *v)
        .ok()
        .flatten()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let host = match ip {
        IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    };
    format!("tcp:{host}:0")
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

    #[test]
    fn h2_config_parses() {
        let data = r#"{
            "servers": [{
                "address": "proxy.example.com",
                "port": 443,
                "h2": true
            }]
        }"#;
        let config = parse_http_config(data.as_bytes()).unwrap();
        assert!(config.h2, "servers[0].h2=true must parse to h2=true");

        let missing = r#"{ "servers": [{ "address": "proxy.example.com", "port": 443 }] }"#;
        let config = parse_http_config(missing.as_bytes()).unwrap();
        assert!(!config.h2, "h2 must default to false when absent");
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

    /// h2 CONNECT 隧道往返（A-1）：本地 hyper h2 server 只接 CONNECT，200 后双向
    /// 回显；client 配 `h2=true` 应经 h2 CONNECT 建隧道并多轮往返。
    #[tokio::test]
    async fn http_outbound_h2_connect_tunnel_roundtrip() {
        use http_body_util::Empty;
        use hyper::{Request, body::Incoming, service::service_fn};
        use hyper_util::rt::{TokioExecutor, TokioIo};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                let io = TokioIo::new(sock);
                let service = service_fn(|req: Request<Incoming>| async move {
                    assert_eq!(
                        req.method(),
                        &hyper::Method::CONNECT,
                        "test h2 server only accepts CONNECT"
                    );
                    // hyper h2 服务端对成功 CONNECT 走 upgrade 通道接管流（服务
                    // 响应 body 被忽略）：隧道 IO 经 hyper::upgrade::on 取出后回环
                    // （Upgraded 是 hyper Read/Write，TokioIo 适配回 tokio traits）。
                    tokio::spawn(async move {
                        if let Ok(upgraded) = hyper::upgrade::on(req).await {
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0u8; 8192];
                            loop {
                                match io.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if io.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    },
                                }
                            }
                        }
                    });
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(hyper::StatusCode::OK)
                            .body(Empty::<bytes::Bytes>::new())
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            }
        });

        let mut cfg =
            HttpOutboundConfig::new(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(port));
        cfg.h2 = true;
        let dial_fn = make_http_dial_fn(Arc::new(cfg));
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(443));
        let mut conn = dial_fn(&dest).await.expect("h2 CONNECT tunnel must establish");

        for msg in [b"first ping over h2".as_slice(), b"2nd".as_slice()] {
            conn.write_all(msg).await.unwrap();
            conn.flush().await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            conn.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, msg, "h2 tunnel echo roundtrip mismatch");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dial_retried_exactly_five_times_on_dead_proxy() {
        // bd cjwc G5（Go client.go:103-119 ExponentialBackoff(5, 100)）：代理
        // accept 后立即断开 = 连接级失败，dial 环节被重试恰好 5 次（accept 计数）；
        // 修复前仅 1 次。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepts_cl = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                accepts_cl.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(sock); // 立即断开 → 客户端响应前 EOF → 重试
            }
        });
        let cfg = Arc::new(HttpOutboundConfig::new(
            Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(port),
        ));
        let dial_fn = make_http_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(443));
        let err = dial_fn(&dest).await.err().expect("dial must fail after retries");
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            5,
            "dial must be attempted exactly 5 times"
        );
        assert!(err.contains("retries exhausted"), "{err}");
    }

    #[test]
    fn render_header_value_table() {
        let (src, tgt) = ("tcp:1.2.3.4:0", "tcp:h.example:443");
        // 无占位原样
        assert_eq!(render_header_value("plain", src, tgt), "plain");
        // 两占位符
        assert_eq!(
            render_header_value("{{.Source}}|{{.Target}}", src, tgt),
            format!("{src}|{tgt}")
        );
        // 带空格形态
        assert_eq!(render_header_value("{{ .Target }}", src, tgt), tgt);
        assert_eq!(render_header_value("{{  .Source  }}", src, tgt), src);
        // 多处占位
        assert_eq!(
            render_header_value("a{{.Target}}b{{.Source}}c{{ .Target }}", src, tgt),
            format!("a{tgt}b{src}c{tgt}")
        );
        // 未知动作 / 未知字段 / 大小写敏感 / 管道与函数 / 未闭合 / 空动作：原样保留
        assert_eq!(render_header_value("{{.Foo}}", src, tgt), "{{.Foo}}");
        assert_eq!(render_header_value("{{.source}}", src, tgt), "{{.source}}");
        assert_eq!(render_header_value("{{if .X}}y{{end}}", src, tgt), "{{if .X}}y{{end}}");
        assert_eq!(render_header_value("open {{ unclosed", src, tgt), "open {{ unclosed");
        assert_eq!(render_header_value("{{}}", src, tgt), "{{}}");
        assert_eq!(render_header_value("", src, tgt), "");
    }

    #[tokio::test]
    async fn template_source_value_uses_dial_src_or_anyip_fallback() {
        // 无 DIAL_SRC scope → Go 降级形态 net.TCPDestination(net.AnyIP, 0)
        assert_eq!(template_source_value(), "tcp:0.0.0.0:0");
        // scope 内 → sendThrough 源 IP；dial 层拿不到端口，端口段固定 0
        let v4: std::net::IpAddr = "127.0.0.2".parse().unwrap();
        let got = xray_transport::system_dialer::DIAL_SRC
            .scope(Some(v4), async { template_source_value() })
            .await;
        assert_eq!(got, "tcp:127.0.0.2:0");
        // IPv6 源对齐 Go Address.String()（自带方括号）
        let v6: std::net::IpAddr = "::1".parse().unwrap();
        let got6 = xray_transport::system_dialer::DIAL_SRC
            .scope(Some(v6), async { template_source_value() })
            .await;
        assert_eq!(got6, "tcp:[::1]:0");
    }

    /// dial 级红→绿：headers 带 `{{.Target}}`/`{{.Source}}` 的配置发出 CONNECT 时
    /// 值已被渲染（Go fillRequestHeader 子集）；未知动作原样保留；默认补头
    /// （TryDefaultHeadersWith 追加项）不参与渲染。
    #[tokio::test]
    async fn connect_request_renders_header_placeholders() {
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

        let cfg =
            HttpOutboundConfig::new(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(port))
                .with_header("X-Target".to_string(), "{{.Target}}".to_string())
                .with_header("X-Source".to_string(), "{{.Source}}".to_string())
                .with_header("X-Mixed".to_string(), "a{{ .Target }}b{{.Source}}c".to_string())
                .with_header("X-Unknown".to_string(), "{{.Foo}} keep".to_string())
                .with_header("User-Agent".to_string(), "tpl-{{.Target}}".to_string());
        let dial_fn = make_http_dial_fn(Arc::new(cfg));
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(443));
        let _conn = dial_fn(&dest).await.expect("tunnel established");
        drop(_conn);

        let request = inspector.await.unwrap();
        assert!(request.contains("X-Target: tcp:target.example.com:443\r\n"), "{request}");
        assert!(request.contains("X-Source: tcp:0.0.0.0:0\r\n"), "{request}");
        assert!(
            request.contains("X-Mixed: atcp:target.example.com:443btcp:0.0.0.0:0c\r\n"),
            "{request}"
        );
        assert!(request.contains("X-Unknown: {{.Foo}} keep\r\n"), "{request}");
        assert!(request.contains("User-Agent: tpl-tcp:target.example.com:443\r\n"), "{request}");
    }

    /// h2 路径同样渲染（establish_h2_tunnel 发出的 CONNECT 头）。
    #[tokio::test]
    async fn h2_connect_renders_header_placeholders() {
        use http_body_util::Empty;
        use hyper::{Request, body::Incoming, service::service_fn};
        use hyper_util::rt::{TokioExecutor, TokioIo};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<(String, String)>>(4);
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(sock);
            let service = service_fn(move |req: Request<Incoming>| {
                let tx = tx.clone();
                async move {
                    let hdrs: Vec<(String, String)> = req
                        .headers()
                        .iter()
                        .map(|(k, v)| {
                            (k.as_str().to_string(), v.to_str().unwrap_or_default().to_string())
                        })
                        .collect();
                    let _ = tx.send(hdrs).await;
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(hyper::StatusCode::OK)
                            .body(Empty::<bytes::Bytes>::new())
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        });

        let mut cfg =
            HttpOutboundConfig::new(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(port))
                .with_header("X-Target".to_string(), "{{.Target}}".to_string())
                .with_header("X-Source".to_string(), "{{.Source}}".to_string());
        cfg.h2 = true;
        let dial_fn = make_http_dial_fn(Arc::new(cfg));
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(443));
        let _conn = dial_fn(&dest).await.expect("h2 CONNECT tunnel must establish");
        drop(_conn);

        let hdrs = rx.recv().await.unwrap();
        let get = |name: &str| {
            hdrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        };
        assert_eq!(get("x-target"), Some("tcp:target.example.com:443"));
        assert_eq!(get("x-source"), Some("tcp:0.0.0.0:0"));
    }
}
