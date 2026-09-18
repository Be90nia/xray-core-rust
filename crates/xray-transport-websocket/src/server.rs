//! WebSocket 服务端：TCP/TLS 监听 + Upgrade + early data 提取。
//!
//! 对应 Go `transport/internet/websocket/hub.go` 的 `ListenWS` +
//! `requestHandler.ServeHTTP`。Rust 端用 `tokio-tungstenite::accept_hdr_async`
//! 拦截 HTTP Upgrade 请求，校验 Host / Path，提取 `Sec-WebSocket-Protocol`
//! header 中的 early data（base64 RawURL 编码）。
//!
//! # 流程
//!
//! 1. `WsListener::bind` 绑 TcpListener
//! 2. `accept()` 收一条 TCP 连接（+ 可选 TLS 包装）
//! 3. `accept_hdr_async` 触发握手，callback 内：
//!    - 校验 `Sec-WebSocket-Key` → 自动由 tungstenite 处理
//!    - 校验 Host / Path → 不匹配返回 `404` 拒绝
//!    - 提取 `Sec-WebSocket-Protocol` base64 → early data
//!    - 回写 `Sec-WebSocket-Protocol` 响应头（必须回写客户端才认）
//! 4. 把握手完成的 `WebSocketStream` + early data 包装为 `WsConnWithEarlyData`

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::Engine;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener as TokioTcpListener,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{Request, Response},
        http::{HeaderMap, StatusCode},
    },
};
use xray_transport::{connection::Connection, read_proxy_protocol};

use crate::{
    config::Config,
    error::{Result, WsError},
    ws_bridge::WsConnection,
};

/// 服务端 accept 出的连接 + 服务端从 `Sec-WebSocket-Protocol` 解出的 early data。
///
/// early data 对应 Go `extraReader`（连接首批字节，调用方需先消费再进入帧循环）。
pub struct AcceptedConn {
    /// 字节流包装的 WS 连接。
    pub conn: Box<dyn Connection>,
    /// 解码后的 early data（可能为空）。
    pub early_data: Vec<u8>,
    /// TCP peer 地址。
    pub remote: SocketAddr,
}

/// WebSocket 服务端监听器。
///
/// 对应 Go `Listener`（`hub.go`）。本结构持有 TcpListener + WS 配置；
/// TLS 包装由调用方在 `accept` 后注入（ponytail：避免 listener 持 TLS acceptor
/// 让数据流走 trait object）。
pub struct WsListener {
    listener: TokioTcpListener,
    configs: Vec<Arc<Config>>,
    /// 可信 XFF header 名单（来自 `sockopt.trustedXForwardedFor`，listener 级，
    /// 对齐 Go `socketSettings.TrustedXForwardedFor`）。空 = 永不采纳 XFF
    /// （默认不信任，防伪造；Go hub.go:63-68）。
    pub trusted_x_forwarded_for: Vec<String>,
}

impl WsListener {
    /// 绑定到 `addr`，使用单个 WS 配置（host/path/heartbeat）。
    pub async fn bind(addr: SocketAddr, config: Arc<Config>) -> Result<Self> {
        Self::bind_multi(addr, vec![config]).await
    }

    /// 绑定到 `addr`，使用多个 WS 配置实现多 path 路由。
    ///
    /// 一个 TCP 端点接受多个 path，握手时按 (host, path) 匹配找到对应 config。
    /// 对应 Go 多个 requestHandler 共享一个 listener（Go 实际是单 path/server）。
    pub async fn bind_multi(addr: SocketAddr, configs: Vec<Arc<Config>>) -> Result<Self> {
        if configs.is_empty() {
            return Err(WsError::InvalidUpgradeRequest { reason: "no WS configs provided".into() });
        }
        let listener = TokioTcpListener::bind(addr).await.map_err(WsError::Io)?;
        Ok(Self { listener, configs, trusted_x_forwarded_for: Vec::new() })
    }

    /// 本地地址。
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(WsError::Io)
    }

    /// 接受一条新连接，完成 WS 握手 + 校验 host/path + 提取 early data。
    ///
    /// **不支持 TLS**：明文 ws:// only。TLS 场景请用 [`accept_tls`](Self::accept_tls)。
    pub async fn accept(&self) -> Result<AcceptedConn> {
        let (mut tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp.local_addr().ok();
        let remote = self.parse_proxy_protocol(&mut tcp, remote).await?;
        Self::ws_handshake(tcp, remote, local, &self.configs, &self.trusted_x_forwarded_for).await
    }

    /// 接受一条新连接，先做 TLS 握手再 WS 握手。
    ///
    /// 流程：TCP accept → PROXY protocol（可选）→ TLS accept → WS handshake。
    /// 对应 Go `tls.NewListener(l, tlsConfig)` 包装 TCP listener。
    pub async fn accept_tls(
        &self,
        tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    ) -> Result<AcceptedConn> {
        let (mut tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp.local_addr().ok();
        let remote = self.parse_proxy_protocol(&mut tcp, remote).await?;
        // TLS 握手。
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls_stream = acceptor
            .accept(tcp)
            .await
            .map_err(|e| WsError::HandshakeFailed(format!("tls accept: {e}")))?;
        Self::ws_handshake(
            tls_stream,
            remote,
            local,
            &self.configs,
            &self.trusted_x_forwarded_for,
        )
        .await
    }

    /// 解析 PROXY protocol（如果启用），返回真实客户端地址。
    async fn parse_proxy_protocol(
        &self,
        tcp: &mut tokio::net::TcpStream,
        original: SocketAddr,
    ) -> Result<SocketAddr> {
        if self.configs.iter().any(|c| c.accept_proxy_protocol) {
            Ok(read_proxy_protocol(tcp).await?.unwrap_or(original))
        } else {
            Ok(original)
        }
    }

    /// 在已建立的流上做 WS 握手 + 多 path 路由 + early data + XFF + 心跳 ping。
    ///
    /// 多 path：在 `configs` 中按 (host, path) 匹配，找到的 config 决定 heartbeat_period。
    /// XFF：仅当 `trusted` 名单 header 命中时从 `X-Forwarded-For` 提取首个 IP 覆盖
    /// remote（port=0，对齐 Go ApplyTrustedXForwardedFor）。
    async fn ws_handshake<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        stream: S,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        configs: &[Arc<Config>],
        trusted: &[String],
    ) -> Result<AcceptedConn> {
        let configs_arc: Arc<[Arc<Config>]> = Arc::from(configs);
        let early_data_slot: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let xff_slot: Arc<std::sync::Mutex<Option<IpAddr>>> = Arc::default();
        let matched_idx_slot: Arc<std::sync::Mutex<Option<usize>>> = Arc::default();

        let ed_cb = Arc::clone(&early_data_slot);
        let xff_cb = Arc::clone(&xff_slot);
        let matched_cb = Arc::clone(&matched_idx_slot);
        let configs_cb = Arc::clone(&configs_arc);

        let callback = move |req: &Request, resp: Response| {
            let headers = req.headers();
            let req_path = req.uri().path();
            let req_host =
                headers.get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");

            // 1. 多 path 路由：找到匹配的 config（host 空放行/非空 Go IsValidHTTPHost
            //    精确匹配（lowercase+剥端口，H2 对齐 internet.go:8-16）+ path 严格匹配）。
            let matched = configs_cb.iter().position(|c| {
                let host_ok = c.host.is_empty()
                    || xray_common::protocol::http::is_valid_http_host(req_host, &c.host);
                let path_ok = req_path == c.normalized_path();
                host_ok && path_ok
            });
            let Some(idx) = matched else {
                let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Some("no matching host/path".into()))
                    .unwrap();
                return Err(denied);
            };
            if let Ok(mut g) = matched_cb.lock() {
                *g = Some(idx);
            }

            // 2. Early data 提取：Sec-WebSocket-Protocol (base64 RawURL no pad)。
            let mut response = resp;
            if let Some(ed_header) = extract_early_data(headers) {
                if let Ok(val) =
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&ed_header.raw)
                {
                    response.headers_mut().insert("Sec-WebSocket-Protocol", val);
                }
                if let Ok(mut guard) = ed_cb.lock() {
                    *guard = ed_header.bytes;
                }
            }

            // 3. X-Forwarded-For 信任门控提取（对应 Go hub.go:63-68
            //    ApplyTrustedXForwardedFor：默认不信任，名单命中才采纳）。
            if let Some(ip) = extract_xff_trusted(headers, trusted) {
                if let Ok(mut guard) = xff_cb.lock() {
                    *guard = Some(ip);
                }
            }

            Ok(response)
        };

        // H14：握手全程 4s 超时（Go hub.go:27-33 Upgrader HandshakeTimeout: 4s；
        // 慢速/半开连接不再无限占用 accept 并发）。
        let ws_stream = tokio::time::timeout(Duration::from_secs(4), accept_hdr_async(stream, callback))
            .await
            .map_err(|_| {
                WsError::HandshakeFailed("websocket handshake timeout (4s)".into())
            })?
            .map_err(|e| WsError::HandshakeFailed(format!("accept_hdr_async: {e}")))?;

        let early_data = early_data_slot.lock().map(|g| g.clone()).unwrap_or_default();
        let xff_ip = xff_slot.lock().ok().and_then(|mut g| g.take());
        let matched_idx = matched_idx_slot.lock().ok().and_then(|mut g| g.take());

        // 4. Remote 决定：XFF 覆盖（port=0，对齐 Go forwardedAddrs[0]）。
        let final_remote = xff_ip.map(|ip| SocketAddr::new(ip, 0)).unwrap_or(remote);

        // 5. 匹配 config 的 heartbeat_period 启动 ping。
        let heartbeat_secs =
            matched_idx.and_then(|i| configs.get(i)).map(|c| c.heartbeat_period).unwrap_or(0);

        let mut conn = WsConnection::from_stream(ws_stream, Some(final_remote), local);
        if heartbeat_secs > 0 {
            conn.start_heartbeat(Duration::from_secs(heartbeat_secs as u64));
        }
        if !early_data.is_empty() {
            conn.read_buf.extend(&early_data);
        }
        Ok(AcceptedConn {
            conn: Box::new(conn) as Box<dyn Connection>,
            early_data,
            remote: final_remote,
        })
    }
}
/// 解析出的 early data（原始 header 字符串 + 解码后字节）。
struct EarlyDataHeader {
    raw: String,
    bytes: Vec<u8>,
}

/// 从 `Sec-WebSocket-Protocol` header 解出 early data。
///
/// 对齐 Go `replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")` +
/// `base64.RawURLEncoding.DecodeString`。Go 用 RawURLEncoding 但 replacer
/// 兼容标准 base64 客户端（把 +/= 替换为 -_ 空）。Rust 端用 URL_SAFE_NO_PAD
/// 直接解码（与 client.rs 编码端对称），不匹配返回 None。
fn extract_early_data(headers: &HeaderMap) -> Option<EarlyDataHeader> {
    let raw = headers.get("Sec-WebSocket-Protocol")?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    // 兼容 Go replacer：标准 base64 → RawURL。
    let normalized: String = raw
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            '=' => '\0', // 移除 padding
            _ => c,
        })
        .filter(|c| *c != '\0')
        .collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&normalized).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(EarlyDataHeader { raw: raw.to_string(), bytes })
}

/// 按信任门控从 `X-Forwarded-For` header 提取首个 IP（最原始客户端）。
///
/// 对齐 Go `hub.go:63-68` + `common/protocol/http/headers.go::ApplyTrustedXForwardedFor`：
/// **仅当** `sockopt.trustedXForwardedFor` 名单中任一 header 在请求中出现时才采纳
/// XFF 首段（H1 修复：此前无条件信任，客户端可伪造源 IP）。其余情况一律 `None`
/// （调用方保持真实连接地址），并按 Go 语义打 warning：
/// - 无名单（默认不信任）→ "not configured" warning
/// - 有名单但名单 header 均不在场 → "potentially forged" warning
fn extract_xff_trusted(headers: &HeaderMap, trusted: &[String]) -> Option<IpAddr> {
    let val = headers.get("X-Forwarded-For")?.to_str().ok()?;
    if trusted.iter().any(|t| headers.contains_key(t.as_str())) {
        let first = val.split(',').next()?.trim();
        return first.parse::<IpAddr>().ok();
    }
    if trusted.is_empty() {
        tracing::warn!(
            xff = val,
            "received \"X-Forwarded-For\" but \"sockopt.trustedXForwardedFor\" is not configured; \
             ignoring it and using the real remote address"
        );
    } else {
        tracing::warn!(xff = val, "ignored potentially forged \"X-Forwarded-For\"");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn extract_early_data_decodes_url_safe_no_pad() {
        // 客户端编码：URL_SAFE_NO_PAD("hello") = "aGVsbG8"
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "aGVsbG8".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded");
        assert_eq!(ed.bytes, b"hello");
        assert_eq!(ed.raw, "aGVsbG8");
    }

    #[test]
    fn extract_early_data_accepts_standard_base64_with_replacer() {
        // 标准 base64("hi!") = "aGkh"（no pad），含 +/= 时：("??") = "Pz8="
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "Pz8=".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded via replacer");
        assert_eq!(ed.bytes, b"??");
    }

    #[test]
    fn extract_early_data_empty_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_missing_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_invalid_base64_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "@@@invalid".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }

    // ===== H1：XFF 信任门控（对齐 Go ApplyTrustedXForwardedFor）=====

    fn hmap(kv: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in kv {
            let name = http::header::HeaderName::from_lowercase(k.to_ascii_lowercase().as_bytes())
                .unwrap();
            h.insert(name, v.parse().unwrap());
        }
        h
    }

    /// H1 回归：无 trusted 名单（默认）→ XFF 一律不采纳（此前无条件信任可伪造源 IP）。
    #[test]
    fn xff_rejected_by_default_without_trusted_list() {
        let h = hmap(&[("X-Forwarded-For", "1.2.3.4, 10.0.0.1")]);
        assert!(extract_xff_trusted(&h, &[]).is_none());
    }

    /// 名单命中 → 采纳首段 IP。
    #[test]
    fn xff_adopted_when_trusted_header_present() {
        let h = hmap(&[("X-Forwarded-For", "1.2.3.4, 10.0.0.1"), ("X-Real-IP", "x")]);
        let ip = extract_xff_trusted(&h, &["X-Real-IP".to_string()]).unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    /// 有名单但名单 header 不在场 → 不采纳。
    #[test]
    fn xff_rejected_when_trusted_header_absent() {
        let h = hmap(&[("X-Forwarded-For", "1.2.3.4")]);
        assert!(extract_xff_trusted(&h, &["X-Real-IP".to_string()]).is_none());
    }

    /// XFF 缺失 → None（无告警路径）。
    #[test]
    fn xff_missing_returns_none() {
        let h = hmap(&[("X-Real-IP", "x")]);
        assert!(extract_xff_trusted(&h, &["X-Real-IP".to_string()]).is_none());
    }

    #[tokio::test]
    async fn accept_tls_completes_ws_handshake() {
        ensure_crypto_provider();
        // 1. 自签证书
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // 2. rustls ServerConfig
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        let tls_config = std::sync::Arc::new(server_config);

        // 3. 启动 WsListener + accept_tls
        let ws_config = std::sync::Arc::new(crate::config::Config::default());
        let listener = WsListener::bind("127.0.0.1:0".parse().unwrap(), ws_config).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            // accept_tls 应成功完成 TLS + WS 握手
            listener.accept_tls(tls_config).await
        });

        // 4. 客户端：TCP + TLS + WS connect
        // 构造信任自签证书的 client config
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let client_config = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        // tokio-tungstenite connect_async wss:// 需要原生 TLS connector
        // ponytail: 直接用 tokio-rustls 手动 TLS 后 tungstenite client_handshake
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tls_stream = connector.connect("localhost".try_into().unwrap(), tcp).await.unwrap();

        // WS 客户端握手
        use tokio_tungstenite::client_async;
        let ws_request = http::Request::builder()
            .method("GET")
            .uri(format!("ws://localhost:{}/", addr.port()))
            .header("Host", format!("localhost:{}", addr.port()))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let (_ws_client, _resp) = client_async(ws_request, tls_stream).await.unwrap();

        // 5. 服务端 accept_tls 完成
        let accepted = server_handle.await.unwrap().unwrap();
        assert_eq!(
            accepted.remote.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    // --- 多 path 路由 E2E ---

    #[tokio::test]
    async fn bind_multi_routes_by_path_and_rejects_unknown() {
        use tokio_tungstenite::{client_async, tungstenite::client::IntoClientRequest};

        let cfg1 = Arc::new(Config { path: "/foo".into(), ..Default::default() });
        let cfg2 = Arc::new(Config { path: "/bar".into(), ..Default::default() });
        let listener = Arc::new(
            WsListener::bind_multi("127.0.0.1:0".parse().unwrap(), vec![cfg1, cfg2]).await.unwrap(),
        );
        let addr = listener.local_addr().unwrap();

        // /foo 匹配。
        let l1 = Arc::clone(&listener);
        let s1 = tokio::spawn(async move { l1.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/foo", addr.port()).into_client_request().unwrap();
        let (_ws, _resp) = client_async(req, tcp).await.expect("/foo should match");
        let _ = s1.await.unwrap().unwrap();

        // /bar 匹配。
        let l2 = Arc::clone(&listener);
        let s2 = tokio::spawn(async move { l2.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/bar", addr.port()).into_client_request().unwrap();
        let (_ws, _resp) = client_async(req, tcp).await.expect("/bar should match");
        let _ = s2.await.unwrap().unwrap();

        // /baz 不匹配 → 握手失败。
        let l3 = Arc::clone(&listener);
        let s3 = tokio::spawn(async move { l3.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/baz", addr.port()).into_client_request().unwrap();
        let result = client_async(req, tcp).await;
        assert!(result.is_err(), "/baz should not match");
        assert!(s3.await.unwrap().is_err(), "server accept should fail too");
    }

    // --- XFF 覆盖 E2E ---

    #[tokio::test]
    async fn xff_header_overrides_remote_addr() {
        use tokio_tungstenite::{client_async, tungstenite::client::IntoClientRequest};

        let cfg = Arc::new(Config::default());
        let listener =
            Arc::new(WsListener::bind("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap());
        let addr = listener.local_addr().unwrap();

        let l = Arc::clone(&listener);
        let server = tokio::spawn(async move { l.accept().await });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req = format!("ws://127.0.0.1:{}/", addr.port()).into_client_request().unwrap();
        req.headers_mut().insert("X-Forwarded-For", "203.0.113.5".parse().unwrap());
        let (_ws, _resp) = client_async(req, tcp).await.unwrap();

        let accepted = server.await.unwrap().unwrap();
        assert_eq!(accepted.remote.ip(), "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(accepted.remote.port(), 0, "XFF override sets port to 0");
    }
}
