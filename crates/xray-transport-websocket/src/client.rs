//! WebSocket 客户端：拨号 + 握手 + early data。
//!
//! 对应 Go `transport/internet/websocket/dialer.go` 的 `dialWebSocket` +
//! `Dial`。Rust 端复用 `tokio-tungstenite` 处理 HTTP Upgrade 握手 + TLS，
//! Xray 自身只负责构造 URI、自定义 header、`Sec-WebSocket-Protocol` (early data)
//! 与 [`WsConnection`] 字节流包装。
//!
//! # Early Data (0-RTT)
//!
//! Go 约定：early data 用 base64.RawURLEncoding 编码后放入
//! `Sec-WebSocket-Protocol` header（不是 URL `?ed=` 参数）。
//! 服务端若识别到，先把这些字节当作「连接首批数据」喂给上层，再进入 WS 帧循环。
//!
//! # TLS
//!
//! `tls_config: Some(_)` 走 rustls + wss://；`None` 走明文 ws://。
//! 拨 TCP 由 `tokio-tungstenite` 内部完成（用 URI 的 host:port）。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use base64::Engine;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, client_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest, handshake::client::Request as WsRequest, http::HeaderValue,
        protocol::WebSocketConfig,
    },
};
use xray_common::{browser::try_default_headers_with, net::destination::Destination};
use xray_transport::connection::Connection;

use crate::{
    config::Config,
    error::{Result, WsError},
    ws_bridge::WsConnection,
};

/// 拨号参数（与 Go `dialWebSocket` 入参对齐）。
pub struct DialOptions<'a> {
    /// WS 配置（host/path/header/heartbeat）。
    pub config: &'a Config,
    /// 目标地址（端口用于 URI authority；地址若与 `config.host` 不一致则用 host）。
    pub destination: &'a Destination,
    /// 可选 early data（0-RTT 第一批字节）。`None` 或空切片表示无 early data。
    pub early_data: Option<&'a [u8]>,
    /// 可选 rustls `ClientConfig`（`Some` → `wss://`，`None` → `ws://`）。
    pub tls_config: Option<Arc<rustls::ClientConfig>>,
    /// TLS SNI（`tlsSettings.serverName`）。None 用 destination 地址。
    /// Go：拨号目标（dest）与 SNI 解耦（CDN/argo 场景 SNI/Host 是配置域名）。
    pub tls_server_name: Option<String>,
    /// tlsSettings.fingerprint。接线（md5i）：解析成功（含缺省 → Go
    /// `GetFingerprint("")` 默认 chrome）即走 btls uTLS + ALPN http/1.1 重写；
    /// 非法指纹名 → Go `GetFingerprint` nil 语义 → 标准 rustls。
    pub fingerprint: Option<String>,
    /// `tlsSettings` 原文（证书验证 verifier 构建 + ALPN 伪装解析用）。
    pub security_json: Option<serde_json::Value>,
}

/// 完成 WS 握手并返回字节流包装。
///
/// 返回 `WsConnection<MaybeTlsStream<TcpStream>>`，可直接作为
/// `AsyncRead + AsyncWrite + Connection` 使用。
#[allow(clippy::result_large_err)] // WsError::Tungstenite 136B；Box 化属类型变更，超出行为零变更契约
pub async fn dial(
    opts: DialOptions<'_>,
) -> Result<WsConnection<MaybeTlsStream<Box<dyn xray_transport::connection::Connection>>>> {
    // TLS 自管时 URI 也必须用 ws://：tungstenite 的 uri_mode 按 scheme 判断，
    // wss + Connector::Plain 会报 "TLS support not compiled in"。
    let uri = build_request_uri(opts.config, opts.destination, false);
    let request = build_request(
        &uri,
        opts.config,
        opts.tls_server_name.as_deref(),
        opts.destination,
        opts.early_data,
    )?;

    // ponytail: WebSocketConfig 默认 64 MiB max_message_size 足够代理流量。
    let ws_cfg = WebSocketConfig::default();

    // 自管 TCP + TLS：tokio-tungstenite 的 connect_async_tls_with_config 用
    // URI authority 做 SNI，而 CDN/argo 场景 URI authority（拨号目标）与
    // SNI/Host（配置域名）必须解耦（Go NetDial(dest) + ServerName(tlsSettings)）。
    // connector=None 时 tungstenite 把传入流当 TLS-ready（Plain 包装）。
    let host = opts.destination.address().to_string();
    let port = opts.destination.port().value();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    tcp.set_nodelay(true).ok();
    let stream: Box<dyn xray_transport::connection::Connection> = match opts.tls_config {
        Some(cfg) => {
            // Go dialer.go:79-99：fingerprint 解析成功即走 tls.UClient +
            // WebsocketHandshakeContext（指纹名缺省 → chrome 默认；非法名 →
            // GetFingerprint nil → 标准 TLS）。md5i 接线：btls 真实指纹 + ALPN
            // 重写 http/1.1（2026-09-06 回归根因 = chrome 模板 ALPN h2 被 CDN
            // 协商，h1 upgrade 帧解析失败；ALPN 修复见 connect_with_alpn）。
            let sni = opts.tls_server_name.as_deref().unwrap_or(host.as_str());
            let inner = Box::new(xray_transport::connection::TcpConnection::new(tcp))
                as Box<dyn xray_transport::connection::Connection>;
            let tls_stream: Box<dyn xray_transport::connection::Connection> =
                match xray_tls::fingerprint::get_fingerprint(
                    opts.fingerprint.as_deref().unwrap_or(""),
                ) {
                    Ok(fp) => {
                        let alpn =
                            xray_tls::utls::websocket_handshake_alpn(opts.security_json.as_ref());
                        Box::new(
                            xray_tls::utls::u_client_with_alpn(
                                inner,
                                sni,
                                cfg,
                                fp,
                                None,
                                opts.security_json.as_ref(),
                                Some(&alpn),
                            )
                            .await?,
                        ) as Box<dyn xray_transport::connection::Connection>
                    },
                    Err(_) => Box::new(xray_tls::utls::client(inner, sni, cfg).await?)
                        as Box<dyn xray_transport::connection::Connection>,
                };
            tls_stream
        },
        None => Box::new(xray_transport::connection::TcpConnection::new(tcp)),
    };

    // connector=None 时 tungstenite(native-tls feature)会对流再叠一层 TLS;
    // 我们的 TLS 分支已自管 TLS,必须显式 Plain(仅明文分支也是 Plain 包装)。
    let (stream, _resp) =
        client_async_tls_with_config(request, stream, Some(ws_cfg), Some(Connector::Plain)).await?;

    // remote/local addr：地址不暴露；调用方需要时通过 dispatcher 注入。
    let mut conn = WsConnection::from_stream(stream, None, None);
    // 客户端心跳（Go dialer.go:165 NewConnection(conn, _, _, HeartbeatPeriod)）：
    // heartbeatPeriod > 0 时两侧都起 ping，防 NAT/CDN 长空闲掐断。
    if opts.config.heartbeat_period > 0 {
        conn.start_heartbeat(std::time::Duration::from_secs(opts.config.heartbeat_period as u64));
    }
    Ok(conn)
}

/// Owned 拨号参数：[`DialOptions`] 的 `'static` 版本，供 [`DelayDialConn`]
/// 的延迟拨号任务 spawn 使用（对应 Go `delayDialConn` 持有的 dest + streamSettings）。
#[derive(Clone)]
pub struct DialParams {
    /// WS 配置（host/path/header/ed）。
    pub config: Config,
    /// 拨号目标（URI authority + TCP 连接地址）。
    pub destination: Destination,
    /// 可选 rustls `ClientConfig`（`Some` → `wss://`，`None` → `ws://`）。
    pub tls_config: Option<Arc<rustls::ClientConfig>>,
    /// TLS SNI（`tlsSettings.serverName`）。
    pub tls_server_name: Option<String>,
    /// `tlsSettings.fingerprint`（接线语义同 [`DialOptions::fingerprint`]）。
    pub fingerprint: Option<String>,
    /// `tlsSettings` 原文（verifier 构建 + ALPN 伪装解析）。
    pub security_json: Option<serde_json::Value>,
}

/// 用 owned 参数拨号（内部组 [`DialOptions`] 调 [`dial`]）。
#[allow(clippy::result_large_err)] // WsError::Tungstenite 136B；Box 化属类型变更，超出行为零变更契约
pub async fn dial_with_params(
    params: DialParams,
    early_data: Option<Vec<u8>>,
) -> Result<WsConnection<MaybeTlsStream<Box<dyn xray_transport::connection::Connection>>>> {
    let DialParams { config, destination, tls_config, tls_server_name, fingerprint, security_json } =
        params;
    dial(DialOptions {
        config: &config,
        destination: &destination,
        early_data: early_data.as_deref(),
        tls_config,
        tls_server_name,
        fingerprint,
        security_json,
    })
    .await
}

/// 延迟拨号工厂：入参为本次握手要携带的 early data（`None` = 不带），
/// 返回建立好的连接。由 register 层组装（含 finalmask 包装）。
pub type DialFuture = Pin<
    Box<dyn Future<Output = io::Result<Box<dyn xray_transport::connection::Connection>>> + Send>,
>;
pub type DialFactory = Arc<dyn Fn(Option<Vec<u8>>) -> DialFuture + Send + Sync>;

/// Go `dialer.go:168-221 delayDialConn` 的等价物：`Ed > 0` 时真实拨号推迟到
/// 首次 Write，首包 ≤ Ed 字节以 early data 进握手头（0-RTT，省 1 RTT）。
///
/// - 首次 `poll_write`：≤ Ed 整包交给工厂作 early data 并 spawn 拨号任务， `Pending`
///   到拨号完成；被握手吸收则 `Ready(Ok(len))`，超 Ed 则不带 early
///   data、原包落帧写（`dialer.go:178-198`）。
/// - `poll_read`：未拨号时等待拨号完成（`dialed` channel 语义，`dialer.go:200-212`）。
/// - 关闭/drop：abort 未完成的拨号任务（`cancel()` 语义，`dialer.go:214-221`）。
pub struct DelayDialConn {
    ed: u32,
    factory: DialFactory,
    joining: Option<JoinHandle<io::Result<Box<dyn xray_transport::connection::Connection>>>>,
    conn: Option<Box<dyn xray_transport::connection::Connection>>,
    /// 首写记账 `(首写长度, 是否被握手吸收)`，拨号完成时消费一次。
    first_write: Option<(usize, bool)>,
    closed: bool,
}

impl DelayDialConn {
    /// `Ed` 容量上限与拨号工厂；真实拨号在首次 Write 才发生。
    pub fn new(ed: u32, factory: DialFactory) -> Self {
        Self { ed, factory, joining: None, conn: None, first_write: None, closed: false }
    }

    /// 驱动拨号任务到完成。无任务时 `Pending`（等首次 Write 触发）。
    fn poll_dial(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.conn.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(handle) = self.joining.as_mut() else {
            return Poll::Pending;
        };
        match Pin::new(handle).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.closed = true;
                Poll::Ready(Err(io::Error::other(format!("dial task failed: {e}"))))
            },
            Poll::Ready(Ok(Err(e))) => {
                // Go dialer.go:188-191：拨号失败即 Close。
                self.closed = true;
                Poll::Ready(Err(e))
            },
            Poll::Ready(Ok(Ok(conn))) => {
                self.conn = Some(conn);
                self.joining = None;
                Poll::Ready(Ok(()))
            },
        }
    }
}

impl AsyncRead for DelayDialConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.closed {
            // Go io.ErrClosedPipe。
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            )));
        }
        if this.conn.is_none() {
            // 未拨号且无拨号任务：等首次 Write（Go dialer.go:204-210）。
            ready!(this.poll_dial(cx))?;
        }
        Pin::new(this.conn.as_mut().expect("dial completed")).poll_read(cx, buf)
    }
}

impl AsyncWrite for DelayDialConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            )));
        }
        if this.conn.is_none() {
            if this.joining.is_none() {
                // 首写触发拨号：≤ Ed 整包进握手头，超 Ed 不带 early data。
                let ed = if buf.len() <= this.ed as usize { Some(buf.to_vec()) } else { None };
                this.first_write = Some((buf.len(), ed.is_some()));
                let factory = this.factory.clone();
                this.joining = Some(tokio::spawn(async move { factory(ed).await }));
            }
            ready!(this.poll_dial(cx))?;
            let (len, absorbed) =
                this.first_write.take().expect("recorded when dial was triggered");
            if absorbed {
                // 首包已编码进 Sec-WebSocket-Protocol 握手头，视为已消费。
                return Poll::Ready(Ok(len));
            }
            // 超 Ed：原包照常走帧写（Go dialer.go:197 d.Conn.Write(b)）。
        }
        Pin::new(this.conn.as_mut().expect("dial completed")).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.conn.as_mut() {
            Some(conn) => Pin::new(conn).poll_flush(cx),
            // 未拨号：无缓冲数据可冲。
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        match this.conn.as_mut() {
            Some(conn) => Pin::new(conn).poll_shutdown(cx),
            // 未拨号：直接闭合并取消拨号任务（Go Close 的 cancel 分支）。
            None => {
                this.closed = true;
                if let Some(handle) = this.joining.take() {
                    handle.abort();
                }
                Poll::Ready(Ok(()))
            },
        }
    }
}

impl Connection for DelayDialConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        // 未拨号无对端（Go 未拨号时内嵌 net.Conn 为 nil）。
        match &self.conn {
            Some(c) => c.remote_addr(),
            None => Ok(None),
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match &self.conn {
            Some(c) => c.local_addr(),
            None => Ok(None),
        }
    }
}

impl Drop for DelayDialConn {
    fn drop(&mut self) {
        // 拨号中途丢弃：abort 任务（Go cancel() 语义），不留孤儿连接。
        if let Some(handle) = self.joining.take() {
            handle.abort();
        }
    }
}

/// 构造 URI（`ws://` 或 `wss://` + authority + path）。
///
/// 对应 Go `dialer.go` 中 `uri := protocol + "://" + host + path`。
fn build_request_uri(cfg: &Config, dest: &Destination, use_tls: bool) -> String {
    let protocol = if use_tls { "wss" } else { "ws" };
    let host = dest.address().to_string();
    // ponytail: URI authority 用 dest 地址（真实拨号目标）。
    // Host header 用 cfg.host（在 build_request 中设置，CDN/SNI 场景使用）。
    let port = dest.port().value();
    let needs_explicit_port = !(port == 80 && !use_tls) && !(port == 443 && use_tls);
    let authority = if needs_explicit_port { format!("{host}:{port}") } else { host };
    let path = cfg.normalized_path();
    format!("{protocol}://{authority}{path}")
}

/// 构造自定义 WS Upgrade request：Host 三级回退 + user header + 浏览器伪装头
/// + early-data。
#[allow(clippy::result_large_err)] // 存量清零批次：result_large_err
fn build_request(
    uri: &str,
    cfg: &Config,
    tls_server_name: Option<&str>,
    dest: &Destination,
    ed: Option<&[u8]>,
) -> Result<WsRequest> {
    let mut req = uri
        .into_client_request()
        .map_err(|e| WsError::HandshakeFailed(format!("invalid URI: {e}")))?;

    // 1. Host header 三级回退（Go dialer.go:144-150）： wsSettings.Host → tlsSettings.serverName →
    //    dest address。 CDN 按 IP 拨号 + 对端校验 Host 时，缺 serverName 级会导致握手 404。
    let host_header = if !cfg.host.is_empty() {
        cfg.host.clone()
    } else if let Some(sni) = tls_server_name.filter(|s| !s.is_empty()) {
        sni.to_string()
    } else {
        dest.address().to_string()
    };
    req.headers_mut().insert(
        http::header::HOST,
        HeaderValue::from_str(&host_header)
            .map_err(|e| WsError::HandshakeFailed(format!("invalid host header: {e}")))?,
    );

    // 2. 用户自定义 header。
    for (k, v) in &cfg.header {
        // 头名解析：用 http::HeaderName 验证。
        let name = k
            .parse::<http::header::HeaderName>()
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header name {k:?}: {e}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header value for {k}: {e}")))?;
        req.headers_mut().insert(name, value);
    }

    // 2.5. 浏览器伪装（Go websocket/config.go:22-29 GetRequestHeader →
    //      `TryDefaultHeadersWith(header, "ws")`，"ws" 是 variant 名）：
    //      UA 缺省 → Chrome 全套；UA 为枚举值 → 对应伪装；其他 → 不动。
    //      Host/Upgrade/Connection/Sec-WS-* 由 tungstenite 生成，伪装头
    //      只叠加 UA/Sec-Fetch 族，不覆盖用户自定义（票 yz8n）。
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    try_default_headers_with(&mut headers, "ws");
    let header_map = req.headers_mut();
    header_map.clear();
    for (k, v) in headers {
        let name = k
            .parse::<http::header::HeaderName>()
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header name {k:?}: {e}")))?;
        let value = HeaderValue::from_str(&v)
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header value for {k}: {e}")))?;
        header_map.insert(name, value);
    }

    // 3. Early data → Sec-WebSocket-Protocol header (base64 RawURL no padding)。 对齐
    //    Go：header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
    if let Some(data) = ed {
        if !data.is_empty() {
            // ponytail: 用 RawURLEncoding（无 padding）匹配 v2ray/xray 协议约定。
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
            // tungstenite::http::header 常量名：SEC_WEBSOCKET_PROTOCOL
            req.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_str(&encoded)
                    .map_err(|e| WsError::HandshakeFailed(format!("early data encode: {e}")))?,
            );
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };

    use super::*;

    fn dest(host: &str, port: u16) -> Destination {
        Destination::new(Address::new_domain(host), Port::new(port), Network::TCP)
    }

    #[test]
    fn uri_uses_destination_address_not_config_host() {
        // URI authority 用 dest 地址（cfg.host 仅作为 Host header）。
        let cfg =
            Config { host: "cdn.example.com".into(), path: "/ws".into(), ..Default::default() };
        let d = dest("1.2.3.4", 443);
        assert_eq!(build_request_uri(&cfg, &d, true), "wss://1.2.3.4/ws");
    }

    #[test]
    fn uri_falls_back_to_destination_address() {
        let cfg = Config::default(); // host 空
        let d = dest("example.com", 80);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com/");
    }

    #[test]
    fn uri_explicit_nonstandard_port() {
        let cfg = Config::default();
        let d = dest("example.com", 8080);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com:8080/");
    }

    #[test]
    fn uri_standard_port_wss_omits_port() {
        let cfg = Config::default();
        let d = dest("example.com", 443);
        assert_eq!(build_request_uri(&cfg, &d, true), "wss://example.com/");
    }

    #[test]
    fn uri_path_normalized_prepends_slash() {
        let cfg = Config { path: "api".into(), ..Default::default() };
        let d = dest("example.com", 80);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com/api");
    }

    #[test]
    fn build_request_sets_host_header() {
        let cfg = Config { host: "front.example.com".into(), ..Default::default() };
        let req = build_request("ws://1.2.3.4/", &cfg, None, &dest("1.2.3.4", 80), None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "front.example.com");
    }

    #[test]
    fn build_request_attaches_early_data_as_sec_websocket_protocol() {
        let cfg = Config::default();
        let ed = b"hello-ed";
        let req = build_request(
            "ws://example.com/",
            &cfg,
            None,
            &dest("example.com", 80),
            Some(ed.as_slice()),
        )
        .unwrap();
        let v = req.headers().get("Sec-WebSocket-Protocol").expect("header should be set");
        // base64 URL_SAFE_NO_PAD("hello-ed") = "aGVsbG8tZWQ"
        assert_eq!(v.to_str().unwrap(), "aGVsbG8tZWQ");
    }

    #[test]
    fn build_request_empty_early_data_omits_header() {
        let cfg = Config::default();
        let req =
            build_request("ws://example.com/", &cfg, None, &dest("example.com", 80), Some(&[]))
                .unwrap();
        assert!(req.headers().get("Sec-WebSocket-Protocol").is_none());
    }

    #[test]
    fn build_request_attaches_custom_headers() {
        let mut cfg = Config::default();
        cfg.header.insert("X-Forwarded-For".into(), "10.0.0.1".into());
        cfg.header.insert("X-Custom".into(), "v".into());
        let req =
            build_request("ws://example.com/", &cfg, None, &dest("example.com", 80), None).unwrap();
        assert_eq!(req.headers().get("x-forwarded-for").unwrap(), "10.0.0.1");
        assert_eq!(req.headers().get("x-custom").unwrap(), "v");
    }

    #[test]
    fn build_request_host_fallback_chain_host_servername_dest() {
        // 三级回退（Go dialer.go:144-150）：wsSettings.Host → tlsSettings.serverName
        // → dest address。CDN 按 IP 拨号 + 对端校验 Host 依赖 serverName 级。
        let d = dest("203.0.113.9", 443);

        // 1) cfg.host 优先
        let cfg = Config { host: "front.example.com".into(), ..Default::default() };
        let req =
            build_request("wss://203.0.113.9/", &cfg, Some("sni.example.com"), &d, None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "front.example.com");

        // 2) host 空 → serverName
        let cfg = Config::default();
        let req =
            build_request("wss://203.0.113.9/", &cfg, Some("sni.example.com"), &d, None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "sni.example.com");

        // 3) host/serverName 皆空 → dest address
        let req = build_request("wss://203.0.113.9/", &cfg, None, &d, None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "203.0.113.9");
    }

    #[test]
    fn build_request_injects_chrome_masquerade_for_ws() {
        // 票 yz8n：Go config.go:27 GetRequestHeader → TryDefaultHeadersWith(header, "ws")。
        let cfg = Config::default();
        let req =
            build_request("ws://example.com/", &cfg, None, &dest("example.com", 80), None).unwrap();
        let ua = req.headers().get("user-agent").expect("UA must be set").to_str().unwrap();
        assert!(
            ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
                && ua.ends_with(" Safari/537.36"),
            "UA must masquerade as Chrome, got: {ua}"
        );
        assert_eq!(req.headers().get("sec-fetch-mode").unwrap(), "websocket");
        assert_eq!(req.headers().get("sec-fetch-dest").unwrap(), "empty");
        assert_eq!(req.headers().get("sec-fetch-site").unwrap(), "same-origin");
        assert_eq!(req.headers().get("cache-control").unwrap(), "no-cache");
        assert_eq!(req.headers().get("pragma").unwrap(), "no-cache");
        assert_eq!(req.headers().get("accept").unwrap(), "*/*");
        assert!(req.headers().get("sec-ch-ua").is_some(), "CH-UA GREASE present");
        // tungstenite 生成的基础握手头必须保留。
        assert!(req.headers().get("sec-websocket-key").is_some());
        assert_eq!(req.headers().get("upgrade").unwrap(), "websocket");
        assert_eq!(req.headers().get("connection").unwrap(), "Upgrade");
    }

    #[test]
    fn build_request_masquerade_keeps_custom_headers() {
        let mut cfg = Config::default();
        cfg.header.insert("User-Agent".into(), "my-agent/9".into());
        cfg.header.insert("Accept".into(), "application/json".into());
        let req =
            build_request("ws://example.com/", &cfg, None, &dest("example.com", 80), None).unwrap();
        assert_eq!(req.headers().get("user-agent").unwrap(), "my-agent/9");
        assert_eq!(req.headers().get("accept").unwrap(), "application/json");
        assert!(req.headers().get("sec-fetch-mode").is_none(), "custom UA → no masquerade");
    }

    #[tokio::test]
    async fn dial_starts_client_heartbeat_when_configured() {
        // 真实 ws 握手（本地 listener + accept_async），dial 后心跳任务句柄存在。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                        // 保活片刻让客户端完成 dial + 断言。
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        drop(ws);
                    }
                });
            }
        });

        let d = dest("127.0.0.1", addr.port());
        let cfg = Config { heartbeat_period: 1, ..Default::default() };
        let conn = dial(DialOptions {
            config: &cfg,
            destination: &d,
            early_data: None,
            tls_config: None,
            tls_server_name: None,
            fingerprint: None,
            security_json: None,
        })
        .await
        .unwrap();
        assert!(conn.heartbeat_handle.is_some(), "heartbeatPeriod>0 → 客户端心跳任务已启动");

        // 对照：period=0 不启动。
        let cfg = Config::default();
        let conn = dial(DialOptions {
            config: &cfg,
            destination: &d,
            early_data: None,
            tls_config: None,
            tls_server_name: None,
            fingerprint: None,
            security_json: None,
        })
        .await
        .unwrap();
        assert!(conn.heartbeat_handle.is_none());
    }

    // -------------------------------------------------------------------
    // DelayDialConn：Go dialer.go:168-221 delayDialConn 语义
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // md5i：fingerprint 接线 — ws TLS 出站 btls 真实指纹 + ALPN 重写
    // -------------------------------------------------------------------

    /// 抓取拨号发来的首个 TLS record（ClientHello）；收满 record 或 EOF 即止。
    async fn capture_client_hello(listener: tokio::net::TcpListener) -> Vec<u8> {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
                .await
                .expect("hello read timeout")
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 5 && buf[0] == 0x16 {
                let want = 5 + (usize::from(buf[3]) << 8) + usize::from(buf[4]);
                if buf.len() >= want {
                    break;
                }
            }
        }
        buf
    }

    async fn hello_for(fingerprint: Option<&str>, alpn: Option<Vec<&str>>) -> Vec<u8> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let d = dest("127.0.0.1", listener.local_addr().unwrap().port());
        let server = tokio::spawn(capture_client_hello(listener));

        let mut sec = serde_json::json!({});
        if let Some(fp) = fingerprint {
            sec["fingerprint"] = serde_json::Value::String(fp.into());
        }
        if let Some(alpn) = alpn.as_deref() {
            sec["alpn"] = serde_json::json!(alpn);
        }
        let tls_config =
            xray_tls::client_config::build_client_config("tls", Some(&sec), "localhost")
                .unwrap()
                .unwrap();
        let result = dial(DialOptions {
            config: &Config::default(),
            destination: &d,
            early_data: None,
            tls_config: Some(tls_config),
            tls_server_name: Some("localhost".into()),
            fingerprint: fingerprint.map(String::from),
            security_json: Some(sec),
        })
        .await;
        assert!(result.is_err(), "capture server drops conn → dial must fail");
        server.await.unwrap()
    }

    /// 最小 ClientHello 解析：提取 cipher_suites 段（GREASE 判别用）。
    /// 返回 `(cipher 字节, cipher 数量)`；结构异常返回 None。
    fn parse_cipher_suites(hello: &[u8]) -> Option<(&[u8], usize)> {
        if hello.len() < 44 || hello[0] != 0x16 || hello[5] != 0x01 {
            return None;
        }
        let mut c = 43; // record(5) + hs type/len(4) + version(2) + random(32)
        c += 1 + usize::from(hello[c]); // session_id
        if c + 3 > hello.len() {
            return None;
        }
        let len = (usize::from(hello[c]) << 8) + usize::from(hello[c + 1]);
        let suites = hello.get(c + 2..c + 2 + len)?;
        Some((suites, len / 2))
    }

    /// chrome 判别：cipher 数量多且含 GREASE（BoringSSL 每连接随机取值，
    /// 形如 0xXaXa）；rustls 默认 6 cipher 且无 GREASE。
    fn is_btls_chrome_hello(hello: &[u8]) -> bool {
        let Some((suites, n)) = parse_cipher_suites(hello) else {
            return false;
        };
        n >= 12 && suites.chunks_exact(2).any(|c| c[0] == c[1] && (c[0] & 0x0f) == 0x0a)
    }

    /// md5i 验收：ws 出站 fingerprint=chrome → btls 真实 chrome ClientHello
    /// （多 cipher + GREASE，rustls 从不发送），且用户未配 alpn 时 ALPN 重写为
    /// 仅 http/1.1（Go `WebsocketHandshakeContext` 语义）。
    #[tokio::test]
    async fn dial_tls_fingerprint_chrome_sends_btls_hello_with_h1_alpn() {
        let hello = hello_for(Some("chrome"), None).await;
        assert_eq!(hello[0], 0x16, "TLS handshake record");
        assert!(is_btls_chrome_hello(&hello), "not a btls chrome hello");
        let mut h1_wire = vec![0x00, 0x09, 0x08];
        h1_wire.extend_from_slice(b"http/1.1");
        assert!(
            hello.windows(h1_wire.len()).any(|w| w == h1_wire.as_slice()),
            "ALPN must be http/1.1-only"
        );
        assert!(
            !hello.windows(4).any(|w| w == [0x02, b'h', b'2', 0x08]),
            "h2 must not be offered on ws"
        );
    }

    /// 伪装组合：用户 alpn 恰为 ["h2","http/1.1"] → 原样保留（Go 语义）。
    #[tokio::test]
    async fn dial_tls_chrome_keeps_h2_h1_alpn_when_configured() {
        let hello = hello_for(Some("chrome"), Some(vec!["h2", "http/1.1"])).await;
        assert!(is_btls_chrome_hello(&hello));
        assert!(
            hello.windows(4).any(|w| w == [0x02, b'h', b'2', 0x08]),
            "configured h2+http/1.1 camouflage ALPN must survive"
        );
    }

    /// 非法指纹名 → Go GetFingerprint nil 语义 → 标准 rustls（6 cipher 无 GREASE）。
    #[tokio::test]
    async fn dial_tls_invalid_fingerprint_falls_back_to_rustls_hello() {
        let hello = hello_for(Some("nosuchfingerprint"), None).await;
        assert_eq!(hello[0], 0x16);
        let (_, n) = parse_cipher_suites(&hello).expect("parseable rustls hello");
        assert!(n <= 16, "rustls hello must have a small cipher set, got {n}");
        assert!(!is_btls_chrome_hello(&hello));
    }

    use std::{sync::Mutex, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_transport::connection::DuplexConnection;

    /// 工厂调用记录：每次收到的 early data（`None` = 超长未携带）。
    type DialRecord = Arc<Mutex<Vec<Option<Vec<u8>>>>>;

    /// 取当前记录快照（锁被毒化时按空处理，测试失败由断言报出）。
    fn recorded(record: &DialRecord) -> Vec<Option<Vec<u8>>> {
        record.lock().map(|g| g.clone()).unwrap_or_default()
    }
    /// 记录 early data 的工厂：延迟 `delay` 后返回 duplex 客户端半边（一次性 take）。
    fn recording_factory(
        record: DialRecord,
        delay: Duration,
    ) -> (DialFactory, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(4096);
        let client = Arc::new(Mutex::new(Some(client)));
        let factory: DialFactory = Arc::new(move |ed| {
            if let Ok(mut g) = record.lock() {
                g.push(ed.clone());
            }
            let client = client.lock().ok().and_then(|mut g| g.take());
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                let client = client.expect("factory called at most once per duplex");
                Ok(Box::new(DuplexConnection::new(client)) as Box<dyn Connection>)
            })
        });
        (factory, server)
    }
    /// 首写前不拨号（Go Dial Ed>0 只建 delayDialConn 不拨号）。
    #[tokio::test]
    async fn delay_dial_defers_until_first_write() {
        let record: DialRecord = Arc::default();
        let (factory, _server) = recording_factory(record.clone(), Duration::ZERO);
        drop(DelayDialConn::new(64, factory));
        assert!(recorded(&record).is_empty(), "must not dial before first write");
    }

    /// Go cd4ce973：未拨号时 LocalAddr/RemoteAddr 不得 panic（Go 修复 nil 内嵌
    /// 接口的方法提升 panic；Rust 侧契约 = 返回 Ok(None)）。
    #[tokio::test]
    async fn delay_dial_addr_before_dial_returns_none_not_panic() {
        let record: DialRecord = Arc::default();
        let (factory, _server) = recording_factory(record.clone(), Duration::from_secs(30));
        let conn = DelayDialConn::new(64, factory);
        assert_eq!(conn.local_addr().unwrap(), None, "undialed local_addr → None");
        assert_eq!(conn.remote_addr().unwrap(), None, "undialed remote_addr → None");
    }

    /// 首写 ≤ Ed：整包进握手头，Write 即返回，帧上无数据。
    #[tokio::test]
    async fn delay_dial_first_write_within_ed_enters_handshake() {
        let record: DialRecord = Arc::default();
        let (factory, mut server) = recording_factory(record.clone(), Duration::ZERO);
        let mut conn = DelayDialConn::new(64, factory);
        let n = conn.write(b"hello-ed".as_slice()).await.unwrap();
        assert_eq!(n, 8);
        assert_eq!(recorded(&record), vec![Some(b"hello-ed".to_vec())]);
        // early data 被握手吸收：对端读不到（没有帧写出）。
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_millis(50), server.read(&mut buf)).await;
        assert!(r.is_err(), "early data must be absorbed by handshake, not written as frame");
    }

    /// 首写超 Ed：不带 early data，原包照常走帧写到对端。
    #[tokio::test]
    async fn delay_dial_first_write_over_ed_skips_early_data() {
        let record: DialRecord = Arc::default();
        let (factory, mut server) = recording_factory(record.clone(), Duration::ZERO);
        let mut conn = DelayDialConn::new(4, factory);
        let payload = [7u8; 10];
        conn.write_all(&payload).await.unwrap();
        assert_eq!(recorded(&record), vec![None]);
        let mut buf = [0u8; 10];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }

    /// Read 在未拨号时必须 Pending 且不触发拨号（Go dialer.go:204-210 select
    /// dialed/ctx 语义）；拨号由首次 Write 触发后，Read 读到连接数据。
    #[tokio::test]
    async fn delay_dial_read_waits_for_dial_then_receives() {
        use std::{future::poll_fn, task::Poll};

        let record: DialRecord = Arc::default();
        let (factory, mut server) = recording_factory(record.clone(), Duration::from_millis(30));
        // 预先从对端半边塞数据：停在 duplex 缓冲，拨号完成后立即可读。
        server.write_all(b"pong").await.unwrap();
        let mut conn = DelayDialConn::new(64, factory);

        // 未拨号时 Read：一次 poll 必须 Pending，且不得触发拨号。
        poll_fn(|cx| {
            let mut tmp = [0u8; 4];
            let mut buf = tokio::io::ReadBuf::new(&mut tmp);
            assert!(matches!(Pin::new(&mut conn).poll_read(cx, &mut buf), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        assert!(recorded(&record).is_empty(), "read must not trigger dialing");

        // 首写触发拨号（≤ Ed → 进握手头），完成后 Read 读到预填数据。
        let n = conn.write(b"x".as_slice()).await.unwrap();
        assert_eq!(n, 1);
        let mut buf = [0u8; 4];
        let rx = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("read must complete once dial finishes")
            .unwrap();
        assert_eq!(&buf[..rx], b"pong");
        assert_eq!(recorded(&record), vec![Some(b"x".to_vec())]);
    }

    /// 未拨号 shutdown：不拨号、直接闭合，后续 Write 报 BrokenPipe（Go ErrClosedPipe）。
    #[tokio::test]
    async fn delay_dial_shutdown_before_dial_aborts_and_rejects_write() {
        let record: DialRecord = Arc::default();
        let (factory, _server) = recording_factory(record.clone(), Duration::ZERO);
        let mut conn = DelayDialConn::new(64, factory);
        conn.shutdown().await.unwrap();
        assert!(recorded(&record).is_empty(), "shutdown must not dial");
        let err = conn.write(b"x".as_slice()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
