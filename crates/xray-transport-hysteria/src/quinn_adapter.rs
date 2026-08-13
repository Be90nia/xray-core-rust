//! quinn → hysteria trait 适配器。
//!
//! 把 quinn 0.11 的 `Connection` / `SendStream` / `RecvStream` 包装为
//! [`crate::conn::QuicConn`] / [`crate::conn::QuicStream`]，让 hysteria
//! 的 interConn / UdpSessionManager 状态机直接复用 quinn QUIC 栈。
//!
//! ## 切片边界（5lb 切片1a）
//!
//! 本模块只做"trait 适配"——QuicConn/QuicStream 接口实现。**不含**：
//! - HysteriaTransport（dial_and_authenticate 的 QUIC 拨号 + h3 auth 握手）—— 切片1b
//! - CongestionControl → quinn_proto::congestion::Controller 适配 —— 切片1c
//!
//! ## quinn datagram 注意
//!
//! quinn 0.11 的 `datagram` feature 是 unstable（默认关闭）。已在 workspace
//! Cargo.toml 启用。`connection.send_datagram` / `read_datagram` 才可用。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::sync::Mutex;

use crate::conn::{QuicConn, QuicStream};

/// quinn 双向 stream 包装为 [`QuicStream`]。
///
/// quinn 的 bi stream 拆成 `SendStream` + `RecvStream` 两个独立半边，
/// 我们组合起来对应 hysteria 的单一 `QuicStream` 抽象。
pub struct QuinnQuicStream {
    send: Mutex<SendStream>,
    recv: Mutex<RecvStream>,
    local: SocketAddr,
    remote: SocketAddr,
}

impl std::fmt::Debug for QuinnQuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnQuicStream")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl QuinnQuicStream {
    /// 构造。地址字段由调用方从 [`quinn::Connection`] 取后传入。
    #[must_use]
    pub fn new(
        send: SendStream,
        recv: RecvStream,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            local,
            remote,
        }
    }
}

impl QuicStream for QuinnQuicStream {
    fn read<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut recv = self.recv.lock().await;
            match recv.read(buf).await {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream ended")),
                Err(quinn::ReadError::Reset(code)) => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("stream reset: {code}"),
                )),
                Err(e) => Err(io::Error::other(format!("quinn read: {e}"))),
            }
        })
    }

    fn write<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut send = self.send.lock().await;
            match send.write(buf).await {
                Ok(n) => Ok(n),
                Err(quinn::WriteError::Stopped(code)) => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("stream stopped: {code}"),
                )),
                Err(e) => Err(io::Error::other(format!("quinn write: {e}"))),
            }
        })
    }

    fn cancel_read(&self, code: u64) {
        // quinn reset code 是 VarInt，u64 可能溢出——按 quinn 约定截断。
        let code = VarInt::try_from(code).unwrap_or(VarInt::MAX);
        // ponytail: try_lock 在已锁状态返回 Err，cancel 是尽力语义——跳过即可
        if let Ok(mut recv) = self.recv.try_lock() {
            let _ = recv.stop(code);
        }
    }

    fn close(&self) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>> {
        // ponytail: trait 签名不带 'a（future 必须 'static），stream 关闭由调用方
        // drop Arc<QuinnQuicStream> 时自动 finish SendStream/RecvStream 完成。
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

/// quinn `Connection` 包装为 [`QuicConn`]。
pub struct QuinnQuicConn {
    conn: Connection,
    /// quinn endpoint（client 端必须持有，否则 endpoint drop 会关闭 QUIC 连接；
    /// server 端 endpoint 由 QuinnQuicListener 管理，此处为 None）。
    #[allow(dead_code)]
    endpoint: Option<quinn::Endpoint>,
    /// h3 客户端 driver + SendRequest 持有项（仅 client 认证后注入）。
    ///
    /// h3 的 `Connection`（driver）持有 control/QPACK stream 状态；`SendRequest::drop` 在
    /// 成为最后一个 sender 时会发起 `H3_NO_ERROR` 关闭整条 QUIC 连接。hysteria 认证后要用
    /// 同一条 QUIC 连接开 raw bidi stream，因此把 driver 和一份不 drop 的 `SendRequest`
    /// 挂在 conn 上保活，直到 conn 本身 drop。
    h3_keepalive: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl std::fmt::Debug for QuinnQuicConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnQuicConn")
            .field("local", &self.conn.local_ip())
            .field("remote", &self.conn.remote_address())
            .finish_non_exhaustive()
    }
}

impl QuinnQuicConn {
    #[must_use]
    pub fn new(conn: Connection) -> Self {
        Self { conn, endpoint: None, h3_keepalive: None }
    }

    /// 注入 endpoint（client 拨号后调用，保活 endpoint）。
    pub(crate) fn with_endpoint(mut self, endpoint: quinn::Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// 注入 h3 保活项（client 认证成功后调用）。
    pub(crate) fn with_h3_keepalive(mut self, keepalive: Box<dyn std::any::Any + Send + Sync>) -> Self {
        self.h3_keepalive = Some(keepalive);
        self
    }

    /// 暴露内部 quinn::Connection 引用（供上层 transport adapter 用）。
    #[must_use]
    pub fn inner(&self) -> &Connection {
        &self.conn
    }
}





impl QuicConn for QuinnQuicConn {
    fn send_datagram<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.conn
                .send_datagram(bytes::Bytes::copy_from_slice(data))
                .map_err(|e| io::Error::other(format!("quinn send_datagram: {e}")))
        })
    }

    fn receive_datagram(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Vec<u8>>> + Send>> {
        // ponytail: trait 签名不带 'a（返回 Future + Send），所以 future 不能借用 self
        // 需要 Arc<Connection>——但我们只持 &self。改用 raw pointer + unsafe 不安全
        // 实际方案：trait 签名可能设计有问题，应该带 'a
        // 暂时方案：用 spawn + channel，但太复杂
        // 改方案：trait 修正为带 'a
        // 但 trait 修改影响范围大，先用 Arc 克隆
        // 实际上 quinn::Connection 内部是 Arc，clone 廉价
        let conn = self.conn.clone();
        Box::pin(async move {
            let data = conn
                .read_datagram()
                .await
                .map_err(|e| io::Error::other(format!("quinn read_datagram: {e}")))?;
            Ok(data.to_vec())
        })
    }

    fn close_with_error(&self, code: u64, reason: &str) {
        // quinn close code 是 VarInt
        let code = VarInt::try_from(code).unwrap_or(VarInt::MAX);
        self.conn.close(code, reason.as_bytes());
    }

    fn local_addr(&self) -> SocketAddr {
        // quinn::Connection::local_ip 返回 Option<IpAddr>，端口需要从外部记录
        // ponytail: hysteria 只用 local_addr 做日志，端口 0 足够
        let ip = self.conn.local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        SocketAddr::new(ip, 0)
    }

    fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    fn as_quinn_connection(&self) -> Option<&quinn::Connection> {
        Some(&self.conn)
    }
}

// ===== quinn TransportConfig 构建（拥塞控制 + QUIC 参数；client dialer + server listener 共用） =====

use std::time::Duration;
use crate::config;
use crate::dialer::QuicConfig;

/// 将 [`QuicConfig`] 转为 quinn [`quinn::TransportConfig`]。
///
/// 拥塞控制（对应 Go `quic.Config.CongestionControl`）：`congestion == "bbr"` →
/// quinn-proto BBR；其他（`""`、`"cubic"`、`"new_reno"`）→ 默认 CUBIC。
/// hysteria 协议默认 BBR（见 `QuicConfig::default_for_hysteria`）。
pub(crate) fn build_hysteria_transport_config(qc: &QuicConfig) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    if qc.max_idle_timeout_ms > 0 {
        if let Ok(v) = quinn::VarInt::try_from(qc.max_idle_timeout_ms) {
            t.max_idle_timeout(Some(quinn::IdleTimeout::from(v)));
        }
    }
    if qc.keep_alive_period_ms > 0 {
        t.keep_alive_interval(Some(Duration::from_millis(qc.keep_alive_period_ms)));
    }
    if qc.enable_datagrams {
        t.datagram_receive_buffer_size(Some(8192));
    }
    if qc.max_incoming_streams >= 0 {
        t.max_concurrent_bidi_streams(quinn::VarInt::try_from(qc.max_incoming_streams as u64).unwrap_or(quinn::VarInt::MAX));
    }
    // 拥塞控制选择
    match qc.congestion.to_ascii_lowercase().as_str() {
        "bbr" => {
            t.congestion_controller_factory(std::sync::Arc::new(
                quinn_proto::congestion::BbrConfig::default(),
            ));
        }
        "cubic" | "" | "new_reno" => {
            t.congestion_controller_factory(std::sync::Arc::new(
                quinn_proto::congestion::CubicConfig::default(),
            ));
        }
        _ => {
            // 未知类型回退默认（CUBIC），与 Go quic-go 未知回退一致。
            t.congestion_controller_factory(std::sync::Arc::new(
                quinn_proto::congestion::CubicConfig::default(),
            ));
        }
    }
    t
}

// ===== 切片1b (续): QuinnQuicListener + QuinnListenerFactory =====

use crate::hub::{HysteriaListenerFactory, HysteriaQuicListener};
use xray_proto::xray::transport::internet::QuicParams;
use crate::conn::InterStreamConn;

/// quinn Endpoint 包装为 [`HysteriaQuicListener`]。
pub struct QuinnQuicListener {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
}

impl QuinnQuicListener {
    #[must_use]
    pub fn new(endpoint: quinn::Endpoint) -> Option<Self> {
        let local_addr = endpoint.local_addr().ok()?;
        Some(Self { endpoint, local_addr })
    }
}

impl HysteriaQuicListener for QuinnQuicListener {
    fn accept(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Arc<dyn QuicConn>>> + Send>> {
        let ep = self.endpoint.clone();
        Box::pin(async move {
            let conn = ep.accept().await
                .ok_or_else(|| io::Error::other("listener closed"))?
                .await
                .map_err(|e| io::Error::other(format!("quinn accept: {e}")))?;
            let result: Arc<dyn QuicConn> = Arc::new(QuinnQuicConn::new(conn));
            Ok(result)
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn close(&self) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>> {
        let ep = self.endpoint.clone();
        Box::pin(async move {
            ep.close(VarInt::from_u32(0), b"");
            Ok(())
        })
    }
}

/// quinn 实现的 [`HysteriaListenerFactory`]。
///
/// 络定 UDP socket + ALPN `h3`，accept QUIC 连接。每条连接先做 h3 `/auth` 握手
/// （校验 `Hysteria-Auth` 头），通过后切换到 raw bidi stream 模式，将每个 stream
/// 经 `on_new_conn` 回调投递给上层。对应 Go `Listen()` + `http3.Server.ServeQUICConn`。
pub struct QuinnListenerFactory {
    rustls_server_config: Arc<rustls::ServerConfig>,
}

impl QuinnListenerFactory {
    #[must_use]
    pub fn new(rustls_server_config: Arc<rustls::ServerConfig>) -> Self {
        Self { rustls_server_config }
    }
}

impl HysteriaListenerFactory for QuinnListenerFactory {
    fn listen(
        &self,
        bind_addr: SocketAddr,
        _config: Arc<crate::proto_config::Config>,
        quic_params: Arc<QuicParams>,
        _masq: crate::hub::MasqType,
        validator: Option<Arc<dyn crate::hub::AuthValidator>>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    ) -> Pin<Box<dyn std::future::Future<Output = crate::error::Result<Arc<dyn HysteriaQuicListener>>> + Send>> {
        // ponytail: hysteria ALPN 固定 h3（与 client hysteria_transport::QuinnHysteriaTransport 对称）
        let mut rustls_config = (*self.rustls_server_config).clone();
        rustls_config.alpn_protocols = vec![b"h3".to_vec()];
        Box::pin(async move {
            let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("rustls→quic server: {e}"))))?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
            let qc = QuicConfig::from_params(&quic_params);
            server_config.transport_config(Arc::new(build_hysteria_transport_config(&qc)));
            let endpoint = quinn::Endpoint::server(server_config, bind_addr)
                .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("bind: {e}"))))?;

            // spawn accept loop：每个 QUIC conn → h3 auth → raw bidi streams → on_new_conn。
            // endpoint.close()（listener close）会让 accept 返回 None，循环自然退出。
            let ep = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = ep.accept().await {
                    let validator = validator.clone();
                    let on_new_conn = on_new_conn.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                serve_hysteria_connection(conn, validator, on_new_conn).await;
                            }
                            Err(e) => {
                                tracing::debug!(error = ?e, "hysteria quic handshake failed");
                            }
                        }
                    });
                }
            });

            let listener = QuinnQuicListener::new(endpoint)
                .ok_or_else(|| crate::error::HysteriaError::Io(io::Error::other("local_addr failed")))?;
            Ok(Arc::new(listener) as Arc<dyn HysteriaQuicListener>)
        })
    }
}

/// 服务单个 hysteria QUIC 连接：h3 `/auth` 握手 → raw bidi stream 循环。
///
/// 对应 Go `http3.Server.ServeQUICConn`（auth）+ `conn.AcceptStream`（data）。
async fn serve_hysteria_connection(
    conn: quinn::Connection,
    validator: Option<Arc<dyn crate::hub::AuthValidator>>,
    on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
) {
    let remote = conn.remote_address();
    let local = conn
        .local_ip()
        .map(|ip| SocketAddr::new(ip, 0))
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

    // Phase 1: h3 /auth 握手
    if !h3_auth(&conn, &validator).await {
        tracing::warn!(%remote, "hysteria auth failed, closing");
        conn.close(VarInt::from_u32(0), b"auth failed");
        return;
    }
    tracing::info!(%remote, "hysteria client authenticated");

    // Phase 2: raw bidi streams（FrameTypeTCPRequest 前缀由 InterStreamConn 处理）
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let qs = QuinnQuicStream::new(send, recv, local, remote);
                let isc = Arc::new(InterStreamConn::new(Arc::new(qs), local, remote, false));
                on_new_conn(isc);
            }
            Err(e) => {
                tracing::debug!(error = ?e, %remote, "hysteria bidi stream loop ended");
                break;
            }
        }
    }
}

/// h3 `/auth` 握手：accept 一个 HTTP/3 请求，校验 `Hysteria-Auth`，回应 233/403。
///
/// h3 server Connection 在函数内创建并使用。认证成功后，h3 server 的 Drop 会关闭
/// QUIC 连接（H3_NO_ERROR）——用 `std::mem::forget` 防止，保持连接存活以接收 raw data stream。
/// h3-quinn 的 incoming_bi 不会在认证结束后抢消费后续 bidi stream（stream::unfold 惰性，
/// 不调 accept 则不 poll）。详见 listener_factory_accept_bi_echo_roundtrip 测试验证。
async fn h3_auth(
    conn: &quinn::Connection,
    validator: &Option<Arc<dyn crate::hub::AuthValidator>>,
) -> bool {
    let h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = ?e, "h3 server init failed");
                return false;
            }
        };
    let mut h3_server = h3_server;
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut stream) = match resolver.resolve_request().await {
                    Ok(v) => v,
                    Err(_) => {
                        std::mem::forget(h3_server);
                        return false;
                    }
                };
                let is_auth = req.method() == http::Method::POST
                    && req.uri().path() == crate::config::URLPath;
                let auth_hdr = req
                    .headers()
                    .get(crate::config::RequestHeaderAuth)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let ok = if !is_auth {
                    false
                } else if let Some(v) = validator {
                    v.validate(auth_hdr).is_some()
                } else {
                    true
                };
                let status = if ok {
                    crate::config::StatusAuthOK
                } else {
                    403u16
                };
                let resp = http::Response::builder()
                    .status(status)
                    .header(crate::config::ResponseHeaderUDPEnabled, "rl")
                    .header(crate::config::CommonHeaderPadding, "0")
                    .body(());
                match resp {
                    Ok(r) => {
                        let _ = stream.send_response(r).await;
                        let _ = stream.finish().await;
                    }
                    Err(_) => {
                        std::mem::forget(h3_server);
                        return false;
                    }
                }
                if ok {
                    std::mem::forget(h3_server);
                    return true;
                }
            }
            Ok(None) => {
                std::mem::forget(h3_server);
                return false;
            }
            Err(e) => {
                tracing::debug!(error = ?e, "h3 accept ended");
                std::mem::forget(h3_server);
                return false;
            }
        }
    }
}


// ===== 切片1c: QuinnHttp3Server + DefaultRequestHandler + Salamander =====

use crate::hub::{AuthRequest, AuthResponse, HysteriaHttp3Server, HysteriaRequestHandler, MasqueradeHandler};
use std::collections::HashMap;

/// Salamander XOR 混淆（对应 Go `salamander.Salamander`）。
///
/// 将响应 body 与 key 循环 XOR。key 为空时不混淆。
pub fn salamander_obfuscate(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// h3 server 实现的 [`HysteriaHttp3Server`]。
pub struct QuinnHttp3Server;

impl HysteriaHttp3Server for QuinnHttp3Server {
    fn serve_quic_conn(
        &self,
        conn: Arc<dyn QuicConn>,
        handler: Arc<dyn HysteriaRequestHandler>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let quinn_conn = match conn.as_quinn_connection() {
                Some(c) => c.clone(),
                None => return,
            };
            let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn)).await {
                Ok(c) => c,
                Err(_) => return,
            };
            loop {
                match h3_conn.accept().await {
                    Ok(Some(resolver)) => {
                        let h = handler.clone();
                        tokio::spawn(async move {
                        let (req, mut stream) = match resolver.resolve_request().await {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                            let method = req.method().to_string();
                            let path = req.uri().path().to_string();
                            let host = req.uri().host().unwrap_or(config::URLHost).to_string();
                            let auth_header = req
                                .headers()
                                .get(config::RequestHeaderAuth)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let brutal_down = req
                                .headers()
                                .get(config::CommonHeaderCCRX)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0);
                            drop(req);

                            let auth_req = AuthRequest {
                                method: method.clone(),
                                host: host.clone(),
                                path: path.clone(),
                                auth_header: auth_header.clone(),
                                brutal_down_bps: brutal_down,
                            };

                            // 尝试 auth
                            if let Some(auth_resp) = h.try_auth(&auth_req).await {
                                let resp = http::Response::builder()
                                    .status(auth_resp.status_code)
                                    .header("Hysteria-UDP", if auth_resp.udp_enabled { "rl" } else { "" })
                                    .header(config::CommonHeaderPadding, &auth_resp.padding)
                                    .body(())
                                    .unwrap();
                                let _ = stream.send_response(resp).await;
                            } else {
                                // Masquerade
                                let masq = h.masquerade();
                                let hdrs: HashMap<String, String> = HashMap::new();
                                let (status, headers, body) = masq.serve(&method, &path, &hdrs).await;
                                let mut builder = http::Response::builder().status(status);
                                for (k, v) in &headers {
                                    builder = builder.header(k.as_str(), v.as_str());
                                }
                                let resp = builder.body(()).unwrap();
                                let _ = stream.send_response(resp).await;
                                let _ = stream.send_data(bytes::Bytes::from(body)).await;
                            }
                            let _ = stream.finish().await;
                        });
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        })
    }
}

/// 默认请求处理器（对应 Go `httpHandler`）。
///
/// 路由：POST /auth → 验证 → 233/拒绝；其他 → masquerade handler。
pub struct DefaultRequestHandler {
    validator: Option<Arc<dyn crate::hub::AuthValidator>>,
    masq: Arc<dyn MasqueradeHandler>,
    on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    salamander_key: Vec<u8>,
}

impl DefaultRequestHandler {
    #[must_use]
    pub fn new(
        validator: Option<Arc<dyn crate::hub::AuthValidator>>,
        masq: Arc<dyn MasqueradeHandler>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
        salamander_key: Vec<u8>,
    ) -> Self {
        Self { validator, masq, on_new_conn, salamander_key }
    }
}

impl HysteriaRequestHandler for DefaultRequestHandler {
    fn try_auth(
        &self,
        req: &AuthRequest,
    ) -> Pin<Box<dyn std::future::Future<Output = Option<AuthResponse>> + Send>> {
        let validator = self.validator.clone();
        let req = req.clone();
        Box::pin(async move {
            if req.method != "POST" || req.path != config::URLPath {
                return None;
            }
            let validator = validator?;
            let user = validator.validate(&req.auth_header)?;
            // Auth OK → respond 233
            Some(AuthResponse {
                status_code: config::StatusAuthOK,
                udp_enabled: true,
                brutal_down_bps: req.brutal_down_bps,
                padding: "0".into(),
            })
        })
    }

    fn dispatch_tcp_stream(
        &self,
        stream: Arc<dyn QuicStream>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let on_new = self.on_new_conn.clone();
        Box::pin(async move {
            let conn = Arc::new(InterStreamConn::new(stream, local, remote, false));
            on_new(conn);
        })
    }

    fn masquerade(&self) -> Arc<dyn MasqueradeHandler> {
        self.masq.clone()
    }
}

#[cfg(test)]
mod masq_tests {
    use super::*;

    #[test]
    fn salamander_empty_key_noop() {
        let mut data = b"hello".to_vec();
        salamander_obfuscate(&mut data, b"");
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn salamander_xor_roundtrip() {
        let original = b"test data 123".to_vec();
        let key = b"secret";
        let mut data = original.clone();
        salamander_obfuscate(&mut data, key);
        assert_ne!(&data, &original, "XOR should change data");
        salamander_obfuscate(&mut data, key);
        assert_eq!(&data, &original, "double XOR should restore");
    }

    #[test]
    fn salamander_key_shorter_than_data() {
        let key = b"ab";
        let data = b"abcdef".to_vec();
        let mut encrypted = data.clone();
        salamander_obfuscate(&mut encrypted, key);
        // verify each byte: data[i] ^ key[i % 2]
        assert_eq!(encrypted[0], b'a' ^ b'a');
        assert_eq!(encrypted[1], b'b' ^ b'b');
        assert_eq!(encrypted[2], b'c' ^ b'a');
        assert_eq!(encrypted[3], b'd' ^ b'b');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
    }

    /// 辅助：构造一对 QuinnQuicConn 对接（loopback）。
    /// 返回 (client_conn, server_conn, server_endpoint)——endpoint 必须由调用方持有，
    /// 否则 drop 后连接进入 idle 关闭流程（30s 后 accept_bi 超时）。
    async fn make_loopback_conn_pair() -> (QuinnQuicConn, QuinnQuicConn, std::sync::Arc<quinn::Endpoint>) {
        ensure_crypto_provider();
        // 生成自签证书
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = cert.key_pair.serialize_der();
        let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
        let server_crypto = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls_cert], rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap())
            .unwrap();
        let server_crypto = Arc::new(server_crypto);

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        let server_endpoint = std::sync::Arc::new(
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap()
        );
        let server_addr = server_endpoint.local_addr().unwrap();

        // client config trust store
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert.cert.der().clone()).unwrap();
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        // ponytail: server_endpoint Arc 必须由调用方持有，否则 task 完成后 endpoint drop
        // → 所有 connection 进入 idle 关闭流程（accept_bi 30s 超时）
        let ep_for_task = std::sync::Arc::clone(&server_endpoint);
        let server_task = tokio::spawn(async move {
            let incoming = ep_for_task.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            QuinnQuicConn::new(conn)
        });

        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let client = QuinnQuicConn::new(client_conn);
        let server = server_task.await.unwrap();

        (client, server, server_endpoint)
    }

    #[tokio::test]
    async fn datagram_roundtrip() {
        let (client, server, _ep) = make_loopback_conn_pair().await;

        // client → server datagram
        client
            .send_datagram(b"hello hysteria")
            .await
            .expect("send");

        let received = server.receive_datagram().await.expect("recv");
        assert_eq!(received, b"hello hysteria");
    }

    #[tokio::test]
    async fn datagram_both_directions() {
        let (client, server, _ep) = make_loopback_conn_pair().await;

        client.send_datagram(b"c2s").await.unwrap();
        let s_recv = server.receive_datagram().await.unwrap();
        assert_eq!(s_recv, b"c2s");

        server.send_datagram(b"s2c").await.unwrap();
        let c_recv = client.receive_datagram().await.unwrap();
        assert_eq!(c_recv, b"s2c");
    }

    #[tokio::test]
    async fn remote_addr_populated_after_handshake() {
        // ponytail: quinn::Connection::local_ip 返 None/unspecified（端口不维护），
        // hysteria transport 只用 local_addr 做日志。仅验证 remote_addr 含真实 IP+端口。
        let (client, server, _ep) = make_loopback_conn_pair().await;
        assert_eq!(client.remote_addr().ip(), std::net::IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert_eq!(server.remote_addr().ip(), std::net::IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert_ne!(client.remote_addr().port(), 0);
        assert_ne!(server.remote_addr().port(), 0);
    }

    #[tokio::test]
    async fn close_with_error_no_panic() {
        let (client, _server, _ep) = make_loopback_conn_pair().await;
        client.close_with_error(0x100, "test close");
        // 不 panic 即通过
    }

    #[tokio::test]
    async fn stream_construct_via_trait() {
        // ponytail: stream roundtrip 需 quinn client/server endpoint 双向 accept_bi 调度，
        // current-thread runtime + idle_timeout(30s) 下易超时。stream 实际工作由
        // transport.open_stream 在 hysteria 切片1b 中接入。本测试仅验证 QuinnQuicStream
        // 构造不 panic + 地址字段正确。
        let (client, _server, _ep) = make_loopback_conn_pair().await;
        let (c_send, c_recv) = client.inner().open_bi().await.expect("open_bi");
        let stream = QuinnQuicStream::new(
            c_send, c_recv,
            client.local_addr(), client.remote_addr(),
        );
        assert_eq!(stream.local_addr(), client.local_addr());
        assert_eq!(stream.remote_addr(), client.remote_addr());
    }

    /// 集成测试：QuinnListenerFactory (server) ↔ QuinnHysteriaTransport (client) 全链路。
    ///
    /// 验证：UDP bind → QUIC accept → h3 /auth 握手 → raw bidi data stream → on_new_conn。
    /// client dial+auth 后 open_stream，server 经 on_new_conn 收到，echo 回包验证双向通信。
    #[tokio::test]
    async fn listener_factory_full_auth_and_stream_roundtrip() {
        use crate::hysteria_transport::QuinnHysteriaTransport;
        use crate::dialer::{DialDestination, HysteriaTransport};
        use std::sync::Arc;
        use tokio::sync::Notify;

        ensure_crypto_provider();

        // 自签证书
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        ).unwrap();
        let server_tls = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        // server: QuinnListenerFactory
        let factory = QuinnListenerFactory::new(Arc::new(server_tls));
        let proto_config = Arc::new(crate::proto_config::Config::default());
        let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
        let masq = crate::hub::MasqType::NotFound;
        struct TestValidator;
        impl crate::hub::AuthValidator for TestValidator {
            fn validate(&self, auth: &str) -> Option<String> {
                if auth == "test-secret" { Some("user".into()) } else { None }
            }
            fn count(&self) -> usize { 1 }
        }
        let validator: Option<Arc<dyn crate::hub::AuthValidator>> = Some(Arc::new(TestValidator));

        let (stream_tx, mut stream_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<InterStreamConn>>();
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(move |s| {
            let _ = stream_tx.send(s);
        });

        let listener = factory
            .listen("127.0.0.1:0".parse().unwrap(), proto_config, quic_params, masq, validator, on_new_conn)
            .await
            .expect("listen should succeed");
        let server_addr = listener.local_addr();

        // client: QuinnHysteriaTransport (insecure verifier for self-signed cert)
        let client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let transport = Arc::new(
            QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap()).expect("transport"),
        );

        // dial + auth
        let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();
        let conn = transport
            .dial_and_authenticate(&dest, &qc, "test-secret", 0)
            .await
            .expect("dial + auth should succeed");

        // open a data stream
        let stream = transport.open_stream(&conn).await.expect("open_stream");
        // client=false：纯 echo 验证 QUIC stream 双向通（FrameTypeTCPRequest 前缀由 conn.rs 单测覆盖）
        let isc = Arc::new(InterStreamConn::new(stream, conn.local_addr(), conn.remote_addr(), false));

        // quinn 0.11 的 open_bi 是 lazy 的——STREAM frame 延迟到首次 write 才发出。
        // 故 client 必须先 write 再等 on_new_conn，否则 server accept_bi 永不返回。
        // 真实 hysteria client 同样在 open 后立即写 FrameTypeTCPRequest+dest。
        let payload = b"hello hysteria!";
        isc.write(payload).await.expect("client write");

        // server 经 accept_bi 收到 stream → on_new_conn
        let server_isc = tokio::time::timeout(std::time::Duration::from_secs(10), stream_rx.recv())
            .await
            .expect("server should receive stream via on_new_conn")
            .expect("channel not empty");

        // echo: server reads → server writes back → client reads
        let mut buf = vec![0u8; payload.len()];
        server_isc.read(&mut buf).await.expect("server read");
        assert_eq!(&buf, payload, "server received client payload");
        server_isc.write(&buf).await.expect("server echo write");

        let mut got = vec![0u8; payload.len()];
        isc.read(&mut got).await.expect("client read echo");
        assert_eq!(&got, payload, "echo roundtrip through QUIC + h3 auth");

        let _ = listener.close().await;
    }

    /// NoVerifier: 接受任意服务端证书（仅测试用）。
    #[derive(Debug)]
    struct NoVerifier;
    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            ]
        }
}


}
