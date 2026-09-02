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
use xray_transport::finalmask::salamander::SalamanderObfuscator;

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
    /// 拥塞控制槽位（client 认证协商后热切换 CC 用；server 端不包装 QuinnQuicConn，
    /// slot 由 serve_hysteria_connection 直接持有）。
    cc_slot: Option<std::sync::Arc<crate::congestion::quinn_bridge::HysteriaCCSlot>>,
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
        Self { conn, endpoint: None, h3_keepalive: None, cc_slot: None }
    }

    /// 注入 endpoint（client 拨号后调用，保活 endpoint）。
    pub(crate) fn with_endpoint(mut self, endpoint: quinn::Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// 注入 CC 槽位（client 拨号时创建，auth 协商后热切换用）。
    pub(crate) fn with_cc_slot(
        mut self,
        slot: std::sync::Arc<crate::congestion::quinn_bridge::HysteriaCCSlot>,
    ) -> Self {
        self.cc_slot = Some(slot);
        self
    }

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

/// [`CongestionSetter`] 的 quinn conn 实现（m9j：client 侧 auth 后热切换 CC）。
///
/// quinn 无 post-handshake CC API，实际由 conn 创建时装好的可热切换 factory +
/// [`cc_slot`](QuinnQuicConn::with_cc_slot) 生效。
impl crate::congestion::utils::CongestionSetter for QuinnQuicConn {
    fn set_congestion_control(
        &self,
        cc: Box<dyn crate::congestion::types::CongestionControl>,
    ) {
        match &self.cc_slot {
            Some(slot) => slot.set_congestion_control(cc),
            None => tracing::warn!("QuinnQuicConn has no cc_slot, congestion control not set"),
        }
    }
}

// ===== quinn TransportConfig 构建（拥塞控制 + QUIC 参数；client dialer + server listener 共用） =====

use std::time::Duration;
use crate::config;
use crate::dialer::QuicConfig;

/// 将 [`QuicConfig`] 转为 quinn [`quinn::TransportConfig`] + CC 槽位。
///
/// 拥塞控制（对应 Go auth 后 `SetCongestionControl` switch）：预装可热切换工厂
/// （初始 quinn CUBIC），auth 握手后由调用方用返回的 [`HysteriaCCSlot`] 按
/// `apply_negotiated` 协商结果切换到 hysteria 自己的 Brutal/BBR。
/// （旧实现按 congestion 字段预选 quinn 内建 BBR/CUBIC 是错的——Go 从不预选。）
pub(crate) fn build_hysteria_transport_config(
    qc: &QuicConfig,
) -> (quinn::TransportConfig, std::sync::Arc<crate::congestion::quinn_bridge::HysteriaCCSlot>) {
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
    // 流量控制窗口（Go dialer.go:86-89 / hub.go:265-268 Initial*+Max* → quinn 单窗口取 max）
    let (stream_win, conn_win) = receive_windows(qc);
    if let Ok(v) = quinn::VarInt::try_from(stream_win) {
        t.stream_receive_window(v);
    }
    if let Ok(v) = quinn::VarInt::try_from(conn_win) {
        t.receive_window(v);
    }
    // 禁用路径 MTU 探测（Go dialer.go:92 / hub.go:271；Windows 上 Go 恒 false，仅显式配置生效）
    if qc.disable_path_mtu_discovery {
        t.mtu_discovery_config(None);
    }
    let slot = crate::congestion::quinn_bridge::install_swappable_cc(&mut t);
    (t, slot)
}

/// quic-go `Initial*ReceiveWindow`（初始信用）与 `Max*ReceiveWindow`（auto-tune 上限）
/// 二值在 quinn 合一为固定窗口——取 max 对齐 Go 稳态。
/// 返回 `(stream_window, connection_window)`。
pub(crate) fn receive_windows(qc: &QuicConfig) -> (u64, u64) {
    (
        qc.initial_stream_receive_window.max(qc.max_stream_receive_window),
        qc.initial_connection_receive_window.max(qc.max_connection_receive_window),
    )
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
    /// salamander UDP 混淆（对应 Go hub 侧 `UdpmaskManager.WrapPacketConnServer`，None = 不包装）。
    salamander: Option<Arc<SalamanderObfuscator>>,
}

impl QuinnListenerFactory {
    #[must_use]
    pub fn new(rustls_server_config: Arc<rustls::ServerConfig>) -> Self {
        Self { rustls_server_config, salamander: None }
    }

    /// 注入 salamander UDP 混淆（builder 风格，None = 不包装）。
    #[must_use]
    pub fn with_salamander(
        mut self,
        obfs: Option<Arc<SalamanderObfuscator>>,
    ) -> Self {
        self.salamander = obfs;
        self
    }
}

impl HysteriaListenerFactory for QuinnListenerFactory {
    fn listen(
        &self,
        bind_addr: SocketAddr,
        config: Arc<crate::proto_config::Config>,
        quic_params: Arc<QuicParams>,
        masq: crate::hub::MasqType,
        validator: Option<Arc<dyn crate::hub::AuthValidator>>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    ) -> Pin<Box<dyn std::future::Future<Output = crate::error::Result<Arc<dyn HysteriaQuicListener>>> + Send>> {
        // ponytail: hysteria ALPN 固定 h3（与 client hysteria_transport::QuinnHysteriaTransport 对称）
        let mut rustls_config = (*self.rustls_server_config).clone();
        rustls_config.alpn_protocols = vec![b"h3".to_vec()];
        let salamander = self.salamander.clone();
        // masq handler（对应 Go hub.go:210-254 listen 时 switch masqType 构造）+
        // 静态 auth token（Go hub.go:63-64 validator 缺席时 config.Auth 对比）
        let masq_handler = masq.build_handler();
        let static_auth = config.auth.clone();
        Box::pin(async move {
            let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("rustls→quic server: {e}"))))?;
            let mut template = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
            let qc = QuicConfig::from_params(&quic_params);
            // 模板 transport config（endpoint 级兜底；每连接 accept_with 时覆盖）。
            let (template_tc, _unused_slot) = build_hysteria_transport_config(&qc);
            template.transport_config(Arc::new(template_tc));
            // salamander：UDP socket 包 XOR 后经 abstract socket 交给 quinn
            // （对应 Go hub 侧 pktConn 包装后再 quic.Transport.Listen）
            let endpoint = match &salamander {
                Some(obfs) => crate::salamander_socket::SalamanderSocket::bind(obfs.clone(), bind_addr)
                    .await
                    .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("salamander bind: {e}"))))?
                    .server_endpoint(template.clone())
                    .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("bind: {e}"))))?,
                None => quinn::Endpoint::server(template.clone(), bind_addr)
                    .map_err(|e| crate::error::HysteriaError::Io(io::Error::other(format!("bind: {e}"))))?,
            };
            // spawn accept loop：每个 QUIC conn → h3 auth → CC 协商 → raw bidi streams → on_new_conn。
            // endpoint.close()（listener close）会让 accept 返回 None，循环自然退出。
            // CC：每连接独立 slot（quinn 无 post-handshake 换 CC API，用 accept_with
            // 给每个 incoming 配带独立 swappable factory 的 transport config）。
            let ep = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = ep.accept().await {
                    let validator = validator.clone();
                    let on_new_conn = on_new_conn.clone();
                    let quic_params = quic_params.clone();
                    let masq_handler = masq_handler.clone();
                    let static_auth = static_auth.clone();
                    let (tc, cc_slot) = build_hysteria_transport_config(&qc);
                    let mut server_config = template.clone();
                    server_config.transport_config(Arc::new(tc));
                    tokio::spawn(async move {
                        match incoming.accept_with(Arc::new(server_config)) {
                            Ok(connecting) => match connecting.await {
                                Ok(conn) => {
                                    serve_hysteria_connection(conn, validator, on_new_conn, quic_params, cc_slot, masq_handler, static_auth).await;
                                }
                                Err(e) => {
                                    tracing::debug!(error = ?e, "hysteria quic handshake failed");
                                }
                            },
                            Err(e) => {
                                tracing::debug!(error = ?e, "hysteria quic accept failed");
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
/// 服务单个 hysteria QUIC 连接：h3 `/auth` 握手 → CC 协商 → raw bidi stream 循环。
///
/// 对应 Go `http3.Server.ServeQUICConn`（auth + SetCongestionControl switch）+
/// `conn.AcceptStream`（data）。CC 协商（hub.go:75-86）：`down` 取请求
/// `Hysteria-CC-RX`（客户端下行容量），`UseBrutal(min(BrutalUp, down))`。
async fn serve_hysteria_connection(
    conn: quinn::Connection,
    validator: Option<Arc<dyn crate::hub::AuthValidator>>,
    on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    quic_params: Arc<QuicParams>,
    cc_slot: std::sync::Arc<crate::congestion::quinn_bridge::HysteriaCCSlot>,
    masq: Arc<dyn crate::hub::MasqueradeHandler>,
    static_auth: String,
) {
    let remote = conn.remote_address();
    let local = conn
        .local_ip()
        .map(|ip| SocketAddr::new(ip, 0))
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

    // Phase 1: h3 /auth 握手（返回客户端 CCRX 供 CC 协商）。
    // 非 auth 请求 / 密码错由 h3_auth 内 masquerade 应答（连接保持，Go hub.go:112-117）；
    // None 仅在 h3 层终结（客户端断开）时返回。
    let auth_down = match h3_auth(&conn, &validator, &quic_params, &masq, &static_auth).await {
        Some(down) => down,
        None => {
            tracing::debug!(%remote, "hysteria h3 auth phase ended without auth");
            conn.close(VarInt::from_u32(0), b"");
            return;
        }
    };
    tracing::info!(%remote, "hysteria client authenticated");

    // Phase 1.5: CC 协商（Go hub.go:75-86 switch）
    if let Err(e) = crate::congestion::quinn_bridge::apply_negotiated(
        &cc_slot,
        &quic_params.congestion,
        &quic_params.bbr_profile,
        quic_params.brutal_up,
        auth_down,
    ) {
        tracing::warn!(error = %e, %remote, "hysteria congestion negotiation failed, keeping default");
    }

    // Phase 2: raw bidi streams（FrameTypeTCPRequest 前缀由 InterStreamConn 处理）
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let qs = QuinnQuicStream::new(send, recv, local, remote);
                let frame_type = match crate::conn::read_varint_stream(&qs).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(error = ?error, %remote, "hysteria stream frame type read failed");
                        continue;
                    }
                };
                if frame_type != crate::config::FrameTypeTCPRequest {
                    let _ = qs.cancel_read(0x101);
                    continue;
                }
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

/// h3 请求处理：auth 判定 + masquerade 分发（对应 Go `httpHandler.ServeHTTP` hub.go:112-117）。
///
/// 每个请求先过 AuthHTTP 判定（Go hub.go:44：POST + :authority=="hysteria" +
/// path=="/auth"）；通过 → 233 + `Hysteria-*` 头，成功返回 `Some(客户端 CCRX)`
/// （Go hub.go:66 供 UseBrutal(min(BrutalUp, down)) 协商）。
/// 不通过（非 auth 请求或密码错，Go hub.go:67 user==nil 时直接 false）→ masq handler
/// 应答并继续循环（连接保持）。None 仅在 h3 层 accept 终结时返回。
///
/// h3 server Connection 在函数内创建并使用。认证成功后，h3 server 的 Drop 会关闭
/// QUIC 连接（H3_NO_ERROR）——用 `std::mem::forget` 防止，保持连接存活以接收 raw data stream。
/// h3-quinn 的 incoming_bi 不会在认证结束后抢消费后续 bidi stream（stream::unfold 惰性，
/// 不调 accept 则不 poll）。详见 listener_factory_accept_bi_echo_roundtrip 测试验证。
async fn h3_auth(
    conn: &quinn::Connection,
    validator: &Option<Arc<dyn crate::hub::AuthValidator>>,
    quic_params: &QuicParams,
    masq: &Arc<dyn crate::hub::MasqueradeHandler>,
    static_auth: &str,
) -> Option<u64> {
    let h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = ?e, "h3 server init failed");
                return None;
            }
        };
    let mut h3_server = h3_server;
    /// wire 错误短路（须在 h3_server 绑定后定义，宏卫生）。
    macro_rules! bail {
        () => {{
            std::mem::forget(h3_server);
            return None;
        }};
    }
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut stream) = match resolver.resolve_request().await {
                    Ok(v) => v,
                    Err(_) => bail!(),
                };
                let method = req.method().as_str().to_string();
                let path = req.uri().path().to_string();
                // Go hub.go:44 r.Host == URLHost —— h3 的 :authority 伪头。
                let host = req
                    .uri()
                    .authority()
                    .map(|a| a.host().to_string())
                    .unwrap_or_default();
                let auth_hdr = req
                    .headers()
                    .get(crate::config::RequestHeaderAuth)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                // 客户端下行容量（Go hub.go:66 请求头 CCRX → UseBrutal 的 down）。
                let client_down = req
                    .headers()
                    .get(crate::config::CommonHeaderCCRX)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let req_headers: HashMap<String, String> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            v.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect();
                drop(req);

                let is_auth = method == "POST"
                    && host == crate::config::URLHost
                    && path == crate::config::URLPath;
                // Go hub.go:61-65：validator 非空且 count>0 → 查表；否则 config.Auth
                // 非空 → 静态比对；两者皆无 → false（安全侧：拒绝）。
                let ok = if !is_auth {
                    false
                } else {
                    match validator {
                        Some(v) if v.count() > 0 => v.validate(&auth_hdr).is_some(),
                        _ if !static_auth.is_empty() => auth_hdr == static_auth,
                        _ => false,
                    }
                };

                if ok {
                    // Go hub.go:49-53/102-105：233 + Hysteria-* 头
                    let resp = http::Response::builder()
                        .status(crate::config::StatusAuthOK)
                        .header(crate::config::ResponseHeaderUDPEnabled, "true")
                        // Go hub.go:51 本端 BrutalDown（客户端协商 UseBrutal 的 down）。
                        .header(crate::config::CommonHeaderCCRX, quic_params.brutal_down.to_string())
                        .header(crate::config::CommonHeaderPadding, "0")
                        .body(());
                    match resp {
                        Ok(r) => {
                            let _ = stream.send_response(r).await;
                            let _ = stream.finish().await;
                        }
                        Err(_) => bail!(),
                    }
                    std::mem::forget(h3_server);
                    return Some(client_down);
                }

                // masquerade（Go hub.go:112-117：AuthHTTP false → masqHandler.ServeHTTP）
                let (status, headers, body) = masq.serve(&method, &path, &req_headers).await;
                let mut builder = http::Response::builder().status(status);
                for (k, v) in &headers {
                    builder = builder.header(k.as_str(), v.as_str());
                }
                match builder.body(()) {
                    Ok(r) => {
                        let _ = stream.send_response(r).await;
                        if !body.is_empty() {
                            let _ = stream.send_data(bytes::Bytes::from(body)).await;
                        }
                        let _ = stream.finish().await;
                    }
                    Err(_) => bail!(),
                }
                // 连接保持，继续处理后续请求（Go h3 server 持续 serve）
            }
            Ok(None) => bail!(),
            Err(e) => {
                tracing::debug!(error = ?e, "h3 accept ended");
                bail!();
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
                                    // Go strconv.FormatBool——"true"/"false"，非 "rl"
                                    .header("Hysteria-UDP", if auth_resp.udp_enabled { "true" } else { "false" })
                                    .header(config::CommonHeaderCCRX, auth_resp.brutal_down_bps.to_string())
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

    /// quicParams 全字段 → `QuicConfig` → 窗口/keepalive/MTU 决策（Go dialer.go:85-115 /
    /// hub.go:264-294 对齐；quinn 无 getter，断言决策纯函数 + build 不 panic）。
    #[test]
    fn transport_config_maps_all_quic_fields() {
        use xray_proto::xray::transport::internet::QuicParams;
        let qp = QuicParams {
            congestion: "bbr".into(),
            bbr_profile: "aggressive".into(),
            brutal_up: 13_107_200,
            init_stream_receive_window: 16_384,
            max_stream_receive_window: 65_536,
            init_conn_receive_window: 32_768,
            max_conn_receive_window: 131_072,
            max_idle_timeout: 45,
            keep_alive_period: 15,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 64,
            ..QuicParams::default()
        };
        let qc = QuicConfig::from_params(&qp);
        // 秒 → 毫秒（Go time.Duration(quicParams.MaxIdleTimeout) * time.Second）
        assert_eq!(qc.max_idle_timeout_ms, 45_000);
        assert_eq!(qc.keep_alive_period_ms, 15_000);
        assert_eq!(qc.max_incoming_streams, 64);
        assert!(qc.disable_path_mtu_discovery);
        // CC 字段透传（auth 后 apply_negotiated 消费）
        assert_eq!(qc.congestion, "bbr");
        assert_eq!(qc.bbr_profile, "aggressive");
        assert_eq!(qc.brutal_up, 13_107_200);
        // quic-go Initial（初始信用）/ Max（auto-tune 上限）→ quinn 单固定窗口取 max
        assert_eq!(receive_windows(&qc), (65_536, 131_072));
        // build 不 panic（CC 槽位行为由 quinn_bridge 自测覆盖）
        let _ = build_hysteria_transport_config(&qc);
    }

    /// 默认 quicParams：窗口 8MiB / 20MiB（Go 8388608 与 8388608*5/2）。
    #[test]
    fn transport_config_default_windows() {
        let qc = QuicConfig::from_params(&xray_proto::xray::transport::internet::QuicParams::default());
        assert_eq!(receive_windows(&qc), (8_388_608, 20_971_520));
        assert!(!qc.disable_path_mtu_discovery);
        assert_eq!(qc.keep_alive_period_ms, 0, "Go keep-alive 默认关闭（dialer.go:113-115 注释）");
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

    /// 集成测试：salamander UDP 混淆下的 QUIC 全链路（bd Xray-core-rust-6op）。
    ///
    /// 两端 UDP socket 都包 `[8B salt][XOR(payload, BLAKE2b-256(PSK||salt))]`：
    /// QUIC 握手（Initial/Handshake）+ h3 /auth + bidi stream echo 全部过 XOR。
    /// 不带 obfs 的零行为变化由 `listener_factory_full_auth_and_stream_roundtrip` 钉死。
    #[tokio::test]
    async fn listener_factory_salamander_obfs_roundtrip() {
        use crate::hysteria_transport::QuinnHysteriaTransport;
        use crate::dialer::{DialDestination, HysteriaTransport};
        use crate::salamander_socket::parse_salamander_obfs;
        use xray_transport::finalmask::salamander::SalamanderObfuscator;
        use std::sync::Arc;

        ensure_crypto_provider();

        // finalmask JSON → obfuscator（两端同一 PSK，对齐 Go udpmaskManager 语义）
        let fm: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1"}}]}"#,
        )
        .unwrap();
        let obfs: Option<Arc<SalamanderObfuscator>> =
            parse_salamander_obfs(Some(&fm)).unwrap();
        assert!(obfs.is_some(), "salamander entry must produce an obfuscator");

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

        // server: 带 salamander 的 QuinnListenerFactory
        let factory = QuinnListenerFactory::new(Arc::new(server_tls))
            .with_salamander(obfs.clone());
        let proto_config = Arc::new(crate::proto_config::Config::default());
        let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
        struct ObfsValidator;
        impl crate::hub::AuthValidator for ObfsValidator {
            fn validate(&self, auth: &str) -> Option<String> {
                if auth == "obfs-secret" { Some("user".into()) } else { None }
            }
            fn count(&self) -> usize { 1 }
        }
        let validator: Option<Arc<dyn crate::hub::AuthValidator>> = Some(Arc::new(ObfsValidator));

        let (stream_tx, mut stream_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<InterStreamConn>>();
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(move |s| {
            let _ = stream_tx.send(s);
        });

        let listener = factory
            .listen(
                "127.0.0.1:0".parse().unwrap(),
                proto_config,
                quic_params,
                crate::hub::MasqType::NotFound,
                validator,
                on_new_conn,
            )
            .await
            .expect("listen with salamander should succeed");
        let server_addr = listener.local_addr();

        // client: 带 salamander 的 QuinnHysteriaTransport
        let client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let transport = Arc::new(
            QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
                .expect("transport")
                .with_salamander(obfs),
        );

        // dial + auth——QUIC 握手本身就在 salamander XOR 内完成
        let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "obfs-secret", 0),
        )
        .await
        .expect("dial+auth should not hang under salamander")
        .expect("dial + auth through salamander should succeed");

        // bidi stream echo（双向数据均过 XOR）
        let stream = transport.open_stream(&conn).await.expect("open_stream");
        let isc = Arc::new(InterStreamConn::new(stream, conn.local_addr(), conn.remote_addr(), false));
        let payload = b"salamander obfs echo!";
        isc.write(payload).await.expect("client write");

        let server_isc = tokio::time::timeout(std::time::Duration::from_secs(10), stream_rx.recv())
            .await
            .expect("server should receive stream via on_new_conn")
            .expect("channel not empty");

        let mut buf = vec![0u8; payload.len()];
        server_isc.read(&mut buf).await.expect("server read");
        assert_eq!(&buf, payload);
        server_isc.write(&buf).await.expect("server echo write");

        let mut got = vec![0u8; payload.len()];
        isc.read(&mut got).await.expect("client read echo");
        assert_eq!(&got, payload, "echo roundtrip through salamander-obfuscated QUIC");

        let _ = listener.close().await;
    }

    /// 集成测试：Brutal 拥塞协商全链路（m9j）。
    ///
    /// client brutal_up=5MB/s + server brutal_down=8MB/s → 响应 CCRX=8MB/s →
    /// `UseBrutal(min(5MB/s, 8MB/s))`；server 侧对称（请求 CCRX=3MB/s）。
    /// 验证协商代码路径（头解析 + apply_negotiated + adapter 热切换）不破坏
    /// 数据面。算法选择语义由 quinn_bridge 单测钉死。
    ///
    /// 带宽必须用现实量级：Brutal 窗口 = 2×bps×rtt，回环 RTT 亚毫秒下小带宽
    /// 会把窗口钳到 1 MTU（1200B）导致 quinn 发送停滞（Go quic-go 同数学）。
    #[tokio::test]
    async fn listener_factory_brutal_negotiation_roundtrip() {
        use crate::hysteria_transport::QuinnHysteriaTransport;
        use crate::dialer::{DialDestination, HysteriaTransport, QuicConfig};
        use std::sync::Arc;

        ensure_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        ).unwrap();
        let server_tls = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        let factory = QuinnListenerFactory::new(Arc::new(server_tls));
        let proto_config = Arc::new(crate::proto_config::Config::default());
        // server：congestion=""（默认 brutal 协商）+ brutal_up=9MB/s / brutal_down=8MB/s。
        let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams {
            congestion: String::new(),
            brutal_up: 9_000_000,
            brutal_down: 8_000_000,
            ..Default::default()
        });
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

        let client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let transport = Arc::new(
            QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap()).expect("transport"),
        );

        // client：brutal_up=5MB/s；请求头 CCRX（brutal_down_bps）=3MB/s。
        let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
        let qc = QuicConfig {
            congestion: String::new(),
            brutal_up: 5_000_000,
            bbr_profile: "standard".into(),
            ..QuicConfig::default_for_hysteria()
        };
        let conn = transport
            .dial_and_authenticate(&dest, &qc, "test-secret", 3_000_000)
            .await
            .expect("dial + auth should succeed");

        let stream = transport.open_stream(&conn).await.expect("open_stream");
        let isc = Arc::new(InterStreamConn::new(stream, conn.local_addr(), conn.remote_addr(), false));
        let payload = b"hello brutal!";
        isc.write(payload).await.expect("client write");

        let server_isc = tokio::time::timeout(std::time::Duration::from_secs(10), stream_rx.recv())
            .await
            .expect("server should receive stream via on_new_conn")
            .expect("channel not empty");

        let mut buf = vec![0u8; payload.len()];
        server_isc.read(&mut buf).await.expect("server read");
        server_isc.write(&buf).await.expect("server echo write");

        let mut got = vec![0u8; payload.len()];
        isc.read(&mut got).await.expect("client read echo");
        assert_eq!(&got, payload, "echo roundtrip with Brutal negotiated both sides");

        let _ = listener.close().await;
    }

    /// e2e masquerade（bd ect）：非 hysteria 的 h3 请求 → 伪装响应。
    ///
    /// 对齐 Go `hub.go:112-117` ServeHTTP：非 auth 请求（这里 GET /，:authority=
    /// localhost ≠ hysteria）→ masqHandler。响应 status/headers/body 为
    /// `MasqType::String` 配置原样；连接不关，第二个请求仍走 masq。
    #[tokio::test]
    async fn masquerade_serves_non_auth_h3_request() {
        use std::collections::HashMap;
        use std::sync::Arc;

        ensure_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        ).unwrap();
        let server_tls = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        let factory = QuinnListenerFactory::new(Arc::new(server_tls));
        let masq = crate::hub::MasqType::String {
            body: "fake website".into(),
            headers: HashMap::from([("X-Masq".to_string(), "1".to_string())]),
            status_code: 200,
        };
        struct MasqValidator;
        impl crate::hub::AuthValidator for MasqValidator {
            fn validate(&self, auth: &str) -> Option<String> {
                if auth == "secret" { Some("user".into()) } else { None }
            }
            fn count(&self) -> usize { 1 }
        }
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
        let listener = factory
            .listen(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(crate::proto_config::Config::default()),
                Arc::new(xray_proto::xray::transport::internet::QuicParams::default()),
                masq,
                Some(Arc::new(MasqValidator)),
                on_new_conn,
            )
            .await
            .expect("listen should succeed");
        let server_addr = listener.local_addr();

        // 普通 h3 客户端：GET /，无任何 hysteria 头
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        )));
        let conn = ep.connect(server_addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move { let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await; });

        async fn get_page(
            send_req: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
        ) -> (u16, Option<String>, Vec<u8>) {
            let req = http::Request::builder()
                .method("GET")
                .uri("https://localhost/")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            let resp = stream.recv_response().await.unwrap();
            let status = resp.status().as_u16();
            let x_masq = resp
                .headers()
                .get("X-Masq")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut body = Vec::new();
            use bytes::Buf as _;
            while let Some(chunk) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(chunk.chunk());
            }
            (status, x_masq, body)
        }

        let (status, x_masq, body) = get_page(&mut send_req).await;
        assert_eq!(status, 200, "非 auth 请求必须收到 masq 响应而非 403/断连");
        assert_eq!(x_masq.as_deref(), Some("1"));
        assert_eq!(body, b"fake website");

        // 同连接第二个请求：连接不因 masq 关闭（Go h3 server 持续 serve）
        let (status, _, body) = get_page(&mut send_req).await;
        assert_eq!((status, body.as_slice()), (200, &b"fake website"[..]));

        let _ = listener.close().await;
    }

    /// e2e masquerade（bd ect）：auth 密码错 → 伪装响应（非 403/断连）；
    /// 正确密码 auth → 233（正常 hysteria 流量不受 masquerade 影响）。
    ///
    /// 对齐 Go `hub.go:43-110`：AuthHTTP 校验失败不写响应直接 false → masqHandler；
    /// 校验通过 → 233 + Hysteria-* 头。
    #[tokio::test]
    async fn masquerade_covers_failed_auth_and_correct_auth_works() {
        use std::collections::HashMap;
        use std::sync::Arc;

        ensure_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        ).unwrap();
        let server_tls = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        let factory = QuinnListenerFactory::new(Arc::new(server_tls));
        let masq = crate::hub::MasqType::String {
            body: "masqueraded".into(),
            headers: HashMap::new(),
            status_code: 200,
        };
        struct MasqValidator2;
        impl crate::hub::AuthValidator for MasqValidator2 {
            fn validate(&self, auth: &str) -> Option<String> {
                if auth == "secret" { Some("user".into()) } else { None }
            }
            fn count(&self) -> usize { 1 }
        }
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
        let listener = factory
            .listen(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(crate::proto_config::Config::default()),
                Arc::new(xray_proto::xray::transport::internet::QuicParams::default()),
                masq,
                Some(Arc::new(MasqValidator2)),
                on_new_conn,
            )
            .await
            .expect("listen should succeed");
        let server_addr = listener.local_addr();

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        )));
        let conn = ep.connect(server_addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move { let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await; });

        // 错密码 POST /auth（hysteria 协议形态，:authority=hysteria）→ masq 响应
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", "wrong-password")
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "auth 密码错必须落 masq（非 233/403/断连）"
        );
        let mut body = Vec::new();
        use bytes::Buf as _;
        while let Some(chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(chunk.chunk());
        }
        assert_eq!(body, b"masqueraded");

        // 新连接：正确密码 auth → 233（正常 hysteria 流量不受影响）
        let conn2 = ep.connect(server_addr, "localhost").unwrap().await.unwrap();
        let (mut driver2, mut send_req2) =
            h3::client::new(h3_quinn::Connection::new(conn2)).await.unwrap();
        tokio::spawn(async move { let _ = std::future::poll_fn(|cx| driver2.poll_close(cx)).await; });
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", "secret")
            .header("Hysteria-CC-RX", "0")
            .body(())
            .unwrap();
        let mut stream = send_req2.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.recv_response(),
        )
        .await
        .expect("auth response should arrive")
        .unwrap();
        assert_eq!(resp.status().as_u16(), 233, "正确密码 auth → 233");
        assert_eq!(
            resp.headers().get("Hysteria-CC-RX").unwrap(),
            "0",
            "233 响应带 Hysteria-CC-RX（Go hub.go:103）"
        );

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
