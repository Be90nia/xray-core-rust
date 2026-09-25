//! Trojan 入站处理器（server），对应 Go `proxy/trojan/server.go`。
//!
//! ## 切片2（当前）
//!
//! 实现 [`TrojanServer`] impl `InboundHandler` + [`trojan_server_handshake`] 端到端验证。
//! Trojan 协议无握手响应——客户端发完 header 后直接发 payload，服务端验证 hash 后
//! 直接开始转发（切片2 仅验证 header 解析 + 用户校验，不转发）。
//!
//! ## 切片3 待实现
//!
//! - fallback（不合法用户重定向到 fallback dest）
//! - dispatch to outbound handler
//! - UDP ASSOCIATE
//! - TLS 包装层

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    sync::Mutex,
    task::JoinHandle,
};
use tracing::{debug, info, warn};
use xray_app_dispatcher::{OutboundHandlerManager, default::SimpleOhm};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::{
    address::Address, destination::Destination, network::Network as CommonNetwork, port::Port,
};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::{link::Link, system_listener::InboundTcpListener};

use crate::{
    fallback::FallbackPolicy,
    protocol::{CRLF, Network, addr_type, parse_udp_packet_stream, write_udp_packet},
    validator::{MemoryUser, Validator},
};

/// 包装流，记录所有读取字节用于 fallback 回放。
struct RecordingStream<S> {
    inner: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = dst.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, dst);
        let after = dst.filled().len();
        if after > before {
            this.buf.extend_from_slice(&dst.filled()[before..after]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Trojan 入站服务器。
///
/// `listener` 用 `tokio::sync::Mutex`（可跨 await 点持锁），与 socks 切片2 模式一致。
pub struct TrojanServer {
    /// Handler 标签（用于路由匹配）。
    tag: String,
    /// 用户验证器（共享）。
    validator: Arc<Validator>,
    /// Fallback 决策树（可选）。
    fallbacks: Option<Arc<FallbackPolicy>>,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消 accept().
    slot: Mutex<Option<(Arc<TcpListener>, JoinHandle<()>)>>,
}

impl TrojanServer {
    /// 创建新 Trojan 服务器。
    #[must_use]
    pub fn new(tag: impl Into<String>, validator: Arc<Validator>) -> Self {
        Self { tag: tag.into(), validator, fallbacks: None, slot: Mutex::new(None) }
    }

    /// 设置 fallback 决策树。
    #[must_use]
    pub fn with_fallbacks(mut self, fallbacks: Arc<FallbackPolicy>) -> Self {
        self.fallbacks = Some(fallbacks);
        self
    }

    /// Handler 标签。
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 用户验证器引用（用于 `add_user`/`remove_user`）。
    #[must_use]
    pub fn validator(&self) -> &Arc<Validator> {
        &self.validator
    }
}

#[async_trait::async_trait]
impl InboundHandler for TrojanServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let listener = Arc::new(
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "Trojan server started");

        let tag = self.tag.clone();
        let validator = self.validator.clone();
        let fallbacks = self.fallbacks.clone();
        // sm80④：独立 Handler 路径无装配层注入，SessionDefault 60s 兜底。
        let handshake_timeout = xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT;
        let listener_clone = Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener_clone.accept().await {
                    Ok((stream, peer)) => {
                        let tag = tag.clone();
                        let validator = validator.clone();
                        let fallbacks = fallbacks.clone();
                        tokio::spawn(async move {
                            let mut recorder =
                                RecordingStream { inner: stream, buf: Vec::with_capacity(256) };
                            match trojan_server_handshake(
                                &mut recorder,
                                &validator,
                                handshake_timeout,
                            )
                            .await
                            {
                                Ok((network, addr, port, user)) => {
                                    debug!(
                                        tag = %tag,
                                        peer = %peer,
                                        network = ?network,
                                        dest_addr = ?addr,
                                        dest_port = port,
                                        user = %user.email,
                                        "Trojan handshake succeeded"
                                    );
                                },
                                Err(e) => {
                                    warn!(tag = %tag, peer = %peer, error = %e, "Trojan handshake failed");
                                    if let Some(fb_policy) = &fallbacks {
                                        // ponytail: SNI/ALPN/path 来自 TLS
                                        // 层，当前未接线，用空字符串通配匹配
                                        if let Some(fb) = fb_policy.decide("", "", "") {
                                            if let Err(e) = do_fallback(
                                                recorder,
                                                &fb.dest,
                                                0,
                                                peer,
                                                std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                                            )
                                            .await
                                            {
                                                warn!(tag = %tag, peer = %peer, error = %e, "fallback failed");
                                            }
                                        }
                                    }
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
            info!(tag = %self.tag, "Trojan server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0
        0
    }
}

/// Trojan 服务端握手——读取并校验 Trojan 请求头。
///
/// 流程（首字节识别分叉，见 `protocol` 模块文档「trojan v2 草案」节）：
///
/// **v1**（首字节为小写 hex）：
/// 1. 读 56 字节 hex key（首字节已读）
/// 2. `Validator::get_by_key` 校验用户
/// 3. 读 2 字节 CRLF
/// 4. 读 1 字节 CMD (`Network`)
/// 5. 读 addr+port（SOCKS5 格式: ATYP + addr + 2 字节 BE port）
/// 6. 读 2 字节 CRLF
///
/// **v2 草案**（首字节 `0x02`）：
/// 1. 读 16 字节 `md5(password)`，`Validator::get_by_md5` 校验用户
/// 2. 读 addr+port（SOCKS5 格式，恒 TCP，无 cmd、无尾 CRLF）
///
/// 验证成功返回 `(network, addr, port, user)`，失败返回 `TrojanError`。
/// Trojan 协议无握手响应——调用方验证通过后直接开始双向转发。
///
/// # Errors
///
/// - `TrojanError::ReadUserHash`: 读 hex key 失败
/// - `TrojanError::UserNotFound`: 用户 hash 不在 validator 中
/// - `TrojanError::ReadCrlf`: CRLF 不匹配
/// - `TrojanError::ReadCommand`: CMD 非法
/// - `TrojanError::ReadAddressPort`: addr/port 解析失败
/// - `TrojanError::HandshakeTimeout`: 整段握手读超时（60s）
/// - `TrojanError::InvalidVersionPrefix`: 首字节非 v1 hex 且非 v2 `0x02`
pub async fn trojan_server_handshake<S>(
    stream: &mut S,
    validator: &Validator,
    // sm80④：policy Timeouts.Handshake（Go server.go::Process SetReadDeadline）
    handshake_timeout: std::time::Duration,
) -> crate::Result<(Network, Address, u16, MemoryUser)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    // Go `server.go::Process`：SetReadDeadline(Timeouts.Handshake) 限制整段握手
    // 读取；超时按握手失败处理（防静默连接占位，对齐 nginx client_header_timeout
    // 语义，见 features/policy/policy.go:125-133）。sm80④ 起由装配层注入。
    tokio::time::timeout(handshake_timeout, trojan_server_handshake_inner(stream, validator))
        .await
        .map_err(|_| crate::TrojanError::HandshakeTimeout)?
}

/// 从流中读取 SOCKS5 格式 addr+port（先读 ATYP 确定后续长度）。
///
/// v1 / v2 草案握手共用；对应 Go `addrParser.ReadAddressPort`。
async fn read_addr_port_from_stream<S>(stream: &mut S) -> crate::Result<(Address, u16)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    let mut atyp_buf = [0u8; 1];
    stream
        .read_exact(&mut atyp_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read atyp: {e}")))?;
    let atyp = atyp_buf[0];

    // 根据 ATYP 读取剩余 addr+port 字节
    let (addr, port) = match atyp {
        addr_type::IPV4 => {
            let mut buf = [0u8; 6]; // 4 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv4+port: {e}")))?;
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[0..4]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (Address::IPv4(std::net::Ipv4Addr::from(ip)), port)
        },
        addr_type::DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(|e| {
                crate::TrojanError::ReadAddressPort(format!("read domain len: {e}"))
            })?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2]; // domain + 2 port
            stream.read_exact(&mut buf).await.map_err(|e| {
                crate::TrojanError::ReadAddressPort(format!("read domain+port: {e}"))
            })?;
            let domain = String::from_utf8(buf[0..len].to_vec())
                .map_err(|_| crate::TrojanError::InvalidRemoteAddress)?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            (Address::Domain(domain), port)
        },
        addr_type::IPV6 => {
            let mut buf = [0u8; 18]; // 16 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv6+port: {e}")))?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[0..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), port)
        },
        _ => {
            return Err(crate::TrojanError::ReadAddressPort(format!("unknown atyp: {atyp:#x}")));
        },
    };
    Ok((addr, port))
}

/// 握手协议本体（无超时；超时由 [`trojan_server_handshake`] 统一包裹）。
async fn trojan_server_handshake_inner<S>(
    stream: &mut S,
    validator: &Validator,
) -> crate::Result<(Network, Address, u16, MemoryUser)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    // 1. 读首字节判协议版本：v1 hex key 起始 / v2 草案 0x02 / 其余拒绝（→ fallback）。 v1 key
    //    恒为小写 hex，首字节 ∈ 0x30-0x39 / 0x61-0x66，与 0x02 零冲突。
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|e| crate::TrojanError::ReadUserHash(format!("read version: {e}")))?;

    if first[0] == crate::protocol::V2_VERSION {
        // trojan v2 草案：[0x02][16B md5(password)][addr+port]，无 cmd、无尾 CRLF，恒 TCP。
        let mut md5_buf = [0u8; crate::protocol::MD5_KEY_LEN];
        stream
            .read_exact(&mut md5_buf)
            .await
            .map_err(|e| crate::TrojanError::ReadUserHash(format!("read md5 key: {e}")))?;
        let user = validator.get_by_md5(&md5_buf).ok_or(crate::TrojanError::UserNotFound)?;
        let (addr, port) = read_addr_port_from_stream(stream).await?;
        return Ok((Network::Tcp, addr, port, user));
    }
    if !crate::protocol::is_v1_hex_prefix(first[0]) {
        return Err(crate::TrojanError::InvalidVersionPrefix(first[0]));
    }

    // 2. v1：首字节即 56 字节 hex key 的第 1 字节，补读剩余 55 字节
    let mut key_buf = [0u8; 56];
    key_buf[0] = first[0];
    stream
        .read_exact(&mut key_buf[1..])
        .await
        .map_err(|e| crate::TrojanError::ReadUserHash(format!("read key: {e}")))?;

    // 3. 校验 key via Validator
    let user = validator.get_by_key(&key_buf).ok_or(crate::TrojanError::UserNotFound)?;

    // 4. 读 CRLF
    let mut crlf = [0u8; 2];
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read header crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!("expected CRLF, got {crlf:?}")));
    }

    // 5. 读 1 字节 CMD
    let mut cmd_buf = [0u8; 1];
    stream
        .read_exact(&mut cmd_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadCommand(format!("read cmd: {e}")))?;
    let network = Network::from_command(cmd_buf[0]);
    // 6. 读 addr+port（SOCKS5 格式，v1/v2 共用）
    let (addr, port) = read_addr_port_from_stream(stream).await?;

    // 7. 读结尾 CRLF
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read tail crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!("expected tail CRLF, got {crlf:?}")));
    }

    Ok((network, addr, port, user))
}

// ============================================================================
// do_fallback: handshake failure redirect
// ============================================================================

/// Replay recorded bytes + pipe remaining stream to fallback destination.
///
/// Corresponds to Go `proxy/trojan/server.go` fallback dial + `io.Copy` bridge.
async fn do_fallback<S>(
    recorder: RecordingStream<S>,
    dest: &str,
    xver: u8,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // PROXY header + 录制首字节回放 + 双向 pipe（xray_transport::fallback 公共实现）
    xray_transport::fallback::fallback_to_dest(
        recorder.inner,
        &recorder.buf,
        dest,
        peer,
        local,
        xver,
    )
    .await
}

// ============================================================================
// serve_trojan
// ============================================================================

/// Trojan inbound entry point (aligns with `xray_core::inbound::serve_socks5`).
pub async fn serve_trojan(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    users: HashMap<String, MemoryUser>,
    fallbacks: Option<Arc<FallbackPolicy>>,
    tls: Option<Arc<xray_transport::TlsAcceptor>>,
    // sm80④：装配层传 policy_for_level(level).timeout.handshake；测试可传短值。
    handshake_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    let validator = Arc::new(Validator::new());
    for (_, user) in users {
        if let Err(e) = validator.add(user) {
            warn!(error = %e, "skip duplicate user during serve_trojan init");
        }
    }

    info!(
        addr = %listener.local_addr()?,
        users = validator.get_key_count(),
        "trojan inbound listening"
    );

    let local = listener.local_addr()?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "trojan accept failed");
                continue;
            },
        };

        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let fb_policy = fallbacks.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Some(acc) = tls {
                match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        // fallback 路由需要 TLS 层 SNI/ALPN（Go：connectionState.ServerName /
                        // NegotiatedProtocol）
                        let conn = tls_stream.get_ref().1;
                        let name = conn.server_name().unwrap_or("").to_string();
                        let alpn = conn
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).into_owned())
                            .unwrap_or_default();
                        let recorder =
                            RecordingStream { inner: tls_stream, buf: Vec::with_capacity(256) };
                        handle_trojan_connection(
                            recorder,
                            validator,
                            handler,
                            fb_policy,
                            peer,
                            local,
                            name,
                            alpn,
                            handshake_timeout,
                        )
                        .await;
                    },
                    Err(e) => warn!(error = %e, "trojan TLS accept failed"),
                }
            } else {
                let recorder = RecordingStream { inner: stream, buf: Vec::with_capacity(256) };
                handle_trojan_connection(
                    recorder,
                    validator,
                    handler,
                    fb_policy,
                    peer,
                    local,
                    String::new(),
                    String::new(),
                    handshake_timeout,
                )
                .await;
            }
        });
    }
}

/// 处理单个已解包 Trojan 连接（transport listener 路径）。
///
/// 与 [`serve_trojan`] 每 conn 逻辑相同，但连接来自 transport 层
/// （ws/grpc/kcp 解包后），TLS 已在 transport hub 内终结——`tls_name`/
/// `tls_alpn` 传空（Go：非 `*tls.Conn` 同为空）。
#[allow(clippy::too_many_arguments)] // 与 serve_trojan 装配参数集一一对应
pub async fn serve_trojan_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    validator: Arc<Validator>,
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
    fb_policy: Option<Arc<FallbackPolicy>>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    tls_name: String,
    tls_alpn: String,
    // sm80④：policy Timeouts.Handshake
    handshake_timeout: std::time::Duration,
) {
    let recorder = RecordingStream { inner: stream, buf: Vec::with_capacity(256) };
    handle_trojan_connection(
        recorder,
        validator,
        handler,
        fb_policy,
        peer,
        local,
        tls_name,
        tls_alpn,
        handshake_timeout,
    )
    .await;
}

/// 处理单个 Trojan 连接：handshake → dispatch / fallback。
#[allow(clippy::too_many_arguments)] // handshake+fallback 装配参数集
async fn handle_trojan_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut recorder: RecordingStream<S>,
    validator: Arc<Validator>,
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
    fb_policy: Option<Arc<FallbackPolicy>>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    tls_name: String,
    tls_alpn: String,
    handshake_timeout: std::time::Duration,
) {
    match trojan_server_handshake(&mut recorder, &validator, handshake_timeout).await {
        Ok((network, addr, port, user)) => {
            if matches!(network, Network::Udp) {
                debug!(peer = %peer, user = %user.email, "trojan UDP relay start");
                handle_trojan_udp_relay(recorder.inner, handler).await;
                return;
            }
            let dest = Destination::new(addr, Port::new(port), CommonNetwork::TCP);
            let (read_half, write_half) = tokio::io::split(recorder.inner);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            debug!(peer = %peer, user = %user.email, dest = %dest, "trojan dispatching");
            // per-user stats（Go trojan/inbound 认证后 ctx 带 user 语义）：
            // from=客户端源地址，email/level=认证用户。
            let access = xray_app_dispatcher::AccessContext {
                from: peer.to_string(),
                email: user.email.clone(),
                level: user.level,
                ..Default::default()
            };
            let _ = handler.dispatch_with_access(&dest, link, access).await;
        },
        Err(e) => {
            warn!(peer = %peer, error = %e, "trojan handshake failed");
            if let Some(fb_policy) = &fb_policy {
                let path = xray_transport::fallback::extract_path_from_first_bytes(&recorder.buf)
                    .unwrap_or("");
                if let Some(fb) = fb_policy.decide(&tls_name, &tls_alpn, path) {
                    info!(peer = %peer, dest = %fb.dest, xver = fb.xver, name = %tls_name, alpn = %tls_alpn, path, "trojan fallback");
                    if let Err(e) =
                        do_fallback(recorder, &fb.dest, fb.xver as u8, peer, local).await
                    {
                        warn!(peer = %peer, error = %e, "fallback failed");
                    }
                }
            }
        },
    }
}
// ============================================================================
// UDP relay（UDP-over-TCP，经中央 dispatcher）
// ============================================================================

/// Trojan 入站 UDP relay（UDP-over-TCP），对应 Go `proxy/trojan/server.go::handleUDPPayload`。
///
/// 客户端握手后 TCP 流承载连续的 UDP 帧 `[addr+port][2B len][CRLF][payload]`。
/// 所有数据报经 [`UdpDispatchSession`] 走 dispatcher routing（域名目标原样
/// 交给 outbound 解析，freedom 会解析），不再 raw socket 直连：
/// - TCP 读分支：`parse_udp_packet_stream` 拆帧 → `Destination::udp` → `send_packet`
/// - dispatch 读分支：`recv_packet` → `write_udp_packet` 编码 → 回写客户端流
async fn handle_trojan_udp_relay<S>(
    stream: S,
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let mut session = xray_app_dispatcher::UdpDispatchSession::new(handler);
    let mut buf: Vec<u8> = Vec::with_capacity(16_384);
    let mut chunk = [0u8; 8192];

    loop {
        tokio::select! {
            r = read_half.read(&mut chunk) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                let mut consumed = 0usize;
                let mut fatal = false;
                loop {
                    match parse_udp_packet_stream(&buf[consumed..]) {
                        Ok(Some((addr, port, payload, used))) => {
                            consumed += used;
                            let dest = Destination::new(addr, Port::new(port), CommonNetwork::UDP);
                            if let Err(e) = session.send_packet(&dest, payload).await {
                                warn!(error = %e, dest = %dest, "trojan udp send_packet failed");
                            }
                        }
                        Ok(None) => break, // 数据不足，继续读
                        Err(e) => {
                            warn!(error = %e, "trojan udp parse fatal, aborting relay");
                            fatal = true;
                            break;
                        }
                    }
                }
                if consumed > 0 {
                    buf.drain(..consumed);
                }
                if fatal {
                    break;
                }
            }
            r = session.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        let mut packet = Vec::with_capacity(payload.len() + 32);
                        if write_udp_packet(
                            &mut packet,
                            source.address(),
                            source.port().value(),
                            &payload,
                        )
                        .is_err()
                        {
                            break;
                        }
                        if write_half.write_all(&packet).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break, // outbound 关闭 / 错误
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use xray_app_dispatcher::{
        DispatchHandler,
        default::{DialBridge, SimpleOhm},
    };
    use xray_common::net::address::Address;
    use xray_proxy_freedom::{FreedomDispatchBridge, make_freedom_dial_fn};

    use super::*;
    use crate::{
        config::{MemoryAccount, hex_sha224},
        protocol::{COMMAND_TCP, Network as TrojanNetwork, write_request_header},
    };

    fn make_validator_with_user(password: &str) -> Arc<Validator> {
        let validator = Arc::new(Validator::new());
        let account = MemoryAccount::new(password.to_string());
        let user = MemoryUser::new("user@example.com", 0, account);
        validator.add(user).unwrap();
        validator
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv4_succeeds() {
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test", validator.clone());
        server.start().await.unwrap();

        // 客户端构造完整 Trojan header
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key); // 56 字节 hex
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        // 连接并发送 header
        // 注意：TrojanServer start 绑定到随机端口，但我们不知道具体端口
        // 直接测试 trojan_server_handshake 函数
        let mut buf = header.clone();
        buf.extend_from_slice(b"payload data");
        let mut cursor = std::io::Cursor::new(buf);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_ok());
        let (network, addr, port, user) = result.unwrap();
        assert_eq!(network, Network::Tcp);
        match addr {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [127, 0, 0, 1]),
            _ => panic!("expected IPv4"),
        }
        assert_eq!(port, 80);
        assert_eq!(user.email, "user@example.com");

        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn handshake_invalid_user_fails() {
        let validator = make_validator_with_user("password");
        let bad_key = hex_sha224("wrong-password");
        let mut header = Vec::new();
        header.extend_from_slice(&bad_key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_err());
    }

    /// 静默客户端（握手半途不发数据）→ 整段握手读 60s 超时终止
    /// （Go SessionDefault().Timeouts.Handshake=60s；start_paused 自动推进挂钟）。
    #[tokio::test(start_paused = true)]
    async fn handshake_read_timeout_terminates() {
        let validator = make_validator_with_user("password");
        // client 端存活但不写任何字节 → read_exact 永等 → 60s deadline 触发
        let (_silent_client, mut server) = tokio::io::duplex(64);

        let started = std::time::Instant::now();
        let result = trojan_server_handshake(
            &mut server,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(
            matches!(result, Err(crate::TrojanError::HandshakeTimeout)),
            "silent client must hit handshake timeout, got {result:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "paused clock must auto-advance past the 60s deadline"
        );
    }

    #[tokio::test]
    async fn handshake_valid_user_domain_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::DOMAIN);
        let domain = b"example.com";
        header.push(domain.len() as u8);
        header.extend_from_slice(domain);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_ok());
        let (_, addr, port, _) = result.unwrap();
        match addr {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("expected Domain"),
        }
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv6_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV6);
        let v6 = std::net::Ipv6Addr::LOCALHOST;
        header.extend_from_slice(&v6.octets());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_ok());
        let (_, addr, _, _) = result.unwrap();
        match addr {
            Address::IPv6(v6) => assert_eq!(v6, std::net::Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[tokio::test]
    async fn handshake_truncated_key_fails() {
        let validator = make_validator_with_user("password");
        // 只提供 10 字节（不够 56）
        let short = vec![0u8; 10];
        let mut cursor = std::io::Cursor::new(short);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_truncated_header_after_valid_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        // 缺少 CRLF + CMD + addr
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_invalid_crlf_after_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(b"XX"); // 不是 CRLF
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_unknown_atyp_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(0x05); // 未知 ATYP
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop abort，端口释放
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test-close", validator);
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
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), TcpStream::connect(&addr))
                .await;
        if let Ok(Ok(_)) = result {
            panic!("listener should be closed after close()");
        }
    }

    /// 端到端：trojan client → trojan inbound (serve_trojan) → freedom outbound → echo server。
    ///
    /// 与 socks5 e2e 同模式：验证 accept → handshake → dispatch → echo 回环。
    #[tokio::test]
    async fn serve_trojan_dispatches_to_echo_via_freedom() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    },
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = Arc::new(DialBridge::new("freedom", dial_fn)) as Arc<dyn DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 构造用户表：password → MemoryUser，HashMap key = user.key_hash()
        let account = MemoryAccount::new("password");
        let user = MemoryUser::new("echo-test@example.com", 0, account.clone());
        let mut users = HashMap::new();
        users.insert(user.key_hash(), user);

        // 4. 起 trojan inbound
        let trojan_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let trojan_addr = trojan_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_trojan(
                trojan_listener,
                ohm_clone,
                users,
                None,
                None,
                xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await;
        });

        // 5. trojan client：构造 header + payload
        let mut client = TcpStream::connect(trojan_addr).await.unwrap();
        let dest_addr = Address::IPv4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let mut header = Vec::new();
        write_request_header(
            &mut header,
            &account,
            TrojanNetwork::Tcp,
            &dest_addr,
            echo_addr.port(),
        )
        .unwrap();
        let payload = b"hello trojan proxy!";
        header.extend_from_slice(payload);
        client.write_all(&header).await.unwrap();

        // 6. 读 echo（跳过可能的 0 字节，读到 payload 长度）
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through trojan proxy");
    }

    /// 计数装饰器：证明 UDP 帧经 DispatchHandler 走 routing 而非 raw socket 直连。
    #[derive(Debug)]
    struct CountingDispatch {
        inner: Arc<dyn DispatchHandler>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DispatchHandler for CountingDispatch {
        fn tag(&self) -> &str {
            "counting-freedom"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let inner = Arc::clone(&self.inner);
            let calls = Arc::clone(&self.calls);
            let dest = dest.clone();
            Box::pin(async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                inner.dispatch(&dest, link).await;
            })
        }
    }

    /// 端到端：trojan UDP relay → 中央 dispatcher → freedom → UDP echo server。
    ///
    /// 验证 bd b2e：UDP 帧不再 raw socket 直连，而是经 `DispatchHandler`
    /// 走 routing（calls 计数断言 dispatch link 真实建立）。
    #[tokio::test]
    async fn serve_trojan_udp_relay_dispatches_via_freedom() {
        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], src).await;
            }
        });

        // 2. dispatcher：freedom（TCP+UDP dispatch）外裹计数器
        let ohm = Arc::new(SimpleOhm::new());
        let freedom = Arc::new(FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new(
            "freedom",
            make_freedom_dial_fn(),
        ))));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = Arc::new(CountingDispatch { inner: freedom, calls: Arc::clone(&calls) })
            as Arc<dyn DispatchHandler>;
        ohm.set_default(counting);

        // 3. trojan inbound
        let account = MemoryAccount::new("password");
        let user = MemoryUser::new("udp-test@example.com", 0, account.clone());
        let mut users = HashMap::new();
        users.insert(user.key_hash(), user);
        let trojan_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let trojan_addr = trojan_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_trojan(
                trojan_listener,
                ohm_clone,
                users,
                None,
                None,
                xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await;
        });

        // 4. client：UDP 模式 header + 一帧指向 echo server
        let mut client = TcpStream::connect(trojan_addr).await.unwrap();
        let dest_addr = Address::IPv4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let mut req = Vec::new();
        write_request_header(&mut req, &account, TrojanNetwork::Udp, &dest_addr, echo_addr.port())
            .unwrap();
        let payload = b"udp via dispatch";
        write_udp_packet(&mut req, &dest_addr, echo_addr.port(), payload).unwrap();
        client.write_all(&req).await.unwrap();

        // 5. 读回包帧（echo 经 freedom XUDP 回来）
        let (raddr, rport, rpayload) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    if let Ok(Some((a, p, pl, _))) = crate::protocol::parse_udp_packet_stream(&buf)
                    {
                        return (a, p, pl.to_vec());
                    }
                    let n = client.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "client stream closed before udp response");
                    buf.extend_from_slice(&chunk[..n]);
                }
            })
            .await
            .expect("udp response within 5s");

        assert_eq!(rpayload, payload);
        assert_eq!(raddr, dest_addr);
        assert_eq!(rport, echo_addr.port());
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "udp relay must go through dispatcher"
        );
    }
    // ========================================================================
    // trojan v2 草案握手
    // ========================================================================

    fn v2_header(password: &str, addr_bytes: &[u8], atyp: u8, port: u16) -> Vec<u8> {
        let mut header = vec![crate::protocol::V2_VERSION];
        header.extend_from_slice(&crate::config::md5_key(password));
        header.push(atyp);
        header.extend_from_slice(addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());
        header
    }

    /// v2 草案握手（IPv4）：恒 TCP、无 cmd、无尾 CRLF，payload 从 header 末尾起。
    #[tokio::test]
    async fn handshake_v2_ipv4_succeeds() {
        let validator = make_validator_with_user("password");
        let mut buf = v2_header("password", &[127, 0, 0, 1], addr_type::IPV4, 8080);
        buf.extend_from_slice(b"payload");
        let mut cursor = std::io::Cursor::new(buf);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        let (network, addr, port, user) = result.expect("v2 handshake must succeed");
        assert_eq!(network, Network::Tcp);
        match addr {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [127, 0, 0, 1]),
            _ => panic!("expected IPv4"),
        }
        assert_eq!(port, 8080);
        assert_eq!(user.email, "user@example.com");
        // payload 紧跟 header（无尾 CRLF）：buffer 位置 = header 长度
        assert_eq!(cursor.position(), 1 + 16 + 1 + 4 + 2);
    }

    /// v2 草案握手（Domain 目标）。
    #[tokio::test]
    async fn handshake_v2_domain_succeeds() {
        let validator = make_validator_with_user("password");
        let mut header = vec![crate::protocol::V2_VERSION];
        header.extend_from_slice(&crate::config::md5_key("password"));
        header.push(addr_type::DOMAIN);
        header.push(b"example.com".len() as u8);
        header.extend_from_slice(b"example.com");
        header.extend_from_slice(&443u16.to_be_bytes());
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        let (_, addr, port, _) = result.expect("v2 domain handshake must succeed");
        match addr {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("expected Domain"),
        }
        assert_eq!(port, 443);
    }

    /// v1/v2 识别分叉：同一 validator、同一密码，v1 头与 v2 头都握手成功
    /// 且解析出同一用户。
    #[tokio::test]
    async fn handshake_v1_v2_same_validator_fork() {
        let validator = make_validator_with_user("password");

        // v1 头
        let mut v1 = Vec::new();
        v1.extend_from_slice(&hex_sha224("password"));
        v1.extend_from_slice(&CRLF);
        v1.push(COMMAND_TCP);
        v1.push(addr_type::IPV4);
        v1.extend_from_slice(&[10, 0, 0, 1]);
        v1.extend_from_slice(&1u16.to_be_bytes());
        v1.extend_from_slice(&CRLF);

        // v2 头
        let v2 = v2_header("password", &[10, 0, 0, 2], addr_type::IPV4, 2);

        let r1 = trojan_server_handshake(
            &mut std::io::Cursor::new(v1),
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        let r2 = trojan_server_handshake(
            &mut std::io::Cursor::new(v2),
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        let (_, _, _, u1) = r1.expect("v1 handshake");
        let (_, _, _, u2) = r2.expect("v2 handshake");
        assert_eq!(u1, u2, "v1/v2 must resolve to the same user");
    }

    /// v2 错误密码 → UserNotFound（与 v1 拒绝语义一致，走 fallback）。
    #[tokio::test]
    async fn handshake_v2_wrong_password_rejected() {
        let validator = make_validator_with_user("password");
        let header = v2_header("wrong-password", &[127, 0, 0, 1], addr_type::IPV4, 80);
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(
            &mut cursor,
            &validator,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(
            matches!(result, Err(crate::TrojanError::UserNotFound)),
            "wrong md5 must be rejected, got {result:?}"
        );
    }

    /// 非法版本前缀（非 v1 hex 且非 0x02）→ InvalidVersionPrefix 拒绝。
    #[tokio::test]
    async fn handshake_invalid_version_prefix_rejected() {
        let validator = make_validator_with_user("password");
        for first in [0x00u8, 0x01, 0x03, 0x07, 0x20, 0xFF, b'g', b'G'] {
            let mut header = vec![first];
            header.extend_from_slice(&[1, 127, 0, 0, 1, 0, 80]);
            let mut cursor = std::io::Cursor::new(header);
            let result = trojan_server_handshake(
                &mut cursor,
                &validator,
                xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await;
            assert!(
                matches!(result, Err(crate::TrojanError::InvalidVersionPrefix(_))),
                "prefix {first:#04x} must be rejected as invalid version"
            );
        }
    }
}
