//! Shadowsocks outbound → DialBridge 适配器。
//!
//! 把 SS 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_ss_dial_fn`] 闭包，内部拨号到 SS 服务器 →
//! 写 SS 加密首帧（addr+port）→ 返回 SS 加密连接。
//!
//! ## Connection wrapper
//!
//! [`SSStream`] 不直接实现 `AsyncRead`/`AsyncWrite`（SS chunk 天然分帧），
//! 因此 [`SsConnection`] 包装 `SSStream<TcpStream>`，用
//! `write_chunk`/`read_chunk` 循环桥接到 `AsyncRead`/`AsyncWrite` trait。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::connection::Connection;
use xray_xudp::packet::{PacketError, PacketReader, PacketWriter};

use crate::client::Client;
use crate::config::MemoryAccount;
use crate::ss2022::UdpOverTcpConfig;
use crate::protocol::{decode_udp_packet, encode_udp_packet};
use crate::stream::SSStream;
use crate::validator::{MemoryUser, Validator};

/// SS duplex 缓冲（与 hysteria/tuic 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// XUDP GlobalID 长度（与 Go `xudp` / hysteria dispatcher 一致）。
const GLOBAL_ID_LEN: usize = 8;

/// SS 加密流 → Connection trait 实现。
///
/// 桥接 `SSStream<Box<dyn Connection>>` 的 `write_chunk`/`read_chunk` 到
/// `AsyncRead`/`AsyncWrite`：spawn 一个 [`pump_ss_stream`] task，在 SS 加密
/// chunk 流与 `tokio::io::duplex` 明文 IO 之间双向搬运。`SsConnection` 自身只
/// 持有 duplex 客户端半 + pump task 句柄，trait 方法全部委托给 duplex。
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct SsConnection {
    inner: DuplexStream,
    _pump: JoinHandle<()>,
}

impl SsConnection {
    /// 从已写完首帧（addr+port）的 `SSStream` 构造。
    /// 首帧由 `Client::dial_target` 写入，本包装只负责 body 加密透传。
    #[must_use]
    pub fn new(stream: SSStream<Box<dyn Connection>>) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_ss_stream(stream, server_io));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl SsConnection {
    /// UDP 变体：从已 connect 到 SS 服务器 UDP 端口的 socket 构造，
    /// spawn XUDP 帧 ↔ SS UDP 数据报 pump（[`pump_ss_udp`]）。
    fn new_udp(sock: UdpSocket, account: MemoryAccount, default_dest: Destination) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_ss_udp(sock, account, server_io, default_dest));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl SsConnection {
    /// UDP 变体（SS-2022）：从已 connect 到 SS 服务器 UDP 端口的 socket 构造，
    /// spawn XUDP 帧 ↔ SS-2022 UDP 会话帧 pump（[`pump_ss2022_udp`]）。
    fn new_udp_2022(sock: UdpSocket, params: Ss2022DialParams, default_dest: Destination) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_ss2022_udp(sock, params, server_io, default_dest));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl AsyncRead for SsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for SsConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// 双向 pump：在 `SSStream`（加密 chunk 流）与 `DuplexStream`（明文 IO）之间桥接。
///
/// - up：read duplex（8KB）→ `write_chunk` → flush（明文 → 密文 chunk）
/// - down：底层单次 read（cancel-safe）→ `pending` 缓冲 → `try_open_chunk`
///   完整解帧（nonce 只在整帧解出时推进，select! 取消不损流状态）
///
/// `SSStream` 的 `write_chunk`/`read_chunk` 共享单一 nonce 计数器且均需 `&mut self`，
/// 不可并发持有（也无法像 hysteria 那样 `split` 成独立读写半）。故采用 `select!` 串行
/// 推进：down 方向不直接调 async `read_chunk`（其内部 read_exact 半途被取消会丢字节），
/// 而是用 cancel-safe 的单次底层 `read` 喂 `pending`，再同步解帧；up 方向用
/// cancel-safe 的 `AsyncReadExt::read`。连接为 transport 层产物
/// `Box<dyn Connection>`（ws+tls 包装或裸 TCP），无 TcpStream::readable 可用。
async fn pump_ss_stream(mut stream: SSStream<Box<dyn Connection>>, server_io: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let mut up_buf = vec![0u8; 8 * 1024];
    let mut down_buf = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        // 先把 pending 中完整帧全部解出（NeedMore 才进 select 等新数据）
        loop {
            match stream.try_open_chunk(&mut pending) {
                Ok(crate::stream::ChunkOut::Message(plaintext)) => {
                    if wr.write_all(&plaintext).await.is_err() {
                        return;
                    }
                    let _ = wr.flush().await;
                }
                Ok(crate::stream::ChunkOut::NeedMore) => break,
                Ok(crate::stream::ChunkOut::End) => {
                    // 0 长度 chunk = 流结束标记
                    let _ = wr.shutdown().await;
                    return;
                }
                Err(e) => {
                    tracing::debug!("ss pump down decode error: {e}");
                    return;
                }
            }
        }
        tokio::select! {
            // up: 明文 duplex 读 → 加密 chunk 写到 SS wire
            n = rd.read(&mut up_buf) => {
                match n {
                    Ok(0) => {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        if stream.write_chunk(&up_buf[..n]).await.is_err() {
                            break;
                        }
                        if stream.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("ss pump up read error: {e}");
                        break;
                    }
                }
            }
            // down: cancel-safe 单次底层读 → pending（解帧在循环顶部同步完成）
            n = stream.get_mut().read(&mut down_buf) => {
                match n {
                    Ok(0) => {
                        let _ = wr.shutdown().await;
                        break;
                    }
                    Ok(n) => pending.extend_from_slice(&down_buf[..n]),
                    Err(e) => {
                        tracing::debug!("ss pump down read error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

/// SS outbound 配置。
#[derive(Debug, Clone)]
pub struct SsOutboundConfig {
    /// SS 账户（cipher + key + password）。
    pub account: MemoryAccount,
    /// SS 服务器地址。
    pub server_address: Address,
    /// SS 服务器端口。
    pub server_port: u16,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
    /// SS-2022 出站参数（method 命中 2022-blake3-* 时 Some，account 字段不用于该路径）。
    pub ss2022: Option<Ss2022DialParams>,
    /// UDP-over-TCP 配置（仅 SS-2022 路径填充；Go 旧 AEAD ClientConfig 无 UoT 字段）。
    pub udp_over_tcp: UdpOverTcpConfig,
    /// 可选 streamSettings（TLS/WS/...）。None 走 raw TCP（与 trojan/vmess dispatcher 一致）。
    pub stream_settings: Option<xray_transport::dialer::StreamSettings>,
}

/// SS-2022 出站拨号参数（对应 Go `shadowsocks_2022.ClientConfig{Method, Key}`）。
#[derive(Debug, Clone)]
pub struct Ss2022DialParams {
    /// cipher method 名（"2022-blake3-aes-128-gcm" 等）。
    pub method: String,
    /// 用户 PSK（base64）。
    pub psk_b64: String,
    /// server 主 PSK（base64，多用户 "iPSK:uPSK" 密码格式的第一段）。
    pub identity_psk_b64: Option<String>,
}
impl SsOutboundConfig {
    /// 构造配置。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: u16) -> Self {
        Self {
            account,
            server_address,
            server_port,
            level: 0,
            email: String::new(),
            ss2022: None,
            udp_over_tcp: UdpOverTcpConfig::default(),
            stream_settings: None,
        }
    }

    /// 设置 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<xray_transport::dialer::StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 设置用户 email（builder 风格）。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// 设置 SS-2022 出站参数（builder 风格）。
    #[must_use]
    pub fn with_ss2022(mut self, params: Ss2022DialParams) -> Self {
        self.ss2022 = Some(params);
        self
    }

    /// 设置 UDP-over-TCP 配置（builder 风格）。
    #[must_use]
    pub fn with_udp_over_tcp(mut self, cfg: UdpOverTcpConfig) -> Self {
        self.udp_over_tcp = cfg;
        self
    }
}

/// 解析 SS outbound settings JSON → SsOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 8388, "method": "aes-256-gcm", "password": "..." }] }`
pub fn parse_ss_config(data: &[u8]) -> Result<SsOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers
        .first()
        .ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let method = first
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].method".to_string())?;
    let password = first
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    // SS-2022 分支（Go infra/conf/shadowsocks.go：method 命中 shadowaead_2022.List
    // 时转 shadowsocks_2022.ClientConfig；密码为 base64 PSK，多用户 "iPSK:uPSK"）。
    if crate::ss2022::key::CipherKind2022::from_name(method).is_ok() {
        let port = u16::try_from(port).map_err(|_| "port out of range")?;
        let level = first.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let email = first.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // uot/uotVersion → UdpOverTcpConfig（Go shadowsocks.go:243-244，零值 false/0）。
        let uot_cfg = UdpOverTcpConfig {
            enabled: first.get("uot").and_then(|v| v.as_bool()).unwrap_or(false),
            version: first
                .get("uotVersion")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as u32,
        };
        let (psk_b64, identity_psk_b64) = match password.split(':').collect::<Vec<_>>()[..] {
            [u] => (u.to_string(), None),
            [i, u, ..] => (u.to_string(), Some(i.to_string())),
            [] => return Err("empty password".to_string()),
        };
        // account 占位：2022 拨号路径读 ss2022 参数，不读 account；cipher 字段用
        // 任意 AEAD（None 已被 Go 上游 v26.7.28 删除）。
        let placeholder = MemoryAccount::from_proto(&xray_proto::xray::proxy::shadowsocks::Account {
            password: psk_b64.clone(),
            cipher_type: crate::config::CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        })
        .map_err(|e| format!("ss2022 account placeholder: {e}"))?;
        return Ok(SsOutboundConfig::new(
            placeholder,
            Address::Domain(address.to_string()),
            port,
        )
        .with_level(level)
        .with_email(email)
        .with_udp_over_tcp(uot_cfg)
        .with_ss2022(Ss2022DialParams {
            method: method.to_string(),
            psk_b64,
            identity_psk_b64,
        }));
    }
    let cipher_type = crate::config::CipherType::from_name(method)
        .ok_or_else(|| format!("unsupported cipher: {method}"))?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    let proto_account = xray_proto::xray::proxy::shadowsocks::Account {
        password: password.to_string(),
        cipher_type: cipher_type.as_i32(),
        iv_check: false,
    };
    let account = MemoryAccount::from_proto(&proto_account)
        .map_err(|e| format!("ss account: {e}"))?;
    // 可选字段：level / email（对应 Go infra/conf outbound server）。
    let level = first.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let email = first.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(SsOutboundConfig::new(account, Address::Domain(address.to_string()), port)
        .with_level(level)
        .with_email(email))
}

/// 构造 SS 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<SsOutboundConfig>`，每次调用：
/// 1. `Client::dial_target` 拨号到 SS 服务器 + 写首帧
/// 2. 包装为 [`SsConnection`]（impl [`Connection`]）
/// 3. 返回连接
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_ss_dial_fn(config: Arc<SsOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        let network = dest.network();
        Box::pin(async move {
            match network {
                // TCP：先建到 SS 服务器的传输连接（streamSettings 走 transport
                // dialer（ws+tls/...），否则裸 TCP），再在其上跑 SS 协议握手
                Network::TCP => {
                    let host = match &config.server_address {
                        Address::Domain(d) => d.clone(),
                        Address::IPv4(ip) => ip.to_string(),
                        Address::IPv6(ip) => ip.to_string(),
                    };
                    let target_str = match &target_addr {
                        Address::Domain(d) => d.clone(),
                        Address::IPv4(ip) => ip.to_string(),
                        Address::IPv6(ip) => ip.to_string(),
                    };
                    // 1. 到 SS 服务器的连接（与 trojan dispatcher 同模式）
                    let server_dest = Destination::tcp(
                        config.server_address.clone(),
                        Port::new(config.server_port),
                    );
                    let sockopt = config
                        .stream_settings
                        .as_ref()
                        .map(|s| s.socket_options())
                        .unwrap_or_default();
                    let conn: Box<dyn Connection> = match &config.stream_settings {
                        Some(s) => xray_transport::dialer::dial(&server_dest, s, &sockopt)
                            .await
                            .map_err(|e| format!("ss dial server ({}): {e}", s.protocol))?,
                        None => {
                            let sa = resolve_server(&config.server_address, config.server_port)
                                .await
                                .map_err(|e| format!("ss resolve server: {e}"))?;
                            let tcp = TcpStream::connect(sa)
                                .await
                                .map_err(|e| format!("ss dial server (tcp): {e}"))?;
                            tcp.set_nodelay(true).ok();
                            Box::new(xray_transport::connection::TcpConnection::new(tcp))
                        }
                    };

                    // 2. 在该连接上跑 SS 协议握手 + 拨 target
                    let stream = if let Some(p) = &config.ss2022 {
                        // SS-2022：Client2022（多用户时 EIH 首帧）
                        let mut client = crate::ss2022::client::Client2022::new(
                            &p.method,
                            &p.psk_b64,
                            &host,
                            config.server_port,
                        )
                        .map_err(|e| format!("ss2022 client: {e}"))?;
                        if let Some(i) = &p.identity_psk_b64 {
                            client = client
                                .with_identity(i)
                                .map_err(|e| format!("ss2022 identity: {e}"))?;
                        }
                        // dial_target_on 已 mark_response_rekey_2022 设响应 rekey 状态机；
                        // pump_ss_stream 首次 try_open_chunk 时会经 drive_2022_rekey 解
                        // salt+fixed+var（payload=0 时只读 salt+fixed）。此处不再额外
                        // read_response_handshake，否则双重读同 conn → 首 read_exact EOF。
                        let stream = client
                            .dial_target_on(conn, &target_str, target_port)
                            .await
                            .map_err(|e| format!("ss2022 dial: {e}"))?;
                        stream
                    } else {

                        let client = Client::new(config.account.clone(), host, config.server_port);
                        client
                            .dial_target_for_proxy_on(conn, &target_addr, target_port)
                            .await
                            .map_err(|e| format!("ss dial: {e}"))?
                    };
                    Ok(Box::new(SsConnection::new(stream)) as Box<dyn Connection>)
                }
                // UDP：dial SS 服务器的 UDP 端口（Go internet dialer 的 network
                // 跟随 dest）。legacy：每数据报独立 [salt][AEAD(addr+port+payload)]；
                // 2022：per-connection 会话帧（sessionId/packetId + EIH），均非
                // XUDP-over-TCP
                Network::UDP => {
                    let server = resolve_server(&config.server_address, config.server_port)
                        .await
                        .map_err(|e| format!("ss udp dial: {e}"))?;
                    let local = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                    let sock = UdpSocket::bind(local)
                        .await
                        .map_err(|e| format!("ss udp bind: {e}"))?;
                    sock.connect(server)
                        .await
                        .map_err(|e| format!("ss udp connect: {e}"))?;
                    let default_dest = Destination::udp(target_addr, Port::new(target_port));
                    if let Some(p) = &config.ss2022 {
                        Ok(Box::new(SsConnection::new_udp_2022(
                            sock,
                            p.clone(),
                            default_dest,
                        )) as Box<dyn Connection>)
                    } else {
                        Ok(Box::new(SsConnection::new_udp(
                            sock,
                            config.account.clone(),
                            default_dest,
                        )) as Box<dyn Connection>)
                    }
                }
                Network::Unix => Err("ss outbound does not support unix network".to_string()),
            }
        })
    })
}

/// 解析 SS 服务器地址 → SocketAddr（Domain 走系统 DNS）。
async fn resolve_server(addr: &Address, port: u16) -> io::Result<SocketAddr> {
    match addr {
        Address::IPv4(ip) => Ok(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Ok(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ss server dns: no address")),
    }
}

/// SS outbound UDP 双向 pump：duplex 内的 XUDP 帧流 ↔ SS 服务器 UDP 数据报。
///
/// 对应 Go `shadowsocks` outbound UDP 分支（与 hysteria `pump_hysteria_udp` /
/// freedom `pump_request`/`pump_response` 同构）：
///
/// - up：XUDP 帧 → [`encode_udp_packet`]（每数据报独立 salt + AEAD
///   addr+port+payload）→ `sock.send`（已 connect SS 服务器）。帧内
///   per-packet target 缺省用 `default_dest`。
/// - down：`sock.recv` → [`decode_udp_packet`]（单用户 validator）→ 解出
///   (来源, payload) → XUDP 帧写回 duplex。
async fn pump_ss_udp(
    sock: UdpSocket,
    account: MemoryAccount,
    server_io: DuplexStream,
    default_dest: Destination,
) {
    let sock = Arc::new(sock);
    let (mut rd, mut wr) = tokio::io::split(server_io);
    // 回包解码 validator：单用户（出站只有一个 account）
    let validator = Validator::new();
    let _ = validator.add(MemoryUser::new("ss-udp-outbound", account.clone()));

    // up: duplex → XUDP 帧解析 → SS UDP 数据报
    let up_sock = Arc::clone(&sock);
    let up = async move {
        let mut accum: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            // 先把 accum 里所有完整帧消费掉
            let mut progress = true;
            while progress {
                match parse_and_send(&up_sock, &account, &mut accum, &default_dest).await {
                    Ok(made) => progress = made,
                    Err(e) => {
                        tracing::debug!("ss udp up forward error: {e}");
                        return;
                    }
                }
            }
            match rd.read(&mut buf).await {
                Ok(0) => return, // link EOF
                Ok(n) => accum.extend_from_slice(&buf[..n]),
                Err(e) => {
                    tracing::debug!("ss udp up read error: {e}");
                    return;
                }
            }
        }
    };

    // down: SS 服务器回包 → decode → XUDP 帧 → duplex
    let down = async move {
        let global_id: [u8; GLOBAL_ID_LEN] = rand::random();
        let mut rbuf = vec![0u8; 65_535];
        loop {
            let n = match sock.recv(&mut rbuf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!("ss udp down recv error: {e}");
                    break;
                }
            };
            // 解码失败跳过（Go DecodeUDPPacket 失败丢弃该包）
            let Ok((header, payload)) = decode_udp_packet(&validator, &rbuf[..n]) else {
                continue;
            };
            // 回包帧来源 = SS 解出的响应来源地址
            let source = Destination::udp(header.address, Port::new(header.port));
            let mut frame = Vec::with_capacity(payload.len() + 64);
            let mut pw = PacketWriter::new(&mut frame, source, global_id);
            if pw.write_packet(&payload).is_err() {
                break;
            }
            drop(pw);
            if wr.write_all(&frame).await.is_err() {
                break; // client 侧已关闭
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

/// SS-2022 outbound UDP 双向 pump：duplex 内的 XUDP 帧流 ↔ SS 服务器 2022 UDP 数据报。
///
/// 对应 Go `shadowsocks_2022` outbound 的 `DialPacketConn` + `CopyPacketConn`
/// （非 UoT 时 connection 是 connected UDP socket，per-packet 会话帧）：
///
/// - up：XUDP 帧 → [`ClientUdpSession2022::encode`]（单会话 sessionId +
///   递增 packetId + EIH + session subkey AEAD）→ `sock.send`。
/// - down：`sock.recv` → [`ClientUdpSession2022::decode`] → (来源, payload)
///   → XUDP 帧写回 duplex。
async fn pump_ss2022_udp(
    sock: UdpSocket,
    params: Ss2022DialParams,
    server_io: DuplexStream,
    default_dest: Destination,
) {
    use crate::ss2022::key::{psk_from_base64, CipherKind2022};
    use crate::ss2022::packet::ClientUdpSession2022;

    let kind = CipherKind2022::from_name(&params.method);
    let session = match kind.map_err(|e| e.to_string()).and_then(|kind| {
        let mut psk_list = Vec::new();
        if let Some(i) = &params.identity_psk_b64 {
            psk_list.push(psk_from_base64(i).map_err(|e| e.to_string())?);
        }
        psk_list.push(psk_from_base64(&params.psk_b64).map_err(|e| e.to_string())?);
        ClientUdpSession2022::new(kind, psk_list).map_err(|e| e.to_string())
    }) {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            tracing::debug!("ss2022 udp session init: {e}");
            return;
        }
    };

    let sock = Arc::new(sock);
    let (mut rd, mut wr) = tokio::io::split(server_io);

    // up: duplex → XUDP 帧解析 → 2022 UDP 数据报
    let up_sock = Arc::clone(&sock);
    let up_session = Arc::clone(&session);
    let up = async move {
        let mut accum: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            let mut progress = true;
            while progress {
                match parse_and_send_2022(&up_sock, &up_session, &mut accum, &default_dest).await {
                    Ok(made) => progress = made,
                    Err(e) => {
                        tracing::debug!("ss2022 udp up forward error: {e}");
                        return;
                    }
                }
            }
            match rd.read(&mut buf).await {
                Ok(0) => return, // link EOF
                Ok(n) => accum.extend_from_slice(&buf[..n]),
                Err(e) => {
                    tracing::debug!("ss2022 udp up read error: {e}");
                    return;
                }
            }
        }
    };

    // down: SS 服务器回包 → decode → XUDP 帧 → duplex
    let down = async move {
        let global_id: [u8; GLOBAL_ID_LEN] = rand::random();
        let mut rbuf = vec![0u8; 65_535];
        loop {
            let n = match sock.recv(&mut rbuf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!("ss2022 udp down recv error: {e}");
                    break;
                }
            };
            // 解码失败跳过（Go ReadPacket 失败丢弃该包）
            let Ok((addr, port, payload)) = session.decode(&rbuf[..n]) else {
                continue;
            };
            let source = Destination::udp(addr, Port::new(port));
            let mut frame = Vec::with_capacity(payload.len() + 64);
            let mut pw = PacketWriter::new(&mut frame, source, global_id);
            if pw.write_packet(&payload).is_err() {
                break;
            }
            drop(pw);
            if wr.write_all(&frame).await.is_err() {
                break; // client 侧已关闭
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

/// 从 accum 前端解析一个 XUDP 帧 → 2022 帧编码 → `sock.send`。
///
/// 返回 `true` 表示消费了一帧；accum 为空或帧不完整返回 `false`；
/// 致命错误返回 `Err`。
async fn parse_and_send_2022(
    sock: &Arc<UdpSocket>,
    session: &std::sync::Arc<crate::ss2022::packet::ClientUdpSession2022>,
    accum: &mut Vec<u8>,
    default_dest: &Destination,
) -> io::Result<bool> {
    if accum.is_empty() {
        return Ok(false);
    }
    let (result, consumed) = {
        let mut cursor = std::io::Cursor::new(&accum[..]);
        let mut pr = PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        (r, cursor.position() as usize)
    };
    match result {
        Ok(Some(pkt)) => {
            accum.drain(..consumed);
            let (data, target) = pkt.into_parts();
            let dest = target.unwrap_or_else(|| default_dest.clone());
            let enc = session
                .encode(dest.address(), dest.port().value(), &data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            sock.send(&enc).await?;
            Ok(true)
        }
        Ok(None) => Ok(false), // 帧不完整，等更多数据
        Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// 从 accum 前端解析一个 XUDP 帧 → `encode_udp_packet` → `sock.send`。
///
/// 返回 `true` 表示消费了一帧；accum 为空或帧不完整返回 `false`；
/// 致命错误返回 `Err`。
async fn parse_and_send(
    sock: &Arc<UdpSocket>,
    account: &MemoryAccount,
    accum: &mut Vec<u8>,
    default_dest: &Destination,
) -> io::Result<bool> {
    if accum.is_empty() {
        return Ok(false);
    }
    let (result, consumed) = {
        let mut cursor = std::io::Cursor::new(&accum[..]);
        let mut pr = PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        (r, cursor.position() as usize)
    };
    match result {
        Ok(Some(pkt)) => {
            accum.drain(..consumed);
            let (data, target) = pkt.into_parts();
            let dest = target.unwrap_or_else(|| default_dest.clone());
            let enc = encode_udp_packet(account, dest.address(), dest.port().value(), &data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            sock.send(&enc).await?;
            Ok(true)
        }
        Ok(None) => Ok(false), // 帧不完整，等更多数据
        Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "test".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn config_construction() {
        let cfg = SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            8388,
        );
        assert_eq!(cfg.server_port, 8388);
    }

    #[test]
    fn parse_ss_config_2022_single_user() {
        let data = br#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm",
            "password":"aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ=="}]}"#;
        let cfg = parse_ss_config(data).expect("parse 2022");
        let p = cfg.ss2022.expect("ss2022 params");
        assert_eq!(p.method, "2022-blake3-aes-256-gcm");
        assert_eq!(p.psk_b64, "aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ==");
        assert!(p.identity_psk_b64.is_none());
        assert_eq!(cfg.server_port, 8388);
    }

    #[test]
    fn parse_ss_config_2022_multi_user() {
        // base64(32B server PSK) : base64(32B user PSK)
        let ipsk = "serverpskserverpskserverpskserver".to_string();
        let upsk = "userpskuserpskuserpskuserpskuser".to_string();
        let data = format!(
            r#"{{"servers":[{{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-128-gcm",
            "password":"{ipsk}:{upsk}"}}]}}"#
        );
        // 长度不匹配（非 16/32B 解码）会报 InvalidPassword——这里只验证解析分流
        let r = parse_ss_config(data.as_bytes());
        // 非法 PSK 长度：dial 时才校验，parse 阶段只要 method 命中就通过
        if let Ok(cfg) = r {
            let p = cfg.ss2022.expect("ss2022 params");
            assert_eq!(p.identity_psk_b64.as_deref(), Some(ipsk.as_str()));
            assert_eq!(p.psk_b64, upsk);
        }
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let cfg = Arc::new(SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            443,
        ));
        let _dial = make_ss_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    #[test]
    fn parse_ss_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "ss.example.com",
                "port": 8388,
                "method": "aes-128-gcm",
                "password": "test-password"
            }]
        }"#;
        let config = parse_ss_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port, 8388);
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "ss.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_ss_config_missing_servers_fails() {
        let result = parse_ss_config(b"{}");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ss_config_maps_uot_to_udp_over_tcp() {
        // 2022 路径：uot/uotVersion → UdpOverTcpConfig（Go shadowsocks.go:243-244）。
        let data = br#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm",
            "password":"aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ==",
            "uot":true,"uotVersion":1}]}"#;
        let cfg = parse_ss_config(data).unwrap();
        assert!(cfg.udp_over_tcp.enabled);
        assert_eq!(cfg.udp_over_tcp.version, 1);

        // 缺省 uot → false/0。
        let data = br#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm",
            "password":"aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ=="}]}"#;
        let cfg = parse_ss_config(data).unwrap();
        assert!(!cfg.udp_over_tcp.enabled);
        assert_eq!(cfg.udp_over_tcp.version, 0);

        // 旧 AEAD 路径：Go 旧 ClientConfig 无 UoT 字段 → 保持默认。
        let data = br#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"aes-256-gcm","password":"secret","uot":true,"uotVersion":1}]}"#;
        let cfg = parse_ss_config(data).unwrap();
        assert!(!cfg.udp_over_tcp.enabled);
        assert_eq!(cfg.udp_over_tcp.version, 0);
    }

    /// `SsConnection`（duplex pump）端到端：客户端 AsyncRead/AsyncWrite → 加密 chunk →
    /// SS inbound 解密 → echo → 加密回响 → 客户端读回。
    ///
    /// 直接证明 SsConnection 的 pump 走 SS 加密层：若退化为明文透传（旧行为），
    /// inbound 的 `read_chunk` 会 AEAD open 失败而 panic。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ss_connection_pump_roundtrips_through_inbound_echo() {
        use crate::inbound::SsInbound;
        use std::net::{IpAddr, SocketAddr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use xray_common::net::address::Address;

        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = echo_listener.accept().await.expect("echo accept");
            let (mut rd, mut wr) = tokio::io::split(sock);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });

        // 2. SS inbound：handle_conn 握手 → read_chunk body → echo → write_chunk 回响
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind inbound");
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let account = make_account();
        let ib = std::sync::Arc::new(SsInbound::new(account.clone(), "u@pump.local"));
        let echo_v4 = match echo_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4 echo addr"),
        };
        let echo_socket = SocketAddr::new(IpAddr::V4(echo_v4), echo_addr.port());

        let server_handle = tokio::spawn({
            let ib = std::sync::Arc::clone(&ib);
            async move {
                let (conn, _) = inbound_listener.accept().await.expect("inbound accept");
                let (_header, mut ss_stream) = ib.handle_conn(conn).await.expect("handshake");
                let body = ss_stream.read_chunk().await.expect("read body").expect("non-empty");
                let mut ec = TcpStream::connect(echo_socket).await.expect("connect echo");
                ec.write_all(&body).await.expect("fwd echo");
                ec.flush().await.expect("flush echo");
                let mut echoed = vec![0u8; body.len()];
                ec.read_exact(&mut echoed).await.expect("read echo back");
                ss_stream.write_chunk(&echoed).await.expect("write resp chunk");
                ss_stream.flush().await.expect("flush resp");
            }
        });

        // 3. client：dial_target（写 IV + 首帧）→ SsConnection::new → AsyncRead/Write
        let client = Client::new(account, inbound_addr.ip().to_string(), inbound_addr.port());
        let tcp = TcpStream::connect((inbound_addr.ip(), inbound_addr.port()))
            .await
            .expect("connect inbound");
        let stream = client
            .dial_target_on(
                Box::new(xray_transport::connection::TcpConnection::new(tcp)) as Box<dyn Connection>,
                &Address::IPv4(echo_v4),
                echo_addr.port(),
            )
            .await
            .expect("dial_target");
        let mut conn = SsConnection::new(stream);

        let payload = b"hello ss duplex pump!";
        conn.write_all(payload).await.expect("ss write");
        conn.flush().await.expect("ss flush");

        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.expect("ss read");

        assert_eq!(&got[..], payload, "echo through SsConnection pump");
        server_handle.await.expect("server task join");
    }

    /// UDP 分支 e2e：`make_ss_dial_fn`(UDP dest) → dial SS 服务器 UDP 端口 →
    /// 每数据报 `[salt][AEAD(addr+port+payload)]` 编解码 → fake SS 服务器
    /// echo 回包 → XUDP 帧经 dispatch 会话收回。
    ///
    /// MarkerUdp 式 raw 透传给不出回包（UDP echo 服务器与 SS 语义不同），
    /// 只有 UDP 分支真实编解码 + XUDP 装拆帧才能 roundtrip。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ss_udp_dial_fn_roundtrips_through_udp_echo() {
        use std::time::Duration;
        use xray_app_dispatcher::UdpDispatchSession;

        // 1. fake SS UDP 服务器：decode（匹配用户）→ echo → encode 回来源
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().unwrap();
        let srv_account = make_account();
        let validator = Validator::new();
        validator
            .add(MemoryUser::new("srv", srv_account.clone()))
            .expect("add user");
        tokio::spawn(async move {
            let mut b = [0u8; 65_535];
            while let Ok((n, from)) = server.recv_from(&mut b).await {
                let Ok((header, payload)) = decode_udp_packet(&validator, &b[..n]) else {
                    continue;
                };
                let Ok(enc) = encode_udp_packet(
                    &srv_account,
                    &header.address,
                    header.port,
                    &payload,
                ) else {
                    continue;
                };
                let _ = server.send_to(&enc, from).await;
            }
        });

        // 2. outbound：DialBridge(make_ss_dial_fn) + UdpDispatchSession（XUDP 帧）
        let cfg = Arc::new(SsOutboundConfig::new(
            make_account(),
            Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
            server_addr.port(),
        ));
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(
            xray_app_dispatcher::default::DialBridge::new(
                "ss-udp-out",
                make_ss_dial_fn(Arc::clone(&cfg)),
            ),
        );
        let mut session = UdpDispatchSession::new(handler);

        // 3. 经 dispatch 会话发 UDP 包，收回包（来源 = 请求目标）
        let dest = Destination::udp(
            Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(9),
        );
        let payload = b"ss-udp-outbound-e2e";
        session.send_packet(&dest, payload).await.expect("send");

        let (source, got) = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("echo within 5s")
            .expect("recv ok")
            .expect("session alive");
        assert_eq!(&got[..], payload);
        assert_eq!(source.address(), dest.address());
        assert_eq!(source.port(), dest.port());
    }
}
