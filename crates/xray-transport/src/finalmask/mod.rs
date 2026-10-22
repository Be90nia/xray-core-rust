//! # Finalmask 流量伪装框架
//!
//! 对应 Go `transport/internet/finalmask/finalmask.go`。
//! 提供 UDP/TCP 流量伪装的链式包装基础设施——把代理流量伪装成常见协议特征，规避 DPI。
//!
//! ## 核心接口
//!
//! - [`UdpIo`]：UDP I/O 抽象（对应 Go `net.PacketConn` 子集）
//! - [`Udpmask`]：UDP 伪装（包装 PacketConn）
//! - [`Tcpmask`]：TCP 伪装（包装 Conn）
//!
//! ## Manager
//!
//! [`UdpmaskManager`] / [`TcpmaskManager`] 按逆序链式应用多个伪装模块（对应 Go
//! `slices.Backward`）。

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinHandle,
};

pub mod custom;
pub mod fragment;
pub mod mkcp;
pub mod noise;
pub mod realm;
pub mod salamander;
pub mod salamander_gecko;
pub mod sudoku;
pub mod udphop;
pub mod xdns;
pub mod xicmp;
pub mod xmc;

/// UDP 读缓冲区大小（对应 Go `finalmask.UDPSize = 4096`）。
pub const UDP_SIZE: usize = 4096;

/// PacketIoConn 收/发队列有界容量（票 b2og）。
///
/// UDP 语义：对端黑洞且本端 socket 发送缓冲长期满时，满载即丢弃并计数——
/// 对齐内核 socket 缓冲满时的丢包行为，杜绝 unbounded 队列无界增长。
const PACKET_QUEUE_CAP: usize = 128;

/// `AsyncRead + AsyncWrite + Send + Unpin` 的组合 trait（用于 trait object）。
///
/// Rust 的 trait object 只能含一个非 auto trait，故 `dyn AsyncRead + AsyncWrite` 非法。
/// 通过此组合 trait + blanket impl 解决。
pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// UDP I/O 抽象（对应 Go `net.PacketConn` 的子集）。
#[async_trait]
pub trait UdpIo: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// `tokio::net::UdpSocket` 适配为 [`UdpIo`]。
#[async_trait]
impl UdpIo for tokio::net::UdpSocket {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::send_to(self, buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self, buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

/// `Arc<UdpSocket>` 同样适配 [`UdpIo`]（共享同一内核 socket；
/// `UdpHub` 把 socket 交给 mask 链包装后仍需自持句柄用于 `local_addr`/close）。
#[async_trait]
impl UdpIo for std::sync::Arc<tokio::net::UdpSocket> {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::send_to(self.as_ref(), buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self.as_ref(), buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self.as_ref())
    }
}

/// UDP 伪装接口（对应 Go `Udpmask`）。
pub trait Udpmask: Send + Sync {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>>;

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>>;
}

/// TCP 伪装接口（对应 Go `Tcpmask`）。
pub trait Tcpmask: Send + Sync {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>>;

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>>;
}

/// UDP 伪装管理器（对应 Go `UdpmaskManager`）。
///
/// header/custom 等具体伪装模块通过实现 [`Udpmask`] trait 直接加入 `udpmasks` 数组，
/// 不需要专门的 header 聚合类型（与 Go `headerManagerConn` 不同）。
pub struct UdpmaskManager {
    pub udpmasks: Vec<Box<dyn Udpmask>>,
}

impl UdpmaskManager {
    #[must_use]
    pub fn new(udpmasks: Vec<Box<dyn Udpmask>>) -> Self {
        Self { udpmasks }
    }

    pub fn wrap_packet_conn_client(&self, raw: Box<dyn UdpIo>) -> io::Result<Box<dyn UdpIo>> {
        let mut raw = raw;
        let total = self.udpmasks.len();
        for i in (0..total).rev() {
            raw = self.udpmasks[i].wrap_packet_conn_client(raw, i, total.saturating_sub(1))?;
        }
        Ok(raw)
    }

    pub fn wrap_packet_conn_server(&self, raw: Box<dyn UdpIo>) -> io::Result<Box<dyn UdpIo>> {
        let mut raw = raw;
        let total = self.udpmasks.len();
        for i in (0..total).rev() {
            raw = self.udpmasks[i].wrap_packet_conn_server(raw, i, total.saturating_sub(1))?;
        }
        Ok(raw)
    }
}

/// TCP 伪装管理器（对应 Go `TcpmaskManager`）。
pub struct TcpmaskManager {
    pub tcpmasks: Vec<Box<dyn Tcpmask>>,
}

impl TcpmaskManager {
    #[must_use]
    pub fn new(tcpmasks: Vec<Box<dyn Tcpmask>>) -> Self {
        Self { tcpmasks }
    }

    pub fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let mut raw = raw;
        for mask in self.tcpmasks.iter().rev() {
            raw = mask.wrap_conn_client(raw)?;
        }
        Ok(raw)
    }

    pub fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let mut raw = raw;
        for mask in self.tcpmasks.iter().rev() {
            raw = mask.wrap_conn_server(raw)?;
        }
        Ok(raw)
    }
}

/// TCP 伪装连接标记（对应 Go `TcpMaskConn` interface）。
pub trait TcpMaskConn: AsyncIo {
    fn raw_conn(&self) -> Option<&dyn AsyncIo> {
        None
    }
    fn splice(&self) -> bool {
        false
    }
}

/// `Box<dyn Connection>` → `Box<dyn AsyncIo>` 上转（用于喂给 mask 模块）。
///
/// `Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin` 是 `AsyncIo` 的子集
/// （`AsyncIo = AsyncRead + AsyncWrite + Send + Sync + Unpin`），但 Rust 不允许
/// `Box<dyn Connection>` → `Box<dyn AsyncIo>` 自动 upcast（vtable 顺序不同）。
/// 用 newtype 包装 + Pin 投影转接 AsyncRead/AsyncWrite forward。
fn conn_to_asyncio(conn: Box<dyn crate::connection::Connection>) -> Box<dyn AsyncIo> {
    Box::new(ConnAsAsyncIo(conn))
}

/// newtype 包装 `Box<dyn Connection>` 为 `Box<dyn AsyncIo>`，forward AsyncRead/AsyncWrite。
struct ConnAsAsyncIo(Box<dyn crate::connection::Connection>);

impl AsyncRead for ConnAsAsyncIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncRead::poll_read(this, cx, buf)
    }
}
impl AsyncWrite for ConnAsAsyncIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_shutdown(this, cx)
    }
}

/// 把 [`TcpmaskManager::wrap_conn_client`] 的 `Box<dyn AsyncIo>` 结果适配为
/// `Box<dyn Connection>`（加 `remote_addr`/`local_addr` no-op）。
///
/// 用在 TCP dial/listen 路径上：`Box<dyn Connection>` → mask 包装 → `Box<dyn Connection>`。
/// 若无 mask（`tcpmasks` 为空），原样返回输入 conn。
pub fn wrap_conn_client_into_connection(
    mgr: &TcpmaskManager,
    conn: Box<dyn crate::connection::Connection>,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    if mgr.tcpmasks.is_empty() {
        return Ok(conn);
    }
    let raw: Box<dyn AsyncIo> = conn_to_asyncio(conn);
    let wrapped = apply_tcpmasks(&mgr.tcpmasks, raw, true)?;
    Ok(Box::new(AsyncIoConn(wrapped)))
}

/// 同 [`wrap_conn_client_into_connection`]，server 侧用。
pub fn wrap_conn_server_into_connection(
    mgr: &TcpmaskManager,
    conn: Box<dyn crate::connection::Connection>,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    if mgr.tcpmasks.is_empty() {
        return Ok(conn);
    }
    let raw: Box<dyn AsyncIo> = conn_to_asyncio(conn);
    let wrapped = apply_tcpmasks(&mgr.tcpmasks, raw, false)?;
    Ok(Box::new(AsyncIoConn(wrapped)))
}

/// 裸 TCP accept 后的连接形态：配了 `finalmask.tcp` 链 → [`Self::Masked`]，
/// 否则原流 [`Self::Plain`] 直通（零包装、零 dyn 分派）。
///
/// 对应 Go `tcp/hub.go` `keepAccepting` 的 `TcpmaskManager.WrapConnServer`：
/// mask 是 wire 最外层，必须在 TLS/REALITY 握手**之前**套上（TLS 记录跑在 mask 内）。
pub enum MaybeTcpMaskConn<C> {
    /// 未配置 finalmask（或 `tcp` 链为空）：原连接直通。
    Plain(C),
    /// 已套 server 侧 mask 链（mask 握手在首次读写时完成）。
    Masked(Box<dyn AsyncIo>),
}

impl<C> MaybeTcpMaskConn<C> {
    /// 未 mask 时返回底层裸流——vision splice 的 `dup_tcp_stream` 只能对它做；
    /// mask 生效时返回 `None`（wire 字节已非明文，裸 socket 克隆不可直接 splice）。
    #[must_use]
    pub fn plain(&self) -> Option<&C> {
        match self {
            Self::Plain(c) => Some(c),
            Self::Masked(_) => None,
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for MaybeTcpMaskConn<C> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(c) => std::pin::Pin::new(c).poll_read(cx, buf),
            Self::Masked(c) => std::pin::Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for MaybeTcpMaskConn<C> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(c) => std::pin::Pin::new(c).poll_write(cx, buf),
            Self::Masked(c) => std::pin::Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(c) => std::pin::Pin::new(c).poll_flush(cx),
            Self::Masked(c) => std::pin::Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(c) => std::pin::Pin::new(c).poll_shutdown(cx),
            Self::Masked(c) => std::pin::Pin::new(c).poll_shutdown(cx),
        }
    }
}

/// accept 后按 `finalmask.tcp` 链做 server 侧包装（Go `hub.go` WrapListener）。
///
/// 空 manager（未配 finalmask / `tcp` 空数组）→ [`MaybeTcpMaskConn::Plain`]
/// 原样直通，未配 mask 的既有入站路径逐字节不变。
///
/// # Errors
/// mask 链构造（如 xmc 的 RSA 派生）失败时返回底层 `io::Error`。
pub fn maybe_mask_server<C: AsyncIo + 'static>(
    mgr: &TcpmaskManager,
    conn: C,
) -> io::Result<MaybeTcpMaskConn<C>> {
    if mgr.tcpmasks.is_empty() {
        return Ok(MaybeTcpMaskConn::Plain(conn));
    }
    let raw: Box<dyn AsyncIo> = Box::new(conn);
    Ok(MaybeTcpMaskConn::Masked(apply_tcpmasks(&mgr.tcpmasks, raw, false)?))
}

/// 便捷入口（TCP 系 transport dial 路径用）：从 `StreamSettings.finalmask_json`
/// 构建 [`TcpmaskManager`] 并 client 侧包装 conn。
///
/// 对应 Go 各 TCP transport dial 中 `streamSettings.TcpmaskManager.WrapConnClient`
/// （websocket/dialer.go:56-63、grpc/dial.go:129-135、httpupgrade/dialer.go:55-60、
/// splithttp/dialer.go:127-134、tcp/dialer.go:27-33）。
/// 无 mask / 空数组 → 原样返回（向后兼容）。
pub fn wrap_conn_client_from_settings(
    settings: &crate::dialer::StreamSettings,
    conn: Box<dyn crate::connection::Connection>,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    let mgr = build_tcpmask_manager_from_json(settings.finalmask_json.as_ref())?;
    if mgr.tcpmasks.is_empty() {
        return Ok(conn);
    }
    wrap_conn_client_into_connection(&mgr, conn)
}

// ===== UDP mask 接入 Connection（o76 残余接线，V-Batch8-fjoj） =====

/// 把 [`UdpmaskManager::wrap_packet_conn_client`] 的 `Box<dyn UdpIo>` 结果适配为
/// `Box<dyn Connection>`（client 侧发往固定 `remote_addr`）。
///
/// 用在 UDP transport dial 路径：`Box<dyn UdpIo>` → mask 包装 → `Box<dyn Connection>`，
/// 让 [`Connection`](crate::connection::Connection) consumer（不关心 UDP vs TCP 抽象）能消费 UDP
/// 流。
///
/// **语义**：每次 read 取 1 个 UDP packet（不足 `buf` 长度则下次 read 取剩余或下一包）；
/// write 把 buffer 发到记录的 `remote_addr`。
///
/// 若 `udpio` 来自空 manager（`udpmasks` 为空），原样适配（无 mask）——无 mask 行为不变。
pub fn wrap_packet_conn_client_into_connection(
    udpio: Box<dyn UdpIo>,
    remote_addr: SocketAddr,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    Ok(Box::new(PacketIoConn::new(udpio, remote_addr)))
}

/// 同 [`wrap_packet_conn_client_into_connection`]，server 侧。
///
/// `remote_addr` 在 server 方向语义弱（UDP 不记录 peer，但传入供 caller 记录上下文）。
/// 默认返回 `Ok(None)`，因 server 真正 peer 来自下一次 recv。
pub fn wrap_packet_conn_server_into_connection(
    udpio: Box<dyn UdpIo>,
    _remote_hint: SocketAddr,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    // ponytail: server 方向无法确定 peer；接口签名保留 remote_hint 仅为对称 client 路径，
    // 实际 `remote_addr()` 返回 Ok(None)。若未来要识别 peer，根据 `_remote_hint` 改进。
    Ok(Box::new(PacketIoConn::new(udpio, SocketAddr::from(([0, 0, 0, 0], 0)))))
}

/// 把 `&[Box<dyn Tcpmask>]` 按 client/server 方向链式包装到 `raw`。
///
/// 对应 Go `TcpmaskManager.WrapConnClient/Server` 的语义：逆序链式 apply。
fn apply_tcpmasks(
    masks: &[Box<dyn Tcpmask>],
    mut raw: Box<dyn AsyncIo>,
    is_client: bool,
) -> io::Result<Box<dyn AsyncIo>> {
    for mask in masks.iter().rev() {
        raw = if is_client { mask.wrap_conn_client(raw)? } else { mask.wrap_conn_server(raw)? };
    }
    Ok(raw)
}

/// `Box<dyn AsyncIo>` → `Box<dyn Connection>` 适配器（`remote_addr`/`local_addr` no-op）。
struct AsyncIoConn(Box<dyn AsyncIo>);

impl AsyncRead for AsyncIoConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // ponytail: AsyncIoConn 是 newtype 包装，Pin 投影到 inner 字段
        // （unsafe 是必要的——Box<dyn AsyncIo> 是 Unpin，且 AsyncIo: Unpin）
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncRead::poll_read(this, cx, buf)
    }
}
impl AsyncWrite for AsyncIoConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: newtype Pin 投影——字段 0 已被外层 Pin 结构性固定，map_unchecked_mut 不产生移动
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_shutdown(this, cx)
    }
}

impl crate::connection::Connection for AsyncIoConn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

/// `Box<dyn UdpIo>` → `Box<dyn Connection>` 适配器（一包一 op 语义）。
///
/// 内部 driver task 在构造时启动，持有底层 socket 的 `Arc<UdpSocket>` clone，
/// 持续 `recv_from` 推到共享 `Mutex<VecDeque<Vec<u8>>>`；`poll_read` 从队列拉出。
///
/// `write` 路径是 fire-and-forget：spawn task 发到 `remote_addr` 后立即返回
/// `Ready(Ok(n))`，**不感知** send 错误——UDP 写错误由 socket 层的 NAT/ICMP
/// 反馈呈现，对应用语义不阻挡（与 Go `net.PacketConn.WriteTo` 同）。
///
/// ponytail: stop 信号缺失——driver task 一直运行直到 socket recv_from 出错（典型的是 socket drop
/// 后内核报 error）。Drop 时 abort JoinHandle 立即取消。
struct PacketIoConn {
    /// 共享底层 socket。`UdpSocket` 是 Sync 通过内核，clone Arc 多 reader OK。
    inner: Arc<dyn UdpIo>,
    /// write 目标地址。
    remote_addr: SocketAddr,
    /// 读队列：driver 收包推入；`poll_recv` 在 `Pending` 时注册 waker——
    /// 语义与 `Notify` + 每次 spawn 唤醒等价，但零辅助任务。
    rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// 写队列（有界，[`PACKET_QUEUE_CAP`]）：`poll_write` 推入后单个 send
    /// worker 顺序 `send_to`——复用 worker 而非每包 spawn（每包 spawn 在高
    /// PPS 下堆积一次性任务）。FIFO 顺序也严格于原并发 spawn。满载丢弃
    /// （UDP 语义）不阻塞上层（票 b2og）。
    tx: mpsc::Sender<Vec<u8>>,
    /// 收/发两方向满载丢弃累计包数（票 b2og）。
    dropped: Arc<AtomicU64>,
    /// recv loop handler；Drop 时 abort 取消。
    driver: Mutex<Option<JoinHandle<()>>>,
    /// send worker handler；Drop 时 abort 取消。
    worker: Mutex<Option<JoinHandle<()>>>,
    /// 上一次 poll_read 装不下而被截断的包尾字节（回填队首，下次 poll_read 先发）。
    /// AsyncRead 是字节流契约：静默丢字节会损坏上层流（如 KCP 段错位）。
    leftover: Mutex<Vec<u8>>,
}

impl PacketIoConn {
    fn new(inner: Box<dyn UdpIo>, remote_addr: SocketAddr) -> Self {
        // Box→Arc 必须走标准库 `From<Box<T>> for Arc<T>`（值 move 进带 {strong,weak}
        // 计数头的新分配）。 此前 Box::into_raw + Arc::from_raw 是 UB：Box
        // 分配没有计数头，Arc::clone 在分配外 fetch_add、drop 按错误 layout dealloc →
        // STATUS_HEAP_CORRUPTION(0xc0000374)。
        let inner: Arc<dyn UdpIo> = inner.into();
        let (pkt_tx, pkt_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_CAP);
        let (snd_tx, mut snd_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        let driver_inner = Arc::clone(&inner);
        let dropped_driver = Arc::clone(&dropped);
        let driver = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_SIZE];
            while let Ok((n, _src)) = driver_inner.recv_from(&mut buf).await {
                // 有界队列：读端消费不过来时丢新包（UDP 语义），计数可观测
                match pkt_tx.try_send(buf[..n].to_vec()) {
                    Ok(()) => {},
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        let total = dropped_driver.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::debug!(
                            dropped = total,
                            "PacketIoConn recv queue full, packet dropped"
                        );
                    },
                    Err(mpsc::error::TrySendError::Closed(_)) => break, // 读端已 drop
                }
            }
        });
        let worker_inner = Arc::clone(&inner);
        let worker = tokio::spawn(async move {
            while let Some(data) = snd_rx.recv().await {
                // ponytail: send 失败仅记日志——Connection 写入 UDP 失败无 caller 同步点，
                // UDP 写错误由 socket 层 NAT/ICMP 反馈呈现（Go PacketConn.WriteTo 同）。
                if let Err(e) = worker_inner.send_to(&data, remote_addr).await {
                    tracing::debug!(error = %e, "PacketIoConn send_to failed");
                }
            }
        });
        Self {
            inner,
            remote_addr,
            rx: Mutex::new(Some(pkt_rx)),
            tx: snd_tx,
            dropped,
            driver: Mutex::new(Some(driver)),
            worker: Mutex::new(Some(worker)),
            leftover: Mutex::new(Vec::new()),
        }
    }
}

impl Drop for PacketIoConn {
    fn drop(&mut self) {
        if let Some(handle) = self.driver.lock().take() {
            handle.abort();
        }
        if let Some(handle) = self.worker.lock().take() {
            handle.abort();
        }
    }
}

impl AsyncRead for PacketIoConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // 先排空上次超长包的剩余字节（回填队首）：AsyncRead 是字节流契约，
        // 丢字节 = 静默损坏上层流（KCP 段错位）。
        {
            let mut leftover = self.leftover.lock();
            if !leftover.is_empty() {
                let n = leftover.len().min(buf.remaining());
                buf.put_slice(&leftover[..n]);
                leftover.drain(..n);
                return std::task::Poll::Ready(Ok(()));
            }
        }
        let mut rx = self.rx.lock();
        let Some(recv) = rx.as_mut() else {
            // driver 已退出且队列排空：EOF（0 字节 Ready 读），上层据此断链而非挂死。
            return std::task::Poll::Ready(Ok(()));
        };
        match recv.poll_recv(cx) {
            std::task::Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..n]);
                if n < pkt.len() {
                    // 超长包剩余字节回填队首（7xia）：读缓冲装不下的部分留到下次
                    // poll_read 先发——Go 无此桥接层（kcp 直接以 mtu 级缓冲读
                    // PacketConn 恒不截断），按 AsyncRead 流契约保留全部字节，
                    // 不静默丢弃。driver 层 recv_from(buf=UDP_SIZE) 的 UDP 截断
                    // 与 Go ReadFrom 截断语义一致（保留）。
                    *self.leftover.lock() = pkt[n..].to_vec();
                }
                std::task::Poll::Ready(Ok(()))
            },
            std::task::Poll::Ready(None) => {
                *rx = None;
                std::task::Poll::Ready(Ok(()))
            },
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketIoConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let n = buf.len();
        // fire-and-forget：入队即 Ready；worker 异步发送。队列有界（票 b2og）：
        // 满 = 对端黑洞且 socket 缓冲长期满 → 丢包计数（UDP 语义），不阻塞上层。
        // 队列关闭仅在 conn 已半亡（worker 被 abort）时发生，包静默丢弃与原
        // spawn-丢包语义一致。
        match self.tx.try_send(buf.to_vec()) {
            Ok(()) => {},
            Err(mpsc::error::TrySendError::Full(_)) => {
                let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(dropped = total, "PacketIoConn send queue full, packet dropped");
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("PacketIoConn send queue closed, packet dropped");
            },
        }
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::connection::Connection for PacketIoConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        if self.remote_addr.ip().is_unspecified() && self.remote_addr.port() == 0 {
            Ok(None)
        } else {
            Ok(Some(self.remote_addr))
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr().map(Some)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityMode {
    /// 无加密，XOR 链 + FNV1a-32 认证。
    #[default]
    Original,
    /// AES-128-GCM AEAD。
    Aes128Gcm,
    /// Salamander BLAKE2b 混淆。
    Salamander,
}

impl SecurityMode {
    /// 从字符串解析（对应 Go proto enum name）。
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "original" | "none" | "zero" => Some(Self::Original),
            "aes-128-gcm" | "aes128gcm" => Some(Self::Aes128Gcm),
            "salamander" => Some(Self::Salamander),
            _ => None,
        }
    }
}

/// Finalmask 顶层配置（对应 Go `FinalmaskConfig` + KCP `SecurityConfig`）。
#[derive(Debug, Clone, Default)]
pub struct FinalmaskConfig {
    /// 加密模式。
    pub security: SecurityMode,
    /// 共享密码（aes128gcm/salamander 使用）。
    pub password: String,
    /// 协议头伪装 ID（0=DNS, 1=DTLS, 2=SRTP, 3=uTP, 4=WeChat, 5=WireGuard）。
    pub header_id: Option<i32>,
}

/// 根据配置构建 UDP 伪装管理器（对应 Go `CreateUdpmaskManager`）。
///
/// 按 `header` → `security` 顺序追加到 manager，对应 Go `slices.Backward` 逆序应用。
pub fn build_udpmask_manager(config: &FinalmaskConfig) -> io::Result<UdpmaskManager> {
    let mut masks: Vec<Box<dyn Udpmask>> = Vec::new();

    // 1. Security mask
    match config.security {
        SecurityMode::Original => {
            masks.push(Box::new(mkcp::original::OriginalConfig));
        },
        SecurityMode::Aes128Gcm => {
            masks.push(Box::new(mkcp::aes128gcm::Aes128GcmConfig {
                password: config.password.clone(),
            }));
        },
        SecurityMode::Salamander => {
            masks
                .push(Box::new(salamander::SalamanderConfig { password: config.password.clone() }));
        },
    }

    // 2. Header mask (optional, wraps security layer)
    if let Some(id) = config.header_id {
        if let Some(hid) = mkcp::header::HeaderId::from_i32(id) {
            masks.push(Box::new(mkcp::header::HeaderConfig::from_id(hid)));
        }
    }

    Ok(UdpmaskManager::new(masks))
}
// ===== 从 streamSettings.finalmask JSON 构造 Manager =====

/// 从 `finalmask_json` 构造 [`UdpmaskManager`]（对应 Go `streamSettings.UdpmaskManager`）。
///
/// JSON 形态与 `parse_finalmask_udp_chain` 一致：顶层为对象，`udp` 数组每项
/// `{"type","settings"}`。支持的 mask 类型（对齐 Go `infra/conf` `udpmaskLoader`）：
///
/// - `mkcp-legacy` —— `mkcp-original` / `mkcp-aes128gcm` / `header-*`（KCP 原版）
/// - `salamander` —— `SalamanderConfig{ password }`
/// - `noise` —— `NoiseConfig{ reset, noise[] }`（周期重置 + 噪声包序列）
/// - `sudoku` —— `SudokuConfig`（UDP/TCP 共用同一配置形态）
/// - `xdns` —— `xdns::Config{ domains, resolvers, extra_poll }`（DNS-over-UDP 隧道，v26.9.30 形态）
/// - `xicmp` —— `XicmpConfig{ ips, dgram }`（wrap 时仅允许最外层）
/// - `realm` —— `realm::Config`（STUN/HTTP NAT 穿透，settings 从 `url` 解析）
/// - `udphop` —— `udphop::UdphopConfig`（UDP 端口跳跃，client-only；Go 三模式
///   intervallocal/intervalremote/perconnremote + remoteIPs 前缀随机 + remotePorts
///   轮换，interval>=5s 双层校验）
/// - `header-custom` —— `custom::Config`（自定义 UDP 头，`mode`=prefix/standalone）
///
/// 未知 mask 类型返回 `InvalidInput`（不静默丢配置）。`None` 或空 `udp` 数组返回
/// 空 manager（无 mask 行为不变）。
///
/// 与 `parse_finalmask_udp_chain` 的差别：本函数返回 `UdpmaskManager`
/// （可调 `wrap_packet_conn_client/server`），后者返回 `CodecChain`（同步
/// `encode/decode`，供 KCP 等同步 UDP 栈逐包 mask）。
pub fn build_udpmask_manager_from_json(
    json: Option<&serde_json::Value>,
) -> io::Result<UdpmaskManager> {
    let mut masks: Vec<Box<dyn Udpmask>> = Vec::new();
    let Some(v) = json else {
        return Ok(UdpmaskManager::new(masks));
    };
    let Some(arr) = v.get("udp").and_then(|x| x.as_array()) else {
        return Ok(UdpmaskManager::new(masks));
    };
    for entry in arr {
        masks.push(build_udpmask_entry(entry)?);
    }
    Ok(UdpmaskManager::new(masks))
}

fn build_udpmask_entry(entry: &serde_json::Value) -> io::Result<Box<dyn Udpmask>> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: expected an object"))?;
    let mask_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: missing `type`"))?;
    let settings = obj.get("settings").cloned().unwrap_or(serde_json::Value::Null);
    match mask_type {
        "mkcp-legacy" => build_mkcp_legacy_udpmask(&settings),
        "salamander" => {
            // Go Salamander.PacketSize（transport_finalmask.go:747-749，Build :753-760）：
            // PacketSize 是 Int32Range（common.go:298-311 只收 "a-b" 字符串或纯数字，
            // 对象/布尔形态 Go 直接 "Invalid integer range" 硬错）。to>0 切
            // GeckoConfig（QUIC 长头分片原语，wire 不同于普通 salamander）；Rust
            // gecko 子模式未实现（salamander.rs 模块注释），to>0 显式拒绝——静默
            // 保持普通 salamander 会伪装成同 wire 而实际对端语义已变。to<=0（Go
            // 走普通分支）放行。
            let to = match settings.get("packetSize") {
                None | Some(serde_json::Value::Null) => 0,
                Some(serde_json::Value::String(s)) => parse_range_string(s)?.1,
                Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
                Some(_) => {
                    return Err(mask_err(
                        "finalmask: salamander \"packetSize\": invalid integer range, expected \
                         string of form \"1-2\" or plain integer",
                    ));
                },
            };
            if to > 0 {
                return Err(mask_err(
                    "finalmask: salamander \"packetSize\" (gecko mode) is not supported by this \
                     build; remove the key",
                ));
            }
            Ok(Box::new(salamander::SalamanderConfig {
                password: settings
                    .get("password")
                    .or_else(|| settings.get("key"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }))
        },
        "noise" => build_noise_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "sudoku" => Ok(Box::new(build_sudoku_config(&settings))),
        "xdns" => build_xdns_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "xicmp" => build_xicmp_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "realm" => build_realm_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "header-custom" => {
            let (udp, udp_standalone) = build_custom_udp(&settings)?;
            Ok(Box::new(custom::Config { udp, udp_standalone, ..custom::Config::default() }))
        },
        // 票 4kq9：client-only 连接级包装（Go udphop/config.go WrapPacketConnServer
        // 报 client only，server 侧同构拒绝；interval>=5 双层校验在模块内）。
        "udphop" => build_udphop_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("finalmask: unsupported udp mask type {other:?}"),
        )),
    }
}

/// `mkcp-legacy` → `Udpmask`（对应 Go `MkcpLegacy.Build` UDP 形态）。
///
/// `header` 空 + `password`/`value` 空 → `OriginalConfig`。
/// `header` 空 + `password`/`value` 非空 → `Aes128GcmConfig{ password }`。
/// `header` 非空（dns/dtls/srtp/utp/wechat/wireguard）→ `HeaderConfig::from_id(...)`。
fn build_mkcp_legacy_udpmask(settings: &serde_json::Value) -> io::Result<Box<dyn Udpmask>> {
    let header = settings.get("header").and_then(|v| v.as_str()).unwrap_or("");
    let password = settings
        .get("password")
        .or_else(|| settings.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !header.is_empty() {
        // ponytail: dns 用 value 字段作 domain（与 codec 路径一致），其他 header 忽略 value
        let domain = settings
            .get("domain")
            .or_else(|| settings.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("www.baidu.com")
            .to_string();
        let id = match header.to_ascii_lowercase().as_str() {
            "dns" => mkcp::header::HeaderId::Dns,
            "dtls" => mkcp::header::HeaderId::Dtls,
            "srtp" => mkcp::header::HeaderId::Srtp,
            "utp" => mkcp::header::HeaderId::Utp,
            "wechat" => mkcp::header::HeaderId::Wechat,
            "wireguard" => mkcp::header::HeaderId::Wireguard,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("finalmask: invalid header {header:?}"),
                ));
            },
        };
        let cfg = mkcp::header::HeaderConfig { id, domain };
        return Ok(Box::new(cfg));
    }
    if !password.is_empty() {
        return Ok(Box::new(mkcp::aes128gcm::Aes128GcmConfig { password: password.to_string() }));
    }
    Ok(Box::new(mkcp::original::OriginalConfig))
}

/// 从 `finalmask_json` 构造 [`TcpmaskManager`]（对应 Go `streamSettings.TcpmaskManager`）。
///
/// JSON 形态顶层对象 `tcp` 数组，每项 `{"type","settings"}`。支持（对齐 Go
/// `infra/conf` `tcpmaskLoader`）：
///
/// - `fragment` —— `FragmentConfig{ packets_from, packets_to, length, interval }`
/// - `sudoku` —— `SudokuConfig`（与 UDP 同一配置形态）
/// - `xmc` —— `xmc::Config`（Minecraft 握手伪装，profiles + password 派生 RSA）
/// - `header-custom` —— `custom::Config`（自定义 TCP 序列 clients/servers/errors）
///
/// 未知 mask 类型返回 `InvalidInput`。`None` / 缺失 `tcp` 键 / 空数组 → 空 manager。
pub fn build_tcpmask_manager_from_json(
    json: Option<&serde_json::Value>,
) -> io::Result<TcpmaskManager> {
    let mut masks: Vec<Box<dyn Tcpmask>> = Vec::new();
    let Some(v) = json else {
        return Ok(TcpmaskManager::new(masks));
    };
    let Some(arr) = v.get("tcp").and_then(|x| x.as_array()) else {
        return Ok(TcpmaskManager::new(masks));
    };
    for entry in arr {
        masks.push(build_tcpmask_entry(entry)?);
    }
    Ok(TcpmaskManager::new(masks))
}

fn build_tcpmask_entry(entry: &serde_json::Value) -> io::Result<Box<dyn Tcpmask>> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: expected an object"))?;
    let mask_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: missing `type`"))?;
    let settings = obj.get("settings").cloned().unwrap_or(serde_json::Value::Null);
    match mask_type {
        "fragment" => build_fragment_config(&settings).map(|c| Box::new(c) as Box<dyn Tcpmask>),
        "sudoku" => Ok(Box::new(build_sudoku_config(&settings))),
        "xmc" => build_xmc_config(&settings).map(|c| Box::new(c) as Box<dyn Tcpmask>),
        "header-custom" => build_custom_tcp(&settings).map(|tcp| {
            Box::new(custom::Config { tcp: Some(tcp), ..custom::Config::default() })
                as Box<dyn Tcpmask>
        }),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("finalmask: unsupported tcp mask type {other:?}"),
        )),
    }
}

// ===== JSON settings → 各 mask 模块 Config（对齐 Go `infra/conf/transport_finalmask.go`）=====

fn mask_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn json_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

fn json_str_vec(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn json_bool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn json_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

/// Go `Int32Range`：接受整数 / `{from,to}` / `"a-b"` 字符串；from>to 时交换（ensureOrder）。
fn json_range(v: &serde_json::Value, key: &str) -> io::Result<(i64, i64)> {
    match v.get(key) {
        Some(serde_json::Value::Object(o)) => {
            let from = o.get("from").and_then(|x| x.as_i64()).unwrap_or(0);
            let to = o.get("to").and_then(|x| x.as_i64()).unwrap_or(0);
            Ok((from.min(to), from.max(to)))
        },
        Some(serde_json::Value::Number(n)) => {
            let x =
                n.as_i64().ok_or_else(|| mask_err(format!("invalid integer range for {key:?}")))?;
            Ok((x, x))
        },
        Some(serde_json::Value::String(s)) => parse_range_string(s),
        None | Some(serde_json::Value::Null) => Ok((0, 0)),
        Some(_) => Err(mask_err(format!("invalid range for {key:?}"))),
    }
}

/// Go `ParseRangeString`："114-514" / "-114-514" / "114514" / ""→(0,0)；非法字符串报错。
fn parse_range_string(s: &str) -> io::Result<(i64, i64)> {
    let invalid = || mask_err(format!("invalid range string {s:?}"));
    let s = s.trim();
    if s.is_empty() {
        return Ok((0, 0));
    }
    let body = s.strip_prefix('-').unwrap_or(s);
    let (first, second) = match body.split_once('-') {
        None => {
            let x: i64 = s.parse().map_err(|_| invalid())?;
            return Ok((x, x));
        },
        Some((l, r)) => {
            let l = if body.len() < s.len() { format!("-{l}") } else { l.to_string() };
            (l, r.to_string())
        },
    };
    let lo: i64 = first.parse().map_err(|_| invalid())?;
    let hi: i64 = second.parse().map_err(|_| invalid())?;
    Ok((lo.min(hi), lo.max(hi)))
}

/// Go `RandRange`：缺省 `{0,255}`；越界（越出 0..=255）报错（对齐 Go Build 校验）。
fn json_rand_range(v: &serde_json::Value) -> io::Result<(i64, i64)> {
    let (from, to) = if v.get("randRange").is_none_or(|x| x.is_null()) {
        (0, 255)
    } else {
        json_range(v, "randRange")?
    };
    if !(0..=255).contains(&from) || !(0..=255).contains(&to) {
        return Err(mask_err("invalid randRange"));
    }
    Ok((from, to))
}

/// Go `PraseByteSlice`：`""`/`"array"`=JSON 字节数组、`"str"`、`"hex"`、`"base64"`。
fn parse_byte_slice(raw: Option<&serde_json::Value>, typ: &str) -> io::Result<Vec<u8>> {
    match typ.to_ascii_lowercase().as_str() {
        "" | "array" => match raw {
            None => Ok(Vec::new()),
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .map(|x| {
                    x.as_u64()
                        .filter(|n| *n <= 255)
                        .map(|n| n as u8)
                        .ok_or_else(|| mask_err("packet byte must be 0-255"))
                })
                .collect(),
            Some(_) => Err(mask_err("packet must be a JSON byte array for type array")),
        },
        "str" => Ok(raw.and_then(|x| x.as_str()).unwrap_or("").as_bytes().to_vec()),
        "hex" => hex::decode(raw.and_then(|x| x.as_str()).unwrap_or(""))
            .map_err(|e| mask_err(format!("invalid hex packet: {e}"))),
        "base64" => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(raw.and_then(|x| x.as_str()).unwrap_or(""))
                .map_err(|e| mask_err(format!("invalid base64 packet: {e}")))
        },
        _ => Err(mask_err(format!("unknown type {typ:?}"))),
    }
}

/// Go `validateCustomVarName`：空串放行；否则 `^[A-Za-z_][A-Za-z0-9_]*$`。
fn validate_var_name(name: &str) -> io::Result<()> {
    let ok = name.is_empty()
        || (name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    if ok { Ok(()) } else { Err(mask_err(format!("invalid variable name {name:?}"))) }
}

/// Go `validateCustomItemSpec`：packet/rand/reuse/transform 至多一种；全空时不得有 capture。
fn validate_item_kinds(
    packet_len: usize,
    rand: i32,
    reuse: &str,
    has_transform: bool,
    capture: &str,
) -> io::Result<()> {
    let kinds = usize::from(packet_len > 0)
        + usize::from(rand > 0)
        + usize::from(!reuse.is_empty())
        + usize::from(has_transform);
    if kinds > 1 || (kinds == 0 && !capture.is_empty()) {
        return Err(mask_err("exactly one item kind must be set"));
    }
    Ok(())
}

/// Go `buildCustomTransform`。
fn parse_expr(v: &serde_json::Value) -> io::Result<custom::Expr> {
    let op = json_str(v, "op");
    if op.is_empty() {
        return Err(mask_err("transform op is required"));
    }
    let args = v
        .get("args")
        .and_then(|x| x.as_array())
        .ok_or_else(|| mask_err("transform args are required"))?;
    if args.is_empty() {
        return Err(mask_err("transform args are required"));
    }
    Ok(custom::Expr {
        op: op.to_string(),
        args: args.iter().map(parse_expr_arg).collect::<io::Result<_>>()?,
    })
}

/// Go `buildCustomTransformArg`：bytes/u64/reuse/metadata/transform 恰好一种。
fn parse_expr_arg(v: &serde_json::Value) -> io::Result<custom::ExprArg> {
    let bytes_raw = v.get("bytes").filter(|x| !x.is_null());
    let has_bytes = match bytes_raw {
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(_) => true,
        None => false,
    };
    let has_u64 = v.get("u64").is_some_and(|x| !x.is_null());
    let reuse = json_str(v, "reuse");
    let metadata = json_str(v, "metadata");
    let transform = v.get("transform").filter(|x| !x.is_null());
    let kinds = usize::from(has_bytes)
        + usize::from(has_u64)
        + usize::from(!reuse.is_empty())
        + usize::from(!metadata.is_empty())
        + usize::from(transform.is_some());
    if kinds != 1 {
        return Err(mask_err("transform arg must set exactly one value"));
    }
    if has_bytes {
        return Ok(custom::ExprArg::Bytes(parse_byte_slice(bytes_raw, json_str(v, "type"))?));
    }
    if has_u64 {
        let n = v.get("u64").and_then(|x| x.as_u64()).ok_or_else(|| mask_err("invalid u64 arg"))?;
        return Ok(custom::ExprArg::U64(n));
    }
    if !reuse.is_empty() {
        validate_var_name(reuse)?;
        return Ok(custom::ExprArg::Var(reuse.to_string()));
    }
    if !metadata.is_empty() {
        return Ok(custom::ExprArg::Metadata(metadata.to_string()));
    }
    Ok(custom::ExprArg::Expr(Box::new(parse_expr(
        transform.expect("kinds==1 且前置分支未命中，transform 必为 Some"),
    )?)))
}

/// Go `HeaderCustomTCP.Build` → `custom::TCPConfig`。
fn build_custom_tcp(settings: &serde_json::Value) -> io::Result<custom::TCPConfig> {
    Ok(custom::TCPConfig {
        clients: parse_tcp_sequences(settings, "clients")?,
        servers: parse_tcp_sequences(settings, "servers")?,
        errors: parse_tcp_sequences(settings, "errors")?,
    })
}

fn parse_tcp_sequences(
    settings: &serde_json::Value,
    key: &str,
) -> io::Result<Vec<custom::TCPSequence>> {
    let Some(rows) = settings.get(key).and_then(|x| x.as_array()) else {
        return Ok(Vec::new());
    };
    rows.iter()
        .map(|row| {
            let items = row
                .as_array()
                .ok_or_else(|| mask_err(format!("header-custom: {key} row must be an array")))?;
            Ok(custom::TCPSequence {
                sequence: items.iter().map(parse_custom_tcp_item).collect::<io::Result<_>>()?,
            })
        })
        .collect()
}

fn parse_custom_tcp_item(v: &serde_json::Value) -> io::Result<custom::TCPItem> {
    let rand = json_i64(v, "rand") as i32;
    let (rand_min, rand_max) = json_rand_range(v)?;
    let packet = parse_byte_slice(v.get("packet"), json_str(v, "type"))?;
    let save = json_str(v, "capture");
    let reuse = json_str(v, "reuse");
    validate_var_name(save)?;
    validate_var_name(reuse)?;
    let transform = v.get("transform").filter(|x| !x.is_null());
    validate_item_kinds(packet.len(), rand, reuse, transform.is_some(), save)?;
    let (delay_min, delay_max) = json_range(v, "delay")?;
    Ok(custom::TCPItem {
        delay_min,
        delay_max,
        rand,
        rand_min: rand_min as u8,
        rand_max: rand_max as u8,
        packet,
        save: save.to_string(),
        var: reuse.to_string(),
        expr: match transform {
            Some(t) => Some(parse_expr(t)?),
            None => None,
        },
    })
}

fn parse_custom_udp_item(v: &serde_json::Value) -> io::Result<custom::UDPItem> {
    let rand = json_i64(v, "rand") as i32;
    let (rand_min, rand_max) = json_rand_range(v)?;
    let packet = parse_byte_slice(v.get("packet"), json_str(v, "type"))?;
    let save = json_str(v, "capture");
    let reuse = json_str(v, "reuse");
    validate_var_name(save)?;
    validate_var_name(reuse)?;
    let transform = v.get("transform").filter(|x| !x.is_null());
    validate_item_kinds(packet.len(), rand, reuse, transform.is_some(), save)?;
    Ok(custom::UDPItem {
        rand,
        rand_min: rand_min as u8,
        rand_max: rand_max as u8,
        packet,
        save: save.to_string(),
        var: reuse.to_string(),
        expr: match transform {
            Some(t) => Some(parse_expr(t)?),
            None => None,
        },
    })
}

/// Go `HeaderCustomUDP.Build` → `(prefix 形态, standalone 形态)`。
fn build_custom_udp(
    settings: &serde_json::Value,
) -> io::Result<(Option<custom::UDPConfig>, Option<custom::UDPConfig>)> {
    let mode = json_str(settings, "mode");
    match mode {
        "" | "prefix" | "standalone" => {},
        other => return Err(mask_err(format!("unknown udp mode {other:?}"))),
    }
    let read_items = |key: &str| -> io::Result<Vec<custom::UDPItem>> {
        match settings.get(key).and_then(|x| x.as_array()) {
            None => Ok(Vec::new()),
            Some(items) => items.iter().map(parse_custom_udp_item).collect(),
        }
    };
    let cfg = custom::UDPConfig { client: read_items("client")?, server: read_items("server")? };
    Ok(if mode == "standalone" { (None, Some(cfg)) } else { (Some(cfg), None) })
}

/// Go `NoiseMask.Build` → `noise::NoiseConfig`。
fn build_noise_config(settings: &serde_json::Value) -> io::Result<noise::NoiseConfig> {
    // Go NoiseMask.script（transport_finalmask.go:313）走 xlua 编译的噪声脚本；
    // Rust 无 Lua 运行时，非空 script 显式拒绝而非静默忽略（票 5std M14，alwc
    // fail-loud 模式——静默丢 = 整个噪声掩码不生效）。空串/null = 未设置
    // （Go `if c.Script != ""` 同语义），放行。
    if let Some(s) = settings.get("script") {
        let requested = match s {
            serde_json::Value::String(x) => !x.is_empty(),
            serde_json::Value::Null => false,
            _ => true,
        };
        if requested {
            return Err(mask_err(
                "noise script (Lua) is not supported by this build; remove the \"script\" key or use \"noise\" items instead",
            ));
        }
    }
    let (reset_min, reset_max) = json_range(settings, "reset")?;
    let empty: Vec<serde_json::Value> = Vec::new();
    let mut items = Vec::new();
    for item in settings.get("noise").and_then(|x| x.as_array()).unwrap_or(&empty) {
        let (rand_min, rand_max) = json_range(item, "rand")?;
        let is_exp = json_str(item, "type").eq_ignore_ascii_case("exp");
        // Go：互斥校验先于 exp 分支——exp 的 packet 是 JSON 字符串（原始字节恒非空），
        // 故 type=exp 且 rand.to>0 时 Go 侧必触发互斥错误，此处对齐。
        if rand_max > 0 && is_exp {
            return Err(mask_err("noise item: packet and rand are mutually exclusive"));
        }
        if is_exp {
            let Some(exp) = item.get("packet").and_then(|x| x.as_str()) else {
                return Err(mask_err(r#""packet" of noise "type": "exp" must be a string"#));
            };
            let segments = parse_noise_exp(exp)?;
            let (delay_min, delay_max) = json_range(item, "delay")?;
            items.push(noise::NoiseItem {
                segments,
                delay_min,
                delay_max,
                ..noise::NoiseItem::default()
            });
            continue;
        }
        let packet = parse_byte_slice(item.get("packet"), json_str(item, "type"))?;
        if !packet.is_empty() && rand_max > 0 {
            return Err(mask_err("noise item: packet and rand are mutually exclusive"));
        }
        let (rand_range_min, rand_range_max) = json_rand_range(item)?;
        let (delay_min, delay_max) = json_range(item, "delay")?;
        items.push(noise::NoiseItem {
            rand_min,
            rand_max,
            rand_range_min: rand_range_min as i32,
            rand_range_max: rand_range_max as i32,
            packet,
            delay_min,
            delay_max,
            segments: Vec::new(),
        });
    }
    Ok(noise::NoiseConfig { reset_min, reset_max, items })
}

/// Go `parseNoiseExp`（e51b3c36）：按 `<\s*([a-z]+)(?:\s+([^>]*?))?\s*>` 逐段切分
/// exp 表达式；段间/尾部非空白内容报 `invalid noise exp near ...`；零段报
/// `empty noise exp`。手写扫描复刻正则语义（避免为此引入 regex 依赖）。
fn parse_noise_exp(exp: &str) -> io::Result<Vec<noise::NoiseSegment>> {
    let mut segments = Vec::new();
    let bytes = exp.as_bytes();
    let (mut last, mut i) = (0usize, 0usize);
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let Some((end, key, arg)) = try_match_noise_tag(exp, i) else {
            i += 1;
            continue;
        };
        if !exp[last..i].trim().is_empty() {
            return Err(mask_err(format!("invalid noise exp near {}", &exp[last..i])));
        }
        last = end;
        i = end;
        segments.push(build_noise_segment(key, arg)?);
    }
    if !exp[last..].trim().is_empty() {
        return Err(mask_err(format!("invalid noise exp near {}", &exp[last..])));
    }
    if segments.is_empty() {
        return Err(mask_err(format!("empty noise exp: {exp}")));
    }
    Ok(segments)
}

/// 在 `start` 处尝试匹配 Go 正则 `<\s*([a-z]+)(?:\s+([^>]*?))?\s*>`。
///
/// 成功返回 `(匹配终点, key, arg)`；失败返回 `None`（调用方前移一格继续扫描，
/// 与 `FindAllStringSubmatchIndex` 的逐位置尝试语义一致）。
fn try_match_noise_tag(exp: &str, start: usize) -> Option<(usize, &str, &str)> {
    let b = exp.as_bytes();
    let mut j = start + 1;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    let key_start = j;
    while j < b.len() && b[j].is_ascii_lowercase() {
        j += 1;
    }
    if j == key_start {
        return None;
    }
    let key = &exp[key_start..j];
    // 可选参数组 `\s+([^>]*?)` + 尾随 `\s*`：arg 从首个非空白起，到 `'>'` 前的
    // 最后一个非空白止（惰性 `[^>]*?` 与贪婪 `\s*` 的净效果）。
    let mut k = j;
    while k < b.len() && b[k].is_ascii_whitespace() {
        k += 1;
    }
    match b.get(k) {
        Some(b'>') => Some((k + 1, key, "")),
        Some(_) => {
            let mut m = k;
            while m < b.len() && b[m] != b'>' {
                m += 1;
            }
            if m >= b.len() {
                return None;
            }
            Some((m + 1, key, exp[k..m].trim_end()))
        },
        None => None,
    }
}

/// Go `buildNoiseSegment`：`<key arg>` → [`noise::NoiseSegment`]。
///
/// - `b`：hex 字节串（容忍内部空白，`0x`/`0X` 前缀可剥）
/// - `r`/`rc`/`rd`：随机字节/ASCII 字母/数字，尺寸 `"lo-hi"` 或 `"n"`（0..=65535）
/// - `t`/`c`/`n`：时间戳/计数器/nonce，无参
fn build_noise_segment(key: &str, arg: &str) -> io::Result<noise::NoiseSegment> {
    let size_segment = |kind: noise::NoiseSegmentKind| -> io::Result<noise::NoiseSegment> {
        if arg.is_empty() {
            return Err(mask_err(format!("<{key}> in noise exp needs a size")));
        }
        let (lo, hi) = parse_range_string(arg)?;
        if lo < 0 || hi < lo || hi > 65535 {
            return Err(mask_err(format!("invalid size in noise exp: {arg}")));
        }
        Ok(noise::NoiseSegment { kind, bytes: Vec::new(), min_size: lo, max_size: hi })
    };
    match key {
        "b" => {
            let joined: String = arg.split_whitespace().collect();
            let hex_str =
                joined.strip_prefix("0x").or_else(|| joined.strip_prefix("0X")).unwrap_or(&joined);
            if hex_str.is_empty() {
                return Err(mask_err("empty bytes in noise exp"));
            }
            let raw = hex::decode(hex_str)
                .map_err(|e| mask_err(format!("invalid hex in noise exp: {arg}: {e}")))?;
            Ok(noise::NoiseSegment { bytes: raw, ..noise::NoiseSegment::default() })
        },
        "r" => size_segment(noise::NoiseSegmentKind::Random),
        "rc" => size_segment(noise::NoiseSegmentKind::RandomAscii),
        "rd" => size_segment(noise::NoiseSegmentKind::RandomDigit),
        "t" | "c" | "n" => {
            if !arg.is_empty() {
                return Err(mask_err(format!("<{key}> in noise exp takes no argument")));
            }
            let kind = match key {
                "t" => noise::NoiseSegmentKind::Timestamp,
                "c" => noise::NoiseSegmentKind::Counter,
                _ => noise::NoiseSegmentKind::Nonce,
            };
            Ok(noise::NoiseSegment { kind, ..noise::NoiseSegment::default() })
        },
        _ => Err(mask_err(format!("unknown <{key}> in noise exp"))),
    }
}

/// Go `Sudoku.Build` → `sudoku::SudokuConfig`（新驼峰键优先，legacy 下划线键兜底）。
fn build_sudoku_config(settings: &serde_json::Value) -> sudoku::SudokuConfig {
    sudoku::SudokuConfig {
        password: json_str(settings, "password").to_string(),
        ascii: json_str(settings, "ascii").to_string(),
        custom_table: {
            let t = json_str(settings, "customTable");
            if t.is_empty() {
                json_str(settings, "custom_table").to_string()
            } else {
                t.to_string()
            }
        },
        custom_tables: {
            let t = json_str_vec(settings, "customTables");
            if t.is_empty() { json_str_vec(settings, "custom_tables") } else { t }
        },
        padding_min: {
            let p = json_i64(settings, "paddingMin").max(0) as u32;
            if p == 0 { json_i64(settings, "padding_min").max(0) as u32 } else { p }
        },
        padding_max: {
            let p = json_i64(settings, "paddingMax").max(0) as u32;
            if p == 0 { json_i64(settings, "padding_max").max(0) as u32 } else { p }
        },
    }
}

/// Go `XDNS.Build` → `xdns::Config`（bd 2ktp ④ 对齐 v26.9.30：domains 为对象
/// 数组（lenLimit/labelLimit 缺省 255/63），resolvers 为 `{type,settings.addr}`，
/// extraPoll 0-3；`domain` 键已废弃）。resolver `settings` 内 `addr` 以外的键
/// （worker/tlsConfig/quicConfig 等）本 JSON 层不支持，显式报错不静默丢弃
/// （Go conf 层由 `XDNSResolver` 展开为 `ResolverProto` 字段，Rust conf 层
/// 尚未实现该形态，见 bd o7ns D4 能力边界）。
fn build_xdns_config(settings: &serde_json::Value) -> io::Result<xdns::Config> {
    if settings.get("domain").is_some_and(|x| !x.is_null()) {
        return Err(mask_err(
            "xdns: `domain` was removed; use domains(server) & resolvers(client)",
        ));
    }
    let mut domains = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = settings.get("domains") {
        for d in arr {
            domains.extend(xdns::build_domain_config(d)?);
        }
    }
    let mut resolvers = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = settings.get("resolvers") {
        for r in arr {
            let obj = r.as_object().ok_or_else(|| mask_err("xdns: resolver must be an object"))?;
            let rtype = obj
                .get("type")
                .and_then(|t| t.as_str())
                .ok_or_else(|| mask_err("xdns: resolver missing type"))?;
            let resolver_settings = obj
                .get("settings")
                .and_then(|s| s.as_object())
                .ok_or_else(|| mask_err("xdns: resolver missing settings"))?;
            let addr = resolver_settings
                .get("addr")
                .and_then(|a| a.as_str())
                .ok_or_else(|| mask_err("xdns: resolver missing settings.addr"))?;
            for key in resolver_settings.keys() {
                if key != "addr" {
                    return Err(mask_err(format!(
                        "xdns: resolver setting {key:?} not supported (only addr)"
                    )));
                }
            }
            let kind = match rtype {
                "udp" => xdns::ResolverKind::Udp,
                "tcp" => xdns::ResolverKind::Tcp,
                "https" => {
                    return Err(mask_err(
                        "xdns: DOH (https) resolver not supported (UDP-only stack)",
                    ));
                },
                other => {
                    return Err(mask_err(format!("xdns: unknown resolver type {other:?}")));
                },
            };
            resolvers.push(xdns::ResolverConfig {
                kind,
                addr: addr.to_string(),
                worker: 0,
                tls_config: None,
                quic_config: None,
            });
        }
    }
    let extra_poll = match settings.get("extraPoll") {
        Some(x) if !x.is_null() => {
            x.as_i64().ok_or_else(|| mask_err("xdns: invalid extraPoll"))? as i32
        },
        _ => 0,
    };
    if !(0..=3).contains(&extra_poll) {
        return Err(mask_err("xdns: extraPoll < 0 || extraPoll > 3"));
    }
    Ok(xdns::Config { domains, resolvers, extra_poll })
}

/// Go `Xicmp.Build` → `XicmpConfig`；「仅最外层」约束由 wrap 时 `level != 0` 校验（模块内）。
fn build_xicmp_config(settings: &serde_json::Value) -> io::Result<xicmp::XicmpConfig> {
    let ips = json_str_vec(settings, "ips");
    for ip in &ips {
        ip.parse::<std::net::IpAddr>()
            .map_err(|e| mask_err(format!("xicmp: invalid ip {ip:?}: {e}")))?;
    }
    Ok(xicmp::XicmpConfig { ips, dgram: json_bool(settings, "dgram") })
}

/// Go `Realm.Build` → `realm::Config`（URL 形如 `realm://token@host:port/id`；
/// scheme `realm`→https、`realm+http`→http；Rust 端 TLS 细节由 `use_tls` 简化承载）。
fn build_realm_config(settings: &serde_json::Value) -> io::Result<realm::Config> {
    let url = json_str(settings, "url");
    let (raw_scheme, rest) =
        url.split_once("://").ok_or_else(|| mask_err(format!("realm: invalid url {url:?}")))?;
    let scheme = match raw_scheme {
        "realm" => "https",
        "realm+http" => "http",
        other => return Err(mask_err(format!("realm: invalid scheme {other:?}"))),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (u, h),
        None => ("", authority),
    };
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return Err(mask_err("realm: invalid host"));
    }
    let port = match port {
        Some(p) => p,
        None if scheme == "http" => "80".to_string(),
        None => "443".to_string(),
    };
    let token = percent_decode(userinfo)?;
    if token.is_empty() {
        return Err(mask_err("realm: invalid token"));
    }
    let id = percent_decode(path)?;
    if id.is_empty() {
        return Err(mask_err("realm: invalid id"));
    }
    let stun_servers = json_str_vec(settings, "stunServers");
    if stun_servers.is_empty() {
        return Err(mask_err("realm: empty stunServers"));
    }
    for s in &stun_servers {
        let (h, p) = split_host_port(s)?;
        if h.is_empty() || p.is_none() {
            return Err(mask_err(format!("realm: invalid stunServer {s:?}")));
        }
    }
    // Go RealmConfig.ipMode（transport_finalmask.go:1012；消费 realm/client.go:39、
    // server.go:63）与 portMapping（:1013，NAT 端口映射）：Rust 端均无对应能力
    // （票 5std M16/M17），非缺省值显式拒绝而非静默忽略。ipMode=""/null、
    // portMapping.enabled=false/缺省在 Go 侧同为无操作，放行不构成静默丢。
    if let Some(m) = settings.get("ipMode") {
        let requested = match m {
            serde_json::Value::String(x) => !x.is_empty(),
            serde_json::Value::Null => false,
            _ => true,
        };
        if requested {
            return Err(mask_err(
                "realm: \"ipMode\" is not supported by this build; remove the key",
            ));
        }
    }
    if let Some(pm) = settings.get("portMapping") {
        let requested = match pm {
            serde_json::Value::Object(o) => {
                o.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false)
            },
            serde_json::Value::Null => false,
            _ => true,
        };
        if requested {
            return Err(mask_err(
                "realm: \"portMapping\" is not supported by this build; remove the key or set enabled=false",
            ));
        }
    }
    // Go RealmConfig.TlsConfig（transport_finalmask.go:1011，Build :1077-1082；
    // 消费 realm/client.go:65、server.go:89 NewClient(..., TlsConfig) 定形隧道
    // TLS）：Rust 端 TLS 细节仅由 scheme 承载（use_tls），完整 TLS 配置无对应
    // 能力——非 null 显式拒绝而非静默忽略；null/缺省 Go 侧同为 nil 无操作，放行。
    if settings.get("tlsConfig").is_some_and(|x| !x.is_null()) {
        return Err(mask_err(
            "realm: \"tlsConfig\" is not supported by this build; remove the key",
        ));
    }
    Ok(realm::Config {
        scheme: scheme.to_string(),
        host,
        port,
        token,
        id,
        stun_servers,
        use_tls: scheme == "https",
    })
}

/// `udphop` settings → [`udphop::UdphopConfig`]（对齐 Go `UDPHop.Build`，
/// infra/conf/transport_finalmask.go:1105-1148）。
fn build_udphop_config(settings: &serde_json::Value) -> io::Result<udphop::UdphopConfig> {
    // mode：逗号分隔的 intervallocal / intervalremote / perconnremote（Go 不 trim，
    // 带空格的段直接 invalid mode）。
    let mut local = false;
    let mut remote = false;
    let mut remote_once = false;
    for m in json_str(settings, "mode").split(',') {
        match m.to_ascii_lowercase().as_str() {
            "intervallocal" => local = true,
            "intervalremote" => remote = true,
            "perconnremote" => remote_once = true,
            other => {
                return Err(mask_err(format!("finalmask udphop: invalid mode {other:?}")));
            },
        }
    }
    // interval：0/0 缺省 30-30；from<5 拒绝（Go "interval must be at least 5"）。
    let (interval_from, interval_to) = match settings.get("interval") {
        None | Some(serde_json::Value::Null) => (30, 30),
        Some(_) => json_range(settings, "interval")?,
    };
    if interval_from < 5 {
        return Err(mask_err("finalmask udphop: interval must be at least 5"));
    }
    // remoteIPs：前缀 "10.0.0.0/24" 或裸 IP（补全长 /32、/128，Go ParseAddr→PrefixFrom）。
    let mut remote_ips = Vec::new();
    for ip in json_str_vec(settings, "remoteIPs") {
        remote_ips.push(parse_ip_prefix(&ip)?);
    }
    let remote_ports: Vec<u32> = settings
        .get("remotePorts")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect())
        .unwrap_or_default();
    Ok(udphop::UdphopConfig {
        local,
        remote,
        remote_once,
        interval_min: interval_from,
        interval_max: interval_to,
        remote_ips,
        remote_ports,
    })
}

/// `"10.0.0.0/24"` → `(10.0.0.0, 24)`；裸 IP → 全长前缀 `/32`、`/128`（对齐 Go
/// `UDPHop.Build` 的 ParsePrefix / ParseAddr+PrefixFrom 双形态）。
fn parse_ip_prefix(s: &str) -> io::Result<(std::net::IpAddr, u8)> {
    let invalid = || mask_err(format!("finalmask udphop: invalid ip {s:?}"));
    match s.split_once('/') {
        Some((addr, bits)) => {
            let addr: std::net::IpAddr = addr.parse().map_err(|_| invalid())?;
            let bits: u8 = bits.parse().map_err(|_| invalid())?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return Err(invalid());
            }
            Ok((addr, bits))
        },
        None => {
            let addr: std::net::IpAddr = s.parse().map_err(|_| invalid())?;
            Ok((addr, if addr.is_ipv4() { 32 } else { 128 }))
        },
    }
}

/// `[v6]:port` / `host:port` / `host`（port 可缺省，调用方按需校验）。
fn split_host_port(s: &str) -> io::Result<(String, Option<String>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) =
            rest.split_once(']').ok_or_else(|| mask_err(format!("missing ']' in {s:?}")))?;
        return Ok((host.to_string(), tail.strip_prefix(':').map(str::to_string)));
    }
    Ok(match s.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => (host.to_string(), Some(port.to_string())),
        _ => (s.to_string(), None),
    })
}

/// Go `url.PathUnescape`（%XX 解码，非法转义报错）。
fn percent_decode(s: &str) -> io::Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or_else(|| mask_err(format!("invalid URL escape in {s:?}")))?;
            let val = std::str::from_utf8(hex)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| mask_err(format!("invalid URL escape in {s:?}")))?;
            out.push(val);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| mask_err(format!("invalid utf-8 in URL: {e}")))
}

/// Go `XMC.Build` → `xmc::Config`（RSA-1024 密钥从 password 确定性派生）。
fn build_xmc_config(settings: &serde_json::Value) -> io::Result<xmc::Config> {
    let profiles = settings
        .get("profiles")
        .and_then(|x| x.as_array())
        .ok_or_else(|| mask_err("xmc: minecraft profiles are required"))?;
    if profiles.is_empty() {
        return Err(mask_err("xmc: minecraft profiles are required"));
    }
    let password = json_str(settings, "password");
    if password.is_empty() {
        return Err(mask_err("xmc: empty password"));
    }
    let mut profiles_out = Vec::with_capacity(profiles.len());
    for p in profiles {
        let username = json_str(p, "username");
        let valid = (3..=16).contains(&username.len())
            && username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(mask_err(format!("invalid minecraft profile username: {username:?}")));
        }
        let uuid = json_str(p, "uuid")
            .parse::<uuid::Uuid>()
            .map_err(|e| mask_err(format!("invalid minecraft profile UUID: {e}")))?;
        let textures_value = json_str(p, "texturesValue");
        let textures_signature = json_str(p, "texturesSignature");
        if textures_value.is_empty() || textures_signature.is_empty() {
            return Err(mask_err(format!("incomplete minecraft profile textures: {username:?}")));
        }
        profiles_out.push(xmc::Profile {
            username: username.to_string(),
            uuid: *uuid.as_bytes(),
            textures_value: textures_value.to_string(),
            textures_signature: textures_signature.to_string(),
        });
    }
    let private_key = xmc::derivation::derive_rsa_key(password)
        .map_err(|e| mask_err(format!("derive minecraft rsa key: {e}")))?;
    use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePublicKey};
    let rsa_private_key = private_key
        .to_pkcs1_der()
        .map_err(|e| mask_err(format!("marshal minecraft rsa private key: {e}")))?
        .as_bytes()
        .to_vec();
    let rsa_public_key = rsa::RsaPublicKey::from(&private_key)
        .to_public_key_der()
        .map_err(|e| mask_err(format!("marshal minecraft rsa public key: {e}")))?
        .as_bytes()
        .to_vec();
    Ok(xmc::Config {
        profiles: profiles_out,
        password: password.to_string(),
        rsa_private_key,
        rsa_public_key,
        hostname: json_str(settings, "hostname").to_string(),
        padding_disabled: false,
    })
}

fn build_fragment_config(settings: &serde_json::Value) -> io::Result<fragment::FragmentConfig> {
    fn opt_u64(v: &serde_json::Value, key: &str) -> u64 {
        v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
    }
    fn opt_i64(v: &serde_json::Value, key: &str) -> i64 {
        v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
    }
    // 单个 range 值：Go `Int32Range` JSON（`{"from":x,"to":y}`）；数字宽容为单值。
    fn range_pair(r: Option<&serde_json::Value>) -> (i64, i64) {
        match r {
            Some(serde_json::Value::Object(o)) => {
                let from = o.get("from").and_then(|x| x.as_i64()).unwrap_or(0);
                let to = o.get("to").and_then(|x| x.as_i64()).unwrap_or(from);
                (from, to)
            },
            Some(serde_json::Value::Number(n)) => {
                let x = n.as_i64().unwrap_or(0);
                (x, x)
            },
            _ => (0, 0),
        }
    }
    // ponytail: Go `length`/`interval` 是单值 range {from, to}；Rust 端
    // FragmentConfig 字段是 `Vec<i64>`，单元素 = 单段 range。
    fn opt_range1(v: &serde_json::Value, key: &str) -> (i64, i64) {
        range_pair(v.get(key))
    }
    // Go `FragmentMask` 键名对齐（transport_finalmask.go:240-247）：Go 原名
    // `packets`/`lengths[]`/`delays[]`/`maxSplit` 优先；proto 简化名
    // `packets_from`/`packets_to`/`interval`/`max_split` 向后兼容。
    let (packets_from, packets_to) = match settings.get("packets").and_then(|x| x.as_str()) {
        // Go Build :251-254："tlshello" → (0,1)（首包 ClientHello 特殊分片）。
        Some(s) if s.eq_ignore_ascii_case("tlshello") => (0u64, 1u64),
        // Go Build :257-264：ParseRangeString；from==0 硬错（0 会误触 tlshello 检测）。
        Some(s) if !s.is_empty() => {
            let (from, to) = parse_range_string(s)?;
            if from == 0 {
                return Err(mask_err("finalmask fragment: PacketsFrom can't be 0"));
            }
            (from as u64, to as u64)
        },
        // Go Build :255-256：空串 → (0,0)；键缺省走 proto 名。
        _ => (opt_u64(settings, "packets_from"), opt_u64(settings, "packets_to")),
    };
    // Go Build :267-275：`lengths[]` 非空优先，否则单段 `length`（Go/Rust 同名）。
    let mut lengths_min = Vec::new();
    let mut lengths_max = Vec::new();
    match settings.get("lengths").and_then(|x| x.as_array()) {
        Some(entries) if !entries.is_empty() => {
            for r in entries {
                let (from, to) = range_pair(Some(r));
                lengths_min.push(from);
                lengths_max.push(to);
            }
        },
        _ => {
            let (from, to) = opt_range1(settings, "length");
            lengths_min.push(from);
            lengths_max.push(to);
        },
    }
    // Go Build :282-284：末段 LengthsMin==0 硬错（含未提供 lengths/length 的缺省 {0,0}
    // 情形——Go 走 else 分支同样命中，空 settings 不豁免）。
    if lengths_min.last() == Some(&0) {
        return Err(mask_err("finalmask fragment: last lengths entry min can't be 0"));
    }
    // Go Build :283-291：`delays[]` 非空优先，否则单段 `delay`；proto 简化名 `interval` 兜底。
    let mut delays_min = Vec::new();
    let mut delays_max = Vec::new();
    match settings.get("delays").and_then(|x| x.as_array()) {
        Some(entries) if !entries.is_empty() => {
            for r in entries {
                let (from, to) = range_pair(Some(r));
                delays_min.push(from);
                delays_max.push(to);
            }
        },
        _ => {
            let (from, to) = match settings.get("delay") {
                Some(d) if !d.is_null() => range_pair(Some(d)),
                _ => opt_range1(settings, "interval"),
            };
            delays_min.push(from);
            delays_max.push(to);
        },
    }
    // Go Build :293-294：`maxSplit` 单段；proto 简化名 `max_split`。
    let (max_split_min, max_split_max) = match settings.get("maxSplit") {
        Some(m) if !m.is_null() => range_pair(Some(m)),
        _ => (opt_i64(settings, "max_split"), opt_i64(settings, "max_split")),
    };
    Ok(fragment::FragmentConfig {
        packets_from,
        packets_to,
        max_split_min,
        max_split_max,
        lengths_min,
        lengths_max,
        delays_min,
        delays_max,
    })
}

// ===== 同步逐包 codec 链（KCP 等同步 UDP 栈复用同一套 mkcp 算子） =====

/// 同步逐包编解码接口。
///
/// 与 [`Udpmask`] 包装同一套 mkcp 算子（original/aes128gcm/header），供同步 UDP 栈
/// （如 `xray-transport-kcp` 的 `std::net::UdpSocket` 路径）在 socket 读写 seam 上
/// 逐包 encode/decode，语义等价 Go `WrapPacketConnClient`/`WrapPacketConnServer`
/// （mkcp 各算子对称、无握手，client/server 共用同一编解码）。
pub trait PacketCodec: Send + Sync {
    /// 发送方向：把一个明文 packet 变换为线上字节。
    ///
    /// # Errors
    /// 算子特定（如 AEAD key 派生失败）。
    fn encode(&self, pkt: &[u8]) -> io::Result<Vec<u8>>;

    /// 接收方向：把线上字节还原为明文 packet。
    ///
    /// # Errors
    /// - `InvalidData`：校验失败（FNV1a/AEAD tag 不符、长度不符）。
    fn decode(&self, pkt: &[u8]) -> io::Result<Vec<u8>>;
}

/// 逐包 codec 链：按数组顺序 encode、逆序 decode。
///
/// 对应 Go `UdpmaskManager` 链式嵌套——数组序 `[m0, m1]` 表示 m1 包 m0 包 raw，
/// 发送时 `payload → m0.encode → m1.encode → 线上`，接收反向。
#[derive(Clone)]
pub struct CodecChain {
    codecs: Vec<Arc<dyn PacketCodec>>,
}

impl CodecChain {
    /// 构建链。
    #[must_use]
    pub fn new(codecs: Vec<Arc<dyn PacketCodec>>) -> Self {
        Self { codecs }
    }

    /// 链长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.codecs.len()
    }

    /// 是否为空链（等价无 mask）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codecs.is_empty()
    }

    /// 发送方向逐层 encode。
    ///
    /// # Errors
    /// 任一层算子错误透传。
    pub fn encode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        let mut data = pkt.to_vec();
        for c in &self.codecs {
            data = c.encode(&data)?;
        }
        Ok(data)
    }

    /// 接收方向逐层 decode（encode 的逆序）。
    ///
    /// # Errors
    /// 任一层算子错误透传。
    pub fn decode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        let mut data = pkt.to_vec();
        for c in self.codecs.iter().rev() {
            data = c.decode(&data)?;
        }
        Ok(data)
    }
}

/// 从 `streamSettings.finalmask` JSON 解析 UDP 伪装 codec 链。
///
/// 对应 Go `udpmaskLoader` + `Mask.Build(false)` 的 mkcp 子集
/// （`infra/conf/transport_internet.go`）：`udp` 数组每项 `{"type", "settings"}`，
/// 当前支持 `type == "mkcp-legacy"`（`settings.{header, value}`，对应 Go `MkcpLegacy`）：
///
/// - `header` 空 + `value` 空 → original（XOR 链 + FNV1a）
/// - `header` 空 + `value` 非空 → aes128gcm（password = `value`）
/// - `header` = dns/dtls/srtp/utp/wechat/wireguard → 协议头伪装 （dns 的 domain = `value`，默认
///   `www.baidu.com`）
///
/// 其余 type 报错（不静默丢配置）。`None` / 无 `udp` 数组 / 空数组 → `Ok(None)`
/// （无 mask，行为不变）。
///
/// # Errors
/// - `InvalidInput`：未知 type、非法 header 名、算子构造失败。
pub fn parse_finalmask_udp_chain(
    json: Option<&serde_json::Value>,
) -> io::Result<Option<CodecChain>> {
    let Some(v) = json else { return Ok(None) };
    let Some(entries) = v.get("udp").and_then(|u| u.as_array()) else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(None);
    }

    let mut codecs: Vec<Arc<dyn PacketCodec>> = Vec::new();
    for entry in entries {
        let ty = entry.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        let settings = entry.get("settings").cloned().unwrap_or(serde_json::Value::Null);
        match ty {
            "mkcp-legacy" => codecs.push(build_mkcp_legacy_codec(&settings)?),
            // 票 4kq9：udphop 是连接级包装（UdpmaskManager 路径，见 build_udpmask_entry），
            // 结构上非逐包 codec，CodecChain 无处安放——显式指路而非含糊 unsupported。
            "udphop" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "finalmask: udphop is a conn-level wrapper, not a per-packet codec; \
                     it only applies via UdpmaskManager (wrap_packet_conn_client)",
                ));
            },
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "finalmask: unsupported udp mask type {other:?} (supported: mkcp-legacy)"
                    ),
                ));
            },
        }
    }
    Ok(Some(CodecChain::new(codecs)))
}

/// `mkcp-legacy` 单条目 → codec（对应 Go `MkcpLegacy.Build`，transport_internet.go:1725）。
fn build_mkcp_legacy_codec(settings: &serde_json::Value) -> io::Result<Arc<dyn PacketCodec>> {
    let header = settings.get("header").and_then(|h| h.as_str()).unwrap_or_default();
    let value = settings.get("value").and_then(|v| v.as_str()).unwrap_or_default();

    if header.is_empty() {
        return Ok(if value.is_empty() {
            Arc::new(mkcp::original::OriginalConfig)
        } else {
            Arc::new(mkcp::aes128gcm::Aes128GcmCodec::new(value)?)
        });
    }

    use mkcp::header::{HeaderConfig, HeaderId};
    let cfg = match header.to_ascii_lowercase().as_str() {
        "dns" => HeaderConfig {
            id: HeaderId::Dns,
            domain: if value.is_empty() { "www.baidu.com".to_string() } else { value.to_string() },
        },
        "dtls" => HeaderConfig::from_id(HeaderId::Dtls),
        "srtp" => HeaderConfig::from_id(HeaderId::Srtp),
        "utp" => HeaderConfig::from_id(HeaderId::Utp),
        "wechat" => HeaderConfig::from_id(HeaderId::Wechat),
        "wireguard" => HeaderConfig::from_id(HeaderId::Wireguard),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("finalmask: invalid header {other:?}"),
            ));
        },
    };
    Ok(Arc::new(mkcp::header::HeaderCodec::new(&cfg)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_managers_construct() {
        let _tcp = TcpmaskManager::new(vec![]);
        let _udp = UdpmaskManager::new(vec![]);
    }

    #[test]
    fn udp_size_is_4096() {
        assert_eq!(UDP_SIZE, 4096);
    }

    #[test]
    fn security_mode_from_name() {
        assert_eq!(SecurityMode::from_name("original"), Some(SecurityMode::Original));
        assert_eq!(SecurityMode::from_name("none"), Some(SecurityMode::Original));
        assert_eq!(SecurityMode::from_name("aes-128-gcm"), Some(SecurityMode::Aes128Gcm));
        assert_eq!(SecurityMode::from_name("aes128gcm"), Some(SecurityMode::Aes128Gcm));
        assert_eq!(SecurityMode::from_name("salamander"), Some(SecurityMode::Salamander));
        assert_eq!(SecurityMode::from_name("unknown"), None);
    }

    #[test]
    fn build_manager_original_no_header() {
        let config = FinalmaskConfig::default();
        let mgr = build_udpmask_manager(&config).unwrap();
        // Original mode: 1 mask (no header)
        assert!(!mgr.udpmasks.is_empty());
    }

    #[test]
    fn build_manager_aes128gcm_with_header() {
        let config = FinalmaskConfig {
            security: SecurityMode::Aes128Gcm,
            password: "test-pass".into(),
            header_id: Some(5), // WireGuard
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        // Aes128Gcm + header: 2 masks
        assert_eq!(mgr.udpmasks.len(), 2);
    }

    #[test]
    fn build_manager_salamander_with_dns_header() {
        let config = FinalmaskConfig {
            security: SecurityMode::Salamander,
            password: "sal-key".into(),
            header_id: Some(0), // DNS
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        assert_eq!(mgr.udpmasks.len(), 2);
    }

    #[test]
    fn build_manager_invalid_header_id_ignored() {
        let config = FinalmaskConfig {
            security: SecurityMode::Original,
            password: String::new(),
            header_id: Some(99), // invalid
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        // Invalid header_id ignored: only 1 mask (security)
        assert_eq!(mgr.udpmasks.len(), 1);
    }

    // ===== parse_finalmask_udp_chain / CodecChain =====

    fn fm(v: &str) -> serde_json::Value {
        serde_json::from_str(v).unwrap()
    }

    #[test]
    fn parse_chain_none_cases() {
        assert!(parse_finalmask_udp_chain(None).unwrap().is_none());
        // 无 udp 数组
        assert!(parse_finalmask_udp_chain(Some(&fm(r#"{"tcp":[]}"#))).unwrap().is_none());
        // 空 udp 数组
        assert!(parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[]}"#))).unwrap().is_none());
    }

    #[test]
    fn parse_chain_mkcp_original() {
        // Go MkcpLegacy.Build：header 空 + value 空 → original
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#,
        )))
        .unwrap()
        .unwrap();
        assert_eq!(chain.len(), 1);
        let enc = chain.encode(b"kcp-pkt").unwrap();
        // original overhead = 6（4B FNV + 2B len）
        assert_eq!(enc.len(), 7 + 6);
        assert_eq!(chain.decode(&enc).unwrap(), b"kcp-pkt");
    }

    #[test]
    fn parse_chain_mkcp_aes128gcm() {
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"pass123"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        assert_eq!(chain.len(), 1);
        let enc = chain.encode(b"secret").unwrap();
        // aes128gcm overhead = 28（12B nonce + 16B tag）
        assert_eq!(enc.len(), 6 + 28);
        assert_eq!(chain.decode(&enc).unwrap(), b"secret");
    }

    #[test]
    fn parse_chain_header_dns_defaults_domain() {
        // dns 无 value → 默认 www.baidu.com；与显式 HeaderCodec 等价
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"header":"DNS"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        let reference = mkcp::header::HeaderCodec::new(&mkcp::header::HeaderConfig {
            id: mkcp::header::HeaderId::Dns,
            domain: "www.baidu.com".to_string(),
        })
        .unwrap();
        assert_eq!(chain.encode(b"x").unwrap().len(), reference.encode(b"x").unwrap().len());
    }

    #[test]
    fn parse_chain_all_header_kinds() {
        for (name, _id) in [("dtls", 1), ("srtp", 2), ("utp", 3), ("wechat", 4), ("wireguard", 5)] {
            let chain = parse_finalmask_udp_chain(Some(&fm(&format!(
                r#"{{"udp":[{{"type":"mkcp-legacy","settings":{{"header":"{name}"}}}}]}}"#
            ))))
            .unwrap()
            .unwrap();
            let enc = chain.encode(b"payload").unwrap();
            assert_eq!(chain.decode(&enc).unwrap(), b"payload", "header {name}");
        }
    }

    #[test]
    fn parse_chain_stacked_masks() {
        // 两条 mkcp-legacy 叠加：aes128gcm + srtp（对齐 Go 多 mask 链）
        let chain = parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[
                {"type":"mkcp-legacy","settings":{"value":"pw"}},
                {"type":"mkcp-legacy","settings":{"header":"srtp"}}
            ]}"#)))
        .unwrap()
        .unwrap();
        assert_eq!(chain.len(), 2);
        let enc = chain.encode(b"data").unwrap();
        // aes 28 + srtp 4
        assert_eq!(enc.len(), 4 + 28 + 4);
        assert_eq!(chain.decode(&enc).unwrap(), b"data");
    }

    #[test]
    fn parse_chain_invalid_header_errors() {
        let r = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"header":"bogus"}}]}"#,
        )));
        assert!(r.is_err());
    }

    #[test]
    fn parse_chain_unknown_type_errors() {
        let r = parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[{"type":"noise"}]}"#)));
        assert!(r.is_err());
        let err = match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected unsupported-type error"),
        };
        assert!(err.contains("unsupported udp mask type"));
    }

    #[test]
    fn chain_decode_tampered_ciphertext_fails() {
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"pw"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        let mut enc = chain.encode(b"data").unwrap();
        enc[13] ^= 0xFF; // 翻转密文一字节
        assert!(chain.decode(&enc).is_err());
    }

    /// 端到端：`build_udpmask_manager_from_json` + `wrap_packet_conn_client/server`
    /// 一对儿（mkcp-original codec）应能对带前缀/后缀的 payload 做 UDP 包级 mask
    /// encode/decode round-trip。对应 Go `transport/internet/udp/dialer.go:40 + hub.go:72`。
    #[test]
    fn udpmask_manager_roundtrip_mkcp_original() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            use tokio::net::UdpSocket;
            let fm: serde_json::Value =
                serde_json::from_str(r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#).unwrap();
            let mgr = build_udpmask_manager_from_json(Some(&fm)).expect("manager");
            assert_eq!(mgr.udpmasks.len(), 1);

            let client_raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server_raw.local_addr().unwrap();
            let client_addr = client_raw.local_addr().unwrap();

            let client_udpio: Box<dyn UdpIo> =
                mgr.wrap_packet_conn_client(Box::new(client_raw)).unwrap();
            let server_udpio: Box<dyn UdpIo> =
                mgr.wrap_packet_conn_server(Box::new(server_raw)).unwrap();

            let payload = b"hello-udpmask-roundtrip";
            client_udpio.send_to(payload, server_addr).await.unwrap();
            let mut buf = vec![0u8; 1500];
            let (n, src) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                server_udpio.recv_from(&mut buf),
            )
            .await
            .expect("server recv timeout")
            .unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(src, client_addr);

            let reply = b"reply-from-server";
            server_udpio.send_to(reply, client_addr).await.unwrap();
            let (n, src) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client_udpio.recv_from(&mut buf),
            )
            .await
            .expect("client recv timeout")
            .unwrap();
            assert_eq!(&buf[..n], reply);
            assert_eq!(src, server_addr);
        });
    }

    /// `wrap_packet_conn_*_into_connection` 把 `Box<dyn UdpIo>` 适配为
    /// `Box<dyn Connection>`（client 方向 `remote_addr` 由调用方传入）。
    #[test]
    fn wrap_packet_conn_into_connection_roundtrip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            use tokio::{
                io::{AsyncReadExt, AsyncWriteExt},
                net::UdpSocket,
            };
            let fm: serde_json::Value = serde_json::from_str(
                r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"hello-udp-pass"}}]}"#,
            )
            .unwrap();
            let mgr = build_udpmask_manager_from_json(Some(&fm)).expect("manager");

            let client_raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server_raw.local_addr().unwrap();
            let client_addr = client_raw.local_addr().unwrap();

            let server_udpio: Box<dyn UdpIo> =
                mgr.wrap_packet_conn_server(Box::new(server_raw)).unwrap();
            let mut server_conn: Box<dyn crate::connection::Connection> =
                crate::finalmask::wrap_packet_conn_server_into_connection(
                    server_udpio,
                    client_addr,
                )
                .expect("wrap_packet_conn_server_into_connection");

            let client_udpio: Box<dyn UdpIo> =
                mgr.wrap_packet_conn_client(Box::new(client_raw)).unwrap();
            let mut client_conn: Box<dyn crate::connection::Connection> =
                crate::finalmask::wrap_packet_conn_client_into_connection(
                    client_udpio,
                    server_addr,
                )
                .expect("wrap_packet_conn_client_into_connection");
            assert_eq!(client_conn.remote_addr().unwrap(), Some(server_addr));

            client_conn.write_all(b"client-connection-payload").await.expect("client write");

            let mut read_buf = vec![0u8; 256];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                server_conn.read(&mut read_buf),
            )
            .await
            .expect("server read timeout")
            .expect("server read ok");
            assert_eq!(&read_buf[..n], b"client-connection-payload");
        });
    }

    /// mock UdpIo：recv_from 只吐一个预设包，随后 Err 关闭 driver（触发 EOF）。
    struct MockSinglePacketUdpIo {
        packet: Vec<u8>,
        addr: SocketAddr,
        delivered: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl UdpIo for MockSinglePacketUdpIo {
        async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if !self.delivered.swap(true, std::sync::atomic::Ordering::AcqRel) {
                let n = self.packet.len().min(buf.len());
                buf[..n].copy_from_slice(&self.packet[..n]);
                Ok((n, self.addr))
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "mock closed"))
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.addr)
        }
    }

    /// 7xia：读缓冲小于包大小时，剩余字节必须回填队首，字节流零丢失。
    /// （旧实现静默丢弃剩余字节——AsyncRead 流契约违约。）
    #[test]
    fn packet_io_conn_small_read_buffer_no_byte_loss() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            use tokio::io::AsyncReadExt;
            let packet: Vec<u8> = (0..100u8).collect();
            let udpio = Box::new(MockSinglePacketUdpIo {
                packet: packet.clone(),
                addr: "127.0.0.1:9000".parse().unwrap(),
                delivered: std::sync::atomic::AtomicBool::new(false),
            });
            let mut conn =
                wrap_packet_conn_client_into_connection(udpio, "127.0.0.1:9000".parse().unwrap())
                    .expect("wrap");

            // 10 字节小缓冲分 10 次读：100 字节必须全部按序到达
            let mut got = Vec::new();
            for _ in 0..10 {
                let mut chunk = [0u8; 10];
                conn.read_exact(&mut chunk).await.expect("read_exact");
                got.extend_from_slice(&chunk);
            }
            assert_eq!(got, packet, "小缓冲读不得丢字节（剩余字节回填队首）");

            // 包消费完后 driver 因 Err 退出 → 队列关闭 → EOF
            let mut b = [0u8; 1];
            assert_eq!(conn.read(&mut b).await.expect("final read"), 0);
        });
    }

    // ===== JSON settings parse（build_*_entry 接线族，对齐 Go udpmask/tcpmaskLoader）=====

    #[test]
    fn parse_json_noise_config_fields() {
        let settings = fm(r#"{"reset":{"from":2,"to":5},
                "noise":[{"rand":{"from":10,"to":20},"delay":3},
                         {"packet":[1,2,3]}]}"#);
        let cfg = build_noise_config(&settings).unwrap();
        assert_eq!((cfg.reset_min, cfg.reset_max), (2, 5));
        assert_eq!(cfg.items.len(), 2);
        assert_eq!((cfg.items[0].rand_min, cfg.items[0].rand_max), (10, 20));
        assert_eq!((cfg.items[0].delay_min, cfg.items[0].delay_max), (3, 3));
        assert_eq!(cfg.items[0].rand_range_max, 255); // randRange 缺省 {0,255}
        assert_eq!(cfg.items[1].packet, vec![1, 2, 3]);
        // packet 与 rand>0 互斥（对齐 Go Build 校验）
        let bad = fm(r#"{"noise":[{"rand":{"from":1,"to":9},"packet":[1]}]}"#);
        assert!(build_noise_config(&bad).is_err());
    }

    #[test]
    fn parse_json_noise_exp_config_roundtrip() {
        // type=exp：packet 是表达式字符串；delay 字段 roundtrip 进 Item。
        let settings = fm(r#"{"reset":{"from":1,"to":2},
                "noise":[{"type":"exp","packet":"<b 0x0d0a0d0a><t><r 24><rc 8-16><rd 4><c><n>","delay":{"from":5,"to":9}}]}"#);
        let cfg = build_noise_config(&settings).unwrap();
        assert_eq!(cfg.items.len(), 1);
        let segs = &cfg.items[0].segments;
        assert_eq!(segs.len(), 7);
        assert_eq!(segs[0].kind, noise::NoiseSegmentKind::Bytes);
        assert_eq!(segs[0].bytes, vec![0x0d, 0x0a, 0x0d, 0x0a]);
        assert_eq!(segs[1].kind, noise::NoiseSegmentKind::Timestamp);
        assert_eq!(segs[2].kind, noise::NoiseSegmentKind::Random);
        assert_eq!((segs[2].min_size, segs[2].max_size), (24, 24));
        assert_eq!(segs[3].kind, noise::NoiseSegmentKind::RandomAscii);
        assert_eq!((segs[3].min_size, segs[3].max_size), (8, 16));
        assert_eq!(segs[4].kind, noise::NoiseSegmentKind::RandomDigit);
        assert_eq!((segs[4].min_size, segs[4].max_size), (4, 4));
        assert_eq!(segs[5].kind, noise::NoiseSegmentKind::Counter);
        assert_eq!(segs[6].kind, noise::NoiseSegmentKind::Nonce);
        // delay 字段 roundtrip（任务验收点）
        assert_eq!((cfg.items[0].delay_min, cfg.items[0].delay_max), (5, 9));
        // legacy item 不受影响（同配置混排）。
        let mixed = fm(r#"{"noise":[{"type":"exp","packet":"<b 01>"},
                         {"packet":[9],"delay":1}]}"#);
        let cfg = build_noise_config(&mixed).unwrap();
        assert_eq!(cfg.items[1].packet, vec![9]);
        assert!(cfg.items[1].segments.is_empty());
        // type 大小写不敏感（Go strings.ToLower）。
        let upper = fm(r#"{"noise":[{"type":"EXP","packet":"<b ff>"}]}"#);
        assert_eq!(build_noise_config(&upper).unwrap().items[0].segments.len(), 1);
    }

    #[test]
    fn parse_json_noise_exp_errors() {
        // packet 非字符串（Go json.Unmarshal 报 "must be a string"）。
        let e =
            build_noise_config(&fm(r#"{"noise":[{"type":"exp","packet":[1,2]}]}"#)).unwrap_err();
        assert!(e.to_string().contains("must be a string"), "{e}");
        // exp + rand>0 → Go 侧互斥校验先触发。
        let e =
            build_noise_config(&fm(r#"{"noise":[{"type":"exp","packet":"<t>","rand":{"to":9}}]}"#))
                .unwrap_err();
        assert!(e.to_string().contains("mutually exclusive"), "{e}");
        // 散文本段间 → invalid near。
        let e = parse_noise_exp("x<r>").unwrap_err();
        assert!(e.to_string().contains("invalid noise exp near x"), "{e}");
        // 尾部散文本（用无参合法段，避免段错误先于尾检触发——Go 同序）。
        let e = parse_noise_exp("<t>trailing").unwrap_err();
        assert!(e.to_string().contains("invalid noise exp near trailing"), "{e}");
        // 空表达式。
        let e = parse_noise_exp("").unwrap_err();
        assert!(e.to_string().contains("empty noise exp"), "{e}");
        // 未知 key / 缺尺寸 / 无参 key 带参 / 非法尺寸 / 非法 hex。
        assert!(parse_noise_exp("<zz 5>").is_err());
        assert!(parse_noise_exp("<r>").is_err());
        assert!(parse_noise_exp("<t 5>").is_err());
        assert!(parse_noise_exp("<r 70000>").is_err());
        assert!(parse_noise_exp("<b zzzz>").is_err());
    }

    /// 票 5std M14：noise 顶层 `script`（Go NoiseMask.script，xlua 编译）非空
    /// 硬错，不再静默丢（静默 = 整个噪声掩码不生效）；空串/null = 未设置，放行。
    #[test]
    fn parse_json_noise_script_rejected_loudly() {
        // Go transport_finalmask_noise_test.go:179 同款输入形态
        let e = build_noise_config(&fm(r#"{"reset":{"from":30,"to":60},"script":"noise.lua"}"#))
            .unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("script"), "{msg}");
        assert!(msg.contains("not supported"), "{msg}");
        // 类型手误（数字）→ 同样拒启，不静默丢
        assert!(build_noise_config(&fm(r#"{"script":123}"#)).is_err());
        // 空串 = 未设置，放行（Go `if c.Script != ""`）
        build_noise_config(&fm(r#"{"script":""}"#)).unwrap();
    }

    #[test]
    fn parse_json_sudoku_config_fields() {
        let cfg = build_sudoku_config(&fm(r#"{"password":"pw","ascii":"prefer_ascii",
                "customTable":"xxppvvvv","paddingMax":80}"#));
        assert_eq!(cfg.password, "pw");
        assert_eq!(cfg.ascii, "prefer_ascii");
        assert_eq!(cfg.custom_table, "xxppvvvv");
        assert_eq!(cfg.padding_max, 80);
        // legacy 下划线键兜底（对齐 Go Sudoku）
        let legacy = build_sudoku_config(&fm(
            r#"{"custom_table":"xxppvvvv","custom_tables":["a","b"],"padding_min":10}"#,
        ));
        assert_eq!(legacy.custom_table, "xxppvvvv");
        assert_eq!(legacy.custom_tables, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(legacy.padding_min, 10);
    }

    #[test]
    fn parse_json_xdns_config_fields_and_validations() {
        // v26.9.30 形态（bd 2ktp ④）：domains 对象数组 + resolvers {type,settings}
        let cfg = build_xdns_config(&fm(r#"{"domains":[{"name":"t.example.com","types":[16]}],
                "resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53"}}],
                "extraPoll":1}"#))
        .unwrap();
        assert_eq!(cfg.domains.len(), 1);
        assert_eq!(cfg.domains[0].name, "t.example.com");
        assert_eq!((cfg.domains[0].len_limit, cfg.domains[0].label_limit), (255, 63));
        assert_eq!(cfg.domains[0].types, vec![16]);
        assert_eq!(cfg.resolvers[0].kind, xdns::ResolverKind::Udp);
        assert_eq!(cfg.resolvers[0].addr, "1.1.1.1:53");
        assert_eq!(cfg.extra_poll, 1);
        // 已废弃 domain 键报错（对齐 Go PrintRemovedFeatureError）
        assert!(build_xdns_config(&fm(r#"{"domain":"x.com"}"#)).is_err());
        // extraPoll 越界报错（对齐 Go Build 校验）
        assert!(build_xdns_config(&fm(r#"{"extraPoll":4}"#)).is_err());
        // resolver 未知 type 报错
        assert!(
            build_xdns_config(&fm(
                r#"{"resolvers":[{"type":"quic","settings":{"addr":"1.1.1.1:53"}}]}"#
            ))
            .is_err()
        );
        // https（DOH）已知 type 但 Rust 栈未实现 → 显式报错（bd o7ns D4）
        assert!(
            build_xdns_config(&fm(
                r#"{"resolvers":[{"type":"https","settings":{"addr":"dns.google"}}]}"#
            ))
            .is_err()
        );
        // settings 未知键显式报错，不静默丢弃（bd o7ns D4）
        assert!(
            build_xdns_config(&fm(
                r#"{"resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53","worker":8}}]}"#
            ))
            .is_err()
        );
        // tcp resolver 可解析（wrap 期报 UDP-only 不支持）
        assert!(
            build_xdns_config(&fm(
                r#"{"resolvers":[{"type":"tcp","settings":{"addr":"1.1.1.1:53"}}]}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn parse_json_xicmp_config_fields() {
        let cfg =
            build_xicmp_config(&fm(r#"{"ips":["2001:db8::1","10.0.0.1"],"dgram":true}"#)).unwrap();
        assert_eq!(cfg.ips, vec!["2001:db8::1".to_string(), "10.0.0.1".to_string()]);
        assert!(cfg.dgram);
        assert!(build_xicmp_config(&fm(r#"{"ips":["not-an-ip"]}"#)).is_err());
    }

    #[test]
    fn parse_json_realm_config_fields() {
        let cfg = build_realm_config(&fm(
            r#"{"url":"realm://secret%2Btok@stun.example.com:8443/peer-id",
                "stunServers":["stun1.example.com:3478"]}"#,
        ))
        .unwrap();
        assert_eq!(cfg.scheme, "https");
        assert_eq!(cfg.host, "stun.example.com");
        assert_eq!(cfg.port, "8443");
        assert_eq!(cfg.token, "secret+tok"); // percent-decode
        assert_eq!(cfg.id, "peer-id");
        assert!(cfg.use_tls);
        // realm+http 缺省端口 80
        let http = build_realm_config(&fm(
            r#"{"url":"realm+http://tok@h.example.com/p","stunServers":["s:1"]}"#,
        ))
        .unwrap();
        assert_eq!((http.scheme.as_str(), http.port.as_str()), ("http", "80"));
        assert!(!http.use_tls);
        // 缺 stunServers 报错（对齐 Go）
        assert!(build_realm_config(&fm(r#"{"url":"realm://t@h.com/id"}"#)).is_err());
    }

    /// 票 5std M16/M17：realm `ipMode` / `portMapping` 非缺省值硬错（Rust 无
    /// 对应能力，静默忽略 = NAT 打洞/IP 模式行为与配置意图不符）；
    /// ipMode="" 与 portMapping.enabled=false 在 Go 侧同为无操作，放行。
    #[test]
    #[allow(clippy::err_expect)] // 存量清零批次：测试断言期 expect（realm::Config 无 Debug，禁 expect_err）
    fn parse_json_realm_ip_mode_and_port_mapping_rejected_loudly() {
        let base = r#"{"url":"realm://tok@h.example.com/id","stunServers":["s:1"]}"#;
        // ipMode 非空 → 拒（Go IPMode 消费点 realm/client.go:39）
        let e = build_realm_config(&fm(
            r#"{"url":"realm://tok@h.example.com/id","stunServers":["s:1"],"ipMode":"auto64"}"#,
        ))
        .err()
        .expect("non-empty ipMode must reject");
        assert!(e.to_string().contains("ipMode"), "{e}");
        // portMapping.enabled=true → 拒（Go NAT 端口映射）
        let e = build_realm_config(&fm(
            r#"{"url":"realm://tok@h.example.com/id","stunServers":["s:1"],"portMapping":{"enabled":true}}"#,
        ))
        .err()
        .expect("portMapping enabled=true must reject");
        assert!(e.to_string().contains("portMapping"), "{e}");
        // 非对象类型手误 → 同样拒启，不静默丢
        let e = build_realm_config(&fm(
            r#"{"url":"realm://tok@h.example.com/id","stunServers":["s:1"],"portMapping":1}"#,
        ))
        .err()
        .expect("non-object portMapping must reject");
        assert!(e.to_string().contains("portMapping"), "{e}");
        // Go 缺省语义放行：ipMode="" / enabled=false / 缺省
        build_realm_config(&fm(
            r#"{"url":"realm://tok@h.example.com/id","stunServers":["s:1"],"ipMode":"","portMapping":{"enabled":false}}"#,
        ))
        .unwrap();
        build_realm_config(&fm(base)).unwrap();
    }

    #[test]
    fn parse_json_xmc_config_fields() {
        let cfg = build_xmc_config(&fm(r#"{"hostname":"mc.example.com","password":"mc-pass",
                "profiles":[{"username":"steve_1","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5",
                             "texturesValue":"v","texturesSignature":"s"}]}"#))
        .unwrap();
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.profiles[0].username, "steve_1");
        assert_eq!(
            cfg.profiles[0].uuid,
            *uuid::Uuid::parse_str("069a79f4-44e9-4726-a5be-fca90e38aaf5").unwrap().as_bytes()
        );
        assert_eq!(cfg.profiles[0].textures_value, "v");
        assert_eq!(cfg.profiles[0].textures_signature, "s");
        assert_eq!(cfg.password, "mc-pass");
        assert_eq!(cfg.hostname, "mc.example.com");
        assert!(!cfg.rsa_private_key.is_empty());
        assert!(!cfg.rsa_public_key.is_empty());
        // 空 profiles / 非法用户名 / 非法 UUID 报错（对齐 Go XMC.Build）
        assert!(build_xmc_config(&fm(r#"{"password":"p","profiles":[]}"#)).is_err());
        assert!(build_xmc_config(&fm(
            r#"{"profiles":[{"username":"x","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","texturesValue":"v","texturesSignature":"s"}]}"#
        ))
        .is_err());
        assert!(build_xmc_config(&fm(
            r#"{"password":"p","profiles":[{"username":"abc","uuid":"not-a-uuid","texturesValue":"v","texturesSignature":"s"}]}"#
        ))
        .is_err());
    }

    #[test]
    fn parse_json_custom_tcp_config() {
        let cfg = build_custom_tcp(&fm(r#"{"clients":[
                  [{"delay":{"from":1,"to":2},"packet":[1,2],"capture":"hello"},
                   {"reuse":"hello"},
                   {"packet":"aabb","type":"hex"}]
                ],
                "servers":[[{"transform":{"op":"concat","args":[{"bytes":[170]}]}}]]}"#))
        .unwrap();
        assert_eq!(cfg.clients.len(), 1);
        let seq = &cfg.clients[0].sequence;
        assert_eq!(seq.len(), 3);
        assert_eq!((seq[0].delay_min, seq[0].delay_max), (1, 2));
        assert_eq!(seq[0].packet, vec![1, 2]);
        assert_eq!(seq[0].save, "hello");
        assert_eq!((seq[1].rand, seq[1].rand_min, seq[1].rand_max), (0, 0, 255));
        assert_eq!(seq[1].var, "hello");
        assert_eq!(seq[2].packet, vec![0xaa, 0xbb]);
        // transform → Expr
        let expr = cfg.servers[0].sequence[0].expr.as_ref().unwrap();
        assert_eq!(expr.op, "concat");
        assert!(matches!(&expr.args[0], custom::ExprArg::Bytes(b) if b == &vec![0xaa]));
        // 两种 kind 并存报错（对齐 Go exactly one item kind）
        assert!(build_custom_tcp(&fm(r#"{"clients":[[{"rand":1,"reuse":"v"}]]}"#)).is_err());
        // 非法变量名报错
        assert!(
            build_custom_tcp(&fm(r#"{"clients":[[{"packet":[1],"capture":"9bad"}]]}"#)).is_err()
        );
    }

    #[test]
    fn parse_json_custom_udp_config() {
        // 默认 prefix 模式 → udp
        let (udp, standalone) = build_custom_udp(&fm(
            r#"{"client":[{"packet":[7,7],"capture":"m"}],"server":[{"rand":2}]}"#,
        ))
        .unwrap();
        assert!(standalone.is_none());
        let udp = udp.unwrap();
        assert_eq!(udp.client.len(), 1);
        assert_eq!(udp.client[0].packet, vec![7, 7]);
        // standalone 模式 → udp_standalone
        let (udp, standalone) =
            build_custom_udp(&fm(r#"{"mode":"standalone","client":[]}"#)).unwrap();
        assert!(udp.is_none());
        assert!(standalone.is_some());
        // 未知 mode 报错
        assert!(build_custom_udp(&fm(r#"{"mode":"bogus"}"#)).is_err());
    }

    #[test]
    fn build_udpmask_entry_wires_all_types() {
        let json = fm(r#"{"udp":[
                {"type":"noise","settings":{"reset":{"from":1,"to":2}}},
                {"type":"sudoku","settings":{"password":"p"}},
                {"type":"xdns","settings":{"domains":[{"name":"t.example.com","types":[16]}],"resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53"}}]}},
                {"type":"xicmp","settings":{"ips":["10.0.0.1"]}},
                {"type":"realm","settings":{"url":"realm://t@h.example.com/i","stunServers":["s.example.com:3478"]}},
                {"type":"header-custom","settings":{"client":[]}}
            ]}"#);
        let mgr = build_udpmask_manager_from_json(Some(&json)).unwrap();
        assert_eq!(mgr.udpmasks.len(), 6);
    }

    /// Go Salamander.PacketSize（transport_finalmask.go:747-760）：to>0 切 Gecko
    /// wire 原语，Rust 未实现 → 指名键硬错；to<=0（Go 普通分支）/缺省放行。
    #[test]
    fn salamander_packet_size_rejects_gecko_mode_passes_plain() {
        let err = |v: &str| match build_udpmask_entry(&fm(v)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected packetSize reject"),
        };
        // Int32Range 两种合法形态（字符串 range / 纯数字）均触发 gecko 拒绝。
        assert!(
            err(r#"{"type":"salamander","settings":{"password":"p","packetSize":"100-200"}}"#)
                .contains("packetSize")
        );
        assert!(
            err(r#"{"type":"salamander","settings":{"password":"p","packetSize":1200}}"#)
                .contains("packetSize")
        );
        // 对象/布尔形态：Go Int32Range 直接 "Invalid integer range" 硬错，Rust 同拒。
        assert!(
            err(r#"{"type":"salamander","settings":{"password":"p","packetSize":{"from":100}}}"#)
                .contains("invalid integer range")
        );
        // to<=0 / 缺省 / null → Go 走普通 salamander 分支，放行。
        build_udpmask_entry(&fm(r#"{"type":"salamander","settings":{"password":"p"}}"#)).unwrap();
        build_udpmask_entry(&fm(
            r#"{"type":"salamander","settings":{"password":"p","packetSize":null}}"#,
        ))
        .unwrap();
        build_udpmask_entry(&fm(
            r#"{"type":"salamander","settings":{"password":"p","packetSize":"0-0"}}"#,
        ))
        .unwrap();
    }

    /// Go RealmConfig.TlsConfig（transport_finalmask.go:1011，Build :1077-1082，
    /// 消费 realm/client.go:65）：Rust 仅 use_tls，非 null 指名键硬错；null/缺省放行。
    #[test]
    fn realm_tls_config_rejects_non_null_passes_absent() {
        let err = match build_udpmask_entry(&fm(
            r#"{"type":"realm","settings":{"url":"realm://t@h.example.com/i",
                "stunServers":["s.example.com:3478"],"tlsConfig":{"serverName":"h.example.com"}}}"#,
        )) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected tlsConfig reject"),
        };
        assert!(err.contains("tlsConfig"), "got: {err}");
        build_udpmask_entry(&fm(
            r#"{"type":"realm","settings":{"url":"realm://t@h.example.com/i","stunServers":["s.example.com:3478"]}}"#,
        ))
        .unwrap();
        build_udpmask_entry(&fm(r#"{"type":"realm","settings":{"url":"realm://t@h.example.com/i",
                "stunServers":["s.example.com:3478"],"tlsConfig":null}}"#))
        .unwrap();
    }

    /// Go XDNSDomain.Names[]（transport_finalmask.go:813，Build :841-858）：一项
    /// names 展开多条域；Rust 旧方言 name 兜底。
    #[test]
    fn xdns_names_array_expands_domains() {
        let cfg = build_xdns_config(&fm(r#"{"domains":[
                {"names":["a.example.com","b.example.com"],"types":[16]},
                {"name":"c.example.com","types":[1]}
            ],"resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53"}}]}"#))
        .unwrap();
        assert_eq!(cfg.domains.len(), 3);
        assert_eq!(cfg.domains[0].name, "a.example.com");
        assert_eq!(cfg.domains[1].name, "b.example.com");
        assert_eq!(cfg.domains[2].name, "c.example.com");
        // 同参展开：names 两条共享 types。
        assert_eq!(cfg.domains[1].types, cfg.domains[0].types);
    }

    #[test]
    fn build_tcpmask_entry_wires_all_types() {
        let json = fm(r#"{"tcp":[
                {"type":"fragment","settings":{"length":{"from":10,"to":20}}},
                {"type":"sudoku","settings":{"password":"p"}},
                {"type":"xmc","settings":{"password":"mc-pass","hostname":"h",
                    "profiles":[{"username":"steve_1","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","texturesValue":"v","texturesSignature":"s"}]}},
                {"type":"header-custom","settings":{"clients":[]}}
            ]}"#);
        let mgr = build_tcpmask_manager_from_json(Some(&json)).unwrap();
        assert_eq!(mgr.tcpmasks.len(), 4);
    }

    #[test]
    fn fragment_config_go_style_keys_parse() {
        // Go FragmentMask 原名（transport_finalmask.go:240-247）：packets 字符串 range /
        // lengths[] / delays[] / maxSplit。修复前这些键整段被静默丢弃（只读 proto 名）。
        let cfg = build_fragment_config(&fm(
            r#"{"packets":"tlshello","lengths":[{"from":10,"to":20},{"from":30,"to":40}],
                "delays":[{"from":5,"to":10}],"maxSplit":{"from":2,"to":4}}"#,
        ))
        .unwrap();
        assert_eq!((cfg.packets_from, cfg.packets_to), (0, 1));
        assert_eq!(cfg.lengths_min, vec![10, 30]);
        assert_eq!(cfg.lengths_max, vec![20, 40]);
        assert_eq!(cfg.delays_min, vec![5]);
        assert_eq!(cfg.delays_max, vec![10]);
        assert_eq!((cfg.max_split_min, cfg.max_split_max), (2, 4));
        // packets 数字 range 字符串走 Go ParseRangeString（"1-3" → from=1, to=3）。
        // length 显式给出：Go 下无 length 的 fragment 末段 min==0 本就硬错（Build :282）。
        let cfg = build_fragment_config(&fm(r#"{"packets":"1-3","length":{"from":100,"to":200}}"#))
            .unwrap();
        assert_eq!((cfg.packets_from, cfg.packets_to), (1, 3));
        // Go Build :263-264：range 字符串 from==0 硬错。
        let err = build_fragment_config(&fm(r#"{"packets":"0-3"}"#)).unwrap_err();
        assert!(err.to_string().contains("PacketsFrom can't be 0"), "got: {err}");
    }

    #[test]
    fn fragment_config_proto_style_keys_compat() {
        // proto 简化名（packets_from/packets_to/length/interval/max_split）向后兼容不回归。
        let cfg = build_fragment_config(&fm(
            r#"{"packets_from":0,"packets_to":1,"length":{"from":100,"to":200},
                "interval":{"from":7,"to":9},"max_split":3}"#,
        ))
        .unwrap();
        assert_eq!((cfg.packets_from, cfg.packets_to), (0, 1));
        assert_eq!(cfg.lengths_min, vec![100]);
        assert_eq!(cfg.lengths_max, vec![200]);
        assert_eq!(cfg.delays_min, vec![7]);
        assert_eq!(cfg.delays_max, vec![9]);
        assert_eq!((cfg.max_split_min, cfg.max_split_max), (3, 3));
    }

    #[test]
    fn fragment_config_go_names_take_priority() {
        // 双名同现：Go 原名优先（Go FragmentMask 字段语义；proto 名是 Rust 简化名）。
        let cfg = build_fragment_config(&fm(r#"{"packets":"1-3","packets_from":9,"packets_to":9,
                "lengths":[{"from":10,"to":10}],"length":{"from":99,"to":99},
                "delays":[{"from":1,"to":2}],"delay":{"from":3,"to":3},"interval":{"from":8,"to":8},
                "maxSplit":{"from":2,"to":3},"max_split":7}"#))
        .unwrap();
        assert_eq!((cfg.packets_from, cfg.packets_to), (1, 3), "packets wins over proto name");
        assert_eq!(cfg.lengths_min, vec![10], "lengths[] wins over length");
        assert_eq!(cfg.lengths_max, vec![10]);
        assert_eq!(cfg.delays_min, vec![1], "delays[] wins over delay/interval");
        assert_eq!(cfg.delays_max, vec![2]);
        assert_eq!((cfg.max_split_min, cfg.max_split_max), (2, 3), "maxSplit wins over max_split");
    }

    #[test]
    fn fragment_config_last_lengths_min_zero_rejected() {
        // 票 1xb0，Go Build :282-284：末段 min==0 硬错（文案可定位）。
        let e =
            build_fragment_config(&fm(r#"{"lengths":[{"from":10,"to":20},{"from":0,"to":5}]}"#))
                .unwrap_err();
        assert!(e.to_string().contains("last lengths entry min can't be 0"), "got: {e}");
        // Go 只查末段：非末段 min==0 合法。
        build_fragment_config(&fm(r#"{"lengths":[{"from":0,"to":5},{"from":10,"to":20}]}"#))
            .unwrap();
        // 未提供 lengths/length → 缺省 {0,0} 末段命中，Go 同样报错（else 分支）。
        let e = build_fragment_config(&fm("{}")).unwrap_err();
        assert!(e.to_string().contains("last lengths entry min can't be 0"), "got: {e}");
        // proto 兼容名单段 length 同受校验。
        let e = build_fragment_config(&fm(r#"{"length":{"from":0,"to":0}}"#)).unwrap_err();
        assert!(e.to_string().contains("last lengths entry min can't be 0"), "got: {e}");
    }

    #[test]
    fn udphop_mask_type_registers_and_configures() {
        // 票 4kq9：Go infra/conf/transport_finalmask.go:92 注册 udphop；Build（:1105-1148）
        // 三模式 + interval 缺省 30-30 + from<5 拒绝 + remoteIPs 前缀/裸 IP 双形态。
        let json =
            fm(r#"{"udp":[{"type":"udphop","settings":{"mode":"intervallocal,intervalremote",
                "interval":{"from":30,"to":30},"remoteIPs":["10.0.0.0/24","1.2.3.4"],
                "remotePorts":[10000,10001]}}]}"#);
        let mgr = build_udpmask_manager_from_json(Some(&json)).expect("udphop must register now");
        assert_eq!(mgr.udpmasks.len(), 1);

        // interval 缺省 30-30（Go Build :1128-1131）；装配不报错即走通。
        let json = fm(r#"{"udp":[{"type":"udphop","settings":{"mode":"perconnremote"}}]}"#);
        build_udpmask_manager_from_json(Some(&json)).expect("default interval must pass");

        // from<5：Go Build :1132-1134 "interval must be at least 5"（mode 先于
        // interval 校验，用例必须带合法 mode——空 mode 在 Go 是更早的 invalid mode）。
        let err = build_udpmask_manager_from_json(Some(&fm(
            r#"{"udp":[{"type":"udphop","settings":{"mode":"intervallocal","interval":3}}]}"#,
        )))
        .err()
        .expect("interval<5 must fail at Build");
        assert!(err.to_string().contains("interval must be at least 5"), "got: {err}");

        // 空/缺 mode：Go Split("", ",") → [""] → default → invalid mode（同构报错）。
        let err = build_udpmask_manager_from_json(Some(&fm(
            r#"{"udp":[{"type":"udphop","settings":{"interval":30}}]}"#,
        )))
        .err()
        .expect("empty mode must fail like Go");
        assert!(err.to_string().contains("invalid mode"), "got: {err}");

        // 非法 mode（Go Build :1113-1115）与非法 IP（:1118-1133）显式报错。
        let err = build_udpmask_manager_from_json(Some(&fm(
            r#"{"udp":[{"type":"udphop","settings":{"mode":"bogus"}}]}"#,
        )))
        .err()
        .expect("bad mode must fail");
        assert!(err.to_string().contains("invalid mode"), "got: {err}");
        let err = build_udpmask_manager_from_json(Some(&fm(
            r#"{"udp":[{"type":"udphop","settings":{"mode":"intervallocal","remoteIPs":["not-an-ip"]}}]}"#,
        )))
        .err()
        .expect("bad ip must fail");
        assert!(err.to_string().contains("invalid ip"), "got: {err}");

        // codec 链路径（KCP 同步栈）：udphop 是连接级 wrapper，结构上非逐包 codec，
        // 显式指路而非含糊 unsupported。
        let json = fm(r#"{"udp":[{"type":"udphop","settings":{"mode":"intervalremote",
                "interval":{"from":30,"to":30},"remotePorts":[10000,10001]}}]}"#);
        let e = parse_finalmask_udp_chain(Some(&json)).err().expect("codec chain must reject");
        assert!(e.to_string().contains("conn-level wrapper"), "got: {e}");
    }

    /// 票 4kq9 验收 3：TCP/UDP 链式装配——同一 finalmask JSON 下 tcp(fragment) 与
    /// udp(udphop) 两 manager 同时装配成功。
    #[test]
    fn tcp_udp_chain_assembly_with_udphop() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":100}}],
                "udp":[{"type":"udphop","settings":{"mode":"intervallocal,intervalremote",
                    "interval":"30-30","remoteIPs":["10.0.0.0/24"],
                    "remotePorts":[10000,10001]}}]}"#,
        )
        .unwrap();
        let tcp = build_tcpmask_manager_from_json(Some(&json)).expect("tcp manager");
        let udp = build_udpmask_manager_from_json(Some(&json)).expect("udp manager");
        assert_eq!(tcp.tcpmasks.len(), 1);
        assert_eq!(udp.udpmasks.len(), 1);
    }

    #[test]
    fn build_entries_unknown_type_still_errors() {
        // xmc 仅 TCP、noise 仅 UDP（与 Go registry 一致）：错侧注册必须仍报 unsupported
        let udp = fm(r#"{"udp":[{"type":"xmc"}]}"#);
        let err = match build_udpmask_manager_from_json(Some(&udp)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected unsupported udp mask type error"),
        };
        assert!(err.contains("unsupported udp mask type"), "got: {err}");
        let tcp = fm(r#"{"tcp":[{"type":"noise"}]}"#);
        let err = match build_tcpmask_manager_from_json(Some(&tcp)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected unsupported tcp mask type error"),
        };
        assert!(err.contains("unsupported tcp mask type"), "got: {err}");
    }

    /// 票 b2og：PacketIoConn 发送队列有界——worker 卡死在 send_to（对端黑洞）
    /// 时，持续 poll_write 不得无界堆积，超出容量的包必须被丢弃并计数。
    #[tokio::test]
    async fn packet_io_conn_bounded_send_queue_drops_when_send_to_blocked() {
        use std::{
            sync::atomic::AtomicUsize,
            task::{Context, Poll, Waker},
        };

        struct BlockedUdpIo {
            received: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl UdpIo for BlockedUdpIo {
            async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                self.received.fetch_add(1, Ordering::Relaxed);
                // 模拟对端黑洞：worker 卡死在首个 send_to 上，队列因此填满
                std::future::pending::<io::Result<usize>>().await
            }

            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                std::future::pending().await
            }

            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }

        let received = Arc::new(AtomicUsize::new(0));
        let mut conn = PacketIoConn::new(
            Box::new(BlockedUdpIo { received: Arc::clone(&received) }),
            "127.0.0.1:9".parse().unwrap(),
        );
        let mut cx = Context::from_waker(Waker::noop());
        use tokio::io::AsyncWrite as _;
        for i in 0..1000u32 {
            let buf = [i as u8; 16];
            match std::pin::Pin::new(&mut conn).poll_write(&mut cx, &buf) {
                Poll::Ready(Ok(n)) => assert_eq!(n, 16, "fire-and-forget stays Ready"),
                other => panic!("poll_write must never pend (UDP semantics), got {other:?}"),
            }
        }
        // worker 有机会消费首个包并卡死在 send_to
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let dropped = conn.dropped.load(Ordering::Relaxed);
        let consumed = received.load(Ordering::Relaxed);
        assert!(consumed <= 1, "worker must be stuck on first send_to, got {consumed}");
        assert!(
            dropped >= (1000 - PACKET_QUEUE_CAP - 1) as u64,
            "overflow packets must be dropped: expected >= {}, got {dropped}",
            1000 - PACKET_QUEUE_CAP - 1
        );
        // 有界性：未丢弃的包 = 已消费 + 队列残留，总量不得超过容量
        assert!(
            (1000u64 - dropped) as usize <= PACKET_QUEUE_CAP + consumed,
            "queued + in-flight must stay bounded by PACKET_QUEUE_CAP"
        );
    }
}
