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
//! [`UdpmaskManager`] / [`TcpmaskManager`] 按逆序链式应用多个伪装模块（对应 Go `slices.Backward`）。

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub mod custom;
pub mod fragment;
pub mod mkcp;
pub mod noise;
pub mod realm;
pub mod salamander;
pub mod salamander_gecko;
pub mod sudoku;
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
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
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
/// 让 [`Connection`] consumer（不关心 UDP vs TCP 抽象）能消费 UDP 流。
///
/// **语义**：每次 read 取 1 个 UDP packet（不足 `buf` 长度则下次 read 取剩余或下一包）；
/// write 把 buffer 发到记录的 `remote_addr`。
///
/// 若 `udpio` 来自空 manager（`udpmasks` 为空），原样适配（无 mask）——无 mask 行为不变。
#[must_use]
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
#[must_use]
pub fn wrap_packet_conn_server_into_connection(
    udpio: Box<dyn UdpIo>,
    _remote_hint: SocketAddr,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    // ponytail: server 方向无法确定 peer；接口签名保留 remote_hint 仅为对称 client 路径，
    // 实际 `remote_addr()` 返回 Ok(None)。若未来要识别 peer，根据 `_remote_hint` 改进。
    Ok(Box::new(PacketIoConn::new(udpio, "0.0.0.0:0".parse().unwrap())))
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
        raw = if is_client {
            mask.wrap_conn_client(raw)?
        } else {
            mask.wrap_conn_server(raw)?
        };
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
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
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
/// ponytail: stop 信号缺失——driver task 一直运行直到 socket recv_from 出错（典型的是 socket drop 后内核报 error）。Drop 时 abort JoinHandle 立即取消。
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
        // Box→Arc 必须走标准库 `From<Box<T>> for Arc<T>`（值 move 进带 {strong,weak} 计数头的新分配）。
        // 此前 Box::into_raw + Arc::from_raw 是 UB：Box 分配没有计数头，Arc::clone 在分配外
        // fetch_add、drop 按错误 layout dealloc → STATUS_HEAP_CORRUPTION(0xc0000374)。
        let inner: Arc<dyn UdpIo> = inner.into();
        let (pkt_tx, pkt_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_CAP);
        let (snd_tx, mut snd_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        let driver_inner = Arc::clone(&inner);
        let dropped_driver = Arc::clone(&dropped);
        let driver = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_SIZE];
            loop {
                match driver_inner.recv_from(&mut buf).await {
                    Ok((n, _src)) => {
                        // 有界队列：读端消费不过来时丢新包（UDP 语义），计数可观测
                        match pkt_tx.try_send(buf[..n].to_vec()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                let total = dropped_driver.fetch_add(1, Ordering::Relaxed) + 1;
                                tracing::debug!(dropped = total, "PacketIoConn recv queue full, packet dropped");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break, // 读端已 drop
                        }
                    }
                    Err(_) => break,
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
            }
            std::task::Poll::Ready(None) => {
                *rx = None;
                std::task::Poll::Ready(Ok(()))
            }
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
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(dropped = total, "PacketIoConn send queue full, packet dropped");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("PacketIoConn send queue closed, packet dropped");
            }
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
            "aes-128-gcm" | "aes128gcm" | "aes-128-gcm" => Some(Self::Aes128Gcm),
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
/// 按 [header] → [security] 顺序追加到 manager，对应 Go `slices.Backward` 逆序应用。
pub fn build_udpmask_manager(config: &FinalmaskConfig) -> io::Result<UdpmaskManager> {
    let mut masks: Vec<Box<dyn Udpmask>> = Vec::new();

    // 1. Security mask
    match config.security {
        SecurityMode::Original => {
            masks.push(Box::new(mkcp::original::OriginalConfig));
        }
        SecurityMode::Aes128Gcm => {
            masks.push(Box::new(mkcp::aes128gcm::Aes128GcmConfig {
                password: config.password.clone(),
            }));
        }
        SecurityMode::Salamander => {
            masks.push(Box::new(salamander::SalamanderConfig {
                password: config.password.clone(),
            }));
        }
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
/// - `xdns` —— `xdns::Config{ domains, resolvers }`（DNS-over-UDP 隧道）
/// - `xicmp` —— `XicmpConfig{ ips, dgram }`（wrap 时仅允许最外层）
/// - `realm` —— `realm::Config`（STUN/HTTP NAT 穿透，settings 从 `url` 解析）
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
    let Some(v) = json else { return Ok(UdpmaskManager::new(masks)); };
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
        "salamander" => Ok(Box::new(salamander::SalamanderConfig {
            password: settings
                .get("password")
                .or_else(|| settings.get("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })),
        "noise" => build_noise_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "sudoku" => Ok(Box::new(build_sudoku_config(&settings))),
        "xdns" => build_xdns_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "xicmp" => build_xicmp_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "realm" => build_realm_config(&settings).map(|c| Box::new(c) as Box<dyn Udpmask>),
        "header-custom" => {
            let (udp, udp_standalone) = build_custom_udp(&settings)?;
            Ok(Box::new(custom::Config {
                udp,
                udp_standalone,
                ..custom::Config::default()
            }))
        }
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
    let header = settings
        .get("header")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
            }
        };
        let cfg = mkcp::header::HeaderConfig { id, domain };
        return Ok(Box::new(cfg));
    }
    if !password.is_empty() {
        return Ok(Box::new(mkcp::aes128gcm::Aes128GcmConfig {
            password: password.to_string(),
        }));
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
    let Some(v) = json else { return Ok(TcpmaskManager::new(masks)); };
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
            Box::new(custom::Config {
                tcp: Some(tcp),
                ..custom::Config::default()
            }) as Box<dyn Tcpmask>
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
        }
        Some(serde_json::Value::Number(n)) => {
            let x = n.as_i64().ok_or_else(|| mask_err(format!("invalid integer range for {key:?}")))?;
            Ok((x, x))
        }
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
        }
        Some((l, r)) => {
            let l = if body.len() < s.len() { format!("-{l}") } else { l.to_string() };
            (l, r.to_string())
        }
    };
    let lo: i64 = first.parse().map_err(|_| invalid())?;
    let hi: i64 = second.parse().map_err(|_| invalid())?;
    Ok((lo.min(hi), lo.max(hi)))
}

/// Go `RandRange`：缺省 `{0,255}`；越界（越出 0..=255）报错（对齐 Go Build 校验）。
fn json_rand_range(v: &serde_json::Value) -> io::Result<(i64, i64)> {
    let (from, to) = if v.get("randRange").map_or(true, |x| x.is_null()) {
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
        }
        _ => Err(mask_err(format!("unknown type {typ:?}"))),
    }
}

/// Go `validateCustomVarName`：空串放行；否则 `^[A-Za-z_][A-Za-z0-9_]*$`。
fn validate_var_name(name: &str) -> io::Result<()> {
    let ok = name.is_empty()
        || (name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    if ok {
        Ok(())
    } else {
        Err(mask_err(format!("invalid variable name {name:?}")))
    }
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
    let has_u64 = v.get("u64").map_or(false, |x| !x.is_null());
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
        let n = v
            .get("u64")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| mask_err("invalid u64 arg"))?;
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
        "" | "prefix" | "standalone" => {}
        other => return Err(mask_err(format!("unknown udp mode {other:?}"))),
    }
    let read_items = |key: &str| -> io::Result<Vec<custom::UDPItem>> {
        match settings.get(key).and_then(|x| x.as_array()) {
            None => Ok(Vec::new()),
            Some(items) => items.iter().map(parse_custom_udp_item).collect(),
        }
    };
    let cfg = custom::UDPConfig {
        client: read_items("client")?,
        server: read_items("server")?,
    };
    Ok(if mode == "standalone" {
        (None, Some(cfg))
    } else {
        (Some(cfg), None)
    })
}

/// Go `NoiseMask.Build` → `noise::NoiseConfig`。
fn build_noise_config(settings: &serde_json::Value) -> io::Result<noise::NoiseConfig> {
    let (reset_min, reset_max) = json_range(settings, "reset")?;
    let empty: Vec<serde_json::Value> = Vec::new();
    let mut items = Vec::new();
    for item in settings.get("noise").and_then(|x| x.as_array()).unwrap_or(&empty) {
        let (rand_min, rand_max) = json_range(item, "rand")?;
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
        });
    }
    Ok(noise::NoiseConfig {
        reset_min,
        reset_max,
        items,
    })
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
            if t.is_empty() {
                json_str_vec(settings, "custom_tables")
            } else {
                t
            }
        },
        padding_min: {
            let p = json_i64(settings, "paddingMin").max(0) as u32;
            if p == 0 {
                json_i64(settings, "padding_min").max(0) as u32
            } else {
                p
            }
        },
        padding_max: {
            let p = json_i64(settings, "paddingMax").max(0) as u32;
            if p == 0 {
                json_i64(settings, "padding_max").max(0) as u32
            } else {
                p
            }
        },
    }
}

/// Go `Xdns.Build` → `xdns::Config`（`domain` 已废弃；domains=server / resolvers=client）。
fn build_xdns_config(settings: &serde_json::Value) -> io::Result<xdns::Config> {
    if settings.get("domain").map_or(false, |x| !x.is_null()) {
        return Err(mask_err(
            "xdns: `domain` was removed; use domains(server) & resolvers(client)",
        ));
    }
    let domains = json_str_vec(settings, "domains");
    let resolvers = json_str_vec(settings, "resolvers");
    if domains.is_empty() && resolvers.is_empty() {
        return Err(mask_err("xdns: empty domains & empty resolvers"));
    }
    for r in &resolvers {
        if !r.contains("+udp://") {
            return Err(mask_err(format!("xdns: invalid resolver {r:?}")));
        }
    }
    Ok(xdns::Config { domains, resolvers })
}

/// Go `Xicmp.Build` → `XicmpConfig`；「仅最外层」约束由 wrap 时 `level != 0` 校验（模块内）。
fn build_xicmp_config(settings: &serde_json::Value) -> io::Result<xicmp::XicmpConfig> {
    let ips = json_str_vec(settings, "ips");
    for ip in &ips {
        ip.parse::<std::net::IpAddr>()
            .map_err(|e| mask_err(format!("xicmp: invalid ip {ip:?}: {e}")))?;
    }
    Ok(xicmp::XicmpConfig {
        ips,
        dgram: json_bool(settings, "dgram"),
    })
}

/// Go `Realm.Build` → `realm::Config`（URL 形如 `realm://token@host:port/id`；
/// scheme `realm`→https、`realm+http`→http；Rust 端 TLS 细节由 `use_tls` 简化承载）。
fn build_realm_config(settings: &serde_json::Value) -> io::Result<realm::Config> {
    let url = json_str(settings, "url");
    let (raw_scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| mask_err(format!("realm: invalid url {url:?}")))?;
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

/// `[v6]:port` / `host:port` / `host`（port 可缺省，调用方按需校验）。
fn split_host_port(s: &str) -> io::Result<(String, Option<String>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| mask_err(format!("missing ']' in {s:?}")))?;
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
    let mut usernames = Vec::with_capacity(profiles.len());
    for p in profiles {
        let username = json_str(p, "username");
        let valid = (3..=16).contains(&username.len())
            && username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(mask_err(format!(
                "invalid minecraft profile username: {username:?}"
            )));
        }
        json_str(p, "uuid")
            .parse::<uuid::Uuid>()
            .map_err(|e| mask_err(format!("invalid minecraft profile UUID: {e}")))?;
        if json_str(p, "texturesValue").is_empty() || json_str(p, "texturesSignature").is_empty() {
            return Err(mask_err(format!(
                "incomplete minecraft profile textures: {username:?}"
            )));
        }
        usernames.push(username.to_string());
    }
    let private_key = xmc::derivation::derive_rsa_key(password)
        .map_err(|e| mask_err(format!("derive minecraft rsa key: {e}")))?;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
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
        usernames,
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
    // ponytail: Go `length`/`interval` 是单值 range {from, to}；Rust 端
    // FragmentConfig 字段是 `Vec<i64>`，单元素 = 单段 range。
    fn opt_range1(v: &serde_json::Value, key: &str) -> (i64, i64) {
        let r = v.get(key);
        match r {
            Some(serde_json::Value::Object(o)) => {
                let from = o.get("from").and_then(|x| x.as_i64()).unwrap_or(0);
                let to = o.get("to").and_then(|x| x.as_i64()).unwrap_or(from);
                (from, to)
            }
            Some(serde_json::Value::Number(n)) => {
                let x = n.as_i64().unwrap_or(0);
                (x, x)
            }
            _ => (0, 0),
        }
    }
    let (length_min, length_max) = opt_range1(settings, "length");
    let (delay_min, delay_max) = opt_range1(settings, "interval");
    Ok(fragment::FragmentConfig {
        packets_from: opt_u64(settings, "packets_from"),
        packets_to: opt_u64(settings, "packets_to"),
        max_split_min: opt_i64(settings, "max_split"),
        max_split_max: opt_i64(settings, "max_split"),
        lengths_min: vec![length_min],
        lengths_max: vec![length_max],
        delays_min: vec![delay_min],
        delays_max: vec![delay_max],
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
/// - `header` = dns/dtls/srtp/utp/wechat/wireguard → 协议头伪装
///   （dns 的 domain = `value`，默认 `www.baidu.com`）
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
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "finalmask: unsupported udp mask type {other:?} (supported: mkcp-legacy)"
                    ),
                ));
            }
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
            domain: if value.is_empty() {
                "www.baidu.com".to_string()
            } else {
                value.to_string()
            },
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
        }
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
        let chain =
            parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#)))
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
        for (name, id) in [
            ("dtls", 1),
            ("srtp", 2),
            ("utp", 3),
            ("wechat", 4),
            ("wireguard", 5),
        ] {
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
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[
                {"type":"mkcp-legacy","settings":{"value":"pw"}},
                {"type":"mkcp-legacy","settings":{"header":"srtp"}}
            ]}"#,
        )))
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
            let fm: serde_json::Value = serde_json::from_str(
                r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#,
            )
            .unwrap();
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
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::UdpSocket;
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

            client_conn
                .write_all(b"client-connection-payload")
                .await
                .expect("client write");

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
            let mut conn = wrap_packet_conn_client_into_connection(
                udpio,
                "127.0.0.1:9000".parse().unwrap(),
            )
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
        let settings = fm(
            r#"{"reset":{"from":2,"to":5},
                "noise":[{"rand":{"from":10,"to":20},"delay":3},
                         {"packet":[1,2,3]}]}"#,
        );
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
    fn parse_json_sudoku_config_fields() {
        let cfg = build_sudoku_config(&fm(
            r#"{"password":"pw","ascii":"prefer_ascii",
                "customTable":"xxppvvvv","paddingMax":80}"#,
        ));
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
        let cfg = build_xdns_config(&fm(
            r#"{"domains":["t.example.com:txt"],"resolvers":["t.example.com+udp://1.1.1.1:53"]}"#,
        ))
        .unwrap();
        assert_eq!(cfg.domains, vec!["t.example.com:txt".to_string()]);
        assert_eq!(cfg.resolvers, vec!["t.example.com+udp://1.1.1.1:53".to_string()]);
        // 已废弃 domain 键报错（对齐 Go PrintRemovedFeatureError）
        assert!(build_xdns_config(&fm(r#"{"domain":"x.com"}"#)).is_err());
        // 双空报错
        assert!(build_xdns_config(&fm(r#"{}"#)).is_err());
        // resolver 缺 +udp:// 报错
        assert!(build_xdns_config(&fm(r#"{"resolvers":["udp://1.1.1.1:53"]}"#)).is_err());
    }

    #[test]
    fn parse_json_xicmp_config_fields() {
        let cfg = build_xicmp_config(&fm(r#"{"ips":["2001:db8::1","10.0.0.1"],"dgram":true}"#))
            .unwrap();
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

    #[test]
    fn parse_json_xmc_config_fields() {
        let cfg = build_xmc_config(&fm(
            r#"{"hostname":"mc.example.com","password":"mc-pass",
                "profiles":[{"username":"steve_1","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5",
                             "texturesValue":"v","texturesSignature":"s"}]}"#,
        ))
        .unwrap();
        assert_eq!(cfg.usernames, vec!["steve_1".to_string()]);
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
        let cfg = build_custom_tcp(&fm(
            r#"{"clients":[
                  [{"delay":{"from":1,"to":2},"packet":[1,2],"capture":"hello"},
                   {"reuse":"hello"},
                   {"packet":"aabb","type":"hex"}]
                ],
                "servers":[[{"transform":{"op":"concat","args":[{"bytes":[170]}]}}]]}"#,
        ))
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
        assert!(build_custom_tcp(&fm(r#"{"clients":[[{"packet":[1],"capture":"9bad"}]]}"#)).is_err());
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
        let json = fm(
            r#"{"udp":[
                {"type":"noise","settings":{"reset":{"from":1,"to":2}}},
                {"type":"sudoku","settings":{"password":"p"}},
                {"type":"xdns","settings":{"resolvers":["t.example.com+udp://1.1.1.1:53"]}},
                {"type":"xicmp","settings":{"ips":["10.0.0.1"]}},
                {"type":"realm","settings":{"url":"realm://t@h.example.com/i","stunServers":["s.example.com:3478"]}},
                {"type":"header-custom","settings":{"client":[]}}
            ]}"#,
        );
        let mgr = build_udpmask_manager_from_json(Some(&json)).unwrap();
        assert_eq!(mgr.udpmasks.len(), 6);
    }

    #[test]
    fn build_tcpmask_entry_wires_all_types() {
        let json = fm(
            r#"{"tcp":[
                {"type":"fragment","settings":{}},
                {"type":"sudoku","settings":{"password":"p"}},
                {"type":"xmc","settings":{"password":"mc-pass","hostname":"h",
                    "profiles":[{"username":"steve_1","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","texturesValue":"v","texturesSignature":"s"}]}},
                {"type":"header-custom","settings":{"clients":[]}}
            ]}"#,
        );
        let mgr = build_tcpmask_manager_from_json(Some(&json)).unwrap();
        assert_eq!(mgr.tcpmasks.len(), 4);
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
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Poll, Waker};

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
