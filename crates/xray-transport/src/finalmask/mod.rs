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
    rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// 写队列：`poll_write` 推入后单个 send worker 顺序 `send_to`——
    /// 复用 worker 而非每包 spawn（每包 spawn 在高 PPS 下堆积一次性任务）。
    /// FIFO 顺序也严格于原并发 spawn。
    tx: mpsc::UnboundedSender<Vec<u8>>,
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
        let (pkt_tx, pkt_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (snd_tx, mut snd_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver_inner = Arc::clone(&inner);
        let driver = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_SIZE];
            loop {
                match driver_inner.recv_from(&mut buf).await {
                    Ok((n, _src)) => {
                        if pkt_tx.send(buf[..n].to_vec()).is_err() {
                            break; // 读端已 drop
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
        // fire-and-forget：入队即 Ready；worker 异步发送。队列关闭仅在 conn 已
        // 半亡（worker 被 abort）时发生，包静默丢弃与原 spawn-丢包语义一致。
        if self.tx.send(buf.to_vec()).is_err() {
            tracing::debug!("PacketIoConn send queue closed, packet dropped");
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
/// `{"type","settings"}`。支持的 mask 类型（与现有模块对齐）：
///
/// - `mkcp-legacy` —— `mkcp-original` / `mkcp-aes128gcm` / `header-*`（KCP 原版）
/// - `salamander` —— `SalamanderConfig{ password }`
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
/// JSON 形态顶层对象 `tcp` 数组，每项 `{"type","settings"}`。当前支持：
///
/// - `fragment` —— `FragmentConfig{ packets_from, packets_to, length, interval }`
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
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("finalmask: unsupported tcp mask type {other:?}"),
        )),
    }
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
}
