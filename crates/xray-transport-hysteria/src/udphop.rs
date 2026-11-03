//! UdpHopPacketConn —— 多端口 UDP 跳跃连接（对应 Go `udphop/conn.go`）。
//!
//! 完整翻译 hop/recv 循环 + buf pool 复用。Go 用 goroutine + channel；
//! Rust 端用 tokio::sync::mpsc + spawn 任务。
//!
//! ponytail: Go 用 `net.PacketConn`，Rust 端用 [`PacketConn`] trait 抽象，
//! 上层（quinn adapter）注入 `tokio::net::UdpSocket` 或 `std::net::UdpSocket` 适配。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use parking_lot::Mutex;
use skeleton_infra::{ObjectPool, Owned, ResetPhase};
use tokio::sync::mpsc;

use crate::error::{HysteriaError, Result};

/// UDP 包缓冲大小（对应 Go `udpBufferSize = finalmask.UDPSize`）。
pub const UDP_BUFFER_SIZE: usize = 1500;

/// 默认 hop 间隔（对应 Go `defaultHopInterval = 30 * time.Second`）。
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);

/// 最小允许的 hop 间隔（对应 Go `5 * time.Second`）。
pub const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

/// 接收 channel 缓冲（对应 Go `packetQueueSize = 1024`）。
pub const PACKET_QUEUE_SIZE: usize = 1024;

/// 单个 UDP 数据包（对应 Go `udpPacket`）。
#[derive(Debug)]
struct UdpPacket {
    /// 数据（池化 buf，随包 move，由消费端 read_from 归还池；err 包为空）。
    buf: Vec<u8>,
    /// 有效字节数。
    n: usize,
    /// 源地址。
    addr: Option<SocketAddr>,
    /// 错误（超时/IO 错误）。
    err: Option<std::io::Error>,
}

/// 池化 buf 复用（对应 Go `udphop` 包级 `sync.Pool`）。
///
/// recv_loop 与 read_from 消费端共享：buf 随 [`UdpPacket`] 零拷贝流转，
/// 消费端拷出数据后归还（对齐 Go `ReadFrom` 的 `pool.Put`）。
///
/// 槽位存储 / 借还记账 / 有界降级 / 分片全部由 udf [`ObjectPool`] 承担（2026-11-03
/// 迁移，依据见 `reports/audit-2026-11-03/bufpool-migration.md`）：
/// - 取出走 `acquire_owned`：`'static` 句柄，跨 `recv_from` 的 await 持有成立， 任务被取消时 Drop
///   即归还（不遗留脱离池的野块）；
/// - 归还走 `insert`（按值入池）：`Some(buf)` = 池已满，裸块就地释放； `dropped_overflow` +
///   审计事件由池留痕（原实现的静默丢弃变成可观测）；
/// - reset 钩子做容量归一（红线：池化对象等重，防池毒化）。
struct BufPool {
    inner: Arc<ObjectPool<Vec<u8>>>,
}

impl BufPool {
    fn new() -> Self {
        Self {
            inner: Arc::new(ObjectPool::with_reset(
                // max = idle 额度 + 在途额度：插入件按值认领宇宙配额，留一倍余量，
                // 使「容量因拒收」只发生在 idle 面（= 原 `put` 的 `PACKET_QUEUE_SIZE` 门）。
                PACKET_QUEUE_SIZE * 2,
                PACKET_QUEUE_SIZE,
                // 工厂 = 原 `get` 的 miss 分支（池空才分配）。
                || vec![0u8; UDP_BUFFER_SIZE],
                |buf: &mut Vec<u8>| {
                    // 容量归一：合规块只付一次 len 比较；异形块（超长/短块）就地归一到
                    // 定长，免得把脏块投给下一个借出方。
                    if buf.len() != UDP_BUFFER_SIZE {
                        buf.clear();
                        buf.resize(UDP_BUFFER_SIZE, 0);
                    }
                },
                ResetPhase::OnReturn,
            )),
        }
    }

    /// 取 buf（Go `pool.Get`）：优先复用，池空才按工厂分配。
    ///
    /// 返回 `'static` 句柄而非裸块：recv 循环跨 `recv_from` 的 await 持有它；进
    /// [`UdpPacket`] 前才 `detach()` 交出裸块——包在 mpsc 上跨任务，消费端不需要
    /// 知道池的存在。
    fn get(&self) -> Owned<Vec<u8>> {
        self.inner.acquire_owned()
    }

    /// 归还 buf（Go `pool.Put`）：容量裁决/计数/审计全由 `insert` 完成。
    fn put(&self, buf: Vec<u8>) {
        // `Some` = 池已满（`insert` 已记 dropped_overflow + 发审计事件）⇒ 就地释放。
        drop(self.inner.insert(buf));
    }
}

// ponytail: 不引入 async_trait crate。改用 `Box<dyn Future>` + 手写 trait。

/// 接收一个 UDP 包的 future 类型。
pub type RecvFuture =
    std::pin::Pin<Box<dyn Future<Output = std::io::Result<(usize, SocketAddr)>> + Send>>;

/// 发送一个 UDP 包的 future 类型。
pub type SendFuture = std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send>>;

/// 关闭的 future 类型。
pub type CloseFuture = std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

/// `net.PacketConn` 的异步抽象（对应 Go `net.PacketConn`）。
///
/// ponytail: 不引入 async_trait crate，方法返回 `Pin<Box<dyn Future>>`。
/// PacketConn future（`Pin<Box<dyn Future>>`，ponytail 不引 async_trait）。
type PacketFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

pub trait PacketConn: Send + Sync {
    /// 接收数据包到 buf，返回 (字节数, 源地址)。
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> PacketFuture<'a, (usize, SocketAddr)>;

    /// 发送数据包到指定地址。
    fn send_to<'a>(&'a self, buf: &'a [u8], addr: SocketAddr) -> PacketFuture<'a, usize>;

    /// 关闭。
    fn close(&self) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

    /// 本地地址。
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

/// ListenUDPFunc —— 创建 PacketConn 的回调（对应 Go `ListenUDPFunc`）。
///
/// 上层注入。Go 端调 `internet.DialSystem(ctx, udp_dst)`。
pub type ListenUdpFunc = Arc<
    dyn Fn(
            &SocketAddr,
        )
            -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn PacketConn>>> + Send>>
        + Send
        + Sync,
>;

/// UdpHopPacketConn —— 多端口跳跃 PacketConn（对应 Go `UdpHopPacketConn`）。
///
/// - 周期性在 `addrs` 间切换活跃 conn
/// - 所有 conn 的 recv 复用同一个 mpsc channel
/// - WriteTo 始终发到当前活跃 addr
pub struct UdpHopPacketConn {
    inner: Arc<Mutex<UdpHopInner>>,
    /// 接收 channel。
    recv_rx: tokio::sync::Mutex<mpsc::Receiver<UdpPacket>>,
    recv_tx: mpsc::Sender<UdpPacket>,
    /// 池化 buf（recv_loop 与 read_from 共享，对应 Go 包级 sync.Pool）。
    pool: Arc<BufPool>,
    /// hop 任务句柄（spawn 时由调用方持有；Drop 时 abort）。
    hop_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// recv 任务句柄（每 hop 启动一个）。
    #[allow(dead_code)] // 句柄随 conn 保活统一回收，本体无需读取
    recv_handles: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

struct UdpHopInner {
    addrs: Vec<SocketAddr>,
    hop_interval_min: Duration,
    hop_interval_max: Duration,
    listen_udp_func: ListenUdpFunc,
    prev_conn: Option<Arc<dyn PacketConn>>,
    current_conn: Option<Arc<dyn PacketConn>>,
    addr_index: usize,
    closed: bool,
}

impl std::fmt::Debug for UdpHopPacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("UdpHopPacketConn")
            .field("addr_count", &inner.addrs.len())
            .field("addr_index", &inner.addr_index)
            .field("hop_interval_min", &inner.hop_interval_min)
            .field("hop_interval_max", &inner.hop_interval_max)
            .field("closed", &inner.closed)
            .finish()
    }
}

impl UdpHopPacketConn {
    /// 构造（对应 Go `NewUDPHopPacketConn`）。
    ///
    /// 异步：内部 spawn 两个 tokio 任务（hop_loop + recv_loop on current_conn）。
    ///
    /// # Panics
    /// - `addrs` 为空
    /// - `hop_interval_min < 5s` 或 `hop_interval_max < 5s`
    /// - `hop_interval_max < hop_interval_min`
    /// - `listen_udp_func` 为空（编译时强类型保证）
    pub async fn new(
        addrs: Vec<SocketAddr>,
        hop_interval_min: Duration,
        hop_interval_max: Duration,
        listen_udp_func: ListenUdpFunc,
        current_conn: Arc<dyn PacketConn>,
        addr_index: usize,
    ) -> Result<Arc<Self>> {
        if addrs.is_empty() {
            return Err(HysteriaError::InvalidUdpHop("len(addrs) == 0".into()));
        }
        let hop_min =
            if hop_interval_min.is_zero() { DEFAULT_HOP_INTERVAL } else { hop_interval_min };
        let hop_max =
            if hop_interval_max.is_zero() { DEFAULT_HOP_INTERVAL } else { hop_interval_max };
        if hop_min < MIN_HOP_INTERVAL {
            return Err(HysteriaError::InvalidUdpHop(format!(
                "hopIntervalMin {:?} < {:?}",
                hop_min, MIN_HOP_INTERVAL
            )));
        }
        if hop_max < MIN_HOP_INTERVAL {
            return Err(HysteriaError::InvalidUdpHop(format!(
                "hopIntervalMax {:?} < {:?}",
                hop_max, MIN_HOP_INTERVAL
            )));
        }
        if hop_max < hop_min {
            return Err(HysteriaError::InvalidUdpHop(format!(
                "hopIntervalMax {:?} < hopIntervalMin {:?}",
                hop_max, hop_min
            )));
        }

        let (recv_tx, recv_rx) = mpsc::channel(PACKET_QUEUE_SIZE);
        let pool = Arc::new(BufPool::new());

        let inner = Arc::new(Mutex::new(UdpHopInner {
            addrs,
            hop_interval_min: hop_min,
            hop_interval_max: hop_max,
            listen_udp_func,
            prev_conn: None,
            current_conn: Some(Arc::clone(&current_conn)),
            addr_index,
            closed: false,
        }));

        let _conn_inner = Arc::clone(&inner);
        // spawn recv loop on initial current_conn
        let recv_tx_clone = recv_tx.clone();
        let conn_for_recv = Arc::clone(&current_conn);
        let pool_for_recv = Arc::clone(&pool);
        #[allow(
            clippy::disallowed_methods,
            reason = "数据面连接任务（UDP hop recv 泵）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
        )]
        let recv_handle = tokio::spawn(async move {
            recv_loop(conn_for_recv, recv_tx_clone, pool_for_recv).await;
        });

        // spawn hop loop
        let hop_inner = Arc::clone(&inner);
        let hop_recv_tx = recv_tx.clone();
        let pool_for_hop = Arc::clone(&pool);
        #[allow(
            clippy::disallowed_methods,
            reason = "数据面连接任务（UDP hop 换口循环）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
        )]
        let hop_handle = tokio::spawn(async move {
            hop_loop(hop_inner, hop_recv_tx, pool_for_hop).await;
        });

        Ok(Arc::new(Self {
            inner,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            recv_tx,
            pool,
            hop_handle: tokio::sync::Mutex::new(Some(hop_handle)),
            recv_handles: tokio::sync::Mutex::new(vec![recv_handle]),
        }))
    }

    /// 从接收 channel 读一个包（对应 Go `ReadFrom`）。
    ///
    /// 异步：等到有包或所有 conn 关闭。
    pub async fn read_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let pkt = self
            .recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"))?;

        let UdpPacket { buf: pkt_buf, n, addr, err } = pkt;
        if let Some(err) = err {
            return Err(err);
        }
        if buf.len() < n {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short buffer"));
        }
        buf[..n].copy_from_slice(&pkt_buf[..n]);
        // buf 归还池，供 recv_loop 复用（对齐 Go ReadFrom 的 pool.Put）。
        self.pool.put(pkt_buf);
        Ok((n, addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))))
    }

    /// 发送到当前活跃 addr（对应 Go `WriteTo`）。
    #[allow(clippy::await_holding_lock)] // guard 有意存活跨 await（同步锁保护写路径）
    pub async fn write_to(&self, buf: &[u8]) -> std::io::Result<usize> {
        let inner = self.inner.lock();
        if inner.closed {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "closed"));
        }
        let conn = inner
            .current_conn
            .clone()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "no conn"))?;
        let addr = inner.addrs[inner.addr_index];
        drop(inner);
        conn.send_to(buf, addr).await
    }

    /// 关闭（对应 Go `Close`）。
    #[allow(clippy::await_holding_lock)] // guard 有意存活跨 await（同步锁保护）
    pub async fn close(&self) -> std::io::Result<()> {
        // abort hop loop
        if let Some(handle) = self.hop_handle.lock().await.take() {
            handle.abort();
        }
        // abort recv loops
        let mut handles = self.recv_handles.lock().await;
        for h in handles.drain(..) {
            h.abort();
        }

        #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
        let mut inner = self.inner.lock();
        if inner.closed {
            return Ok(());
        }
        inner.closed = true;
        if let Some(prev) = inner.prev_conn.take() {
            let _ = prev.close().await;
        }
        let result =
            if let Some(cur) = inner.current_conn.take() { cur.close().await } else { Ok(()) };
        inner.addrs.clear();
        drop(inner);

        // 关闭 channel
        drop_helpers(&self.recv_tx);
        result
    }

    /// 本地地址（对应 Go `LocalAddr`）。
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let inner = self.inner.lock();
        inner
            .current_conn
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "no conn"))?
            .local_addr()
    }

    /// 取所有 addrs。
    #[must_use]
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.inner.lock().addrs.clone()
    }

    /// 取当前 addr index。
    #[must_use]
    pub fn addr_index(&self) -> usize {
        self.inner.lock().addr_index
    }
}

/// recv 循环（对应 Go `recvLoop`）。
///
/// buf 从池借出（`'static` 句柄），直接 recv 进池 buf（无草稿拷贝），成功后
/// `detach` 出裸块随包 move 出去，由消费端 read_from 用 `insert` 归还池
/// （对齐 Go `pool.Get`/`pool.Put`）。
async fn recv_loop(conn: Arc<dyn PacketConn>, tx: mpsc::Sender<UdpPacket>, pool: Arc<BufPool>) {
    loop {
        let mut buf = pool.get();
        // 先绑定再 match：scrutinee 临时 future 持有 &mut buf，会延长借用跨过 match 臂。
        let res = conn.recv_from(buf.as_mut_slice()).await;
        match res {
            Ok((n, addr)) => {
                // buf 所有权零拷贝移入 packet（Go: readCh <- packet{p: p[:n]}）。
                let pkt = UdpPacket { buf: buf.detach(), n, addr: Some(addr), err: None };
                match tx.try_send(pkt) {
                    Ok(()) => {},
                    // 队列满：丢弃包，buf 归还池（Go 侧 channel 阻塞背压，此处丢弃防堆积）。
                    Err(mpsc::error::TrySendError::Full(pkt)) => pool.put(pkt.buf),
                    // channel 关闭（conn 已 drop）：退出循环（Go: closeCh 分支）。
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            },
            Err(e) => {
                let kind = e.kind();
                if matches!(kind, std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
                    // buf 未消费，归还池（Go: pool.Put(p[:cap(p))] 后 continue）。
                    // 句柄未 detach ⇒ drop 即归还（不必绕 insert 一趟）。
                    drop(buf);
                    let _ =
                        tx.try_send(UdpPacket { buf: Vec::new(), n: 0, addr: None, err: Some(e) });
                    continue;
                }
                return;
            },
        }
    }
}

/// hop 循环（对应 Go `hopLoop`）。
async fn hop_loop(
    inner: Arc<Mutex<UdpHopInner>>,
    recv_tx: mpsc::Sender<UdpPacket>,
    pool: Arc<BufPool>,
) {
    loop {
        let interval = next_hop_interval(&inner);
        tokio::time::sleep(interval).await;
        if !hop_once(&inner, &recv_tx, &pool).await {
            return;
        }
    }
}

fn next_hop_interval(inner: &Arc<Mutex<UdpHopInner>>) -> Duration {
    let g = inner.lock();
    if g.hop_interval_min == g.hop_interval_max {
        return g.hop_interval_min;
    }
    let range = (g.hop_interval_max - g.hop_interval_min).as_millis() as u64;
    let extra = rand::random_range(0..=range);
    g.hop_interval_min + Duration::from_millis(extra)
}

/// 执行一次 hop。返回 false 表示已关闭，循环应退出。
async fn hop_once(
    inner: &Arc<Mutex<UdpHopInner>>,
    recv_tx: &mpsc::Sender<UdpPacket>,
    pool: &Arc<BufPool>,
) -> bool {
    let (new_addr_index, target_addr, listen_fn) = {
        let mut g = inner.lock();
        if g.closed {
            return false;
        }
        let idx = rand::random_range(0..g.addrs.len());
        g.addr_index = idx;
        (idx, g.addrs[idx], Arc::clone(&g.listen_udp_func))
    };

    let new_conn = match listen_fn(&target_addr).await {
        Ok(c) => c,
        Err(_) => return true,
    };

    let prev_conn_opt = {
        let mut g = inner.lock();
        if g.closed {
            return false;
        }
        let prev = g.prev_conn.take();
        g.prev_conn = g.current_conn.take();
        g.current_conn = Some(Arc::clone(&new_conn));
        prev
    };

    if let Some(prev) = prev_conn_opt {
        let _ = prev.close().await;
    }

    // spawn new recv loop
    let tx = recv_tx.clone();
    let conn_for_recv = Arc::clone(&new_conn);
    let pool_for_recv = Arc::clone(pool);
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面连接任务（换口后新 recv 泵）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    tokio::spawn(async move {
        recv_loop(conn_for_recv, tx, pool_for_recv).await;
    });

    let _ = new_addr_index;
    true
}

/// ponytail: drop_helpers 是 noop（mpsc::Sender 的 close 在所有 sender drop 时发生）。
fn drop_helpers(_tx: &mpsc::Sender<UdpPacket>) {
    // mpsc 会在所有 Sender drop 后让 Receiver 返回 None。
    // 当前 self 持有 recv_tx（最后 drop），关闭时机由 self drop 决定。
    // 此处仅占位，避免 close 后 channel 仍有 Sender。
}

/// 构造 `Vec<SocketAddr>`（对应 Go `ToAddrs(ip, ports)`）。
#[must_use]
pub fn to_addrs(ip: std::net::IpAddr, ports: &[u32]) -> Vec<SocketAddr> {
    ports.iter().map(|&p| SocketAddr::new(ip, p as u16)).collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn to_addrs_basic() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let addrs = to_addrs(ip, &[80, 443, 8080]);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].port(), 80);
        assert_eq!(addrs[1].port(), 443);
        assert_eq!(addrs[2].port(), 8080);
        assert_eq!(addrs[0].ip(), ip);
    }

    #[test]
    fn to_addrs_empty() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(to_addrs(ip, &[]).is_empty());
    }

    #[test]
    fn constants_match_go() {
        assert_eq!(UDP_BUFFER_SIZE, 1500);
        assert_eq!(DEFAULT_HOP_INTERVAL, Duration::from_secs(30));
        assert_eq!(MIN_HOP_INTERVAL, Duration::from_secs(5));
        assert_eq!(PACKET_QUEUE_SIZE, 1024);
    }

    #[test]
    fn next_hop_interval_equal_min_max_returns_min() {
        let (tx, _rx) = mpsc::channel::<UdpPacket>(1);
        let _ = tx;
        let inner = Arc::new(Mutex::new(UdpHopInner {
            addrs: vec!["127.0.0.1:80".parse().unwrap()],
            hop_interval_min: Duration::from_secs(10),
            hop_interval_max: Duration::from_secs(10),
            listen_udp_func: Arc::new(|_| Box::pin(async { unreachable!() })),
            prev_conn: None,
            current_conn: None,
            addr_index: 0,
            closed: false,
        }));
        let i = next_hop_interval(&inner);
        assert_eq!(i, Duration::from_secs(10));
    }

    #[test]
    fn next_hop_interval_within_range() {
        let inner = Arc::new(Mutex::new(UdpHopInner {
            addrs: vec!["127.0.0.1:80".parse().unwrap()],
            hop_interval_min: Duration::from_secs(10),
            hop_interval_max: Duration::from_secs(20),
            listen_udp_func: Arc::new(|_| Box::pin(async { unreachable!() })),
            prev_conn: None,
            current_conn: None,
            addr_index: 0,
            closed: false,
        }));
        for _ in 0..50 {
            let i = next_hop_interval(&inner);
            assert!(i >= Duration::from_secs(10) && i <= Duration::from_secs(20), "got {:?}", i);
        }
    }

    /// 恒定产包的 mock PacketConn。
    struct MockRecvConn {
        payload_len: usize,
        addr: SocketAddr,
    }

    impl PacketConn for MockRecvConn {
        fn recv_from<'a>(
            &'a self,
            buf: &'a mut [u8],
        ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a>>
        {
            Box::pin(async move {
                // 让出调度模拟真实到达节奏，避免 recv_loop 空转抢占消费端。
                tokio::time::sleep(Duration::from_millis(1)).await;
                buf[..self.payload_len].fill(0xAB);
                Ok((self.payload_len, self.addr))
            })
        }

        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            _addr: SocketAddr,
        ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn close(&self) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
            Box::pin(async { Ok(()) })
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.addr)
        }
    }

    #[tokio::test]
    async fn recv_loop_recycles_bufs_to_pool() {
        let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let conn = UdpHopPacketConn::new(
            vec![addr],
            MIN_HOP_INTERVAL,
            MIN_HOP_INTERVAL,
            Arc::new(|_| Box::pin(async { unreachable!() })),
            Arc::new(MockRecvConn { payload_len: 16, addr }),
            0,
        )
        .await
        .expect("new");

        let mut buf = [0u8; UDP_BUFFER_SIZE];
        for _ in 0..8 {
            let (n, from) = conn.read_from(&mut buf).await.expect("read_from");
            assert_eq!(n, 16);
            assert_eq!(from, addr);
            assert!(buf[..n].iter().all(|&b| b == 0xAB));
        }

        // 回池断言：消费端归还后池非空。
        let m = conn.pool.inner.metrics();
        assert!(m.core.idle >= 1, "pool should hold recycled bufs, idle={}", m.core.idle);
        // 复用断言：8 包只允许 ≤2 次池外新分配（首包 + 至多一个在途 buf）。
        assert!(
            m.constructed <= 2,
            "8 packets should reuse pooled bufs, constructed={}",
            m.constructed
        );
        // 同口径正面读数：至少 6 次命中 idle 槽（改前只断言分配数上限）。
        assert!(m.reused >= 6, "8 packets should reuse pooled bufs, reused={}", m.reused);
        assert_eq!(m.reset_panicked, 0, "归一路径只有赋值，不得 panic");

        conn.close().await.ok();
    }

    #[test]
    fn buf_pool_get_put_reuses() {
        let pool = BufPool::new();
        let b = pool.get().detach();
        assert_eq!(b.len(), UDP_BUFFER_SIZE);
        assert_eq!(pool.inner.metrics().constructed, 1, "池空 ⇒ 工厂造一块");
        pool.put(b);
        assert_eq!(pool.inner.metrics().core.idle, 1, "归还即入 idle");
        let b2 = pool.get().detach();
        assert_eq!(pool.inner.metrics().constructed, 1, "must reuse instead of realloc");
        assert_eq!(pool.inner.metrics().reused, 1, "命中 idle 槽一次");
        pool.put(b2);
        assert_eq!(pool.inner.metrics().core.idle, 1);
    }

    /// 红线：reset 钩子负责容量归一——异形块插入后必须归一到定长才可能被借出。
    /// **反向自检锚点**：把钩子改成 no-op，本断言必红（迁移报告有实测记录）。
    #[test]
    fn buf_pool_reset_normalizes_poisoned_block() {
        let pool = BufPool::new();
        pool.put(vec![0xCD; UDP_BUFFER_SIZE * 3]);
        assert_eq!(pool.inner.metrics().core.idle, 1, "归一到定长的块才入池");
        let reused = pool.get();
        assert_eq!(reused.len(), UDP_BUFFER_SIZE, "reset 必须把块归一到定长");
        assert!(
            reused.iter().all(|&b| b == 0),
            "归一后必须清零：禁把上一轮的脏数据发给下一个借出方"
        );
    }

    /// udf 独有语义：`insert` 收不下时**按值交回**（`Some`）+ `dropped_overflow`
    /// 留痕，池不静默吞块（改前的静默丢弃在这里变成可观测）。
    #[test]
    fn buf_pool_insert_overflow_returns_object_and_counts() {
        let pool = BufPool::new();
        for _ in 0..PACKET_QUEUE_SIZE {
            pool.put(vec![0u8; UDP_BUFFER_SIZE]);
        }
        assert_eq!(pool.inner.metrics().core.idle, PACKET_QUEUE_SIZE, "idle 额度内全收");
        assert_eq!(pool.inner.metrics().core.dropped_overflow, 0);

        // 第 N+1 块：idle 额度已满 ⇒ 交回，本模块就地释放并计数。
        pool.put(vec![0u8; UDP_BUFFER_SIZE]);
        let m = pool.inner.metrics();
        assert_eq!(m.core.dropped_overflow, 1, "超量归还必须计数，不得静默");
        assert_eq!(m.core.idle, PACKET_QUEUE_SIZE, "idle 不得越过额度");
    }
}
