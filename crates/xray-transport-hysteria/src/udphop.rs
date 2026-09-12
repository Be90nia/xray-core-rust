//! UdpHopPacketConn —— 多端口 UDP 跳跃连接（对应 Go `udphop/conn.go`）。
//!
//! 完整翻译 hop/recv 循环 + buf pool 复用。Go 用 goroutine + channel；
//! Rust 端用 tokio::sync::mpsc + spawn 任务。
//!
//! ponytail: Go 用 `net.PacketConn`，Rust 端用 [`PacketConn`] trait 抽象，
//! 上层（quinn adapter）注入 `tokio::net::UdpSocket` 或 `std::net::UdpSocket` 适配。

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
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
#[derive(Default)]
struct BufPool {
    bufs: Mutex<VecDeque<Vec<u8>>>,
    /// 池空时的新分配次数（供测试断言复用）。
    allocs: AtomicUsize,
}

impl BufPool {
    /// 取 buf（Go `pool.Get`）：优先复用，池空才分配。
    fn get(&self) -> Vec<u8> {
        if let Some(buf) = self.bufs.lock().pop_front() {
            return buf;
        }
        self.allocs.fetch_add(1, Ordering::Relaxed);
        vec![0u8; UDP_BUFFER_SIZE]
    }

    /// 归还 buf（Go `pool.Put`），超量直接丢弃防无界滞留。
    fn put(&self, buf: Vec<u8>) {
        let mut bufs = self.bufs.lock();
        if bufs.len() < PACKET_QUEUE_SIZE {
            bufs.push_back(buf);
        }
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
pub trait PacketConn: Send + Sync {
    /// 接收数据包到 buf，返回 (字节数, 源地址)。
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a>>;

    /// 发送数据包到指定地址。
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>>;

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
    #[allow(dead_code)]
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
        let pool = Arc::new(BufPool::default());

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

        let conn_inner = Arc::clone(&inner);
        // spawn recv loop on initial current_conn
        let recv_tx_clone = recv_tx.clone();
        let conn_for_recv = Arc::clone(&current_conn);
        let pool_for_recv = Arc::clone(&pool);
        let recv_handle = tokio::spawn(async move {
            recv_loop(conn_for_recv, recv_tx_clone, pool_for_recv).await;
        });

        // spawn hop loop
        let hop_inner = Arc::clone(&inner);
        let hop_recv_tx = recv_tx.clone();
        let pool_for_hop = Arc::clone(&pool);
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
        Ok((n, addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())))
    }

    /// 发送到当前活跃 addr（对应 Go `WriteTo`）。
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
/// buf 从池 Get，直接 recv 进池 buf（无草稿拷贝），成功后随包 move 出去，
/// 由消费端 read_from 归还池（对齐 Go `pool.Get`/`pool.Put`）。
async fn recv_loop(conn: Arc<dyn PacketConn>, tx: mpsc::Sender<UdpPacket>, pool: Arc<BufPool>) {
    loop {
        let mut buf = pool.get();
        // 先绑定再 match：scrutinee 临时 future 持有 &mut buf，会延长借用跨过 match 臂。
        let res = conn.recv_from(buf.as_mut_slice()).await;
        match res {
            Ok((n, addr)) => {
                // buf 所有权零拷贝移入 packet（Go: readCh <- packet{p: p[:n]}）。
                let pkt = UdpPacket { buf, n, addr: Some(addr), err: None };
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
                    pool.put(buf);
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
        let pooled = conn.pool.bufs.lock().len();
        assert!(pooled >= 1, "pool should hold recycled bufs, got {pooled}");
        // 复用断言：8 包只允许 ≤2 次池外新分配（首包 + 至多一个在途 buf）。
        let allocs = conn.pool.allocs.load(Ordering::Relaxed);
        assert!(allocs <= 2, "8 packets should reuse pooled bufs, allocs={allocs}");

        conn.close().await.ok();
    }

    #[test]
    fn buf_pool_get_put_reuses() {
        let pool = BufPool::default();
        let b = pool.get();
        assert_eq!(b.len(), UDP_BUFFER_SIZE);
        assert_eq!(pool.allocs.load(Ordering::Relaxed), 1);
        pool.put(b);
        let b2 = pool.get();
        assert_eq!(pool.allocs.load(Ordering::Relaxed), 1, "must reuse instead of realloc");
        pool.put(b2);
        assert_eq!(pool.bufs.lock().len(), 1);
    }
}
