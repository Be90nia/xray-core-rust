//! WireGuard UDP driver——协调 UDP 传输 + Tunnel + smoltcp 网络栈。
//!
//! 对应 Go `proxy/wireguard/bind.go` 的 conn.Bind 实现。
//!
//! ## 架构
//!
//! ```text
//! [User TCP/UDP] ←→ [smoltcp Interface] ←IP pkts→ [VirtualDevice]
//!                                                            ↓ (rx→tun, tx←tun)
//!                                                     [WgDriver tasks]
//!                                                            ↓
//!                       [WgTransport: Direct(UdpSocket) | Dialed(system dialer)]
//!                                                            ↔ [Tunnel] ↔ [WG peer]
//! ```
//!
//! task 拓扑（Go netBindClient 形态，bind.go:79-192）：
//! - 读 task：transport 收原始 WG 数据报（reserved 清零）→ readQueue（mpsc）
//! - N 个 worker task：readQueue → Tunnel.decapsulate → netstack.ingest_rx
//!   （N = `num_workers`，<=0 时 CPU 数——Go `Open` 的 N 个 receive func）
//! - 定时器 task：Tunnel.update_timers + netstack.drain_tx → Tunnel.encapsulate
//!   → transport 发送（每 100ms）
//!
//! ## 注意
//!
//! - Tunnel 是同步的（`&mut self`），用 [`parking_lot::Mutex`] 保护
//! - smoltcp Interface 不 Sync，整个 [`WgNetStack`] 也在 Mutex 内
//! - worker 并行消费 readQueue；decapsulate 在 peer tunnel 锁上串行（与 Go
//!   wireguard-go 单 goroutine 解密等价），ingest/poll 可与其它 worker 的
//!   recv 重叠

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use tokio::time::interval;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_xudp::packet::{PacketReader, PacketWriter};

use crate::dispatcher::{apply_reserved, clear_reserved};
use crate::error::{Result, WgError};
use crate::netstack::WgNetStack;
use crate::peer::SharedPeer;
use crate::tunnel::Output;

/// 定时器驱动间隔（boringtun 推荐 ~100ms）。
const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/// UDP socket 接收缓冲。
const UDP_RECV_BUF_SIZE: usize = 65535;

/// 原始 WG 数据报队列容量（Go readQueue 为无缓冲 chan；此处有界背压）。
const READ_QUEUE_CAP: usize = 1024;

/// 原始 WG 数据报（reserved 已清零）+ 来源地址。
type WgDatagram = (Vec<u8>, SocketAddr);

/// Go bind.go:94-100 `Open` 的 worker 数语义：<=0 → CPU 数；仍 <=0 → 1。
fn effective_workers(num_workers: i32) -> usize {
    let workers = if num_workers <= 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    } else {
        num_workers as usize
    };
    if workers == 0 { 1 } else { workers }
}

/// WG UDP 传输——直连 socket 或经 system dialer 的拨号连接。
pub enum WgTransport {
    /// 直连 UDP socket（无代理链；Go `internet.Dial` 无 ProxySettings 时的 raw UDP）。
    Direct(Arc<UdpSocket>),
    /// 经 system dialer 拨出（Go bind.go:118-192 `netBindClient.connectTo`——
    /// WG 自身 UDP 可经 socks 等出站链）。
    Dialed(Arc<DialedUdp>),
}

/// Go `netBindClient`（bind.go:118-192）——WG UDP 经 Xray system dialer 出站。
///
/// `dialer` 返回的 `Connection` 遵循 dispatcher 的 XUDP 帧约定（UDP dispatch
/// 管道），一帧 = 一个 WG 数据报。惰性拨号（首次 send）；读侧死亡或写失败后
/// 下次 send 重拨（Go `Send` 的 `nend.conn == nil → connectTo` 语义）。
pub struct DialedUdp {
    /// system dialer（Go `internet.Dialer`，经出站链拨 UDP dest）。
    dialer: DialFn,
    /// WG peer endpoint（UDP，IP 已解析）。
    dest: Destination,
    /// 当前连接写半边；`None` = 未连接/已死，下次 send 重拨。
    writer: AsyncMutex<Option<tokio::io::WriteHalf<Box<dyn Connection>>>>,
    /// 读 task 入队句柄（[`WgDriver::with_transport`] 注入）。
    queue_tx: Mutex<Option<mpsc::Sender<WgDatagram>>>,
    /// 关停信号（main_loop 注入；`None` 时读 task 不受关停控制）。
    shutdown: Mutex<Option<watch::Receiver<bool>>>,
}

impl DialedUdp {
    /// 构造（拨号发生在首次 send——Go connectTo 惰性语义）。
    pub fn new(dialer: DialFn, dest: Destination) -> Self {
        Self {
            dialer,
            dest,
            writer: AsyncMutex::new(None),
            queue_tx: Mutex::new(None),
            shutdown: Mutex::new(None),
        }
    }

    fn set_queue_tx(&self, tx: mpsc::Sender<WgDatagram>) {
        *self.queue_tx.lock() = Some(tx);
    }

    fn set_shutdown(&self, rx: watch::Receiver<bool>) {
        *self.shutdown.lock() = Some(rx);
    }

    /// 拨号 + spawn 读 task（Go bind.go:126-166 connectTo：dial → 读 goroutine → readQueue）。
    async fn connect(
        self: Arc<Self>,
    ) -> std::result::Result<tokio::io::WriteHalf<Box<dyn Connection>>, String> {
        let conn = (self.dialer)(&self.dest).await?;
        let (read, write) = tokio::io::split(conn);
        let d = Arc::clone(&self);
        tokio::spawn(async move {
            d.read_loop(read).await;
        });
        Ok(write)
    }

    /// 发送一个 WG 数据报（XUDP 帧，target = WG endpoint）。
    pub(crate) async fn send(self: Arc<Self>, wg: &[u8]) -> std::result::Result<(), String> {
        let mut guard = self.writer.lock().await;
        if guard.is_none() {
            *guard = Some(Arc::clone(&self).connect().await?);
        }
        let mut frame = Vec::with_capacity(wg.len() + 64);
        let mut pw = PacketWriter::new(&mut frame, self.dest.clone(), [0u8; 8]);
        pw.write_packet(wg)
            .map_err(|e| format!("wg dialed xudp frame: {e}"))?;
        let res = match guard.as_mut() {
            Some(w) => w.write_all(&frame).await,
            None => unreachable!("connect() filled writer"),
        };
        if res.is_err() {
            *guard = None; // 连接死——下次 send 重拨
        }
        res.map_err(|e| format!("wg dialed conn write: {e}"))
    }

    /// 读循环：XUDP 帧 → readQueue（Go connectTo 的读 goroutine，bind.go:133-163）。
    ///
    /// reserved 清零在入队前（Go bind.go:145-149）。连接 EOF/错误 → 清空 writer
    /// 促使下次 send 重拨。
    async fn read_loop(self: Arc<Self>, mut read: tokio::io::ReadHalf<Box<dyn Connection>>) {
        let Some(tx) = self.queue_tx.lock().clone() else {
            return;
        };
        let mut shut = self.shutdown.lock().clone();
        let src = dest_socket_addr(&self.dest);
        let mut acc = Vec::new();
        let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
        loop {
            let n = tokio::select! {
                _ = wait_shutdown(&mut shut) => break,
                r = read.read(&mut buf) => match r {
                    Ok(n) => n,
                    Err(_) => break,
                },
            };
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n]);
            loop {
                let frame = {
                    let mut cursor = std::io::Cursor::new(&acc[..]);
                    let mut reader = PacketReader::new(&mut cursor);
                    match reader.read_packet() {
                        Ok(Some(pkt)) => Some((cursor.position() as usize, pkt)),
                        Ok(None) => None, // 半帧，等更多字节
                        Err(_) => {
                            acc.clear(); // 坏帧：丢弃重同步
                            None
                        }
                    }
                };
                let Some((consumed, pkt)) = frame else { break };
                let (mut payload, _) = pkt.into_parts();
                clear_reserved(&mut payload);
                if tx.send((payload, src)).await.is_err() {
                    *self.writer.lock().await = None;
                    return;
                }
                acc.drain(..consumed);
            }
        }
        *self.writer.lock().await = None; // 连接死——下次 send 重拨
    }
}

/// `Option<watch::Receiver>` 的关停等待（`None` = 永不关停）。
async fn wait_shutdown(shut: &mut Option<watch::Receiver<bool>>) {
    match shut {
        Some(rx) => {
            let _ = rx.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Destination（IP）→ SocketAddr（Dialed 读路径的伪源地址）。
fn dest_socket_addr(dest: &Destination) -> SocketAddr {
    let ip = match dest.address() {
        Address::IPv4(v4) => std::net::IpAddr::V4(*v4),
        Address::IPv6(v6) => std::net::IpAddr::V6(*v6),
        Address::Domain(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, dest.port().value())
}

/// WireGuard driver——协调 UDP socket + Tunnel + netstack。
///
/// 一个 driver 对应一个 peer + 一个 UdpSocket。
/// 由 [`WireguardOutboundHandler`](crate::outbound::WireguardOutboundHandler) 或
/// [`WireguardInboundHandler`](crate::inbound::WireguardInboundHandler) 创建并 spawn。
pub struct WgDriver {
    /// peer 会话列表（单 peer=client；多 peer=server multi-peer）。
    peers: Vec<SharedPeer>,
    /// UDP 传输——直连 socket 或经 system dialer 拨号（Go conn.Bind）。
    transport: WgTransport,
    /// smoltcp 网络栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// 远端 endpoint（client 模式固定；server 模式从首包学习）。
    remote: Mutex<Option<SocketAddr>>,
    /// server 模式 addr→peer index 路由缓存。
    addr_route: Mutex<HashMap<SocketAddr, usize>>,
    /// 每 peer 的 allowed_ips CIDR（出站 IP 包路由）。
    allowed_cidrs: Vec<Vec<smoltcp::wire::IpCidr>>,
    /// WG 包头 reserved 字段（Go `bind.go netBindClient.reserved`，Warp 用）。
    /// 长度 3 时发送路径写入包头 [1..4]。
    reserved: Mutex<Vec<u8>>,
    /// worker 数（Go `netBind.workers` ← config.proto `num_workers`；
    /// <=0 → CPU 数，见 [`effective_workers`]）。
    num_workers: i32,
    /// 原始 WG 数据报队列（Go `netBind.readQueue`）。
    queue_tx: mpsc::Sender<WgDatagram>,
    queue_rx: AsyncMutex<Option<mpsc::Receiver<WgDatagram>>>,
}

impl WgDriver {
    /// 构造单 peer driver（client/outbound 模式）。
    pub fn new(peer: SharedPeer, sock: Arc<UdpSocket>, netstack: Arc<AsyncMutex<WgNetStack>>) -> Self {
        Self::new_multi(vec![peer], vec![vec![]], sock, netstack)
    }

    /// 构造多 peer driver（server/inbound 模式）。
    ///
    /// # 参数
    ///
    /// - `peers`：所有配置的 peer 会话
    /// - `allowed_cidrs`：每 peer 的 allowed_ips CIDR（与 peers 等长，用于出站路由）
    /// - `sock`：已绑定的 UDP socket
    /// - `netstack`：smoltcp 网络栈
    pub fn new_multi(
        peers: Vec<SharedPeer>,
        allowed_cidrs: Vec<Vec<smoltcp::wire::IpCidr>>,
        sock: Arc<UdpSocket>,
        netstack: Arc<AsyncMutex<WgNetStack>>,
    ) -> Self {
        Self::with_transport(peers, allowed_cidrs, WgTransport::Direct(sock), netstack)
    }

    /// 以指定传输构造 driver（client/outbound + system dialer 注入用）。
    ///
    /// `Dialed` 传输在此时注入 readQueue 发送端——连接本身仍惰性（首次 send）。
    pub fn with_transport(
        peers: Vec<SharedPeer>,
        allowed_cidrs: Vec<Vec<smoltcp::wire::IpCidr>>,
        transport: WgTransport,
        netstack: Arc<AsyncMutex<WgNetStack>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(READ_QUEUE_CAP);
        if let WgTransport::Dialed(d) = &transport {
            d.set_queue_tx(tx.clone());
        }
        Self {
            peers,
            allowed_cidrs,
            transport,
            netstack,
            remote: Mutex::new(None),
            addr_route: Mutex::new(HashMap::new()),
            reserved: Mutex::new(Vec::new()),
            num_workers: 0,
            queue_tx: tx,
            queue_rx: AsyncMutex::new(Some(rx)),
        }
    }

    /// 设置 worker 数（Go `conf.NumWorkers`，bind.go:94-104）。
    #[must_use]
    pub fn with_num_workers(mut self, num_workers: i32) -> Self {
        self.num_workers = num_workers;
        self
    }

    /// 设置 WG 包头 reserved 字段（3 字节，Cloudflare Warp 客户端标记）。
    pub fn set_reserved(&self, reserved: Vec<u8>) {
        *self.reserved.lock() = reserved;
    }

    /// 发送 WG 数据报（reserved 写包头，Go `bind.go:184-190` Send 语义）。
    ///
    /// `Direct`：`send_to(target)`；`Dialed`：XUDP 帧写连接（target 内含于 dest）。
    async fn send_wg(&self, wg: &mut [u8], target: SocketAddr) {
        apply_reserved(wg, &self.reserved.lock().clone());
        match &self.transport {
            WgTransport::Direct(sock) => {
                let _ = sock.send_to(wg, target).await;
            }
            WgTransport::Dialed(d) => {
                if let Err(e) = Arc::clone(d).send(wg).await {
                    tracing::warn!(error = %e, "wg dialed send failed");
                }
            }
        }
    }

    /// 设置远端 endpoint（client 模式启动时）。
    pub fn set_remote(&self, addr: SocketAddr) {
        *self.remote.lock() = Some(addr);
        self.peers[0].set_endpoint(addr);
    }

    /// 尝试解封装入站包，返回 (peer_idx, outputs)。
    ///
    /// 单 peer：直接解封装。
    /// 多 peer：先查 addr_route 缓存，miss 时遍历所有 peer。
    fn decapsulate_incoming(&self, data: &[u8], src: SocketAddr) -> Option<(usize, Vec<Output>)> {
        if self.peers.len() == 1 {
            self.peers[0].set_endpoint(src);
            *self.remote.lock() = Some(src);
            self.peers[0].with_tunnel(|t| t.decapsulate(data)).ok().map(|outs| (0, outs))
        } else {
            // 查缓存
            let cached = self.addr_route.lock().get(&src).copied();
            if let Some(idx) = cached {
                if idx < self.peers.len() {
                    self.peers[idx].set_endpoint(src);
                    if let Ok(outs) = self.peers[idx].with_tunnel(|t| t.decapsulate(data)) {
                        if !outs.is_empty() {
                            return Some((idx, outs));
                        }
                    }
                }
            }
            // 遍历所有 peer（WG MAC 验证确保只有正确 peer 产生输出）
            for (idx, peer) in self.peers.iter().enumerate() {
                peer.set_endpoint(src);
                if let Ok(outs) = peer.with_tunnel(|t| t.decapsulate(data)) {
                    if !outs.is_empty() {
                        self.addr_route.lock().insert(src, idx);
                        return Some((idx, outs));
                    }
                }
            }
            None
        }
    }

    /// 根据出站 IP 包目的地址路由到正确 peer。
    fn route_outgoing(&self, ip_pkt: &[u8]) -> usize {
        if self.peers.len() == 1 {
            return 0;
        }
        let dest = match ip_pkt.first() {
            Some(&b) if b >> 4 == 4 && ip_pkt.len() >= 20 => {
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]))
            }
            Some(&b) if b >> 4 == 6 && ip_pkt.len() >= 40 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&ip_pkt[24..40]);
                smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(
                    u16::from_be_bytes([o[0], o[1]]),
                    u16::from_be_bytes([o[2], o[3]]),
                    u16::from_be_bytes([o[4], o[5]]),
                    u16::from_be_bytes([o[6], o[7]]),
                    u16::from_be_bytes([o[8], o[9]]),
                    u16::from_be_bytes([o[10], o[11]]),
                    u16::from_be_bytes([o[12], o[13]]),
                    u16::from_be_bytes([o[14], o[15]]),
                ))
            }
            _ => return 0,
        };
        for (idx, cidrs) in self.allowed_cidrs.iter().enumerate() {
            for cidr in cidrs {
                if cidr.contains_addr(&dest) {
                    return idx;
                }
            }
        }
        0 // fallback
    }


    /// 启动 driver。返回 JoinHandle——调用方可丢弃以停止。
    ///
    /// 内部由 [`WgDriver::main_loop`] 编排：读 task + N 个 worker task + 定时器循环。
    pub async fn spawn(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        let driver = Arc::clone(&self);
        let handle = tokio::spawn(async move {
            driver.main_loop().await;
        });
        Ok(handle)
    }

    /// 主循环——编排读 task、worker 池与定时器（Go bind.go:79-107 `Open`）。
    ///
    /// - Direct 传输：spawn 单读 task（`recv_from` → readQueue）
    /// - Dialed 传输：读 task 由首次拨号时 spawn（`DialedUdp::connect`）
    /// - N 个 worker 并行消费 readQueue（Go `Open` 返回的 N 个 receive func，
    ///   N = `num_workers`，<=0 → CPU 数）
    /// - 本 task 跑定时器循环：update_timers + keepalive + drain_tx → encapsulate
    ///
    /// main_loop future 被 drop（inbound select! 取消）时经 Drop guard 广播
    /// 关停，读 task 与 worker 退出——不泄漏持有的 `Arc<Self>`。
    pub async fn main_loop(self: Arc<Self>) {
        // 双启动保护：readQueue 消费端只能被取一次。
        let Some(rx) = self.queue_rx.lock().await.take() else {
            tracing::warn!("wg driver main_loop already started");
            return;
        };
        let (shut_tx, shut_rx) = watch::channel(false);
        struct ShutGuard(watch::Sender<bool>);
        impl Drop for ShutGuard {
            fn drop(&mut self) {
                let _ = self.0.send(true);
            }
        }
        let _shut = ShutGuard(shut_tx);
        let multi = self.peers.len() > 1;
        tracing::debug!(
            peer_count = self.peers.len(),
            workers = effective_workers(self.num_workers),
            "wg driver main loop started"
        );

        match &self.transport {
            WgTransport::Direct(sock) => {
                let sock = Arc::clone(sock);
                let tx = self.queue_tx.clone();
                let mut shut = shut_rx.clone();
                tokio::spawn(async move {
                    direct_read_loop(sock, tx, &mut shut).await;
                });
            }
            WgTransport::Dialed(d) => d.set_shutdown(shut_rx.clone()),
        }

        let rx = Arc::new(AsyncMutex::new(rx));
        for _ in 0..effective_workers(self.num_workers) {
            let driver = Arc::clone(&self);
            let rx = Arc::clone(&rx);
            let shut = shut_rx.clone();
            tokio::spawn(async move {
                driver.worker_loop(rx, shut).await;
            });
        }

        let mut timer = interval(TIMER_INTERVAL);
        let mut last_keepalive = std::time::Instant::now();
        let keepalive_interval = self.peers[0].with_tunnel(|t| t.keepalive_interval());

        loop {
            timer.tick().await;
            for peer in &self.peers {
                let timer_outputs = peer.with_tunnel(|t| t.update_timers());
                if let Ok(outs) = timer_outputs {
                    let ep = if multi { peer.endpoint() } else { *self.remote.lock() };
                    if let Some(ep) = ep {
                        for out in outs {
                            if let Output::Network(mut wg) = out {
                                self.send_wg(&mut wg, ep).await;
                            }
                        }
                    }
                }
            }
            if !multi {
                if let Some(interval_secs) = keepalive_interval {
                    if last_keepalive.elapsed().as_secs() >= u64::from(interval_secs) {
                        last_keepalive = std::time::Instant::now();
                        let ka_outputs = self.peers[0].with_tunnel(|t| t.encapsulate(&[]));
                        if let Ok(outs) = ka_outputs {
                            let remote = *self.remote.lock();
                            if let Some(r) = remote {
                                for out in outs {
                                    if let Output::Network(mut wg) = out {
                                        self.send_wg(&mut wg, r).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let tx_pkts: Vec<Vec<u8>> = {
                let mut stack = self.netstack.lock().await;
                stack.poll(smoltcp::time::Instant::now());
                stack.drain_tx()
            };
            if tx_pkts.is_empty() { continue; }
            for pkt in &tx_pkts {
                let peer_idx = self.route_outgoing(pkt);
                let endpoint = if multi { self.peers[peer_idx].endpoint() } else { *self.remote.lock() };
                if endpoint.is_none() { continue; }
                let enc_outputs = self.peers[peer_idx].with_tunnel(|t| t.encapsulate(pkt));
                match enc_outputs {
                    Ok(outs) => {
                        if let Some(ep) = endpoint {
                            for out in outs {
                                if let Output::Network(mut wg) = out {
                                    self.send_wg(&mut wg, ep).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "wg encapsulate failed");
                    }
                }
            }
        }
    }

    /// worker 循环——消费 readQueue → decapsulate → ingest（Go receive func 主体）。
    async fn worker_loop(
        self: Arc<Self>,
        rx: Arc<AsyncMutex<mpsc::Receiver<WgDatagram>>>,
        mut shut: watch::Receiver<bool>,
    ) {
        let multi = self.peers.len() > 1;
        loop {
            let (pkt, src) = {
                let mut guard = rx.lock().await;
                tokio::select! {
                    _ = shut.changed() => return,
                    r = guard.recv() => match r {
                        Some(v) => v,
                        None => return,
                    },
                }
            };
            // reserved 已在读 task 清零（Go bind.go:145-149 位于 connectTo 读循环）
            let Some((peer_idx, outputs)) = self.decapsulate_incoming(&pkt, src) else {
                continue;
            };
            let mut stack = self.netstack.lock().await;
            let peer_endpoint = self.peers[peer_idx].endpoint();
            for out in outputs {
                match out {
                    Output::Ip(ip) => stack.ingest_rx(ip),
                    Output::Network(mut wg) => {
                        let target = if multi { peer_endpoint } else { *self.remote.lock() };
                        if let Some(t) = target {
                            self.send_wg(&mut wg, t).await;
                        }
                    }
                }
            }
            stack.poll(smoltcp::time::Instant::now());
        }
    }
}

/// Direct 读循环：`recv_from` → reserved 清零 → readQueue。
async fn direct_read_loop(
    sock: Arc<UdpSocket>,
    tx: mpsc::Sender<WgDatagram>,
    shut: &mut watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
    loop {
        let r = tokio::select! {
            _ = shut.changed() => return,
            r = sock.recv_from(&mut buf) => r,
        };
        let (n, src) = match r {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "wg udp recv error");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if n == 0 { continue; }
        // Warp 下行可能带非零 reserved——清零后再入队（Go bind.go:145-149）
        let mut pkt = buf[..n].to_vec();
        clear_reserved(&mut pkt);
        if tx.send((pkt, src)).await.is_err() {
            return;
        }
    }
}

/// 绑定 UDP socket（双栈 / v4-only / v6-only）。
///
/// `bind_addr` 形如 `"0.0.0.0:0"`（client 随机端口）或 `"0.0.0.0:51820"`（server 固定端口）。
pub async fn bind_udp_socket(bind_addr: &str) -> Result<Arc<UdpSocket>> {
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| WgError::Io(e))?;
    Ok(Arc::new(sock))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, PeerConfig};
    use crate::peer::shared_peer;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    fn make_keypair(seed: u8) -> (String, String) {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes: [u8; 32] = [seed; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
    }

    fn v4_cidr(o1: u8, o2: u8, o3: u8, o4: u8) -> smoltcp::wire::IpCidr {
        smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(o1, o2, o3, o4)),
            32,
        )
    }

    #[test]
    fn effective_workers_matches_go_open_semantics() {
        // Go bind.go:94-100：<=0 → NumCPU；仍 <=0 → 1；正值原样
        assert_eq!(effective_workers(4), 4);
        assert_eq!(effective_workers(1), 1);
        let default = effective_workers(0);
        assert!(default >= 1, "NumCPU fallback >= 1");
        assert_eq!(effective_workers(-3), default, "负值同默认");
    }

    /// mock system dialer：捕获 dest，返回 duplex Connection（一次性）。
    fn mock_dialer(
        seen: Arc<Mutex<Option<Destination>>>,
    ) -> (DialFn, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let slot: Arc<AsyncMutex<Option<tokio::io::DuplexStream>>> =
            Arc::new(AsyncMutex::new(Some(client)));
        let dialer: DialFn = Arc::new(move |dest: &Destination| {
            *seen.lock() = Some(dest.clone());
            let slot = Arc::clone(&slot);
            Box::pin(async move {
                match slot.lock().await.take() {
                    Some(c) => Ok(Box::new(
                        xray_transport::connection::DuplexConnection::new(c),
                    ) as Box<dyn Connection>),
                    None => Err("unexpected second dial".to_string()),
                }
            })
        });
        (dialer, server)
    }

    #[tokio::test]
    async fn dialed_udp_send_lazy_dials_and_downlink_scrubs_reserved() {
        let seen: Arc<Mutex<Option<Destination>>> = Arc::new(Mutex::new(None));
        let (dialer, mut wire) = mock_dialer(Arc::clone(&seen));
        let dest = Destination::new(
            Address::from_ipv4_bytes([203, 0, 113, 1]),
            Port::new(51820),
            Network::UDP,
        );
        let dialed = Arc::new(DialedUdp::new(dialer, dest.clone()));
        let (tx, mut rx) = mpsc::channel(16);
        dialed.set_queue_tx(tx);

        // 上行：send → 惰性拨号 → XUDP 帧（target=dest）出现在对端
        let wg_pkt = vec![4u8, 0xAA, 0xBB, 0xCC, 0xDD];
        Arc::clone(&dialed).send(&wg_pkt).await.expect("send");
        assert_eq!(seen.lock().as_ref(), Some(&dest), "dialer 以 WG endpoint 调用");

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), wire.read(&mut buf))
            .await
            .expect("wire read timeout")
            .expect("wire read");
        let pkt = PacketReader::new(std::io::Cursor::new(&buf[..n]))
            .read_packet()
            .expect("parse frame")
            .expect("one packet");
        assert_eq!(pkt.data(), &wg_pkt[..], "payload = WG 数据报");
        let target = pkt.udp_target().expect("udp target");
        assert_eq!(target.address(), &Address::from_ipv4_bytes([203, 0, 113, 1]));
        assert_eq!(target.port().value(), 51820);

        // 下行：对端写帧（[1..4] 脏）→ readQueue 收到清零后的 payload
        let down = vec![1u8, 9, 9, 9, 5, 5, 5];
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, dest.clone(), [0u8; 8]);
            pw.write_packet(&down).expect("write frame");
        }
        wire.write_all(&frame).await.expect("wire write");
        let (payload, _src) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("queue timeout")
            .expect("queued datagram");
        assert_eq!(payload, vec![1u8, 0, 0, 0, 5, 5, 5], "reserved 清零（Go bind.go:145-149）");
    }

    /// 双 driver 真握手贯穿 worker 池（num_workers=2 两侧）——证明多 worker
    /// 拓扑下收发/解封装/入栈全链路不回归。
    #[tokio::test]
    async fn driver_pair_handshake_with_multiple_workers() {
        let (sec_c, pub_c) = make_keypair(0x11);
        let (sec_s, pub_s) = make_keypair(0x22);

        let server_sock = bind_udp_socket("127.0.0.1:0").await.expect("server bind");
        let server_addr = server_sock.local_addr().expect("server addr");

        let server_cfg = DeviceConfig {
            secret_key: sec_s,
            endpoint: vec!["10.0.0.1/32".into()],
            ..Default::default()
        };
        let server_peer =
            shared_peer(&server_cfg, &PeerConfig { public_key: pub_c, ..Default::default() }, 0)
                .expect("server peer");
        let server_ns = Arc::new(AsyncMutex::new(WgNetStack::new(&[v4_cidr(10, 0, 0, 1)], 1420)));
        let server = Arc::new(
            WgDriver::new(server_peer, server_sock, server_ns).with_num_workers(2),
        );
        tokio::spawn(Arc::clone(&server).main_loop());

        let client_cfg = DeviceConfig {
            secret_key: sec_c,
            endpoint: vec!["10.0.0.2/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_s,
                endpoint: format!("127.0.0.1:{}", server_addr.port()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client_peer = shared_peer(&client_cfg, &client_cfg.peers[0], 0).expect("client peer");
        let client_sock = bind_udp_socket("127.0.0.1:0").await.expect("client bind");
        let client_ns = Arc::new(AsyncMutex::new(WgNetStack::new(&[v4_cidr(10, 0, 0, 2)], 1420)));
        let client = Arc::new(
            WgDriver::new(client_peer, client_sock, client_ns).with_num_workers(2),
        );
        client.set_remote(server_addr);
        tokio::spawn(Arc::clone(&client).main_loop());

        // 触发握手：client netstack UDP socket 发往 10.0.0.1:53 → tx →
        // timer encapsulate 产生 handshake init（tunnel.rs setup_handshake 模式）
        {
            let mut s = client.netstack.lock().await;
            let h = s.add_udp_socket();
            s.with_udp_socket(h, |sock| {
                crate::dispatcher::bind_ephemeral(sock);
                let _ = sock.send_slice(
                    b"go",
                    smoltcp::wire::IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
                        53,
                    ),
                );
            });
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if client.peers[0].is_online() && server.peers[0].is_online() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "handshake not completed within 10s (client online: {}, server online: {})",
                client.peers[0].is_online(),
                server.peers[0].is_online()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

