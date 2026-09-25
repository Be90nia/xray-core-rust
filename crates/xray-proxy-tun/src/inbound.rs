//! TUN 入站 Handler——接收 TUN 设备 IP 包并注入 smoltcp netstack。
//!
//! 对应 Go `proxy/tun/server.go` 的 `Server.Process`。
//!
//! ## 流程
//!
//! 1. 创建 TUN 设备
//! 2. 从 TUN 设备 recv IP 包 → smoltcp netstack
//! 3. smoltcp 把入站 TCP/UDP 流通过 dispatcher 注入本地
//!
//! ## TCP 连接流（bd ipb5：SYN 惰性注册）
//!
//! smoltcp 无通配端口监听（`listen(0)==Err(Unaddressable)`，对应 Go
//! `tcp.NewForwarder(gstack, 0, 65535)` 的 port0=通配）。改为仿 UDP 路径在 IP 层
//! 识别：收到 TCP SYN 时用 [`parse_tcp_syn_dst`] 解出 dst (addr, port)，
//! `TunNetStack::ensure_tcp_listen` 按 dst 惰性建 listen socket 并缓存（同 dst
//! 复用，accept 后摘除）→ smoltcp 完成 SYN-ACK/握手 → poll 后检查 Established
//! → 通知上层 dispatcher。
//!
//! ## UDP 数据报流
//!
//! 不走 smoltcp UDP socket（见下），由 driver loop 直接解 IP+UDP 头后 dispatch。
//! 对应 Go `proxy/tun/stack_gvisor.go:103` 的 UDP handler。
//!
//! ## TCP dispatch
//!
//! TCP accept 后构造 Link（duplex ↔ smoltcp socket 中继），调
//! `DispatchHandler::dispatch(dest, link)`。中继模式与
//! `xray-proxy-wireguard/src/dispatcher.rs::TcpRelay` 一致。
//!
//! ## UDP dispatch（bd 9wc，当前切片）
//!
//! smoltcp 0.12 的 `udp::Socket::bind` 禁止 port 0 且 `accepts` 严格匹配
//! `endpoint.port == dst_port`（`smoltcp/socket/udp.rs:222`、`iface/interface/udp.rs:481`），
//! 无法"接收任意端口的 UDP"。TUN 必须截获所有 UDP 流量，绕过 smoltcp UDP socket：
//!
//! 1. 从 TUN recv IP 包后，先用 [`parse_udp_packet`] 解 IP+UDP 头，提取 (src, dst)。 是 UDP 包 →
//!    走本路径；否则继续交给 smoltcp（TCP/ICMP）。
//! 2. 按 `event.src`（IP+UDP 头的源端）作 full-cone NAT key，懒建 [`UdpDispatchSession`]，首包确定
//!    routing。
//! 3. session.send_packet(&dest, payload) 把数据转发到 dispatcher （`dest = event.dst`，即 IP+UDP
//!    头中的真实目标地址）。
//! 4. session reader task 持续 recv 响应，用 [`build_udp_response`] 装回 IP+UDP 包（src/dst
//!    交换），写回 TUN。
//!
//! # ponytail: 一个 remote src 一个 session
//!
//! 对应 Go `proxy/tun/udp_fullcone.go` 的 `udpConns map[net.Destination]*udpConn`：
//! 按 source 分桶天然 cone NAT。session 生命周期由 inbound handler 持有
//! （`Arc<Mutex<HashMap>>`），后续切片可加 idle 淘汰（Go `CancelAfterInactivity(1min)`）。
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex as ParkMutex;
use smoltcp::{iface::SocketHandle, wire::IpEndpoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, mpsc},
    task::JoinHandle,
    time::interval,
};
use xray_app_dispatcher::{DispatchHandler, UdpDispatchSession};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::{
    config::{StackOptions, Tun},
    device::TunDevice,
    error::Result,
    netstack::{
        TcpAcceptEvent, TunNetStack, UdpPacketMeta, build_udp_response, parse_tcp_syn_dst,
        parse_udp_packet,
    },
};

/// TUN 设备接收缓冲。
const TUN_RECV_BUF_SIZE: usize = 65535;

/// smoltcp poll 定时器间隔。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// duplex 缓冲大小。
const DUPLEX_BUF: usize = 64 * 1024;

/// 中继轮询间隔（ms）。
const RELAY_POLL_MS: u64 = 5;

/// TUN 入站 Handler。
///
/// 持有 TUN 设备 + smoltcp 网栈 + 驱动任务句柄。
pub struct TunInboundHandler {
    tag: String,
    started: AtomicBool,
    /// TUN 设备句柄——start() 后填充。
    device: ParkMutex<Option<Arc<TunDevice>>>,
    /// join handle——close() 用以终止 task。
    join: ParkMutex<Option<JoinHandle<()>>>,
    /// smoltcp 网栈句柄（与 driver task 共享）。
    netstack: Arc<AsyncMutex<TunNetStack>>,
    /// 配置参数（用于构造 TUN 设备和网栈）。
    options: StackOptions,
    /// dispatcher handler（TCP accept 后桥接到 outbound）。
    dispatch: Arc<dyn DispatchHandler>,
}

impl TunInboundHandler {
    /// 从 StackOptions 构造入站 Handler。
    ///
    /// 不在此创建设备——构造仅做参数校验。`start()` 时启动。
    ///
    /// # 参数
    ///
    /// - `tag`：handler 唯一标识
    /// - `options`：StackOptions（含 tun 设备配置）
    pub async fn new(
        tag: impl Into<String>,
        options: StackOptions,
        dispatch: Arc<dyn DispatchHandler>,
    ) -> Result<Self> {
        let tag = tag.into();

        // 校验：必须有 tun 设备配置
        let _ = options.tun.as_ref().ok_or_else(|| {
            crate::error::TunError::InvalidConfig("tun inbound requires a tun device".into())
        })?;

        // smoltcp 网栈（先不创建——start 时根据实际设备地址初始化）
        // 这里用占位地址，start 时重新创建
        let local = smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(0, 0, 0, 0)),
            0,
        );
        let netstack = Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));

        Ok(Self {
            tag,
            started: AtomicBool::new(false),
            device: ParkMutex::new(None),
            join: ParkMutex::new(None),
            netstack,
            options,
            dispatch,
        })
    }

    /// 共享 smoltcp 网栈句柄（dispatcher 桥接用）。
    #[must_use]
    pub fn netstack(&self) -> &Arc<AsyncMutex<TunNetStack>> {
        &self.netstack
    }
}

#[async_trait]
impl InboundHandler for TunInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 启动 TUN 设备 + 驱动 task。
    async fn start(&self) -> std::result::Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }

        // 取出 tun 配置（校验存在；设备参数从 options 读——对应 Go NewTun(options)）
        let cfg = &self.options;
        let _ = cfg
            .tun
            .as_ref()
            .ok_or_else(|| InboundError::ListenError("tun device config missing".into()))?;

        // 创建 TUN 设备（JSON name/mtu/gateway；缺省由 parse_json 归一化）
        let (v4_addr, v4_prefix) = cfg.device_ipv4();
        let device = Arc::new(
            TunDevice::create(&cfg.name, &v4_addr.to_string(), v4_prefix, cfg.mtu as u16)
                .map_err(|e| InboundError::ListenError(format!("tun device create: {e}")))?,
        );

        // 启动设备
        device.start().map_err(|e| InboundError::ListenError(format!("tun device start: {e}")))?;

        // 用配置地址重建 netstack（gateway 全部 CIDR；空则设备默认 v4）
        {
            let locals = cfg.local_cidrs();
            let mut stack = self.netstack.lock().await;
            *stack = TunNetStack::new(&locals, cfg.mtu as usize);
        }

        *self.device.lock() = Some(Arc::clone(&device));

        // spawn driver task
        let netstack = Arc::clone(&self.netstack);
        let dev = Arc::clone(&device);
        let dispatch = Arc::clone(&self.dispatch);
        let handle = tokio::spawn(async move {
            tun_driver_loop(dev, netstack, dispatch).await;
        });

        *self.join.lock() = Some(handle);
        tracing::info!(tag = %self.tag, "tun inbound started");
        Ok(())
    }

    /// 关闭 TUN 设备 + 停止驱动 task。
    async fn close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        if let Some(handle) = self.join.lock().take() {
            handle.abort();
        }
        if let Some(dev) = self.device.lock().take() {
            let _ = dev.close();
        }
        tracing::info!(tag = %self.tag, "tun inbound closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        0
    }
}

/// per-source UDP session 存储（full-cone NAT，key = IP+UDP 源端点）。
///
/// 对应 Go `proxy/tun/udp_fullcone.go:31` 的 `udpConns map[net.Destination]*udpConn`：
/// 按 source 分桶实现 cone NAT，每个 remote src 一个 dispatch link。
/// UDP session 空闲清理超时（对应 Go `signal.CancelAfterInactivity(1min)`）。
/// 1 分钟未活动即从 map 中淘汰并关闭 dispatch session。
const UDP_SESSION_IDLE_SECS: u64 = 60;
/// 空闲清理扫描间隔（30s）——避开 1 分钟阈值，每两扫一次仍可容忍 ~90s。
const UDP_SESSION_SWEEP_SECS: u64 = 30;

/// per-source UDP session 存储（full-cone NAT，key = IP+UDP 源端点）。
///
/// 对应 Go `proxy/tun/udp_fullcone.go:31` 的 `udpConns map[net.Destination]*udpConn`：
/// 按 source 分桶实现 cone NAT，每个 remote src 一个 dispatch link。
type UdpSessions = Arc<ParkMutex<HashMap<IpEndpoint, Arc<UdpSessionEntry>>>>;
/// 单个 remote src 的 UDP 会话句柄（票 8gr6）。
///
/// 对应 Go `proxy/tun/udp_fullcone.go` 的 `*udpConn`：每条会话一个 owner task
/// 独占 [`UdpDispatchSession`]（收发无互斥——reader 不再持锁跨 recv），map 里
/// 只留非阻塞入队句柄。sweep 淘汰 = 从 map 移除 entry → cmd_tx 随 Arc 释放
/// 而 drop → owner task 收到 channel 关闭自动退出 → session drop → dispatch
/// duplex EOF，outbound 侧随之回收（Go `CancelAfterInactivity` 语义）。
///
/// p14e：`last_used_nanos` 由 handle_udp_packet 每次命中更新；sweep 任务每
/// 30s 检查一次，超过 60s 未活动则淘汰。
struct UdpSessionEntry {
    /// 客户端包入队口（非阻塞；owner task 顺序消费转发 outbound）。
    cmd_tx: mpsc::UnboundedSender<SessionCmd>,
    /// 最近一次命中的 wall-clock 纳秒（std::time::SystemTime 测得）。
    /// sweep 任务对比 `now - last_used > 60s` 决定淘汰。
    last_used_nanos: AtomicI64,
}

/// owner task 的输入命令。
enum SessionCmd {
    /// 转发一个客户端数据报到 outbound。
    Send { dest: Destination, payload: Bytes },
}

async fn tun_driver_loop(
    device: Arc<TunDevice>,
    netstack: Arc<AsyncMutex<TunNetStack>>,
    dispatch: Arc<dyn DispatchHandler>,
) {
    let mut timer = interval(POLL_INTERVAL);
    // 读侧批量缓冲（票 ukh8）：Linux 一次 syscall 出一批，其他平台单包。
    let mut rx = RxPackets::new(&device);

    // UDP 走 IP+UDP 头解析路径；TCP 走 SYN 惰性注册路径（票 ipb5，见主循环），
    // 均不预先创建 smoltcp socket。
    let udp_sessions: UdpSessions = Arc::new(ParkMutex::new(HashMap::new()));
    let _udp_sweeper = spawn_udp_session_sweeper(Arc::clone(&udp_sessions));

    tracing::debug!("tun driver main loop started");

    loop {
        tokio::select! {
            // 从 TUN 设备读取 IP 包（Linux：一次 syscall 读一批 GRO 拆分段）
            result = rx.recv(&device) => {
                match result {
                    Ok(count) => {
                        // 票 fnlv：UDP 无锁预分流（bypass 语义不变），TCP 包收切片
                        // 进单次临界区——批量读的 syscall 摊销不再被逐包锁拆碎。
                        // 票 6dfy：owned 物化（alloc+memcpy）在临界区外完成，
                        // 锁内 ingest 只做 move——smoltcp ingest_rx 要求 owned
                        // Vec，借用视图无法进 rx queue。
                        let mut tcp_pkts: Vec<Vec<u8>> = Vec::new();
                        for i in 0..count {
                            let pkt = rx.packet(i);
                            // 先尝试按 UDP 解析：能解出 4 元组就 bypass smoltcp，
                            // 避免 smoltcp 对未 bind 端口发 ICMP port unreachable。
                            // ponytail: 直接判字节，省一次 smoltcp poll 锁。
                            if let Some((meta, payload)) = parse_udp_packet(pkt) {
                                handle_udp_packet(
                                    &udp_sessions,
                                    meta,
                                    payload,
                                    Arc::clone(&dispatch),
                                    Arc::clone(&device),
                                );
                            } else {
                                tcp_pkts.push(pkt.to_vec());
                            }
                        }

                        // 唯一临界区：整批 TCP ingest + 批尾一次 poll/accept/drain。
                        // drive_stack_batch 是同步 fn——锁内无 await 由编译器保证。
                        let (accepted, tx_pkts) = {
                            let mut stack = netstack.lock().await;
                            drive_stack_batch(&mut stack, tcp_pkts)
                        };

                        // 锁外：accept 建桥（tokio::spawn 不再发生在临界区内）+
                        // 批聚合单次写回 TUN。
                        dispatch_accepted(&netstack, accepted, &dispatch).await;
                        write_tx_back(&device, tx_pkts).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "tun recv error");
                        // ponytail: 不退出循环——设备可能临时错误
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            // 每 100ms 触发：poll + drain_tx（票 fnlv：spawn 移出临界区）
            _ = timer.tick() => {
                let (accepted, tx_pkts) = {
                    let mut stack = netstack.lock().await;
                    stack.poll(smoltcp::time::Instant::now());
                    // 处理 ICMP echo request 并自动回复
                    stack.process_icmp_echo();
                    // 只收集 accept 事件，建桥 spawn 在锁外进行
                    (stack.check_tcp_accepts(), stack.drain_tx())
                };
                dispatch_accepted(&netstack, accepted, &dispatch).await;
                write_tx_back(&device, tx_pkts).await;
            }
        }
    }
}

/// TUN 读侧缓冲与批量读取（票 ukh8 平台收敛点）。
///
/// Linux：设备以 offload/vnet_hdr 创建——一次 syscall 读出内核 GRO 聚合
/// 大包并拆成 ≤MTU 的段（64KiB 聚合 ≈ 44 个 1500MTU 包，缓冲按
/// IDEAL_BATCH_SIZE 预留）；vnet_hdr 协商失败时 tun-rs 内部退化为单包读。
/// 其他平台：单包 recv，行为与改动前一致。
struct RxPackets {
    #[cfg(target_os = "linux")]
    original: Box<[u8]>,
    #[cfg(target_os = "linux")]
    bufs: Vec<Vec<u8>>,
    #[cfg(target_os = "linux")]
    sizes: Vec<usize>,
    #[cfg(not(target_os = "linux"))]
    buf: Vec<u8>,
    #[cfg(not(target_os = "linux"))]
    len: usize,
}

impl RxPackets {
    fn new(device: &TunDevice) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                original: vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 65535].into_boxed_slice(),
                bufs: vec![vec![0u8; device.mtu() as usize]; tun_rs::IDEAL_BATCH_SIZE],
                sizes: vec![0; tun_rs::IDEAL_BATCH_SIZE],
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = device;
            Self { buf: vec![0u8; TUN_RECV_BUF_SIZE], len: 0 }
        }
    }

    /// 读一批包，返回包数（非 Linux 恒 0 或 1）。
    async fn recv(&mut self, device: &TunDevice) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            device.recv_batch(&mut self.original, &mut self.bufs, &mut self.sizes).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let n = device.recv(&mut self.buf).await?;
            self.len = n;
            Ok(usize::from(n != 0))
        }
    }

    /// 第 i 个包（i < 上次 recv 返回值）。
    fn packet(&self, i: usize) -> &[u8] {
        #[cfg(target_os = "linux")]
        {
            &self.bufs[i][..self.sizes[i]]
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = i;
            &self.buf[..self.len]
        }
    }
}

/// tx 队列写回 TUN（票 ukh8 平台收敛点）：Linux 走 GRO 批量写（同流
/// TCP/UDP 小包合并后减少 write syscall 次数），其他平台逐包写。
/// 回写失败静默忽略——与改动前行为一致（TCP 由内核重传兜底）。
async fn write_tx_back(device: &TunDevice, tx_pkts: Vec<Vec<u8>>) {
    #[cfg(target_os = "linux")]
    {
        let _ = device.send_batch(tx_pkts).await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        for pkt in tx_pkts {
            let _ = device.send(&pkt).await;
        }
    }
}

/// 单 UDP 数据报 → dispatch（full-cone NAT）。
///
/// 对应 Go `udp_fullcone.go:HandlePacket`：按 src 懒建 `udpConn`，首次
/// 确定 routing，后续包复用同一 session。响应回写由 owner task 持续
/// recv 完成（票 8gr6：channel 化，收发无互斥）。
fn handle_udp_packet(
    sessions: &UdpSessions,
    meta: UdpPacketMeta,
    payload: &[u8],
    dispatch: Arc<dyn DispatchHandler>,
    device: Arc<TunDevice>,
) {
    // 懒建 session：按 src 找；不在则建（含 owner task 一次性 spawn）。
    // p14e：last_used_nanos 初始化为当前 wall-clock，避免刚建的 session
    // 被下一次 sweep 误判为已空闲 60s。
    let entry = {
        let mut map = sessions.lock();
        map.entry(meta.src)
            .or_insert_with(|| {
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
                spawn_udp_session_task(
                    Arc::clone(&dispatch),
                    cmd_rx,
                    Arc::clone(&device),
                    meta.src,
                    meta.dst,
                );
                Arc::new(UdpSessionEntry { cmd_tx, last_used_nanos: AtomicI64::new(now_nanos()) })
            })
            .clone()
    };
    // 每次命中刷新最后活跃时间，sweep 据此淘汰。
    entry.last_used_nanos.store(now_nanos(), Ordering::Relaxed);

    // 非阻塞入队（票 8gr6）：对端不应答使 recv 挂死时，后续包照常入队送达，
    // 不再与 reader 争锁排队。首包由 owner task 懒建 dispatch link。
    let Some(dest) = ip_endpoint_to_udp_destination(&meta.dst) else {
        tracing::warn!(src = %meta.src, dst = %meta.dst, "udp: invalid destination, dropping");
        return;
    };
    let _ = entry.cmd_tx.send(SessionCmd::Send { dest, payload: Bytes::copy_from_slice(payload) });
}

/// 当前 wall-clock 纳秒（SystemTime → UNIX_EPOCH 偏移）。用作 session
/// 最后活跃时间戳（p14e）。
fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// p14e：周期性扫描 idle 60s+ 的 UDP session 并从 map 淘汰（票 8gr6 重构：
/// 无 try_lock 探测——owner task 独占 session，map 移除即可回收）。
/// 后台 spawn，无关主 driver loop。
fn spawn_udp_session_sweeper(sessions: UdpSessions) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(UDP_SESSION_SWEEP_SECS));
        // 跳过首 tick（首次运行时所有 entry 都很新）
        tick.tick().await;
        loop {
            tick.tick().await;
            sweep_udp_sessions(&sessions);
        }
    })
}

/// 单轮 idle 淘汰（票 8gr6）：owner task 独占 session，sweep 只需从 map 移除
/// entry；cmd_tx 随 Arc 释放而 drop，owner task 收到 channel 关闭退出，
/// session drop 触发 dispatch duplex EOF。
fn sweep_udp_sessions(sessions: &UdpSessions) {
    let now = now_nanos();
    let idle_nanos = (UDP_SESSION_IDLE_SECS as i64) * 1_000_000_000;
    let mut removed = 0usize;
    {
        let mut map = sessions.lock();
        let expired: Vec<IpEndpoint> = map
            .iter()
            .filter(|(_, v)| {
                now.saturating_sub(v.last_used_nanos.load(Ordering::Relaxed)) > idle_nanos
            })
            .map(|(k, _)| *k)
            .collect();
        for k in &expired {
            if map.remove(k).is_some() {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        tracing::debug!(count = removed, "tun udp sessions swept");
    }
}

/// 把 IP 协议族的 smoltcp IpEndpoint 转 xray Destination（UDP）。
fn ip_endpoint_to_udp_destination(ep: &IpEndpoint) -> Option<Destination> {
    let address = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::IPv4(std::net::Ipv4Addr::from(v4.octets())),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::IPv6(std::net::Ipv6Addr::from(v6.octets())),
    };
    Some(Destination::new(address, Port::new(ep.port), Network::UDP))
}
/// xray Address → smoltcp IpAddress（域名返回 None；build_udp_response 需要 IP）。
#[allow(clippy::incompatible_msrv)] // smoltcp 唯一公开构造 from_octets（1.91 stable，晚于 workspace MSRV 声明）
fn address_to_smoltcp(addr: &Address) -> Option<smoltcp::wire::IpAddress> {
    match addr {
        Address::IPv4(v4) => Some(smoltcp::wire::IpAddress::Ipv4(
            smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
        )),
        Address::IPv6(v6) => Some(smoltcp::wire::IpAddress::Ipv6(
            smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
        )),
        Address::Domain(_) => None,
    }
}

/// 每 remote src 一个 owner task（票 8gr6，对齐 Go `udp_fullcone.go` 每 conn
/// 独立 goroutine）。
///
/// task 独占 [`UdpDispatchSession`]，回包装帧后经 channel 交由写回 task 发往
/// TUN；写回端退出（device 失败）时 abort 会话 task，session drop 关闭 duplex。
fn spawn_udp_session_task(
    dispatch: Arc<dyn DispatchHandler>,
    cmd_rx: mpsc::UnboundedReceiver<SessionCmd>,
    device: Arc<TunDevice>,
    original_src: IpEndpoint,
    original_dst: IpEndpoint,
) {
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    let session =
        tokio::spawn(run_udp_session(dispatch, cmd_rx, reply_tx, original_src, original_dst));
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            if let Err(e) = device.send(&reply).await {
                tracing::warn!(error = %e, "udp: write reply to tun failed");
                break;
            }
        }
        // 写回端退出（device 失败或会话结束）——终止会话 task
        session.abort();
    });
}

/// UDP 会话主循环（票 8gr6）：channel 驱动 send、`select!` 驱动 recv，
/// 收发无互斥——对端不应答使 recv 挂起时 send 分支照常就绪。
///
/// `cmd_rx` 关闭（sweep 淘汰 / map 侧 drop）→ 返回；`recv_packet()` 返回
/// `Ok(None)`（outbound 关闭）或 Err → 返回。session drop → duplex 关闭。
async fn run_udp_session(
    dispatch: Arc<dyn DispatchHandler>,
    mut cmd_rx: mpsc::UnboundedReceiver<SessionCmd>,
    reply_tx: mpsc::UnboundedSender<Vec<u8>>,
    original_src: IpEndpoint,
    original_dst: IpEndpoint,
) {
    let mut session = UdpDispatchSession::new(dispatch);
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(SessionCmd::Send { dest, payload }) => {
                    if let Err(e) = session.send_packet(&dest, &payload).await {
                        tracing::warn!(error = %e, src = %original_src, dst = %original_dst, "udp: session.send_packet failed");
                        return;
                    }
                }
                None => {
                    tracing::debug!(src = %original_src, dst = %original_dst, "udp: session swept");
                    return;
                }
            },
            resp = session.recv_packet() => match resp {
                Ok(Some((resp_src, payload))) => {
                    // resp_src 是 outbound 视角的来源（= 原 dst），构造 IP+UDP 回包
                    let resp_ip = address_to_smoltcp(resp_src.address());
                    let Some(resp_ip) = resp_ip else {
                        tracing::warn!("udp: response destination is domain, cannot build IP packet");
                        continue;
                    };
                    let reply = build_udp_response(
                        resp_ip,
                        resp_src.port().value(),
                        original_src.addr,
                        original_src.port,
                        &payload,
                    );
                    if reply_tx.send(reply).is_err() {
                        return; // 写回端已退出（device 失败）
                    }
                }
                Ok(None) => {
                    tracing::debug!(src = %original_src, dst = %original_dst, "udp: session closed");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, src = %original_src, dst = %original_dst, "udp: session.recv_packet failed");
                    return;
                }
            },
        }
    }
}

/// 票 fnlv：整批 TCP 包的单次栈驱动临界区（同步 fn——锁内无 await 由
/// 编译器保证）。顺序：逐包 ensure_listen（票 ipb5，必须先于 ingest）+ ingest，
/// 批尾统一 poll + ICMP + accept 收集 + drain——批量读 syscall 的摊销不再被
/// 逐包 poll/drain 拆碎，netstack 锁获取次数从每包 1 次降为每批 1 次。
/// smoltcp `poll` 内部循环消化 rx_queue 全部 pending 段（POLL_RX_BUDGET），
/// 一次批尾 poll 与逐包 poll 的状态机结果等价。
/// 返回 (accept 事件, TX 批)——建桥 spawn 与写回 TUN 都在锁外进行。
/// 消费 owned 批（票 6dfy）：alloc+copy 已由调用方在临界区外完成，
/// 锁内 ingest 逐包 move 进 smoltcp rx queue。
fn drive_stack_batch(
    stack: &mut TunNetStack,
    pkts: Vec<Vec<u8>>,
) -> (Vec<TcpAcceptEvent>, Vec<Vec<u8>>) {
    for pkt in pkts {
        // TCP SYN → 惰性注册 listen socket（票 ipb5）。必须发生在
        // ingest 之前，poll 才能为该 SYN 生成 SYN-ACK。
        // 注册失败（port=0 等，几乎不可能）→ 丢弃该 SYN，连接建不起来，
        // 不静默吞掉：error 日志可见。
        if let Some(dst) = parse_tcp_syn_dst(&pkt) {
            if let Err(e) = stack.ensure_tcp_listen(dst) {
                tracing::error!(error = %e, dst = ?dst, "tcp lazy listen failed, dropping SYN");
            }
        }
        stack.ingest_rx(pkt);
    }
    stack.poll(smoltcp::time::Instant::now());
    // 处理 ICMP echo request 并自动回复
    stack.process_icmp_echo();
    // 只收集 accept 事件（状态机转移在锁内完成）；建桥 spawn 锁外
    (stack.check_tcp_accepts(), stack.drain_tx())
}

/// 票 fnlv：锁外消费 accept 事件——每个新连接建桥 dispatch。
/// `tokio::spawn` 不再发生在 netstack 临界区内。
async fn dispatch_accepted(
    netstack: &Arc<AsyncMutex<TunNetStack>>,
    events: Vec<TcpAcceptEvent>,
    dispatch: &Arc<dyn DispatchHandler>,
) {
    for event in events {
        accept_tcp_connection(netstack, event, dispatch).await;
    }
}

/// 单个已 accept 的 TCP 连接 → 建桥 dispatch（票 ipb5，原 handle_socket_events 主体）。
/// 锁外调用：dest 解析失败的罕见分支重取锁摘除 socket，不持有调用方临界区。
async fn accept_tcp_connection(
    netstack: &Arc<AsyncMutex<TunNetStack>>,
    event: TcpAcceptEvent,
    dispatch: &Arc<dyn DispatchHandler>,
) {
    // 从 local endpoint 构建 destination
    let dest = match ip_endpoint_to_destination(&event.local) {
        Some(d) => d,
        None => {
            tracing::warn!(
                remote = %event.remote,
                "tcp accept: no local endpoint, dropping connection"
            );
            netstack.lock().await.remove_socket(event.handle);
            return;
        },
    };

    // 创建两路 duplex 桥接 smoltcp socket ↔ Link
    // ponytail: 双 duplex（up/down 独立），与 wireguard TcpRelay 一致
    let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
    let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
    let link = Link::new(new_reader(client_from_relay), new_writer(client_to_relay));

    tracing::debug!(
        handle = ?event.handle,
        remote = %event.remote,
        dest = ?dest,
        "tcp connection accepted → dispatch"
    );

    // spawn 中继 task（smoltcp socket ↔ duplex）
    let relay = TunTcpRelay {
        from_client: relay_from_client,
        to_client: relay_to_client,
        netstack: Arc::clone(netstack),
        handle: event.handle,
    };
    tokio::spawn(relay.run());

    // spawn dispatch（link → outbound）
    let dispatch = Arc::clone(dispatch);
    tokio::spawn(async move {
        dispatch.dispatch(&dest, link).await;
    });
}

/// smoltcp IpEndpoint → Destination（TCP）。
fn ip_endpoint_to_destination(local: &Option<IpEndpoint>) -> Option<Destination> {
    let ep = local.as_ref()?;
    let address = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::IPv4(std::net::Ipv4Addr::from(v4.octets())),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::IPv6(std::net::Ipv6Addr::from(v6.octets())),
    };
    Some(Destination::new(address, Port::new(ep.port), Network::TCP))
}

/// smoltcp TCP socket ↔ tokio duplex 中继 task（inbound 方向）。
///
/// 持有 duplex 的"远端" + netstack + socket handle，桥接 TUN 侧的 smoltcp
/// TCP socket 与 dispatcher Link 的读写端。
///
/// # ponytail: 与 xray-proxy-wireguard/src/dispatcher.rs::TcpRelay 结构相同，
/// 仅 netstack 类型不同（TunNetStack vs WgNetStack）。第三个消费者出现时提取 trait。
struct TunTcpRelay {
    /// 从 Link 写入端读取用户数据（up 方向）。
    from_client: tokio::io::DuplexStream,
    /// 向 Link 读取端写入 smoltcp 数据（down 方向）。
    to_client: tokio::io::DuplexStream,
    /// smoltcp 网栈。
    netstack: Arc<AsyncMutex<TunNetStack>>,
    /// 已 accept 的 smoltcp TCP socket handle。
    handle: SocketHandle,
}

impl TunTcpRelay {
    /// 运行中继循环直到 socket 关闭或出错。
    async fn run(mut self) {
        let mut timer = tokio::time::interval(Duration::from_millis(RELAY_POLL_MS));
        timer.tick().await; // 消掉首次立即触发

        loop {
            let mut user_buf = vec![0u8; 8192];
            tokio::select! {
                // down: dispatcher 写 link.writer 的响应数据 → smoltcp socket send → TUN client
                result = self.from_client.read(&mut user_buf) => {
                    match result {
                        Ok(0) | Err(_) => {
                            self.finish().await;
                            return;
                        }
                        Ok(n) => {
                            user_buf.truncate(n);
                            self.send_to_smoltcp(&user_buf).await;
                        }
                    }
                }
                _ = timer.tick() => {}
            }
            // up: smoltcp socket recv（TUN client 请求）→ link.reader 供 dispatcher 读取
            if self.recv_from_smoltcp().await {
                let _ = self.to_client.shutdown().await;
                self.finish().await;
                return;
            }
        }
    }

    /// 发送用户数据到 smoltcp TCP socket。
    async fn send_to_smoltcp(&self, data: &[u8]) {
        let mut stack = self.netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());
        stack.with_tcp_socket(self.handle, |s| {
            if s.may_send() {
                let _ = s.send_slice(data);
            }
        });
        stack.poll(smoltcp::time::Instant::now());
    }

    /// 从 smoltcp TCP socket 接收数据写入 to_client。返回 true 表示 socket 已关闭。
    async fn recv_from_smoltcp(&mut self) -> bool {
        let (data, closed) = {
            let mut stack = self.netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let r = stack.with_tcp_socket(self.handle, |s| {
                let mut buf = vec![0u8; 8192];
                let n = s.recv_slice(&mut buf).unwrap_or(0);
                buf.truncate(n);
                (buf, !s.is_active())
            });
            stack.poll(smoltcp::time::Instant::now());
            r
        };
        if !data.is_empty() {
            let _ = self.to_client.write_all(&data).await;
        }
        closed
    }

    /// 关闭 smoltcp socket 并从 SocketSet 移除（FIN 由 driver loop drain_tx 发出）。
    async fn finish(&self) {
        let mut stack = self.netstack.lock().await;
        stack.with_tcp_socket(self.handle, |s| s.close());
        stack.poll(smoltcp::time::Instant::now());
        stack.remove_socket(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::atomic::AtomicU32};

    use super::*;

    struct DummyTun;
    impl crate::config::Tun for DummyTun {
        fn start(&self) -> std::result::Result<(), crate::error::TunError> {
            Ok(())
        }

        fn close(&self) -> std::result::Result<(), crate::error::TunError> {
            Ok(())
        }

        fn name(&self) -> std::result::Result<String, crate::error::TunError> {
            Ok("dummy0".into())
        }

        fn index(&self) -> std::result::Result<i32, crate::error::TunError> {
            Ok(0)
        }
    }

    fn make_options() -> StackOptions {
        StackOptions { tun: Some(Box::new(DummyTun)), ..Default::default() }
    }

    /// 测试用 DispatchHandler——记录 dispatch 调用次数。
    #[derive(Debug)]
    struct CountingDispatch {
        tag: String,
        calls: Arc<AtomicU32>,
    }

    impl CountingDispatch {
        fn new(tag: &str) -> (Self, Arc<AtomicU32>) {
            let calls = Arc::new(AtomicU32::new(0));
            (Self { tag: tag.into(), calls: Arc::clone(&calls) }, calls)
        }
    }

    impl DispatchHandler for CountingDispatch {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            _link: Link,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    fn make_dispatch() -> (Arc<CountingDispatch>, Arc<AtomicU32>) {
        let (d, calls) = CountingDispatch::new("test-out");
        (Arc::new(d), calls)
    }

    #[tokio::test]
    async fn construct_inbound_handler() {
        let opts = make_options();
        let (dispatch, _) = make_dispatch();
        let h = TunInboundHandler::new("test", opts, dispatch).await;
        assert!(h.is_ok(), "construct failed: {:?}", h.err());
    }

    #[tokio::test]
    async fn construct_rejects_no_tun() {
        let opts = StackOptions::default();
        let (dispatch, _) = make_dispatch();
        let result = TunInboundHandler::new("test", opts, dispatch).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tag_and_port() {
        let opts = make_options();
        let (dispatch, _) = make_dispatch();
        let h = TunInboundHandler::new("test", opts, dispatch).await.expect("construct");
        assert_eq!(h.tag(), "test");
        assert_eq!(h.port(), 0);
    }

    #[test]
    fn ip_endpoint_to_destination_ipv4() {
        let ep = smoltcp::wire::IpEndpoint {
            addr: smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
            port: 443,
        };
        let dest = ip_endpoint_to_destination(&Some(ep)).expect("some dest");
        assert_eq!(dest.address(), &Address::IPv4("10.0.0.1".parse().unwrap()));
        assert_eq!(dest.port().value(), 443);
        assert_eq!(dest.network(), Network::TCP);
    }

    #[test]
    fn ip_endpoint_to_destination_ipv6() {
        let ep = smoltcp::wire::IpEndpoint {
            addr: smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(
                0, 0, 0, 0, 0, 0, 0, 1,
            )),
            port: 8080,
        };
        let dest = ip_endpoint_to_destination(&Some(ep)).expect("some dest");
        assert_eq!(dest.network(), Network::TCP);
        assert_eq!(dest.port().value(), 8080);
    }

    #[test]
    fn ip_endpoint_to_destination_none() {
        assert!(ip_endpoint_to_destination(&None).is_none());
    }

    #[test]
    fn ip_endpoint_to_udp_destination_ipv4() {
        // UDP destination 从 IP+UDP 头的 dst 端提取（不是 socket local endpoint）
        let ep = smoltcp::wire::IpEndpoint {
            addr: smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 8, 8)),
            port: 53,
        };
        let dest = ip_endpoint_to_udp_destination(&ep).expect("some dest");
        assert_eq!(
            dest.address(),
            &Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            "udp dest addr must come from IP+UDP header dst, not bound socket"
        );
        assert_eq!(dest.port().value(), 53);
        assert_eq!(dest.network(), Network::UDP);
    }

    #[test]
    fn ip_endpoint_to_udp_destination_ipv6() {
        let ep = smoltcp::wire::IpEndpoint {
            addr: smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )),
            port: 443,
        };
        let dest = ip_endpoint_to_udp_destination(&ep).expect("some dest");
        assert_eq!(dest.network(), Network::UDP);
        assert_eq!(dest.port().value(), 443);
    }

    /// UDP 端到端 dispatch 路径（bd 9wc acceptance）：
    /// 构造 fake IPv4+UDP 包（src=10.0.0.2:12345, dst=8.8.8.8:53）→ 解析 → dispatch → 验证
    /// dispatcher 收到的 destination 与 IP 头的 dst 一致。
    #[tokio::test]
    async fn udp_dispatch_uses_real_destination_from_ip_header() {
        use std::sync::Mutex;

        // Capture handler：记录 dispatch 收到的 destination
        #[derive(Debug)]
        struct CaptureHandler(Arc<Mutex<Option<Destination>>>);
        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(
                &self,
                dest: &Destination,
                _link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
                *self.0.lock().expect("lock") = Some(dest.clone());
                Box::pin(async {})
            }
        }

        let captured = Arc::new(Mutex::new(None::<Destination>));
        let handler: Arc<dyn DispatchHandler> = Arc::new(CaptureHandler(Arc::clone(&captured)));

        // 构造 fake UDP 包：src=10.0.0.2:12345, dst=8.8.8.8:53, payload="dns-query"
        let req = make_test_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"dns-query");
        let (meta, payload) = parse_udp_packet(&req).expect("parse fake udp packet");
        assert_eq!(
            meta.dst.addr,
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 8, 8))
        );
        assert_eq!(meta.dst.port, 53);
        assert_eq!(payload, b"dns-query");

        // 把真实 destination (meta.dst) 转 xray Destination，喂给 UdpDispatchSession
        let dest = ip_endpoint_to_udp_destination(&meta.dst).expect("udp dest");
        let mut session = UdpDispatchSession::new(handler);
        session.send_packet(&dest, payload).await.expect("send_packet should succeed");

        // 等 dispatch 跑完（spawn 后给点时间）
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let captured_dest = captured
            .lock()
            .expect("dispatcher should have been called")
            .clone()
            .expect("captured destination");
        assert_eq!(
            captured_dest.address(),
            &Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            "dispatcher must see real destination 8.8.8.8 (from IP header), not local endpoint"
        );
        assert_eq!(captured_dest.port().value(), 53);
        assert_eq!(captured_dest.network(), Network::UDP);
    }

    /// 不同 source src 各自分桶（full-cone NAT 语义）：两个 src 各发一包 → 两路 dispatch。
    #[tokio::test]
    async fn udp_dispatch_full_cone_per_source() {
        use std::{collections::HashSet, sync::Mutex};

        #[derive(Debug)]
        struct CaptureHandler(Arc<Mutex<Vec<Destination>>>);
        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(
                &self,
                dest: &Destination,
                _link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
                self.0.lock().expect("lock").push(dest.clone());
                Box::pin(async {})
            }
        }

        let captured = Arc::new(Mutex::new(Vec::<Destination>::new()));
        let handler: Arc<dyn DispatchHandler> = Arc::new(CaptureHandler(Arc::clone(&captured)));

        let mut session1 = UdpDispatchSession::new(Arc::clone(&handler));
        let mut session2 = UdpDispatchSession::new(Arc::clone(&handler));

        let d1 = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            Port::new(53),
            Network::UDP,
        );
        let d2 = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            Port::new(53),
            Network::UDP,
        );
        session1.send_packet(&d1, b"from-session1").await.expect("s1");
        session2.send_packet(&d2, b"from-session2").await.expect("s2");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let seen: HashSet<_> = captured
            .lock()
            .expect("lock")
            .iter()
            .map(|d| (format!("{}", d.address()), d.port().value()))
            .collect();
        // 两路 dest 都应被 dispatch 看到（full-cone per-session）
        assert!(seen.contains(&("8.8.8.8".to_string(), 53)));
        assert!(seen.contains(&("1.1.1.1".to_string(), 53)));
    }

    /// 构造测试用 IPv4+UDP 包（与 netstack.rs 中 make_ipv4_udp_packet 等价，避免跨 crate 共享）。
    fn make_test_ipv4_udp_packet(
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    /// 构造测试用 IPv4+TCP 包（无校验和——VirtualDevice caps 全 ignored）。
    fn make_test_ipv4_tcp_packet(
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let total = 20 + 20;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        pkt
    }

    /// 端到端 TCP dispatch 路径（bd ipb5 acceptance）：
    /// 真驱动 smoltcp 三次握手——SYN（dst=公网 IP:443）→ 惰性 listen 注册 →
    /// SYN-ACK（从 TX 读 ISN）→ ACK → Established → handle_socket_events →
    /// dispatch 收到的 destination 与 SYN 的 dst 一致。
    #[tokio::test]
    async fn tcp_syn_handshake_triggers_dispatch_with_real_destination() {
        use std::sync::Mutex;

        use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

        #[derive(Debug)]
        struct CaptureHandler(Arc<Mutex<Option<Destination>>>);
        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(
                &self,
                dest: &Destination,
                _link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
                *self.0.lock().expect("lock") = Some(dest.clone());
                Box::pin(async {})
            }
        }

        let captured = Arc::new(Mutex::new(None::<Destination>));
        let handler: Arc<dyn DispatchHandler> = Arc::new(CaptureHandler(Arc::clone(&captured)));

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<TunNetStack>> =
            Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));

        // TUN 真实形态：SYN 的 dst 是公网 IP（非本机接口地址），依赖 AnyIP 放行
        let syn = make_test_ipv4_tcp_packet(
            [10, 0, 0, 2],
            40000,
            [93, 184, 216, 34],
            443,
            1000,
            0,
            0x02, // SYN
        );

        {
            let mut stack = netstack.lock().await;
            // ① SYN → 惰性注册（与 driver loop 顺序一致：ensure 先于 ingest）
            let dst = parse_tcp_syn_dst(&syn).expect("parse SYN dst");
            stack.ensure_tcp_listen(dst).expect("lazy listen");
            stack.ingest_rx(syn);
            stack.poll(smoltcp::time::Instant::now());

            // ② 从 TX 读 SYN-ACK 的 seq（smoltcp ISN，测试无法预知）
            let tx = stack.drain_tx();
            let synack_seq = tx
                .iter()
                .find(|p| p.len() >= 34 && p[9] == 6 && (p[20 + 13] & 0x12) == 0x12)
                .map(|p| u32::from_be_bytes([p[20 + 4], p[20 + 5], p[20 + 6], p[20 + 7]]))
                .expect("SYN-ACK must be emitted for lazy-listened SYN");

            // ③ ACK 完成握手 → socket Established
            let ack = make_test_ipv4_tcp_packet(
                [10, 0, 0, 2],
                40000,
                [93, 184, 216, 34],
                443,
                1001,
                synack_seq.wrapping_add(1),
                0x10, // ACK
            );
            stack.ingest_rx(ack);
            stack.poll(smoltcp::time::Instant::now());
            let _ = stack.drain_tx();

            // ④ accept → dispatch（票 fnlv：锁内收集事件，锁外建桥）
            let accepted = stack.check_tcp_accepts();
            drop(stack);
            dispatch_accepted(&netstack, accepted, &(handler as Arc<dyn DispatchHandler>)).await;
        }

        // dispatch 在 spawn 的 task 里执行，current-thread runtime 需让出让其跑完
        tokio::time::sleep(Duration::from_millis(50)).await;

        // dispatch 同步捕获（CaptureHandler.dispatch 立即写 captured）
        let dest = captured
            .lock()
            .expect("lock")
            .clone()
            .expect("dispatch must be triggered by handshake");
        assert_eq!(
            dest.address(),
            &Address::IPv4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            "dest must come from SYN dst, not interface address"
        );
        assert_eq!(dest.port().value(), 443);
        assert_eq!(dest.network(), Network::TCP);
    }

    /// 无 listen 注册（无 SYN）时 handle_socket_events 不误触发 dispatch。
    #[tokio::test]
    async fn handle_socket_events_no_listen_no_dispatch() {
        let local = smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
            24,
        );
        let netstack: Arc<AsyncMutex<TunNetStack>> =
            Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));
        let (dispatch, calls) = make_dispatch();

        {
            let mut stack = netstack.lock().await;
            let accepted = stack.check_tcp_accepts();
            drop(stack);
            dispatch_accepted(&netstack, accepted, &(dispatch as Arc<dyn DispatchHandler>)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no spurious dispatch");
    }

    /// p14e/8gr6：超过 UDP_SESSION_IDLE_SECS 的 session 被 sweep 淘汰，最近
    /// 活跃的不动；淘汰后 entry 的 cmd_tx 随 Arc 释放而 drop，owner task 收到
    /// channel 关闭自动退出（会话回收闭环）。直接插旧戳驱动，不等 60s。
    #[tokio::test]
    async fn sweep_drops_idle_keeps_recent_and_owner_task_exits() {
        #[derive(Debug)]
        struct StubDispatch;
        #[async_trait::async_trait]
        impl DispatchHandler for StubDispatch {
            fn tag(&self) -> &str {
                "stub"
            }

            fn dispatch(
                &self,
                _dest: &Destination,
                _link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                Box::pin(async {})
            }
        }
        let dispatch: Arc<dyn DispatchHandler> = Arc::new(StubDispatch);
        let sessions: UdpSessions = Arc::new(ParkMutex::new(HashMap::new()));

        let old_ep = smoltcp::wire::IpEndpoint::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
            1234,
        );
        let new_ep = smoltcp::wire::IpEndpoint::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2)),
            1235,
        );

        // idle entry 绑定一个真实 owner task，验证回收闭环
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (reply_tx, _reply_rx) = mpsc::unbounded_channel();
        let owner = tokio::spawn(run_udp_session(
            Arc::clone(&dispatch),
            cmd_rx,
            reply_tx,
            old_ep,
            smoltcp::wire::IpEndpoint::new(
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 8, 8)),
                53,
            ),
        ));
        let (cmd_tx_new, _cmd_rx_new) = mpsc::unbounded_channel();
        {
            let mut m = sessions.lock();
            m.insert(
                old_ep,
                Arc::new(UdpSessionEntry {
                    cmd_tx,
                    last_used_nanos: AtomicI64::new(0), // 远古
                }),
            );
            m.insert(
                new_ep,
                Arc::new(UdpSessionEntry {
                    cmd_tx: cmd_tx_new,
                    last_used_nanos: AtomicI64::new(now_nanos()),
                }),
            );
        }

        sweep_udp_sessions(&sessions);

        {
            let m = sessions.lock();
            assert!(m.contains_key(&new_ep), "recent entry preserved");
            assert!(!m.contains_key(&old_ep), "idle entry swept");
        }
        // cmd_tx 已随 entry 释放 → owner task 必须退出（会话回收闭环）
        tokio::time::timeout(Duration::from_millis(500), owner)
            .await
            .expect("owner task must exit after sweep (cmd_tx dropped)")
            .expect("owner task join");
    }

    /// 票 8gr6 断言 1：对端不应答（recv 挂死）时，同 src 第二包必须在 1s 内
    /// 送达 outbound——channel 化后 send 与 recv 无互斥，不再排队等锁。
    #[tokio::test]
    async fn udp_second_packet_reaches_outbound_while_recv_blackholed() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Debug)]
        struct BlackholeHandler {
            req_bytes: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl DispatchHandler for BlackholeHandler {
            fn tag(&self) -> &str {
                "blackhole"
            }

            fn dispatch(
                &self,
                _dest: &Destination,
                link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                let req_bytes = Arc::clone(&self.req_bytes);
                Box::pin(async move {
                    let mut reader = link.reader;
                    // 黑洞不写响应，但必须显式持有写端：edition 2021 disjoint
                    // capture 只捕获用到的 link.reader，link.writer 若不 move
                    // 进 future 会在 dispatch() 返回时随临时值 drop → resp 半边
                    // EOF → recv_packet Ok(None)，黑洞前提被破坏。
                    let _writer = link.writer;
                    loop {
                        match reader.read_multi_buffer().await {
                            Ok(mb) => {
                                req_bytes.fetch_add(mb.len(), Ordering::Relaxed);
                                if mb.is_empty() {
                                    // EOF 兜底：避免空转烧 CPU
                                    tokio::time::sleep(Duration::from_millis(1)).await;
                                }
                            },
                            Err(_) => return,
                        }
                    }
                })
            }
        }

        let req_bytes = Arc::new(AtomicUsize::new(0));
        let dispatch: Arc<dyn DispatchHandler> =
            Arc::new(BlackholeHandler { req_bytes: Arc::clone(&req_bytes) });

        let src = smoltcp::wire::IpEndpoint::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2)),
            12345,
        );
        let dst = smoltcp::wire::IpEndpoint::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 8, 8)),
            53,
        );
        let dest = ip_endpoint_to_udp_destination(&dst).expect("udp dest");

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (reply_tx, _reply_rx) = mpsc::unbounded_channel();
        let _owner = tokio::spawn(run_udp_session(dispatch, cmd_rx, reply_tx, src, dst));

        let payload = bytes::Bytes::from(vec![0xABu8; 100]);
        cmd_tx
            .send(SessionCmd::Send { dest: dest.clone(), payload: payload.clone() })
            .expect("send pkt1");
        // 等首包 establish link 后再发第二包
        tokio::time::sleep(Duration::from_millis(50)).await;
        cmd_tx.send(SessionCmd::Send { dest, payload }).expect("send pkt2");

        // 两帧合计保守下限：2 × (2B len + 100B payload) = 204；XUDP 帧头
        // （meta 序列化）远小于 payload，单帧不可能达到 204。
        const TWO_FRAMES_MIN: usize = 204;
        let delivered = tokio::time::timeout(Duration::from_secs(1), async {
            while req_bytes.load(Ordering::Relaxed) < TWO_FRAMES_MIN {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            delivered.is_ok(),
            "second packet must reach outbound within 1s while recv is blackholed, got {} bytes",
            req_bytes.load(Ordering::Relaxed)
        );
    }

    /// 票 fnlv 契约 1：整批单临界区语义等价——[SYN, ACK] 同批（或分批）drive
    /// 完成三次握手，accept 事件由批尾统一收集；批驱动（锁内）期间 dispatch
    /// 零触发，建桥 spawn 只发生在锁外 dispatch_accepted。
    #[tokio::test]
    async fn batch_drive_completes_handshake_and_defers_spawn_out_of_lock() {
        use std::sync::Mutex;

        use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

        #[derive(Debug)]
        struct CaptureHandler(Arc<Mutex<Option<Destination>>>);
        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(
                &self,
                dest: &Destination,
                _link: Link,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
                *self.0.lock().expect("lock") = Some(dest.clone());
                Box::pin(async {})
            }
        }

        let captured = Arc::new(Mutex::new(None::<Destination>));
        let handler: Arc<dyn DispatchHandler> = Arc::new(CaptureHandler(Arc::clone(&captured)));

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<TunNetStack>> =
            Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));

        // 批 1：SYN 单包批 → 批尾一次 poll 出 SYN-ACK（GRO 批读聚合形态）
        let syn = make_test_ipv4_tcp_packet(
            [10, 0, 0, 2],
            40000,
            [93, 184, 216, 34],
            443,
            1000,
            0,
            0x02, // SYN
        );
        let (accepted1, tx) = {
            let mut stack = netstack.lock().await;
            drive_stack_batch(&mut stack, vec![syn.to_vec()])
        };
        assert!(accepted1.is_empty(), "SYN alone must not accept");
        let synack_seq = tx
            .iter()
            .find(|p| p.len() >= 34 && p[9] == 6 && (p[20 + 13] & 0x12) == 0x12)
            .map(|p| u32::from_be_bytes([p[20 + 4], p[20 + 5], p[20 + 6], p[20 + 7]]))
            .expect("SYN-ACK must be emitted at batch end");
        assert!(!captured.lock().expect("lock").is_some(), "no dispatch inside critical section");

        // 批 2：ACK 完成握手 → accept 事件批尾收集
        let ack = make_test_ipv4_tcp_packet(
            [10, 0, 0, 2],
            40000,
            [93, 184, 216, 34],
            443,
            1001,
            synack_seq.wrapping_add(1),
            0x10, // ACK
        );
        let (accepted2, _) = {
            let mut stack = netstack.lock().await;
            drive_stack_batch(&mut stack, vec![ack.to_vec()])
        };
        assert_eq!(accepted2.len(), 1, "accept collected once per batch");

        // 锁外建桥 → dispatch 收到 SYN 的 dst（与真实 driver loop 两段式一致）
        dispatch_accepted(&netstack, accepted2, &handler).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let dest = captured
            .lock()
            .expect("lock")
            .clone()
            .expect("dispatch must fire from lock-external bridge");
        assert_eq!(dest.address(), &Address::IPv4(std::net::Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(dest.port().value(), 443);
        assert_eq!(dest.network(), Network::TCP);
    }

    /// 票 fnlv 契约 2：拆分后各锁职责单一 + 并发无死锁（带 deadline）——
    /// driver 批驱动（poll+drain）与 TunTcpRelay 轮询（send/recv）并发抢同一
    /// netstack 锁，用户数据经 relay 进 socket、被 driver 排进 TX 的完整一轮
    /// 必须在 deadline 内完成；持锁跨 await 或锁序颠倒都会撞死 deadline。
    #[tokio::test]
    async fn concurrent_batch_drive_and_relay_no_deadlock() {
        use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<TunNetStack>> =
            Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));

        // 真实握手造一条 Established 连接：SYN 批 → ACK 批 → accept
        let syn =
            make_test_ipv4_tcp_packet([10, 0, 0, 2], 40000, [93, 184, 216, 34], 443, 1000, 0, 0x02);
        let synack_seq = {
            let mut stack = netstack.lock().await;
            let (_, tx) = drive_stack_batch(&mut stack, vec![syn.to_vec()]);
            tx.iter()
                .find(|p| p.len() >= 34 && p[9] == 6 && (p[20 + 13] & 0x12) == 0x12)
                .map(|p| u32::from_be_bytes([p[20 + 4], p[20 + 5], p[20 + 6], p[20 + 7]]))
                .expect("SYN-ACK")
        };
        let ack = make_test_ipv4_tcp_packet(
            [10, 0, 0, 2],
            40000,
            [93, 184, 216, 34],
            443,
            1001,
            synack_seq.wrapping_add(1),
            0x10,
        );
        let (accepted, _) = {
            let mut stack = netstack.lock().await;
            drive_stack_batch(&mut stack, vec![ack.to_vec()])
        };
        assert_eq!(accepted.len(), 1);
        let handle = accepted[0].handle;

        // 与真实 driver loop 同形态建 relay（duplex 两端 + 同一把锁）
        let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
        let (relay_to_client, mut client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
        let relay = TunTcpRelay {
            from_client: relay_from_client,
            to_client: relay_to_client,
            netstack: Arc::clone(&netstack),
            handle,
        };
        tokio::spawn(relay.run());
        // 消费端保活：relay_to_client 的对端不被 drop → relay 收方向不 EOF
        let _relay_sink = tokio::spawn(async move {
            let mut sink = vec![0u8; 64];
            while let Ok(n) = client_from_relay.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });

        // driver 侧：循环批驱动（锁内 poll+drain），检到 payload 包置位。
        // 空批 drive = 纯 timer tick 形态，与 relay 轮询交错抢锁。
        let tx_has_payload = Arc::new(AtomicBool::new(false));
        let driver = {
            let netstack = Arc::clone(&netstack);
            let tx_has_payload = Arc::clone(&tx_has_payload);
            tokio::spawn(async move {
                let empty: Vec<Vec<u8>> = Vec::new();
                for _ in 0..500 {
                    let (accepted, tx) = {
                        let mut stack = netstack.lock().await;
                        drive_stack_batch(&mut stack, empty.clone())
                    };
                    debug_assert!(accepted.is_empty());
                    if tx.iter().any(|p| p.len() > 40) {
                        tx_has_payload.store(true, Ordering::SeqCst);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };

        // 用户数据经 relay 写入 smoltcp socket（relay.send_to_smoltcp 抢锁）
        let mut user = client_to_relay;
        user.write_all(b"ping").await.expect("write to relay");
        user.flush().await.expect("flush to relay");

        // deadline 内用户数据必须被 driver 从 socket 排进 TX（无死锁证明）
        let completed = tokio::time::timeout(Duration::from_secs(5), async {
            while !tx_has_payload.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            completed.is_ok(),
            "deadlock suspected: relay→socket data never reached TX within 5s"
        );
        driver.await.expect("driver task join");
    }
}
