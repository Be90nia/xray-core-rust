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
//! ## TCP 连接流
//!
//! 创建 Listen socket → poll 后检查 Established → 通知上层 dispatcher。
//! 对应 Go `tcp.NewForwarder(r.CreateEndpoint() → handler.HandleConnection)`。
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
//! 1. 从 TUN recv IP 包后，先用 [`parse_udp_packet`] 解 IP+UDP 头，提取 (src, dst)。
//!    是 UDP 包 → 走本路径；否则继续交给 smoltcp（TCP/ICMP）。
//! 2. 按 `event.src`（IP+UDP 头的源端）作 full-cone NAT key，懒建
//!    [`UdpDispatchSession`]，首包确定 routing。
//! 3. session.send_packet(&dest, payload) 把数据转发到 dispatcher
//!    （`dest = event.dst`，即 IP+UDP 头中的真实目标地址）。
//! 4. session reader task 持续 recv 响应，用 [`build_udp_response`] 装回 IP+UDP
//!    包（src/dst 交换），写回 TUN。
//!
//! # ponytail: 一个 remote src 一个 session
//!
//! 对应 Go `proxy/tun/udp_fullcone.go` 的 `udpConns map[net.Destination]*udpConn`：
//! 按 source 分桶天然 cone NAT。session 生命周期由 inbound handler 持有
//! （Arc<Mutex<HashMap>>），后续切片可加 idle 淘汰（Go `CancelAfterInactivity(1min)`）。
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as ParkMutex;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
use xray_app_dispatcher::{DispatchHandler, UdpDispatchSession};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::config::{StackOptions, Tun};
use crate::device::TunDevice;
use crate::error::Result;
use crate::netstack::{
    build_udp_response, parse_udp_packet, TunNetStack, UdpPacketMeta,
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
        device
            .start()
            .map_err(|e| InboundError::ListenError(format!("tun device start: {e}")))?;

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
type UdpSessions = Arc<ParkMutex<HashMap<IpEndpoint, Arc<UdpSessionEntry>>>>;

/// 单个 remote src 的 session 条目：session + reader task handle。
///
/// reader 只 spawn 一次；后续包复用 task 即可（session 是 &mut self，
/// send_packet 仍可并发调用——内部 duplex 是 &mut self + 异步，task 串行）。
struct UdpSessionEntry {
    session: AsyncMutex<UdpDispatchSession>,
    reader_started: AtomicBool,
}

async fn tun_driver_loop(
    device: Arc<TunDevice>,
    netstack: Arc<AsyncMutex<TunNetStack>>,
    dispatch: Arc<dyn DispatchHandler>,
) {
    let mut timer = interval(POLL_INTERVAL);
    let mut recv_buf = vec![0u8; TUN_RECV_BUF_SIZE];

    // 初始化：仅创建 TCP Listen socket（TCP 后续切片处理 destination 提取）。
    // UDP 走 IP+UDP 头解析路径，不创建 smoltcp UDP socket。
    // 对应 Go stackGVisor.Start() 中 tcp.NewForwarder。
    // ponytail: 单端口监听（TUN 入站通常由 iptables/nftables 重定向到 TUN，
    // 实际 dest 地址在 IP 包头中，不依赖 listen 端口）
    // TODO: 多端口监听由上层配置注入
    let mut tcp_listen_handle = {
        let mut stack = netstack.lock().await;
        let handle = stack.add_tcp_socket();
        if let Err(e) = stack.tcp_listen(handle, 0) {
            // listen 0 表示由 smoltcp 自动选端口；失败则记录但不中断
            tracing::warn!(error = %e, "tcp listen failed, inbound TCP disabled");
        } else {
            tracing::debug!(?handle, "tcp listen socket created");
        }
        Some(handle)
    };

    let udp_sessions: UdpSessions = Arc::new(ParkMutex::new(HashMap::new()));

    tracing::debug!("tun driver main loop started");

    loop {
        tokio::select! {
            // 从 TUN 设备读取 IP 包
            result = device.recv(&mut recv_buf) => {
                match result {
                    Ok(n) => {
                        if n == 0 { continue; }
                        let pkt = &recv_buf[..n];

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
                            continue;
                        }

                        let mut stack = netstack.lock().await;
                        stack.ingest_rx(pkt.to_vec());
                        stack.poll(smoltcp::time::Instant::now());
                        // 处理 ICMP echo request 并自动回复
                        stack.process_icmp_echo();
                        // 检测 TCP accept 事件
                        handle_socket_events(
                            &mut stack,
                            &netstack,
                            &mut tcp_listen_handle,
                            &dispatch,
                        );
                        // drain tx 并写回 TUN
                        let tx_pkts = stack.drain_tx();
                        drop(stack); // 释放锁再 await
                        for pkt in tx_pkts {
                            let _ = device.send(&pkt).await;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "tun recv error");
                        // ponytail: 不退出循环——设备可能临时错误
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            // 每 100ms 触发：poll + drain_tx
            _ = timer.tick() => {
                let tx_pkts: Vec<Vec<u8>> = {
                    let mut stack = netstack.lock().await;
                    stack.poll(smoltcp::time::Instant::now());
                    // 处理 ICMP echo request 并自动回复
                    stack.process_icmp_echo();
                    // 检测 TCP accept 事件
                    handle_socket_events(
                        &mut stack,
                        &netstack,
                        &mut tcp_listen_handle,
                        &dispatch,
                    );
                    stack.drain_tx()
                };
                for pkt in tx_pkts {
                    let _ = device.send(&pkt).await;
                }
            }
        }
    }
}

/// 单 UDP 数据报 → dispatch（full-cone NAT）。
///
/// 对应 Go `udp_fullcone.go:HandlePacket`：按 src 懒建 `udpConn`，首次
/// 确定 routing，后续包复用同一 session。响应回写由 [`UdpDispatchSession`]
/// reader task 持续 recv 完成。
fn handle_udp_packet(
    sessions: &UdpSessions,
    meta: UdpPacketMeta,
    payload: &[u8],
    dispatch: Arc<dyn DispatchHandler>,
    device: Arc<TunDevice>,
) {
    // 懒建 session：按 src 找；不在则建。
    let entry = {
        let mut map = sessions.lock();
        map.entry(meta.src)
            .or_insert_with(|| {
                Arc::new(UdpSessionEntry {
                    session: AsyncMutex::new(UdpDispatchSession::new(Arc::clone(&dispatch))),
                    reader_started: AtomicBool::new(false),
                })
            })
            .clone()
    };

    // 把 dest + payload 通过 session 转发；首包懒建 dispatch link。
    // 必须 spawn：send_packet 是 async，driver loop 不能 await（会阻塞 TUN recv）。
    let dest = ip_endpoint_to_udp_destination(&meta.dst);
    let Some(dest) = dest else {
        tracing::warn!(src = %meta.src, dst = %meta.dst, "udp: invalid destination, dropping");
        return;
    };

    let meta_src = meta.src;
    let meta_dst = meta.dst;
    let payload = payload.to_vec();
    let entry_clone = Arc::clone(&entry);
    tokio::spawn(async move {
        let mut s = entry_clone.session.lock().await;
        if let Err(e) = s.send_packet(&dest, &payload).await {
            tracing::warn!(error = %e, src = %meta_src, dst = %meta_dst, "udp: session.send_packet failed");
            return;
        }
        drop(s);
        // 首包懒启 reader task（仅一次）：session 是 &mut self，
        // 不能跨 await 持锁，所以 reader task 拿 Arc<UdpSessionEntry>。
        spawn_udp_session_reader_if_first(&entry_clone, Arc::clone(&device), meta_src, meta_dst);
    });
}

/// 把 IP 协议族的 smoltcp IpEndpoint 转 xray Destination（UDP）。
fn ip_endpoint_to_udp_destination(ep: &IpEndpoint) -> Option<Destination> {
    let address = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => {
            Address::IPv4(std::net::Ipv4Addr::from(v4.octets()))
        }
        smoltcp::wire::IpAddress::Ipv6(v6) => {
            Address::IPv6(std::net::Ipv6Addr::from(v6.octets()))
        }
    };
    Some(Destination::new(address, Port::new(ep.port), Network::UDP))
}

/// xray Address → smoltcp IpAddress（域名返回 None；build_udp_response 需要 IP）。
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

/// 首包懒启 UDP session reader task（每个 remote src 仅一次）。
///
/// reader 持续 `recv_packet()`，把 outbound 响应装回 IP+UDP 包（src/dst 交换），
/// 写回 TUN。session 关闭后 `recv_packet()` 返回 `Ok(None)` → task 退出。
///
/// # ponytail: 不主动清理 sessions map
///
/// Go 端用 `CancelAfterInactivity(1min)` 回收空闲 udpConn。本切片先用 Arc 永久持有，
/// 后续切片加 idle 淘汰（需要把 sessions 从 ParkMutex<HashMap> 升到带 idle 跟踪的
/// 数据结构）。
fn spawn_udp_session_reader_if_first(
    entry: &Arc<UdpSessionEntry>,
    device: Arc<TunDevice>,
    original_src: IpEndpoint,
    original_dst: IpEndpoint,
) {
    // compare_exchange 保证仅一次 spawn
    if entry
        .reader_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let entry = Arc::clone(entry);
    tokio::spawn(async move {
        loop {
            let pkt = {
                let mut s = entry.session.lock().await;
                s.recv_packet().await
            };
            match pkt {
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
                    if let Err(e) = device.send(&reply).await {
                        tracing::warn!(error = %e, "udp: write reply to tun failed");
                        return;
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
            }
        }
    });
}

fn handle_socket_events(
    stack: &mut TunNetStack,
    netstack: &Arc<AsyncMutex<TunNetStack>>,
    tcp_listen_handle: &mut Option<SocketHandle>,
    dispatch: &Arc<dyn DispatchHandler>,
) {
    // TCP accept 检测
    let Some(handle) = *tcp_listen_handle else { return };
    let Some(event) = stack.check_tcp_accept(handle) else { return };

    // accept 后该 socket 进入 Established，作为连接 socket；
    // 新建一个 listen socket 接受下一个连接。
    let new_listen = stack.add_tcp_socket();
    if let Err(e) = stack.tcp_listen(new_listen, 0) {
        tracing::warn!(error = %e, "tcp re-listen failed");
    }
    *tcp_listen_handle = Some(new_listen);

    // 从 local endpoint 构建 destination
    let dest = match ip_endpoint_to_destination(&event.local) {
        Some(d) => d,
        None => {
            tracing::warn!(
                remote = %event.remote,
                "tcp accept: no local endpoint, dropping connection"
            );
            stack.remove_socket(event.handle);
            return;
        }
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
        smoltcp::wire::IpAddress::Ipv4(v4) => {
            Address::IPv4(std::net::Ipv4Addr::from(v4.octets()))
        }
        smoltcp::wire::IpAddress::Ipv6(v6) => {
            Address::IPv6(std::net::Ipv6Addr::from(v6.octets()))
        }
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
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicU32;

    struct DummyTun;
    impl crate::config::Tun for DummyTun {
        fn start(&self) -> std::result::Result<(), crate::error::TunError> { Ok(()) }
        fn close(&self) -> std::result::Result<(), crate::error::TunError> { Ok(()) }
        fn name(&self) -> std::result::Result<String, crate::error::TunError> { Ok("dummy0".into()) }
        fn index(&self) -> std::result::Result<i32, crate::error::TunError> { Ok(0) }
    }

    fn make_options() -> StackOptions {
        StackOptions {
            tun: Some(Box::new(DummyTun)),
            ..Default::default()
        }
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
        fn tag(&self) -> &str { &self.tag }
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
            addr: smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1)),
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
            addr: smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
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
            fn tag(&self) -> &str { "capture" }
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
        assert_eq!(meta.dst.addr, smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 8, 8)));
        assert_eq!(meta.dst.port, 53);
        assert_eq!(payload, b"dns-query");

        // 把真实 destination (meta.dst) 转 xray Destination，喂给 UdpDispatchSession
        let dest = ip_endpoint_to_udp_destination(&meta.dst).expect("udp dest");
        let mut session = UdpDispatchSession::new(handler);
        session
            .send_packet(&dest, payload)
            .await
            .expect("send_packet should succeed");

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
        use std::collections::HashSet;
        use std::sync::Mutex;

        #[derive(Debug)]
        struct CaptureHandler(Arc<Mutex<Vec<Destination>>>);
        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str { "capture" }
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

    /// 端到端 dispatch 路径：构造 netstack + listen socket，模拟 TCP accept
    /// （手动让 socket 进入 Established），验证 handle_socket_events 触发 dispatch。
    #[tokio::test]
    async fn handle_socket_events_triggers_dispatch() {
        use crate::netstack::TunNetStack;
        use smoltcp::wire::{IpCidr, IpAddress, Ipv4Address};

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<TunNetStack>> =
            Arc::new(AsyncMutex::new(TunNetStack::new(&[local], 1500)));

        // 创建 listen socket
        let listen_handle = {
            let mut stack = netstack.lock().await;
            let h = stack.add_tcp_socket();
            // listen 0 不绑端口（测试环境不依赖真实端口）；忽略错误
            let _ = stack.tcp_listen(h, 0);
            h
        };

        let (dispatch_concrete, calls) = make_dispatch();
        let dispatch: Arc<dyn DispatchHandler> = dispatch_concrete;
        let mut tcp_listen = Some(listen_handle);

        // 直接驱动 smoltcp：没有真实 TUN 流量，socket 不会进入 Established，
        // 所以 check_tcp_accept 返回 None——验证 handle_socket_events 不 panic、
        // 不误触发 dispatch。
        {
            let mut stack = netstack.lock().await;
            handle_socket_events(
                &mut stack,
                &netstack,
                &mut tcp_listen,
                &dispatch,
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no spurious dispatch");
        // listen handle 未变（无 accept）
        assert_eq!(tcp_listen, Some(listen_handle));
    }
}
