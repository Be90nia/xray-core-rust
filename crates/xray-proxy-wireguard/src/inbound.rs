//! WireGuard 入站 Handler——接收 WireGuard 流量并注入本地。
//!
//! 对应 Go `proxy/wireguard/server.go` 的 `Server.Process`。
//!
//! ## 流程
//!
//! 1. 监听 UDP 端口
//! 2. 接收 WG 数据报 → Tunnel.decapsulate → smoltcp netstack
//! 3. smoltcp 把入站 TCP 流通过 dispatcher 注入本地
//!
//! ## TCP 连接流
//!
//! driver task 驱动 WG 协议 + netstack poll；accept loop（与 driver 同 task，
//! `select!` 并发）poll 后 drain 已 Established 的惰性监听连接 → 通知 dispatcher。
//! 对应 Go `tcp.NewForwarder(r.CreateEndpoint() → handler.HandleConnection)`。
//! 中继模式与 `xray-proxy-tun/src/inbound.rs::TunTcpRelay` 一致。

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex as ParkMutex;
use skeleton_infra::fx::{FxScope, Spawned};
use smoltcp::{iface::SocketHandle, wire::IpEndpoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, mpsc},
    time::interval,
};
use xray_app_dispatcher::{AccessContext, DispatchHandler, UdpDispatchSession};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::{
    config::DeviceConfig,
    driver::{WgDriver, bind_udp_socket},
    error::Result,
    netstack::{WgNetStack, nanos_now},
    peer::shared_peer,
    users::{DriverSlot, WgUserRegistry},
};

/// duplex 缓冲大小。
const DUPLEX_BUF: usize = 64 * 1024;

/// accept loop 轮询间隔（ms）。
const ACCEPT_POLL_MS: u64 = 100;

/// 中继轮询间隔（ms）。
const RELAY_POLL_MS: u64 = 5;

/// 内层 UDP 会话空闲淘汰（秒）——对齐 tun inbound 同款阈值（票 8gr6/p14e）；
/// Go `CancelAfterInactivity(4min)` 的保守近似（udp_session.rs ponytail 注：
/// 中央 session 不内置空闲超时，由调用方生命周期管理）。
const WG_UDP_SESSION_IDLE_SECS: u64 = 60;

/// UDP 会话/监听清扫周期（秒）。
const WG_UDP_SWEEP_SECS: u64 = 30;

/// TCP relay 关闭前等待 FIN/残留数据被确认的上限（票 97ng）。
const FINISH_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// 单会话待发数据报队列上限（Go `udpQueueLimit = 1024` 同值，满即丢）。
const WG_UDP_QUEUE_CAP: usize = 1024;

/// WireGuard 入站 Handler。
///
/// 持有 driver + 监听状态 + 监听端口 + dispatcher handler。
pub struct WireguardInboundHandler {
    tag: String,
    port: u16,
    started: AtomicBool,
    /// driver 句柄槽——start() 后消费；与 registry 共享（动态热插）。
    driver: DriverSlot,
    /// join handle——close() 用以终止 task。任务归组件自持 [`FxScope`] 托管
    /// （B6，bd t975；scope 不接 close，闸关不可达，组件释放兜底 abort）。
    join: ParkMutex<Option<Spawned<()>>>,
    /// 组件内自持托管 scope（B6，app 家族同款）：start 主任务与 accept 循环内
    /// 的 sweep/dispatch 托管面任务统一经此 spawn。
    fx: Arc<FxScope>,
    /// smoltcp 网栈句柄（与 driver 共享）。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// dispatcher handler（TCP accept 后桥接到 outbound）。
    dispatch: Arc<dyn DispatchHandler>,
    /// 动态用户注册表（AddUser/RemoveUser，Go `users sync.Map` 等价物）。
    /// Arc 共享给 accept loop（dispatch 挂 per-user 上下文，bd ttni）。
    registry: Arc<WgUserRegistry>,
}

impl WireguardInboundHandler {
    /// 从 DeviceConfig 构造入站 Handler。
    ///
    /// 不在此 spawn driver——构造仅做参数校验。`start()` 时启动。
    ///
    /// # 参数
    ///
    /// - `tag`：handler 唯一标识
    /// - `config`：DeviceConfig（is_client 应为 false）
    /// - `listen_port`：UDP 监听端口
    /// - `dispatch`：dispatcher handler（TCP accept 后桥接到 outbound）
    pub async fn new(
        tag: impl Into<String>,
        config: &DeviceConfig,
        listen_port: u16,
        dispatch: Arc<dyn DispatchHandler>,
    ) -> Result<Self> {
        let tag = tag.into();
        // bd 7v0k③：peers 空允许启动（Go 官方空配置 + API 建户；
        // xray api inbound_user_add 载荷支持另票）
        // 创建所有配置的 peer session（multi-peer server 模式）
        let mut peers = Vec::with_capacity(config.peers.len());
        let mut allowed_cidrs = Vec::with_capacity(config.peers.len());
        for (i, peer_cfg) in config.peers.iter().enumerate() {
            peers.push(shared_peer(config, peer_cfg, i as u32)?);
            let cidrs: Vec<smoltcp::wire::IpCidr> =
                peer_cfg.allowed_ips.iter().filter_map(|s| s.parse().ok()).collect();
            allowed_cidrs.push(cidrs);
        }

        // 动态用户注册表（同 driver 槽 Arc 共享，AddUser/RemoveUser 热插）
        let driver_slot: DriverSlot = Arc::new(ParkMutex::new(None));
        let registry = Arc::new(WgUserRegistry::new(config.clone(), Arc::clone(&driver_slot))?);

        // 绑定监听 UDP
        let bind_addr = format!("0.0.0.0:{listen_port}");
        let sock = bind_udp_socket(&bind_addr).await?;

        // smoltcp 网栈
        let local_cidrs = parse_local_cidrs(config)?;
        let mtu = config.effective_mtu() as usize;
        let netstack = Arc::new(AsyncMutex::new(WgNetStack::new(&local_cidrs, mtu)));
        // num_workers（Go server.go:52 也传 conf.NumWorkers → netBind.workers）
        let driver = Arc::new(
            WgDriver::new_multi(peers, allowed_cidrs, sock, Arc::clone(&netstack))
                .with_num_workers(config.num_workers),
        );
        // driver 注入槽——此后 AddUser 可用（Go "too early" 边界与此对应）
        *driver_slot.lock() = Some(driver);

        Ok(Self {
            tag,
            port: listen_port,
            started: AtomicBool::new(false),
            driver: driver_slot,
            registry,
            join: ParkMutex::new(None),
            fx: Arc::new(FxScope::new()),
            netstack,
            dispatch,
        })
    }

    /// 共享 smoltcp 网栈句柄（dispatcher 桥接用）。
    #[must_use]
    pub fn netstack(&self) -> &Arc<AsyncMutex<WgNetStack>> {
        &self.netstack
    }

    /// 动态用户注册表句柄（原生 AddUser/RemoveUser 入口）。
    #[must_use]
    pub fn user_registry(&self) -> &WgUserRegistry {
        &self.registry
    }

    /// 同步启动核心——proxyman 适配器复用（PinFuture 要求 'static，逻辑不借 self 跨 await）。
    ///
    /// # Errors
    /// - [`InboundError::AlreadyStarted`]：重复启动。
    /// - [`InboundError::Closed`]：driver 槽为空。
    pub(crate) fn do_start(&self) -> std::result::Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        let driver =
            self.driver.lock().clone().ok_or_else(|| InboundError::Closed(self.tag.clone()))?;

        let netstack = Arc::clone(&self.netstack);
        let registry = Arc::clone(&self.registry);
        let dispatch = Arc::clone(&self.dispatch);

        // B6（bd t975）：主任务（driver + accept loop select!）经组件自持 scope
        // 托管；close 显式 abort 语义不变，组件释放兜底 abort。
        // 接收者（self.fx）与被 future 捕获的绑定（fx）分离，规避 E0505。
        let fx = Arc::clone(&self.fx);
        let main_task = async move {
            // driver loop 与 accept loop 在同一 task 内 select! 并发
            tokio::select! {
                _ = driver.main_loop() => {}
                _ = wg_accept_loop(netstack, registry, dispatch, fx) => {}
            }
        };
        let handle = self.fx.spawn_tracked(main_task).expect("internal FxScope is never closed");
        *self.join.lock() = Some(handle);
        crate::WG_LOG
            .info(format!("wireguard inbound started tag={} port={}", self.tag, self.port));
        Ok(())
    }

    /// 同步关闭核心——proxyman 适配器复用。
    pub(crate) fn do_close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        if let Some(handle) = self.join.lock().take() {
            handle.abort();
        }
        crate::WG_LOG.info(format!("wireguard inbound closed tag={}", self.tag));
        Ok(())
    }
}

#[async_trait]
impl InboundHandler for WireguardInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 启动 driver task + accept loop。
    ///
    /// driver（WG 协议 + netstack poll）与 accept loop（TCP accept 检测 + dispatch）
    /// 在同一 tokio task 内通过 `select!` 并发运行，共享 netstack AsyncMutex。
    async fn start(&self) -> std::result::Result<(), InboundError> {
        Self::do_start(self)
    }

    /// 关闭 driver task + accept loop。
    async fn close(&self) -> std::result::Result<(), InboundError> {
        Self::do_close(self)
    }

    fn port(&self) -> u16 {
        self.port
    }
}

/// 从 DeviceConfig.endpoint 解析为 smoltcp IpCidr（与 outbound 共用逻辑）。
#[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
fn parse_local_cidrs(config: &DeviceConfig) -> Result<Vec<smoltcp::wire::IpCidr>> {
    let parsed = crate::wireguard::parse_endpoints(config)?;
    parsed
        .addrs
        .into_iter()
        .map(|addr| {
            let cidr_prefix = if addr.is_ipv4() { 32 } else { 128 };
            let smoltcp_addr = match addr {
                std::net::IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
                ),
                std::net::IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(
                    smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
                ),
            };
            Ok(smoltcp::wire::IpCidr::new(smoltcp_addr, cidr_prefix))
        })
        .collect()
}

/// accept loop——周期性 poll 网栈并 drain 已建立的惰性监听连接，dispatch 到 outbound。
///
/// 监听 socket 不在启动时预建：netstack 在嗅探到隧道内 TCP SYN 时按目标 tuple
/// 惰性建立（smoltcp 无通配监听语义，对应 Go `tcp.NewForwarder` 的 per-request
/// accept）。本 loop 只负责 poll → [`WgNetStack::drain_accepted`] →
/// 每条新连接 spawn duplex 中继 + dispatch。
async fn wg_accept_loop(
    netstack: Arc<AsyncMutex<WgNetStack>>,
    registry: Arc<WgUserRegistry>,
    dispatch: Arc<dyn DispatchHandler>,
    fx: Arc<FxScope>,
) {
    let mut timer = interval(Duration::from_millis(ACCEPT_POLL_MS));
    // Go time.Ticker 丢 tick 不补发（Burst 是 tokio 默认）
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    crate::WG_LOG.debug("wg accept loop started");

    // 内层 UDP 转发（票 z7ya）：per-源会话表 + 空闲清扫（Go udp forwarder 语义，
    // 结构对齐 xray-proxy-tun/src/inbound.rs 的 full-cone 会话模型）
    let udp_sessions: WgUdpSessions = Arc::new(ParkMutex::new(HashMap::new()));
    let sweep_netstack = Arc::clone(&netstack);
    let sweep_sessions = Arc::clone(&udp_sessions);
    // B6（bd t975）：sweep 定时任务经组件自持 scope 托管（与 accept loop 同生命周期）。
    let fx_sweep = Arc::clone(&fx);
    fx_sweep
        .spawn_tracked(async move {
            let mut tick = interval(Duration::from_secs(WG_UDP_SWEEP_SECS));
            // Go time.Ticker 丢 tick 不补发（Burst 是 tokio 默认）
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // 跳过首个立即 tick（启动时全为新）
            loop {
                tick.tick().await;
                let now = nanos_now();
                let idle = (WG_UDP_SESSION_IDLE_SECS as i64) * 1_000_000_000;
                sweep_netstack.lock().await.sweep_udp(now, idle);
                let mut map = sweep_sessions.lock();
                let expired: Vec<IpEndpoint> = map
                    .iter()
                    .filter(|(_, s)| now.saturating_sub(s.last_used_nanos) > idle)
                    .map(|(k, _)| *k)
                    .collect();
                for k in expired {
                    map.remove(&k);
                }
            }
        })
        .expect("internal FxScope is never closed");

    loop {
        timer.tick().await;
        let mut stack = netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());

        for event in stack.drain_accepted() {
            // 从 local endpoint 构建 destination（隧道内目标）
            let dest = match ip_endpoint_to_destination(&event.local) {
                Some(d) => d,
                None => {
                    crate::WG_LOG.warn(format!(
                        "wg tcp accept: no local endpoint, dropping connection remote={}",
                        event.remote
                    ));
                    stack.remove_socket(event.handle);
                    continue;
                },
            };

            // 创建两路 duplex 桥接 smoltcp socket ↔ Link
            // ponytail: 双 duplex（up/down 独立），与 tun TunTcpRelay 一致
            let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
            let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
            let link = Link::new(new_reader(client_from_relay), new_writer(client_to_relay));

            crate::WG_LOG.debug(format!(
                "wg tcp connection accepted → dispatch handle={:?} remote={} dest={:?}",
                event.handle, event.remote, dest
            ));

            // spawn 中继 task（smoltcp socket ↔ duplex）
            let relay = WgTcpRelay {
                from_client: relay_from_client,
                to_client: relay_to_client,
                netstack: Arc::clone(&netstack),
                handle: event.handle,
            };
            // spawn 中继 task（smoltcp socket ↔ duplex）——组件自持 FxScope
            // 记账（B6 t975），scope drop 兜底 abort。
            fx.spawn_tracked(relay.run()).expect("internal FxScope is never closed");

            // spawn dispatch（link → outbound），挂 per-user 上下文
            // （Go server.go:352-364：GetUserByAddr(隧道内源) →
            // session.Inbound{Source, User}；bd ttni）
            let user = match &event.remote.addr {
                smoltcp::wire::IpAddress::Ipv4(v4) => registry
                    .get_user_by_addr(std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.octets()))),
                smoltcp::wire::IpAddress::Ipv6(v6) => registry
                    .get_user_by_addr(std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.octets()))),
            };
            let access = AccessContext {
                from: event.remote.to_string(),
                email: user.as_ref().map(|u| u.email.clone()).unwrap_or_default(),
                level: user.as_ref().map_or(0, |u| u.level),
                inbound_tag: String::new(),
                allowed_network: None,
                ..Default::default()
            };
            let dispatch = Arc::clone(&dispatch);
            // B6（bd t975）：per-conn dispatch 任务经组件自持 scope 托管。
            let fx_dispatch = Arc::clone(&fx);
            fx_dispatch
                .spawn_tracked(async move {
                    dispatch.dispatch_with_access(&dest, link, access).await;
                })
                .expect("internal FxScope is never closed");
        }

        // 内层 UDP：drain 全部转发监听的待收数据报并路由到 per-源会话。
        // 锁内只做同步 drain（无 await）；会话 spawn/入队均非阻塞。
        let now = nanos_now();
        for (dst, src, payload) in stack.drain_udp(now) {
            forward_wg_udp_datagram(
                &fx,
                &udp_sessions,
                &netstack,
                &dispatch,
                dst,
                src,
                payload,
                now,
            );
        }
    }
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

/// smoltcp IpAddress → xray Address（隧道内 endpoint 转换，仅 IP）。
fn ip_address_to_address(addr: &smoltcp::wire::IpAddress) -> Address {
    match addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::IPv4(std::net::Ipv4Addr::from(v4.octets())),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::IPv6(std::net::Ipv6Addr::from(v6.octets())),
    }
}

/// xray Address（仅 IP）→ smoltcp IpEndpoint；Domain 返回 None（回包无 IP 源）。
fn address_to_ip_endpoint(address: &Address, port: u16) -> Option<IpEndpoint> {
    let addr = match address {
        Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(crate::netstack::to_smoltcp_v4(*v4)),
        Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(crate::netstack::to_smoltcp_v6(*v6)),
        Address::Domain(_) => return None,
    };
    Some(IpEndpoint { addr, port })
}

// ===== 内层 UDP 转发（票 z7ya，对应 Go udp forwarder） =====

/// 内层 UDP 会话命令。
enum WgUdpCmd {
    Send { dest: Destination, payload: Vec<u8> },
}

/// per-隧道内源 UDP 会话句柄（full-cone NAT 键 = 源 endpoint）。
///
/// 对应 Go `proxy/tun/udp_fullcone.go` 的 `udpConns[src]` 与
/// `xray-proxy-tun/src/inbound.rs::UdpSessionEntry`：map 只留非阻塞入队口 +
/// 最近使用时间，owner task 独占 [`UdpDispatchSession`]。sweep/摘除 → cmd_tx
/// 随 entry drop → task 退出 → session drop → dispatch duplex EOF，outbound 回收。
struct WgUdpSession {
    cmd_tx: mpsc::Sender<WgUdpCmd>,
    last_used_nanos: i64,
}

/// 会话表（accept loop 与 sweeper 共享）。
type WgUdpSessions = Arc<ParkMutex<HashMap<IpEndpoint, WgUdpSession>>>;

/// 单个内层 UDP 数据报路由：per-源会话命中即入队转发，未命中建会话。
///
/// 对应 Go `udpConnectionHandler.HandlePacket`：按源 endpoint full-cone 分桶，
/// 队列满丢包（Go `> queue full` 同语义）；首包目标决定 dispatch 链路，后续包
/// 各带目标由 XUDP 帧头 per-packet 路由。owner task 已退出时摘除死会话、本包
/// 丢弃，后续包按新会话重建（Go `connectionFinished` 同语义）。
///
/// 8/7 参豁免台账（B6 t975 新增 `fx` 后越线）：①数据面 4 元（dst/src/payload/
/// now）收包 → `now` 是 accept loop 级共享时钟戳，非 per-报文属性，塞进结构
/// 是语义谎；②infra 面 4 引用（fx/sessions/netstack/dispatch）收包 →
/// per-报文构造 = 4 次 Arc clone（UDP 快路新增分配），或借用结构体（构造点
/// 仍 8 项，纯搬运）。唯一调用方 wg_accept_loop 两组成员各自独立另用，收包
/// 牵动整个 accept loop 局部布局 → 无语义收益，allow + 台账（仓规：豁免一律
/// 显式 allow + 理由）。
#[allow(clippy::too_many_arguments, reason = "8/7 参：收包两种形态均负收益，见上函数 doc 台账")]
fn forward_wg_udp_datagram(
    fx: &Arc<FxScope>,
    sessions: &WgUdpSessions,
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    dispatch: &Arc<dyn DispatchHandler>,
    dst: IpEndpoint,
    src: IpEndpoint,
    payload: Vec<u8>,
    now: i64,
) {
    let dest = Destination::udp(ip_address_to_address(&dst.addr), Port::new(dst.port));
    let mut map = sessions.lock();
    if let Some(entry) = map.get_mut(&src) {
        entry.last_used_nanos = now;
        match entry.cmd_tx.try_send(WgUdpCmd::Send { dest, payload }) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // 逐报文丢弃分支（仅 overload 时触发，非稳态逐包路径）。event! 逃生口
                // 已随 redline_sites 门关闭（PM 2026-10-27 裁决），一律迁 LogFacade。
                crate::WG_LOG.debug(format!(
                    "wg udp: session queue full, packet dropped src={src} dst={dst:?}"
                ));
                return;
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                crate::WG_LOG
                    .debug(format!("wg udp: session closed by outbound, packet dropped src={src}"));
            },
        }
        map.remove(&src);
        return;
    }
    let (cmd_tx, cmd_rx) = mpsc::channel(WG_UDP_QUEUE_CAP);
    // 组件自持 FxScope 记账（B6 t975）：UDP 快路 per-源会话任务（首包路径 spawn，
    // Go udp forwarder 语义），scope drop 兜底 abort。
    fx.spawn_tracked(run_wg_udp_session(
        Arc::clone(dispatch),
        cmd_rx,
        Arc::clone(netstack),
        src,
        dest,
        payload,
    ))
    .expect("internal FxScope is never closed");
    map.insert(src, WgUdpSession { cmd_tx, last_used_nanos: now });
}

/// 内层 UDP 会话 owner task（per-隧道内源，Go `udpConn` 等价物）。
///
/// 独占一个 [`UdpDispatchSession`]：
/// - 上行：cmd 队列（accept loop 非阻塞入队）→ `send_packet`（XUDP 帧 → dispatcher）
/// - 下行：`recv_packet` → 从**原目标** endpoint 发回 smoltcp（Go `writeUDP(payload, dst, src)`
///   语义），driver 定时器 drain_tx 加密发回 WG client。
///
/// 回包源取请求的原目标而非 XUDP 帧来源：帧来源是真实应答方，被 freedom override /
/// 代理链改写后对隧道内客户端不可达（Go `udp_fullcone.go` `Write` 用会话的 `c.dst`）。
///
/// 退出条件：cmd 口关闭（sweep/摘除）、outbound 关闭（`Ok(None)`）、收发 IO 错。
async fn run_wg_udp_session(
    dispatch: Arc<dyn DispatchHandler>,
    mut cmd_rx: mpsc::Receiver<WgUdpCmd>,
    netstack: Arc<AsyncMutex<WgNetStack>>,
    inner_src: IpEndpoint,
    first_dest: Destination,
    first_payload: Vec<u8>,
) {
    let mut session = UdpDispatchSession::new(dispatch);
    // 回包源 = 最近一次请求的原目标（会话换目标时跟随；Go 固定用建会话时的 dst）。
    let mut reply_src = address_to_ip_endpoint(first_dest.address(), first_dest.port().value());
    if let Err(e) = session.send_packet(&first_dest, &first_payload).await {
        crate::WG_LOG.warn(format!(
            "wg udp: first send_packet failed error={e} src={inner_src} dst={first_dest:?}"
        ));
        return;
    }
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(WgUdpCmd::Send { dest, payload }) => {
                    reply_src =
                        address_to_ip_endpoint(dest.address(), dest.port().value()).or(reply_src);
                    if let Err(e) = session.send_packet(&dest, &payload).await {
                        crate::WG_LOG.warn(format!(
                            "wg udp: send_packet failed error={e} src={inner_src} dst={dest:?}"
                        ));
                        return;
                    }
                },
                None => {
                    crate::WG_LOG.debug(format!("wg udp: session swept src={inner_src}"));
                    return;
                },
            },
            resp = session.recv_packet() => match resp {
                Ok(Some((source, payload))) => {
                    // 原目标仅 IP 包来源（内层数据报目标恒为 IP）；域名才退化为帧来源。
                    let Some(reply_src) = reply_src
                        .or_else(|| address_to_ip_endpoint(source.address(), source.port().value()))
                    else {
                        crate::WG_LOG.warn(format!(
                            "wg udp: reply source unusable, dropped src={inner_src} resp={source}"
                        ));
                        continue;
                    };
                    let mut stack = netstack.lock().await;
                    let sent = stack.udp_send_reply(reply_src, &payload, inner_src, nanos_now());
                    stack.poll(smoltcp::time::Instant::now());
                    if !sent {
                        crate::WG_LOG.warn(format!(
                            "wg udp: reply dropped (socket unavailable) src={inner_src} reply_src={reply_src:?}"
                        ));
                    }
                },
                Ok(None) => {
                    crate::WG_LOG.debug(format!("wg udp: outbound closed session src={inner_src}"));
                    return;
                },
                Err(e) => {
                    crate::WG_LOG
                        .warn(format!("wg udp: recv_packet failed error={e} src={inner_src}"));
                    return;
                },
            },
        }
    }
}

/// smoltcp TCP socket ↔ tokio duplex 中继 task（inbound 方向）。
///
/// 持有 duplex 的"远端" + netstack + socket handle，桥接 WG 侧的 smoltcp
/// TCP socket 与 dispatcher Link 的读写端。
///
/// # ponytail: 与 xray-proxy-tun/src/inbound.rs::TunTcpRelay 和
/// xray-proxy-wireguard/src/dispatcher.rs::TcpRelay 结构相同，仅 netstack 类型不同。
/// 第三个消费者已出现——后续提取共享 trait。
struct WgTcpRelay {
    /// 从 Link 写入端读取用户数据（up 方向）。
    from_client: tokio::io::DuplexStream,
    /// 向 Link 读取端写入 smoltcp 数据（down 方向）。
    to_client: tokio::io::DuplexStream,
    /// smoltcp 网栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// 已 accept 的 smoltcp TCP socket handle。
    handle: SocketHandle,
}

impl WgTcpRelay {
    /// 运行中继循环直到 socket 关闭或出错。
    async fn run(mut self) {
        let mut timer = tokio::time::interval(Duration::from_millis(RELAY_POLL_MS));
        // Go time.Ticker 丢 tick 不补发（Burst 是 tokio 默认）
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timer.tick().await; // 消掉首次立即触发

        loop {
            let mut user_buf = vec![0u8; 8192];
            tokio::select! {
                // down: dispatcher 写 link.writer 的响应数据 → smoltcp socket send → WG client
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
            // up: smoltcp socket recv（WG client 请求）→ link.reader 供 dispatcher 读取
            if self.recv_from_smoltcp().await {
                let _ = self.to_client.shutdown().await;
                self.finish().await;
                return;
            }
        }
    }

    /// 发送用户数据到 smoltcp TCP socket。
    ///
    /// `send_slice` 只接受 tx 缓冲当前空闲空间（SOCKET_BUF_SIZE=64KB），必须循环
    /// 写完为止：缓冲满期间释放 netstack 锁等待——driver 定时器 drain_tx 把数据
    /// 发上线路、WG client ACK 后空间才腾出；不释放会饿死唯一能推进发送的 task。
    /// 单次调用丢弃残余会让下行响应恰好在 64KB 处静默截断（票 gmhe 遗留，同
    /// dispatcher.rs::TcpRelay 修法；Go server.go:381-386 DispatchLink 全量拷贝无丢弃）。
    async fn send_to_smoltcp(&self, mut data: &[u8]) {
        let mut stack = self.netstack.lock().await;
        while !data.is_empty() {
            stack.poll(smoltcp::time::Instant::now());
            let (written, active) = stack.with_tcp_socket(self.handle, |s| {
                let written = if s.may_send() { s.send_slice(data).unwrap_or(0) } else { 0 };
                (written, s.is_active())
            });
            data = &data[written..];
            if !data.is_empty() && !active {
                // 对端已复位/关闭：残余无处可去，交由 run 循环的关闭路径收尾
                return;
            }
            if !data.is_empty() {
                drop(stack);
                tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
                stack = self.netstack.lock().await;
            }
        }
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

    /// 关闭 smoltcp socket 并从 SocketSet 移除。
    ///
    /// 票 97ng：`close()` 只把残留数据 + FIN 排进 tx 队列，慢客户端可能还有最多
    /// 一个 tx 缓冲（64KB）未 ACK。立即 `remove_socket` 会丢弃这部分数据、且迟到
    /// ACK 撞上无主 socket 被 smoltcp 回 RST——大响应在关闭瞬间被截断。关闭后继续
    /// poll（driver 定时器同步 drain_tx 发上线路）直到 FIN 被确认或超时再移除。
    async fn finish(&self) {
        let mut stack = self.netstack.lock().await;
        stack.with_tcp_socket(self.handle, |s| s.close());
        let deadline = xray_frame::compat::clock().now_instant() + FINISH_DRAIN_TIMEOUT;
        loop {
            stack.poll(smoltcp::time::Instant::now());
            let active = stack.with_tcp_socket(self.handle, |s| s.is_active());
            if !active || xray_frame::compat::clock().now_instant() >= deadline {
                break;
            }
            // 释放锁让位给 driver 定时器 drain_tx（唯一把 tx 发上线路的 task）
            drop(stack);
            tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
            stack = self.netstack.lock().await;
        }
        stack.remove_socket(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::atomic::AtomicU32};

    use xray_buf::multi::MultiBuffer;

    use super::*;
    use crate::{config::PeerConfig, driver::WgDriver};

    fn make_keypair(seed: u8) -> (String, String) {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes: [u8; 32] = [seed; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
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

    /// 空 driver 槽的合法注册表（accept loop 直测用，无需真 driver）。
    fn test_registry() -> Arc<WgUserRegistry> {
        Arc::new(
            WgUserRegistry::new(
                DeviceConfig { secret_key: "aa".repeat(32), ..Default::default() },
                Arc::new(ParkMutex::new(None)),
            )
            .expect("registry"),
        )
    }

    fn make_config(seed: u8) -> DeviceConfig {
        let (sec, pub_) = make_keypair(seed);
        DeviceConfig {
            secret_key: sec,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig { public_key: pub_, ..Default::default() }],
            ..Default::default()
        }
    }

    /// TOCTOU 加固：bind(:0)→drop→`WireguardInboundHandler::new`（构造期绑
    /// UDP）之间端口可能被并行测试/其他进程抢占（Windows 10048 / Unix
    /// EADDRINUSE）——占用时换端口重试至多 5 次。返回实际端口与 handler。
    async fn new_handler_retrying(
        tag: &str,
        cfg: &DeviceConfig,
        dispatch: Arc<dyn DispatchHandler>,
    ) -> (u16, WireguardInboundHandler) {
        for _ in 0..5 {
            let port = xray_common::testing::pick_free_ports(1).await[0];
            match WireguardInboundHandler::new(tag, cfg, port, Arc::clone(&dispatch)).await {
                Ok(h) => return (port, h),
                Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
                Err(e) => panic!("{tag}: wg inbound construct: {e:?}"),
            }
        }
        panic!("{tag}: wg inbound bind: EADDRINUSE persisted across 5 port retries");
    }

    #[tokio::test]
    async fn construct_inbound_handler() {
        let (dispatch, _) = make_dispatch();
        let cfg = make_config(0x66);
        let (_port, _h) = new_handler_retrying("test", &cfg, dispatch).await;
    }

    #[tokio::test]
    async fn construct_allows_no_peers() {
        // bd 7v0k③：peers 空允许启动（Go 官方空配置 + API 建户），旧实现拒绝
        let (dispatch, _) = make_dispatch();
        let (sec, _) = make_keypair(0x77);
        let cfg = DeviceConfig { secret_key: sec, ..Default::default() };
        let result = WireguardInboundHandler::new("test", &cfg, 0, dispatch).await;
        let handler = result.expect("empty peers must construct (Go empty config + API 建户)");
        assert_eq!(handler.user_registry().users_count(), 0);
    }

    #[tokio::test]
    async fn start_close_lifecycle() {
        let (dispatch, _) = make_dispatch();
        let cfg = make_config(0x88);
        let (port, h) = new_handler_retrying("test", &cfg, dispatch).await;
        assert_eq!(h.port(), port);
        assert_eq!(h.tag(), "test");

        // start
        h.start().await.expect("start");
        // double start 应失败
        let result = h.start().await;
        assert!(result.is_err(), "double start should fail");

        // close
        h.close().await.expect("close");
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
    fn ip_endpoint_to_destination_none() {
        assert!(ip_endpoint_to_destination(&None).is_none());
    }
    /// 测试用 DispatchHandler——记录 (dest, 请求 payload) 并回写固定响应；
    /// dispatch_with_access 额外捕获 access 上下文（bd ttni user 归属验证）。
    #[derive(Debug)]
    struct EchoDispatch {
        tag: String,
        response: Vec<u8>,
        seen: SeenLog,
        access_seen: Arc<ParkMutex<Vec<AccessContext>>>,
    }

    /// (dest, 请求 payload) 记录表共享句柄。
    type SeenLog = Arc<ParkMutex<Vec<(Destination, Vec<u8>)>>>;

    impl EchoDispatch {
        #[allow(clippy::type_complexity)] // 签名类型即业务语义，抽 type alias 反而更晦涩
        fn new(
            tag: &str,
            response: &[u8],
        ) -> (Arc<Self>, SeenLog, Arc<ParkMutex<Vec<AccessContext>>>) {
            let seen = Arc::new(ParkMutex::new(Vec::new()));
            let access_seen = Arc::new(ParkMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    tag: tag.into(),
                    response: response.to_vec(),
                    seen: Arc::clone(&seen),
                    access_seen: Arc::clone(&access_seen),
                }),
                seen,
                access_seen,
            )
        }
    }

    impl DispatchHandler for EchoDispatch {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn dispatch_with_access(
            &self,
            dest: &Destination,
            link: Link,
            access: AccessContext,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.access_seen.lock().push(access);
            self.dispatch(dest, link)
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            let response = self.response.clone();
            let seen = Arc::clone(&self.seen);
            let dest = dest.clone();
            Box::pin(async move {
                let mut r = link.reader;
                let mut w = link.writer;
                let mb = match r.read_multi_buffer().await {
                    Ok(mb) if !mb.is_empty() => mb,
                    _ => return,
                };
                seen.lock().push((dest.clone(), mb.to_vec()));
                let mut resp = MultiBuffer::new();
                resp.merge_bytes(&response);
                let _ = w.write_multi_buffer(resp).await;
            })
        }
    }

    /// 大响应回归专用 dispatch：写完响应后挂起等放行，保持 link（进而 relay 侧
    /// smoltcp socket）存活到客户端确认收满。写完即 drop link 会让 relay 收 EOF
    /// → finish() 在数据仍在途时 close+remove socket，负载下制造关闭竞态。
    #[derive(Debug)]
    struct HoldEchoDispatch {
        tag: String,
        response: Vec<u8>,
        release: Arc<tokio::sync::Notify>,
    }

    impl HoldEchoDispatch {
        fn new(tag: &str, response: &[u8]) -> (Arc<Self>, Arc<tokio::sync::Notify>) {
            let release = Arc::new(tokio::sync::Notify::new());
            (
                Arc::new(Self {
                    tag: tag.into(),
                    response: response.to_vec(),
                    release: Arc::clone(&release),
                }),
                release,
            )
        }
    }

    impl DispatchHandler for HoldEchoDispatch {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            link: Link,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            let response = self.response.clone();
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                let mut r = link.reader;
                let mut w = link.writer;
                let req = match r.read_multi_buffer().await {
                    Ok(mb) if !mb.is_empty() => mb,
                    _ => return,
                };
                drop(req); // 请求内容本测试不关心，读完即触发回灌
                let mut resp = MultiBuffer::new();
                resp.merge_bytes(&response);
                let _ = w.write_multi_buffer(resp).await;
                // 客户端收满 192KB 才 notify；notify_one 的 permit 语义兜底
                release.notified().await;
            })
        }
    }

    /// accept loop 接线：SYN 驱动惰性建听 → 三次握手 → drain → dispatch 被调用。
    #[tokio::test]
    async fn accept_loop_lazy_listen_dispatches_syn() {
        use smoltcp::{
            time::Instant,
            wire::{IpAddress, IpCidr, Ipv4Address},
        };

        use crate::netstack::test_packets::{TCP_ACK, TCP_SYN, make_tcp_packet, tcp_seq_number};

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<WgNetStack>> =
            Arc::new(AsyncMutex::new(WgNetStack::new(&[local], 1420)));
        let (dispatch, calls) = make_dispatch();
        let registry = test_registry();
        xray_common::testing::spawn(
            "accept-loop-lazy-listen-dispatches-syn",
            wg_accept_loop(
                Arc::clone(&netstack),
                registry,
                dispatch,
                Arc::new(skeleton_infra::fx::FxScope::new()),
            ),
        );

        // 隧道内 client 10.0.0.2:5555 → server 10.0.0.1:80 的 SYN
        {
            let mut stack = netstack.lock().await;
            stack.ingest_rx(make_tcp_packet(
                ([10, 0, 0, 2], 5555),
                ([10, 0, 0, 1], 80),
                TCP_SYN,
                1000,
                0,
            ));
            stack.poll(Instant::now());
        }

        // 无 driver 时 tx_queue 由测试侧 drain——取 SYN-ACK 的 ISN
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
        let server_seq = loop {
            let seq = {
                let mut stack = netstack.lock().await;
                stack.drain_tx().iter().find_map(|p| tcp_seq_number(p))
            };
            if let Some(seq) = seq {
                break seq;
            }
            assert!(xray_frame::compat::clock().now_instant() < deadline, "no SYN-ACK within 5s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        {
            let mut stack = netstack.lock().await;
            stack.ingest_rx(make_tcp_packet(
                ([10, 0, 0, 2], 5555),
                ([10, 0, 0, 1], 80),
                TCP_ACK,
                1001,
                server_seq + 1,
            ));
            stack.poll(Instant::now());
        }

        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) == 0 {
            assert!(xray_frame::compat::clock().now_instant() < deadline, "no dispatch within 5s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 端到端：真 WG client（WgDriver）经 UDP loopback 隧道内 TCP 连 Rust wg
    /// server inbound，请求数据 echo 往返。无 Go 标准客户端环境，以
    /// boringtun Rust↔Rust 全隧道（真 noise 握手 + 真加密 IP 包）替代。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试断言期 guard 有意存活
    async fn tunnel_tcp_end_to_end_echoes() {
        use std::net::SocketAddr;

        use smoltcp::{
            time::Instant,
            wire::{IpAddress, IpCidr, Ipv4Address},
        };

        const TUNNEL_TCP_PORT: u16 = 8080;
        let (sec_c, pub_c) = make_keypair(0x11);
        let (sec_s, pub_s) = make_keypair(0x22);

        let server_cfg = DeviceConfig {
            secret_key: sec_s,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_c.clone(),
                allowed_ips: vec!["10.0.0.2/32".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (dispatch, seen, access_seen) = EchoDispatch::new("wg-e2e-out", b"echo:pong");
        let (udp_port, server) = new_handler_retrying("wg-e2e", &server_cfg, dispatch).await;
        server.start().await.expect("server start");

        // bd ttni：AddUser（同公钥原位替换静态 peer）后，dispatch 携带
        // per-user 上下文（Go server.go:352-364 GetUserByAddr → session.Inbound）
        server
            .user_registry()
            .add_user(
                "u@wg",
                3,
                PeerConfig {
                    public_key: pub_c,
                    allowed_ips: vec!["10.0.0.2/32".into()],
                    ..Default::default()
                },
            )
            .expect("add user");
        // client：单 peer WgDriver（driver_pair_handshake_with_multiple_workers 同骨架）
        let client_cfg = DeviceConfig {
            secret_key: sec_c,
            endpoint: vec!["10.0.0.2/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_s,
                endpoint: format!("127.0.0.1:{udp_port}"),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client_peer = shared_peer(&client_cfg, &client_cfg.peers[0], 0).expect("client peer");
        let client_sock = bind_udp_socket("127.0.0.1:0").await.expect("client bind");
        let client_ns = Arc::new(AsyncMutex::new(WgNetStack::new(
            &[IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 32)],
            1420,
        )));
        let client = Arc::new(WgDriver::new(client_peer, client_sock, Arc::clone(&client_ns)));
        client.set_remote(SocketAddr::from(([127, 0, 0, 1], udp_port)));
        xray_common::testing::spawn(
            "tunnel-tcp-end-to-end-echoes",
            Arc::clone(&client).main_loop(),
        );

        // 隧道内 TCP connect 10.0.0.1:8080
        let handle = {
            let mut s = client_ns.lock().await;
            let h = s.add_tcp_socket();
            s.tcp_connect(h, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), TUNNEL_TCP_PORT)
                .expect("tcp connect");
            h
        };

        // 驱动 client 侧 TCP：发 ping，收 echo
        let mut sent = false;
        let mut got: Vec<u8> = Vec::new();
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(15);
        while !got.starts_with(b"echo:pong") {
            assert!(
                xray_frame::compat::clock().now_instant() < deadline,
                "tcp echo not received in 15s; got={got:?}"
            );
            {
                let mut s = client_ns.lock().await;
                s.poll(Instant::now());
                s.with_tcp_socket(handle, |sock| {
                    if sock.may_send() && !sent {
                        let _ = sock.send_slice(b"ping");
                        sent = true;
                    }
                    let mut buf = [0u8; 64];
                    let n = sock.recv_slice(&mut buf).unwrap_or(0);
                    got.extend_from_slice(&buf[..n]);
                });
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // server 侧记录：destination = 隧道内目标，payload = 请求
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
        while seen.lock().is_empty() {
            assert!(
                xray_frame::compat::clock().now_instant() < deadline,
                "dispatch not recorded in 5s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
        let s = seen.lock();
        let (dest, payload) = &s[0];
        assert_eq!(dest.network(), Network::TCP);
        assert_eq!(dest.address(), &Address::IPv4("10.0.0.1".parse().unwrap()));
        assert_eq!(dest.port().value(), TUNNEL_TCP_PORT);
        assert_eq!(payload, b"ping");

        // bd ttni：dispatch 携带的 user 上下文来自 GetUserByAddr(10.0.0.2)
        #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
        let acc = access_seen.lock();
        let ctx = acc.last().expect("dispatch_with_access captured");
        assert_eq!(ctx.email, "u@wg", "user email 挂接");
        assert_eq!(ctx.level, 3, "user level 挂接");
        assert!(ctx.from.starts_with("10.0.0.2"), "from = 隧道内源地址，got {}", ctx.from);
        assert_eq!(ctx.inbound_tag, "", "inbound_tag 由生产入口填充");

        server.close().await.expect("server close");
    }

    /// 票 gmhe 遗留回归：响应 > smoltcp tx 缓冲（SOCKET_BUF_SIZE=64KB）时
    /// WgTcpRelay::send_to_smoltcp 必须循环写满不丢字节。回灌 192KB（3 × 缓冲），
    /// client 慢读制造缓冲满，逐字节比对。
    ///
    /// 确定性机制（票 odaw，原 `#[ignore]` 已去）：
    /// ① 流保持打开：HoldEchoDispatch 写完不 drop link，等测试确认收满后放行。
    ///    原写法 dispatch 写完即 EOF → relay finish() 在数据仍在途时
    ///    close()+remove_socket()，客户端后续 ACK 撞上无主 socket 被 smoltcp
    ///    回 RST（iface/interface/tcp.rs 对未命中包即回 RST），尾部 WG 包又已无
    ///    重传保障 → client 提前 !is_active() 假报截断（空载全靠时序赢）。
    ///    EOF 推迟到收满之后，关闭竞态整体消失。
    /// ② 读端确定性节流：固定 4KB/轮；仅零进展轮（等隧道往返）睡 5ms，
    ///    有进展轮只 yield_now——推进不依赖调度快慢。
    /// ③ 满缓冲硬断言：client rx 打满 recv_capacity()（= 广告零窗 → 服务端
    ///    tx 必满 → relay 必经 written==0 停泵重试）且零进展轮 ≥1，缺一即红，
    ///    防退化成安慰剂绿。
    #[tokio::test]
    #[allow(clippy::print_stderr)] // 吞吐/停轮诊断输出（assert 语义的一部分）
    async fn tunnel_tcp_inbound_large_response_no_truncation() {
        use std::net::SocketAddr;

        use smoltcp::{
            time::Instant,
            wire::{IpAddress, IpCidr, Ipv4Address},
        };

        const TUNNEL_TCP_PORT: u16 = 8080;
        const PAYLOAD_LEN: usize = 192 * 1024;
        let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();

        let (sec_c, pub_c) = make_keypair(0x11);
        let (sec_s, pub_s) = make_keypair(0x22);

        let server_cfg = DeviceConfig {
            secret_key: sec_s,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_c.clone(),
                allowed_ips: vec!["10.0.0.2/32".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (dispatch, release) = HoldEchoDispatch::new("wg-e2e-large", &payload);
        let (udp_port, server) = new_handler_retrying("wg-e2e-large", &server_cfg, dispatch).await;
        server.start().await.expect("server start");
        server
            .user_registry()
            .add_user(
                "u@wg",
                3,
                PeerConfig {
                    public_key: pub_c,
                    allowed_ips: vec!["10.0.0.2/32".into()],
                    ..Default::default()
                },
            )
            .expect("add user");

        let client_cfg = DeviceConfig {
            secret_key: sec_c,
            endpoint: vec!["10.0.0.2/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_s,
                endpoint: format!("127.0.0.1:{udp_port}"),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client_peer = shared_peer(&client_cfg, &client_cfg.peers[0], 0).expect("client peer");
        let client_sock = bind_udp_socket("127.0.0.1:0").await.expect("client bind");
        let client_ns = Arc::new(AsyncMutex::new(WgNetStack::new(
            &[IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 32)],
            1420,
        )));
        let client = Arc::new(WgDriver::new(client_peer, client_sock, Arc::clone(&client_ns)));
        client.set_remote(SocketAddr::from(([127, 0, 0, 1], udp_port)));
        xray_common::testing::spawn(
            "tunnel-tcp-inbound-large-response-no-truncation",
            Arc::clone(&client).main_loop(),
        );

        let handle = {
            let mut s = client_ns.lock().await;
            let h = s.add_tcp_socket();
            s.tcp_connect(h, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), TUNNEL_TCP_PORT)
                .expect("tcp connect");
            h
        };

        // 阶段 A（确定性造满）：只 poll 不读，直到 rx 队列填满。
        // 不能依赖「读得比数据到得慢」——Linux 上轮询循环可能比数据到达快，
        // 队列永远不满，测试前置条件失效（CI ubuntu/macos 实测）。
        let mut sent = false;
        let mut hit_rx_full = false;
        let fill_deadline =
            xray_frame::compat::clock().now_instant() + std::time::Duration::from_secs(15);
        while !hit_rx_full && xray_frame::compat::clock().now_instant() < fill_deadline {
            let mut s = client_ns.lock().await;
            s.poll(Instant::now());
            s.with_tcp_socket(handle, |sock| {
                if sock.recv_queue() == sock.recv_capacity() {
                    hit_rx_full = true;
                }
                if sock.may_send() && !sent {
                    let _ = sock.send_slice(b"ping");
                    sent = true;
                }
            });
            drop(s);
            if !hit_rx_full {
                tokio::task::yield_now().await;
            }
        }

        // 阶段 B：正常慢读排空（4KB/轮）。
        let mut got: Vec<u8> = Vec::new();
        let started = xray_frame::compat::clock().now_instant();
        let mut stall_rounds: u32 = 0;
        while got.len() < PAYLOAD_LEN {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "large response incomplete: got {}/{} (stall_rounds={stall_rounds})",
                got.len(),
                PAYLOAD_LEN
            );
            let before = got.len();
            let mut closed = false;
            {
                let mut s = client_ns.lock().await;
                s.poll(Instant::now());
                s.with_tcp_socket(handle, |sock| {
                    // 满缓冲观测点必须在排空之前：poll 后 rx 处于本轮峰值
                    if sock.recv_queue() == sock.recv_capacity() {
                        hit_rx_full = true;
                    }
                    if sock.may_send() && !sent {
                        let _ = sock.send_slice(b"ping");
                        sent = true;
                    }
                    let mut buf = [0u8; 4096];
                    let n = sock.recv_slice(&mut buf).unwrap_or(0);
                    got.extend_from_slice(&buf[..n]);
                    closed = !sock.is_active();
                });
            }
            if closed && got.len() < PAYLOAD_LEN {
                panic!("response truncated: got {}/{}", got.len(), PAYLOAD_LEN);
            }
            if got.len() == before {
                stall_rounds += 1;
                // 零进展 = 在等隧道往返（服务端 tx 满/零窗）：让位而非盲睡
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
        let elapsed = started.elapsed();

        // 满缓冲必要条件，缺一即红（防止没经过满缓冲的安慰剂绿）
        assert!(hit_rx_full, "client rx never full: buffer-full path not exercised");
        assert_eq!(got.len(), PAYLOAD_LEN, "byte count");
        assert!(got == payload, "content mismatch");
        eprintln!(
            "large-response: {PAYLOAD_LEN}B in {elapsed:?}, stall_rounds={stall_rounds}, hit_rx_full={hit_rx_full}"
        );

        // 收满后放行 dispatch 任务，relay 走正常关闭路径
        release.notify_one();
        server.close().await.expect("server close");
    }

    /// 票 97ng 回归：dispatch 写完响应**立即** drop link 时，relay 收 EOF 走
    /// finish()——必须等残留 tx 数据被 ACK 后再摘 socket。
    ///
    /// 确定性现场：连接后**先发请求**触发回灌，客户端随后停读 1.5s（smoltcp rx
    /// 打满 → 广告零窗 → 服务端 tx 缓冲必满），此时 dispatch 已 drop link、
    /// relay 已进 finish()。修前：立即 remove_socket 丢弃缓冲内未 ACK 数据，
    /// 客户端恢复读后尾部缺失（`!is_active()` 提前关闭）。修后：等 FIN ACK 再摘。
    #[tokio::test]
    async fn tunnel_tcp_inbound_dispatch_eof_flushes_tail() {
        use std::net::SocketAddr;

        use smoltcp::{
            time::Instant,
            wire::{IpAddress, IpCidr, Ipv4Address},
        };

        const TUNNEL_TCP_PORT: u16 = 8081;
        const PAYLOAD_LEN: usize = 128 * 1024;
        let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();

        let (sec_c, pub_c) = make_keypair(0x33);
        let (sec_s, pub_s) = make_keypair(0x44);

        let server_cfg = DeviceConfig {
            secret_key: sec_s,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_c.clone(),
                allowed_ips: vec!["10.0.0.2/32".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (dispatch, release) = HoldEchoDispatch::new("wg-e2e-97ng", &payload);
        let (udp_port, server) = new_handler_retrying("wg-e2e-97ng", &server_cfg, dispatch).await;
        server.start().await.expect("server start");
        server
            .user_registry()
            .add_user(
                "u@wg",
                3,
                PeerConfig {
                    public_key: pub_c,
                    allowed_ips: vec!["10.0.0.2/32".into()],
                    ..Default::default()
                },
            )
            .expect("add user");

        let client_cfg = DeviceConfig {
            secret_key: sec_c,
            endpoint: vec!["10.0.0.2/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_s,
                endpoint: format!("127.0.0.1:{udp_port}"),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client_peer = shared_peer(&client_cfg, &client_cfg.peers[0], 0).expect("client peer");
        let client_sock = bind_udp_socket("127.0.0.1:0").await.expect("client bind");
        let client_ns = Arc::new(AsyncMutex::new(WgNetStack::new(
            &[IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 32)],
            1420,
        )));
        let client = Arc::new(WgDriver::new(client_peer, client_sock, Arc::clone(&client_ns)));
        client.set_remote(SocketAddr::from(([127, 0, 0, 1], udp_port)));
        xray_common::testing::spawn(
            "tunnel-tcp-inbound-dispatch-eof-flushes-tail",
            Arc::clone(&client).main_loop(),
        );

        let handle = {
            let mut s = client_ns.lock().await;
            let h = s.add_tcp_socket();
            s.tcp_connect(h, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), TUNNEL_TCP_PORT)
                .expect("tcp connect");
            h
        };

        // dispatch 写完响应即放行（drop link）——97ng 竞态条件
        release.notify_one();

        // ① 先把请求发出去触发回灌（握手可能还需重试，轮询到发出为止）
        let mut sent = false;
        let send_deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(10);
        while !sent && xray_frame::compat::clock().now_instant() < send_deadline {
            let mut s = client_ns.lock().await;
            s.poll(Instant::now());
            s.with_tcp_socket(handle, |sock| {
                if sock.may_send() {
                    sent = sock.send_slice(b"ping").is_ok();
                }
            });
            drop(s);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(sent, "request never sent: handshake did not complete");

        // ② 停读 1.5s：回灌把客户端 rx 打满 → 服务端 tx 缓冲满 → relay 在此窗口内 finish()
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // ③ 恢复读：修前尾部已丢（提前 !is_active 或收不满）
        let mut got: Vec<u8> = Vec::new();
        let started = xray_frame::compat::clock().now_instant();
        while got.len() < PAYLOAD_LEN {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "response incomplete: got {}/{}",
                got.len(),
                PAYLOAD_LEN
            );
            let before = got.len();
            let mut closed = false;
            {
                let mut s = client_ns.lock().await;
                s.poll(Instant::now());
                s.with_tcp_socket(handle, |sock| {
                    let mut buf = [0u8; 4096];
                    let n = sock.recv_slice(&mut buf).unwrap_or(0);
                    got.extend_from_slice(&buf[..n]);
                    closed = !sock.is_active();
                });
            }
            if closed && got.len() < PAYLOAD_LEN {
                panic!("response truncated at dispatch EOF: got {}/{}", got.len(), PAYLOAD_LEN);
            }
            if got.len() == before {
                tokio::time::sleep(Duration::from_millis(2)).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
        assert!(got == payload, "content mismatch");

        server.close().await.expect("server close");
    }
}
