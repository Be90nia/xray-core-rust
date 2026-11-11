//! MASQUE 服务端（Go `proxy/masque/server.go` 直译形态，规划 B4.3）。
//!
//! 管线（Go `Process` 对应）：hub 闸门（[`MasqueServer::gate`]：Basic 认证常数
//! 时间比较 + 地址池分配）→ [`TunnelAcceptor`]（process_tunnel）→ accept 隧道
//! → `assign_addresses` + `advertise_route`（全路由）→ 包路由：
//! - 隧道间转发：目的地址命中其他隧道 → 该隧道 512 有界队列（Go `server.go:37
//!   tunnelQueueSize`），满丢弃 + 计数；
//! - 池内未分配地址：丢弃；发往服务器自身地址：进本机栈；
//! - 本机栈（[`xray_frame::ipstack::PacketStack`]）：TCP accept → duplex 中继 →
//!   `DispatchHandler`；UDP → per-源 [`UdpDispatchSession`]（Go `HandleConnection` / udp forwarder
//!   对应面）。
//!
//! 栈桥与 wireguard `inbound.rs` 同构（其件头已预告第三消费方）；公共提炼归
//! `xray-app-dispatcher` 需引入 smoltcp 依赖——依赖方向归 PM 裁决，本批自持
//! （见 crate 文档）。

use std::{collections::HashMap, io, net::IpAddr, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use xray_app_dispatcher::{AccessContext, DispatchHandler, UdpDispatchSession};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_frame::{ipstack::PacketStack, scope::ComponentScope};
use xray_transport::{
    dialer::StreamSettings,
    finalmask::{self, TcpmaskManager},
    listener_registry::TransportListener,
    sockopt::SocketOptions,
};
use xray_transport_masque::{
    capsule::{AddressRequestEntry, AssignedAddress, IpPrefix, IpRoute},
    connect::{ConnectIpSession, MIN_PACKET_SIZE, SessionWriter},
    hub::{self, GateDeny, GateGrant, RequestMeta, ServerConn, TunnelAcceptor, TunnelGate},
    pool::AddressPool,
};

use crate::{LOG, MASQUE_PROTOCOL};

/// 隧道间转发有界队列（Go `server.go:37 tunnelQueueSize = 512`）。
const TUNNEL_QUEUE_SIZE: usize = 512;

/// 栈 driver 轮询间隔（wireguard accept loop 同档；Go readFromStack 是阻塞
/// 泵，本仓轮询形态取 accept 桥同值）。
const DRIVER_POLL_MS: u64 = 50;

/// 栈内 UDP 会话队列（wireguard WG_UDP_QUEUE_CAP 同值 64）。
const UDP_QUEUE_CAP: usize = 64;

/// 栈内 UDP 会话空闲超时（秒；wireguard WG_UDP_SESSION_IDLE_SECS 同值 30）。
const UDP_SESSION_IDLE_SECS: u64 = 30;

/// duplex 缓冲（wireguard DUPLEX_BUF 同值）。
const DUPLEX_BUF: usize = 64 * 1024;

// ===== 配置解析（Go `infra/conf/masque.go MasqueServerConfig.Build` 同规） =====

/// 服务端用户（Go `MasqueUserConfig`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueUser {
    /// 用户 email（validator 键，小写归一；日志面只记本字段）。
    pub email: String,
    /// Basic 密码（SecretMasking：禁进日志）。
    pub password: String,
    /// 认证用户策略层级（Go `level`）。
    pub level: u32,
}

/// 服务端 settings（`parse_server_settings` 产物）。
#[derive(Debug, Clone)]
pub struct MasqueServerSettings {
    /// 认证用户表。
    pub users: Vec<MasqueUser>,
    /// 地址前缀（每族最多一；`ip/prefix_len` 形态）。
    pub addresses: Vec<IpPrefix>,
    /// 隧道 MTU（缺省 [`MIN_PACKET_SIZE`]）。
    pub mtu: usize,
}

/// settings JSON → [`MasqueServerSettings`]（Go `MasqueServerConfig.Build` 同规；
/// `clients` 是 `users` 的 Go 别名键）。
///
/// 与 Go 的差异（任务书验收 1 明文）：`users` 为空数组/缺失 → `Err`（Go 只查
/// address，空 users 表 = 认证恒败的静默形态——本仓 fail-visible）。
pub fn parse_server_settings(v: &serde_json::Value) -> Result<MasqueServerSettings, String> {
    // clients 别名（Go :56-58 `if c.Clients != nil { c.Users = c.Clients }`；
    // users 存在时优先）。
    let users_json = v.get("users").or_else(|| v.get("clients"));
    let Some(list) = users_json.and_then(|u| u.as_array()) else {
        return Err("\"users\" is not set (MASQUE server requires at least one user)".into());
    };
    if list.is_empty() {
        return Err("\"users\" is empty (MASQUE server requires at least one user)".into());
    }
    let mut users = Vec::with_capacity(list.len());
    for u in list {
        let password = u.get("pass").and_then(|p| p.as_str()).unwrap_or_default().to_owned();
        if password.is_empty() {
            return Err("empty password for user".into());
        }
        users.push(MasqueUser {
            email: u.get("email").and_then(|e| e.as_str()).unwrap_or_default().to_owned(),
            password,
            level: u.get("level").and_then(|l| l.as_u64()).unwrap_or(0).min(u32::MAX as u64) as u32,
        });
    }

    // address[]（Go :66-86）：非空 + 解析 + 每族最多一前缀。
    let Some(addrs) = v.get("address").and_then(|a| a.as_array()) else {
        return Err("\"address\" is not set".into());
    };
    if addrs.is_empty() {
        return Err("\"address\" is empty".into());
    }
    let mut addresses = Vec::new();
    let mut has_v4 = false;
    let mut has_v6 = false;
    for s in addrs {
        let text = s.as_str().ok_or("address entries must be strings")?;
        let (ip_text, len_text) = text
            .split_once('/')
            .ok_or_else(|| format!("invalid address {text:?}: expected \"ip/prefix_len\""))?;
        let addr: IpAddr = ip_text.parse().map_err(|e| format!("invalid address {text:?}: {e}"))?;
        let prefix_len: u8 =
            len_text.parse().map_err(|_| format!("invalid address {text:?}: bad prefix length"))?;
        let is_v4 = addr.is_ipv4();
        if (is_v4 && has_v4) || (!is_v4 && has_v6) {
            return Err("only one address per IP family is supported".into());
        }
        if is_v4 {
            has_v4 = true;
        } else {
            has_v6 = true;
        }
        let prefix = IpPrefix { addr, prefix_len };
        // 池边界校验（网络/广播/无可分配；R10 三条）。
        AddressPool::new(prefix.clone()).map_err(|e| e.to_string())?;
        addresses.push(prefix);
    }

    // mtu（Go :92-94）：0 = 缺省；否则 [1280, 65535]。
    let mtu_raw = v.get("mtu").and_then(|m| m.as_u64()).unwrap_or(0);
    let mtu = if mtu_raw == 0 {
        MIN_PACKET_SIZE
    } else {
        usize::try_from(mtu_raw).map_err(|_| "\"mtu\" overflow".to_string())?;
        let mtu_raw_usize = mtu_raw as usize;
        if !(MIN_PACKET_SIZE..=65_535).contains(&mtu_raw_usize) {
            return Err("\"mtu\" must be between 1280 and 65535".into());
        }
        mtu_raw as usize
    };

    Ok(MasqueServerSettings { users, addresses, mtu })
}

// ===== Validator（Go `proxy/masque/account.go` 直译） =====

/// 用户表（email 小写键；`get` 常数时间比较密码——Go `subtle.ConstantTimeCompare`）。
#[derive(Debug, Default)]
struct Validator {
    users: HashMap<String, MasqueUser>,
}

impl Validator {
    fn new(users: Vec<MasqueUser>) -> Self {
        let mut map = HashMap::with_capacity(users.len());
        for u in users {
            map.insert(u.email.to_lowercase(), u);
        }
        Self { users: map }
    }

    /// 认证（Go `validator.get`）：密码比较常数时间（长度无关路径——逐字节
    /// 累积 diff，避免提前返回；email 命中后仍全量比较以抹平时序）。
    fn get(&self, email: &str, password: &str) -> Option<&MasqueUser> {
        let user = self.users.get(&email.to_lowercase())?;
        let expected = user.password.as_bytes();
        let provided = password.as_bytes();
        // 常数时间比较（subtle.ConstantTimeCompare 语义）：长度先比（Go 同形——
        // 长度差返回 0 不进比较循环），逐字节 XOR 累积。
        let mut diff = (expected.len() ^ provided.len()) as u8;
        let n = expected.len().max(provided.len());
        for i in 0..n {
            let a = expected.get(i).copied().unwrap_or(0);
            let b = provided.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }
        if diff == 0 { Some(user) } else { None }
    }
}

// ===== 隧道句柄与服务器 =====

/// 活跃隧道句柄（Go `serverTunnel` 的路由面；写泵独占消费 queue）。
struct TunnelHandle {
    /// 隧道间转发队列（512 有界；`try_send` 满 = 丢弃，Go `t.send` 同语义）。
    queue_tx: mpsc::Sender<Vec<u8>>,
    /// 隧道归属用户 email（AccessContext.email；Go `t.user.Email`）。
    user_email: String,
    /// 归属用户层级（AccessContext.level）。
    user_level: u32,
}

impl TunnelHandle {
    /// 非阻塞投递（Go `serverTunnel.send`：满/关 = false）。
    fn send(&self, pkt: Vec<u8>) -> bool {
        self.queue_tx.try_send(pkt).is_ok()
    }
}

/// gate 分配结果（经 [`GateGrant::extra`] opaque 传递给 acceptor）。
struct TunnelAllocation {
    addrs: Vec<IpAddr>,
}

/// MASQUE 服务端（Go `Server` 对应面）。
pub struct MasqueServer {
    tag: String,
    validator: Validator,
    /// 地址池（每族一；`std::sync::Mutex` 短临界区——gate 快路）。
    pools: Vec<std::sync::Mutex<AddressPool>>,
    /// 各池服务器自身地址（Go `s.local`；发往这些地址的包进本机栈）。
    local: Vec<IpAddr>,
    /// 活跃隧道表（分配地址 → 隧道；std Mutex 短临界区）。
    tunnels: std::sync::Mutex<HashMap<IpAddr, Arc<TunnelHandle>>>,
    /// 本机栈（Go `s.dev` = wireguard.CreateNetTUN 产物对应面）。
    stack: Arc<tokio::sync::Mutex<PacketStack>>,
    dispatch: Arc<dyn DispatchHandler>,
    /// §3.5.6 ①类托管：server 任务账本（driver loop + 隧道泵 + 栈桥）。
    scope: ComponentScope,
    closed: std::sync::atomic::AtomicBool,
}

impl MasqueServer {
    /// 构造服务端（Go `NewServer`）：建栈 + spawn driver loop。
    ///
    /// `scope` 由装配面持有（listener close 时经 [`Self::close`] 收口）。
    pub fn new(
        tag: impl Into<String>,
        settings: MasqueServerSettings,
        dispatch: Arc<dyn DispatchHandler>,
        scope: ComponentScope,
    ) -> io::Result<Arc<Self>> {
        let tag = tag.into();
        let mut pools = Vec::with_capacity(settings.addresses.len());
        let mut local = Vec::with_capacity(settings.addresses.len());
        for prefix in &settings.addresses {
            let pool = AddressPool::new(prefix.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            local.push(pool.server_addr());
            pools.push(std::sync::Mutex::new(pool));
        }
        // 本机栈地址 = 各池服务器自身地址（Go CreateNetTUN(local, nil, mtu, s)）。
        let cidrs: Vec<smoltcp::wire::IpCidr> =
            local.iter().map(|a| ip_to_cidr(*a, u8::MAX)).collect();
        let stack = Arc::new(tokio::sync::Mutex::new(PacketStack::new(&cidrs, settings.mtu)));
        let server = Arc::new(Self {
            tag,
            validator: Validator::new(settings.users),
            pools,
            local,
            tunnels: std::sync::Mutex::new(HashMap::new()),
            stack,
            dispatch,
            scope,
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        server.spawn_driver_loop();
        Ok(server)
    }

    /// 闸门（Basic 认证 + 地址分配；Go `Process` 前置段）。
    ///
    /// 认证失败 = 401 + `WWW-Authenticate`；无地址可分 = 503；分配结果经
    /// [`GateGrant::extra`] 传给 acceptor。日志只记 email（R8 SecretMasking）。
    #[must_use]
    pub fn gate(self: &Arc<Self>) -> TunnelGate {
        let server = Arc::clone(self);
        Arc::new(move |meta: &RequestMeta| {
            let (Some(user), Some(pass)) = (&meta.auth_user, &meta.auth_pass) else {
                LOG.warn(format!("masque: missing credentials from {}", meta.peer));
                return Err(GateDeny::Auth);
            };
            let Some(account) = server.validator.get(user, pass) else {
                // 401 面（Go :271-282：Reject + access rejected；只记 email 不记密码）。
                LOG.warn(format!("masque: authentication failed for {user} from {}", meta.peer));
                return Err(GateDeny::Auth);
            };
            let email = account.email.clone();
            let level = account.level;
            // 每池分配一址（Go :287-292）；无地址 = 503（Go :289-293）。
            let mut addrs = Vec::with_capacity(server.pools.len());
            for pool in &server.pools {
                let mut p = pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(addr) = p.allocate() {
                    addrs.push(addr);
                }
            }
            if addrs.is_empty() {
                LOG.warn(format!("masque: no address left to assign for {email}"));
                return Err(GateDeny::Unavailable);
            }
            LOG.info(format!(
                "masque: tunnel from {} assigned {addrs:?} (user {email})",
                meta.peer
            ));
            Ok(GateGrant {
                email,
                level,
                extra: Some(
                    Arc::new(TunnelAllocation { addrs }) as Arc<dyn std::any::Any + Send + Sync>
                ),
            })
        })
    }

    /// 隧道接受器（Go `addConn` → worker Process 对应面）。
    #[must_use]
    pub fn acceptor(self: &Arc<Self>) -> Arc<dyn TunnelAcceptor> {
        Arc::new(ServerAcceptor(Arc::clone(self)))
    }

    /// 关闭服务端（Go `Server.Close`）：关闸 + 关全部活跃隧道。
    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.scope.close_gate();
        let tunnels: Vec<Arc<TunnelHandle>> = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        // drop 隧道句柄 = queue 关闭 = 写泵退出；读泵随 scope cancel/EOF 收敛。
        let mut map = self.tunnels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        map.clear();
        drop(tunnels);
    }

    fn spawn_driver_loop(self: &Arc<Self>) {
        let server = Arc::clone(self);
        let _ = self.scope.spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_millis(DRIVER_POLL_MS));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            timer.tick().await; // 消掉首个立即 tick
            let udp_sessions: std::sync::Mutex<
                HashMap<smoltcp::wire::IpEndpoint, UdpSessionEntry>,
            > = std::sync::Mutex::new(HashMap::new());
            loop {
                timer.tick().await;
                let now = nanos_now();
                {
                    let mut stack = server.stack.lock().await;
                    stack.poll(smoltcp::time::Instant::now());
                    // 栈出站包 → 按目的路由到隧道（Go readFromStack；无隧道 = 丢）。
                    for pkt in stack.drain_tx() {
                        let Some(dst) = packet_destination(&pkt) else { continue };
                        let tunnel = server.lookup(&dst);
                        if let Some(t) = tunnel {
                            t.send(pkt);
                        }
                    }
                    // TCP accept → duplex 中继 + dispatch（Go HandleConnection 对应面）。
                    for event in stack.drain_accepted() {
                        server.bridge_tcp_accept(&mut stack, event);
                    }
                    // UDP → per-源会话（Go udp forwarder 对应面）。
                    for (dst, src, payload) in stack.drain_udp(now) {
                        forward_udp_datagram(&server, &udp_sessions, dst, src, payload, now);
                    }
                    // 老化清扫（wireguard 同款：UDP 会话 + TCP 监听槽）。
                    stack.sweep_udp(now, (UDP_SESSION_IDLE_SECS as i64) * 1_000_000_000);
                    stack.sweep_listens(now, (UDP_SESSION_IDLE_SECS as i64) * 1_000_000_000);
                }
                // UDP 会话表摘除（锁外判定过期）。
                sweep_udp_sessions(&udp_sessions, now);
            }
        });
    }

    /// 活跃隧道查表（Go `s.lookup`）。
    fn lookup(&self, addr: &IpAddr) -> Option<Arc<TunnelHandle>> {
        self.tunnels.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(addr).cloned()
    }

    /// 目的地址是否落在任一池前缀内（Go `s.inPool`）。
    fn in_pool(&self, addr: &IpAddr) -> bool {
        self.pools.iter().any(|p| {
            p.lock()
                .map(|p| p.prefix_contains(*addr))
                .unwrap_or_else(|e| e.into_inner().prefix_contains(*addr))
        })
    }

    /// TCP accept 桥（Go `HandleConnection` 对应面；锁内调用——同步 spawn 面）。
    fn bridge_tcp_accept(
        &self,
        stack: &mut PacketStack,
        event: xray_frame::ipstack::TcpAcceptEvent,
    ) {
        let Some(dest) = ip_endpoint_to_destination(event.local.as_ref()) else {
            LOG.warn(format!(
                "masque tcp accept: no local endpoint, dropping remote={}",
                event.remote
            ));
            stack.remove_socket(event.handle);
            return;
        };
        let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
        let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
        let link = xray_transport::link::Link::new(
            new_reader(client_from_relay),
            new_writer(client_to_relay),
        );
        let relay = crate::relay::StackTcpRelay {
            from_client: relay_from_client,
            to_client: relay_to_client,
            stack: Arc::clone(&self.stack),
            handle: event.handle,
        };
        let _ = self.scope.spawn(async move { relay.run().await });
        // AccessContext（Go :448-470 ContextWithAccessMessage 面；email/level 由
        // 隧道归属用户填充——注册表键 = 分配地址）。
        let src_ip = endpoint_to_ip(&event.remote.addr);
        let (email, level) = src_ip
            .and_then(|ip| self.lookup(&ip))
            .map(|t| (t.user_email.clone(), t.user_level))
            .unwrap_or_default();
        let access = AccessContext {
            from: event.remote.to_string(),
            email,
            level,
            inbound_tag: self.tag.clone(),
            inbound_name: MASQUE_PROTOCOL.to_owned(),
            ..Default::default()
        };
        let dispatch = Arc::clone(&self.dispatch);
        let _ = self.scope.spawn(async move {
            dispatch.dispatch_with_access(&dest, link, access).await;
        });
    }
}

/// 隧道 acceptor 壳（`MasqueServer` → `Arc<dyn TunnelAcceptor>`）。
struct ServerAcceptor(Arc<MasqueServer>);

impl TunnelAcceptor for ServerAcceptor {
    fn add_tunnel(&self, conn: ServerConn) {
        let server = Arc::clone(&self.0);
        let scope = server.scope.clone();
        let _ = scope
            .spawn(process_tunnel(server, conn))
            .map_err(|_| LOG.warn("masque: scope closed at shutdown, tunnel dropped"));
    }
}

/// 单隧道处理（Go `Process` 后半 + `readFromTunnel` + `serveAddressRequests` +
/// `writeToTunnel` 三泵合一本任务族）。
async fn process_tunnel(server: Arc<MasqueServer>, conn: ServerConn) {
    // gate 产物面（accept 消费 conn 前取出）。
    let email = conn.grant.email.clone();
    let level = conn.grant.level;
    // gate 分配结果（opaque 下转）。
    let addrs = conn
        .grant
        .extra
        .as_ref()
        .and_then(|a| a.downcast_ref::<TunnelAllocation>().map(|a| a.addrs.clone()))
        .unwrap_or_default();
    if addrs.is_empty() {
        let _ = conn.reject(GateDeny::Unavailable);
        return;
    }
    // accept：200 + upgraded IO（Go sconn.Accept()）。
    let stream = match conn.accept().await {
        Ok(s) => s,
        Err(e) => {
            LOG.warn(format!("masque: failed to accept the tunnel: {e}"));
            return;
        },
    };
    let mut session = ConnectIpSession::server_session(stream);
    // 地址分配 + 全路由通告（Go :305-317 AssignAddresses/AdvertiseRoute）。
    let mut writer = match session.writer() {
        Ok(w) => w,
        Err(e) => {
            LOG.warn(format!("masque: tunnel closed before configure: {e}"));
            return;
        },
    };

    let prefixes: Vec<IpPrefix> =
        addrs.iter().map(|a| IpPrefix { addr: *a, prefix_len: ip_bit_len(*a) }).collect();
    if let Err(e) = writer.assign_addresses(&prefixes) {
        LOG.warn(format!("masque: assign_addresses failed: {e}"));
        return;
    }
    if let Err(e) = writer.advertise_route(&full_routes(&addrs)) {
        LOG.warn(format!("masque: advertise_route failed: {e}"));
        return;
    }

    // 注册隧道表（Go s.register；server 关闭态 = 拒）。
    let queue_tx = {
        let (queue_tx, mut queue_rx) = mpsc::channel(TUNNEL_QUEUE_SIZE);
        {
            let mut map = server.tunnels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if server.closed.load(std::sync::atomic::Ordering::SeqCst) {
                LOG.warn("masque: server closed, tunnel rejected");
                return;
            }
            for addr in &addrs {
                map.insert(
                    *addr,
                    Arc::new(TunnelHandle {
                        queue_tx: queue_tx.clone(),
                        user_email: email.clone(),
                        user_level: level,
                    }),
                );
            }
        }
        // 写泵（Go writeToTunnel）：队列 → send_packet；ICMP 回灌进栈。
        let pump_writer = match session.writer() {
            Ok(w) => w,
            Err(e) => {
                LOG.warn(format!("masque: tunnel closed before configure: {e}"));
                return;
            },
        };
        let stack = Arc::clone(&server.stack);
        let _ = server.scope.spawn(async move {
            let mut writer = pump_writer;
            while let Some(pkt) = queue_rx.recv().await {
                match writer.send_packet(&pkt).await {
                    Ok(Some(icmp)) => {
                        let mut s = stack.lock().await;
                        s.ingest_rx(icmp);
                        s.poll(smoltcp::time::Instant::now());
                    },
                    Ok(None) => {},
                    Err(_) => return,
                }
            }
        });
        queue_tx
    };
    drop(queue_tx); // 表内句柄持克隆；本任务只留所有权转移记录

    // 读泵（Go readFromTunnel）：隧道包 → 隧道间转发 / 本机栈。
    // 本隧道句柄（Go other != t 的回环判定锚：注册表命中的是自己的地址 =
    // 目的地址是本隧道分配地址 = 回环，丢弃）。
    let self_handle = addrs.first().and_then(|a| server.lookup(a));
    let mut request_rx = session.take_request_rx();
    loop {
        tokio::select! {
            pkt = session.recv_packet() => match pkt {
                Ok(packet) => {
                    let Some(dst) = packet_destination(&packet) else { continue };
                    if is_link_local_or_multicast(&dst) {
                        continue;
                    }
                    if let Some(other) = server.lookup(&dst) {
                        // 隧道间转发（Go :405-413）：命中其他隧道 → 512 有界
                        // 队列（满丢弃 + debug 留痕）；命中自己 = 回环丢弃。
                        if let Some(handle) = &self_handle {
                            if Arc::ptr_eq(&other, handle) {
                                continue;
                            }
                        }
                        if !other.send(packet) {
                            LOG.debug(format!(
                                "masque: tunnel-to-tunnel queue full, packet to {dst} dropped"
                            ));
                        }
                        continue;
                    }
                    if server.in_pool(&dst) && !server.local.contains(&dst) {
                        continue;
                    }
                    let mut stack = server.stack.lock().await;
                    stack.ingest_rx(packet);
                    stack.poll(smoltcp::time::Instant::now());
                },
                Err(_) => break,
            },
            req = async {
                match request_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(entries) = req else { continue };
                serve_address_request(&mut writer, &addrs, entries);
            },
        }
    }

    // 收尾（Go defer s.release）：表移除 + 池归还。
    {
        let mut map = server.tunnels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for addr in &addrs {
            map.remove(addr);
        }
    }
    for addr in &addrs {
        for pool in &server.pools {
            let mut p = pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if p.prefix_contains(*addr) {
                p.release(addr);
            }
        }
    }
}

/// 地址请求回应（Go `serveAddressRequests` 单批）：请求条目按族匹配已分配
/// 地址（首个未用）；其余已分配地址作为 additional（request_id = 0）。
fn serve_address_request(
    writer: &mut SessionWriter,
    addrs: &[IpAddr],
    req: Vec<AddressRequestEntry>,
) {
    let mut used: Vec<bool> = vec![false; addrs.len()];
    let mut assigned: Vec<AssignedAddress> = Vec::with_capacity(req.len());
    for entry in &req {
        let req_v4 = entry.prefix.addr.is_ipv4();
        let mut hit = None;
        for (i, addr) in addrs.iter().enumerate() {
            if addr.is_ipv4() == req_v4 && !used[i] {
                used[i] = true;
                hit = Some(addr);
                break;
            }
        }
        let prefix = hit.map_or_else(
            || reject_prefix_for(&entry.prefix.addr),
            |a| IpPrefix { addr: *a, prefix_len: ip_bit_len(*a) },
        );
        assigned.push(AssignedAddress { request_id: entry.request_id, prefix });
    }
    for (i, addr) in addrs.iter().enumerate() {
        if !used[i] {
            assigned.push(AssignedAddress {
                request_id: 0,
                prefix: IpPrefix { addr: *addr, prefix_len: ip_bit_len(*addr) },
            });
        }
    }
    if let Err(e) = writer.respond_assignments(assigned) {
        LOG.debug(format!("masque: respond_assignments failed: {e}"));
    }
}

/// 同族拒绝前缀（Go `address.go` Respond 拒绝形态）。
fn reject_prefix_for(addr: &IpAddr) -> IpPrefix {
    match addr {
        IpAddr::V4(_) => {
            IpPrefix { addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), prefix_len: 32 }
        },
        IpAddr::V6(_) => {
            IpPrefix { addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), prefix_len: 128 }
        },
    }
}

/// 全路由通告（Go `fullRoutes`）：有 v4 分配 → 0.0.0.0-255.255.255.255；
/// 有 v6 分配 → ::-全 ffff（Go AddrFrom16 全 0xff）。
fn full_routes(addrs: &[IpAddr]) -> Vec<IpRoute> {
    let mut routes = Vec::with_capacity(2);
    if addrs.iter().any(|a| a.is_ipv4()) {
        routes.push(IpRoute {
            start_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            end_ip: IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            ip_protocol: 0,
        });
    }
    if addrs.iter().any(|a| a.is_ipv6()) {
        routes.push(IpRoute {
            start_ip: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            end_ip: IpAddr::V6(std::net::Ipv6Addr::from([0xff_u8; 16])),
            ip_protocol: 0,
        });
    }
    routes
}

/// 包目的提取（Go `packetDestination`）：v4 [16:20] / v6 [24:40]。
fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(o)))
        },
        _ => None,
    }
}

/// link-local 单播 / 多播丢弃（Go `IsLinkLocalUnicast/IsMulticast`）。
fn is_link_local_or_multicast(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v) => v.is_link_local() || v.is_multicast(),
        // fe80::/10（Go IsLinkLocalUnicast）+ ff00::/8（多播）。
        IpAddr::V6(v) => {
            let seg = v.segments();
            (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xff00) == 0xff00
        },
    }
}

fn ip_bit_len(a: IpAddr) -> u8 {
    if a.is_ipv4() { 32 } else { 128 }
}

fn endpoint_to_ip(addr: &smoltcp::wire::IpAddress) -> Option<IpAddr> {
    match addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => {
            Some(IpAddr::V4(std::net::Ipv4Addr::from(v4.octets())))
        },
        smoltcp::wire::IpAddress::Ipv6(v6) => {
            Some(IpAddr::V6(std::net::Ipv6Addr::from(v6.octets())))
        },
    }
}

/// smoltcp IpEndpoint（可空）→ Destination（TCP）。
fn ip_endpoint_to_destination(local: Option<&smoltcp::wire::IpEndpoint>) -> Option<Destination> {
    let ep = local?;
    let address = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::IPv4(std::net::Ipv4Addr::from(v4.octets())),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::IPv6(std::net::Ipv6Addr::from(v6.octets())),
    };
    Some(Destination::new(address, Port::new(ep.port), Network::TCP))
}

/// `ip/len` → smoltcp IpCidr（ipstack 装配面）。
fn ip_to_cidr(addr: IpAddr, len: u8) -> smoltcp::wire::IpCidr {
    let address = match addr {
        IpAddr::V4(v) => smoltcp::wire::IpAddress::Ipv4(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv4Address::from(v.octets()),
        ),
        IpAddr::V6(v) => smoltcp::wire::IpAddress::Ipv6(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv6Address::from(v.octets()),
        ),
    };
    smoltcp::wire::IpCidr::new(address, len)
}

/// 墙钟纳秒（wireguard nanos_now 同款：compat clock 端口）。
fn nanos_now() -> i64 {
    xray_frame::ipstack::nanos_now()
}

// ===== UDP 会话桥（wireguard run_wg_udp_session 同构） =====

#[derive(Debug)]
enum UdpCmd {
    Send { dest: Destination, payload: Vec<u8> },
}

#[derive(Debug)]
struct UdpSessionEntry {
    cmd_tx: mpsc::Sender<UdpCmd>,
    last_used_nanos: i64,
}

type UdpSessions = std::sync::Mutex<HashMap<smoltcp::wire::IpEndpoint, UdpSessionEntry>>;

/// 单个 UDP 数据报路由（Go `udpConnectionHandler.HandlePacket` 对应面）：
/// per-源命中即入队；未命中建会话（owner task 独占 UdpDispatchSession）。
#[allow(
    clippy::too_many_arguments,
    reason = "8/7 参：per-报文构造 = 4 次 Arc clone（UDP 快路新增分配），借用结构体无语义收益（wireguard 同款台账）"
)]
fn forward_udp_datagram(
    server: &Arc<MasqueServer>,
    sessions: &UdpSessions,
    dst: smoltcp::wire::IpEndpoint,
    src: smoltcp::wire::IpEndpoint,
    payload: Vec<u8>,
    now: i64,
) {
    let Some(dest_addr) = endpoint_to_ip(&dst.addr) else { return };
    let addr = match dest_addr {
        std::net::IpAddr::V4(v4) => Address::IPv4(v4),
        std::net::IpAddr::V6(v6) => Address::IPv6(v6),
    };
    let dest = Destination::new(addr, Port::new(dst.port), Network::UDP);
    let mut map = sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = map.get_mut(&src) {
        entry.last_used_nanos = now;
        match entry.cmd_tx.try_send(UdpCmd::Send { dest, payload }) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                LOG.debug(format!(
                    "masque udp: session queue full, packet dropped src={src} dst={dst:?}"
                ));
                return;
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                LOG.debug(format!(
                    "masque udp: session closed by outbound, packet dropped src={src}"
                ));
            },
        }
        map.remove(&src);
        return;
    }
    let (cmd_tx, cmd_rx) = mpsc::channel(UDP_QUEUE_CAP);
    let stack = Arc::clone(&server.stack);
    let dispatch = Arc::clone(&server.dispatch);
    let tag = server.tag.clone();
    let _ = server.scope.spawn(run_udp_session(dispatch, cmd_rx, stack, src, dest, payload, tag));
    map.insert(src, UdpSessionEntry { cmd_tx, last_used_nanos: now });
}

/// UDP 会话 owner task（per-隧道内源；wireguard `run_wg_udp_session` 同构）。
async fn run_udp_session(
    dispatch: Arc<dyn DispatchHandler>,
    mut cmd_rx: mpsc::Receiver<UdpCmd>,
    stack: Arc<tokio::sync::Mutex<PacketStack>>,
    inner_src: smoltcp::wire::IpEndpoint,
    first_dest: Destination,
    first_payload: Vec<u8>,
    tag: String,
) {
    let mut session = UdpDispatchSession::new(dispatch);
    // 回包源 = 最近一次请求的原目标（会话换目标时跟随）。
    let mut reply_src = destination_to_endpoint(&first_dest);
    if session.send_packet(&first_dest, &first_payload).await.is_err() {
        LOG.warn(format!("masque udp: first send_packet failed src={inner_src}"));
        return;
    }
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(UdpCmd::Send { dest, payload }) => {
                    reply_src = destination_to_endpoint(&dest).or(reply_src);
                    if session.send_packet(&dest, &payload).await.is_err() {
                        LOG.warn(format!("masque udp: send_packet failed src={inner_src}"));
                        return;
                    }
                },
                None => return,
            },
            resp = session.recv_packet() => match resp {
                Ok(Some((source, payload))) => {
                    let Some(reply_src) = reply_src.or_else(|| destination_to_endpoint(&source)) else {
                        continue;
                    };
                    let mut s = stack.lock().await;
                    let sent = s.udp_send_reply(reply_src, &payload, inner_src, nanos_now());
                    s.poll(smoltcp::time::Instant::now());
                    if !sent {
                        LOG.warn(format!(
                            "masque udp: reply dropped (socket unavailable) src={inner_src}"
                        ));
                    }
                    drop(s);
                },
                Ok(None) | Err(_) => {
                    let _ = tag;
                    return;
                },
            },
        }
    }
}

/// Destination（仅 IP）→ smoltcp IpEndpoint；Domain 返回 None（回包无 IP 源）。
fn destination_to_endpoint(dest: &Destination) -> Option<smoltcp::wire::IpEndpoint> {
    let addr = match dest.address() {
        Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv4Address::from(v4.octets()),
        ),
        Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv6Address::from(v6.octets()),
        ),
        Address::Domain(_) => return None,
    };
    Some(smoltcp::wire::IpEndpoint { addr, port: dest.port().value() })
}

fn sweep_udp_sessions(sessions: &UdpSessions, now: i64) {
    let idle = (UDP_SESSION_IDLE_SECS as i64) * 1_000_000_000;
    let mut map = sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let expired: Vec<smoltcp::wire::IpEndpoint> = map
        .iter()
        .filter(|(_, s)| now.saturating_sub(s.last_used_nanos) > idle)
        .map(|(k, _)| *k)
        .collect();
    for k in expired {
        map.remove(&k);
    }
}

// ===== TCP 栈内中继（wireguard WgTcpRelay 同构；smoltcp socket ↔ duplex） =====
// 实现在 [`crate::relay::StackTcpRelay`]（server/client 共用单份，禁第二副本）。

// ===== 监听装配面（arm_builders 消费；finalmask B4.7 在 hub 侧终结） =====

/// MASQUE 服务端监听装配（hub + gate + acceptor 一体；Go `internet.Listen`
/// proxy worker 管线对应面）。
///
/// `settings.security != "tls"` 时 hub 内部硬错（extra 条款 MASQUE-TLS-REQUIRED）。
pub async fn serve(
    addr: std::net::SocketAddr,
    tag: impl Into<String>,
    settings: MasqueServerSettings,
    dispatch: Arc<dyn DispatchHandler>,
    scope: ComponentScope,
    stream_settings: StreamSettings,
    sockopt: SocketOptions,
) -> io::Result<(Box<dyn TransportListener>, Arc<MasqueServer>)> {
    let server = MasqueServer::new(tag, settings, dispatch, scope)?;
    let gate = server.gate();
    let acceptor = server.acceptor();
    let listener = hub::listen_masque(addr, &stream_settings, &sockopt, gate, acceptor).await?;
    Ok((listener, server))
}

/// finalmask 配置探测（装配面报告用；实际 wrap 在 hub accept 路径）。
#[must_use]
pub fn has_finalmask(settings: &StreamSettings) -> bool {
    settings.finalmask_json.as_ref().is_some_and(|v| !v.is_null())
}

/// tcpmask manager 构造（B4.7：Go `hub.go:168-169 FinalMask.Listen` 对应面——
/// wrap 在 [`hub::listen_masque`] accept 路径内，本函数供装配面预检配置合法性）。
pub fn build_tcpmask(settings: &StreamSettings) -> io::Result<Option<Arc<TcpmaskManager>>> {
    if settings.finalmask_json.as_ref().is_none_or(|v| v.is_null()) {
        return Ok(None);
    }
    finalmask::build_tcpmask_manager_from_json(settings.finalmask_json.as_ref())
        .map(|m| Some(Arc::new(m)))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(email: &str, pass: &str) -> MasqueUser {
        MasqueUser { email: email.into(), password: pass.into(), level: 0 }
    }

    #[test]
    fn parse_rejects_missing_users() {
        let v = serde_json::json!({"address": ["10.0.0.1/24"]});
        assert!(parse_server_settings(&v).is_err(), "missing users must reject");
    }

    #[test]
    fn parse_rejects_empty_users() {
        let v = serde_json::json!({"users": [], "address": ["10.0.0.1/24"]});
        assert!(parse_server_settings(&v).is_err(), "empty users must reject");
    }

    #[test]
    fn parse_rejects_missing_address() {
        let v = serde_json::json!({"users": [{"pass": "p"}]});
        assert!(parse_server_settings(&v).is_err(), "missing address must reject");
    }

    #[test]
    fn parse_rejects_duplicate_family() {
        let v = serde_json::json!({
            "users": [{"pass": "p"}],
            "address": ["10.0.0.1/24", "10.0.1.1/24"]
        });
        assert!(parse_server_settings(&v).is_err(), "duplicate v4 family must reject");
    }

    #[test]
    fn parse_rejects_mtu_out_of_range() {
        let v =
            serde_json::json!({"users": [{"pass": "p"}], "address": ["10.0.0.1/24"], "mtu": 100});
        assert!(parse_server_settings(&v).is_err(), "mtu < 1280 must reject");
        let v =
            serde_json::json!({"users": [{"pass": "p"}], "address": ["10.0.0.1/24"], "mtu": 65536});
        assert!(parse_server_settings(&v).is_err(), "mtu > 65535 must reject");
    }

    #[test]
    fn parse_accepts_valid_and_defaults_mtu() {
        let v = serde_json::json!({
            "users": [{"pass": "p", "email": "a@b", "level": 2}],
            "address": ["10.0.0.1/24", "fd00::1/120"]
        });
        let s = parse_server_settings(&v).expect("valid settings");
        assert_eq!(s.users.len(), 1);
        assert_eq!(s.users[0].level, 2);
        assert_eq!(s.addresses.len(), 2);
        assert_eq!(s.mtu, MIN_PACKET_SIZE);
    }

    #[test]
    fn validator_constant_time_get() {
        let v = Validator::new(vec![user("Alice@x", "secret")]);
        assert!(v.get("alice@x", "secret").is_some(), "email lowercase-normalized");
        assert!(v.get("alice@x", "wrong").is_none());
        assert!(v.get("nobody@x", "secret").is_none());
    }

    #[test]
    fn full_routes_per_family() {
        let r = full_routes(&[IpAddr::V4("10.0.0.2".parse().unwrap())]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].start_ip, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        assert_eq!(r[0].end_ip, IpAddr::V4(std::net::Ipv4Addr::BROADCAST));
        let r = full_routes(&[
            IpAddr::V4("10.0.0.2".parse().unwrap()),
            IpAddr::V6("fd00::2".parse().unwrap()),
        ]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].end_ip, IpAddr::V6(std::net::Ipv6Addr::from([0xff_u8; 16])));
    }

    #[test]
    fn packet_destination_extraction() {
        // v4：dst 在 [16:20]。
        let mut p = vec![0x45u8; 20];
        p[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(packet_destination(&p), Some(IpAddr::V4("8.8.8.8".parse().unwrap())));
        // link-local 丢弃。
        assert!(is_link_local_or_multicast(&IpAddr::V4("169.254.1.1".parse().unwrap())));
        assert!(is_link_local_or_multicast(&IpAddr::V4("224.0.0.1".parse().unwrap())));
        assert!(!is_link_local_or_multicast(&IpAddr::V4("8.8.8.8".parse().unwrap())));
        assert!(is_link_local_or_multicast(&IpAddr::V6("fe80::1".parse().unwrap())));
    }
}
