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
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex as ParkMutex;
use smoltcp::{iface::SocketHandle, wire::IpEndpoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
    time::interval,
};
use xray_app_dispatcher::{AccessContext, DispatchHandler};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::{
    config::DeviceConfig,
    driver::{WgDriver, bind_udp_socket},
    error::Result,
    netstack::WgNetStack,
    peer::shared_peer,
    users::{DriverSlot, WgUserRegistry},
};

/// duplex 缓冲大小。
const DUPLEX_BUF: usize = 64 * 1024;

/// accept loop 轮询间隔（ms）。
const ACCEPT_POLL_MS: u64 = 100;

/// 中继轮询间隔（ms）。
const RELAY_POLL_MS: u64 = 5;

/// WireGuard 入站 Handler。
///
/// 持有 driver + 监听状态 + 监听端口 + dispatcher handler。
pub struct WireguardInboundHandler {
    tag: String,
    port: u16,
    started: AtomicBool,
    /// driver 句柄槽——start() 后消费；与 registry 共享（动态热插）。
    driver: DriverSlot,
    /// join handle——close() 用以终止 task。
    join: ParkMutex<Option<JoinHandle<()>>>,
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

        let handle = tokio::spawn(async move {
            // driver loop 与 accept loop 在同一 task 内 select! 并发
            tokio::select! {
                _ = driver.main_loop() => {}
                _ = wg_accept_loop(netstack, registry, dispatch) => {}
            }
        });
        *self.join.lock() = Some(handle);
        tracing::info!(tag = %self.tag, port = self.port, "wireguard inbound started");
        Ok(())
    }

    /// 同步关闭核心——proxyman 适配器复用。
    pub(crate) fn do_close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        if let Some(handle) = self.join.lock().take() {
            handle.abort();
        }
        tracing::info!(tag = %self.tag, "wireguard inbound closed");
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
#[allow(clippy::incompatible_msrv)] // 存量清零批次：incompatible_msrv
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
) {
    let mut timer = interval(Duration::from_millis(ACCEPT_POLL_MS));
    tracing::debug!("wg accept loop started");

    loop {
        timer.tick().await;
        let mut stack = netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());

        for event in stack.drain_accepted() {
            // 从 local endpoint 构建 destination（隧道内目标）
            let dest = match ip_endpoint_to_destination(&event.local) {
                Some(d) => d,
                None => {
                    tracing::warn!(
                        remote = %event.remote,
                        "wg tcp accept: no local endpoint, dropping connection"
                    );
                    stack.remove_socket(event.handle);
                    continue;
                },
            };

            // 创建两路 duplex 桥接 smoltcp socket ↔ Link
            // ponytail: 双 duplex（up/down 独立），与 tun TunTcpRelay 一致
            let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
            let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
            let link = Link::new(new_reader(client_from_relay), new_writer(client_to_relay));

            tracing::debug!(
                handle = ?event.handle,
                remote = %event.remote,
                dest = ?dest,
                "wg tcp connection accepted → dispatch"
            );

            // spawn 中继 task（smoltcp socket ↔ duplex）
            let relay = WgTcpRelay {
                from_client: relay_from_client,
                to_client: relay_to_client,
                netstack: Arc::clone(&netstack),
                handle: event.handle,
            };
            tokio::spawn(relay.run());

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
            tokio::spawn(async move {
                dispatch.dispatch_with_access(&dest, link, access).await;
            });
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

    async fn free_port() -> u16 {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn construct_inbound_handler() {
        let (dispatch, _) = make_dispatch();
        let cfg = make_config(0x66);
        let port = free_port().await;
        let h = WireguardInboundHandler::new("test", &cfg, port, dispatch).await;
        assert!(h.is_ok(), "construct failed: {:?}", h.err());
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
        let port = free_port().await;

        let h =
            WireguardInboundHandler::new("test", &cfg, port, dispatch).await.expect("construct");
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
        seen: Arc<ParkMutex<Vec<(Destination, Vec<u8>)>>>,
        access_seen: Arc<ParkMutex<Vec<AccessContext>>>,
    }

    impl EchoDispatch {
        #[allow(clippy::type_complexity)] // 存量清零批次：type_complexity
        fn new(
            tag: &str,
            response: &[u8],
        ) -> (
            Arc<Self>,
            Arc<ParkMutex<Vec<(Destination, Vec<u8>)>>>,
            Arc<ParkMutex<Vec<AccessContext>>>,
        ) {
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
        tokio::spawn(wg_accept_loop(Arc::clone(&netstack), registry, dispatch));

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
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let server_seq = loop {
            let seq = {
                let mut stack = netstack.lock().await;
                stack.drain_tx().iter().find_map(|p| tcp_seq_number(p))
            };
            if let Some(seq) = seq {
                break seq;
            }
            assert!(std::time::Instant::now() < deadline, "no SYN-ACK within 5s");
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

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "no dispatch within 5s");
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
        let udp_port = free_port().await;

        // server：生产 inbound handler（new_multi driver + wg_accept_loop）
        let server_cfg = DeviceConfig {
            secret_key: sec_s,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_c.clone(),
                allowed_ips: vec!["10.0.0.2/32".into()], // 回程路由必需
                ..Default::default()
            }],
            ..Default::default()
        };
        let (dispatch, seen, access_seen) = EchoDispatch::new("wg-e2e-out", b"echo:pong");
        let server = WireguardInboundHandler::new("wg-e2e", &server_cfg, udp_port, dispatch)
            .await
            .expect("server construct");
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
        tokio::spawn(Arc::clone(&client).main_loop());

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
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !got.starts_with(b"echo:pong") {
            assert!(
                std::time::Instant::now() < deadline,
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
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while seen.lock().is_empty() {
            assert!(std::time::Instant::now() < deadline, "dispatch not recorded in 5s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        #[allow(clippy::await_holding_lock)] // 存量清零批次
        let s = seen.lock();
        let (dest, payload) = &s[0];
        assert_eq!(dest.network(), Network::TCP);
        assert_eq!(dest.address(), &Address::IPv4("10.0.0.1".parse().unwrap()));
        assert_eq!(dest.port().value(), TUNNEL_TCP_PORT);
        assert_eq!(payload, b"ping");

        // bd ttni：dispatch 携带的 user 上下文来自 GetUserByAddr(10.0.0.2)
        #[allow(clippy::await_holding_lock)] // 存量清零批次
        let acc = access_seen.lock();
        let ctx = acc.last().expect("dispatch_with_access captured");
        assert_eq!(ctx.email, "u@wg", "user email 挂接");
        assert_eq!(ctx.level, 3, "user level 挂接");
        assert!(ctx.from.starts_with("10.0.0.2"), "from = 隧道内源地址，got {}", ctx.from);
        assert_eq!(ctx.inbound_tag, "", "inbound_tag 由生产入口填充");

        server.close().await.expect("server close");
    }
}
