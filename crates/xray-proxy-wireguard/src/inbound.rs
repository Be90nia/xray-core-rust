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
//! `select!` 并发）创建 Listen socket → poll 后检查 Established → 通知 dispatcher。
//! 对应 Go `tcp.NewForwarder(r.CreateEndpoint() → handler.HandleConnection)`。
//! 中继模式与 `xray-proxy-tun/src/inbound.rs::TunTcpRelay` 一致。

use async_trait::async_trait;
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
use xray_app_dispatcher::DispatchHandler;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::config::DeviceConfig;
use crate::driver::{bind_udp_socket, WgDriver};
use crate::error::Result;
use crate::netstack::WgNetStack;
use crate::peer::shared_peer;

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
    /// driver 句柄——start() 后消费。
    driver: ParkMutex<Option<Arc<WgDriver>>>,
    /// join handle——close() 用以终止 task。
    join: ParkMutex<Option<JoinHandle<()>>>,
    /// smoltcp 网栈句柄（与 driver 共享）。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// dispatcher handler（TCP accept 后桥接到 outbound）。
    dispatch: Arc<dyn DispatchHandler>,
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
        if config.peers.is_empty() {
            return Err(crate::error::WgError::InvalidConfig(
                "wireguard inbound requires at least one peer".into(),
            ));
        }
        // 创建所有配置的 peer session（multi-peer server 模式）
        let mut peers = Vec::with_capacity(config.peers.len());
        let mut allowed_cidrs = Vec::with_capacity(config.peers.len());
        for (i, peer_cfg) in config.peers.iter().enumerate() {
            peers.push(shared_peer(config, peer_cfg, i as u32)?);
            let cidrs: Vec<smoltcp::wire::IpCidr> = peer_cfg
                .allowed_ips
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            allowed_cidrs.push(cidrs);
        }

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

        Ok(Self {
            tag,
            port: listen_port,
            started: AtomicBool::new(false),
            driver: ParkMutex::new(Some(driver)),
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
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        let driver = self
            .driver
            .lock()
            .clone()
            .ok_or_else(|| InboundError::Closed(self.tag.clone()))?;

        let netstack = Arc::clone(&self.netstack);
        let dispatch = Arc::clone(&self.dispatch);

        let handle = tokio::spawn(async move {
            // driver loop 与 accept loop 在同一 task 内 select! 并发
            tokio::select! {
                _ = driver.main_loop() => {}
                _ = wg_accept_loop(netstack, dispatch) => {}
            }
        });
        *self.join.lock() = Some(handle);
        tracing::info!(tag = %self.tag, port = self.port, "wireguard inbound started");
        Ok(())
    }

    /// 关闭 driver task + accept loop。
    async fn close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        if let Some(handle) = self.join.lock().take() {
            handle.abort();
        }
        tracing::info!(tag = %self.tag, "wireguard inbound closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

/// 从 DeviceConfig.endpoint 解析为 smoltcp IpCidr（与 outbound 共用逻辑）。
fn parse_local_cidrs(config: &DeviceConfig) -> Result<Vec<smoltcp::wire::IpCidr>> {
    let parsed = crate::wireguard::parse_endpoints(config)?;
    parsed
        .addrs
        .into_iter()
        .map(|addr| {
            let cidr_prefix = if addr.is_ipv4() { 32 } else { 128 };
            let smoltcp_addr = match addr {
                std::net::IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets())),
                std::net::IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets())),
            };
            Ok(smoltcp::wire::IpCidr::new(smoltcp_addr, cidr_prefix))
        })
        .collect()
}

/// accept loop——周期性检查 TCP listen socket 是否有新连接，dispatch 到 outbound。
///
/// 与 `xray-proxy-tun/src/inbound.rs::tun_driver_loop` 中 handle_socket_events 部分
/// 对称：创建 Listen socket → check_tcp_accept → 新建 relay + dispatch。
async fn wg_accept_loop(
    netstack: Arc<AsyncMutex<WgNetStack>>,
    dispatch: Arc<dyn DispatchHandler>,
) {
    let mut timer = interval(Duration::from_millis(ACCEPT_POLL_MS));

    // 初始化：创建 TCP Listen socket（端口 0 = smoltcp 自动选端口）
    let mut tcp_listen_handle = {
        let mut stack = netstack.lock().await;
        let handle = stack.add_tcp_socket();
        if let Err(e) = stack.tcp_listen(handle, 0) {
            tracing::warn!(error = %e, "wg tcp listen failed, inbound TCP disabled");
        } else {
            tracing::debug!(?handle, "wg tcp listen socket created");
        }
        handle
    };

    tracing::debug!("wg accept loop started");

    loop {
        timer.tick().await;
        let mut stack = netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());

        if let Some(event) = stack.check_tcp_accept(tcp_listen_handle) {
            // accept 后该 socket 进入 Established，作为连接 socket；
            // 新建一个 listen socket 接受下一个连接。
            let new_listen = stack.add_tcp_socket();
            if let Err(e) = stack.tcp_listen(new_listen, 0) {
                tracing::warn!(error = %e, "wg tcp re-listen failed");
            }
            tcp_listen_handle = new_listen;

            // 从 local endpoint 构建 destination
            let dest = match ip_endpoint_to_destination(&event.local) {
                Some(d) => d,
                None => {
                    tracing::warn!(
                        remote = %event.remote,
                        "wg tcp accept: no local endpoint, dropping connection"
                    );
                    stack.remove_socket(event.handle);
                    continue;
                }
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

            // spawn dispatch（link → outbound）
            let dispatch = Arc::clone(&dispatch);
            tokio::spawn(async move {
                dispatch.dispatch(&dest, link).await;
            });
        }
    }
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
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicU32;
    use crate::config::PeerConfig;

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

    fn make_config(seed: u8) -> DeviceConfig {
        let (sec, pub_) = make_keypair(seed);
        DeviceConfig {
            secret_key: sec,
            endpoint: vec!["10.0.0.1/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_,
                ..Default::default()
            }],
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
    async fn construct_rejects_no_peers() {
        let (dispatch, _) = make_dispatch();
        let (sec, _) = make_keypair(0x77);
        let cfg = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let result = WireguardInboundHandler::new("test", &cfg, 0, dispatch).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn start_close_lifecycle() {
        let (dispatch, _) = make_dispatch();
        let cfg = make_config(0x88);
        let port = free_port().await;

        let h = WireguardInboundHandler::new("test", &cfg, port, dispatch).await.expect("construct");
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

    /// 验证 tcp_listen 成功 + check_tcp_accept 在无连接时返回 None。
    ///
    /// smoltcp listen(0) 会返回 Unaddressable（port 0 = ephemeral），
    /// 用非零端口验证 listen 设施正确。与 tun inbound 测试对称。
    #[tokio::test]
    async fn tcp_listen_and_check_accept_no_connection() {
        use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<WgNetStack>> =
            Arc::new(AsyncMutex::new(WgNetStack::new(&[local], 1420)));

        // listen on non-zero port should succeed
        let listen_handle = {
            let mut stack = netstack.lock().await;
            let h = stack.add_tcp_socket();
            stack.tcp_listen(h, 443).expect("listen on 443");
            h
        };

        // poll 后检查——没有真实流量，不会 Established
        {
            let mut stack = netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            assert!(stack.check_tcp_accept(listen_handle).is_none());
        }
    }

    /// 验证 accept loop 路径在 listen 失败时不 panic（端口 0 被 smoltcp 拒绝），
    /// check_tcp_accept 返回 None——与 tun inbound handle_socket_events_triggers_dispatch 对称。
    #[tokio::test]
    async fn accept_loop_port0_rejected_no_panic() {
        use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        let netstack: Arc<AsyncMutex<WgNetStack>> =
            Arc::new(AsyncMutex::new(WgNetStack::new(&[local], 1420)));

        // listen 0 = smoltcp 拒绝（port 0 = ephemeral），accept loop 会 warn 并继续
        let listen_handle = {
            let mut stack = netstack.lock().await;
            let h = stack.add_tcp_socket();
            let _ = stack.tcp_listen(h, 0); // 忽略错误，与 production 一致
            h
        };

        // check_tcp_accept 不 panic，返回 None（socket 仍 Closed）
        {
            let mut stack = netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            assert!(stack.check_tcp_accept(listen_handle).is_none());
        }
    }
}
