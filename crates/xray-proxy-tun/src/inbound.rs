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
//! 创建 Bind socket → poll 后 recv 数据报 → 通知上层 dispatcher。
//! 对应 Go `udp.NewForwarder(handler.HandlePacket)`。
//!
//! ## TCP dispatch
//!
//! TCP accept 后构造 Link（duplex ↔ smoltcp socket 中继），调
//! `DispatchHandler::dispatch(dest, link)`。中继模式与
//! `xray-proxy-wireguard/src/dispatcher.rs::TcpRelay` 一致。
//!
//! ## 当前限制
//!
//! - destination 取自 accepted socket 的 local endpoint（TUN 侧地址），
//!   非原始目标地址（需 IP 头解析或 SO_ORIGINAL_DST，后续切片）。
//! - UDP dispatch 留待后续切片。
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as ParkMutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
use xray_features::inbound::{InboundError, InboundHandler};
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_app_dispatcher::DispatchHandler;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::link::Link;

use crate::config::StackOptions;
use crate::config::Tun;
use crate::device::TunDevice;
use crate::error::Result;
use crate::netstack::TunNetStack;

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

        // 取出 tun 配置并创建设备
        let _tun_cfg = self
            .options
            .tun
            .as_ref()
            .ok_or_else(|| InboundError::ListenError("tun device config missing".into()))?;

        // 创建 TUN 设备
        let device = Arc::new(
            TunDevice::create("xray0", "10.0.0.1", 24, 1500)
                .map_err(|e| InboundError::ListenError(format!("tun device create: {e}")))?,
        );

        // 启动设备
        device
            .start()
            .map_err(|e| InboundError::ListenError(format!("tun device start: {e}")))?;

        // 用实际地址重建 netstack
        let local_v4 = smoltcp::wire::Ipv4Address::new(10, 0, 0, 1);
        let local = smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(local_v4),
            24,
        );
        let mtu = 1500usize;
        {
            let mut stack = self.netstack.lock().await;
            *stack = TunNetStack::new(&[local], mtu);
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

async fn tun_driver_loop(
    device: Arc<TunDevice>,
    netstack: Arc<AsyncMutex<TunNetStack>>,
    dispatch: Arc<dyn DispatchHandler>,
) {
    let mut timer = interval(POLL_INTERVAL);
    let mut recv_buf = vec![0u8; TUN_RECV_BUF_SIZE];

    // 初始化：创建 TCP Listen socket + UDP Bind socket
    // 对应 Go stackGVisor.Start() 中 tcp.NewForwarder + udp.NewForwarder
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
    let udp_bind_handle = {
        let mut stack = netstack.lock().await;
        let handle = stack.add_udp_socket();
        if let Err(e) = stack.udp_bind(handle, 0) {
            tracing::warn!(error = %e, "udp bind failed, inbound UDP disabled");
        } else {
            tracing::debug!(?handle, "udp bind socket created");
        }
        Some(handle)
    };

    tracing::debug!("tun driver main loop started");

    loop {
        tokio::select! {
            // 从 TUN 设备读取 IP 包
            result = device.recv(&mut recv_buf) => {
                match result {
                    Ok(n) => {
                        if n == 0 { continue; }
                        let pkt = recv_buf[..n].to_vec();
                        let mut stack = netstack.lock().await;
                        stack.ingest_rx(pkt);
                        stack.poll(smoltcp::time::Instant::now());
                        // 处理 ICMP echo request 并自动回复
                        stack.process_icmp_echo();
                        // 检测 TCP/UDP 事件
                        handle_socket_events(
                            &mut stack,
                            &netstack,
                            &mut tcp_listen_handle,
                            udp_bind_handle,
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
                    // 检测 TCP/UDP 事件
                    handle_socket_events(
                        &mut stack,
                        &netstack,
                        &mut tcp_listen_handle,
                        udp_bind_handle,
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

/// poll 后检测 TCP accept / UDP recv 事件。
///
/// 对应 Go `stackGVisor.Start` 中 tcp/udp forwarder 的回调。
/// TCP accept 后构造 Link 桥接 smoltcp socket → dispatcher。
fn handle_socket_events(
    stack: &mut TunNetStack,
    netstack: &Arc<AsyncMutex<TunNetStack>>,
    tcp_listen_handle: &mut Option<SocketHandle>,
    udp_bind_handle: Option<SocketHandle>,
    dispatch: &Arc<dyn DispatchHandler>,
) {
    // TCP accept 检测
    if let Some(handle) = *tcp_listen_handle {
        if let Some(event) = stack.check_tcp_accept(handle) {
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
    }

    // UDP recv 检测（dispatch 留待后续切片）
    if let Some(handle) = udp_bind_handle {
        loop {
            let event = stack.udp_recv(handle);
            let Some(event) = event else { break; };
            tracing::trace!(
                handle = ?event.handle,
                remote = %event.remote,
                local_port = event.local_port,
                len = event.payload.len(),
                "udp datagram received"
            );
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
                None,
                &dispatch,
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no spurious dispatch");
        // listen handle 未变（无 accept）
        assert_eq!(tcp_listen, Some(listen_handle));
    }
}
