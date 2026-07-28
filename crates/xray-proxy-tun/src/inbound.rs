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
//! ## 当前限制
//!
//! dispatcher 桥接（smoltcp socket → router）在此完成事件检测，
//! 实际 dispatch 调用留待后续切片（当前仅 tracing 日志）。
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as ParkMutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::config::StackOptions;
use crate::config::Tun;
use crate::device::TunDevice;
use crate::error::Result;
use crate::netstack::TunNetStack;

/// TUN 设备接收缓冲。
const TUN_RECV_BUF_SIZE: usize = 65535;

/// smoltcp poll 定时器间隔。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    pub async fn new(tag: impl Into<String>, options: StackOptions) -> Result<Self> {
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
        let handle = tokio::spawn(async move {
            tun_driver_loop(dev, netstack).await;
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

async fn tun_driver_loop(device: Arc<TunDevice>, netstack: Arc<AsyncMutex<TunNetStack>>) {
    let mut timer = interval(POLL_INTERVAL);
    let mut recv_buf = vec![0u8; TUN_RECV_BUF_SIZE];

    // 初始化：创建 TCP Listen socket + UDP Bind socket
    // 对应 Go stackGVisor.Start() 中 tcp.NewForwarder + udp.NewForwarder
    // ponytail: 单端口监听（TUN 入站通常由 iptables/nftables 重定向到 TUN，
    // 实际 dest 地址在 IP 包头中，不依赖 listen 端口）
    // TODO: 多端口监听由上层配置注入
    let tcp_listen_handle = {
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
                        // 检测 TCP/UDP 事件
                        handle_socket_events(
                            &mut stack,
                            tcp_listen_handle,
                            udp_bind_handle,
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
                    // 检测 TCP/UDP 事件
                    handle_socket_events(
                        &mut stack,
                        tcp_listen_handle,
                        udp_bind_handle,
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

/// poll 后检测 TCP accept / UDP recv 事件，通知上层。
///
/// 对应 Go `stackGVisor.Start` 中 tcp/udp forwarder 的回调。
/// 当前实现：tracing 日志 + 留后续 dispatcher 桥接。
fn handle_socket_events(
    stack: &mut TunNetStack,
    tcp_listen_handle: Option<smoltcp::iface::SocketHandle>,
    udp_bind_handle: Option<smoltcp::iface::SocketHandle>,
) {
    // TCP accept 检测
    if let Some(handle) = tcp_listen_handle {
        if let Some(event) = stack.check_tcp_accept(handle) {
            tracing::debug!(
                handle = ?event.handle,
                remote = %event.remote,
                "tcp connection accepted"
            );
            // TODO: dispatcher 桥接——创建 Link (Reader/Writer) 从该 socket，
            // 调 dispatcher.DispatchLink(ctx, destination, link)
            // destination 从 local endpoint（TUN 侧地址+端口）构建
        }
    }

    // UDP recv 检测
    if let Some(handle) = udp_bind_handle {
        // 循环读取所有到达的 UDP 数据报（可能多个）
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
            // TODO: dispatcher 桥接——构建 UDP session，
            // 调 dispatcher.DispatchLink(ctx, destination, link)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn construct_inbound_handler() {
        let opts = make_options();
        let h = TunInboundHandler::new("test", opts).await;
        assert!(h.is_ok(), "construct failed: {:?}", h.err());
    }

    #[tokio::test]
    async fn construct_rejects_no_tun() {
        let opts = StackOptions::default();
        let result = TunInboundHandler::new("test", opts).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tag_and_port() {
        let opts = make_options();
        let h = TunInboundHandler::new("test", opts).await.expect("construct");
        assert_eq!(h.tag(), "test");
        assert_eq!(h.port(), 0);
    }
}
