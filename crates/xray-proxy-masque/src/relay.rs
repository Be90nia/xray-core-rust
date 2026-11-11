//! 用户态栈 socket 桥（server/client 共用；wireguard `inbound.rs::WgTcpRelay`
//! / `dispatcher.rs::UdpRelay` 同构形态——crate 内单份，禁第二副本）。
//!
//! udf 判定：含 dispatcher/XUDP 语义（Xray 方向件），不进 udf；跨 crate 公共
//! 提炼归 `xray-app-dispatcher`（需其引入 smoltcp——依赖方向归 PM 裁决，
//! 见 crate 文档）。

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Mutex as AsyncMutex,
};
use xray_frame::ipstack::PacketStack;

/// duplex 缓冲（wireguard DUPLEX_BUF 同值）。
pub(crate) const DUPLEX_BUF: usize = 64 * 1024;

/// 栈内 TCP 中继轮询间隔（wireguard RELAY_POLL_MS 同值）。
const RELAY_POLL_MS: u64 = 5;

/// smoltcp TCP socket ↔ tokio duplex 中继（server inbound / client outbound
/// 两个方向共用——socket handle 语义对称）。
pub(crate) struct StackTcpRelay {
    /// duplex 的"远端"读半（用户/链路侧 → socket）。
    pub(crate) from_client: tokio::io::DuplexStream,
    /// duplex 的"远端"写半（socket → 用户/链路侧）。
    pub(crate) to_client: tokio::io::DuplexStream,
    /// 用户态栈。
    pub(crate) stack: Arc<AsyncMutex<PacketStack>>,
    /// 已 accept/connect 的 smoltcp TCP socket handle。
    pub(crate) handle: smoltcp::iface::SocketHandle,
}

impl StackTcpRelay {
    /// 运行中继循环直到 socket 关闭或链路断。
    pub(crate) async fn run(mut self) {
        let mut timer = tokio::time::interval(Duration::from_millis(RELAY_POLL_MS));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timer.tick().await; // 消掉首次立即触发
        // 上下行 scratch 循环外复用（bd m6pkl-N6：空转期零分配）。
        let mut user_buf = vec![0u8; 8192];
        let mut down_buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                result = self.from_client.read(&mut user_buf) => {
                    match result {
                        Ok(0) | Err(_) => {
                            self.finish().await;
                            return;
                        }
                        Ok(n) => self.send_to_stack(&user_buf[..n]).await,
                    }
                }
                _ = timer.tick() => {}
            }
            if self.recv_from_stack(&mut down_buf).await {
                let _ = self.to_client.shutdown().await;
                self.finish().await;
                return;
            }
        }
    }

    /// 发送数据到 smoltcp socket（循环写满——`send_slice` 只接受当前空闲空间，
    /// 缓冲满释放锁等待 ACK 腾位；单次丢弃会让下行在 64KB 处截断——票 gmhe 同源）。
    async fn send_to_stack(&self, mut data: &[u8]) {
        while !data.is_empty() {
            let mut stack = self.stack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let (written, active) = stack.with_tcp_socket(self.handle, |s| {
                let written = if s.may_send() { s.send_slice(data).unwrap_or(0) } else { 0 };
                (written, s.is_active())
            });
            stack.poll(smoltcp::time::Instant::now());
            drop(stack);
            data = &data[written..];
            if !active {
                return;
            }
            if written == 0 {
                tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
            }
        }
    }

    /// 从 smoltcp socket 接收 → duplex（返回 true = socket 已关闭且无数据）。
    async fn recv_from_stack(&mut self, scratch: &mut [u8]) -> bool {
        let (recv_len, closed) = {
            let mut stack = self.stack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let r = stack.with_tcp_socket(self.handle, |s| {
                let n = s.recv_slice(scratch).unwrap_or(0);
                (n, !s.is_active())
            });
            stack.poll(smoltcp::time::Instant::now());
            r
        };
        if recv_len > 0 && self.to_client.write_all(&scratch[..recv_len]).await.is_err() {
            return true;
        }
        closed && recv_len == 0
    }

    /// 关闭 socket 并等 FIN 排空（关闭后继续 poll 直到 FIN 确认或超时——
    /// ACK 撞无主 socket 回 RST 会截断大响应）。
    async fn finish(&self) {
        {
            let mut stack = self.stack.lock().await;
            stack.with_tcp_socket(self.handle, |s| s.close());
        }
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_millis(500);
        loop {
            let mut stack = self.stack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let active = stack.with_tcp_socket(self.handle, |s| s.is_active());
            if !active || xray_frame::compat::clock().now_instant() >= deadline {
                stack.remove_socket(self.handle);
                break;
            }
            drop(stack);
            tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
        }
    }
}

/// smoltcp UDP socket 绑定临时端口（1024-65535 随机，冲突重试；`bind(0)` 被
/// smoltcp 拒绝——Go `DialUDPAddrPort(AddrPort{}, ...)` 随机端口语义手动实现）。
/// 16 次全失败返回 `false`（调用方按 socket 不可用处置）。
pub(crate) fn bind_ephemeral(sock: &mut smoltcp::socket::udp::Socket<'static>) -> bool {
    use rand::Rng;
    for _ in 0..16 {
        #[allow(deprecated)] // 存量清零批次
        let port: u16 = rand::thread_rng().gen_range(1024..65535);
        if sock.bind(port).is_ok() {
            return true;
        }
    }
    false
}

/// Destination（仅 IP）→ smoltcp IpEndpoint；Domain 返回 None。
pub(crate) fn destination_to_endpoint(
    dest: &xray_common::net::destination::Destination,
) -> Option<smoltcp::wire::IpEndpoint> {
    use xray_common::net::address::Address;
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

/// smoltcp IpEndpoint → Destination（UDP）。
pub(crate) fn endpoint_to_destination(
    ep: &smoltcp::wire::IpEndpoint,
) -> Option<xray_common::net::destination::Destination> {
    use xray_common::net::{address::Address, port::Port};
    let address = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::IPv4(std::net::Ipv4Addr::from(v4.octets())),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::IPv6(std::net::Ipv6Addr::from(v6.octets())),
    };
    Some(xray_common::net::destination::Destination::new(
        address,
        Port::new(ep.port),
        xray_common::net::network::Network::UDP,
    ))
}

/// 等待 smoltcp TCP socket 连接建立（轮询，最多 5 秒；wireguard
/// `wait_tcp_connected` 同款；时间源 = compat clock 端口）。
pub(crate) async fn wait_tcp_connected(
    stack: &Arc<AsyncMutex<PacketStack>>,
    handle: smoltcp::iface::SocketHandle,
) -> bool {
    let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
    loop {
        let (connected, active) = {
            let mut s = stack.lock().await;
            s.poll(smoltcp::time::Instant::now());
            s.with_tcp_socket(handle, |sock| (sock.is_open(), sock.is_active()))
        };
        if connected && active {
            return true;
        }
        if !active || xray_frame::compat::clock().now_instant() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
    }
}
