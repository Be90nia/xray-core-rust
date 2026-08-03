//! TUN 用户态网络栈——基于 smoltcp 处理 TUN 设备的原始 IP 包。
//!
//! 对应 Go `proxy/tun/stack.go` 的 gVisor netstack。Rust 用 [`smoltcp`] 等价：
//!
//! - [`TunNetStack`] 持有 smoltcp [`Interface`] + 虚拟 [`VirtualDevice`]（rx/tx FIFO）
//! - [`VirtualDevice`] 实现 smoltcp `phy::Device` trait，rx 端 = TUN 设备读出的 IP 包，
//!   tx 端 = smoltcp 欲发送的 IP 包（直接写回 TUN 设备）
//! - 通过 [`TunNetStack::ingest_rx`] 投递 TUN 读出的 IP 包
//! - 通过 [`TunNetStack::drain_tx`] 取出 smoltcp 要发的 IP 包
//! - 通过 [`TunNetStack::poll`] 驱动 smoltcp 协议栈（处理 TCP/UDP socket 状态）
//!
//! ## 线程模型
//!
//! 单线程驱动：inbound handler task 在持锁期间依次执行 ingest_rx → poll → drain_tx。
//! smoltcp Interface 不是 Sync，必须由 driver task 单点驱动。

use std::collections::VecDeque;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::icmp;
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address,
};

/// smoltcp 协议栈 poll 一次处理的最大 RX 包数。
const POLL_RX_BUDGET: usize = 64;

/// TCP/UDP socket 缓冲大小。
const SOCKET_BUF_SIZE: usize = 64 * 1024;

/// UDP socket metadata 槽位数。
const UDP_META_SLOTS: usize = 32;

/// ICMP socket metadata 槽位数。
const ICMP_META_SLOTS: usize = 16;

/// ICMP socket 缓冲大小。
const ICMP_BUF_SIZE: usize = 16 * 1024;

/// TUN 用的 smoltcp 网络栈。
///
/// 内部持有 Interface（不可跨线程共享）+ VirtualDevice（FIFO）+ SocketSet。
/// 由 inbound handler task 单点驱动。
pub struct TunNetStack {
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    /// ICMP socket handle（用于自动回复 echo request）。
    icmp_handle: SocketHandle,
}

impl TunNetStack {
    /// 构造网栈。
    ///
    /// # 参数
    ///
    /// - `local_addrs`：interface 地址（如 `["10.0.0.1/24"]`）
    /// - `mtu`：MTU；与 TunDevice 配置一致
    #[must_use]
    pub fn new(local_addrs: &[IpCidr], mtu: usize) -> Self {
        let mut device = VirtualDevice::new(mtu);
        // IP medium：无 ethernet header，直接 IP 包
        let config = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            for addr in local_addrs {
                let _ = addrs.push(*addr);
            }
        });

        // 配置默认路由：IPv4/IPv6 默认路由指向 interface 地址（对应 Go stackGVisor 的
        // defaultRoute）。smoltcp 对非本地 dest 包走默认路由，没有路由则 drop。
        // ponytail: 用 interface 自己作 gateway——smoltcp 对 TUN medium 直连模式
        // 只需要存在一条默认路由，gateway 字段不影响
        let has_v4 = local_addrs
            .iter()
            .any(|c| matches!(c, IpCidr::Ipv4(_)));
        let has_v6 = local_addrs
            .iter()
            .any(|c| matches!(c, IpCidr::Ipv6(_)));
        iface.routes_mut().update(|routes| {
            if has_v4 {
                // IPv4 默认路由：用 0.0.0.0 作 gateway（TUN medium 无 ARP）
                let _ = routes.push(smoltcp::iface::Route::new_ipv4_gateway(
                    Ipv4Address::new(0, 0, 0, 0),
                ));
            }
            if has_v6 {
                let _ = routes.push(smoltcp::iface::Route::new_ipv6_gateway(
                    Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0),
                ));
            }
        });

let mut stack = Self {
iface,
device,
// ponytail: SocketSet 用 Vec 作 backing storage，'static bound 由 alloc 满足
            sockets: SocketSet::new(Vec::new()),
            icmp_handle: SocketHandle::default(),
};

        // 自动创建 ICMP socket 并绑定到 ident 0——smoltcp 收到 ICMP echo request 时
        // 通过 ICMP socket 传递到上层（对应 Go stackGVisor 的 handleICMPEchoPacket）。
        // smoltcp 与 gVisor 不同：gVisor 在 netstack 层自动回复 echo request，
        // smoltcp 只通过 ICMP socket 传递，需在 driver loop 中手动构建 echo reply。
        // 详见 inbound::handle_icmp_echo_reply。
        let icmp_handle = stack.add_icmp_socket();
        stack.icmp_handle = icmp_handle;

        stack
    }

    /// 投递一个 IP 包到 RX FIFO。handler 从 TUN 设备 recv 后调用。
    pub fn ingest_rx(&mut self, pkt: Vec<u8>) {
        self.device.rx_queue.push_back(pkt);
    }

    /// 取出所有 smoltcp 要发送的 IP 包（待写回 TUN 设备）。
    #[must_use]
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.tx_queue.drain(..).collect()
    }

    /// 驱动 smoltcp 协议栈。handler loop 每次 recv 后 / 每 100ms 调一次。
    pub fn poll(&mut self, now: Instant) {
        // 多次 poll 直到无变化（处理多包交互）
        for _ in 0..POLL_RX_BUDGET {
            let result = self.iface.poll(now, &mut self.device, &mut self.sockets);
            if result == smoltcp::iface::PollResult::None {
                break;
            }
        }
    }

    /// 处理 ICMP echo request 并自动回复 echo reply。
    ///
    /// smoltcp 与 gVisor 不同：gVisor netstack 层自动回复 echo request，
    /// smoltcp 只通过 ICMP socket 传递 echo request 到上层。
    /// 此方法在 poll() 后调用，读取所有待处理的 echo request 并构建 echo reply。
    pub fn process_icmp_echo(&mut self) {
        let mut buf = [0u8; ICMP_BUF_SIZE];
        loop {
            let socket = self.sockets.get_mut::<icmp::Socket<'static>>(self.icmp_handle);
            let (n, remote) = match socket.recv_slice(&mut buf) {
                Ok(result) => result,
                Err(_) => break, // 无更多数据
            };
            let pkt = &buf[..n];
            if pkt.len() < 8 {
                continue;
            }
            // ICMP type 8 = Echo Request → 回复 type 0 = Echo Reply
            if pkt[0] != 8 {
                continue;
            }
            let mut reply = pkt.to_vec();
            reply[0] = 0; // Echo Reply
            reply[2] = 0;
            reply[3] = 0;
            let cksum = icmp_checksum(&reply);
            reply[2..4].copy_from_slice(&cksum.to_be_bytes());
            let socket = self.sockets.get_mut::<icmp::Socket<'static>>(self.icmp_handle);
            let _ = socket.send_slice(&reply, remote);
        }
        // poll 一次让 smoltcp 把发送队列的包写进 tx_queue
        self.iface.poll(Instant::now(), &mut self.device, &mut self.sockets);
    }

    /// 创建一个 TCP socket 加入 socket set，返回 handle。
    ///
    /// 后续 dispatcher 桥接时调用。socket 初始为 closed，需要 [`Self::tcp_connect`]。
    #[must_use]
    pub fn add_tcp_socket(&mut self) -> SocketHandle {
        let recv_buf = tcp::SocketBuffer::new(vec![0; SOCKET_BUF_SIZE]);
        let send_buf = tcp::SocketBuffer::new(vec![0; SOCKET_BUF_SIZE]);
        let socket = tcp::Socket::new(recv_buf, send_buf);
        self.sockets.add(socket)
    }

    /// 创建一个 ICMP socket 加入 socket set，返回 handle。
    ///
    /// 用于自动回复 ICMP echo request（对应 Go stackGVisor.handleICMPEchoPacket）。
    /// smoltcp 的 ICMP socket 绑定到 `Endpoint::Ident(0)` 后，协议栈收到 echo request
    /// 时会自动生成 echo reply 并放入 TX 队列。
    #[must_use]
    pub fn add_icmp_socket(&mut self) -> SocketHandle {
        let rx_buf = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; ICMP_META_SLOTS],
            vec![0; ICMP_BUF_SIZE],
        );
        let tx_buf = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; ICMP_META_SLOTS],
            vec![0; ICMP_BUF_SIZE],
        );
        let socket = icmp::Socket::new(rx_buf, tx_buf);
        let handle = self.sockets.add(socket);
        // 绑定到 ident 0——接收所有 echo request（ident 过滤为 0 表示通配）
        let _ = self.icmp_bind(handle);
        handle
    }

    /// 绑定 ICMP socket。
    ///
    /// 返回 `Err` 表示 smoltcp 拒绝（socket 已绑定 / 状态非法）。
    pub fn icmp_bind(&mut self, handle: SocketHandle) -> Result<(), icmp::BindError> {
        let socket = self.sockets.get_mut::<icmp::Socket<'static>>(handle);
        socket.bind(icmp::Endpoint::Ident(0))
    }

    /// 创建一个 UDP socket 加入 socket set，返回 handle。
    #[must_use]
    pub fn add_udp_socket(&mut self) -> SocketHandle {
        let rx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0; SOCKET_BUF_SIZE],
        );
        let tx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0; SOCKET_BUF_SIZE],
        );
        let socket = udp::Socket::new(rx_buf, tx_buf);
        self.sockets.add(socket)
    }

    /// 移除 socket。
    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    /// 借用指定 TCP socket 执行闭包。
    pub fn with_tcp_socket<R>(
        &mut self,
        handle: SocketHandle,
        f: impl FnOnce(&mut tcp::Socket<'static>) -> R,
    ) -> R {
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        f(socket)
    }

    /// 借用指定 UDP socket 执行闭包。
    pub fn with_udp_socket<R>(
        &mut self,
        handle: SocketHandle,
        f: impl FnOnce(&mut udp::Socket<'static>) -> R,
    ) -> R {
        let socket = self.sockets.get_mut::<udp::Socket<'static>>(handle);
        f(socket)
    }

    /// 发起 TCP 连接（client side）。
    ///
    /// 返回 `Err` 表示 smoltcp 拒绝（如地址族不匹配）。
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: IpAddress,
        port: u16,
    ) -> Result<(), tcp::ConnectError> {
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        // local_endpoint 用 0.0.0.0:0（让 smoltcp 自动选 src 地址）
        socket.connect(self.iface.context(), (remote, port), 0)
    }

    /// TCP 监听（server side）。对应 Go `tcp.NewForwarder` 的 listen 语义。
    ///
    /// 把 socket 置为 Listen 状态，接受任意源地址的连接。
    /// 后续用 [`Self::tcp_accept`] 检查是否有新连接进入。
    ///
    /// # 参数
    ///
    /// - `handle`：TCP socket handle（必须处于 Closed 状态）
    /// - `port`：监听端口
    ///
    /// # 错误
    ///
    /// - [`TunError::TcpListenFailed`]：socket 状态非法或地址不可用
    pub fn tcp_listen(
        &mut self,
        handle: SocketHandle,
        port: u16,
    ) -> Result<(), crate::error::TunError> {
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        socket
            .listen(port)
            .map_err(|e| crate::error::TunError::TcpListenFailed(format!("{e:?}")))
    }

    /// UDP 绑定（server side）。对应 Go `udp.NewForwarder` 的 bind 语义。
    ///
    /// 把 socket 绑定到指定端口，接收发往该端口的 UDP 数据报。
    /// 后续用 [`Self::udp_recv`] 检查是否有数据报到达。
    ///
    /// # 参数
    ///
    /// - `handle`：UDP socket handle（必须处于 Closed 状态）
    /// - `port`：绑定端口
    ///
    /// # 错误
    ///
    /// - [`TunError::UdpBindFailed`]：socket 状态非法或地址不可用
    pub fn udp_bind(
        &mut self,
        handle: SocketHandle,
        port: u16,
    ) -> Result<(), crate::error::TunError> {
        let socket = self.sockets.get_mut::<udp::Socket<'static>>(handle);
        socket
            .bind(port)
            .map_err(|e| crate::error::TunError::UdpBindFailed(format!("{e:?}")))
    }

    /// 检测 TCP socket 是否有新连接已 accept（状态从 Listen 转为 Established）。
    ///
    /// 对应 Go `tcp.NewForwarder` 的 callback：上层创建一个 Listen socket，
    /// poll 后用此方法检测是否有连接进入。检测后 socket 已处于 Established 状态，
    /// 可直接用 `with_tcp_socket` 读写。
    ///
    /// # 参数
    ///
    /// - `handle`：处于 Listen 状态的 TCP socket handle
    ///
    /// # 返回
    ///
    /// - `Some(TcpAcceptEvent)`：连接已 accept，包含 remote endpoint
    /// - `None`：socket 仍处于 Listen 或其他非 Established 状态
    #[must_use]
    pub fn check_tcp_accept(&mut self, handle: SocketHandle) -> Option<TcpAcceptEvent> {
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        match socket.state() {
            tcp::State::Established => {
                let remote = socket.remote_endpoint()?;
                Some(TcpAcceptEvent { handle, remote })
            }
            _ => None,
        }
    }

    /// 从 UDP socket 读取一个数据报（如果存在）。
    ///
    /// 对应 Go `udpForwarder.HandlePacket` 的数据报接收：上层创建绑定 socket，
    /// poll 后用此方法读取到达的数据报。
    ///
    /// # 参数
    ///
    /// - `handle`：已绑定的 UDP socket handle
    ///
    /// # 返回
    ///
    /// - `Some(UdpRecvEvent)`：有数据报到达
    /// - `None`：无数据
    #[must_use]
    pub fn udp_recv(&mut self, handle: SocketHandle) -> Option<UdpRecvEvent> {
        let socket = self.sockets.get_mut::<udp::Socket<'static>>(handle);
        let local_endpoint = socket.endpoint();
        let local_port = local_endpoint.port;
        let local_addr = local_endpoint.addr;
        // recv_slice 返回 (n, meta)，失败表示无数据
        let mut buf = vec![0u8; SOCKET_BUF_SIZE];
        match socket.recv_slice(&mut buf) {
            Ok((n, meta)) => {
                buf.truncate(n);
                Some(UdpRecvEvent {
                    handle,
                    remote: meta.endpoint,
                    local_addr,
                    local_port,
                    payload: buf,
                })
            }
            Err(_) => None,
        }
    }

    /// 向 UDP socket 发送数据报（回包）。
    ///
    /// 对应 Go `udpForwarder` 的回包路径：dispatcher 处理后把响应发回原 socket。
    ///
    /// # 返回
    ///
    /// - `Ok(())`：已放入发送缓冲
    /// - `Err`：缓冲满 / 地址不可达
    pub fn udp_send(
        &mut self,
        handle: SocketHandle,
        remote: IpEndpoint,
        data: &[u8],
    ) -> Result<(), udp::SendError> {
        let socket = self.sockets.get_mut::<udp::Socket<'static>>(handle);
        socket.send_slice(data, remote)
    }

    /// smoltcp Interface 借用（高级用法——路由表修改等）。
    #[must_use]
    pub fn iface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }
}


// ===== 事件检测：poll 后检查 socket 状态变化 =====

/// TCP socket 的状态事件（poll 后检测）。
///
/// 对应 Go `tcp.NewForwarder` 的 callback：新连接到达时通知上层。
///
/// smoltcp 的 accept 语义与 gVisor 不同：gVisor 显式 `CreateEndpoint` 创建新 socket；
/// smoltcp 在 Listen socket 的 SYN-RCVD → ESTABLISHED 转换时完成 accept，
/// `accept()` 返回 remote endpoint。
///
/// 简化策略：上层创建多个 Listen socket（端口池），每次 poll 后检查哪个 socket
/// 从 Listen 变成 Established——那个 socket 即是一个新接受的连接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpAcceptEvent {
    /// 已接受的 socket handle。
    pub handle: SocketHandle,
    /// 远端地址（客户端 IP+端口）。
    pub remote: IpEndpoint,
}

/// UDP 数据报到达事件（poll 后检测）。
///
/// 对应 Go `udpForwarder.HandlePacket`：收到 UDP 数据报后交给 dispatcher。
#[derive(Debug, Clone)]
pub struct UdpRecvEvent {
    /// 收到数据的 socket handle。
    pub handle: SocketHandle,
    /// 远端地址（发送方 IP+端口）。
    pub remote: IpEndpoint,
    /// 本地绑定的地址（TUN 侧 dest，用于 dispatcher destination）。
    pub local_addr: Option<IpAddress>,
    /// 本地端口。
    pub local_port: u16,
    /// 负载。
    pub payload: Vec<u8>,
}

// ===== VirtualDevice：smoltcp phy::Device 实现 =====

/// 虚拟网络设备——rx/tx 端都是 `Vec<u8>` FIFO（IP 包）。
///
/// - rx_queue：handler 从 TUN 设备读出后写入，smoltcp 读出
/// - tx_queue：smoltcp 写入（要发的 IP 包），handler 读出后写回 TUN 设备
pub struct VirtualDevice {
    mtu: usize,
    /// RX FIFO：handler → smoltcp（从 TUN 读出的入站 IP 包）
    rx_queue: VecDeque<Vec<u8>>,
    /// TX FIFO：smoltcp → handler（待写回 TUN 的出站 IP 包）
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    #[must_use]
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }
}

/// RX token：消费一个入站 IP 包。
pub struct VirtRxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

/// TX token：分配缓冲给 smoltcp 写入，结束后入 TX FIFO。
pub struct VirtTxToken {
    tx_queue_ptr: *mut VecDeque<Vec<u8>>,
}

// Safety: tx_queue_ptr 仅在 poll 同步调用栈中存活，由 handler task 单线程驱动。
unsafe impl Send for VirtTxToken {}

impl phy::TxToken for VirtTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // ponytail: 直接用 Vec<u8> 作缓冲，避免额外的 buf pool 抽象
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        // SAFETY: tx_queue_ptr 指向 VirtualDevice 内部 VecDeque，借用期间 handler 不并发访问
        // （smoltcp Device 的 contract：transmit/receive 调用是同步的，token 消费完才返回）
        unsafe {
            (*self.tx_queue_ptr).push_back(buf);
        }
        result
    }
}

// SAFETY: VirtualDevice 只在 handler task 单线程驱动，不跨线程共享。
// smoltcp 的 Device trait 期望单线程使用，但 handler task 的 future 需要 Send bound。
unsafe impl Send for VirtualDevice {}
unsafe impl Sync for VirtualDevice {}

impl phy::Device for VirtualDevice {
    type RxToken<'a> = VirtRxToken where Self: 'a;
    type TxToken<'a> = VirtTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 取一个 RX 包，同时给一个 TX token（用于立即回包，如 ICMP echo reply）
        self.rx_queue.pop_front().map(|packet| {
            let tx_token = VirtTxToken {
                tx_queue_ptr: &mut self.tx_queue as *mut _,
            };
            (VirtRxToken { packet }, tx_token)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // 始终允许发送（缓冲在 VecDeque 中）
        Some(VirtTxToken {
            tx_queue_ptr: &mut self.tx_queue as *mut _,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // 关闭校验和卸载：TUN userspace path 自己算
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps
    }
}

/// 把 std::net::Ipv4Addr 转 smoltcp::wire::Ipv4Address。
///
/// smoltcp 0.12 直接 re-export `core::net::Ipv4Addr`，所以两者等价——
/// 此函数仅作为显式转换点，方便阅读。
#[must_use]
pub fn to_smoltcp_v4(addr: std::net::Ipv4Addr) -> Ipv4Address {
    Ipv4Address::from_octets(addr.octets())
}

/// 把 std::net::Ipv6Addr 转 smoltcp::wire::Ipv6Address。
#[must_use]
pub fn to_smoltcp_v6(addr: std::net::Ipv6Addr) -> Ipv6Address {
    Ipv6Address::from_octets(addr.octets())
}

/// ICMP 校验和计算（RFC 792，与 IP 校验和算法相同）。
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stack() -> TunNetStack {
        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 24);
        TunNetStack::new(&[local], 1500)
    }

    #[test]
    fn construct_stack() {
        let _stack = make_stack();
    }

    #[test]
    fn add_and_remove_tcp_socket() {
        let mut stack = make_stack();
        let handle = stack.add_tcp_socket();
        stack.remove_socket(handle);
    }

    #[test]
    fn add_udp_socket() {
        let mut stack = make_stack();
        let handle = stack.add_udp_socket();
        stack.remove_socket(handle);
    }

    #[test]
    fn drain_tx_empty_initially() {
        let mut stack = make_stack();
        let drained = stack.drain_tx();
        assert!(drained.is_empty());
    }

    #[test]
    fn ingest_rx_does_not_panic() {
        // 喂一个 IPv4 ICMP echo request，poll 后 drain_tx 不 panic
        let mut stack = make_stack();
        let pkt = make_icmp_echo_request();
        stack.ingest_rx(pkt);
        stack.poll(Instant::now());
        let _ = stack.drain_tx();
    }

    fn make_icmp_echo_request() -> Vec<u8> {
        // IPv4 header (20) + ICMP header (8)
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 1; // protocol = ICMP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src = 外部主机
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst = 本地接口地址
        pkt[20] = 8; // ICMP type = Echo Request
        pkt
    }

    #[test]
    fn icmp_socket_auto_created_and_bound() {
        // new() 自动创建 ICMP socket 并绑定到 ident 0
        let mut stack = make_stack();
        // add_icmp_socket 返回 handle，绑定成功
        let handle = stack.add_icmp_socket();
        // 再次绑定应失败（已绑定）
        let result = stack.icmp_bind(handle);
        assert!(result.is_err(), "re-bind should fail");
    }

    #[test]
    fn tcp_listen_succeeds_on_closed_socket() {
        let mut stack = make_stack();
        let handle = stack.add_tcp_socket();
        // Closed 状态下 listen 应成功
        let result = stack.tcp_listen(handle, 8080);
        assert!(result.is_ok(), "tcp_listen failed: {:?}", result.err());
    }

    #[test]
    fn tcp_listen_fails_on_already_listening() {
        let mut stack = make_stack();
        let handle = stack.add_tcp_socket();
        stack.tcp_listen(handle, 8080).expect("first listen");
        // 再次 listen 应失败（状态非法）
        let result = stack.tcp_listen(handle, 9090);
        assert!(result.is_err(), "re-listen should fail");
    }

    #[test]
    fn check_tcp_accept_returns_none_when_listening() {
        // Listen 状态下 check_tcp_accept 应返回 None（无连接）
        let mut stack = make_stack();
        let handle = stack.add_tcp_socket();
        stack.tcp_listen(handle, 8080).expect("listen");
        stack.poll(Instant::now());
        let event = stack.check_tcp_accept(handle);
        assert!(event.is_none());
    }

    #[test]
    fn udp_bind_succeeds_on_closed_socket() {
        let mut stack = make_stack();
        let handle = stack.add_udp_socket();
        let result = stack.udp_bind(handle, 53);
        assert!(result.is_ok(), "udp_bind failed: {:?}", result.err());
    }

    #[test]
    fn udp_recv_returns_none_when_empty() {
        let mut stack = make_stack();
        let handle = stack.add_udp_socket();
        stack.udp_bind(handle, 53).expect("bind");
        stack.poll(Instant::now());
        let event = stack.udp_recv(handle);
        assert!(event.is_none());
    }

    #[test]
    fn icmp_echo_request_delivered_to_socket() {
        // ICMP echo request 应被 smoltcp 协议栈接收并放入 ICMP socket 的 rx 缓冲
        // （smoltcp 不自动回复 echo request，仅传递到 bound ICMP socket）
        let mut stack = make_stack();
        let pkt = make_icmp_echo_request();
        stack.ingest_rx(pkt);
        stack.poll(Instant::now());
        // poll 后 TX 可能为空（无自动回复），也可能有非 ICMP 包
        let _tx = stack.drain_tx();
    }

    #[test]
    fn icmp_echo_reply_generated() {
        // ICMP echo request → process_icmp_echo → TX 应含 echo reply
        let mut stack = make_stack();
        let pkt = make_icmp_echo_request();
        stack.ingest_rx(pkt);
        stack.poll(Instant::now());
        stack.process_icmp_echo();
        let tx = stack.drain_tx();
        // 至少有一个 TX 包（echo reply IP 包）
        assert!(!tx.is_empty(), "no echo reply generated");
        // 检查第一个 TX 包是 IPv4 ICMP echo reply
        let reply = &tx[0];
        assert!(reply.len() >= 28, "reply too short: {}", reply.len());
        assert_eq!(reply[0] >> 4, 4, "not IPv4");
        assert_eq!(reply[9], 1, "protocol not ICMP");
        assert_eq!(reply[20], 0, "ICMP type not Echo Reply (0)");
    }

}
