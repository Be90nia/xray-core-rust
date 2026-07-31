//! smoltcp 用户态网络栈——处理 WireGuard 解密后的 IP 包。
//!
//! 对应 Go `proxy/wireguard/tun.go` 的 gVisor netstack。Rust 用 [`smoltcp`] 等价：
//!
//! - [`WgNetStack`] 持有 smoltcp [`Interface`] + 虚拟 [`VirtualDevice`]（rx/tx FIFO）
//! - [`VirtualDevice`] 实现 smoltcp `phy::Device` trait，rx 端 = 从 WG tunnel 解出的 IP 包，
//!   tx 端 = smoltcp 欲发送的 IP 包（待 WG 加密）
//! - 通过 [`WgNetStack::ingest_rx`] 投递解密后的 IP 包
//! - 通过 [`WgNetStack::drain_tx`] 取出待加密的 IP 包
//! - 通过 [`WgNetStack::poll`] 驱动 smoltcp 协议栈（处理 TCP/UDP socket 状态）
//!
//! ## 线程模型
//!
//! 单线程驱动：driver task 在持锁期间依次执行 ingest_rx → poll → drain_tx。
//! smoltcp Interface 不是 Sync，必须由 driver task 单点驱动。

use std::collections::VecDeque;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

/// smoltcp 协议栈 poll 一次处理的最大 RX 包数。
const POLL_RX_BUDGET: usize = 64;

/// TCP/UDP socket 缓冲大小。
const SOCKET_BUF_SIZE: usize = 64 * 1024;

/// UDP socket metadata 槽位数。
const UDP_META_SLOTS: usize = 32;

/// WireGuard 用的 smoltcp 网络栈。
///
/// 内部持有 Interface（不可跨线程共享）+ VirtualDevice（FIFO）+ SocketSet。
/// 由 driver task 单点驱动。
pub struct WgNetStack {
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
}

impl WgNetStack {
    /// 构造网栈。
    ///
    /// # 参数
    ///
    /// - `local_addrs`：interface 地址（如 `["10.0.0.2/32"]`）
    /// - `mtu`：MTU；与 DeviceConfig.effective_mtu() 一致
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

        Self {
            iface,
            device,
            // ponytail: SocketSet 用 Vec 作 backing storage，'static bound 由 alloc 满足
            sockets: SocketSet::new(Vec::new()),
        }
    }

    /// 投递一个解密后的 IP 包到 RX FIFO。driver 在 decapsulate 后调用。
    pub fn ingest_rx(&mut self, pkt: Vec<u8>) {
        self.device.rx_queue.push_back(pkt);
    }

    /// 取出所有待加密的 IP 包（smoltcp 协议栈要发的）。
    #[must_use]
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.tx_queue.drain(..).collect()
    }

    /// 驱动 smoltcp 协议栈。driver loop 每次 rx 后 / 每 100ms 调一次。
    pub fn poll(&mut self, now: Instant) {
        // 多次 poll 直到无变化（处理多包交互）
        for _ in 0..POLL_RX_BUDGET {
            let result = self.iface.poll(now, &mut self.device, &mut self.sockets);
            if result == smoltcp::iface::PollResult::None {
                break;
            }
        }
    }

    /// 创建一个 TCP socket 加入 socket set，返回 handle。
    ///
    /// driver outbound 建立连接时调用。socket 初始为 closed，需要 [`Self::tcp_connect`]。
    #[must_use]
    pub fn add_tcp_socket(&mut self) -> SocketHandle {
        let recv_buf = tcp::SocketBuffer::new(vec![0; SOCKET_BUF_SIZE]);
        let send_buf = tcp::SocketBuffer::new(vec![0; SOCKET_BUF_SIZE]);
        let socket = tcp::Socket::new(recv_buf, send_buf);
        self.sockets.add(socket)
    }

    /// 创建一个 UDP socket 加入 socket set，返回 handle。
    #[must_use]
    pub fn add_udp_socket(&mut self) -> SocketHandle {
        let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS], vec![0; SOCKET_BUF_SIZE]);
        let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS], vec![0; SOCKET_BUF_SIZE]);
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

    /// smoltcp Interface 借用（高级用法——路由表修改等）。
    #[must_use]
    pub fn iface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }
}

// ===== VirtualDevice：smoltcp phy::Device 实现 =====

/// 虚拟网络设备——rx/tx 端都是 `Vec<u8>` FIFO（IP 包）。
///
/// - rx_queue：driver 写入（从 WG tunnel 解出的 IP 包），smoltcp 读出
/// - tx_queue：smoltcp 写入（要发的 IP 包），driver 读出（喂给 WG tunnel 加密）
pub struct VirtualDevice {
    mtu: usize,
    /// RX FIFO：driver → smoltcp（解密后的入站 IP 包）
    rx_queue: VecDeque<Vec<u8>>,
    /// TX FIFO：smoltcp → driver（待加密的出站 IP 包）
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

// Safety: tx_queue_ptr 仅在 poll 同步调用栈中存活，由 driver task 单线程驱动。
unsafe impl Send for VirtTxToken {}

impl phy::TxToken for VirtTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // ponytail: 直接用 Vec<u8> 作缓冲，避免额外的 buf pool 抽象
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        // SAFETY: tx_queue_ptr 指向 VirtualDevice 内部 VecDeque，借用期间 driver 不并发访问
        // （smoltcp Device 的 contract：transmit/receive 调用是同步的，token 消费完才返回）
        unsafe {
            (*self.tx_queue_ptr).push_back(buf);
        }
        result
    }
}

// SAFETY: VirtualDevice 只在 driver task 单线程驱动，不跨线程共享。
// smoltcp 的 Device trait 期望单线程使用，但 driver task 的 future 需要 Send bound。
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
        // 关闭校验和卸载：WireGuard userspace path 自己算
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stack() -> WgNetStack {
        let local = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 32);
        WgNetStack::new(&[local], 1420)
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
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        pkt[20] = 8; // ICMP type = Echo Request
        pkt
    }
}
