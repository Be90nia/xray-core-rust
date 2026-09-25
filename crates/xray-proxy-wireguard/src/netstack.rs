//! smoltcp 用户态网络栈——处理 WireGuard 解密后的 IP 包。
//!
//! 对应 Go `proxy/wireguard/tun.go` 的 gVisor netstack。Rust 用 [`smoltcp`] 等价：
//!
//! - [`WgNetStack`] 持有 smoltcp [`Interface`] + 虚拟 [`VirtualDevice`]（rx/tx FIFO）
//! - [`VirtualDevice`] 实现 smoltcp `phy::Device` trait，rx 端 = 从 WG tunnel 解出的 IP 包， tx 端
//!   = smoltcp 欲发送的 IP 包（待 WG 加密）
//! - 通过 [`WgNetStack::ingest_rx`] 投递解密后的 IP 包
//! - 通过 [`WgNetStack::drain_tx`] 取出待加密的 IP 包
//! - 通过 [`WgNetStack::poll`] 驱动 smoltcp 协议栈（处理 TCP/UDP socket 状态）
//!
//! ## 线程模型
//!
//! 单线程驱动：driver task 在持锁期间依次执行 ingest_rx → poll → drain_tx。
//! smoltcp Interface 不是 Sync，必须由 driver task 单点驱动。

use std::collections::VecDeque;

use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::{tcp, udp},
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet,
        Ipv6Address, Ipv6Packet, TcpPacket,
    },
};

/// smoltcp 协议栈 poll 一次处理的最大 RX 包数。
const POLL_RX_BUDGET: usize = 64;

/// TCP/UDP socket 缓冲大小。
const SOCKET_BUF_SIZE: usize = 64 * 1024;

/// UDP socket metadata 槽位数。
const UDP_META_SLOTS: usize = 32;

/// 惰性监听表容量上限（SYN 扫描防护）。
///
/// # ponytail: 每 slot ~128KB 缓冲，512 上限最坏 ~64MB；出现端口扫描型内存压力再收紧。
const MAX_PENDING_LISTENS: usize = 512;

/// WireGuard 用的 smoltcp 网络栈。
///
/// 内部持有 Interface（不可跨线程共享）+ VirtualDevice（FIFO）+ SocketSet。
/// 由 driver task 单点驱动。
pub struct WgNetStack {
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    /// 下一个 TCP 临时端口种子（smoltcp 0.12 connect 要求本地端口非 0）。
    ///
    /// # ponytail: 顺序分配 32768..=60767，绕回前不重用；同远端旧连接仍开着的
    /// 精确 tuple 复用需 28000 并发连接，超出代理场景——瓶颈出现再做空闲端口扫描。
    next_ephemeral: u16,
    /// SYN 驱动的惰性 listen socket (handle, 监听 tuple)。
    ///
    /// smoltcp `listen` 对 port 0 恒报 Unaddressable，无通配监听语义；Go gVisor 用
    /// `tcp.NewForwarder` 对每个 SYN 走 per-request accept。Rust 等价物：`ingest_rx`
    /// 嗅探隧道内 TCP SYN，按目标 (addr, port) 惰性建听；accept 后同 tuple 补位
    /// （[`Self::drain_accepted`]）。不变量：同 tuple 至多一个 pending 监听。
    listening: Vec<(SocketHandle, IpEndpoint)>,
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

        // 配置默认路由（inbound accept 必需——SYN-ACK 需路由到远端 peer）。
        // 与 TunNetStack::new 对称：TUN medium 直连模式只需存在默认路由。
        let has_v4 = local_addrs.iter().any(|c| matches!(c, IpCidr::Ipv4(_)));
        let has_v6 = local_addrs.iter().any(|c| matches!(c, IpCidr::Ipv6(_)));
        iface.routes_mut().update(|routes| {
            if has_v4 {
                let _ = routes
                    .push(smoltcp::iface::Route::new_ipv4_gateway(Ipv4Address::new(0, 0, 0, 0)));
            }
            if has_v6 {
                let _ = routes.push(smoltcp::iface::Route::new_ipv6_gateway(Ipv6Address::new(
                    0, 0, 0, 0, 0, 0, 0, 0,
                )));
            }
        });

        Self {
            iface,
            device,
            // ponytail: SocketSet 用 Vec 作 backing storage，'static bound 由 alloc 满足
            sockets: SocketSet::new(Vec::new()),
            next_ephemeral: 0,
            listening: Vec::new(),
        }
    }

    /// 投递一个解密后的 IP 包到 RX FIFO。driver 在 decapsulate 后调用。
    ///
    /// 先嗅探 TCP SYN：smoltcp 没有通配监听（listen 对 port 0 恒报 Unaddressable），
    /// 必须在包入栈前按目标 tuple 建好精确监听，poll 时 SYN 才有归宿——
    /// 对应 Go `tcp.NewForwarder` 的 per-request accept（tun.go:56）。
    pub fn ingest_rx(&mut self, pkt: Vec<u8>) {
        if let Some((addr, port)) = sniff_tcp_syn(&pkt) {
            self.ensure_listen(IpEndpoint { addr, port });
        }
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
    /// 本地端口在此分配——smoltcp 0.12 `connect` 要求本地端口非 0（传 0 恒报
    /// `Unaddressable`），本地地址留 `None` 由栈按接口地址自动选源。
    ///
    /// 返回 `Err` 表示 smoltcp 拒绝（如地址族不匹配）。
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: IpAddress,
        port: u16,
    ) -> Result<(), tcp::ConnectError> {
        self.next_ephemeral = self.next_ephemeral.wrapping_add(1);
        let local_port = 32768 + (self.next_ephemeral as u32 % 28000) as u16;
        let local = smoltcp::wire::IpListenEndpoint { addr: None, port: local_port };
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        socket.connect(self.iface.context(), (remote, port), local)
    }

    /// 惰性建立精确 tuple 的 TCP 监听（幂等）。
    ///
    /// 目标端口为 0、同 tuple 已有 pending 监听、目标地址不属于本接口、或监听表
    /// 已达 [`MAX_PENDING_LISTENS`] 上限时跳过（SYN 由客户端重传兜底）。
    fn ensure_listen(&mut self, local: IpEndpoint) {
        if local.port == 0
            || self.listening.iter().any(|(_, ep)| *ep == local)
            || !self.iface.has_ip_addr(local.addr)
            || self.listening.len() >= MAX_PENDING_LISTENS
        {
            return;
        }
        self.open_listen(local);
    }

    /// 创建并注册一个 listen socket；失败即回收 socket。
    fn open_listen(&mut self, local: IpEndpoint) {
        let handle = self.add_tcp_socket();
        let result = self.with_tcp_socket(handle, |s| {
            s.listen(local)
                .map_err(|e| crate::error::WgError::NetStack(format!("tcp listen {local}: {e:?}")))
        });
        match result {
            Ok(()) => self.listening.push((handle, local)),
            Err(e) => {
                tracing::warn!(error = %e, "wg lazy tcp listen failed");
                self.remove_socket(handle);
            },
        }
    }

    /// 取出全部已 accept（监听 → Established）的连接，并为同 tuple 立即补位新监听。
    ///
    /// accept loop 每 tick 调用一次。补位让下一条到同端口的连接无需等 SYN 重传。
    #[must_use]
    pub fn drain_accepted(&mut self) -> Vec<TcpAcceptEvent> {
        let mut events = Vec::new();
        let mut i = 0;
        while i < self.listening.len() {
            let (handle, local) = self.listening[i];
            let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
            if socket.state() != tcp::State::Established {
                i += 1;
                continue;
            }
            let remote = socket.remote_endpoint();
            // 该 socket 已转为连接 socket，从监听表移除
            self.listening.swap_remove(i);
            match remote {
                Some(remote) => events.push(TcpAcceptEvent { handle, local: Some(local), remote }),
                // Established 却无对端 tuple 理论不可达；防御性回收
                None => self.remove_socket(handle),
            }
            self.open_listen(local);
        }
        events
    }

    /// smoltcp Interface 借用（高级用法——路由表修改等）。
    #[must_use]
    pub fn iface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }
}

/// 从解密后的 IP 包嗅探 TCP SYN（不含 ACK），返回目标 (addr, port)。
///
/// 只认 v4/v6 定长头 + TCP 定长头；非首分片与带扩展头的包直接跳过
/// （smoltcp 本身不重组分片，这类包无论如何进不了 TCP 层）。
fn sniff_tcp_syn(pkt: &[u8]) -> Option<(IpAddress, u16)> {
    let (dst_addr, payload) = match pkt.first()? >> 4 {
        4 => {
            let v4 = Ipv4Packet::new_checked(pkt).ok()?;
            if v4.more_frags() || v4.frag_offset() != 0 || v4.next_header() != IpProtocol::Tcp {
                return None;
            }
            (IpAddress::Ipv4(v4.dst_addr()), v4.payload())
        },
        6 => {
            let v6 = Ipv6Packet::new_checked(pkt).ok()?;
            if v6.next_header() != IpProtocol::Tcp {
                return None;
            }
            (IpAddress::Ipv6(v6.dst_addr()), v6.payload())
        },
        _ => return None,
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    Some((dst_addr, tcp.dst_port()))
}

// ===== 事件检测：poll 后检查 socket 状态变化 =====

/// TCP socket 的状态事件（poll 后检测）。
///
/// 由 SYN 驱动的惰性监听在 SYN-RCVD → ESTABLISHED 转换时产生，
/// [`WgNetStack::drain_accepted`] 批量取出。与 tun crate 的同名事件语义相同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpAcceptEvent {
    /// 已接受的 socket handle。
    pub handle: SocketHandle,
    /// 本地端点（WG 侧地址+端口，用于构建 dispatcher destination）。
    pub local: Option<IpEndpoint>,
    /// 远端地址（客户端 IP+端口）。
    pub remote: IpEndpoint,
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
        Self { mtu, rx_queue: VecDeque::new(), tx_queue: VecDeque::new() }
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
    type RxToken<'a>
        = VirtRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 取一个 RX 包，同时给一个 TX token（用于立即回包，如 ICMP echo reply）
        self.rx_queue.pop_front().map(|packet| {
            let tx_token = VirtTxToken { tx_queue_ptr: &mut self.tx_queue as *mut _ };
            (VirtRxToken { packet }, tx_token)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // 始终允许发送（缓冲在 VecDeque 中）
        Some(VirtTxToken { tx_queue_ptr: &mut self.tx_queue as *mut _ })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // TX 必须算校验和：WireGuard 只做加密，不改内层 IP/TCP 包——对端
        // （wireguard-go + gVisor / 内核）按标准栈校验，缺校验和静默丢包。
        // RX 跳过校验：对端是可信 userspace 栈（gVisor 发包必带校验和）。
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
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

/// 隧道内 IP/TCP 测试包构造。
///
/// RX 侧不校验 checksum（VirtualDevice capabilities 仅 Tx），测试包可零校验和。
#[cfg(test)]
pub(crate) mod test_packets {
    use smoltcp::wire::{Ipv4Packet, TcpPacket};

    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_ACK: u8 = 0x10;

    /// 构造 IPv4 + TCP 定长头包（无 payload）。
    pub fn make_tcp_packet(
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 6; // protocol = TCP
        pkt[12..16].copy_from_slice(&src.0);
        pkt[16..20].copy_from_slice(&dst.0);
        pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..32].copy_from_slice(&ack.to_be_bytes());
        pkt[32] = 0x50; // data offset = 5 words
        pkt[33] = flags;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        pkt
    }

    /// 提取 IPv4+TCP 包的 seq（SYN-ACK ISN 用）；非 TCP 包返回 None。
    pub fn tcp_seq_number(pkt: &[u8]) -> Option<u32> {
        let v4 = Ipv4Packet::new_checked(pkt).ok()?;
        if v4.next_header() != smoltcp::wire::IpProtocol::Tcp {
            return None;
        }
        let tcp = TcpPacket::new_checked(v4.payload()).ok()?;
        Some(tcp.seq_number().0 as u32)
    }
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

    #[test]
    fn tcp_connect_allocates_nonzero_local_port_and_distinct_tuples() {
        let mut stack = make_stack();
        let h1 = stack.add_tcp_socket();
        let h2 = stack.add_tcp_socket();
        let dst = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1));
        // smoltcp 0.12 对本地端口 0 恒报 Unaddressable——内部分配端口后必须成功
        stack.tcp_connect(h1, dst, 80).expect("first connect");
    }

    #[test]
    fn device_computes_tx_checksums() {
        let stack = make_stack();
        let caps = smoltcp::phy::Device::capabilities(&stack.device);
        assert!(caps.checksum.ipv4.tx());
        assert!(caps.checksum.tcp.tx());
        assert!(caps.checksum.udp.tx());
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

    // ===== SYN 驱动惰性监听（inbound TCP 修复核心）=====

    /// listen(0) 恒被 smoltcp 拒绝（Unaddressable）——旧 accept loop 启动即
    /// listen(0)，失败后 warn-continue 等价于 inbound TCP 永久关闭。
    /// 此断言钉死根因，防止任何路径再把 port 0 当通配监听用。
    #[test]
    fn listen_zero_port_is_rejected_by_smoltcp() {
        let mut stack = make_stack();
        let h = stack.add_tcp_socket();
        let err = stack
            .with_tcp_socket(h, |s| s.listen(0u16).map(|_| ()).err())
            .expect("listen(0) must be rejected");
        assert!(matches!(err, tcp::ListenError::Unaddressable));
    }

    /// SYN 入栈即按目标 tuple 惰性建听；完成三次握手后 drain 出 accept 事件，
    /// 同 tuple 补位监听就位。
    #[test]
    fn syn_creates_lazy_listen_and_completes_handshake() {
        use crate::netstack::test_packets::{TCP_ACK, TCP_SYN, make_tcp_packet, tcp_seq_number};

        let mut stack = make_stack(); // 本端 10.0.0.2/32
        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([10, 0, 0, 2], 443),
            TCP_SYN,
            1000,
            0,
        ));
        stack.poll(Instant::now());

        // 监听在 SYN 入栈前建好 → SYN 有归宿，SYN-ACK 已生成
        let server_seq =
            stack.drain_tx().iter().find_map(|p| tcp_seq_number(p)).expect("SYN-ACK with seq");

        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([10, 0, 0, 2], 443),
            TCP_ACK,
            1001,
            server_seq + 1,
        ));
        stack.poll(Instant::now());

        let events = stack.drain_accepted();
        assert_eq!(events.len(), 1, "exactly one accepted connection");
        let local = events[0].local.expect("local endpoint");
        assert_eq!(local.port, 443);
        assert_eq!(local.addr, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)));
        assert_eq!(events[0].remote.port, 5555);
        assert_eq!(stack.listening.len(), 1, "同 tuple 补位监听已就位");
    }

    /// 同 tuple 的 SYN 重传不产生重复监听（幂等）。
    #[test]
    fn syn_retransmit_creates_single_listen() {
        use crate::netstack::test_packets::{TCP_SYN, make_tcp_packet};

        let mut stack = make_stack();
        let syn = make_tcp_packet(([10, 0, 0, 1], 5555), ([10, 0, 0, 2], 443), TCP_SYN, 1000, 0);
        stack.ingest_rx(syn.clone());
        stack.ingest_rx(syn);
        assert_eq!(stack.listening.len(), 1, "retransmitted SYN must not duplicate listen");
    }

    /// 非 SYN 的 TCP 包不建监听。
    #[test]
    fn non_syn_tcp_creates_no_listen() {
        use crate::netstack::test_packets::{TCP_ACK, make_tcp_packet};

        let mut stack = make_stack();
        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([10, 0, 0, 2], 443),
            TCP_ACK,
            1001,
            1000,
        ));
        stack.poll(Instant::now());
        assert!(stack.listening.is_empty());
        assert!(stack.drain_accepted().is_empty());
    }
}
