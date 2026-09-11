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

use std::collections::{HashMap, VecDeque};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::icmp;
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Packet, Ipv4Repr,
    Ipv6Address, Ipv6Packet, Ipv6Repr, IpProtocol, UdpPacket, UdpRepr,
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
    /// 惰性 TCP listen socket 缓存（票 ipb5）：key = SYN 的 dst (addr, port)。
    ///
    /// smoltcp 无通配端口监听（`listen(0)==Err(Unaddressable)`），须按实际包 dst
    /// 逐个注册。accept 后条目即摘除（socket 已转为连接 socket），下个 SYN 重建。
    tcp_listens: HashMap<IpEndpoint, SocketHandle>,
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

        // 默认路由 + AnyIP（票 ipb5）：TUN 截获的包 dst 是真实目标地址（公网 IP），
        // 不是本机接口地址。smoltcp `process_ipv4/ipv6` 在 `any_ip=false` 时直接丢弃
        // 此类包；`any_ip=true` 时仅当 `routes.lookup(dst)` 返回**本机地址**才放行——
        // 因此默认路由的 gateway 必须指向本机地址（对应 Go gVisor netstack 的
        // NIC 全收行为），出站方向 smoltcp 据此找到下一跳（TUN medium 无 ARP）。
        let v4_local = local_addrs.iter().find_map(|c| match c {
            IpCidr::Ipv4(c) => Some(c.address()),
            _ => None,
        });
        let v6_local = local_addrs.iter().find_map(|c| match c {
            IpCidr::Ipv6(c) => Some(c.address()),
            _ => None,
        });
        iface.routes_mut().update(|routes| {
            if let Some(v4) = v4_local {
                let _ = routes.push(smoltcp::iface::Route::new_ipv4_gateway(v4));
            }
            if let Some(v6) = v6_local {
                let _ = routes.push(smoltcp::iface::Route::new_ipv6_gateway(v6));
            }
        });
        iface.set_any_ip(true);

let mut stack = Self {
iface,
device,
// ponytail: SocketSet 用 Vec 作 backing storage，'static bound 由 alloc 满足
            sockets: SocketSet::new(Vec::new()),
            icmp_handle: SocketHandle::default(),
            tcp_listens: HashMap::new(),
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

    /// TCP 惰性监听（票 ipb5）。对应 Go `tcp.NewForwarder(stack, 0, 65535)` 的
    /// 通配端口语义——smoltcp 无此能力（`listen(0)==Err(Unaddressable)`），
    /// 改为在 IP 层解析 SYN 的 dst 后按具体 (addr, port) 注册。
    ///
    /// 缓存命中且 socket 仍处 Listen → 复用；未命中/已失效 → 新建 listen socket
    /// 并入缓存。accept（[`Self::check_tcp_accepts`]）后条目摘除，同 dst 的新
    /// SYN 自动重建。
    ///
    /// # 错误
    ///
    /// - [`TunError::TcpListenFailed`]：port=0（smoltcp 拒绝）或 socket 状态非法
    pub fn ensure_tcp_listen(&mut self, dst: IpEndpoint) -> Result<(), crate::error::TunError> {
        if let Some(&handle) = self.tcp_listens.get(&dst) {
            let state = self.sockets.get_mut::<tcp::Socket<'static>>(handle).state();
            if state == tcp::State::Listen {
                return Ok(());
            }
            // 占用（已 accept）或已失效：摘除后重建
            self.tcp_listens.remove(&dst);
        }
        let handle = self.add_tcp_socket();
        let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
        socket
            .listen(dst)
            .map_err(|e| crate::error::TunError::TcpListenFailed(format!("{e:?}")))?;
        self.tcp_listens.insert(dst, handle);
        Ok(())
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

    /// 检查所有惰性 listen socket 是否有新连接已 accept（票 ipb5）。
    ///
    /// 对应 Go `tcp.NewForwarder` 的 callback：poll 后扫描缓存，状态进入
    /// Established 的 socket 即完成 accept。返回的 socket 已从 listen 缓存摘除
    /// （转为连接 socket，由上层 relay 持有），可继续用 `with_tcp_socket` 读写。
    ///
    /// # 返回
    ///
    /// - `Vec<TcpAcceptEvent>`：本轮全部新 accept 的连接（可为空）
    #[must_use]
    pub fn check_tcp_accepts(&mut self) -> Vec<TcpAcceptEvent> {
        let mut events = Vec::new();
        let handles: Vec<SocketHandle> = self.tcp_listens.values().copied().collect();
        for handle in handles {
            let socket = self.sockets.get_mut::<tcp::Socket<'static>>(handle);
            if socket.state() != tcp::State::Established {
                continue;
            }
            let local = socket.local_endpoint();
            let Some(remote) = socket.remote_endpoint() else {
                continue;
            };
            // accept 完成：从 listen 缓存摘除（同 dst 的下一个 SYN 会重建 listen）
            self.tcp_listens.retain(|_, h| *h != handle);
            events.push(TcpAcceptEvent {
                handle,
                local,
                remote,
            });
        }
        events
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
/// 策略（bd ipb5）：listen socket 按 SYN dst 惰性注册（[`TunNetStack::ensure_tcp_listen`]），
/// 每次 poll 后 [`TunNetStack::check_tcp_accepts`] 扫描缓存，发现 Established 即 accept。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpAcceptEvent {
    /// 已接受的 socket handle。
    pub handle: SocketHandle,
    /// 本地端点（TUN 侧地址+端口，用于构建 dispatcher destination）。
    pub local: Option<IpEndpoint>,
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

/// 解析的 UDP 4 元组（IP+UDP 头中提取的 src/dst）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketMeta {
    pub src: IpEndpoint,
    pub dst: IpEndpoint,
}

/// 从原始 IP 包解析 UDP 4 元组 + payload。
///
/// 对应 Go `stackGVisor.Start` 的 UDP handler：从 IP+UDP 头读取 src/dst，
/// 把 raw UDP payload 交给 dispatcher（不是 smoltcp UDP socket）。
///
/// # 为什么不用 smoltcp UDP socket 接收
///
/// smoltcp 0.12 的 `udp::Socket::bind` 禁止 port 0（`BindError::Unaddressable`，
/// `socket/udp.rs:222`），且 `accepts` 严格匹配 `endpoint.port == dst_port`
///（`iface/interface/udp.rs:481`）——无法"接收任意端口的 UDP"。TUN 的语义是
/// 截获所有进站 UDP，必须在 IP 层解析。
///
/// TCP 的同款限制（`listen(0)==Err(Unaddressable)`）由 [`parse_tcp_syn_dst`] +
/// [`TunNetStack::ensure_tcp_listen`] 以同思路解决（票 ipb5）。
///
/// # 返回
///
/// - `Some((meta, payload))`：UDP 包解析成功
/// - `None`：非 UDP 包 / 包太短 / 校验和错
#[must_use]
pub fn parse_udp_packet(pkt: &[u8]) -> Option<(UdpPacketMeta, &[u8])> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => {
            let packet = Ipv4Packet::new_checked(pkt).ok()?;
            let repr = Ipv4Repr::parse(&packet, &smoltcp::phy::ChecksumCapabilities::ignored()).ok()?;
            if repr.next_header != IpProtocol::Udp {
                return None;
            }
            let payload_start = packet.header_len() as usize;
            let payload_end = payload_start + repr.payload_len;
            if payload_end > pkt.len() {
                return None;
            }
            let udp_pkt = UdpPacket::new_checked(&pkt[payload_start..payload_end]).ok()?;
            let udp_repr = UdpRepr::parse(
                &udp_pkt,
                &IpAddress::Ipv4(repr.src_addr),
                &IpAddress::Ipv4(repr.dst_addr),
                &smoltcp::phy::ChecksumCapabilities::ignored(),
            )
            .ok()?;
            let meta = UdpPacketMeta {
                src: IpEndpoint::new(IpAddress::Ipv4(repr.src_addr), udp_repr.src_port),
                dst: IpEndpoint::new(IpAddress::Ipv4(repr.dst_addr), udp_repr.dst_port),
            };
            Some((meta, udp_pkt.payload()))
        }
        6 => {
            let packet = Ipv6Packet::new_checked(pkt).ok()?;
            let repr = Ipv6Repr::parse(&packet).ok()?;
            if repr.next_header != IpProtocol::Udp {
                return None;
            }
            let payload_start = packet.header_len() as usize;
            let payload_end = payload_start + repr.payload_len;
            if payload_end > pkt.len() {
                return None;
            }
            let udp_pkt = UdpPacket::new_checked(&pkt[payload_start..payload_end]).ok()?;
            let udp_repr = UdpRepr::parse(
                &udp_pkt,
                &IpAddress::Ipv6(repr.src_addr),
                &IpAddress::Ipv6(repr.dst_addr),
                &smoltcp::phy::ChecksumCapabilities::ignored(),
            )
            .ok()?;
            let meta = UdpPacketMeta {
                src: IpEndpoint::new(IpAddress::Ipv6(repr.src_addr), udp_repr.src_port),
                dst: IpEndpoint::new(IpAddress::Ipv6(repr.dst_addr), udp_repr.dst_port),
            };
            Some((meta, udp_pkt.payload()))
        }
        _ => None,
    }
}

/// 从原始 IP 包解析 TCP SYN 的 dst endpoint（票 ipb5）。
///
/// 对应 UDP 路径的 [`parse_udp_packet`]：smoltcp 无通配端口监听，须先在 IP 层
/// 识别 SYN、取 dst (addr, port)，交 [`TunNetStack::ensure_tcp_listen`] 惰性注册。
/// 仅纯 SYN（SYN 置位、ACK 清零）触发注册——三次握手的 ACK/数据段交给既有
/// socket 处理。
///
/// # 返回
///
/// - `Some(IpEndpoint)`：TCP SYN 包的 dst endpoint
/// - `None`：非 TCP 包 / 非 SYN / 包太短 / 解析错
#[must_use]
pub fn parse_tcp_syn_dst(pkt: &[u8]) -> Option<IpEndpoint> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => {
            let packet = Ipv4Packet::new_checked(pkt).ok()?;
            let repr = Ipv4Repr::parse(&packet, &smoltcp::phy::ChecksumCapabilities::ignored()).ok()?;
            if repr.next_header != IpProtocol::Tcp {
                return None;
            }
            parse_syn_dst_from_tcp_header(&pkt[packet.header_len() as usize..], repr.dst_addr.into())
        }
        6 => {
            let packet = Ipv6Packet::new_checked(pkt).ok()?;
            let repr = Ipv6Repr::parse(&packet).ok()?;
            if repr.next_header != IpProtocol::Tcp {
                return None;
            }
            parse_syn_dst_from_tcp_header(&pkt[packet.header_len() as usize..], repr.dst_addr.into())
        }
        _ => None,
    }
}

/// TCP 头（裸字节）→ SYN 判定 + dst endpoint。`dst_addr` 来自 IP 头。
fn parse_syn_dst_from_tcp_header(tcp: &[u8], dst_addr: IpAddress) -> Option<IpEndpoint> {
    // TCP 头固定 20 字节（data offset 高 4 位 = 5，TUN 场景无 TCP 选项时不短于 20；
    // SYN 包带选项时 data offset > 5，头仍以 20 字节固定字段解析）
    if tcp.len() < 20 {
        return None;
    }
    // flags 字节（低 9 位标志中的低 8 位在此）：bit1=SYN bit4=ACK
    let flags = tcp[13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some(IpEndpoint::new(dst_addr, dst_port))
}


/// 构造 UDP 响应 IP 包（IPv4/IPv6，src/dst 已交换）。
///
/// 对应 Go `stackGVisor.writeRawUDPPacket`：dispatcher 处理完一包后，把响应
/// payload 装回 IP+UDP 头，src = 原 dst、dst = 原 src，写回 TUN。
///
/// # 参数
///
/// - `src_ip` / `dst_ip`：必须同族（IPv4 或 IPv6），调用方保证
/// - `src_port` / `dst_port`：UDP 端口
/// - `payload`：UDP payload
#[must_use]
pub fn build_udp_response(
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    match (src_ip, dst_ip) {
        (IpAddress::Ipv4(s4), IpAddress::Ipv4(d4)) => {
            let udp_repr = UdpRepr { src_port, dst_port };
            let ip_repr = Ipv4Repr {
                src_addr: s4,
                dst_addr: d4,
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + payload.len(),
                hop_limit: 64,
            };
            let mut buf = vec![0u8; ip_repr.buffer_len() + udp_repr.header_len() + payload.len()];
            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &smoltcp::phy::ChecksumCapabilities::ignored());
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_repr.buffer_len()..]);
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv4(s4),
                &IpAddress::Ipv4(d4),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &smoltcp::phy::ChecksumCapabilities::ignored(),
            );
            buf
        }
        (IpAddress::Ipv6(s6), IpAddress::Ipv6(d6)) => {
            let udp_repr = UdpRepr { src_port, dst_port };
            let ip_repr = Ipv6Repr {
                src_addr: s6,
                dst_addr: d6,
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + payload.len(),
                hop_limit: 64,
            };
            let mut buf = vec![0u8; ip_repr.buffer_len() + udp_repr.header_len() + payload.len()];
            let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt);
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_repr.buffer_len()..]);
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv6(s6),
                &IpAddress::Ipv6(d6),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &smoltcp::phy::ChecksumCapabilities::ignored(),
            );
            buf
        }
        _ => panic!("build_udp_response: src/dst IP family mismatch"),
    }
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
    fn ensure_tcp_listen_creates_then_reuses() {
        let mut stack = make_stack();
        let dst = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(93, 184, 216, 34)), 443);
        stack.ensure_tcp_listen(dst).expect("first ensure creates listen");
        assert_eq!(stack.tcp_listens.len(), 1, "one cached listen");
        let first = stack.tcp_listens[&dst];
        stack.ensure_tcp_listen(dst).expect("second ensure reuses");
        assert_eq!(stack.tcp_listens.len(), 1, "still one cached listen");
        assert_eq!(stack.tcp_listens[&dst], first, "same handle reused");
    }

    #[test]
    fn ensure_tcp_listen_rejects_port_zero() {
        // smoltcp listen(0) == Err(Unaddressable)，无通配端口监听（票 ipb5）
        let mut stack = make_stack();
        let dst = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)), 0);
        let result = stack.ensure_tcp_listen(dst);
        assert!(result.is_err(), "port 0 must be rejected");
        assert!(stack.tcp_listens.is_empty(), "failed ensure must not cache");
    }

    #[test]
    fn check_tcp_accepts_empty_when_listening() {
        // Listen 状态（无连接）下 check_tcp_accepts 应返回空
        let mut stack = make_stack();
        let dst = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)), 443);
        stack.ensure_tcp_listen(dst).expect("listen");
        stack.poll(Instant::now());
        assert!(stack.check_tcp_accepts().is_empty());
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

    // ===== parse_udp_packet / build_udp_response（bd 9wc） =====

    fn make_ipv4_udp_packet(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        // IPv4 header (20) + UDP header (8) + payload
        let total = 20 + 8 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // ident
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
        pkt[8] = 64; // TTL
        pkt[9] = 17; // protocol = UDP
        pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (ignored by parser)
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        // UDP header
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[26..28].copy_from_slice(&0u16.to_be_bytes()); // UDP checksum (0 = disabled)
        // payload
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_udp_packet_ipv4_extracts_4tuple_and_payload() {
        let pkt = make_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"hello");
        let (meta, payload) = parse_udp_packet(&pkt).expect("parse udp ipv4");
        assert_eq!(meta.src.addr, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)));
        assert_eq!(meta.src.port, 12345);
        assert_eq!(meta.dst.addr, IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)));
        assert_eq!(meta.dst.port, 53);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn parse_udp_packet_returns_none_for_tcp() {
        // 同样的 IPv4 header 但 protocol=TCP (6)
        let mut pkt = make_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"hello");
        pkt[9] = 6; // TCP
        assert!(parse_udp_packet(&pkt).is_none());
    }

    #[test]
    fn parse_udp_packet_returns_none_for_truncated() {
        // 截断：total length 报 50 但 buffer 只 20
        let mut pkt = make_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"hello");
        pkt[2..4].copy_from_slice(&50u16.to_be_bytes());
        assert!(parse_udp_packet(&pkt).is_none());
    }

    #[test]
    fn parse_udp_packet_returns_none_for_empty() {
        assert!(parse_udp_packet(&[]).is_none());
    }

    #[test]
    fn build_udp_response_ipv4_roundtrip() {
        // 构造包 → 解析 → 用 build_udp_response 构造响应 → 再解析响应验证 src/dst 交换
        let req = make_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"dns-query");
        let (req_meta, req_payload) = parse_udp_packet(&req).expect("parse req");
        assert_eq!(req_payload, b"dns-query");

        let reply = build_udp_response(req_meta.dst.addr, req_meta.dst.port, req_meta.src.addr, req_meta.src.port, req_payload);
        let (resp_meta, resp_payload) = parse_udp_packet(&reply).expect("parse resp");
        // 响应的 src 应是请求的 dst；响应的 dst 应是请求的 src
        assert_eq!(resp_meta.src.addr, req_meta.dst.addr);
        assert_eq!(resp_meta.src.port, req_meta.dst.port);
        assert_eq!(resp_meta.dst.addr, req_meta.src.addr);
        assert_eq!(resp_meta.dst.port, req_meta.src.port);
        assert_eq!(resp_payload, b"dns-query");
    }

    #[test]
    fn build_udp_response_ipv6() {
        // 构造 IPv6 + UDP 包（简化版：只用 Ipv6Repr emit 路径）
        let s6 = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let d6 = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let reply = build_udp_response(IpAddress::Ipv6(s6), 53, IpAddress::Ipv6(d6), 33333, b"v6-payload");
        assert!(reply[0] >> 4 == 6, "not IPv6");
        let (meta, payload) = parse_udp_packet(&reply).expect("parse v6 reply");
        assert_eq!(meta.src.addr, IpAddress::Ipv6(s6));
        assert_eq!(meta.dst.addr, IpAddress::Ipv6(d6));
        assert_eq!(meta.src.port, 53);
        assert_eq!(meta.dst.port, 33333);
        assert_eq!(payload, b"v6-payload");
    }

    // ===== parse_tcp_syn_dst（bd ipb5） =====

    /// 构造测试用 IPv4+TCP 包（无校验和——VirtualDevice caps 全 ignored）。
    fn make_ipv4_tcp_packet(
        src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16,
        seq: u32, ack: u32, flags: u8,
    ) -> Vec<u8> {
        let total = 20 + 20;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4; // data offset = 5（20 字节头）
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes()); // window
        pkt
    }

    /// 构造测试用 IPv6+TCP 包（无扩展头）。
    fn make_ipv6_tcp_packet(
        src: Ipv6Address, src_port: u16, dst: Ipv6Address, dst_port: u16, flags: u8,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + 20];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload len
        pkt[6] = 6; // next header = TCP
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        let tcp = &mut pkt[40..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        pkt
    }

    #[test]
    fn parse_tcp_syn_dst_ipv4_extracts_dst() {
        let pkt = make_ipv4_tcp_packet(
            [10, 0, 0, 2], 40000, [93, 184, 216, 34], 443,
            1000, 0, 0x02, // SYN
        );
        let dst = parse_tcp_syn_dst(&pkt).expect("parse SYN");
        assert_eq!(dst.addr, IpAddress::Ipv4(Ipv4Address::new(93, 184, 216, 34)));
        assert_eq!(dst.port, 443);
    }

    #[test]
    fn parse_tcp_syn_dst_ipv6_extracts_dst() {
        let s6 = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let d6 = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let pkt = make_ipv6_tcp_packet(s6, 40000, d6, 8080, 0x02);
        let dst = parse_tcp_syn_dst(&pkt).expect("parse SYN v6");
        assert_eq!(dst.addr, IpAddress::Ipv6(d6));
        assert_eq!(dst.port, 8080);
    }

    #[test]
    fn parse_tcp_syn_dst_returns_none_for_ack_and_synack() {
        // 纯 ACK（0x10）与 SYN-ACK（0x12）都不触发注册
        let ack = make_ipv4_tcp_packet([10, 0, 0, 2], 40000, [1, 2, 3, 4], 443, 1001, 2000, 0x10);
        assert!(parse_tcp_syn_dst(&ack).is_none());
        let synack = make_ipv4_tcp_packet([10, 0, 0, 2], 40000, [1, 2, 3, 4], 443, 1000, 2000, 0x12);
        assert!(parse_tcp_syn_dst(&synack).is_none());
    }

    #[test]
    fn parse_tcp_syn_dst_returns_none_for_udp() {
        let pkt = make_ipv4_udp_packet([10, 0, 0, 2], 12345, [8, 8, 8, 8], 53, b"hello");
        assert!(parse_tcp_syn_dst(&pkt).is_none());
    }

    #[test]
    fn parse_tcp_syn_dst_returns_none_for_truncated() {
        // TCP 头被截断到 < 20 字节
        let mut pkt = make_ipv4_tcp_packet([10, 0, 0, 2], 40000, [1, 2, 3, 4], 443, 1000, 0, 0x02);
        pkt.truncate(30); // IP 头 20 + TCP 头 10
        assert!(parse_tcp_syn_dst(&pkt).is_none());
    }
}

