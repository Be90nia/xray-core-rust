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

use std::collections::{HashSet, VecDeque};

use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::{tcp, udp},
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
        Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
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

/// 同 tuple 惰性监听并发上限——bd n07t F5 的最小 backlog 等价物。
///
/// Go gVisor `tcp.NewForwarder` 对每只 SYN 都建 endpoint（per-request accept，
/// 无界）；此处按每槽 ~128KB 缓冲给 16 的有界队列：同目标 ≤16 只并发握手/待
/// accept 连接各占一槽，超出后新 SYN 无 socket 受理，由 smoltcp 回 RST、客户端
/// 重传退避（与 [`MAX_PENDING_LISTENS`] 溢出语义一致）。
const MAX_LISTENS_PER_TUPLE: usize = 16;

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
    /// （[`Self::drain_accepted`]）。不变量：同 tuple 至多 [`MAX_LISTENS_PER_TUPLE`]
    /// 个 pending 监听（bd n07t F5：同目标并发 SYN 各占一槽排队，替代旧单槽位）。
    listening: Vec<(SocketHandle, IpEndpoint)>,
    /// 已受理 SYN 的 4 元组 (源, 目标)——重传/同 4 元组重复 SYN 不再建槽。
    ///
    /// 同步于建槽动作更新（不等 poll），与 `listening` 条目同生命周期：建槽成功
    /// 插入、drain_accepted accept 时移除。socket 状态在 poll 前不可见（Listen 态
    /// `tuple` 未置位），不能用作建槽判重依据。
    syn_seen: HashSet<(IpEndpoint, IpEndpoint)>,
    /// UDP 转发监听表 (handle, 绑定 endpoint, 最近使用 nanos)。
    ///
    /// 对应 TCP 的 `listening`：smoltcp UDP 同样无通配监听，`ingest_rx` 嗅探
    /// 隧道内 UDP 数据报的目标 tuple 惰性建 socket——票 z7ya，对应 Go 栈
    /// `handleUDP` → udp forwarder 的受理点。使用时间供 [`Self::sweep_udp`] 淘汰。
    udp_listens: Vec<(SocketHandle, IpEndpoint, i64)>,
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

        // AnyIP + 默认路由网关指向本接口地址（bd t8pm：inbound 接受任意 dst）。
        // smoltcp 对 dst 非本机地址的包，AnyIP 准入还要求 routes.lookup(dst) 的
        // 下一跳是本机地址（iface/interface/{ipv4,ipv6}.rs 的 "routed locally" 检查）；
        // 网关 = 自身地址即满足「所有单播 dst 都路由到本栈」。对应 Go 栈对任意 dst
        // 无条件受理（netstack.go CreateNetTUN：handler 在场即收任意地址的连接）。
        iface.set_any_ip(true);
        let self_v4 = local_addrs.iter().find_map(|c| match c {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            IpCidr::Ipv6(_) => None,
        });
        let self_v6 = local_addrs.iter().find_map(|c| match c {
            IpCidr::Ipv4(_) => None,
            IpCidr::Ipv6(cidr) => Some(cidr.address()),
        });
        iface.routes_mut().update(|routes| {
            if let Some(v4) = self_v4 {
                let _ = routes.push(smoltcp::iface::Route::new_ipv4_gateway(v4));
            }
            if let Some(v6) = self_v6 {
                let _ = routes.push(smoltcp::iface::Route::new_ipv6_gateway(v6));
            }
        });

        Self {
            iface,
            device,
            // ponytail: SocketSet 用 Vec 作 backing storage，'static bound 由 alloc 满足
            sockets: SocketSet::new(Vec::new()),
            next_ephemeral: 0,
            listening: Vec::new(),
            syn_seen: HashSet::new(),
            udp_listens: Vec::new(),
        }
    }

    /// 投递一个解密后的 IP 包到 RX FIFO。driver 在 decapsulate 后调用。
    ///
    /// 先按 Go `stack.Input()`（proxy/tun/stack.go:165-172）同款规则滤掉不可转发包
    /// （loopback / v4-mapped v6 / 未指定 dst / 组播 src——静默吞，不回 RST）。
    /// 再嗅探 TCP SYN：smoltcp 没有通配监听（listen 对 port 0 恒报 Unaddressable），
    /// 必须在包入栈前按目标 tuple 建好精确监听，poll 时 SYN 才有归宿——
    /// 对应 Go 栈 handleTCP 对新 SYN 的 per-connection 受理。
    pub fn ingest_rx(&mut self, pkt: Vec<u8>) {
        if not_forwardable(&pkt) {
            return;
        }
        if let Some((src, dst)) = sniff_tcp_syn(&pkt) {
            self.ensure_listen(src, dst);
        }
        // UDP 无重传：首个数据报必须能落地，惰性绑定必须在入栈前完成，
        // poll 时该包即被 socket 接收（否则 smoltcp 逐包回 ICMP port-unreachable，
        // 正是票 z7ya B 向黑洞的机理）。
        if let Some(dst) = sniff_udp_dst(&pkt) {
            self.ensure_udp_listen(dst);
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
        // UDP 监听表以 handle 反查——sweep/防御性回收之外的任意移除路径都不留悬空表项
        self.udp_listens.retain(|(h, _, _)| *h != handle);
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

    /// 惰性建立精确 tuple 的 TCP 监听（4 元组幂等 + per-tuple 并发排队）。
    ///
    /// 任意 dst 都建听——Go 栈对非本机地址的连接同样受理（netstack.go CreateNetTUN：
    /// "the stack takes every connection ... for any address"）；不可转发的 dst 已被
    /// `not_forwardable`（ingest_rx 入口过滤）挡掉。跳过条件：目标端口 0、该 SYN 的
    /// 4 元组已受理（重传/握手在途/已建立——[`Self::syn_seen`]）、同 tuple pending
    /// 已达 [`MAX_LISTENS_PER_TUPLE`]、或监听表已达 [`MAX_PENDING_LISTENS`]。
    fn ensure_listen(&mut self, src: IpEndpoint, dst: IpEndpoint) {
        if dst.port == 0
            || self.syn_seen.contains(&(src, dst))
            || self.tuple_pending(dst) >= MAX_LISTENS_PER_TUPLE
            || self.listening.len() >= MAX_PENDING_LISTENS
        {
            return;
        }
        if self.open_listen(dst) {
            self.syn_seen.insert((src, dst));
        }
    }

    /// 同 tuple 的 pending 监听数（握手在途 + 待 accept 连接 + 空闲补位）。
    fn tuple_pending(&self, dst: IpEndpoint) -> usize {
        self.listening.iter().filter(|(_, ep)| *ep == dst).count()
    }

    /// 创建并注册一个 listen socket；返回是否注册成功（失败已回收 socket）。
    fn open_listen(&mut self, local: IpEndpoint) -> bool {
        let handle = self.add_tcp_socket();
        let result = self.with_tcp_socket(handle, |s| {
            s.listen(local)
                .map_err(|e| crate::error::WgError::NetStack(format!("tcp listen {local}: {e:?}")))
        });
        match result {
            Ok(()) => {
                self.listening.push((handle, local));
                true
            },
            Err(e) => {
                crate::WG_LOG.warn(format!("wg lazy tcp listen failed error={e}"));
                self.remove_socket(handle);
                false
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
                Some(remote) => {
                    // 4 元组槽位已交付 relay，允许同 4 元组后续新连接重新建槽
                    self.syn_seen.remove(&(remote, local));
                    events.push(TcpAcceptEvent { handle, local: Some(local), remote });
                },
                // Established 却无对端 tuple 理论不可达；防御性回收
                //（syn_seen 键随条目遗留，理论上不可达路径不设清扫）
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

    /// 惰性建立精确 tuple 的 UDP 转发监听（幂等）。
    ///
    /// 对应 TCP 的 [`Self::ensure_listen`]：任意 dst 都建（AnyIP 受理，票 t8pm）；
    /// 目标端口为 0、同 tuple 已有监听、或表达 [`MAX_PENDING_LISTENS`] 上限时跳过
    /// （该包由 smoltcp 按无监听处理）。bind 失败回收 socket 并告警。
    fn ensure_udp_listen(&mut self, local: IpEndpoint) {
        if local.port == 0
            || self.udp_listens.iter().any(|(_, ep, _)| *ep == local)
            || self.udp_listens.len() >= MAX_PENDING_LISTENS
        {
            return;
        }
        let handle = self.add_udp_socket();
        let bound = IpListenEndpoint { addr: Some(local.addr), port: local.port };
        let result = self.with_udp_socket(handle, |s| {
            s.bind(bound)
                .map_err(|e| crate::error::WgError::NetStack(format!("udp bind {local}: {e:?}")))
        });
        match result {
            Ok(()) => self.udp_listens.push((handle, local, nanos_now())),
            Err(e) => {
                crate::WG_LOG.warn(format!("wg lazy udp listen failed error={e}"));
                self.remove_socket(handle);
            },
        }
    }

    /// 读取全部 UDP 转发监听的待收数据报。
    ///
    /// 返回 (绑定 endpoint = 隧道内目标, 源 endpoint = 隧道内源, payload)。
    /// accept loop 在 poll 后调用；命中即刷新该监听的使用时间（清扫时间源）。
    #[must_use]
    pub fn drain_udp(&mut self, now: i64) -> Vec<(IpEndpoint, IpEndpoint, Vec<u8>)> {
        let mut out = Vec::new();
        // 字段级拆借：`with_udp_socket` 是 &mut self 方法，借用 udp_listens 期间
        // 不可再调（E0499）；sockets 与 udp_listens 是不相交字段，直接拆借。
        let Self { sockets, udp_listens, .. } = self;
        for (handle, local, used) in udp_listens.iter_mut() {
            let socket = sockets.get_mut::<udp::Socket<'static>>(*handle);
            let mut fresh = false;
            while let Ok((data, meta)) = socket.recv() {
                out.push((*local, meta.endpoint, data.to_vec()));
                fresh = true;
            }
            if fresh {
                *used = now;
            }
        }
        out
    }

    /// 以隧道内目标 endpoint（= 响应源）向隧道内源发回一个 UDP 数据报。
    ///
    /// 对应 Go `stack.writeUDP(payload, src, dst)`：响应以原目标为源地址发回。
    /// 响应源未绑定监听时惰性补建（同一会话后续包换目标）；表满或 bind 失败
    /// 返回 false（调用方丢弃该响应并告警）。调用方随后 poll 一次将其发出。
    pub fn udp_send_reply(
        &mut self,
        reply_src: IpEndpoint,
        payload: &[u8],
        to_client: IpEndpoint,
        now: i64,
    ) -> bool {
        if reply_src.port == 0 {
            return false;
        }
        self.ensure_udp_listen(reply_src);
        let Some(entry) = self.udp_listens.iter_mut().find(|(_, ep, _)| *ep == reply_src) else {
            return false;
        };
        let handle = entry.0;
        entry.2 = now;
        self.with_udp_socket(handle, |s| s.send_slice(payload, to_client).is_ok())
    }

    /// 淘汰空闲 UDP 转发监听（无数据报进出超过 `idle_nanos`）。
    ///
    /// inbound 侧会话表独立清扫（inbound.rs，同空闲阈值）；监听 socket 与会话
    /// 的使用时间同在客户端包路径刷新，空闲时两侧一同回收。返回淘汰数。
    pub fn sweep_udp(&mut self, now: i64, idle_nanos: i64) -> usize {
        let mut removed = 0usize;
        let mut i = 0;
        while i < self.udp_listens.len() {
            if now.saturating_sub(self.udp_listens[i].2) > idle_nanos {
                let (handle, _, _) = self.udp_listens.swap_remove(i);
                self.remove_socket(handle);
                removed += 1;
            } else {
                i += 1;
            }
        }
        if removed > 0 {
            crate::WG_LOG.debug(format!("wg udp forwarder listens swept count={removed}"));
        }
        removed
    }
}

/// 从解密后的 IP 包嗅探 TCP SYN（不含 ACK），返回 (源 endpoint, 目标 endpoint)。
///
/// 只认 v4/v6 定长头 + TCP 定长头；非首分片与带扩展头的包直接跳过
/// （smoltcp 本身不重组分片，这类包无论如何进不了 TCP 层）。
fn sniff_tcp_syn(pkt: &[u8]) -> Option<(IpEndpoint, IpEndpoint)> {
    let (src_addr, dst_addr, payload) = match pkt.first()? >> 4 {
        4 => {
            let v4 = Ipv4Packet::new_checked(pkt).ok()?;
            if v4.more_frags() || v4.frag_offset() != 0 || v4.next_header() != IpProtocol::Tcp {
                return None;
            }
            (IpAddress::Ipv4(v4.src_addr()), IpAddress::Ipv4(v4.dst_addr()), v4.payload())
        },
        6 => {
            let v6 = Ipv6Packet::new_checked(pkt).ok()?;
            if v6.next_header() != IpProtocol::Tcp {
                return None;
            }
            (IpAddress::Ipv6(v6.src_addr()), IpAddress::Ipv6(v6.dst_addr()), v6.payload())
        },
        _ => return None,
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    Some((
        IpEndpoint { addr: src_addr, port: tcp.src_port() },
        IpEndpoint { addr: dst_addr, port: tcp.dst_port() },
    ))
}

/// 从解密后的 IP 包嗅探 UDP 数据报的目标 endpoint。
///
/// 与 [`sniff_tcp_syn`] 同款限定：v4/v6 定长头、首分片（smoltcp 不重组分片）；
/// 目标端口 0 交由 [`WgNetStack::ensure_udp_listen`] 拒绝。
fn sniff_udp_dst(pkt: &[u8]) -> Option<IpEndpoint> {
    let (dst_addr, payload) = match pkt.first()? >> 4 {
        4 => {
            let v4 = Ipv4Packet::new_checked(pkt).ok()?;
            if v4.more_frags() || v4.frag_offset() != 0 || v4.next_header() != IpProtocol::Udp {
                return None;
            }
            (IpAddress::Ipv4(v4.dst_addr()), v4.payload())
        },
        6 => {
            let v6 = Ipv6Packet::new_checked(pkt).ok()?;
            if v6.next_header() != IpProtocol::Udp {
                return None;
            }
            (IpAddress::Ipv6(v6.dst_addr()), v6.payload())
        },
        _ => return None,
    };
    let udp = UdpPacket::new_checked(payload).ok()?;
    Some(IpEndpoint { addr: dst_addr, port: udp.dst_port() })
}

/// 墙钟纳秒——UDP 转发监听/会话空闲清扫的时间源。
///
/// 713x6 台账：模块级自由函数（`WgNetStack` 纯栈包装无 ctx；调用链
/// `udp_send_reply`/空闲清扫不持 PluginContext），迁 Clock 需改栈 API 签名。
#[allow(
    clippy::disallowed_methods,
    reason = "UDP 转发/清扫挂钟读数；自由函数无 ctx 注入面（713x6 台账：结构性不可达）"
)]
pub(crate) fn nanos_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64)
}

/// Go `stack.Input()`（proxy/tun/stack.go:165-172）同款不可转发判定：
/// 4in6 双向、loopback 双向、未指定 dst、组播 src——这些地址「stands for this
/// machine itself or is not a real peer」，隧道对端不应请求；静默吞，不回 RST。
/// 解析失败的包同样丢弃（Go `parsePacket` 失败即 return）。
fn not_forwardable(pkt: &[u8]) -> bool {
    match pkt.first().map_or(0, |b| b >> 4) {
        4 => Ipv4Packet::new_checked(pkt).is_ok_and(|v4| {
            v4.src_addr().is_multicast()
                || v4.src_addr().is_loopback()
                || v4.dst_addr().is_loopback()
                || v4.dst_addr().is_unspecified()
        }),
        6 => Ipv6Packet::new_checked(pkt).is_ok_and(|v6| {
            v6.src_addr().to_ipv4_mapped().is_some()
                || v6.dst_addr().to_ipv4_mapped().is_some()
                || v6.src_addr().is_loopback()
                || v6.dst_addr().is_loopback()
                || v6.dst_addr().is_unspecified()
        }),
        _ => true,
    }
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

    #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
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
    #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
    Ipv4Address::from_octets(addr.octets())
}

/// 把 std::net::Ipv6Addr 转 smoltcp::wire::Ipv6Address。
#[must_use]
pub fn to_smoltcp_v6(addr: std::net::Ipv6Addr) -> Ipv6Address {
    #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
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

    /// 构造 IPv4 + UDP 包（零校验和——RX 不校验，见模块注释）。
    pub fn make_udp_packet(src: ([u8; 4], u16), dst: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 28 + payload.len()];
        let total_len = pkt.len() as u16;
        let udp_len = (8 + payload.len()) as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 17; // protocol = UDP
        pkt[12..16].copy_from_slice(&src.0);
        pkt[16..20].copy_from_slice(&dst.0);
        pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes()); // udp length
        // pkt[26..28] checksum = 0
        pkt[28..].copy_from_slice(payload);
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

    /// 提取 IPv4+TCP 包的 (SYN, ACK, RST) 标志（响应识别用）；非 TCP 包返回 None。
    pub fn tcp_flags(pkt: &[u8]) -> Option<(bool, bool, bool)> {
        let v4 = Ipv4Packet::new_checked(pkt).ok()?;
        if v4.next_header() != smoltcp::wire::IpProtocol::Tcp {
            return None;
        }
        let tcp = TcpPacket::new_checked(v4.payload()).ok()?;
        Some((tcp.syn(), tcp.ack(), tcp.rst()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::test_packets::make_udp_packet;

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
    fn udp_ingest_lazily_binds_and_drains() {
        let mut stack = make_stack(); // 本端 10.0.0.2/32
        stack.ingest_rx(make_udp_packet(([10, 0, 0, 1], 5555), ([1, 2, 3, 4], 53), b"query"));
        stack.poll(Instant::now());

        let dgrams = stack.drain_udp(nanos_now());
        assert_eq!(dgrams.len(), 1, "one datagram expected");
        let (dst, src, payload) = &dgrams[0];
        assert_eq!(dst.addr, IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)), "AnyIP dst");
        assert_eq!(dst.port, 53);
        assert_eq!(src.addr, IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)));
        assert_eq!(src.port, 5555);
        assert_eq!(payload, b"query");
        assert!(stack.drain_udp(nanos_now()).is_empty(), "drain is one-shot");
    }

    #[test]
    fn udp_reply_produces_tx_ip_packet() {
        let mut stack = make_stack();
        stack.ingest_rx(make_udp_packet(([10, 0, 0, 1], 5555), ([1, 2, 3, 4], 53), b"q"));
        stack.poll(Instant::now());
        assert_eq!(stack.drain_udp(nanos_now()).len(), 1);

        let reply_src =
            IpEndpoint { addr: IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)), port: 53 };
        let to_client =
            IpEndpoint { addr: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), port: 5555 };
        assert!(stack.udp_send_reply(reply_src, b"pong", to_client, nanos_now()));
        stack.poll(Instant::now());

        let tx = stack.drain_tx();
        assert_eq!(tx.len(), 1, "reply packet expected in tx queue");
        let v4 = Ipv4Packet::new_checked(&tx[0]).expect("ipv4 packet");
        assert_eq!(v4.next_header(), IpProtocol::Udp);
        assert_eq!(v4.src_addr(), Ipv4Address::new(1, 2, 3, 4), "reply src = 原目标");
        assert_eq!(v4.dst_addr(), Ipv4Address::new(10, 0, 0, 1), "reply dst = 隧道内源");
        let udp = UdpPacket::new_checked(v4.payload()).expect("udp packet");
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 5555);
        assert_eq!(udp.payload(), b"pong");
    }

    #[test]
    fn udp_sweep_removes_idle_listen() {
        let mut stack = make_stack();
        stack.ingest_rx(make_udp_packet(([10, 0, 0, 1], 5555), ([1, 2, 3, 4], 53), b"q"));
        stack.poll(Instant::now());
        assert_eq!(stack.drain_udp(nanos_now()).len(), 1);

        // 未过空闲期：不淘汰
        assert_eq!(stack.sweep_udp(nanos_now(), 60_000_000_000), 0);
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(stack.sweep_udp(nanos_now(), 0), 1, "idle listen removed");
        assert!(stack.drain_udp(nanos_now()).is_empty(), "socket removed with entry");
    }

    #[test]
    fn sniff_udp_dst_rejects_non_udp() {
        use crate::netstack::test_packets::{TCP_SYN, make_tcp_packet};

        assert_eq!(
            sniff_udp_dst(&make_tcp_packet(
                ([10, 0, 0, 1], 5555),
                ([1, 2, 3, 4], 80),
                TCP_SYN,
                1,
                0
            )),
            None,
            "TCP packet is not sniffed as UDP"
        );
        assert_eq!(sniff_udp_dst(&[0u8; 4]), None, "garbage is not sniffed");
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
        #[allow(unused_variables)] // 存量清零批次
        let _h2 = stack.add_tcp_socket();
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

    /// 非本接口地址的 dst 也建听并完成握手（bd t8pm：Go client 打公网 IP 的常见
    /// 拓扑；修复前此类 SYN 被 has_ip_addr 门吞掉，连接永不建立）。accept 事件的
    /// local endpoint 即真实 dst——dispatch 侧据此把它交给 outbound。
    #[test]
    fn syn_to_non_local_dst_creates_listen_and_completes_handshake() {
        use crate::netstack::test_packets::{TCP_ACK, TCP_SYN, make_tcp_packet, tcp_seq_number};

        let mut stack = make_stack(); // 本端 10.0.0.2/32
        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([1, 2, 3, 4], 80),
            TCP_SYN,
            1000,
            0,
        ));
        stack.poll(Instant::now());

        let server_seq =
            stack.drain_tx().iter().find_map(|p| tcp_seq_number(p)).expect("SYN-ACK with seq");

        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([1, 2, 3, 4], 80),
            TCP_ACK,
            1001,
            server_seq + 1,
        ));
        stack.poll(Instant::now());

        let events = stack.drain_accepted();
        assert_eq!(events.len(), 1, "exactly one accepted connection");
        let local = events[0].local.expect("local endpoint");
        assert_eq!(local.port, 80);
        assert_eq!(local.addr, IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)));
    }

    /// loopback dst 静默吞（Go Input() 同款）：不建听、不产生任何出站包。
    #[test]
    fn syn_to_loopback_dst_is_silently_dropped() {
        use crate::netstack::test_packets::{TCP_SYN, make_tcp_packet};

        let mut stack = make_stack();
        stack.ingest_rx(make_tcp_packet(
            ([10, 0, 0, 1], 5555),
            ([127, 0, 0, 2], 80),
            TCP_SYN,
            1000,
            0,
        ));
        stack.poll(Instant::now());
        assert!(stack.listening.is_empty(), "loopback dst must not create listen");
        assert!(stack.drain_tx().is_empty(), "loopback dst must be silently dropped");
        assert!(stack.drain_accepted().is_empty());
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
            1000,
            0,
        ));
        stack.poll(Instant::now());
        assert!(stack.listening.is_empty());
        assert!(stack.drain_accepted().is_empty());
    }

    /// 同目标并发 SYN（异源）各得一槽、各收 SYN-ACK、无 RST——bd n07t F5 修复钉子：
    /// 旧「同 tuple 至多一槽」下监听被首只 SYN 占用（SYN-RECEIVED 绑定远端）后，
    /// 第二只异源 SYN 无 socket 受理被回 RST。
    #[test]
    fn concurrent_syns_to_same_dst_each_get_a_slot() {
        use crate::netstack::test_packets::{TCP_SYN, make_tcp_packet, tcp_flags};

        let mut stack = make_stack(); // 本端 10.0.0.2/32
        for src_port in [5555u16, 5556, 5557] {
            stack.ingest_rx(make_tcp_packet(
                ([10, 0, 0, 1], src_port),
                ([10, 0, 0, 2], 443),
                TCP_SYN,
                1000,
                0,
            ));
        }
        stack.poll(Instant::now());

        assert_eq!(stack.listening.len(), 3, "每只并发 SYN 各得一槽");
        let tx = stack.drain_tx();
        let syn_acks =
            tx.iter().filter(|p| matches!(tcp_flags(p), Some((true, true, false)))).count();
        assert_eq!(syn_acks, 3, "三只 SYN 各回一个 SYN-ACK");
        assert!(
            tx.iter().all(|p| !matches!(tcp_flags(p), Some((_, _, true)))),
            "不得对并发 SYN 回 RST"
        );
    }
}
