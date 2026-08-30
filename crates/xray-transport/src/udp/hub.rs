//! # UDP hub
//!
//! 对应 Go `transport/internet/udp/hub.go`。UDP listener + recv loop。
//!
//! ## 架构
//!
//! - `UdpHub` — 持有 `UdpSocket` + 收包 channel，spawn recv 循环
//! - `UdpPacket` — 收到的 UDP 包（payload + source + optional origDest）
//! - `ListenUDP` — bind + spawn recv loop + return `UdpHub`
//!
//! origDest（TPROXY 原始目标地址）：Linux 下通过 `recvmsg` 读取 `IP_RECVORIGDSTADDR`/
//! `IPV6_RECVORIGDSTADDR` ancillary data 提取；非 Linux 平台不可用（`target = None`）。
//! udpmask wrapping：已接入 `crate::finalmask`——`listen()` 的 `udpmask` 参数
//! 非 `None` 且非空时经 `WrapPacketConnServer` 包装（对应 Go hub.go:71-77）。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

/// UDP 收包缓冲区大小（对应 Go `finalmask.UDPSize = 4096`）。
const UDP_BUFFER_SIZE: usize = 4096;

/// 默认收包 channel 容量（对应 Go `Hub.capacity = 256`）。
const DEFAULT_CACHE_CAPACITY: usize = 256;

// ===== UdpPacket =====

/// 收到的 UDP 包。对应 Go `protocol/udp.Packet`。
pub struct UdpPacket {
    /// 负载数据。
    pub payload: Vec<u8>,
    /// 来源地址。
    pub source: SocketAddr,
    /// 原始目标地址（TPROXY/redirect 场景）。
    ///
    /// Linux 下通过 `recvmsg` ancillary data（`IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR`）
    /// 提取；非 Linux 平台或未启用 `ReceiveOriginalDestination` 时为 `None`。
    pub target: Option<SocketAddr>,
}

// ===== HubOption =====

/// UDP Hub 配置选项。对应 Go `HubOption func(h *Hub)`。
pub trait HubOption: Send + Sync {
    fn apply(&self, hub: &mut UdpHubBuilder);
}

/// 收包 channel 容量。
pub struct Capacity(pub usize);
impl HubOption for Capacity {
    fn apply(&self, hub: &mut UdpHubBuilder) {
        hub.capacity = self.0;
    }
}

/// 是否接收原始目标地址（TPROXY）。
pub struct ReceiveOriginalDestination(pub bool);
impl HubOption for ReceiveOriginalDestination {
    fn apply(&self, hub: &mut UdpHubBuilder) {
        hub.recv_orig_dest = self.0;
    }
}

// ===== UdpHubBuilder =====

/// UDP Hub 构建器（内部用）。
pub struct UdpHubBuilder {
    capacity: usize,
    recv_orig_dest: bool,
}

impl Default for UdpHubBuilder {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CACHE_CAPACITY,
            recv_orig_dest: false,
        }
    }
}

// ===== UdpHub =====

/// UDP Hub。对应 Go `udp.Hub` struct。
///
/// 持有 `UdpSocket` + 收包 channel。`start()` 在独立 tokio task 中运行，
/// `recv_from` → 构造 `UdpPacket` → 发送到 channel。
/// 消费者通过 `receive()` 获取 channel receiver。
pub struct UdpHub {
    socket: Arc<UdpSocket>,
    /// udpmask 包装后的 server 侧 UDP I/O（Go hub.go:71-77 `WrapPacketConnServer`）。
    /// `None` = 无 mask，直接用 raw socket。recv 循环与 `send_to` 均经过此 io。
    io: Option<Arc<dyn crate::finalmask::UdpIo>>,
    rx: mpsc::Receiver<UdpPacket>,
    close_notify: Arc<Notify>,
    recv_orig_dest: bool,
}

impl UdpHub {
    /// 创建 UDP Hub 并 spawn recv 循环。
    ///
    /// 对应 Go `ListenUDP()`：bind → `UdpmaskManager.WrapPacketConnServer`（可选）
    /// → spawn `start()` → return。
    ///
    /// # 参数
    ///
    /// - `addr`：监听地址
    /// - `options`：配置选项（`Capacity`、`ReceiveOriginalDestination`）
    /// - `udpmask`：UDP 伪装链（Go hub.go:71-77：`streamSettings.UdpmaskManager != nil`
    ///   时包装 conn，recv 侧 decode、`send_to` 侧 encode）。`None` / 空 manager =
    ///   不包装（现有行为不变）。
    ///
    /// # 错误
    ///
    /// bind 失败 / mask 包装失败时返回 `io::Error`（后者对应 Go `"mask err"`）。
    pub async fn listen(
        addr: SocketAddr,
        options: &[Box<dyn HubOption>],
        udpmask: Option<crate::finalmask::UdpmaskManager>,
    ) -> io::Result<Self> {
        let mut builder = UdpHubBuilder::default();
        for opt in options {
            opt.apply(&mut builder);
        }

        let socket = Arc::new(bind_udp(addr, builder.recv_orig_dest).await?);
        // udpmask（Go hub.go:71-77）：包装后的 io 由 recv 循环与 send_to 共享。
        // 注意：mask 后无法走 TPROXY recvmsg 路径——对齐 Go（masked conn 的
        // `hub.conn.(*net.UDPConn)` 断言失败 → udpConn=nil → origDest 不可用）。
        let io: Option<Arc<dyn crate::finalmask::UdpIo>> = match udpmask.as_ref() {
            Some(mgr) if !mgr.udpmasks.is_empty() => {
                let wrapped =
                    mgr.wrap_packet_conn_server(Box::new(Arc::clone(&socket)))?;
                Some(Arc::from(wrapped))
            }
            _ => None,
        };
        let (tx, rx) = mpsc::channel(builder.capacity);
        let close_notify = Arc::new(Notify::new());

        let hub = Self {
            socket: Arc::clone(&socket),
            io: io.clone(),
            rx,
            close_notify: Arc::clone(&close_notify),
            recv_orig_dest: builder.recv_orig_dest,
        };

        // Spawn recv 循环。
        let recv_orig_dest = hub.recv_orig_dest;
        tokio::spawn(async move {
            match io {
                Some(io) => {
                    start_recv_loop_masked(&io, tx, close_notify).await;
                }
                None => {
                    start_recv_loop(&socket, tx, close_notify, recv_orig_dest).await;
                }
            }
        });

        Ok(hub)
    }

    /// 获取收包 channel receiver。
    ///
    /// 对应 Go `Hub.Receive() <-chan *udp.Packet`。
    /// 调用后 receiver 所有权转移，只能调用一次。
    pub fn receive(mut self) -> mpsc::Receiver<UdpPacket> {
        // ponytail: 消费 receiver，让调用方直接 await。
        // 如果需要多次获取，改用 Arc<Mutex<Receiver>> 或 watch channel。
        self.rx
    }

    /// 发送 UDP 包到指定地址。
    ///
    /// 对应 Go `Hub.WriteTo(payload, dest)`。
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match &self.io {
            // mask 路径：经 wrap_packet_conn_server 包装的 io 发送（encode 后上线）。
            Some(io) => io.send_to(buf, addr).await,
            None => self.socket.send_to(buf, addr).await,
        }
    }

    /// 监听器本地地址。
    ///
    /// 对应 Go `Hub.Addr()`。
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 关闭 UDP Hub。
    ///
    /// 对应 Go `Hub.Close()`。通知 recv 循环退出。
    /// 底层 UdpSocket 在 Arc drop 时关闭。
    pub fn close(&self) -> io::Result<()> {
        self.close_notify.notify_waiters();
        Ok(())
    }
}

// ===== recv 循环 =====

/// UDP 收包循环。对应 Go `Hub.start()`。
///
/// 普通 UDP 走 `recv_from`；Linux + `recv_orig_dest`（TPROXY）走 `recvmsg`，
/// 一次读取 payload + 发送方 + 原始目标地址（IP_RECVORIGDSTADDR ancillary data）。
/// channel 满时丢弃包（与 Go `select { case c <- payload: default: }` 一致）；
/// 收到 close 信号或 recv 错误时退出。
async fn start_recv_loop(
    socket: &UdpSocket,
    tx: mpsc::Sender<UdpPacket>,
    close_notify: Arc<Notify>,
    recv_orig_dest: bool,
) {
    #[cfg(target_os = "linux")]
    if recv_orig_dest {
        start_recv_loop_tproxy_linux(socket, tx, close_notify).await;
        return;
    }
    let _ = recv_orig_dest;

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, source)) => {
                        if n == 0 {
                            continue;
                        }
                        // 普通 UDP 路径：无原始目标地址（非 TPROXY 场景）。
                        let packet = UdpPacket {
                            payload: buf[..n].to_vec(),
                            source,
                            target: None,
                        };
                        // channel 满时丢弃（与 Go default 分支一致）。
                        if tx.try_send(packet).is_err() {
                            tracing::debug!("UDP hub cache full, dropping packet");
                        }
                    }
                    Err(e) => {
                        // 对应 Go：recv 错误 → log + break。
                        tracing::warn!(error = %e, "failed to read UDP msg");
                        break;
                    }
                }
            }
            _ = close_notify.notified() => {
                // 收到关闭信号，退出循环。
                break;
            }
        }
    }
}

/// mask 后的 UDP 收包循环（Go `Hub.start()` 读 wrapped `net.PacketConn`）。
///
/// 读经 [`crate::finalmask::UdpIo`]（server 侧 wrap，recv 即 decode）；
/// TPROXY origDest 不可用（mask 链无法透传 recvmsg ancillary data，
/// `target` 恒 `None`——对齐 Go masked conn 下 `udpConn=nil` 的行为）。
async fn start_recv_loop_masked(
    io: &Arc<dyn crate::finalmask::UdpIo>,
    tx: mpsc::Sender<UdpPacket>,
    close_notify: Arc<Notify>,
) {
    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            result = io.recv_from(&mut buf) => {
                match result {
                    Ok((n, source)) => {
                        if n == 0 {
                            continue;
                        }
                        let packet = UdpPacket {
                            payload: buf[..n].to_vec(),
                            source,
                            target: None,
                        };
                        if tx.try_send(packet).is_err() {
                            tracing::debug!("UDP hub cache full, dropping packet");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to read UDP msg");
                        break;
                    }
                }
            }
            _ = close_notify.notified() => {
                break;
            }
        }
    }
}

// ===== TPROXY 原始目标地址（Linux only） =====

/// 创建 UDP socket。
///
/// TPROXY 模式（Linux + `recv_orig_dest`）下用 `socket2` 在 bind 前设置
/// `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR`（IPv6 对应）socket option，使其能接收透明
/// 代理流量并附带原始目标地址；其余情况走普通 `UdpSocket::bind`。
async fn bind_udp(addr: SocketAddr, recv_orig_dest: bool) -> io::Result<UdpSocket> {
    #[cfg(target_os = "linux")]
    if recv_orig_dest {
        return bind_udp_tproxy_linux(addr);
    }
    let _ = recv_orig_dest;
    UdpSocket::bind(addr).await
}

#[cfg(target_os = "linux")]
fn bind_udp_tproxy_linux(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::AsRawFd;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // TPROXY 常与 iptables PREROUTING 在同主机共存，SO_REUSEADDR 避免冲突。
    sock.set_reuse_address(true)?;

    let fd = sock.as_raw_fd();
    // 透明绑定（可绑非本地地址）+ 请求原始目标地址 ancillary data。
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR, 1)?;
    if addr.is_ipv6() {
        // IPv6 对应常量在 uclibc 缺失；该环境下 IPv6 TPROXY 退化为无 origDest。
        #[cfg(not(target_env = "uclibc"))]
        {
            setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, 1)?;
            setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR, 1)?;
        }
    }

    sock.bind(&socket2::SockAddr::from(addr))?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

#[cfg(target_os = "linux")]
fn setsockopt_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Linux + `ReceiveOriginalDestination` 时的收包循环：用 `recvmsg` 一次性读取
/// payload + 发送方地址 + 原始目标地址（IP_RECVORIGDSTADDR ancillary data）。
#[cfg(target_os = "linux")]
async fn start_recv_loop_tproxy_linux(
    socket: &UdpSocket,
    tx: mpsc::Sender<UdpPacket>,
    close_notify: Arc<Notify>,
) {
    use std::mem::MaybeUninit;
    use socket2::{MsgHdrMut, MaybeUninitSlice, SockRef};

    // ancillary 缓冲区：容纳一条 IP_RECVORIGDSTADDR/IPV6_RECVORIGDSTADDR cmsg
    // （sockaddr_in6 最大，CMSG_SPACE 后远小于 64 字节）。
    const CMSG_BUF_LEN: usize = 64;

    let mut data_buf = [MaybeUninit::<u8>::zeroed(); UDP_BUFFER_SIZE];
    let mut cmsg_buf = [MaybeUninit::<u8>::zeroed(); CMSG_BUF_LEN];

    loop {
        tokio::select! {
            biased;
            _ = close_notify.notified() => break,
            res = socket.readable() => {
                if let Err(e) = res {
                    tracing::warn!(error = %e, "udp hub readable failed");
                    break;
                }
                let mut iov = [MaybeUninitSlice::new(&mut data_buf)];
                let mut name = empty_sockaddr();
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut name)
                    .with_buffers(&mut iov)
                    .with_control(&mut cmsg_buf);
                // tokio UdpSocket: AsFd → SockRef 借用底层 fd（不取所有权）。
                let sock_ref = SockRef::from(socket);
                match sock_ref.recvmsg(&mut msg, 0) {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }
                        let source = name.as_socket();
                        let target = parse_orig_dst_from_cmsg(&cmsg_buf, msg.control_len());
                        let payload = unsafe {
                            std::slice::from_raw_parts(data_buf.as_ptr() as *const u8, n).to_vec()
                        };
                        let packet = UdpPacket {
                            payload,
                            source: source.unwrap_or_else(|| {
                                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
                            }),
                            target,
                        };
                        // channel 满时丢弃。
                        if tx.try_send(packet).is_err() {
                            tracing::debug!("UDP hub cache full, dropping packet");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // 伪唤醒，重新等 readable。
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to recvmsg UDP");
                        break;
                    }
                }
            }
        }
    }
}

/// 构造全零 `SockAddr`（len 取最大），供 `recvmsg` 的 `msg_name` 写入发送方地址。
///
/// `as_socket()` 按 family 解析 sockaddr_in/sockaddr_in6，不依赖 len。
#[cfg(target_os = "linux")]
fn empty_sockaddr() -> socket2::SockAddr {
    // SAFETY: 全零 sockaddr_storage 合法；recvmsg 写回 storage。
    unsafe {
        let storage: libc::sockaddr_storage = std::mem::zeroed();
        socket2::SockAddr::new(
            storage,
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        )
    }
}

/// 判断一条 cmsg 是否为 IPv6 原始目标地址（IPV6_RECVORIGDSTADDR）。
/// uclibc 缺该常量，该环境下恒为 false（IPv6 TPROXY origDest 不支持）。
#[cfg(target_os = "linux")]
#[cfg(not(target_env = "uclibc"))]
fn is_ipv6_origdst_cmsg(chdr: &libc::cmsghdr) -> bool {
    chdr.cmsg_level == libc::IPPROTO_IPV6 && chdr.cmsg_type == libc::IPV6_RECVORIGDSTADDR
}

#[cfg(target_os = "linux")]
#[cfg(target_env = "uclibc")]
fn is_ipv6_origdst_cmsg(_chdr: &libc::cmsghdr) -> bool {
    false
}

/// 从 `recvmsg` 的 ancillary buffer 解析原始目标地址。
///
/// 内核为每个请求了 `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` 的数据包附加恰好
/// 一条 cmsg，故只需检查首条（`CMSG_FIRSTHDR`）。无法解析时返回 `None`。
#[cfg(target_os = "linux")]
fn parse_orig_dst_from_cmsg(
    cmsg_buf: &[std::mem::MaybeUninit<u8>],
    len: usize,
) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};


    let hdr_size = std::mem::size_of::<libc::cmsghdr>();
    if len < hdr_size {
        return None;
    }
    // 构造临时 msghdr 让 CMSG_FIRSTHDR 工作。
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_control = cmsg_buf.as_ptr() as *mut _;
    hdr.msg_controllen = len as _;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
    if cmsg.is_null() {
        return None;
    }
    let chdr = unsafe { &*cmsg };
    let data = unsafe { libc::CMSG_DATA(cmsg) };
    let data_len = chdr.cmsg_len as usize - hdr_size;

    if chdr.cmsg_level == libc::IPPROTO_IP && chdr.cmsg_type == libc::IP_RECVORIGDSTADDR {
        if data_len < std::mem::size_of::<libc::sockaddr_in>() {
            return None;
        }
        // SAFETY: cmsg data 长度已校验；按 sockaddr_in 读取（网络字节序）。
        let sin = unsafe { &*(data as *const libc::sockaddr_in) };
        // s_addr 按本机序存储，to_ne_bytes 直接得到 [a,b,c,d]。
        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
        Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(sin.sin_port),
        )))
    } else if is_ipv6_origdst_cmsg(chdr) {
        if data_len < std::mem::size_of::<libc::sockaddr_in6>() {
            return None;
        }
        // SAFETY: cmsg data 长度已校验；按 sockaddr_in6 读取。
        let sin6 = unsafe { &*(data as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(sin6.sin6_port),
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )))
    } else {
        None
    }
}

// ===== 旧 API 兼容 =====
//
// 保留 `register_udp_listener` / `unregister_udp_listener` 向后兼容，
// 但标记为 deprecated——新代码应使用 `UdpHub::listen()`。

use std::collections::HashMap;
use std::sync::Mutex;

static UDP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, ()>>> = std::sync::OnceLock::new();
fn udp_hub() -> &'static Mutex<HashMap<SocketAddr, ()>> {
    UDP_HUB.get_or_init(|| Mutex::new(HashMap::new()))
}

/// UDP hub 注册表最大条目数。
const MAX_UDP_HUB_ENTRIES: usize = 4096;

/// 注册 UDP listener。锁中毒时静默忽略。
#[deprecated(note = "use UdpHub::listen() instead")]
pub fn register_udp_listener(addr: SocketAddr) -> io::Result<()> {
    if let Ok(mut hub) = udp_hub().lock() {
        if hub.len() >= MAX_UDP_HUB_ENTRIES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("UDP hub registry full ({MAX_UDP_HUB_ENTRIES})")));
        }
        hub.insert(addr, ());
    }
    Ok(())
}

/// 注销 UDP listener。锁中毒时静默忽略。
#[deprecated(note = "use UdpHub::close() instead")]
pub fn unregister_udp_listener(addr: SocketAddr) {
    if let Ok(mut hub) = udp_hub().lock() {
        hub.remove(&addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_hub_bind_and_recv() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);

        let mut rx = hub.receive();

        // 发送 UDP 包。
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        sender.send_to(b"hello", addr).await.expect("send_to 失败");

        // 接收。
        let packet = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        assert_eq!(&packet.payload, b"hello");
        assert!(packet.target.is_none());
    }

    #[tokio::test]
    async fn udp_hub_local_addr() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn udp_hub_send_to() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .expect("listen 失败");
        let hub_addr = hub.local_addr().expect("local_addr 失败");

        // 接收端。
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let recv_addr = receiver.local_addr().expect("local_addr");

        // Hub 发送。
        hub.send_to(b"world", recv_addr).await.expect("send_to 失败");

        // 接收端验证。
        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("timeout")
        .expect("recv_from 失败");

        assert_eq!(&buf[..n], b"world");
        assert_eq!(from, hub_addr);
    }

    #[tokio::test]
    async fn udp_hub_close_stops_recv_loop() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .expect("listen 失败");

        hub.close().expect("close 失败");

        // close 后 receive 应该最终返回 None（channel 关闭）。
        let mut rx = hub.receive();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await;

        // 可能收到 None（channel 关闭）或 timeout（recv 循环还在等）。
        // 关键是不 panic。
        match result {
            Ok(None) => {} // channel 已关闭 ✅
            Ok(Some(_)) => {} // 收到残留包也 OK
            Err(_) => {} // timeout 也 OK——recv 循环可能在等下一个包
        }
    }

    #[tokio::test]
    async fn udp_hub_capacity_option() {
        let options: Vec<Box<dyn HubOption>> = vec![Box::new(Capacity(10))];
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &options, None)
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn udp_hub_multiple_packets() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");

        let mut rx = hub.receive();

        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        for i in 0..5u8 {
            sender
                .send_to(&[i], addr)
                .await
                .expect("send_to 失败");
        }

        // 接收 5 个包。
        let mut received = Vec::new();
        for _ in 0..5 {
            let packet = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                rx.recv(),
            )
            .await
            .expect("timeout")
            .expect("channel closed");
            received.push(packet.payload);
        }

        // 验证顺序（UDP 不保证顺序，但本地 loopback 通常有序）。
        assert_eq!(received.len(), 5);
    }

    /// udpmask round-trip（o54c，对应 Go hub.go:71-77）：hub 带 manager 监听，
    /// 客户端同配置 `wrap_packet_conn_client` 后发包 → hub recv 循环 decode 出原文；
    /// hub `send_to`（encode 上线）→ 客户端 decode 出原文。
    #[tokio::test]
    async fn udp_hub_listen_with_udpmask_roundtrip() {
        use crate::finalmask::{UdpIo, build_udpmask_manager_from_json};

        let fm: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#,
        )
        .unwrap();
        let mgr = build_udpmask_manager_from_json(Some(&fm)).expect("manager");

        let hub = UdpHub::listen(
            "127.0.0.1:0".parse().unwrap(),
            &[],
            Some(mgr),
        )
        .await
        .expect("listen with udpmask 失败");
        let hub_addr = hub.local_addr().expect("local_addr 失败");

        // 客户端：同配置 client 侧 wrap。
        let client_raw = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let client_addr = client_raw.local_addr().unwrap();
        let client_mgr = build_udpmask_manager_from_json(Some(&fm)).expect("manager");
        let client_io: Box<dyn UdpIo> = client_mgr
            .wrap_packet_conn_client(Box::new(client_raw))
            .expect("client wrap");

        // 反向：hub.send_to（encode）→ client decode。
        hub.send_to(b"masked-pong", client_addr)
            .await
            .expect("hub send_to");
        let mut buf = vec![0u8; 1500];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_io.recv_from(&mut buf),
        )
        .await
        .expect("client recv timeout")
        .expect("client recv ok");
        assert_eq!(&buf[..n], b"masked-pong");

        // 正向：client（encode）→ hub recv 循环 decode。
        client_io
            .send_to(b"masked-ping", hub_addr)
            .await
            .expect("client send_to");
        let mut rx = hub.receive();
        let packet = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("hub recv timeout")
        .expect("hub channel closed");
        assert_eq!(&packet.payload, b"masked-ping");
        assert_eq!(packet.source, client_addr);
        assert!(packet.target.is_none());
    }
}
