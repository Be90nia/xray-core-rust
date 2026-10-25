//! # xICMP 平台 socket 实装（对应 Go `xicmp` 的 socket 层）
//!
//! `XicmpPassthroughConn`（见 [`super::xicmp`]）跑在 [`IcmpRawSocket`] 抽象上；本模块
//! 提供两个平台的真 socket：
//!
//! - **Linux**：`SOCK_DGRAM`+`IPPROTO_ICMP` ping socket（免 root，优）+ `SOCK_RAW` 兜底； v6
//!   同族（ping6 socket / ICMPv6 raw）。
//! - **macOS/BSD**（unix）：同 Linux 实现路径，ping socket 可用性由内核决定，失败自动 回退 raw（Go
//!   在 darwin 的 server 亦走 raw `ip4:icmp`/`ip6:ipv6-icmp`）。
//! - **Windows**：`SOCK_RAW`+`IPPROTO_ICMP`（需 Administrator；无提升权限时 fail-visible）。 不采用
//!   `IcmpSendEcho2`：id/seq 由 OS 指定且为阻塞逐请求模型，无法表达 client 的 id/seq 记账与 async
//!   send/recv 拆分。
//! - **其余平台**：fail-visible 占位（构造即报「平台不支持 xicmp raw socket」）。
//!
//! socket2 只负责创建（raw/dgram + 协议族，`Type::RAW` 在 0.5 被 all 门控所以走
//! `From<c_int>`），创建后立即转 `std::net::UdpSocket` 做全部 IO——std 的
//! send_to/recv_from 以 `std::net::SocketAddr` 为一等公民，避免 socket2 `SockAddr`
//! 转换噪音。
//!
//! ## 候选顺序与权限分类（内核行为 WSL 实测 2026-10-25）
//!
//! - `cfg.dgram` 为真 → 尝试序 `[ping, raw]`；为假 → `[raw, ping]`。首个成功者生效，
//!   两候选都因权限失败（`PermissionDenied`/`Unsupported`）→ 合并报错（fail-visible， 逐候选原因 +
//!   `ping_group_range` 与 `CAP_NET_RAW`/Administrator 双提示）。
//! - ping socket 权限只看 `net.ipv4.ping_group_range`（内核 `ping_init_sock` 不走 CAP_NET_RAW
//!   旁路——**root 也会被默认 "1 0" 拦下**，实测 EACCES）；raw 需 CAP_NET_RAW（Linux，nobody 实测
//!   EPERM）/ Administrator（Windows）。
//! - v6 打不开（如 ping_group_range 关闭且无 CAP_NET_RAW）→ 降级为 `None`：v4 照常 工作，v6
//!   收发时报明确错误。**偏差**：Go 双 socket 任一失败即整体失败；Rust 放宽 为 v4 必须、v6
//!   可降级（默认 sysctl 下 Go 的 dgram 模式同样开不出 v6 socket）。
//!
//! ## dgram（ping socket）内核行为（实测）
//!
//! - 未 bind 时内核自配 id 并**重写**发出帧的 echo id（发 0x4321 → 回包 id=0x0001）， 回包按内核 id
//!   分发 → client 跳过 id 过滤（Go `!c.udp && echo.ID != c.id` 同因）。
//! - v4/v6 checksum 由内核代算（发 checksum=0 的帧实测收到合法回包）。
//! - recv 不带 IP 头。
//!
//! ## raw socket 行为
//!
//! - id 由本模块随机生成（Go `id: mrand.Intn(65536)`），client recv 按 id 过滤。
//! - v4 checksum 用户态算（`marshal_echo`）；v6 checksum 内核代算（IPPROTO_ICMPV6 raw socket 默认
//!   `IPV6_CHECKSUM` offset=2）。
//! - v4 recv 带 IP 头（实测 ihl=20），按 IHL 剥离后才投给上层——[`IcmpRawSocket`] 契约恒为纯 ICMP
//!   帧。
//!
//! ## 已知偏差（wire 不变）
//!
//! - Go server_oob 回包用 ControlMessage 把 source 钉回原 dst（多宿主源地址选择）；
//!   这里靠内核选源。帧格式与回包路由（发往请求 src）一致。
//! - Go raw 模式 recv 缓冲 4096（含 IP 头，最大帧会截断丢弃）；这里 4096+64 不截断。

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use super::{
    UDP_SIZE, UdpIo,
    xicmp::{IcmpRawSocket, XicmpConfig, XicmpPassthroughConn, random_client_id},
};

/// recv 缓冲：最大 echo 帧（UDP_SIZE）+ v4 raw 的 IP 头余量（IHL 最大 60）。
const RECV_BUF: usize = UDP_SIZE + 64;

/// 生成随机 ICMP id（Go `mrand.Intn(65536)`）。
fn random_icmp_id() -> u16 {
    rand::random()
}

/// 打开客户端连接（Go `NewConnClient`）：v4 必须、v6 可降级，随机 clientID/id。
pub(super) fn open_client(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    let (v4, dgram_v4) = open_family(cfg.dgram, true)?;
    let (v6, dgram_v6) = match open_family(cfg.dgram, false) {
        Ok(x) => (Some(x.0), x.1),
        // 降级：ping_group_range 关闭且无 CAP_NET_RAW 时 v4-only 照常工作（偏差见模块文档）
        Err(_) => (None, false),
    };
    let ips = parse_ips(cfg)?;
    let raw: Arc<dyn IcmpRawSocket> = Arc::new(PlatformIcmpSocket::new(Some(v4), v6));
    let conn = XicmpPassthroughConn::new_client(
        random_client_id(),
        random_icmp_id(),
        raw,
        ips,
        dgram_v4,
        dgram_v6,
    );
    Ok(Box::new(conn))
}

/// 打开服务端连接（Go `NewConnServer`：永远 raw 优先，不随 `cfg.dgram`）。
pub(super) fn open_server(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    let (v4, _) = open_family(false, true)?;
    let (v6, _) = match open_family(false, false) {
        Ok(x) => (Some(x.0), x.1),
        Err(_) => (None, false),
    };
    let _ = parse_ips(cfg)?; // ips 白名单语义属连接层（现状未实装），此处仅校验可解析
    let raw: Arc<dyn IcmpRawSocket> = Arc::new(PlatformIcmpSocket::new(Some(v4), v6));
    Ok(Box::new(XicmpPassthroughConn::new_server(raw)))
}

fn parse_ips(cfg: &XicmpConfig) -> io::Result<Vec<IpAddr>> {
    cfg.ips
        .iter()
        .map(|s| {
            s.parse::<IpAddr>().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("xicmp ip {s:?}: {e}"))
            })
        })
        .collect()
}

/// v4/v6 socket 候选尝试序：`dgram_pref` → [ping, raw]，否则 [raw, ping]。
/// ping socket 免 root 但依赖 sysctl（Linux），raw 语义与 Go 默认对齐，按配置偏好排序。
fn candidate_modes(dgram_pref: bool) -> [bool; 2] {
    if dgram_pref { [true, false] } else { [false, true] }
}

/// 打开单族 socket，返回 `(socket, 是否实际为 dgram/ping socket)`。
///
/// 权限类失败（`PermissionDenied`/`Unsupported`）落到下一候选；两候选皆败 → 合并
/// fail-visible 错误（逐候选原因 + ping_group_range 与 CAP_NET_RAW/Administrator 双提示）。
fn open_family(dgram_pref: bool, is_v4: bool) -> io::Result<(IcmpSock, bool)> {
    let mut errs: Vec<String> = Vec::new();
    let mut kind = io::ErrorKind::Other;
    for dgram in candidate_modes(dgram_pref) {
        match IcmpSock::open(dgram, is_v4) {
            Ok(sock) => return Ok((sock, dgram)),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ) =>
            {
                kind = e.kind();
                errs.push(format!("{} socket: {e}", if dgram { "ping" } else { "raw" }));
            },
            Err(e) => return Err(e), // 非权限类错误原样抛出
        }
    }
    Err(io::Error::new(
        kind,
        format!(
            "xicmp: no usable ICMP socket ({}): {}. Hints: ping socket needs \
             net.ipv4.ping_group_range covering your group (Linux); raw socket needs \
             CAP_NET_RAW (Linux) or Administrator (Windows)",
            if is_v4 { "IPv4" } else { "IPv6" },
            errs.join("; ")
        ),
    ))
}

// ===== 统一双族 socket：send 按目的族路由，recv 双族 select =====

struct PlatformIcmpSocket {
    v4: Option<IcmpSock>,
    v6: Option<IcmpSock>,
}

impl PlatformIcmpSocket {
    fn new(v4: Option<IcmpSock>, v6: Option<IcmpSock>) -> Self {
        Self { v4, v6 }
    }
}

/// v6 socket 缺失（降级）时对 v6 收发的明确错误。
fn v6_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "xicmp: IPv6 socket unavailable (needs net.ipv4.ping_group_range or CAP_NET_RAW)",
    )
}

#[async_trait::async_trait]
impl IcmpRawSocket for PlatformIcmpSocket {
    async fn send(&self, packet: &[u8], dst: SocketAddr) -> io::Result<()> {
        let sock = match dst {
            SocketAddr::V4(_) => self.v4.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "xicmp: v4 socket absent")
            })?,
            SocketAddr::V6(_) => self.v6.as_ref().ok_or_else(v6_unavailable)?,
        };
        sock.send(packet, dst).await
    }

    async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        match (self.v4.as_ref(), self.v6.as_ref()) {
            (Some(v4), Some(v6)) => {
                tokio::select! {
                    r = v4.recv() => r,
                    r = v6.recv() => r,
                }
            },
            (Some(v4), None) => v4.recv().await,
            (None, _) => Err(v6_unavailable()),
        }
    }
}

/// 剥离 v4 raw recv 报文的 IP 头（IHL*4），非 v4/畸形头返回 None。
fn strip_v4_header_if_needed(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if !(20..=60).contains(&ihl) || ihl > packet.len() {
        return None;
    }
    Some(&packet[ihl..])
}

// ===== 平台 socket 内核（同名 API：open/send/recv）=====

/// unix（Linux/macOS/BSD）：非阻塞 socket + AsyncFd。
///
/// Linux：ping socket 免 root 但需 `net.ipv4.ping_group_range` 覆盖进程组（内核
/// `ping_init_sock` 不查 CAP_NET_RAW，root 也被默认 `1 0` 拦下），raw 需 CAP_NET_RAW。
/// macOS/BSD：dgram ICMP socket 可用性由内核决定，失败自动回退 raw（Go 在 darwin 的
/// server 同样走 raw `ip4:icmp`/`ip6:ipv6-icmp`）。
#[cfg(unix)]
mod sys {
    use std::net::{SocketAddr, UdpSocket};

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::unix::AsyncFd;

    use super::{RECV_BUF, io, strip_v4_header_if_needed};

    /// 非阻塞 socket + AsyncFd（Linux）。
    pub(super) struct IcmpSock {
        fd: AsyncFd<UdpSocket>,
        /// v4 raw recv 带 IP 头需剥离；dgram 与 v6 不带。
        strip_v4_header: bool,
    }

    impl IcmpSock {
        pub(super) fn open(dgram: bool, is_v4: bool) -> io::Result<Self> {
            let (domain, proto) = if is_v4 {
                (Domain::IPV4, Protocol::ICMPV4)
            } else {
                (Domain::IPV6, Protocol::ICMPV6)
            };
            // socket2 0.5 的 Type::RAW 被 all feature 门控；From<c_int> 无门控，等价
            let sock_type = if dgram { libc::SOCK_DGRAM } else { libc::SOCK_RAW };
            let sock = Socket::new(domain, Type::from(sock_type), Some(proto))?;
            sock.set_nonblocking(true)?;
            // 转 std：全部 IO 走 std::net::UdpSocket（std SocketAddr 一等公民）
            let udp: UdpSocket = sock.into();
            // SAFETY: udp 所有权随 AsyncFd 转移，fd 生命周期内恒有效且不变
            // （tokio 1.54 AsyncFd::new 因 RUSTSEC-2026-0386 废弃，走 register）
            let fd = unsafe { AsyncFd::register(udp) }.map_err(|e| e.into_parts().1)?;
            Ok(Self { fd, strip_v4_header: is_v4 && !dgram })
        }

        pub(super) async fn send(&self, packet: &[u8], dst: SocketAddr) -> io::Result<()> {
            loop {
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|inner| inner.get_ref().send_to(packet, dst)) {
                    Ok(r) => return r.map(|_| ()),
                    Err(_would_block) => continue,
                }
            }
        }

        pub(super) async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
                    Ok(r) => {
                        let (n, src) = r?;
                        let pkt = if self.strip_v4_header {
                            strip_v4_header_if_needed(&buf[..n]).ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "xicmp: bad IPv4 header")
                            })?
                        } else {
                            &buf[..n]
                        };
                        return Ok((pkt.to_vec(), src));
                    },
                    Err(_would_block) => continue,
                }
            }
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::{
        net::{SocketAddr, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering as AtomicOrdering},
        },
        time::Duration,
    };

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::sync::mpsc;

    use super::{RECV_BUF, io, strip_v4_header_if_needed};

    /// Windows recv 线程投递通道容量（与 Linux 侧 xicmp::RECV_CHANNEL_CAP 同量级：
    /// 只吸收调度突发，洪水由内核 socket 缓冲蓄洪/丢弃）。
    const CHANNEL_CAP: usize = 32;

    /// Windows recv 线程的单次读超时（停机延迟上界）。
    const READ_TIMEOUT: Duration = Duration::from_millis(250);

    /// Windows raw socket：无 AsyncFd（unix-only），收走专用阻塞线程 + 有界 channel
    /// （满时线程 park，内核缓冲蓄洪——语义对齐 Linux 侧）。
    pub(super) struct IcmpSock {
        sock: Arc<UdpSocket>,
        /// recv 需 `&mut Receiver` 而 trait 是 `&self`——tokio Mutex 收口；
        /// 双族 select 各锁各的，无竞争。
        rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        /// 停机旗标：Drop 置位，线程在读超时窗内自行退出（≤READ_TIMEOUT）。
        stop: Arc<AtomicBool>,
    }

    impl IcmpSock {
        pub(super) fn open(dgram: bool, is_v4: bool) -> io::Result<Self> {
            if dgram {
                // Windows 无 ping socket：报 EPROTONOSUPPORT 语义，走候选下一项（raw）
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ping sockets are not available on Windows",
                ));
            }
            let (domain, proto) = if is_v4 {
                (Domain::IPV4, Protocol::ICMPV4)
            } else {
                (Domain::IPV6, Protocol::ICMPV6)
            };
            // SOCK_RAW=3（winsock2；socket2 0.5 Type::RAW 被 all 门控，From<c_int> 无门控）
            let sock = Socket::new(domain, Type::from(3), Some(proto))?;
            let udp: UdpSocket = sock.into();
            udp.set_read_timeout(Some(READ_TIMEOUT))?;
            let sock = Arc::new(udp);
            let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_CAP);
            let stop = Arc::new(AtomicBool::new(false));
            let (t_sock, t_stop, strip) = (sock.clone(), stop.clone(), is_v4);
            std::thread::spawn(move || recv_loop(t_sock, t_stop, strip, tx));
            Ok(Self { sock, rx: tokio::sync::Mutex::new(rx), stop })
        }

        pub(super) async fn send(&self, packet: &[u8], dst: SocketAddr) -> io::Result<()> {
            // 阻塞 socket 的 sendto 包进 spawn_blocking，不占 runtime worker；
            // packet 拷贝一次换 'static 闭包
            let sock = self.sock.clone();
            let packet = packet.to_vec();
            tokio::task::spawn_blocking(move || sock.send_to(&packet, dst).map(|_| ())).await?
        }

        pub(super) async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
            self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "xicmp recv thread exited")
            })
        }
    }

    fn recv_loop(
        sock: Arc<UdpSocket>,
        stop: Arc<AtomicBool>,
        strip: bool,
        tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) {
        let mut buf = vec![0u8; RECV_BUF];
        while !stop.load(AtomicOrdering::Relaxed) {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let pkt = if strip {
                        match strip_v4_header_if_needed(&buf[..n]) {
                            Some(p) => p,
                            None => continue,
                        }
                    } else {
                        &buf[..n]
                    };
                    // bare thread 无 async 上下文，blocking_send 合法；
                    // 接收端 drop（连接关闭）→ Err → 线程退出
                    if tx.blocking_send((pkt.to_vec(), src)).is_err() {
                        return;
                    }
                },
                Err(e)
                    if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
                {
                    continue; // 读超时：回头查 stop 旗标
                },
                Err(_) if stop.load(AtomicOrdering::Relaxed) => return,
                Err(_) => continue, // 瞬时错误：下一个读超时窗重查 stop
            }
        }
    }

    impl Drop for IcmpSock {
        fn drop(&mut self) {
            self.stop.store(true, AtomicOrdering::Relaxed);
            // 线程 ≤ READ_TIMEOUT 内自退；socket 由最后一个 Arc 释放时关闭
        }
    }
}

/// 其余平台（既非 unix 也非 windows）：fail-visible 占位——构造即报「平台不支持」，
/// 不静默、不 panic。
#[cfg(not(any(unix, windows)))]
mod sys {
    use std::net::SocketAddr;

    use super::io;

    pub(super) struct IcmpSock;

    impl IcmpSock {
        pub(super) fn open(_dgram: bool, _is_v4: bool) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xicmp: raw ICMP socket is not supported on this platform",
            ))
        }

        pub(super) async fn send(&self, _packet: &[u8], _dst: SocketAddr) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xicmp: raw ICMP socket is not supported on this platform",
            ))
        }

        pub(super) async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xicmp: raw ICMP socket is not supported on this platform",
            ))
        }
    }
}

use sys::IcmpSock;

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{net::SocketAddr, time::Duration};

    use super::*;

    #[test]
    fn candidate_order_prefers_configured_mode() {
        assert_eq!(candidate_modes(true), [true, false], "dgram 偏好 → ping 先试");
        assert_eq!(candidate_modes(false), [false, true], "raw 偏好（Go 默认）→ raw 先试");
    }

    #[test]
    fn strip_v4_header_by_ihl() {
        // 合法 v4 头：version=4, IHL=5 → 剥 20B
        let mut pkt = vec![0x45, 0, 0, 0];
        pkt.extend_from_slice(&[0u8; 16]);
        pkt.extend_from_slice(b"icmp-frame");
        assert_eq!(strip_v4_header_if_needed(&pkt), Some(&b"icmp-frame"[..]));
        // 非法 version
        assert_eq!(strip_v4_header_if_needed(&[0x65, 0, 0, 0]), None);
        // IHL=6 但包长不足
        assert_eq!(strip_v4_header_if_needed(&[0x46, 0, 0, 0]), None);
        // 过短
        assert_eq!(strip_v4_header_if_needed(&[0x45; 10]), None);
    }

    /// 真实收发往返（loopback，需 root / CAP_NET_RAW）。
    ///
    /// 内核对 loopback echo request 的自动回包 data 前缀 = clientID，会被 client 的
    /// 自反馈检查丢弃；server 回包（payload 原样）才被接受——不依赖 sysctl。
    ///
    /// raw 与 dgram 两种模式**串行**跑在一个测试里：回环 raw socket 广播收包，两个
    /// 并行的 e2e 会互相抢对方 client 的请求（回包 id 不匹配被过滤 → 死等超时）。
    #[cfg(target_os = "linux")]
    async fn run_roundtrip(dgram: bool) {
        let tag = if dgram { "dgram" } else { "raw" };
        let payload = format!("xicmp-raw-e2e roundtrip ({tag})").into_bytes();
        let client_cfg = XicmpConfig { ips: vec!["127.0.0.1".to_string()], dgram };
        let server_cfg = XicmpConfig { ips: vec![], dgram };
        let client = open_client(&client_cfg).expect("client open（需 root/CAP_NET_RAW）");
        let server = open_server(&server_cfg).expect("server open（需 root/CAP_NET_RAW）");

        // client → server
        let dst: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let n = client.send_to(&payload, dst).await.unwrap();
        assert_eq!(n, payload.len());

        let mut buf = [0u8; 512];
        let (rn, vaddr) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("server recv timeout")
            .unwrap();
        assert_eq!(&buf[..rn], &payload[..], "server 应剥掉 clientID 收到纯 payload");
        assert!(
            super::super::xicmp::addr_to_client_id(&vaddr).is_some(),
            "server 侧 addr 应为虚拟 IPv6"
        );

        // server → client（原样回发，模拟 echo 应用）
        let sn = server.send_to(&buf[..rn], vaddr).await.unwrap();
        assert_eq!(sn, payload.len(), "server send_to 返回 0 = rec miss（回包被丢）");
        let (n2, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("client recv timeout")
            .unwrap();
        // client 收到整段 echo.Data：server 回包 data = payload（无 clientID 前缀重加）
        assert_eq!(&buf[..n2], &payload[..], "client 应收到 server 回包 payload");
    }

    /// 真实收发往返 e2e（Linux/WSL only）。
    ///
    /// Windows 不编译：raw socket 不投递 loopback ICMP（平台限制），且需 Administrator；
    /// Windows 侧权限/降级取证走 `xicmp_open_error_is_visible_and_classified`。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root/CAP_NET_RAW + real ICMP sockets (WSL): cargo test -- --ignored"]
    async fn roundtrip_client_server_v4_raw_then_dgram() {
        run_roundtrip(false).await;
        run_roundtrip(true).await;
    }
}
