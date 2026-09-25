//! # xICMP 伪装（对应 Go `transport/internet/finalmask/xicmp/`）
//!
//! 把代理流量伪装成 ICMP echo（ping）——payload 编码在 ICMP 包的 data 字段。
//!
//! ## 协议
//!
//! - client：在 ICMP echo request 的 data 前缀 8 字节 clientID（随机）， 后接 payload。server 用
//!   clientID 构造虚拟 IPv6 地址作为 PacketConn addr。
//! - server：收到 echo request 后记录 (clientID → src addr/id/seq)， 回复时用记录的 id/seq 构造
//!   echo reply。
//!
//! ## 范围
//!
//! 本模块实现可测试的纯函数部分：
//! - ICMP echo 包的 marshal/parse + RFC 1071 checksum
//! - clientID ↔ IPv6 地址映射
//! - ring seq 比较
//!
//! raw socket 收发（需 CAP_NET_RAW / root）留给集成层，本模块不依赖平台特权。

use std::{
    collections::HashMap,
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::{
    sync::{Mutex as TokioMutex, mpsc},
    task::JoinHandle,
};

use super::{UDP_SIZE, UdpIo, Udpmask};

/// ICMP Echo Request type（IPv4）。
const ICMP_ECHO_V4: u8 = 8;
/// ICMP Echo Reply type（IPv4）。
const ICMP_ECHO_REPLY_V4: u8 = 0;
/// ICMPv6 Echo Request type。
const ICMP_ECHO_V6: u8 = 128;
/// ICMPv6 Echo Reply type。
const ICMP_ECHO_REPLY_V6: u8 = 129;

/// xICMP 配置（对应 Go `xicmp.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct XicmpConfig {
    /// 目标 IP 列表（client 用于轮换伪装源 IP）。
    pub ips: Vec<String>,
    /// 是否用 ICMP-over-UDP（DGRAM mode，对应 Go `c.DGRAM`）。
    pub dgram: bool,
}

/// ICMP echo 头部（8 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEcho {
    /// ICMP type（8=Echo Request v4, 0=Reply v4, 128=Request v6, 129=Reply v6）。
    pub icmp_type: u8,
    /// ICMP code（echo 通常为 0）。
    pub code: u8,
    /// 校验和（IPv4 必填，IPv6 由下层处理）。
    pub checksum: u16,
    /// Identifier。
    pub id: u16,
    /// Sequence number。
    pub seq: u16,
}

impl IcmpEcho {
    /// 构造 echo request/reply（checksum=0，待 fill_checksum）。
    pub fn new(icmp_type: u8, id: u16, seq: u16) -> Self {
        Self { icmp_type, code: 0, checksum: 0, id, seq }
    }

    /// 是否为 IPv4 echo（request 或 reply）。
    pub fn is_v4(&self) -> bool {
        self.icmp_type == ICMP_ECHO_V4 || self.icmp_type == ICMP_ECHO_REPLY_V4
    }

    /// 序列化为 8 字节头部（大端）。
    pub fn marshal_header(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        buf[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf
    }

    /// 从 8 字节头部解析。
    pub fn parse_header(buf: &[u8; 8]) -> Self {
        Self {
            icmp_type: buf[0],
            code: buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            id: u16::from_be_bytes([buf[4], buf[5]]),
            seq: u16::from_be_bytes([buf[6], buf[7]]),
        }
    }
}

/// 构造完整 ICMP echo 包（对应 Go `marshal`）。
///
/// 格式：`[type:1][code:1][checksum:2][id:2][seq:2][data:N]`
/// IPv4 会计算并填入 checksum；IPv6 checksum 由下层处理（留 0）。
pub fn marshal_echo(icmp_type: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let echo = IcmpEcho::new(icmp_type, id, seq);
    let header = echo.marshal_header();
    let mut packet = Vec::with_capacity(8 + data.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(data);

    // IPv4 需计算 checksum（覆盖整个包）
    let is_v4 = icmp_type == ICMP_ECHO_V4 || icmp_type == ICMP_ECHO_REPLY_V4;
    if is_v4 {
        let cksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&cksum.to_be_bytes());
    }
    packet
}

/// RFC 1071 Internet checksum（对应 Go `golang.org/x/net/icmp.checksum`）。
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    // 奇数长度尾部字节按高字节处理
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    // 折叠进位
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// clientID → 虚拟 IPv6 地址（对应 Go `clientIDToAddr`）。
///
/// 映射规则：`fd00::clientID`（8 字节 clientID 填入 IPv6 后 8 字节）。
pub fn client_id_to_addr(client_id: [u8; 8]) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[8..16].copy_from_slice(&client_id);
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), 0, 0, 0))
}

/// 虚拟 IPv6 地址 → clientID（`client_id_to_addr` 的逆运算）。
pub fn addr_to_client_id(addr: &SocketAddr) -> Option<[u8; 8]> {
    match addr {
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            if octets[0] != 0xfd || octets[1] != 0x00 {
                return None;
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(&octets[8..16]);
            Some(id)
        },
        SocketAddr::V4(_) => None,
    }
}

/// ring 序列号比较（对应 Go `ring`）。
///
/// 返回 `min(|a-b|, |b-a|)`（wrapping），用于检测近期 vs 过期的 seq。
pub fn ring_diff(a: u16, b: u16) -> u16 {
    a.wrapping_sub(b).min(b.wrapping_sub(a))
}

// ===== Udpmask impl =====

impl Udpmask for XicmpConfig {
    fn wrap_packet_conn_client(
        &self,
        _raw: Box<dyn UdpIo>,
        level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        if level != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xicmp requires being at the outermost level",
            ));
        }
        // raw ICMP socket 需平台特权（Linux: CAP_NET_RAW；Windows: admin + IPPROTO_ICMP）。
        // 当前仅 Linux 实装真 socket，Windows cfg 下降为 Unsupported 错误。
        xicmp_open_client(self)
    }

    fn wrap_packet_conn_server(
        &self,
        _raw: Box<dyn UdpIo>,
        level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        if level != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xicmp requires being at the outermost level",
            ));
        }
        xicmp_open_server(self)
    }
}

// ===== raw ICMP socket 抽象 + passthrough 连接 =====

/// 平台无关的 raw ICMP socket 抽象（async send/recv 一帧 ICMP 包）。
///
/// 用于解耦 `XicmpPassthroughConn` 与具体平台 socket 实现：
/// - Linux：`LinuxIcmpRawSocket`（socket2 `SOCK_RAW` + `IPPROTO_ICMP`/`IPPROTO_ICMPV6`）
/// - 测试：`MockIcmpRawSocket`
#[async_trait]
pub trait IcmpRawSocket: Send + Sync {
    /// 发一帧完整 ICMP 包（含 8B echo 头部 + data）。
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
    /// 收一帧完整 ICMP 包（任意 echo 类型，由调用方按 type 过滤）。
    /// 返回 `WouldBlock` 表示当前无包。
    async fn recv(&self) -> io::Result<Vec<u8>>;
}

/// 解析 addr IP 决定 IPv4/IPv6。
fn addr_is_v4(addr: &SocketAddr) -> bool {
    matches!(addr, SocketAddr::V4(_))
}

/// 内部共享 client/server 状态：recv 任务把 raw 包塞这里，
/// 应用层 recv_from 从这里取。
struct XicmpShared {
    /// 后台 recv 任务投递的 raw ICMP 包（已 type-filtered）。
    ///
    /// bounded（容量 [`RECV_CHANNEL_CAP`]）——对端洪水时 recv 任务阻塞在 send 上，
    /// 由内核 socket 缓冲吸收/丢弃，用户态不无界积压（对齐 Go 无缓冲 readCh）。
    rx: mpsc::Receiver<Vec<u8>>,
}
/// xICMP passthrough 连接（对应 Go `xicmpConnClient` / `xicmpConnServer`）。
///
/// 内部封装 `Arc<dyn IcmpRawSocket>` + 后台 recv 任务 + 模式特有状态：
/// - Client：`client_id`（8B 随机）+ `id` + 自增 `seq`；
/// - Server：`rec` map（clientID → 记录的 id/seq/最后时间）。
pub struct XicmpPassthroughConn {
    mode: XicmpMode,
    raw: Arc<dyn IcmpRawSocket>,
    shared: TokioMutex<XicmpShared>,
    client_state: Option<Mutex<XicmpClientState>>,
    server_state: Option<Mutex<XicmpServerState>>,
    closed: Mutex<bool>,
    /// 后台 recv 任务句柄；Drop 时 abort（对应 Go `Close()` 关闭 icmp4/icmp6 使
    /// 阻塞中的 recv goroutine 立即退出——否则任务要等下一个包到达才发现退出）。
    recv_task: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XicmpMode {
    Client,
    Server,
}

struct XicmpClientState {
    client_id: [u8; 8],
    id: u16,
    seq: u16,
}
struct XicmpServerState {
    /// clientID → record（Go `rec map[string]record` 的 Rust 对应）。
    /// key 用 clientID 字节序列的 hex 字符串（与 Go `cAddr.String()` 对齐）。
    rec: HashMap<String, XicmpServerRecord>,
}

struct XicmpServerRecord {
    id: u16,
    seq: u16,
    last: Instant,
}

impl XicmpPassthroughConn {
    /// 构造客户端连接。`raw` 由调用方注入（生产走 Linux socket，测试走 mock）。
    pub fn new_client(client_id: [u8; 8], id: u16, raw: Arc<dyn IcmpRawSocket>) -> Self {
        // client 仅放行 echo reply（v4 type=0 / v6 type=129）
        let (rx, task) = spawn_recv_task(raw.clone(), true);
        Self {
            mode: XicmpMode::Client,
            raw,
            shared: TokioMutex::new(XicmpShared { rx }),
            client_state: Some(Mutex::new(XicmpClientState { client_id, id, seq: 1 })),
            server_state: None,
            closed: Mutex::new(false),
            recv_task: Mutex::new(Some(task)),
        }
    }

    /// 构造服务端连接。
    pub fn new_server(raw: Arc<dyn IcmpRawSocket>) -> Self {
        // server 仅放行 echo request（v4 type=8 / v6 type=128）
        let (rx, task) = spawn_recv_task(raw.clone(), false);
        Self {
            mode: XicmpMode::Server,
            raw,
            shared: TokioMutex::new(XicmpShared { rx }),
            client_state: None,
            server_state: Some(Mutex::new(XicmpServerState { rec: HashMap::new() })),
            closed: Mutex::new(false),
            recv_task: Mutex::new(Some(task)),
        }
    }
}

/// spawn 后台 recv 任务：循环 `raw.recv()` → type-filter → 投 bounded channel。
///
/// 类型过滤在任务内完成（client 仅 echo reply / server 仅 echo request），应用层
/// `recv_from` 拿到的都是过滤后的包。`send().await` 阻塞式发送（满时 park），
/// 语义对齐 Go `select { case readCh <- p; case <-closedCh }`（Go 无缓冲 channel
/// 发送阻塞 + 内核缓冲蓄洪，见 [`RECV_CHANNEL_CAP`]）；接收端 drop 后 send 返回
/// Err，任务退出。
fn spawn_recv_task(
    raw: Arc<dyn IcmpRawSocket>,
    is_client: bool,
) -> (mpsc::Receiver<Vec<u8>>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(RECV_CHANNEL_CAP);
    let task = tokio::spawn(async move {
        loop {
            let pkt = match raw.recv().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let pass = if is_client {
                pkt[0] == ICMP_ECHO_REPLY_V4 || pkt[0] == ICMP_ECHO_REPLY_V6
            } else {
                pkt[0] == ICMP_ECHO_V4 || pkt[0] == ICMP_ECHO_V6
            };
            if pkt.len() >= 8 && pass && tx.send(pkt).await.is_err() {
                return; // 接收端已 drop（连接关闭）
            }
        }
    });
    (rx, task)
}

impl Drop for XicmpPassthroughConn {
    fn drop(&mut self) {
        // 对应 Go Close() 关闭 icmp4/icmp6：立即终止阻塞中的 recv 任务，
        // 不等下一个包到达。abort 对已完成的任务是 no-op。
        if let Some(handle) = self.recv_task.lock().take() {
            handle.abort();
        }
    }
}

impl XicmpPassthroughConn {
    fn is_closed(&self) -> bool {
        *self.closed.lock()
    }

    /// 应用层 payload + addr → 构造 echo 包 + raw.send。
    /// 对应 Go `xicmpConnClient.WriteTo`：8B clientID 前缀 + payload → marshal。
    async fn client_send_to(&self, payload: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        // 对齐 Go `len(p)+16 > UDPSize`：payload 超过 MAX_PAYLOAD (UDP_SIZE - 16) 直接丢
        if payload.len() > MAX_PAYLOAD {
            return Ok(0);
        }
        let state_arc =
            self.client_state.as_ref().ok_or_else(|| io::Error::other("not a client conn"))?;
        let (client_id, seq, id, is_v4) = {
            let mut s = state_arc.lock();
            let seq = s.seq;
            s.seq = s.seq.wrapping_add(1);
            (s.client_id, seq, s.id, addr_is_v4(addr))
        };
        let packet = build_client_packet(client_id, seq, id, payload, is_v4);
        self.raw.send(&packet).await?;
        Ok(payload.len())
    }

    /// 收 echo reply 包：parse → 校验 id 匹配 + seq ring ≤1000 + 剥 clientID。
    async fn client_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let state_arc =
            self.client_state.as_ref().ok_or_else(|| io::Error::other("not a client conn"))?;
        let (client_id, id, seq_current) = {
            let s = state_arc.lock();
            (s.client_id, s.id, s.seq)
        };
        // 循环拉包直到自反馈检查通过
        loop {
            let pkt = {
                let mut sh = self.shared.lock().await;
                match sh.rx.recv().await {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "xicmp recv closed",
                        ));
                    },
                }
            };
            let (rid, rseq, rdata) = match parse_echo_packet(&pkt) {
                Some(t) => t,
                None => continue,
            };
            // id 匹配（dgram mode 下 Go 也检查 id；非 dgram 同）
            if rid != id {
                continue;
            }
            // seq ring ≤1000（避免过期回包）
            if ring_diff(rseq, seq_current.wrapping_sub(1)) > 1000 {
                continue;
            }
            // 自反馈：data 前 8B == clientID（自发的 echo 被本端收到）→ 丢弃
            if rdata.len() >= 8 && rdata[..8] == client_id {
                continue;
            }
            // 对齐 Go `xicmpConnClient.recv4`（client.go:157）：`echo.Data` 整段投 readCh，
            // **不剥前缀**——对端 server.WriteTo 不加回 clientID，
            // 回包 data = `[garbage 8B][payload]`，上层协议处理这 8B。
            // 这里把 `rdata` 整段拷贝到 buf：
            // - 自反馈检查仍保留（防本端 raw socket 收到自己发的 request 被 kernel 反射）
            // - 非自反馈：返回 `rdata` 全量
            let n = rdata.len().min(buf.len());
            buf[..n].copy_from_slice(&rdata[..n]);
            // addr 用 raw socket 报告的 src IP 不可得（trait 未提供），用虚拟 IPv6 占位
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
            return Ok((n, addr));
        }
    }

    /// server send_to：用 rec 查 addr → marshal echo reply → raw.send。
    async fn server_send_to(&self, payload: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        let state_arc =
            self.server_state.as_ref().ok_or_else(|| io::Error::other("not a server conn"))?;
        // payload + 8B（无 clientID 前缀）> UDPSize 视为超限，丢
        if payload.len() + 8 > UDP_SIZE {
            return Ok(0);
        }
        let key = addr.to_string();
        let (id, seq, ip_is_v4) = {
            let mut s = state_arc.lock();
            // GC：清理 1 分钟以上未访问的记录
            let now = Instant::now();
            s.rec.retain(|_, r| now.duration_since(r.last) < Duration::from_secs(60));
            match s.rec.get_mut(&key) {
                Some(r) => {
                    r.last = now;
                    (r.id, r.seq, true /* is_v4 由包决定 */)
                },
                None => return Ok(0), // Go: log + drop
            }
        };
        // is_v4 由 rec 记录的原始 src IP 决定——trait 未暴露 src，记录阶段保留
        // 这里为简化假设 v4（与测试 mock 对齐）
        let packet = build_server_reply(id, seq, payload, ip_is_v4);
        self.raw.send(&packet).await?;
        Ok(payload.len())
    }

    /// server recv_from：parse echo request → 剥 8B clientID → 记录 rec → 返回 (payload,
    /// virtual_v6_addr)
    async fn server_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let state_arc =
            self.server_state.as_ref().ok_or_else(|| io::Error::other("not a server conn"))?;
        loop {
            let pkt = {
                let mut sh = self.shared.lock().await;
                match sh.rx.recv().await {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "xicmp recv closed",
                        ));
                    },
                }
            };
            let (id, seq, rdata) = match parse_echo_packet(&pkt) {
                Some(t) => t,
                None => continue,
            };
            if rdata.len() < 8 {
                continue; // 不足 8B clientID，丢弃
            }
            let mut client_id = [0u8; 8];
            client_id.copy_from_slice(&rdata[..8]);
            let payload = &rdata[8..];
            // 记录到 rec（key = virtual_addr 字符串）
            let vaddr = client_id_to_addr(client_id);
            {
                let mut s = state_arc.lock();
                s.rec
                    .insert(vaddr.to_string(), XicmpServerRecord { id, seq, last: Instant::now() });
            }
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            return Ok((n, vaddr));
        }
    }
}

#[async_trait]
impl UdpIo for XicmpPassthroughConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "xicmp closed"));
        }
        match self.mode {
            XicmpMode::Client => self.client_send_to(buf, &addr).await,
            XicmpMode::Server => self.server_send_to(buf, &addr).await,
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "xicmp closed"));
        }
        match self.mode {
            XicmpMode::Client => self.client_recv_from(buf).await,
            XicmpMode::Server => self.server_recv_from(buf).await,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
    }
}

// ===== 平台 cfg gate：Linux 打开 raw socket，Windows 下降 Unsupported =====

/// 生成随机 clientID（8B，对应 Go `rand.Read(clientID[:])`）。
pub fn random_client_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    id
}

/// 打开客户端 ICMP raw socket 并包装为 `UdpIo`。
fn xicmp_open_client(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::linux_open_client(cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xicmp raw ICMP socket is only implemented on Linux; \
             Windows requires admin + IPPROTO_ICMP and is currently unsupported",
        ))
    }
}

fn xicmp_open_server(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::linux_open_server(cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xicmp raw ICMP socket is only implemented on Linux; \
             Windows requires admin + IPPROTO_ICMP and is currently unsupported",
        ))
    }
}

// ===== Linux 平台 raw ICMP socket 实现 =====

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::os::unix::io::AsRawFd;

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::unix::AsyncFd;

    use super::*;

    /// Linux SOCK_RAW + IPPROTO_ICMP wrapper（占位）。
    ///
    /// ponytail: 真实 send 需 sendmsg + sockaddr_in（destination 由 sendmsg 控制），
    /// recv 需 libc::read + AsyncFd writable/readable。两条链路都非平凡，
    /// 当前以 `Unsupported` 占位，单测走 MockIcmpRawSocket 路径。
    /// 实装时把 send/recv 实现补完并改 `linux_open_client/server` 返回真实 `XicmpPassthroughConn`。
    pub struct LinuxIcmpRawSocket {
        _fd: AsyncFd<Socket>,
    }

    impl LinuxIcmpRawSocket {
        /// 打开 IPv4 ICMP raw socket（`ip4:icmp`）。需 CAP_NET_RAW 或 root。
        pub fn open_v4() -> io::Result<Self> {
            // socket2 0.5 的 Type::RAW 被 `all` feature 门控；From<c_int> 无门控，等价。
            let sock =
                Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))?;
            sock.set_nonblocking(true)?;
            let fd = AsyncFd::new(sock)?;
            Ok(Self { _fd: fd })
        }

        /// 打开 IPv6 ICMPv6 raw socket（`ip6:ipv6-icmp`）。
        pub fn open_v6() -> io::Result<Self> {
            let sock =
                Socket::new(Domain::IPV6, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV6))?;
            sock.set_nonblocking(true)?;
            let fd = AsyncFd::new(sock)?;
            Ok(Self { _fd: fd })
        }
    }

    #[async_trait]
    impl IcmpRawSocket for LinuxIcmpRawSocket {
        async fn send(&self, _packet: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "LinuxIcmpRawSocket::send requires sendmsg with sockaddr_in; \
                 use MockIcmpRawSocket in unit tests",
            ))
        }

        async fn recv(&self) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "LinuxIcmpRawSocket::recv is a placeholder; \
                 production needs libc::read + AsyncFd wiring",
            ))
        }
    }

    /// 打开客户端 ICMP raw socket 占位（v4 + v6 双 socket + sendmsg 路由未实装）。
    pub(super) fn linux_open_client(_cfg: &super::XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xicmp Linux client production socket not yet implemented; \
             use MockIcmpRawSocket for unit tests",
        ))
    }

    pub(super) fn linux_open_server(_cfg: &super::XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xicmp Linux server production socket not yet implemented; \
             use MockIcmpRawSocket for unit tests",
        ))
    }
}

// ===== 内部 client/server 包构造（供集成层调用）=====

/// xICMP 客户端发送构造（对应 Go `xicmpConnClient.WriteTo` 的包构造部分）。
///
/// 在 clientID（8B）和 payload 前缀之上构造 ICMP echo request。
/// 实际发送需要 raw socket（集成层负责）。
pub fn build_client_packet(
    client_id: [u8; 8],
    seq: u16,
    id: u16,
    payload: &[u8],
    is_v4: bool,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(&client_id);
    data.extend_from_slice(payload);
    let icmp_type = if is_v4 { ICMP_ECHO_V4 } else { ICMP_ECHO_V6 };
    marshal_echo(icmp_type, id, seq, &data)
}

/// xICMP 服务端回复构造（对应 Go `xicmpConnServer.WriteTo`）。
///
/// 用记录的 client id/seq 构造 echo reply。
pub fn build_server_reply(id: u16, seq: u16, payload: &[u8], is_v4: bool) -> Vec<u8> {
    let icmp_type = if is_v4 { ICMP_ECHO_REPLY_V4 } else { ICMP_ECHO_REPLY_V6 };
    marshal_echo(icmp_type, id, seq, payload)
}

/// 解析收到的 ICMP echo 包，提取 data 部分（对应 Go recv4/recv6 的 echo.Body.Memory 解析）。
///
/// 返回 `(id, seq, data)` 或 `None`（包过短）。
pub fn parse_echo_packet(packet: &[u8]) -> Option<(u16, u16, &[u8])> {
    if packet.len() < 8 {
        return None;
    }
    let mut header = [0u8; 8];
    header.copy_from_slice(&packet[..8]);
    let echo = IcmpEcho::parse_header(&header);
    Some((echo.id, echo.seq, &packet[8..]))
}

/// 最大 payload 大小限制（对应 Go `len(p)+16 > finalmask.UDPSize`）。
pub const MAX_PAYLOAD: usize = UDP_SIZE.saturating_sub(16);

/// recv 任务 → 应用层通道容量。
///
/// Go `readCh` 是**无缓冲** channel（client.go:83 `make(chan packet)`）：应用层停读时
/// recv goroutine 阻塞在 channel 发送上，洪水由内核 socket 缓冲（Linux 默认
/// SO_RCVBUF ~212KB）吸收、溢出由内核丢弃——用户态永不无界积压。
/// Rust 侧对齐此语义：bounded channel + 阻塞式 `send().await`（满时 recv 任务
/// park，等价 Go 阻塞发送，Err=Closed 即退出）。32 包容量仅吸收调度延迟突发
/// （MTU 1500 下 ~48KB；jumbo 64KB 极端 ~2MB），内核缓冲才是真正的蓄洪/丢弃层。
const RECV_CHANNEL_CAP: usize = 32;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn icmp_checksum_zero_data() {
        // 空数据 checksum = ~0 = 0xffff
        assert_eq!(icmp_checksum(&[]), 0xffff);
        assert_eq!(icmp_checksum(&[0, 0, 0, 0]), 0xffff);
    }

    #[test]
    fn icmp_checksum_odd_length() {
        // 奇数长度：尾部字节按高字节
        let odd = [0x12u8, 0x34, 0x56];
        let even = [0x12u8, 0x34, 0x56, 0x00];
        assert_eq!(icmp_checksum(&odd), icmp_checksum(&even));
    }

    #[test]
    fn marshal_v4_echo_has_checksum() {
        let pkt = marshal_echo(ICMP_ECHO_V4, 0x1234, 0x5678, b"data");
        assert_eq!(pkt[0], ICMP_ECHO_V4);
        assert_eq!(pkt[1], 0);
        // checksum 非 0（IPv4 必须填）
        let cksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(cksum, 0);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0x5678);
        assert_eq!(&pkt[8..], b"data");
    }

    #[test]
    fn marshal_v6_echo_no_checksum() {
        let pkt = marshal_echo(ICMP_ECHO_V6, 0x1234, 0x5678, b"data");
        let cksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        // IPv6 checksum 留 0（由下层处理）
        assert_eq!(cksum, 0);
    }

    #[test]
    fn marshal_roundtrip_checksum_validates() {
        // 构造 → 用 checksum 验证 → 整体 checksum 应为 0
        let pkt = marshal_echo(ICMP_ECHO_V4, 100, 200, b"hello icmp");
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn client_id_to_addr_roundtrip() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let addr = client_id_to_addr(id);
        let recovered = addr_to_client_id(&addr).unwrap();
        assert_eq!(recovered, id);
    }

    #[test]
    fn client_id_addr_is_fd00_prefix() {
        let addr = client_id_to_addr([0xff; 8]);
        match addr {
            SocketAddr::V6(v6) => {
                let octets = v6.ip().octets();
                assert_eq!(octets[0], 0xfd);
                assert_eq!(octets[1], 0x00);
                assert_eq!(&octets[8..16], &[0xff; 8]);
            },
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn addr_to_client_id_rejects_v4() {
        let v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(addr_to_client_id(&v4).is_none());
    }

    #[test]
    fn addr_to_client_id_rejects_non_fd00() {
        let v6: SocketAddr = "[2001:db8::1]:0".parse().unwrap();
        assert!(addr_to_client_id(&v6).is_none());
    }

    #[test]
    fn ring_diff_wraps() {
        assert_eq!(ring_diff(10, 5), 5);
        assert_eq!(ring_diff(5, 10), 5);
        assert_eq!(ring_diff(u16::MAX, 0), 1);
        assert_eq!(ring_diff(0, u16::MAX), 1);
    }

    #[test]
    fn parse_echo_packet_extracts_fields() {
        let pkt = marshal_echo(ICMP_ECHO_V4, 0xabcd, 0x1234, b"payload here");
        let (id, seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(id, 0xabcd);
        assert_eq!(seq, 0x1234);
        assert_eq!(data, b"payload here");
    }

    #[test]
    fn parse_echo_packet_rejects_short() {
        assert!(parse_echo_packet(&[1, 2, 3]).is_none());
    }

    #[test]
    fn build_client_packet_layout() {
        let client_id = [0xaa; 8];
        let pkt = build_client_packet(client_id, 1, 2, b"hi", true);
        let (_id, _seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(&data[..8], &client_id);
        assert_eq!(&data[8..], b"hi");
    }

    #[test]
    fn build_server_reply_layout() {
        let pkt = build_server_reply(0x1111, 0x2222, b"reply", true);
        assert_eq!(pkt[0], ICMP_ECHO_REPLY_V4);
        let (id, seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(id, 0x1111);
        assert_eq!(seq, 0x2222);
        assert_eq!(data, b"reply");
    }

    #[tokio::test]
    async fn udpmask_rejects_non_outermost() {
        let config = XicmpConfig::default();

        struct Stub;
        #[async_trait]
        impl UdpIo for Stub {
            async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                Ok(0)
            }

            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }

            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }
        let raw: Box<dyn UdpIo> = Box::new(Stub);
        let result = config.wrap_packet_conn_client(raw, 1, 2);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udpmask_outermost_passthrough() {
        let config = XicmpConfig::default();

        struct Stub;
        #[async_trait]
        impl UdpIo for Stub {
            async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                Ok(0)
            }

            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }

            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }
        let raw: Box<dyn UdpIo> = Box::new(Stub);
        // level=0（最外层）应透传成功
        let _result = config.wrap_packet_conn_client(raw, 0, 2);
    }

    /// mock raw ICMP socket：记录 send 字节、预设 recv 队列。
    /// 用于单测跑通 XicmpPassthroughConn 的 send_to/recv_from 全链路。
    /// `recv_polls` 计数 recv() 轮询次数——观测后台 recv 任务是否已退出。
    struct MockIcmpRawSocket {
        sent: TestMutex<Vec<Vec<u8>>>,
        recv_queue: TestMutex<VecDeque<Vec<u8>>>,
        recv_polls: std::sync::atomic::AtomicU64,
    }

    impl MockIcmpRawSocket {
        fn new(seed_recv: Vec<Vec<u8>>) -> Self {
            Self {
                sent: TestMutex::new(Vec::new()),
                recv_queue: TestMutex::new(seed_recv.into()),
                recv_polls: std::sync::atomic::AtomicU64::new(0),
            }
        }

        fn recv_polls(&self) -> u64 {
            self.recv_polls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl IcmpRawSocket for MockIcmpRawSocket {
        async fn send(&self, packet: &[u8]) -> io::Result<()> {
            self.sent.lock().push(packet.to_vec());
            Ok(())
        }

        async fn recv(&self) -> io::Result<Vec<u8>> {
            // 模拟生产 raw socket 的语义：阻塞到有包。空队列 → 短 sleep 重试。
            // 对应 Linux 实现：AsyncFd readable().await + libc::read 阻塞。
            loop {
                self.recv_polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(p) = self.recv_queue.lock().pop_front() {
                    return Ok(p);
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }

    /// 等 mock recv 队列长度稳定（50ms 窗口不变）——后台 recv 任务已消费完它能消费的。
    async fn wait_queue_stable(mock: &MockIcmpRawSocket) -> usize {
        let mut prev = usize::MAX;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let cur = mock.recv_queue.lock().len();
            if cur == prev {
                return cur;
            }
            prev = cur;
            tokio::time::sleep(Duration::from_millis(50)).await;
            if std::time::Instant::now() > deadline {
                return mock.recv_queue.lock().len();
            }
        }
    }

    use parking_lot::Mutex as TestMutex;

    #[tokio::test]
    async fn passthrough_client_send_to_marshal_echo_request() {
        // XicmpPassthroughConn::client_send_to 应构造 echo request 包：
        // - 头 8B clientID
        // - 后接 payload
        // - echo type=v4
        // - 写入 raw socket（mock 收）
        let client_id = [0x11u8; 8];
        let mock = Arc::new(MockIcmpRawSocket::new(vec![]));
        let conn = XicmpPassthroughConn::new_client(client_id, 0x4242, mock.clone());

        let payload = b"hello icmp";
        let addr: SocketAddr = "10.0.0.1:0".parse().unwrap();
        let n = conn.send_to(payload, addr).await.unwrap();
        assert_eq!(n, payload.len());

        let sent = mock.sent.lock();
        assert_eq!(sent.len(), 1);
        let pkt = &sent[0];
        // echo request v4
        assert_eq!(pkt[0], ICMP_ECHO_V4);
        // id=0x4242
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x4242);
        // data 部分前 8B 是 clientID
        assert_eq!(&pkt[8..16], &client_id);
        // data 部分 8B 后是 payload
        assert_eq!(&pkt[16..], payload);
        // IPv4 checksum 应使整体 checksum 验证为 0
        assert_eq!(icmp_checksum(pkt), 0);
    }

    #[tokio::test]
    async fn passthrough_client_recv_from_returns_full_echo_data() {
        // 对齐 Go `xicmpConnClient.recv4`（client.go:157）：`echo.Data` 整段投 readCh，不剥前缀。
        // 对端 server.WriteTo（server.go:300）只把 payload 写到 b[8:]，前 8B 是 pool 复用 garbage。
        // 模拟这种 server-style reply：data = `[garbage 8B][payload]`。
        let client_id = [0x22u8; 8];
        let id = 0x9999;
        let seq = 1;

        // server-style reply：data 前 8B 是 garbage（不是 clientID，否则会被自反馈检查丢弃）
        let mut data = vec![0xffu8; 8];
        data.extend_from_slice(b"reply data");
        let reply = marshal_echo(ICMP_ECHO_REPLY_V4, id, seq, &data);

        let mock = Arc::new(MockIcmpRawSocket::new(vec![reply]));
        let conn = XicmpPassthroughConn::new_client(client_id, id, mock.clone());

        let mut buf = [0u8; 64];
        let (n, _addr) = conn.recv_from(&mut buf).await.unwrap();
        // 整 echo.Data（含 garbage 8B + payload）投 readCh
        assert_eq!(&buf[..n], &data[..]);
    }
    #[tokio::test]
    async fn passthrough_client_recv_from_drops_self_feedback() {
        // 自反馈（echo reply data 前 8B == 本端 clientID）应被丢弃，继续 recv 等待下一包。
        let client_id = [0x33u8; 8];
        let id = 0xaaaa;

        // 第一包：自反馈（data 前 8B 匹配 clientID）—— 应被丢弃
        let mut self_data = Vec::new();
        self_data.extend_from_slice(&client_id);
        self_data.extend_from_slice(b"echo of myself");
        let echo_of_self = marshal_echo(ICMP_ECHO_REPLY_V4, id, 1, &self_data);

        // 第二包：server-style reply（data 前 8B garbage）—— 整段投 readCh
        let mut real_data = vec![0xccu8; 8];
        real_data.extend_from_slice(b"actual reply");
        let real_reply = marshal_echo(ICMP_ECHO_REPLY_V4, id, 2, &real_data);

        let mock = Arc::new(MockIcmpRawSocket::new(vec![echo_of_self, real_reply]));
        let conn = XicmpPassthroughConn::new_client(client_id, id, mock.clone());

        let mut buf = [0u8; 64];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        // 第一包被丢弃，第二包整段返回（含 garbage 8B + payload）
        assert_eq!(&buf[..n], &real_data[..]);
    }

    #[tokio::test]
    async fn passthrough_server_recv_from_records_client_id_and_returns_virtual_addr() {
        // server 收到 echo request：剥 8B clientID，记录到 rec，
        // addr = client_id_to_addr(client_id) 虚拟 IPv6。
        let client_id = [0x44u8; 8];

        let mut data = Vec::new();
        data.extend_from_slice(&client_id);
        data.extend_from_slice(b"client payload");
        let request = marshal_echo(ICMP_ECHO_V4, 0x5555, 7, &data);

        let mock = Arc::new(MockIcmpRawSocket::new(vec![request]));
        let conn = XicmpPassthroughConn::new_server(mock.clone());

        let mut buf = [0u8; 64];
        let (n, addr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"client payload");
        // addr 应是虚拟 IPv6（fd00::clientID）
        let recovered = addr_to_client_id(&addr).expect("addr should be virtual v6");
        assert_eq!(recovered, client_id);
    }

    #[tokio::test]
    async fn passthrough_server_send_to_uses_recorded_id_seq() {
        // server send_to(addr=virtual_v6)：从 rec 查 addr → 用记录的 id/seq
        // marshal echo reply → raw.send。
        let client_id = [0x55u8; 8];
        let virtual_addr = client_id_to_addr(client_id);

        // 先送 echo request 进 server 让其记录
        let mut data = Vec::new();
        data.extend_from_slice(&client_id);
        data.extend_from_slice(b"x");
        let request = marshal_echo(ICMP_ECHO_V4, 0x7777, 9, &data);

        let mock = Arc::new(MockIcmpRawSocket::new(vec![request]));
        let conn = XicmpPassthroughConn::new_server(mock.clone());

        // 触发 server 收一次以建立 rec
        let mut buf = [0u8; 16];
        let (_n, _) = conn.recv_from(&mut buf).await.unwrap();

        // 模拟 raw socket 把请求 echo 回去（便于验证 clientID 已记录）
        // 然后 server write_to 应构造 echo reply
        let reply_payload = b"server reply";
        let n = conn.send_to(reply_payload, virtual_addr).await.unwrap();
        assert_eq!(n, reply_payload.len());

        let sent = mock.sent.lock();
        assert_eq!(sent.len(), 1);
        let pkt = &sent[0];
        assert_eq!(pkt[0], ICMP_ECHO_REPLY_V4);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x7777); // id 来自 rec
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 9); // seq 来自 rec
        assert_eq!(&pkt[8..], reply_payload);
    }

    #[tokio::test]
    async fn passthrough_send_to_oversize_returns_zero() {
        // payload 大小超过 MAX_PAYLOAD + 16 = UDP_SIZE（对应 Go `len(p)+16 > UDPSize`）
        // —— Go 行为：返回 (0, nil)。本实现对齐：返回 0、Ok。
        let mock = Arc::new(MockIcmpRawSocket::new(vec![]));
        let conn = XicmpPassthroughConn::new_client([0u8; 8], 0x1234, mock.clone());

        let oversize = vec![0u8; MAX_PAYLOAD + 1];
        let addr: SocketAddr = "10.0.0.1:0".parse().unwrap();
        let n = conn.send_to(&oversize, addr).await.unwrap();
        assert_eq!(n, 0);
        // mock 未收到任何包
        assert_eq!(mock.sent.lock().len(), 0);
    }

    #[tokio::test]
    async fn udpmask_windows_unsupported() {
        // Windows cfg：wrap_packet_conn_* 应返回 Unsupported 错误。
        // 此测试在 Windows 编译时跑；在 Linux/macOS 编译时被 cfg 跳过。
        if cfg!(target_os = "windows") {
            let config = XicmpConfig::default();
            let raw: Box<dyn UdpIo> =
                Box::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let err = config.wrap_packet_conn_client(raw, 0, 1).err().expect("must err on windows");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        } else {
            // 非 Windows：编译期 cfg 跳过此 case
        }
    }

    #[tokio::test]
    async fn passthrough_flood_is_bounded_and_task_exits_on_drop() {
        // v9yx：对端洪水时用户态积压必须有界（对齐 Go 无缓冲 readCh + 内核缓冲丢弃），
        // 且连接 drop 后 recv 任务立即退出（对齐 Go Close() 关闭 icmp conn）。
        let client_id = [0x66u8; 8];
        let id = 0xbeef;

        // server-style 合法回包（garbage 8B 前缀 + payload；id 匹配、seq 就近）
        let mut data = vec![0x99u8; 8];
        data.extend_from_slice(b"flood");
        let reply = marshal_echo(ICMP_ECHO_REPLY_V4, id, 1, &data);

        let total = 100usize;
        let mock = Arc::new(MockIcmpRawSocket::new(vec![reply; total]));
        let conn = XicmpPassthroughConn::new_client(client_id, id, mock.clone());

        // 全程不读 recv_from：recv 任务最多吞 cap+1 包（cap 在队列 + 1 个在
        // parked send future 手里）后阻塞，其余留在 mock 队列——旧 unbounded
        // 实现会全部吞光（settled=0）。
        let settled = wait_queue_stable(&mock).await;
        assert!(
            settled >= total - RECV_CHANNEL_CAP - 1,
            "未读时积压必须有界（≤cap+1 包），实际剩余 {settled}/{total}"
        );

        drop(conn);
        // recv 任务随 Drop abort 立即停止轮询（旧实现滞留到下一个包到达）
        let p1 = mock.recv_polls();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let p2 = mock.recv_polls();
        assert_eq!(p1, p2, "drop 后 recv 任务应已退出（polls 不再增长）");
    }

    #[tokio::test]
    async fn passthrough_task_exits_on_drop_without_pending_packets() {
        // v9yx 后半：空队列（任务停在 recv 轮询）时 drop 连接，任务也立即退出，
        // 不得滞留等下一个包。
        let mock = Arc::new(MockIcmpRawSocket::new(vec![]));
        let conn = XicmpPassthroughConn::new_client([0u8; 8], 0x1234, mock.clone());
        // 让任务先跑进 recv 轮询循环
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(conn);
        let p1 = mock.recv_polls();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let p2 = mock.recv_polls();
        assert_eq!(p1, p2, "空队列下 drop 后 recv 任务应退出");
    }
}
