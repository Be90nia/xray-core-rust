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
//! - passthrough 连接层（client/server 状态机，跑在 [`IcmpRawSocket`] 抽象上）
//!
//! 平台真 socket 收发实装在同目录的 `xicmp_sock` 模块（Linux/macOS ping/raw socket +
//! Windows raw socket）。
//!
//! ## 安全边界
//!
//! mask 层无认证、无防注入：ICMP echo 对 on-path 观察者可读可伪造（id/seq/clientID
//! 均非秘密），安全上等价于裸 ICMP/UDP 传输——机密性与完整性由内层协议（ss/vless
//! AEAD 等）保证，id/seq/clientID 不得用作任何授权判断依据（审计 F14）。服务端
//! `ips` 白名单只是收窄喂帧面（非白名单源整包丢弃，Go `server.go` 同语义），不构成认证。

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
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
    /// IP 列表（Go `c.IPs` 双语义）：client=出站伪装源轮换池；server=来源白名单
    /// （配置了则仅接收该列表内源地址的帧，空 = 未配置 = 不过滤，Go `len(c.ips) > 0`）。
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
        // raw/ping ICMP socket 需平台权限（Linux: ping_group_range 或 CAP_NET_RAW；
        // Windows: Administrator）——打开失败时 fail-visible，见 xicmp_sock。
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
/// - Linux：`SOCK_DGRAM`+`IPPROTO_ICMP` ping socket（免 root）+ `SOCK_RAW` 兜底
/// - Windows：`SOCK_RAW`+`IPPROTO_ICMP`（需 Administrator）
/// - 测试：`MockIcmpRawSocket`
///
/// 实装见同目录的 `xicmp_sock` 模块。
#[async_trait]
pub trait IcmpRawSocket: Send + Sync {
    /// 发一帧完整 ICMP 包（含 8B echo 头部 + data）到 `dst`。
    ///
    /// 对应 Go `WriteTo(b, addr)` 的路由参数（client: ips 轮换/dest，server: 记录的 src）。
    async fn send(&self, packet: &[u8], dst: SocketAddr) -> io::Result<()>;
    /// 收一帧完整 ICMP 包（任意 echo 类型，由调用方按 type 过滤），返回 `(帧, 源地址)`。
    /// v4 raw socket 的 IP 头已由实现层剥离——调用方拿到的恒是纯 ICMP 帧。
    /// 返回 `WouldBlock` 表示当前无包。
    async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)>;
}

/// 内部共享 client/server 状态：recv 任务把 raw 包塞这里，
/// 应用层 recv_from 从这里取。
struct XicmpShared {
    /// 后台 recv 任务投递的 raw ICMP 包 + 源地址（已 type-filtered）。
    ///
    /// bounded（容量 [`RECV_CHANNEL_CAP`]）——对端洪水时 recv 任务阻塞在 send 上，
    /// 由内核 socket 缓冲吸收/丢弃，用户态不无界积压（对齐 Go 无缓冲 readCh）。
    rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}
/// xICMP passthrough 连接（对应 Go `xicmpConnClient` / `xicmpConnServer`）。
///
/// 内部封装 `Arc<dyn IcmpRawSocket>` + 后台 recv 任务 + 模式特有状态：
/// - Client：`client_id`（8B 随机）+ `id` + 自增 `seq`；
/// - Server：`rec` map（clientID → 记录的 id/seq/最后时间）+ 独立清理任务 （周期驱逐空闲记录，Go
///   `clean()` goroutine）。
pub struct XicmpPassthroughConn {
    mode: XicmpMode,
    raw: Arc<dyn IcmpRawSocket>,
    shared: TokioMutex<XicmpShared>,
    client_state: Option<Mutex<XicmpClientState>>,
    server_state: Option<Arc<Mutex<XicmpServerState>>>,
    closed: Mutex<bool>,
    /// 后台 recv 任务句柄；Drop 时 abort（对应 Go `Close()` 关闭 icmp4/icmp6 使
    /// 阻塞中的 recv goroutine 立即退出——否则任务要等下一个包到达才发现退出）。
    recv_task: Mutex<Option<JoinHandle<()>>>,
    /// 后台 rec 清理任务句柄（仅 Server 构造，Go `clean()` goroutine）；Drop 时 abort。
    clean_task: Mutex<Option<JoinHandle<()>>>,
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
    /// 伪装目的 IP 轮换池（Go `c.ips`，每包随机取一个；空 → 用 send_to 的应用层目的地址，
    /// 对应 Go `ip = dest.Address.IP()`——Rust 侧 dest 在每次 send_to 时才可得）。
    ips: Vec<IpAddr>,
    /// v4 socket 实际为 ping socket（dgram）模式：内核自配 id 并重写发出帧（WSL 实测
    /// 发 0x4321 → 回包 id=0x0001），客户端必须跳过 id 过滤（Go `!c.udp` 同因）。
    dgram_v4: bool,
    /// v6 socket 实际为 ping socket 模式（语义同上）。
    dgram_v6: bool,
}
#[derive(Default)]
struct XicmpServerState {
    /// clientID → record（Go `rec map[string]record` 的 Rust 对应）。
    /// key 用 clientID 字节序列的 hex 字符串（与 Go `cAddr.String()` 对齐）。
    rec: HashMap<String, XicmpServerRecord>,
}

struct XicmpServerRecord {
    id: u16,
    seq: u16,
    /// 请求的源地址（回包路由目标，Go `record.addr`；is_v4 也由它决定）。
    src: SocketAddr,
    last: Instant,
}

impl XicmpPassthroughConn {
    /// 构造客户端连接。`raw` 由调用方注入（生产走 `xicmp_sock` 平台实现，测试走 mock）。
    ///
    /// `ips`/`dgram_v4`/`dgram_v6` 由生产侧按 socket 实际打开模式传入（Go `c.ips`/`c.udp`）。
    pub fn new_client(
        client_id: [u8; 8],
        id: u16,
        raw: Arc<dyn IcmpRawSocket>,
        ips: Vec<IpAddr>,
        dgram_v4: bool,
        dgram_v6: bool,
    ) -> Self {
        // client 仅放行 echo reply（v4 type=0 / v6 type=129）；ips 是出站轮换池，
        // 不做 recv 源过滤（Go client 的 c.ips 同样只用于 WriteTo 路由）
        let (rx, task) = spawn_recv_task(raw.clone(), true, Arc::from([]));
        Self {
            mode: XicmpMode::Client,
            raw,
            shared: TokioMutex::new(XicmpShared { rx }),
            client_state: Some(Mutex::new(XicmpClientState {
                client_id,
                id,
                seq: 1,
                ips,
                dgram_v4,
                dgram_v6,
            })),
            server_state: None,
            closed: Mutex::new(false),
            recv_task: Mutex::new(Some(task)),
            clean_task: Mutex::new(None),
        }
    }

    /// 构造服务端连接。`ips` 为来源白名单（Go `NewConnServer` 的 `c.IPs`）：
    /// 空列表 = 未配置 = 不过滤（Go 默认行为），非空则仅接收列表内源地址的帧。
    pub fn new_server(raw: Arc<dyn IcmpRawSocket>, ips: Vec<IpAddr>) -> Self {
        // server 仅放行 echo request（v4 type=8 / v6 type=128）
        let (rx, task) = spawn_recv_task(raw.clone(), false, ips.into());
        let state = Arc::new(Mutex::new(XicmpServerState::default()));
        let clean_task = spawn_clean_task(state.clone());
        Self {
            mode: XicmpMode::Server,
            raw,
            shared: TokioMutex::new(XicmpShared { rx }),
            client_state: None,
            server_state: Some(state),
            closed: Mutex::new(false),
            recv_task: Mutex::new(Some(task)),
            clean_task: Mutex::new(Some(clean_task)),
        }
    }
}

/// spawn 后台 recv 任务：循环 `raw.recv()` → 长度闸 → 源白名单 → type-filter → 投 bounded
/// channel。
///
/// 类型过滤在任务内完成（client 仅 echo reply / server 仅 echo request），应用层
/// `recv_from` 拿到的都是过滤后的包。`send().await` 阻塞式发送（满时 park），
/// 语义对齐 Go `select { case readCh <- p; case <-closedCh }`（Go 无缓冲 channel
/// 发送阻塞 + 内核缓冲蓄洪，见 [`RECV_CHANNEL_CAP`]）；接收端 drop 后 send 返回
/// Err，任务退出。
///
/// `allowed_src` 为 server 来源白名单（Go `server.go:154-161/234-241`：配置了
/// `ips` 则非白名单源整包丢弃，空 = 未配置 = 不过滤）；client 传空。过滤位置与
/// Go 一致——在 readCh 投递之前，非白名单包不占用户态通道槽位。
fn spawn_recv_task(
    raw: Arc<dyn IcmpRawSocket>,
    is_client: bool,
    allowed_src: Arc<[IpAddr]>,
) -> (mpsc::Receiver<(Vec<u8>, SocketAddr)>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(RECV_CHANNEL_CAP);
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面泵任务（raw ICMP socket recv 泵）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    let task = tokio::spawn(async move {
        loop {
            let (pkt, src) = match raw.recv().await {
                Ok(p) => p,
                Err(e) => {
                    // Go recv4/recv6 对真实读错误同样 `LogErrorInner` 后退出（连接随之不可用）；
                    // 畸形帧由平台层丢帧继续，走不到这里——无日志退出 = 后续包静默丢光（jhktt）
                    crate::hot_log!(
                        tracing::Level::WARN,
                        "error={e} is_client={is_client} xicmp: raw socket recv failed, closing"
                    );
                    return;
                },
            };
            // 长度先于 pkt[0] 索引：畸短帧直接丢，不杀死 recv 任务
            if pkt.len() < 8 {
                continue;
            }
            if !allowed_src.is_empty() && !allowed_src.contains(&src.ip()) {
                continue; // Go server.go:154-161/234-241 非白名单源丢弃
            }
            let pass = if is_client {
                pkt[0] == ICMP_ECHO_REPLY_V4 || pkt[0] == ICMP_ECHO_REPLY_V6
            } else {
                pkt[0] == ICMP_ECHO_V4 || pkt[0] == ICMP_ECHO_V6
            };
            if pass && tx.send((pkt, src)).await.is_err() {
                return; // 接收端已 drop（连接关闭）
            }
        }
    });
    (rx, task)
}

/// rec 记录空闲 TTL：超过即被清理任务驱逐
/// （Go `server.go:97` `now.Sub(r.last) > time.Minute` 删）。
const SERVER_REC_TTL: Duration = Duration::from_secs(60);
/// 独立清理 ticker 周期（Go `server.go:75` `time.NewTicker(time.Minute / 2)`）。
const SERVER_CLEAN_INTERVAL: Duration = Duration::from_secs(30);

/// spawn 独立 rec 清理任务（Go `server.go:74,91-107` `clean()` goroutine）：
/// 每 30s 扫一遍 rec，驱逐空闲超 60s 的记录——清理节奏独立于收发包路径，
/// 单向 echo 洪水（只 insert、永不触发 send 路径）不再无界增长（bd 8kaea）。
fn spawn_clean_task(state: Arc<Mutex<XicmpServerState>>) -> JoinHandle<()> {
    spawn_clean_task_with(state, SERVER_CLEAN_INTERVAL, SERVER_REC_TTL)
}

/// [`spawn_clean_task`] 的周期/TTL 可注入版——仅测试用，生产恒走 Go 对齐常量。
fn spawn_clean_task_with(
    state: Arc<Mutex<XicmpServerState>>,
    interval: Duration,
    ttl: Duration,
) -> JoinHandle<()> {
    #[allow(
        clippy::disallowed_methods,
        reason = "常驻监控任务（xicmp 记录 TTL 清理循环）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    tokio::spawn(async move {
        // Delay：错过 tick 顺延，不补发（Go time.Ticker 丢错过 tick 同语义）
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let now = xray_frame::compat::clock().now_instant();
            state.lock().rec.retain(|_, r| now.duration_since(r.last) <= ttl);
        }
    })
}

impl Drop for XicmpPassthroughConn {
    fn drop(&mut self) {
        // 对应 Go Close() 关闭 icmp4/icmp6：立即终止阻塞中的 recv 任务，
        // 不等下一个包到达。abort 对已完成的任务是 no-op。
        if let Some(handle) = self.recv_task.lock().take() {
            handle.abort();
        }
        // 独立清理任务一并终止（Go clean() 经 closeCh 退出）；否则任务持有
        // Arc<ServerState> 永续 tick，连接关闭后泄漏。
        if let Some(handle) = self.clean_task.lock().take() {
            handle.abort();
        }
    }
}

impl XicmpPassthroughConn {
    fn is_closed(&self) -> bool {
        *self.closed.lock()
    }

    /// 应用层 payload + addr → 构造 echo 包 + raw.send。
    /// 对应 Go `xicmpConnClient.WriteTo`：8B clientID 前缀 + payload → marshal；
    /// 路由目的 = ips 随机轮换（Go `c.ips[mrand.Intn(len(c.ips))]`），空池用应用层 addr。
    async fn client_send_to(&self, payload: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        // 对齐 Go `len(p)+16 > UDPSize`：payload 超过 MAX_PAYLOAD (UDP_SIZE - 16) 直接丢
        if payload.len() > MAX_PAYLOAD {
            return Ok(0);
        }
        let state_arc =
            self.client_state.as_ref().ok_or_else(|| io::Error::other("not a client conn"))?;
        let (client_id, seq, id, dst) = {
            let mut s = state_arc.lock();
            let seq = s.seq;
            s.seq = s.seq.wrapping_add(1);
            let dst_ip = if s.ips.is_empty() {
                addr.ip()
            } else {
                let i = rand::rng().random_range(0..s.ips.len());
                s.ips[i]
            };
            (s.client_id, seq, s.id, SocketAddr::new(dst_ip, 0))
        };
        let packet = build_client_packet(client_id, seq, id, payload, dst.is_ipv4());
        self.raw.send(&packet, dst).await?;
        Ok(payload.len())
    }

    /// 收 echo reply 包：parse → 校验 id 匹配（dgram 模式跳过）+ seq ring ≤1000 + 剥 clientID。
    async fn client_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let state_arc =
            self.client_state.as_ref().ok_or_else(|| io::Error::other("not a client conn"))?;
        let (client_id, id, seq_current, dgram_v4, dgram_v6) = {
            let s = state_arc.lock();
            (s.client_id, s.id, s.seq, s.dgram_v4, s.dgram_v6)
        };
        // 循环拉包直到自反馈检查通过
        loop {
            let (pkt, _src) = {
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
            // id 匹配仅 raw 模式：dgram（ping socket）内核重写 id（实测 0x4321→0x0001）
            // 且按 id 分发回包，过滤只会误杀（Go `!c.udp && echo.ID != c.id` 同因）
            let is_v4_reply = pkt[0] == ICMP_ECHO_REPLY_V4;
            if !(if is_v4_reply { dgram_v4 } else { dgram_v6 }) && rid != id {
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
        let (id, seq, dst) = {
            let mut s = state_arc.lock();
            // 清扫已上移独立清理任务（Go server.go:91-107）——Go WriteTo 同样不做
            // GC，rec 命中与否只看条目存在性；这里去掉原热路径 O(n) retain。
            match s.rec.get_mut(&key) {
                Some(r) => {
                    r.last = xray_frame::compat::clock().now_instant();
                    (r.id, r.seq, r.src)
                },
                None => return Ok(0), // Go: log + drop
            }
        };
        // is_v4 与路由目的都由 rec 记录的请求源地址决定（Go `WriteTo(b, cm, r.addr)`；
        // Go 另用 ControlMessage 把 source 钉回原 dst，这里靠内核选源——多宿主偏差见模块文档）
        let packet = build_server_reply(id, seq, payload, dst.is_ipv4());
        self.raw.send(&packet, dst).await?;
        Ok(payload.len())
    }

    /// server recv_from：parse echo request → 剥 8B clientID → 记录 rec（含源地址）→
    /// 返回 (payload, virtual_v6_addr)
    async fn server_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let state_arc =
            self.server_state.as_ref().ok_or_else(|| io::Error::other("not a server conn"))?;
        loop {
            let (pkt, src) = {
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
            // Go server.go:150-152 `len(echo.Data) <= 8 { continue }`：剥掉 8B clientID
            // 后 payload 至少 1 字节——8B 包会产出 0 长度读（上层可能误当 EOF），
            // 且让洪水占 rec 条目更廉价。
            if rdata.len() <= 8 {
                continue;
            }
            let mut client_id = [0u8; 8];
            client_id.copy_from_slice(&rdata[..8]);
            let payload = &rdata[8..];
            // 记录到 rec（key = virtual_addr 字符串）
            let vaddr = client_id_to_addr(client_id);
            {
                let mut s = state_arc.lock();
                s.rec.insert(
                    vaddr.to_string(),
                    XicmpServerRecord {
                        id,
                        seq,
                        src,
                        last: xray_frame::compat::clock().now_instant(),
                    },
                );
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

// ===== 平台实装：Linux ping/raw socket + Windows raw socket（xicmp_sock 模块）=====

/// 生成随机 clientID（8B，对应 Go `rand.Read(clientID[:])`）。
pub fn random_client_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    id
}

/// 打开客户端 ICMP socket 并包装为 `UdpIo`（Go `NewConnClient`）。
fn xicmp_open_client(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    super::xicmp_sock::open_client(cfg)
}

/// 打开服务端 ICMP socket 并包装为 `UdpIo`（Go `NewConnServer`）。
fn xicmp_open_server(cfg: &XicmpConfig) -> io::Result<Box<dyn UdpIo>> {
    super::xicmp_sock::open_server(cfg)
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

    /// mock raw ICMP socket：记录 send 字节与目的地址、预设 recv 队列（附伪造源地址）。
    /// 用于单测跑通 XicmpPassthroughConn 的 send_to/recv_from 全链路。
    /// `recv_polls` 计数 recv() 轮询次数——观测后台 recv 任务是否已退出。
    struct MockIcmpRawSocket {
        sent: TestMutex<Vec<(Vec<u8>, SocketAddr)>>,
        recv_queue: TestMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        recv_polls: std::sync::atomic::AtomicU64,
    }

    /// mock recv 报告的伪造源地址（供 server 回包路由断言用）。
    const MOCK_SRC: SocketAddr =
        SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 7), 0));

    impl MockIcmpRawSocket {
        fn new(seed_recv: Vec<Vec<u8>>) -> Self {
            Self::new_with_srcs(seed_recv.into_iter().map(|p| (p, MOCK_SRC)).collect())
        }

        /// 预设队列时逐包指定伪造源地址（供来源白名单测试用）。
        fn new_with_srcs(seed_recv: VecDeque<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                sent: TestMutex::new(Vec::new()),
                recv_queue: TestMutex::new(seed_recv),
                recv_polls: std::sync::atomic::AtomicU64::new(0),
            }
        }

        fn recv_polls(&self) -> u64 {
            self.recv_polls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl IcmpRawSocket for MockIcmpRawSocket {
        async fn send(&self, packet: &[u8], dst: SocketAddr) -> io::Result<()> {
            self.sent.lock().push((packet.to_vec(), dst));
            Ok(())
        }

        async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
            // 模拟生产 raw socket 的语义：阻塞到有包。空队列 → 短 sleep 重试。
            // 对应 Linux 实现：AsyncFd readable().await + read。
            loop {
                self.recv_polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some((p, src)) = self.recv_queue.lock().pop_front() {
                    return Ok((p, src));
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }

    /// 等 mock recv 队列长度稳定（50ms 窗口不变）——后台 recv 任务已消费完它能消费的。
    async fn wait_queue_stable(mock: &MockIcmpRawSocket) -> usize {
        let mut prev = usize::MAX;
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(2);
        loop {
            let cur = mock.recv_queue.lock().len();
            if cur == prev {
                return cur;
            }
            prev = cur;
            tokio::time::sleep(Duration::from_millis(50)).await;
            if xray_frame::compat::clock().now_instant() > deadline {
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
        let conn =
            XicmpPassthroughConn::new_client(client_id, 0x4242, mock.clone(), vec![], false, false);

        let payload = b"hello icmp";
        let addr: SocketAddr = "10.0.0.1:0".parse().unwrap();
        let n = conn.send_to(payload, addr).await.unwrap();
        assert_eq!(n, payload.len());

        let sent = mock.sent.lock();
        assert_eq!(sent.len(), 1);
        let pkt = &sent[0].0;
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
        // 路由目的 = 应用层 addr 的 IP（ips 空池回退，Go `ip = dest.Address.IP()`）
        assert_eq!(sent[0].1, SocketAddr::from(([10, 0, 0, 1], 0)));
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
        let conn =
            XicmpPassthroughConn::new_client(client_id, id, mock.clone(), vec![], false, false);

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
        let conn =
            XicmpPassthroughConn::new_client(client_id, id, mock.clone(), vec![], false, false);

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
        let conn = XicmpPassthroughConn::new_server(mock.clone(), vec![]);

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
        let conn = XicmpPassthroughConn::new_server(mock.clone(), vec![]);

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
        let pkt = &sent[0].0;
        assert_eq!(pkt[0], ICMP_ECHO_REPLY_V4);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x7777); // id 来自 rec
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 9); // seq 来自 rec
        assert_eq!(&pkt[8..], reply_payload);
        // 回包路由到记录的请求源地址（Go `WriteTo(b, cm, r.addr)`）
        assert_eq!(sent[0].1, MOCK_SRC);
    }

    #[tokio::test]
    async fn passthrough_send_to_oversize_returns_zero() {
        // payload 大小超过 MAX_PAYLOAD + 16 = UDP_SIZE（对应 Go `len(p)+16 > UDPSize`）
        // —— Go 行为：返回 (0, nil)。本实现对齐：返回 0、Ok。
        let mock = Arc::new(MockIcmpRawSocket::new(vec![]));
        let conn =
            XicmpPassthroughConn::new_client([0u8; 8], 0x1234, mock.clone(), vec![], false, false);

        let oversize = vec![0u8; MAX_PAYLOAD + 1];
        let addr: SocketAddr = "10.0.0.1:0".parse().unwrap();
        let n = conn.send_to(&oversize, addr).await.unwrap();
        assert_eq!(n, 0);
        // mock 未收到任何包
        assert_eq!(mock.sent.lock().len(), 0);
    }

    fn reply_pkt(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        // server-style 回包：data 前 8B garbage（否则被自反馈检查丢弃）
        let mut data = vec![0xffu8; 8];
        data.extend_from_slice(payload);
        marshal_echo(ICMP_ECHO_REPLY_V4, id, seq, &data)
    }

    #[tokio::test]
    async fn client_recv_raw_mode_drops_foreign_id() {
        // raw 模式：id 不匹配的回包丢弃继续等（Go `if !c.udp && echo.ID != c.id`）。
        let client_id = [0x71u8; 8];
        let foreign = reply_pkt(0x2222, 1, b"foreign");
        let good = reply_pkt(0x1111, 2, b"mine");
        let mut expected = vec![0xffu8; 8];
        expected.extend_from_slice(b"mine");

        let mock = Arc::new(MockIcmpRawSocket::new(vec![foreign, good]));
        let conn =
            XicmpPassthroughConn::new_client(client_id, 0x1111, mock.clone(), vec![], false, false);

        let mut buf = [0u8; 64];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &expected[..], "应跳过外族 id 回包返回匹配包");
        // foreign 帧只被 recv 任务消费、未投给应用层之外的消费者
        assert_eq!(mock.recv_queue.lock().len(), 0);
    }

    #[tokio::test]
    async fn client_recv_dgram_mode_accepts_kernel_assigned_id() {
        // dgram（ping socket）模式：内核重写 id（WSL 实测发 0x4321 → 回包 id=0x0001），
        // 客户端必须放行任意 id（Go `c.udp` 时不过滤同因）。
        let client_id = [0x72u8; 8];
        let only = reply_pkt(0x0001, 1, b"kernel-id");
        let mut expected = vec![0xffu8; 8];
        expected.extend_from_slice(b"kernel-id");

        let mock = Arc::new(MockIcmpRawSocket::new(vec![only]));
        let conn =
            XicmpPassthroughConn::new_client(client_id, 0xbeef, mock.clone(), vec![], true, true);

        let mut buf = [0u8; 64];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[tokio::test]
    async fn client_recv_from_silent_socket_times_out() {
        // 超时语义：无回包时 recv_from 挂起，由上层 deadline 收口（Go SetReadDeadline 对应）。
        let mock = Arc::new(MockIcmpRawSocket::new(vec![]));
        let conn =
            XicmpPassthroughConn::new_client([0u8; 8], 0x1234, mock.clone(), vec![], false, false);
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_millis(80), conn.recv_from(&mut buf)).await;
        assert!(res.is_err(), "无回包应超时而不是返回");
    }

    #[tokio::test]
    async fn xicmp_open_error_is_visible_and_classified() {
        // 权限分类：ping socket（Linux 需 ping_group_range）与 raw（Linux CAP_NET_RAW /
        // Windows Administrator）都不可用 → fail-visible 带两条提示；特权环境打开成功。
        // 两种结局在 CI（非特权）与本机（root/admin）都必须合法。
        let config = XicmpConfig::default();
        let raw: Box<dyn UdpIo> =
            Box::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        match config.wrap_packet_conn_client(raw, 0, 1) {
            Ok(_conn) => {}, // 特权主机：真实 socket 打开成功
            Err(e) => {
                assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                    ),
                    "unexpected kind {:?}: {e}",
                    e.kind()
                );
                let msg = e.to_string();
                assert!(
                    msg.contains("ping_group_range") && msg.contains("CAP_NET_RAW"),
                    "fail-visible 提示缺失: {msg}"
                );
            },
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
        let conn =
            XicmpPassthroughConn::new_client(client_id, id, mock.clone(), vec![], false, false);

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
        let conn =
            XicmpPassthroughConn::new_client([0u8; 8], 0x1234, mock.clone(), vec![], false, false);
        // 让任务先跑进 recv 轮询循环
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(conn);
        let p1 = mock.recv_polls();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let p2 = mock.recv_polls();
        assert_eq!(p1, p2, "空队列下 drop 后 recv 任务应退出");
    }

    /// 构造 server 侧 echo request：data = `[8B clientID][payload]`。
    fn request_pkt(client_id: [u8; 8], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&client_id);
        data.extend_from_slice(payload);
        marshal_echo(ICMP_ECHO_V4, id, seq, &data)
    }

    #[tokio::test]
    async fn server_whitelist_accepts_configured_source() {
        // bd mmtbf：配置了 ips 白名单时，白名单内源的 echo request 正常投递。
        let client_id = [0x81u8; 8];
        let request = request_pkt(client_id, 0x6001, 1, b"allowed");
        let mock = Arc::new(MockIcmpRawSocket::new(vec![request]));
        // 白名单 = MOCK_SRC 的 IP（203.0.113.7）
        let ips = vec![IpAddr::from([203, 0, 113, 7])];
        let conn = XicmpPassthroughConn::new_server(mock.clone(), ips);

        let mut buf = [0u8; 64];
        let (n, addr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"allowed", "白名单内源应正常投递");
        assert_eq!(addr_to_client_id(&addr).unwrap(), client_id);
    }

    #[tokio::test]
    async fn server_whitelist_drops_non_configured_source() {
        // bd mmtbf：白名单外源的包整包丢弃（Go server.go:154-161）——不投递、不建 rec。
        let request = request_pkt([0x82u8; 8], 0x6002, 1, b"intruder");
        let mock = Arc::new(MockIcmpRawSocket::new(vec![request]));
        let ips = vec!["198.51.100.9".parse::<IpAddr>().unwrap()]; // ≠ MOCK_SRC
        let conn = XicmpPassthroughConn::new_server(mock.clone(), ips);

        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_millis(150), conn.recv_from(&mut buf)).await;
        assert!(res.is_err(), "白名单外源的包应被丢弃而不是投递");
        assert_eq!(mock.recv_queue.lock().len(), 0, "包已被 recv 任务消费并丢弃");
        assert!(
            conn.server_state.as_ref().unwrap().lock().rec.is_empty(),
            "被丢的包不得建立 rec 条目"
        );
    }

    #[tokio::test]
    async fn client_rotation_ips_are_not_recv_filter() {
        // client 的 ips 是出站轮换池（Go client 的 c.ips 只用于 WriteTo 路由），
        // 不得被误用作 recv 源过滤——回包源不在 ips 内仍正常投递。
        let client_id = [0x83u8; 8];
        let mock = Arc::new(MockIcmpRawSocket::new(vec![reply_pkt(0x7777, 1, b"ok")]));
        let conn = XicmpPassthroughConn::new_client(
            client_id,
            0x7777,
            mock.clone(),
            vec!["10.9.9.9".parse().unwrap()],
            false,
            false,
        );

        let mut buf = [0u8; 64];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert!(buf[..n].ends_with(b"ok"), "client 不做源过滤，回包应投递");
    }

    #[tokio::test]
    async fn recv_task_survives_short_frames() {
        // P3：长度判定先于 pkt[0] 索引——畸短帧丢弃且不杀死 recv 任务。
        let client_id = [0x84u8; 8];
        let good = reply_pkt(0x3210, 1, b"still alive");
        let mock = Arc::new(MockIcmpRawSocket::new(vec![vec![1, 2, 3], good]));
        let conn =
            XicmpPassthroughConn::new_client(client_id, 0x3210, mock.clone(), vec![], false, false);

        let mut buf = [0u8; 64];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert!(buf[..n].ends_with(b"still alive"), "短帧后 recv 任务应仍存活");
    }

    #[tokio::test]
    async fn server_drops_data_len_at_or_below_eight() {
        // P3：Go server.go:150-152 `len(echo.Data) <= 8 { continue }`——data 恰 8B
        // （只有 clientID、零 payload）丢弃，9B 正常投递。
        let cid_only = request_pkt([0x85u8; 8], 0x6003, 1, b"");
        let with_payload = request_pkt([0x86u8; 8], 0x6003, 2, b"x");
        let mock = Arc::new(MockIcmpRawSocket::new(vec![cid_only, with_payload]));
        let conn = XicmpPassthroughConn::new_server(mock.clone(), vec![]);

        let mut buf = [0u8; 64];
        let (n, addr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"x", "8B data 包应被丢，9B 包投递");
        assert_eq!(addr_to_client_id(&addr).unwrap(), [0x86u8; 8]);
    }

    #[tokio::test]
    async fn server_rec_evicted_by_independent_clean_task() {
        // bd 8kaea：rec 清理节奏独立于收发包路径（Go server.go:91-107 clean goroutine）。
        // 注入短周期/TTL 驱动同一机制（生产常量 30s/60s 无法在单测窗口内观察）。
        let seeds: Vec<Vec<u8>> = (0..64u16)
            .map(|i| {
                let mut cid = [0x50u8; 8];
                cid[7] = i as u8;
                request_pkt(cid, 0x6004, i, b"flood")
            })
            .collect();
        let mock = Arc::new(MockIcmpRawSocket::new(seeds));
        let conn = XicmpPassthroughConn::new_server(mock.clone(), vec![]);
        assert!(conn.clean_task.lock().is_some(), "server 构造必须挂上独立清理任务");

        // 64 个不同 clientID 的单向包 → 64 条 rec
        let mut buf = [0u8; 64];
        for _ in 0..64 {
            conn.recv_from(&mut buf).await.unwrap();
        }
        let state = conn.server_state.as_ref().unwrap().clone();
        assert_eq!(state.lock().rec.len(), 64, "每包一条 rec 条目");

        // 清理周期过后：空闲条目全部回收；期间无新包，条目只减不增（不发包不泄漏）
        let _clean = spawn_clean_task_with(
            state.clone(),
            Duration::from_millis(20),
            Duration::from_millis(50),
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(state.lock().rec.len(), 0, "空闲超 TTL 的条目应被独立清理任务回收");
    }

    #[tokio::test]
    async fn server_rec_fresh_entries_survive_clean() {
        // 清理只驱逐空闲超 TTL 的条目，不误杀新鲜条目（Go `now.Sub(r.last) > time.Minute`）。
        let cid = [0x51u8; 8];
        let pkt = request_pkt(cid, 0x6005, 1, b"fresh");
        let mock = Arc::new(MockIcmpRawSocket::new(vec![pkt]));
        let conn = XicmpPassthroughConn::new_server(mock.clone(), vec![]);
        let mut buf = [0u8; 64];
        let (_n, vaddr) = conn.recv_from(&mut buf).await.unwrap();

        let state = conn.server_state.as_ref().unwrap().clone();
        let _clean = spawn_clean_task_with(
            state.clone(),
            Duration::from_millis(20),
            Duration::from_millis(10_000),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(state.lock().rec.len(), 1, "新鲜条目不得被清理任务驱逐");
        // rec 命中：回包正常发出（条目仍在）
        let n = conn.send_to(b"reply", vaddr).await.unwrap();
        assert_eq!(n, 5, "新鲜条目应可回包（rec 命中）");
    }
}
