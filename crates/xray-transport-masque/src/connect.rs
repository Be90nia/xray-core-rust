//! CONNECT-IP 会话（RFC 9484）：一条 h2 extended CONNECT 流承载全部 IP 包。
//!
//! 语义唯一源：Go `transport/internet/masque/connectip/conn.go`（v26.11.9 @ 676eaf66）
//! + `transport/internet/masque/conn.go`（会话外壳）。胶囊编解码见 [`crate::capsule`]。
//!
//! ## 与 Go 的形态差异（规划 §4.3 契约）
//!
//! - `recv_packet` 返回**整包 `Vec<u8>`**，不照抄 Go `io.ErrShortBuffer` 续读约定。
//! - h2 写侧超 MTU（`maxCapsulePacketSize`）返回 ICMP packet-too-big 回灌包——取自 Go **h3** 分支的
//!   `DatagramTooLargeError → composeICMPTooLargePacket` 语义 （Go `conn.go` `WritePacket`）；h2 侧
//!   Go 原样发送超限胶囊、由对端读侧丢弃， 本仓在写侧拒绝（[`crate::capsule::MAX_CAPSULE_PAYLOAD`]
//!   硬上限，B1 已立）。
//! - 读侧对端请求（ADDRESS_REQUEST）的拒绝回应由本会话读泵直接完成 （Go 由外壳
//!   `serveAddressRequests` goroutine 完成，净行为等价）。
//! - 队列上界与 Go 同值：数据包/地址分配各 128（Go `maxQueuedDatagrams` /
//!   `maxQueuedCapsules`），路由通告 latest-wins（Go `queueLatest`）；分配队列满 =
//!   协议违规关连接（Go `errCapsuleLimit`），数据包队列满 = 背压（Go `queueDatagram`
//!   为阻塞投递，语义一致）。
//!
//! udf 不适用判定（CLAUDE.md §3.5.5）：协议 wire + 会话状态机，单消费方，无提炼候选。

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
};
use xray_transport::wire::varint::read_varint;

use crate::{
    capsule::{
        self, AddressRequestEntry, AssignedAddress, Capsule, IpPrefix, IpRoute,
        MAX_CAPSULE_PAYLOAD, decode_capsule, encode_capsule,
    },
    error::{MasqueError, Result},
};

/// 隧道最小可承载包长（Go `transport/internet/masque/dialer.go:44 MinPacketSize`；
/// establish 期 `max_packet_size()` 低于此值即拒建）。
pub const MIN_PACKET_SIZE: usize = 1280;

/// h2 承载的每包上限 = 胶囊 DATAGRAM 包上限（Go `conn.go:63 maxCapsulePacketSize`）。
pub(crate) fn h2_max_packet_size() -> usize {
    MAX_CAPSULE_PAYLOAD
}

// 队列上界（Go conn.go:60-61）。
const QUEUE_CAPSULES: usize = 128;
const QUEUE_DATAGRAMS: usize = 128;

/// 防御性帧长上限：合法胶囊（DATAGRAM ≤ 64KB、地址/路由 ≤ 8192 条目 ≈ <200KB）
/// 远低于此值；超限 = 协议违规（Go 读侧可流式跳过任意长度，本仓以显式上限替代，
/// fail-visible）。超出即是解析器预算攻击。
const MAX_FRAME_PAYLOAD: usize = 1 << 20;

/// IP 协议号：ICMP / ICMPv6（Go conn.go:41-44）。
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ICMPV6: u8 = 58;

/// ICMP 回灌最小 MTU（Go icmp.go:22-24）。
const IPV4_MIN_MTU: usize = 68;
const IPV6_MIN_MTU: usize = 1280;

/// 会话共享验证态（读泵更新，收发侧查询）。
#[derive(Debug, Default)]
struct SessionState {
    /// 服务端已分配前缀（非拒绝条目；Go `c.assignedAddresses`）。
    assigned: Vec<IpPrefix>,
    /// 本端通告给对端的前缀（客户端恒 `None`——回应全是拒绝形态，Go
    /// `sendAddressAssignment(restrictPeer=false)` 不设 peerAddresses）。
    peer: Option<Vec<IpPrefix>>,
    /// 对端通告路由（latest-wins；Go `c.localRoutes`）。
    routes: Vec<IpRoute>,
}

type SharedState = Arc<Mutex<SessionState>>;

/// 写泵指令（单 owner 写端，哨兵 `Fin` 收尾——禁 drop-sender 语义）。
enum WriteCmd {
    /// 一颗完整胶囊帧（`varint(type) varint(len) payload`）。
    Frame(Vec<u8>),
    /// 流半关闭（Go `queueFin`：SetWriteDeadline(now) + Close）。
    Fin,
}

/// CONNECT-IP 客户端会话（一条 upgraded h2 流上的 IP 包收发面）。
#[derive(Debug)]
pub struct ConnectIpSession {
    cmd_tx: mpsc::Sender<WriteCmd>,
    packet_rx: mpsc::Receiver<Vec<u8>>,
    assignment_rx: mpsc::Receiver<Vec<AssignedAddress>>,
    /// 服务端模式：客户端地址请求队列（`recv_address_request` 消费；客户端模式恒 None）。
    request_rx: Option<mpsc::Receiver<Vec<AddressRequestEntry>>>,
    /// 共享验证态（与读泵同源：服务端 `assign_addresses`/`advertise_route` 更新，
    /// 读泵消费校验入站包）。
    state: SharedState,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
    driver_task: Option<JoinHandle<()>>,
    max_packet_size: usize,
    /// establish 期确定的本端地址（每族一个；Go `masque.Conn.local`）。
    local_addrs: Vec<IpAddr>,
    last_request_id: u64,
    closed: bool,
}

impl ConnectIpSession {
    /// 由 upgraded IO 构造会话。必须在 tokio runtime 上下文内调用（内部 spawn 读/写泵）。
    ///
    /// `driver` 是 h2 连接驱动任务句柄（hyper `Connection` future）；会话关闭时随
    /// 之中止以释放底层 TCP fd（grpc 侧教训：driver 不回收 = fd 滞留）。
    pub(crate) fn new(
        io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        driver: JoinHandle<()>,
    ) -> Self {
        let (rd, wr) = tokio::io::split(io);
        let (cmd_tx, cmd_rx) = mpsc::channel(QUEUE_CAPSULES);
        let (packet_tx, packet_rx) = mpsc::channel(QUEUE_DATAGRAMS);
        let (assignment_tx, assignment_rx) = mpsc::channel(QUEUE_CAPSULES);
        let state: SharedState = Arc::new(Mutex::new(SessionState::default()));
        // 读泵需要写队列句柄（回应 ADDRESS_REQUEST）；先克隆再 move，原句柄留给 Self。
        let reader_cmd_tx = cmd_tx.clone();
        // ①类待迁移（bd xosi9 改判）：capsule 读泵（解帧 → 验证 → 分发）；寿命 =
        // ConnectIpSession（B4 接线时随隧道宿主经 ComponentScope 托管）；目标托管口 =
        // xray_frame::scope::ComponentScope。
        #[allow(
            clippy::disallowed_methods,
            reason = "①类待迁移（bd xosi9 改判）：capsule 读泵，寿命 = ConnectIpSession 句柄持有；目标托管口 = xray_frame::scope::ComponentScope（B4 隧道宿主接线）"
        )]
        let reader_task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let outcome =
                    read_loop(rd, state, packet_tx, assignment_tx, reader_cmd_tx, None).await;
                match outcome {
                    Ok(()) => crate::LOG.debug("masque: capsule stream closed by peer"),
                    Err(e) => crate::LOG.debug(format!("masque: capsule read failed: {e}")),
                }
            })
        };
        // ①类待迁移（bd xosi9 改判）：capsule 写泵（单 owner 写端）；寿命 =
        // ConnectIpSession；目标托管口 = xray_frame::scope::ComponentScope。
        #[allow(
            clippy::disallowed_methods,
            reason = "①类待迁移（bd xosi9 改判）：capsule 写泵（单 owner 写端 + Fin 哨兵），寿命 = ConnectIpSession；目标托管口 = xray_frame::scope::ComponentScope（B4 隧道宿主接线）"
        )]
        let writer_task = tokio::spawn(write_loop(wr, cmd_rx));
        Self {
            cmd_tx,
            packet_rx,
            assignment_rx,
            request_rx: None,
            state,
            reader_task,
            writer_task,
            driver_task: Some(driver),
            max_packet_size: h2_max_packet_size(),
            local_addrs: Vec::new(),
            last_request_id: 0,
            closed: false,
        }
    }

    /// 请求对端分配前缀（Go `conn.go RequestAddresses`）：ID 自增连续分配，
    /// 前缀必须 masked（主机位全零）。
    pub fn request_addresses(&mut self, prefixes: &[IpPrefix]) -> Result<Vec<u64>> {
        if self.closed {
            return Err(closed_err());
        }
        if prefixes.is_empty() {
            return Err(MasqueError::Protocol(
                "masque: address request must contain at least one prefix".into(),
            ));
        }
        for (i, p) in prefixes.iter().enumerate() {
            if !capsule::is_masked(&p.addr, p.prefix_len) {
                return Err(MasqueError::Protocol(format!(
                    "masque: invalid requested prefix {i}: host bits must be zero"
                )));
            }
        }
        let first = self.last_request_id + 1;
        let entries: Vec<crate::capsule::AddressRequestEntry> = prefixes
            .iter()
            .enumerate()
            .map(|(i, p)| crate::capsule::AddressRequestEntry {
                request_id: first + i as u64,
                prefix: p.clone(),
            })
            .collect();
        let ids: Vec<u64> = entries.iter().map(|e| e.request_id).collect();
        let frame = encode_capsule(&Capsule::AddressRequest(entries))?;
        self.queue_frame(frame)?;
        self.last_request_id = first + prefixes.len() as u64 - 1;
        Ok(ids)
    }

    /// 等待下一条地址分配（Go `ReceiveAddressAssignment`）；含拒绝条目（判定见
    /// [`AssignedAddress::is_rejected`]）。会话已关 = Err。
    pub async fn recv_assignment(&mut self) -> Result<Vec<AssignedAddress>> {
        self.assignment_rx.recv().await.ok_or_else(closed_err)
    }

    /// 发送一个 IP 包。返回 `Some(icmp)` = 包超 MTU，调用方必须把 ICMP 回灌进本端
    /// 用户态栈（Go h3 写侧 `composeICMPTooLargePacket` 语义）；`None` = 已入队或
    /// 包不合法被丢弃（Go `composeDatagram` 失败 = debug 日志 + 静默丢弃）。
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.writer()?.send_packet(packet).await
    }

    /// 接收下一个合法入站 IP 包（已过验证态；Go `ReadPacket` 的整包形态）。
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        self.packet_rx.recv().await.ok_or_else(closed_err)
    }

    /// 隧道可承载的单包上限（Go `MaxPacketSize`；h2 恒为胶囊包上限）。
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    /// 本端地址（establish 期确定；每族一个）。
    pub fn local_addrs(&self) -> &[IpAddr] {
        &self.local_addrs
    }

    /// 关闭会话（尽力优雅）：队列尾投递 Fin 半关闭 + 中止读泵与 h2 driver；
    /// 写泵若空闲则自然写出 Fin 后自行退出，阻塞（对端窗满）时由 Drop 兜底硬中止。
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.cmd_tx.try_send(WriteCmd::Fin);
        self.reader_task.abort();
        if let Some(d) = self.driver_task.take() {
            d.abort();
        }
    }
}

impl Drop for ConnectIpSession {
    fn drop(&mut self) {
        if !self.closed {
            // 未显式 close 的丢弃 = 立即中止（不等 Fin 排空）。
            self.reader_task.abort();
            self.writer_task.abort();
            if let Some(d) = self.driver_task.take() {
                d.abort();
            }
        } else {
            self.writer_task.abort();
        }
    }
}

impl ConnectIpSession {
    /// 写面克隆句柄（服务端多泵形态：读泵独占会话收发面，写泵/地址请求泵经
    /// [`SessionWriter`] 共享写端——cmd_tx 是 mpsc 克隆面，Go `Conn.queueWrite`
    /// 的 mu 串行等价）。
    ///
    /// 会话已关 = Err；克隆句柄存活期间会话写泵不会退出（Drop 兜底 abort）。
    pub fn writer(&self) -> Result<SessionWriter> {
        if self.closed {
            return Err(closed_err());
        }
        Ok(SessionWriter {
            cmd_tx: self.cmd_tx.clone(),
            state: Arc::clone(&self.state),
            max_packet_size: self.max_packet_size,
        })
    }

    fn queue_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        // Go queueWrite：非阻塞入队，满 = 协议违规关连接（errCapsuleLimit）。
        if self.cmd_tx.try_send(WriteCmd::Frame(frame)).is_err() {
            self.close();
            return Err(MasqueError::Protocol("masque: capsule queue full".into()));
        }
        Ok(())
    }
}

/// 会话写面（`ConnectIpSession::writer` 产物）：发送胶囊帧的共享句柄。
///
/// 服务端形态下与读泵并存：读泵独占 `packet_rx/request_rx/assignment_rx`，
/// 写面（地址分配/路由通告/请求回应/数据包出站）经本句柄从多个泵任务并发
/// 投递（mpsc 串行化）。会话关闭（`Fin`/abort）后所有投递失败 = `closed_err`。
#[derive(Debug)]
pub struct SessionWriter {
    cmd_tx: mpsc::Sender<WriteCmd>,
    state: SharedState,
    max_packet_size: usize,
}

impl SessionWriter {
    /// 发送一个 IP 包（语义同 [`ConnectIpSession::send_packet`]）。
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if packet.len() > self.max_packet_size {
            return compose_icmp_packet_too_big(packet, self.max_packet_size).map(Some);
        }
        let data = match compose_datagram(packet) {
            Ok(d) => d,
            Err(e) => {
                crate::LOG.debug(format!(
                    "masque: dropping proxied packet ({} bytes) that can't be proxied: {e}",
                    packet.len()
                ));
                return Ok(None);
            },
        };
        let frame = encode_capsule(&Capsule::Datagram(data))?;
        // Go WritePacket → c.write：直写流（同步阻塞语义）；本仓经写泵队列，
        // 满即背压（与 Go 流窗满阻塞等价）。
        self.cmd_tx.send(WriteCmd::Frame(frame)).await.map_err(|_| closed_err())?;
        Ok(None)
    }

    /// 服务端主动地址分配（Go `AssignAddresses`；会话层包装的写面形态）。
    pub fn assign_addresses(&mut self, prefixes: &[IpPrefix]) -> Result<()> {
        let entries: Vec<AssignedAddress> =
            prefixes.iter().map(|p| AssignedAddress { request_id: 0, prefix: p.clone() }).collect();
        let frame = encode_capsule(&Capsule::AddressAssign(entries))?;
        self.queue_frame(frame)?;
        // 验证态 peer = 非拒绝条目（Go sendAddressAssignment 尾段）。
        let mut st = self.state.lock().map_err(|_| poisoned_err())?;
        st.peer = Some(prefixes.to_vec());
        Ok(())
    }

    /// 路由通告（Go `AdvertiseRoute`；会话层包装的写面形态）。
    pub fn advertise_route(&mut self, routes: &[IpRoute]) -> Result<()> {
        for (i, route) in routes.iter().enumerate() {
            validate_route(route)
                .map_err(|e| MasqueError::Protocol(format!("masque: invalid route {i}: {e}")))?;
            if i > 0 {
                check_route_order(&routes[i - 1], route).map_err(|e| {
                    MasqueError::Protocol(format!("masque: invalid route {i}: {e}"))
                })?;
            }
        }
        let frame = encode_capsule(&Capsule::RouteAdvertisement(routes.to_vec()))?;
        self.queue_frame(frame)?;
        let mut st = self.state.lock().map_err(|_| poisoned_err())?;
        st.routes = routes.to_vec();
        Ok(())
    }

    /// 回应客户端地址请求（Go `AddressRequest.Respond`）：条目回显请求 ID +
    /// 对应分配前缀；不可满足条目 = 同族拒绝前缀（`0.0.0.0/32`/`::/128`），
    /// 额外分配（additional）条目 request_id = 0。与 Go 的差异：验证态 peer
    /// 不随 Respond 更新（分配地址恒由 [`Self::assign_addresses`] 设定，Respond
    /// 条目 ⊆ 已分配集合，净语义一致）。
    pub fn respond_assignments(&mut self, entries: Vec<AssignedAddress>) -> Result<()> {
        let frame = encode_capsule(&Capsule::AddressAssign(entries))?;
        self.queue_frame(frame)
    }

    fn queue_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        // Go queueWrite：非阻塞入队，满 = 协议违规关连接（errCapsuleLimit）。
        if self.cmd_tx.try_send(WriteCmd::Frame(frame)).is_err() {
            return Err(MasqueError::Protocol("masque: capsule queue full".into()));
        }
        Ok(())
    }
}

/// 服务端读泵的 ADDRESS_REQUEST 队列上界（Go `addressRequests` 通道同界 128）。
const QUEUE_REQUESTS: usize = QUEUE_CAPSULES;

impl ConnectIpSession {
    /// 服务端形态构造（B4：hub accept 后）：读泵对 ADDRESS_REQUEST 投递到内部
    /// 通道（不自动拒绝回应——回应由服务端 proxy 层按分配结果经
    /// [`Self::respond_assignments`] 完成，Go `serveAddressRequests` →
    /// `AddressRequest.Respond`）。其余读侧行为与客户端模式对称（Go `Conn`
    /// 两端共用同一结构）。
    ///
    /// 与客户端形态的差异：无独立 h2 driver 任务——服务端连接驱动 =
    /// hub 的 `serve_connection` future（流 EOF 即连接回收，无 fd 滞留面），
    /// `driver_task` 恒 `None`。
    ///
    /// 必须在 tokio runtime 上下文内调用（内部 spawn 读/写泵）。
    pub fn server_session(io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        let (rd, wr) = tokio::io::split(io);
        let (cmd_tx, cmd_rx) = mpsc::channel(QUEUE_CAPSULES);
        let (packet_tx, packet_rx) = mpsc::channel(QUEUE_DATAGRAMS);
        let (assignment_tx, assignment_rx) = mpsc::channel(QUEUE_CAPSULES);
        let (request_tx, request_rx) = mpsc::channel(QUEUE_REQUESTS);
        let state: SharedState = Arc::new(Mutex::new(SessionState::default()));
        let reader_cmd_tx = cmd_tx.clone();
        // ①类待迁移（bd xosi9 改判）：服务端 capsule 读泵；寿命 = ConnectIpSession
        // 句柄持有；目标托管口 = xray_frame::scope::ComponentScope（B4 隧道宿主接线）。
        #[allow(
            clippy::disallowed_methods,
            reason = "①类待迁移（bd xosi9 改判）：服务端 capsule 读泵，寿命 = ConnectIpSession 句柄持有；目标托管口 = xray_frame::scope::ComponentScope（B4 隧道宿主接线）"
        )]
        let reader_task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let outcome =
                    read_loop(rd, state, packet_tx, assignment_tx, reader_cmd_tx, Some(request_tx))
                        .await;
                match outcome {
                    Ok(()) => crate::LOG.debug("masque: capsule stream closed by peer"),
                    Err(e) => crate::LOG.debug(format!("masque: capsule read failed: {e}")),
                }
            })
        };
        // ①类待迁移（bd xosi9 改判）：服务端 capsule 写泵；同上目标托管口。
        #[allow(
            clippy::disallowed_methods,
            reason = "①类待迁移（bd xosi9 改判）：服务端 capsule 写泵（单 owner 写端 + Fin 哨兵），寿命 = ConnectIpSession；目标托管口 = xray_frame::scope::ComponentScope（B4 隧道宿主接线）"
        )]
        let writer_task = tokio::spawn(write_loop(wr, cmd_rx));
        Self {
            cmd_tx,
            packet_rx,
            assignment_rx,
            request_rx: Some(request_rx),
            state,
            reader_task,
            writer_task,
            driver_task: None,
            max_packet_size: h2_max_packet_size(),
            local_addrs: Vec::new(),
            last_request_id: 0,
            closed: false,
        }
    }

    /// 服务端主动地址分配（Go `AssignAddresses` 写面形态；见 [`SessionWriter`]）。
    pub fn assign_addresses(&mut self, prefixes: &[IpPrefix]) -> Result<()> {
        self.writer()?.assign_addresses(prefixes)
    }

    /// 路由通告（Go `AdvertiseRoute` 写面形态；见 [`SessionWriter`]）。
    pub fn advertise_route(&mut self, routes: &[IpRoute]) -> Result<()> {
        self.writer()?.advertise_route(routes)
    }

    /// 取出服务端 ADDRESS_REQUEST 队列读端（`server_session` 产物独有；取出后
    /// 恒 `None`）。消费形态 = 隧道读泵 `select!` 同时等 [`Self::recv_packet`] 与
    /// 本通道（客户端模式恒 `None`）。会话已关 = `None`。
    #[must_use]
    pub fn take_request_rx(&mut self) -> Option<mpsc::Receiver<Vec<AddressRequestEntry>>> {
        self.request_rx.take()
    }

    /// 回应客户端地址请求（Go `AddressRequest.Respond` 写面形态；见
    /// [`SessionWriter::respond_assignments`]）。
    pub fn respond_assignments(&mut self, entries: Vec<AssignedAddress>) -> Result<()> {
        self.writer()?.respond_assignments(entries)
    }
}

/// 路由条目校验（Go `IPRoute.validate`）：同族 + start ≤ end。zone/有效性在
/// std 解析期已保证，不重复检查。
fn validate_route(r: &IpRoute) -> std::result::Result<(), String> {
    if r.start_ip.is_ipv4() != r.end_ip.is_ipv4() {
        return Err(format!("IP address range {}-{} mixes IP versions", r.start_ip, r.end_ip));
    }
    if r.start_ip > r.end_ip {
        return Err(format!("start IP {} is greater than end IP {}", r.start_ip, r.end_ip));
    }
    Ok(())
}

/// 相邻路由排序校验（Go `checkRouteOrder`）：按（族位长，协议号）升序，同组
/// 区间严格递增不重叠。
fn check_route_order(a: &IpRoute, b: &IpRoute) -> std::result::Result<(), String> {
    let fa = usize::from(capsule::ip_bit_len(a.start_ip));
    let fb = usize::from(capsule::ip_bit_len(b.start_ip));
    let proto_a = u16::from(a.ip_protocol);
    let proto_b = u16::from(b.ip_protocol);
    match fa.cmp(&fb).then(proto_a.cmp(&proto_b)) {
        std::cmp::Ordering::Greater => Err(format!(
            "routes are not ordered by IP version and IP protocol: {}-{} (protocol {}) \
             precedes {}-{} (protocol {})",
            a.start_ip, a.end_ip, a.ip_protocol, b.start_ip, b.end_ip, b.ip_protocol
        )),
        std::cmp::Ordering::Equal if a.end_ip >= b.start_ip => Err(format!(
            "IP address ranges {}-{} and {}-{} (protocol {}) overlap or are not in \
             ascending order",
            a.start_ip, a.end_ip, b.start_ip, b.end_ip, b.ip_protocol
        )),
        _ => Ok(()),
    }
}

fn closed_err() -> MasqueError {
    MasqueError::Io(std::io::Error::new(std::io::ErrorKind::NotConnected, "masque: tunnel closed"))
}

// ===== 读泵 =====

async fn read_loop(
    mut rd: impl AsyncRead + Unpin,
    state: SharedState,
    packet_tx: mpsc::Sender<Vec<u8>>,
    assignment_tx: mpsc::Sender<Vec<AssignedAddress>>,
    cmd_tx: mpsc::Sender<WriteCmd>,
    // 服务端模式：`Some` = ADDRESS_REQUEST 投递到该通道（Go `addressRequests`）；
    // `None` = 客户端模式：读泵直接以同族拒绝前缀回应（Go 客户端外壳语义）。
    request_tx: Option<mpsc::Sender<Vec<AddressRequestEntry>>>,
) -> Result<()> {
    loop {
        let (ty, payload) = read_frame(&mut rd).await?;
        match decode_capsule(ty, &payload)? {
            Some(Capsule::Datagram(packet)) => {
                if !validate_incoming(&packet, &state) {
                    crate::LOG.debug(format!(
                        "masque: dropping proxied packet ({} bytes): not allowed",
                        packet.len()
                    ));
                    continue;
                }
                // Go queueDatagram：阻塞投递（满则等空位/会话关）。
                if packet_tx.send(packet).await.is_err() {
                    return Ok(());
                }
            },
            Some(Capsule::AddressAssign(entries)) => {
                {
                    let mut st = state.lock().map_err(|_| poisoned_err())?;
                    st.assigned = entries
                        .iter()
                        .filter(|e| !e.is_rejected())
                        .map(|e| e.prefix.clone())
                        .collect();
                }
                // Go：非阻塞投递，满 = errCapsuleLimit → 连接关闭。
                if assignment_tx.try_send(entries).is_err() {
                    return Err(MasqueError::Protocol(
                        "masque: address assignment queue full".into(),
                    ));
                }
            },
            Some(Capsule::AddressRequest(entries)) => {
                match &request_tx {
                    // 服务端模式：投递给上层 serve（Go `addressRequests` 通道，
                    // 满队列 = errCapsuleLimit 关连接）。
                    Some(tx) => {
                        if tx.try_send(entries).is_err() {
                            return Err(MasqueError::Protocol(
                                "masque: address request queue full".into(),
                            ));
                        }
                    },
                    // 客户端模式：对每个请求以同族拒绝前缀回应（`0.0.0.0/32` /
                    // `::/128`），request ID 原样回显（address.go Respond）。
                    None => {
                        let frame = encode_capsule(&Capsule::AddressAssign(
                            entries
                                .iter()
                                .map(|e| AssignedAddress {
                                    request_id: e.request_id,
                                    prefix: reject_prefix_for(&e.prefix.addr),
                                })
                                .collect(),
                        ))?;
                        if cmd_tx.try_send(WriteCmd::Frame(frame)).is_err() {
                            return Err(MasqueError::Protocol("masque: capsule queue full".into()));
                        }
                    },
                }
            },
            Some(Capsule::RouteAdvertisement(routes)) => {
                // Go queueLatest：容量 1，latest-wins。
                match state.lock() {
                    Ok(mut st) => st.routes = routes,
                    Err(_) => return Err(poisoned_err()),
                }
            },
            Some(Capsule::Unknown { .. }) | None => {},
        }
    }
}

fn poisoned_err() -> MasqueError {
    MasqueError::Protocol("masque: session state mutex poisoned".into())
}

async fn write_loop(mut wr: impl AsyncWrite + Unpin, mut cmd_rx: mpsc::Receiver<WriteCmd>) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            WriteCmd::Frame(data) => {
                if wr.write_all(&data).await.is_err() {
                    return;
                }
                // rustls/tokio-rustls poll_write 是 BufWriter 语义（铁律）：不 flush
                // 则帧滞留 session 缓冲，IP 包逐包出站语义（低延迟隧道）必须逐帧 flush。
                if wr.flush().await.is_err() {
                    return;
                }
            },
            WriteCmd::Fin => {
                let _ = wr.shutdown().await;
                return;
            },
        }
    }
}

/// 读一颗完整胶囊帧（`varint(type) varint(len) payload`）。
async fn read_frame(rd: &mut (impl AsyncRead + Unpin)) -> Result<(u64, Vec<u8>)> {
    let ty = read_varint_async(rd).await?;
    let len = read_varint_async(rd).await?;
    let len = usize::try_from(len)
        .map_err(|_| MasqueError::Protocol("masque: capsule length overflow".into()))?;
    if len > MAX_FRAME_PAYLOAD {
        return Err(MasqueError::Protocol(format!(
            "masque: capsule frame too large ({len} bytes)"
        )));
    }
    let mut payload = vec![0u8; len];
    rd.read_exact(&mut payload).await?;
    Ok((ty, payload))
}

/// RFC 9000 varint 异步读取：先读定长字节窗口，解析复用上浮件
/// [`read_varint`]（勿在本仓再造第二份 varint 解析）。
async fn read_varint_async(rd: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    let mut first = [0u8; 1];
    rd.read_exact(&mut first).await?;
    let total = 1usize << usize::from(first[0] >> 6);
    let mut buf = [0u8; 8];
    buf[0] = first[0];
    rd.read_exact(&mut buf[1..total]).await?;
    let mut cur = Cursor::new(&buf[..total]);
    read_varint(&mut cur).map_err(MasqueError::Io)
}

// ===== 出站包整形（Go conn.go composeDatagram） =====

fn compose_datagram(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.is_empty() {
        return Err(MasqueError::Protocol("masque: empty packet".into()));
    }
    let mut data = packet.to_vec();
    match data[0] >> 4 {
        4 => {
            if data.len() < 20 {
                return Err(MasqueError::Protocol("masque: IPv4 packet too short".into()));
            }
            let hdr_len = usize::from(data[0] & 0x0f) << 2;
            let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if hdr_len < 20 || hdr_len > total_len || total_len > data.len() {
                return Err(MasqueError::Protocol(format!(
                    "masque: malformed IPv4 header: header length {hdr_len}, total length \
                     {total_len}, packet length {}",
                    data.len()
                )));
            }
            if data[8] <= 1 {
                return Err(MasqueError::Protocol(format!(
                    "masque: datagram TTL too small: {}",
                    data[8]
                )));
            }
            data[8] -= 1;
            let ck = ipv4_header_checksum(&data[..hdr_len]);
            data[10..12].copy_from_slice(&ck.to_be_bytes());
        },
        6 => {
            if data.len() < 40 {
                return Err(MasqueError::Protocol("masque: IPv6 packet too short".into()));
            }
            if data[7] <= 1 {
                return Err(MasqueError::Protocol(format!(
                    "masque: datagram Hop Limit too small: {}",
                    data[7]
                )));
            }
            data[7] -= 1;
        },
        v => return Err(MasqueError::Protocol(format!("masque: unknown IP versions: {v}"))),
    }
    Ok(data)
}

// ===== 入站包验证（Go conn.go handleIncomingProxiedPacket） =====

fn validate_incoming(packet: &[u8], state: &SharedState) -> bool {
    if packet.is_empty() {
        return false;
    }
    let (src, dst, ip_proto) = match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            (
                IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
                IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
                packet[9],
            )
        },
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let mut s = [0u8; 16];
            s.copy_from_slice(&packet[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[24..40]);
            (IpAddr::V6(s.into()), IpAddr::V6(d.into()), packet[6])
        },
        _ => return false,
    };
    let st = match state.lock() {
        Ok(st) => st,
        Err(_) => return false,
    };
    if let Some(peer) = &st.peer {
        if !peer.iter().any(|p| prefix_contains(p, src)) {
            return false;
        }
    }
    let allowed = if !st.assigned.is_empty() {
        st.assigned.iter().any(|p| prefix_contains(p, dst))
    } else {
        false
    };
    if allowed {
        return true;
    }
    st.routes.iter().any(|r| {
        if r.start_ip > dst || dst > r.end_ip {
            return false;
        }
        if (r.start_ip.is_ipv4() && ip_proto == IP_PROTO_ICMP)
            || (r.start_ip.is_ipv6() && ip_proto == IP_PROTO_ICMPV6)
        {
            return true;
        }
        r.ip_protocol == 0 || r.ip_protocol == ip_proto
    })
}

/// 前缀包含判定（Go `netip.Prefix.Contains`；pool.rs 共用）。
pub(crate) fn prefix_contains(p: &IpPrefix, ip: IpAddr) -> bool {
    let (p_oct, i_oct): ([u8; 16], [u8; 16]) = match (&p.addr, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (pad_octets(&a.octets()), pad_octets(&b.octets())),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets(), b.octets()),
        _ => return false,
    };
    let full = usize::from(p.prefix_len / 8);
    if p_oct[..full] != i_oct[..full] {
        return false;
    }
    let rem = p.prefix_len % 8;
    rem == 0 || (p_oct[full] >> (8 - rem)) == (i_oct[full] >> (8 - rem))
}

fn pad_octets(v4: &[u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(v4);
    out
}

/// 网络地址 → 首个主机地址（Go `Addr.Next()`；pool.rs 共用）。
pub(crate) fn next_addr(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            u32::from(v).checked_add(1).map_or(IpAddr::V4(v), |n| IpAddr::V4(n.into()))
        },
        IpAddr::V6(v) => {
            u128::from(v).checked_add(1).map_or(IpAddr::V6(v), |n| IpAddr::V6(n.into()))
        },
    }
}

/// 本端地址提取（Go `dialer.go localAddrs`）：跳过拒绝条目，每族取首个；
/// 前缀短于位长时取掩码后下一地址（首个主机地址）。
pub(crate) fn local_addrs(assigned: &[AssignedAddress]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut has4 = false;
    let mut has6 = false;
    for a in assigned {
        if a.is_rejected() {
            continue;
        }
        let mut addr = a.prefix.addr;
        if a.prefix.prefix_len != capsule::ip_bit_len(a.prefix.addr) {
            addr = next_addr(addr);
        }
        match addr {
            IpAddr::V4(_) if !has4 => {
                has4 = true;
                out.push(addr);
            },
            IpAddr::V6(_) if !has6 => {
                has6 = true;
                out.push(addr);
            },
            _ => {},
        }
    }
    out
}

fn reject_prefix_for(addr: &IpAddr) -> IpPrefix {
    match addr {
        IpAddr::V4(_) => IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 32 },
        IpAddr::V6(_) => IpPrefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix_len: 128 },
    }
}

// ===== ICMP packet-too-big 回灌（Go icmp.go composeICMPTooLargePacket） =====

fn compose_icmp_packet_too_big(packet: &[u8], mtu: usize) -> Result<Vec<u8>> {
    if packet.is_empty() {
        return Err(MasqueError::Protocol("masque: empty packet".into()));
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(MasqueError::Protocol("masque: IPv4 packet too short".into()));
            }
            if mtu < IPV4_MIN_MTU {
                return Err(MasqueError::Mtu);
            }
            let hdr_len = usize::from(packet[0] & 0x0f) << 2;
            let quoted = &packet[..packet.len().min(usize::max(20, hdr_len) + 8)];
            let mut icmp = Vec::with_capacity(8 + quoted.len());
            // type=3 Destination Unreachable, code=4 fragmentation needed
            icmp.extend_from_slice(&[3, 4, 0, 0]);
            icmp.extend_from_slice(&(mtu as u32).to_be_bytes());
            icmp.extend_from_slice(quoted);
            let ck = internet_checksum(&icmp);
            icmp[2..4].copy_from_slice(&ck.to_be_bytes());
            let mut out = vec![0u8; 20 + icmp.len()];
            out[0] = 0x45; // 4<<4 | IHL=5
            out[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
            out[8] = 64; // TTL
            out[9] = IP_PROTO_ICMP;
            out[12..16].copy_from_slice(&packet[16..20]);
            out[16..20].copy_from_slice(&packet[12..16]);
            let hdr_ck = ipv4_header_checksum(&out[..20]);
            out[10..12].copy_from_slice(&hdr_ck.to_be_bytes());
            out[20..].copy_from_slice(&icmp);
            Ok(out)
        },
        6 => {
            if packet.len() < 40 {
                return Err(MasqueError::Protocol("masque: IPv6 packet too short".into()));
            }
            if mtu < IPV6_MIN_MTU {
                return Err(MasqueError::Mtu);
            }
            let quoted = &packet[..packet.len().min(1232)];
            let mut icmp = Vec::with_capacity(8 + quoted.len());
            // type=2 Packet Too Big, code=0
            icmp.extend_from_slice(&[2, 0, 0, 0]);
            icmp.extend_from_slice(&(mtu as u32).to_be_bytes());
            icmp.extend_from_slice(quoted);
            let mut s = [0u8; 16];
            s.copy_from_slice(&packet[24..40]); // 伪头 src = 原 dst
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[8..24]); // 伪头 dst = 原 src
            let ck = icmpv6_checksum(&s, &d, &icmp);
            icmp[2..4].copy_from_slice(&ck.to_be_bytes());
            let mut out = vec![0u8; 40 + icmp.len()];
            out[0] = 6 << 4;
            out[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            out[6] = IP_PROTO_ICMPV6;
            out[7] = 64;
            out[8..24].copy_from_slice(&packet[24..40]);
            out[24..40].copy_from_slice(&packet[8..24]);
            out[40..].copy_from_slice(&icmp);
            Ok(out)
        },
        v => Err(MasqueError::Protocol(format!("masque: unknown IP version: {v}"))),
    }
}

/// IPv4 头校验和（Go checksum.go calculateIPv4Checksum：跳过校验和字段本身）。
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for (idx, pair) in header.chunks_exact(2).enumerate() {
        if idx == 5 {
            continue; // 字节偏移 10 = 校验和字段
        }
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    finish_checksum(sum)
}

/// 标准 Internet 校验和（x/net/icmp Marshal 语义：不跳任何字段）。
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [odd] = chunks.remainder() {
        sum += u16::from_be_bytes([*odd, 0]) as u32;
    }
    finish_checksum(sum)
}

/// ICMPv6 校验和：IPv6 伪头（src/dst/上层长度/next=58）+ ICMP 消息。
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + icmp.len());
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, IP_PROTO_ICMPV6]);
    buf.extend_from_slice(icmp);
    internet_checksum(&buf)
}

fn finish_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ===== establish（Go dialer.go establish 的客户端协商段） =====

/// 地址协商：上限校验 → 请求 `0.0.0.0/32` + `::/128` → 等首个含本端地址的分配
/// （Go dialer.go establish）。
pub(crate) async fn establish(mut session: ConnectIpSession) -> Result<ConnectIpSession> {
    if session.max_packet_size < MIN_PACKET_SIZE {
        let n = session.max_packet_size;
        session.close();
        return Err(MasqueError::Protocol(format!(
            "masque: the tunnel can only carry {n}-byte packets, less than {MIN_PACKET_SIZE}"
        )));
    }
    session.request_addresses(&[
        IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 32 },
        IpPrefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix_len: 128 },
    ])?;
    let mut local = Vec::new();
    while local.is_empty() {
        let assigned = session.recv_assignment().await?;
        local = local_addrs(&assigned);
    }
    session.local_addrs = local;
    Ok(session)
}

// ===== B2.3 环回互验（规划 §5 B2.3：进程内 hyper server ↔ 客户端） =====

/// 环回测试支撑：hyper extended-CONNECT server + 胶囊回声泵 + 测试包构造器。
/// 供本模块与 `dialer.rs` TLS e2e 复用；仅测试构建可见，不进生产 API 面。
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::disallowed_methods)] // 测试基建 spawn（spawn 三分类②「压测/测试基建」）

    use std::{collections::HashMap, net::IpAddr};

    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper::{body::Incoming, ext::Protocol, service::service_fn, upgrade::Upgraded};
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto,
    };
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;

    /// 环回 server 固定分配（v4/v6 各一，非 0.0.0.0 形态）。
    pub const ASSIGN_V4: IpPrefix =
        IpPrefix { addr: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10)), prefix_len: 32 };
    pub const ASSIGN_V6: IpPrefix = IpPrefix {
        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        prefix_len: 128,
    };

    /// 环回 server 行为档。
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum ServerBehavior {
        /// 纯回声：地址请求按族固定分配，数据包原样回。
        Echo,
        /// 回声前先注入一个未分配目的（8.8.8.8）的数据包——客户端必须丢弃。
        InjectForeignThenEcho,
        /// 先通告 10/8 全协议路由再回声——客户端须按路由放行 10.x 目的。
        EchoWithRoutes,
    }

    pub fn test_config() -> crate::config::Config {
        crate::config::Config {
            host: String::new(),
            path: crate::config::DEFAULT_PATH.to_string(),
            headers: HashMap::new(),
        }
    }

    pub fn udp_v4_packet(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + payload.len()];
        p[0] = 0x45;
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[8] = ttl;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20 + 2..20 + 4].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[20 + 8..].copy_from_slice(payload);
        let ck = internet_checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p
    }

    pub fn udp_v6_packet(src: Ipv6Addr, dst: Ipv6Addr, hop: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40 + 8 + payload.len()];
        p[0] = 6 << 4;
        let payload_len = (8 + payload.len()) as u16;
        p[4..6].copy_from_slice(&payload_len.to_be_bytes());
        p[6] = 17; // UDP
        p[7] = hop;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40 + 2..40 + 4].copy_from_slice(&payload_len.to_be_bytes());
        p[40 + 8..].copy_from_slice(payload);
        p
    }

    /// 服务端胶囊回声泵：地址请求 → 按族固定分配；数据包 →（可选注入外来包后）原样回。
    pub async fn echo_loop(io: Upgraded, behavior: ServerBehavior) {
        let mut io = TokioIo::new(io);
        let mut foreign_injected = false;
        if behavior == ServerBehavior::EchoWithRoutes {
            let frame = encode_capsule(&Capsule::RouteAdvertisement(vec![IpRoute {
                start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)),
                ip_protocol: 0,
            }]))
            .expect("route frame encodes");
            io.write_all(&frame).await.expect("write routes");
            io.flush().await.expect("flush routes");
        }
        loop {
            let (ty, payload) = match read_frame(&mut io).await {
                Ok(f) => f,
                Err(_) => break,
            };
            let Some(capsule) = decode_capsule(ty, &payload).expect("server decode") else {
                continue;
            };
            match capsule {
                Capsule::AddressRequest(entries) => {
                    let assign: Vec<AssignedAddress> = entries
                        .iter()
                        .map(|e| AssignedAddress {
                            request_id: e.request_id,
                            prefix: if e.prefix.addr.is_ipv4() { ASSIGN_V4 } else { ASSIGN_V6 },
                        })
                        .collect();
                    let frame = encode_capsule(&Capsule::AddressAssign(assign))
                        .expect("assign frame encodes");
                    io.write_all(&frame).await.expect("write assign");
                    io.flush().await.expect("flush assign");
                },
                Capsule::Datagram(packet) => {
                    if behavior == ServerBehavior::InjectForeignThenEcho && !foreign_injected {
                        foreign_injected = true;
                        let foreign = udp_v4_packet(
                            Ipv4Addr::new(8, 8, 8, 8),
                            Ipv4Addr::new(8, 8, 8, 8),
                            64,
                            b"foreign-dst",
                        );
                        let frame =
                            encode_capsule(&Capsule::Datagram(foreign)).expect("foreign encodes");
                        io.write_all(&frame).await.expect("write foreign");
                        io.flush().await.expect("flush foreign");
                    }
                    let frame =
                        encode_capsule(&Capsule::Datagram(packet)).expect("echo frame encodes");
                    io.write_all(&frame).await.expect("write echo");
                    io.flush().await.expect("flush echo");
                },
                _ => {},
            }
        }
    }

    /// 起进程内 hyper auto(h2) server（extended CONNECT 开启），对 CONNECT-IP 流执行
    /// [`echo_loop`]；断言请求形态（:protocol=connect-ip / CONNECT / Capsule-Protocol）。
    pub async fn spawn_loopback_server(io: DuplexStream, behavior: ServerBehavior) {
        tokio::spawn(async move {
            let mut builder = auto::Builder::new(TokioExecutor::new());
            let _ = builder
                .http2()
                .enable_connect_protocol()
                .serve_connection_with_upgrades(
                    TokioIo::new(io),
                    service_fn(move |req: Request<Incoming>| async move {
                        let proto = req
                            .extensions()
                            .get::<Protocol>()
                            .map_or_else(String::new, |p| p.as_str().to_string());
                        assert_eq!(proto, "connect-ip", "server must see :protocol");
                        assert_eq!(req.method(), Method::CONNECT);
                        assert_eq!(
                            req.headers().get("capsule-protocol").and_then(|v| v.to_str().ok()),
                            Some("?1"),
                            "server must see Capsule-Protocol: ?1"
                        );
                        let upgrade = hyper::upgrade::on(req);
                        tokio::spawn(async move {
                            match upgrade.await {
                                Ok(io) => echo_loop(io, behavior).await,
                                Err(e) => panic!("server upgrade failed: {e}"),
                            }
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .expect("static response builds"),
                        )
                    }),
                )
                .await;
        });
    }

    /// request_addresses([0.0.0.0/32, ::/128]) → 等首个分配 → 返回 (ids, entries)。
    pub async fn negotiate_addresses(
        session: &mut ConnectIpSession,
    ) -> Result<(Vec<u64>, Vec<AssignedAddress>)> {
        let ids = session.request_addresses(&[
            IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 32 },
            IpPrefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix_len: 128 },
        ])?;
        let assigned = session.recv_assignment().await?;
        Ok((ids, assigned))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{test_support::*, *};

    /// 建立一条环回 CONNECT-IP 会话（真 hyper server ↔ 真客户端全链路）。
    async fn loopback_session(behavior: ServerBehavior) -> ConnectIpSession {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        spawn_loopback_server(server_io, behavior).await;
        crate::h2::connect_h2(client_io, &test_config(), "masque.test")
            .await
            .expect("loopback CONNECT-IP session")
    }

    #[tokio::test]
    async fn loopback_assign_and_ip_roundtrip() {
        let mut session = loopback_session(ServerBehavior::Echo).await;

        // 地址分配：ids 连续自增；分配非 0.0.0.0 且按族固定。
        let (ids, assigned) = negotiate_addresses(&mut session).await.expect("negotiate");
        assert_eq!(ids, vec![1, 2], "request IDs must be sequential from 1");
        assert_eq!(assigned.len(), 2);
        assert_eq!(assigned[0].request_id, 1);
        assert_eq!(assigned[0].prefix, ASSIGN_V4, "v4 assignment must be 198.18.0.10/32");
        assert_eq!(assigned[1].request_id, 2);
        assert_eq!(assigned[1].prefix, ASSIGN_V6, "v6 assignment must be 2001:db8::1/128");
        assert!(
            !assigned.iter().any(|a| a.is_rejected()),
            "loopback server must assign real addresses, not rejects"
        );

        // local_addrs（establish 语义）：每族一个、首个主机地址。
        let local = local_addrs(&assigned);
        assert_eq!(
            local,
            vec![
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ]
        );

        // 连续 16 个 IPv4/UDP 包往返：载荷一致 + TTL 递减（路由语义）。
        for i in 0..16u16 {
            let payload = format!("dns-query-{i}").into_bytes();
            let packet = udp_v4_packet(
                Ipv4Addr::new(198, 18, 0, 10),
                Ipv4Addr::new(198, 18, 0, 10),
                64,
                &payload,
            );
            let r = session.send_packet(&packet).await.expect("send v4");
            assert!(r.is_none(), "normal packet must not yield ICMP");
            let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
                .await
                .expect("recv within 5s")
                .expect("packet received");
            assert_eq!(got.len(), packet.len());
            assert_eq!(&got[20 + 8..], &payload, "payload must round-trip");
            assert_eq!(got[8], 63, "TTL must be decremented by one");
            assert_eq!(&got[12..20], &packet[12..20], "src/dst must round-trip");
        }

        // IPv6 包往返。
        let v6 = udp_v6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            64,
            b"dns-query-v6",
        );
        let r = session.send_packet(&v6).await.expect("send v6");
        assert!(r.is_none(), "normal packet must not yield ICMP");
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet received");
        assert_eq!(got.len(), v6.len());
        assert_eq!(&got[..7], &v6[..7], "v6 header prefix must round-trip");
        assert_eq!(got[7], 63, "Hop Limit must be decremented by one");
        assert_eq!(&got[8..], &v6[8..], "v6 addresses + payload must round-trip");

        // TTL=1 包：静默丢弃（Go composeDatagram 语义），Ok(None)。
        let dead =
            udp_v4_packet(Ipv4Addr::new(198, 18, 0, 10), Ipv4Addr::new(198, 18, 0, 10), 1, b"dead");
        let r = session.send_packet(&dead).await.expect("send returns");
        assert!(r.is_none(), "TTL=1 packet must be dropped silently");

        // 非法版本包：静默丢弃。
        let mut bad =
            udp_v4_packet(Ipv4Addr::new(198, 18, 0, 10), Ipv4Addr::new(198, 18, 0, 10), 64, b"bad");
        bad[0] = 0x50; // version 5
        let r = session.send_packet(&bad).await.expect("send returns");
        assert!(r.is_none(), "unknown IP version must be dropped silently");

        session.close();
    }

    #[tokio::test]
    async fn loopback_foreign_dst_dropped() {
        let mut session = loopback_session(ServerBehavior::InjectForeignThenEcho).await;
        let _ = negotiate_addresses(&mut session).await.expect("negotiate");

        let packet = udp_v4_packet(
            Ipv4Addr::new(198, 18, 0, 10),
            Ipv4Addr::new(198, 18, 0, 10),
            64,
            b"valid",
        );
        let r = session.send_packet(&packet).await.expect("send");
        assert!(r.is_none(), "normal packet must not yield ICMP");

        // 外来包（dst 8.8.8.8 未分配）必须被吞，只回声 valid。
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet");
        assert_eq!(&got[20 + 8..], b"valid", "first received must be the echoed valid packet");

        let absent = tokio::time::timeout(Duration::from_millis(300), session.recv_packet()).await;
        assert!(absent.is_err(), "foreign-dst packet must be dropped, not delivered");
        session.close();
    }

    #[tokio::test]
    async fn oversize_packet_composes_icmp_ptb() {
        let mut session = loopback_session(ServerBehavior::Echo).await;
        let _ = negotiate_addresses(&mut session).await.expect("negotiate");
        assert_eq!(
            session.max_packet_size(),
            MAX_CAPSULE_PAYLOAD,
            "h2 max packet size = capsule limit (Go MaxPacketSize)"
        );

        // v4 超限 → ICMPv4 DestUnreachable(3)/code 4 + MTU 65535 + 原包头引用 + src/dst 互换。
        let big = udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(198, 18, 0, 10),
            64,
            &vec![0xAB; 70_000],
        );
        let icmp = session
            .send_packet(&big)
            .await
            .expect("send returns")
            .expect("oversize must yield ICMP PTB");
        assert_eq!(icmp[0], 0x45, "outer IPv4 header version/IHL");
        assert_eq!(icmp[8], 64, "outer TTL");
        assert_eq!(icmp[9], 1, "outer proto ICMP");
        assert_eq!(&icmp[12..16], &big[16..20], "src = original dst");
        assert_eq!(&icmp[16..20], &big[12..16], "dst = original src");
        let outer_total = u16::from_be_bytes([icmp[2], icmp[3]]) as usize;
        assert_eq!(outer_total, icmp.len());
        assert_eq!(icmp[20], 3, "ICMP type DestUnreachable");
        assert_eq!(icmp[21], 4, "ICMP code fragmentation needed");
        assert_eq!(&icmp[24..28], &65535u32.to_be_bytes(), "MTU field");
        assert_eq!(&icmp[28..28 + 28], &big[..28], "quoted original header+8");
        let recomputed = ipv4_header_checksum(&icmp[..20]);
        assert_eq!(recomputed.to_be_bytes(), &icmp[10..12], "outer header checksum");
        let mut verify = icmp[20..].to_vec();
        verify[2..4].copy_from_slice(&[0, 0]); // 校验和字段清零后再求和（Internet checksum 定义）
        let icmp_ck = internet_checksum(&verify);
        assert_eq!(icmp_ck.to_be_bytes(), &icmp[22..24], "icmp checksum");

        // v6 超限 → ICMPv6 PacketTooBig(2)/code 0。
        let big6 = udp_v6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            64,
            &vec![0xCD; 70_000],
        );
        let icmp6 = session
            .send_packet(&big6)
            .await
            .expect("send returns")
            .expect("oversize v6 must yield ICMP PTB");
        assert_eq!(icmp6[0], 6 << 4);
        assert_eq!(icmp6[6], 58, "outer next header ICMPv6");
        assert_eq!(&icmp6[8..24], &big6[24..40], "src = original dst");
        assert_eq!(&icmp6[24..40], &big6[8..24], "dst = original src");
        assert_eq!(icmp6[40], 2, "ICMPv6 type PacketTooBig");
        assert_eq!(icmp6[41], 0, "ICMPv6 code");
        assert_eq!(&icmp6[44..48], &65535u32.to_be_bytes(), "MTU field");
        session.close();
    }

    #[tokio::test]
    async fn route_advertisement_allows_route_dst() {
        let mut session = loopback_session(ServerBehavior::EchoWithRoutes).await;
        let _ = negotiate_addresses(&mut session).await.expect("negotiate");

        // dst 10.1.2.3 不在 assigned（198.18.0.10）内，但在通告路由 10/8 内 → 放行。
        let packet = udp_v4_packet(
            Ipv4Addr::new(198, 18, 0, 10),
            Ipv4Addr::new(10, 1, 2, 3),
            64,
            b"via-route",
        );
        let r = session.send_packet(&packet).await.expect("send");
        assert!(r.is_none(), "normal packet must not yield ICMP");
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet");
        assert_eq!(&got[20 + 8..], b"via-route");

        // dst 172.16.0.1 无分配也无路由 → 服务端回声包被客户端吞。
        let foreign = udp_v4_packet(
            Ipv4Addr::new(198, 18, 0, 10),
            Ipv4Addr::new(172, 16, 0, 1),
            64,
            b"no-route",
        );
        let r = session.send_packet(&foreign).await.expect("send");
        assert!(r.is_none(), "normal packet must not yield ICMP");
        let absent = tokio::time::timeout(Duration::from_millis(300), session.recv_packet()).await;
        assert!(absent.is_err(), "packet outside assigned+routes must be dropped");
        session.close();
    }

    // —— 纯函数单测（Go 语义锚点直译） ——
    #[test]
    fn local_addrs_skips_rejected_and_picks_first_per_family() {
        let assigned = vec![
            AssignedAddress { request_id: 1, prefix: ASSIGN_V4 }, // /32 全位长 → addr 原样
            AssignedAddress {
                request_id: 2,
                prefix: IpPrefix { addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), prefix_len: 32 },
            }, // 拒绝
            AssignedAddress { request_id: 3, prefix: ASSIGN_V6 },
            AssignedAddress {
                request_id: 4,
                prefix: IpPrefix {
                    addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
                    prefix_len: 128,
                },
            }, // 第二个 v6 忽略
            AssignedAddress {
                request_id: 0,
                prefix: IpPrefix { addr: IpAddr::V4(Ipv4Addr::new(198, 18, 1, 0)), prefix_len: 24 },
            }, // 非全位长 → 首主机地址
        ];
        let local = local_addrs(&assigned);
        assert_eq!(
            local,
            vec![
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ],
            "rejects skipped; first per family kept; /24 → first host addr"
        );
    }

    #[test]
    fn prefix_contains_matches_netip() {
        let p = IpPrefix { addr: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), prefix_len: 15 };
        assert!(prefix_contains(&p, IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
        assert!(!prefix_contains(&p, IpAddr::V4(Ipv4Addr::new(198, 20, 0, 0))));
        let zero = IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 0 };
        assert!(prefix_contains(&zero, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!prefix_contains(&zero, IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipv4_checksum_skips_field_and_matches_go() {
        // Go checksum.go：跳过字节偏移 10（校验和字段），其余 16 位反码求和取反。
        // 用 RFC 1071 例子交叉锚定：数据 0x0001 0xf203 0xf4f5 0xf6f7 → ck 0x220d。
        let sample = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let mut hdr = [0u8; 20];
        hdr[..8].copy_from_slice(&sample);
        assert_eq!(
            internet_checksum(&hdr),
            ipv4_header_checksum(&hdr),
            "zero cksum field: skip is a no-op"
        );
        assert_eq!(internet_checksum(&sample), 0x220d, "RFC 1071 example");
    }
}
