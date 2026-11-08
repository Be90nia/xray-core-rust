//! TUIC v5 UDP relay 客户端（quic uni-stream 模式 + native DATAGRAM 模式）。
//!
//! 提供 [`TuicUdpAssoc`]：客户端 UDP 关联句柄，分配 `assoc_id`，
//! 支持两种模式（TUIC v5 SPEC：Packet 只经 uni stream 或 datagram，
//! server 同模回包；bi stream 只承载 Connect）：
//! - **quic 模式**（[`TuicUdpAssoc::send_recv`]）：每个 UDP 包独占一条 uni stream；响应经
//!   per-connection `UniRespRouter` pump 配对
//! - **native 模式**（[`TuicUdpAssoc::send_recv_native`]）：QUIC DATAGRAM， 保留 UDP 不可靠语义
//!
//! ## 限制（ponytail）
//!
//! - quic 模式响应无分片（stream 可靠有序，frag_total 恒 1）
//! - native 模式：依赖 quinn DATAGRAM 支持（transport.datagram_receive_buffer_size 已设置）
//! - pkt_id 单调递增，溢出回绕

use std::{
    collections::HashMap,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU16, Ordering},
    },
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::time::Duration;
use xray_frame::{LogFacade, deadline::Budget};

use crate::{
    error::{Result, TuicError},
    protocol::{Packet, VERSION, address::Address, command::type_code, packet::MAX_PACKET_PAYLOAD},
};

/// uni 响应泵诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本项目工具
/// 链上 `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶三形态
/// 实测无效），迁移为唯一关红路径。域 = "tuic"，target `xray_frame::tuic` +
/// mask_secrets。只在泵关闭/响应未配对/帧解析错误分支发射；泵循环外取一次
/// 引用（坑约束⑫热路径零每包开销）。
static UDP_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("tuic", vec![]));

/// 默认 UDP 响应等待时长（mock server 等待 UDP echo）。
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(10);

/// per-connection native 模式收包信箱（键 = `assoc_id`）。
///
/// 共享一条 QUIC 连接时 `read_datagram` 是连接级单点：读方拿到**别的**
/// `assoc_id` 的包时转投信箱，属主下次读取先取信箱——否则两条并发 UDP 流
/// 互偷回包（Go sing-quic `handleUDPMessage` 按 `udpConnMap[sessionID]` 分派
/// 的无泵等价物）。
pub(crate) type DgramInbox =
    Arc<parking_lot::Mutex<HashMap<u16, std::collections::VecDeque<Packet>>>>;

/// 单 assoc 信箱积压上限（UDP 有损语义：超限丢最旧，读方永不被信箱阻塞）。
const DGRAM_INBOX_CAP: usize = 64;

/// TUIC 客户端 UDP 关联句柄。
///
/// 由 [`TuicClient::dial_udp`](crate::client::TuicClient::dial_udp) 创建，
/// 持有 QUIC 连接与 assoc_id、pkt_id 计数器。
#[derive(Clone)]
pub struct TuicUdpAssoc {
    conn: quinn::Connection,
    assoc_id: u16,
    pkt_id: Arc<AtomicU16>,
    /// quic 模式响应路由（per-connection uni-stream pump，见 [`UniRespRouter`]）。
    router: UniRespRouter,
    /// 分片重组器（native 模式接收方向，spec FRAG_TOTAL>1 时按 pkt_id 缓存拼接）。
    assembler: Arc<parking_lot::Mutex<crate::protocol::packet::FragmentAssembler>>,
    /// per-connection native 收包信箱（同连接各 assoc 共用；见 [`DgramInbox`]）。
    inbox: DgramInbox,
}

/// quic 模式（uni-stream）响应路由器。
///
/// SPEC：客户端每包 open_uni 发 Packet；server 每个响应**新开一条** uni stream
/// 回包。本 router spawn 单个 pump task 全局 `accept_uni`，按帧内 `assoc_id`
/// 把响应交给该 UDP 会话当前等待中的请求。
///
/// **配对键 = `assoc_id`（UDP 会话），不是 `(assoc_id, pkt_id)`**
/// （bd j7de2 F3）：TUIC v5 spec 定义 `PKT_ID` 为「UDP 包 ID」，用途是**分片
/// 重组**（同一 UDP 包的多片共享 PKT_ID），**不是**请求-响应配对键——server
/// 回包用自己的 PKT_ID 编号（第三方实现不 echo 请求的 PKT_ID）。修前按
/// `(assoc,pkt)` 严格配对 → 第三方对端的回包全部落空（`unmatched udp resp`）
/// → 请求超时。同 assoc 内按到达顺序 FIFO 交付（UDP 语义本就是尽力而为）。
///
/// ponytail: quic 模式响应无分片（stream 可靠有序，frag_total 恒 1），无需重组器。
#[derive(Clone)]
pub(crate) struct UniRespRouter {
    waiters: Waiters,
}

/// assoc_id → 等待者 FIFO 队列（每项 = 一个待应答槽；`None` = 已超时废弃）。
type WaiterSlot = Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<Packet>>>>;

/// assoc_id → 等待者队列共享句柄。
type Waiters = Arc<parking_lot::Mutex<HashMap<u16, std::collections::VecDeque<WaiterSlot>>>>;

impl UniRespRouter {
    /// 在连接建立后调用：spawn per-connection 响应 pump（连接关闭自动退出）。
    pub(crate) fn spawn(conn: quinn::Connection) -> Self {
        let waiters: Waiters = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let w = Arc::clone(&waiters);
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（bd kwevg · §3.5.6）：热路径豁免（B6 t975）：每帧泵——per-connection uni-stream 响应路由（accept_uni 循环），数据面热路径零改动（坑约束 12）；托管接线归 P1 插件装配；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
        )]
        tokio::spawn(async move {
            let log = &*UDP_LOG;
            loop {
                let mut uni = match conn.accept_uni().await {
                    Ok(u) => u,
                    Err(e) => {
                        log.debug(format!("tuic uni resp router closed: {e:?}"));
                        break;
                    },
                };
                match read_response_packet(&mut uni).await {
                    Ok(pkt) => {
                        let mut w = w.lock();
                        let Some(queue) = w.get_mut(&pkt.assoc_id) else {
                            log.debug(format!(
                                "tuic: unmatched udp resp assoc={} pkt={}",
                                pkt.assoc_id, pkt.pkt_id
                            ));
                            continue;
                        };
                        // FIFO 交付：跳过已超时（槽空）或已断开（send 失败）的等待者
                        let mut delivered = false;
                        while let Some(slot) = queue.pop_front() {
                            let tx = slot.lock().take();
                            let Some(tx) = tx else { continue };
                            if tx.send(pkt.clone()).is_ok() {
                                delivered = true;
                                break;
                            }
                        }
                        if queue.is_empty() {
                            w.remove(&pkt.assoc_id);
                        }
                        if !delivered {
                            log.debug(format!(
                                "tuic: udp resp assoc={} pkt={} had no live waiter",
                                pkt.assoc_id, pkt.pkt_id
                            ));
                        }
                    },
                    Err(e) => log.debug(format!("tuic: uni resp stream parse: {e:?}")),
                }
            }
        });
        Self { waiters }
    }

    /// open_uni 发送 Packet 并等待该 `assoc_id` 会话的下一个响应。
    async fn send_and_wait(
        &self,
        conn: &quinn::Connection,
        pkt: &Packet,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let slot: WaiterSlot = Arc::new(parking_lot::Mutex::new(Some(tx)));
        self.waiters.lock().entry(pkt.assoc_id).or_default().push_back(Arc::clone(&slot));
        let recv = async {
            let mut uni = conn.open_uni().await?;
            // 帧 = VER+TYPE + 头 + 载荷，分两段写：uni stream 是字节流，
            // wire 字节序列与「整帧一次写」完全一致，但省掉
            // 「载荷先拥有化成 Bytes、再拷进整帧缓冲」两遍 memcpy。
            let mut hdr = BytesMut::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + pkt.addr.encoded_len());
            hdr.put_u8(VERSION);
            hdr.put_u8(type_code::PACKET);
            pkt.write_header(&mut hdr, payload.len())?;
            uni.write_all(&hdr).await?;
            uni.write_all(payload).await?;
            let _ = uni.finish();
            rx.await.map_err(|_| TuicError::UnexpectedEof("udp resp router dropped"))
        };
        match Budget::tokio().deadline(timeout).timeout(recv).await {
            // Bytes → Vec：read_payload 产的 VEC-kind Bytes 唯一引用时零拷贝归还
            Ok(Ok(resp)) => Ok(resp.data.into()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // 超时：清空本槽（sender drop → 后续响应跳过本槽，不会错投）
                *slot.lock() = None;
                Err(TuicError::UdpTimeout(timeout))
            },
        }
    }
}

/// 将 Packet 帧序列化为 wire 格式（VER + TYPE + payload）——client/server 共用
/// （server 响应侧分片后逐片编码，线格式单一来源）。
///
/// # Errors
/// 透传 [`Packet::write_payload`]（`data.len()` 超 u16 上限 → `PacketTooLarge`）。
pub(crate) fn encode_packet_frame(pkt: &Packet) -> Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(pkt.encoded_len() + 2);
    buf.put_u8(VERSION);
    buf.put_u8(type_code::PACKET);
    pkt.write_payload(&mut buf)?;
    Ok(buf)
}

/// native datagram 的分片数（本轮分片规则单一来源）。
///
/// 每片长度由调用方按 `frag_payload` 连续切分（末片可能不足）；单片返回 1。
/// 总负载上界 = [`MAX_UDP_PAYLOAD`]。
fn native_frag_total(data_len: usize, frag_payload: usize) -> Result<u8> {
    if data_len <= frag_payload {
        return Ok(1);
    }
    if data_len > crate::protocol::packet::MAX_UDP_PAYLOAD {
        return Err(TuicError::PacketTooLarge(data_len));
    }
    u8::try_from(data_len.div_ceil(frag_payload)).map_err(|_| TuicError::PacketTooLarge(data_len))
}

/// native datagram 帧编码（载荷借用 → 不经拥有化中转）。
///
/// 与 `build_native_fragments` + [`encode_packet_frame`] 的组合产出的字节
/// 逐字节一致（同一分片规则 + 同一头布局）；差别仅在载荷不拥有化
/// （省每包 1 遍 `copy_from_slice`）。
pub(crate) fn encode_native_frames(
    assoc_id: u16,
    pkt_id: u16,
    target: &Address,
    data: &[u8],
    frag_payload: usize,
) -> Result<Vec<BytesMut>> {
    let frag_total = native_frag_total(data.len(), frag_payload)?;
    let mut out = Vec::with_capacity(frag_total as usize);
    let mut off = 0usize;
    for i in 0..frag_total {
        // 空载荷也需产出一帧（SIZE=0），故按剩余长度切而不走 chunks
        let len = (data.len() - off).min(frag_payload);
        let chunk = &data[off..off + len];
        off += len;
        // spec：仅首片携带目标 Address（后续片 addr=None → 0xff）
        let addr = if i == 0 { target.clone() } else { Address::None };
        let mut buf = BytesMut::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + addr.encoded_len() + len);
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        let meta = Packet { assoc_id, pkt_id, frag_total, frag_id: i, addr, data: Bytes::new() };
        meta.write_payload_with(&mut buf, chunk)?;
        out.push(buf);
    }
    Ok(out)
}

impl TuicUdpAssoc {
    /// 由 [`TuicClient`](crate::client::TuicClient) 构造。
    pub(crate) fn new(
        conn: quinn::Connection,
        assoc_id: u16,
        router: UniRespRouter,
        inbox: DgramInbox,
    ) -> Self {
        Self {
            conn,
            assoc_id,
            pkt_id: Arc::new(AtomicU16::new(0)),
            router,
            assembler: Arc::new(parking_lot::Mutex::new(
                crate::protocol::packet::FragmentAssembler::new(),
            )),
            inbox,
        }
    }

    /// 当前关联 ID。
    #[must_use]
    pub fn assoc_id(&self) -> u16 {
        self.assoc_id
    }

    /// 发送一个 UDP 包并等待响应（quic 模式，uni-stream）。
    ///
    /// 流程（TUIC v5 SPEC uni-stream 模型）：
    /// 1. open_uni 写入 Packet 帧（VER + TYPE + ASSOC + PKT + FRAG + SIZE + ADDR + DATA）
    /// 2. finish() 通知 server 写方向结束
    /// 3. 响应经 `UniRespRouter` pump 从 server 新开的 uni stream 配对收取
    ///
    /// `timeout` 为 None 时使用 `DEFAULT_UDP_TIMEOUT`。
    ///
    /// # Errors
    ///
    /// 见 [`TuicError`]；典型：QUIC 流错误、超时、响应解析失败。
    pub async fn send_recv(
        &self,
        target: Address,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        // 载荷不进 Packet（保持借用）：Packet 只承载帧头，SIZE 由 payload.len() 给出
        let pkt = Packet::new(self.assoc_id, pkt_id, target, Bytes::new());
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        self.router.send_and_wait(&self.conn, &pkt, data, to).await
    }

    /// 计算单 datagram 可容纳的 UDP 负载大小（帧头开销之外）。
    fn native_frag_payload(&self, addr: &Address) -> Option<usize> {
        self.conn.max_datagram_size().map(|max| max.saturating_sub(10 + addr.encoded_len()).max(1))
    }

    /// 发送 Packet 帧（单包或按 frag 分片），DATA 超过单 datagram 容量时
    /// 按 TUIC v5 spec 切成 FRAG_TOTAL 片（同 pkt_id，FRAG_ID 0-based）。
    async fn send_native(&self, target: &Address, data: &[u8], pkt_id: u16) -> Result<()> {
        let Some(frag_payload) = self.native_frag_payload(target) else {
            return Err(TuicError::ProtocolParse("native datagram mode not negotiated".into()));
        };
        // 载荷全程借用（不拥有化）：分片布局与 owned 路径同一函数产出，
        // wire 字节逐字节一致（见 encode_native_frames 文档）。
        for frame in encode_native_frames(self.assoc_id, pkt_id, target, data, frag_payload)? {
            self.conn.send_datagram(frame.freeze()).map_err(TuicError::QuinnSendDatagram)?;
        }
        Ok(())
    }

    /// 发送一个 UDP 包并等待响应（native DATAGRAM 模式）。
    ///
    /// 流程：
    /// 1. DATA ≤ 单 datagram 容量：单片直发（FRAG_TOTAL=1） 超过：按 TUIC v5 spec 切 FRAG_TOTAL
    ///    片（同 pkt_id，FRAG_ID 0-based， 非首片 addr=None/0xff）
    /// 2. 通过 [`quinn::Connection::send_datagram`] 发送
    /// 3. 循环 [`quinn::Connection::read_datagram`] 收响应，FRAG_TOTAL>1 的 分片经
    ///    `FragmentAssembler` 拼接（票 ao93：大 DNS/WireGuard 包不再丢）； 连接被多条 UDP
    ///    流共享时按帧内 `assoc_id` 分派（异己包转投 `DgramInbox`，不会互偷回包）
    ///
    /// `timeout` 为 None 时使用 `DEFAULT_UDP_TIMEOUT`。
    ///
    /// # Errors
    ///
    /// 见 [`TuicError`]；典型：QUIC datagram 不支持、超时、响应解析失败。
    pub async fn send_recv_native(
        &self,
        target: Address,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        self.send_native(&target, data, pkt_id).await?;

        // 循环收响应 datagram，分片收齐即返回（同一超时窗口）
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        loop {
            // 先取本 assoc 信箱（别的流读到的、本流的回包已在里面）
            let pkt = match self.take_inbox_packet() {
                Some(pkt) => pkt,
                None => {
                    let resp = Budget::tokio()
                        .deadline(to)
                        .timeout(self.conn.read_datagram())
                        .await
                        .map_err(|_| TuicError::UdpTimeout(to))?
                        .map_err(TuicError::Quinn)?;
                    let mut cursor = &resp[..];
                    let type_byte = crate::protocol::parse_header(&mut cursor)?;
                    if type_byte != type_code::PACKET {
                        return Err(TuicError::UnknownCommandType(type_byte));
                    }
                    let pkt = Packet::read_payload(&mut cursor)?;
                    if pkt.assoc_id != self.assoc_id {
                        // 共享连接上别的 UDP 流的回包：转投其信箱后继续等本流
                        self.stash_foreign_packet(pkt);
                        continue;
                    }
                    pkt
                },
            };
            let complete = self.assembler.lock().feed(pkt)?;
            if let Some(full) = complete {
                // Bytes → Vec：assembler 拼接产的 VEC-kind 唯一引用时零拷贝归还
                return Ok(full.data.into());
            }
        }
    }

    /// 取本 assoc 信箱里的下一个包（空则顺手清掉条目）。
    fn take_inbox_packet(&self) -> Option<Packet> {
        let mut inbox = self.inbox.lock();
        let queue = inbox.get_mut(&self.assoc_id)?;
        let pkt = queue.pop_front();
        if queue.is_empty() {
            inbox.remove(&self.assoc_id);
        }
        pkt
    }

    /// 把别的 assoc 的回包转投其信箱（超上限丢最旧，UDP 有损语义）。
    fn stash_foreign_packet(&self, pkt: Packet) {
        let mut inbox = self.inbox.lock();
        let queue = inbox.entry(pkt.assoc_id).or_default();
        if queue.len() >= DGRAM_INBOX_CAP {
            queue.pop_front();
        }
        queue.push_back(pkt);
    }

    /// 检查连接是否支持 DATAGRAM（native 模式可用性）。
    #[must_use]
    pub fn datagram_supported(&self) -> bool {
        // transport config 已设置 datagram_receive_buffer_size 且 ALPN
        // 协商成功即表示支持；精确容量经 `max_datagram_size()` 探测。
        self.conn.max_datagram_size().is_some()
    }
}

/// 按 native datagram 容量切分 Packet 帧（纯函数，可单测；server 响应侧复用）。
///
/// spec（TUIC v5）：单包直接 FRAG_TOTAL=1；超长切 FRAG_TOTAL 片，同 pkt_id、
/// FRAG_ID 0-based，**仅首片携带目标 Address**，后续片 addr=None（wire 编码
/// `0xff`）——接收方按首片地址路由。分片为 `Bytes::slice` 零拷贝视图。
///
/// 总负载上界 = [`MAX_UDP_PAYLOAD`]（UDP 数据报物理上限）；每片长度仍受
/// `frag_payload`（单 datagram 容量）约束。
pub(crate) fn build_native_fragments(
    assoc_id: u16,
    pkt_id: u16,
    target: &Address,
    data: Bytes,
    frag_payload: usize,
) -> Result<Vec<Packet>> {
    let frag_total = native_frag_total(data.len(), frag_payload)?;
    if frag_total == 1 {
        return Ok(vec![Packet::new(assoc_id, pkt_id, target.clone(), data)]);
    }
    let mut frags = Vec::with_capacity(frag_total as usize);
    for (i, chunk) in data.chunks(frag_payload).enumerate() {
        frags.push(Packet {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id: i as u8,
            // spec：非首片不带目标地址（Address::None → 0xff）
            addr: if i == 0 { target.clone() } else { Address::None },
            // slice 借用 data 产出共享视图，零拷贝；data 在循环结束后 drop
            data: data.slice_ref(chunk),
        });
    }
    Ok(frags)
}

/// 从 uni stream 读出一个完整 Packet 帧（含 VER+TYPE 头）。
///
/// QUIC 流允许单次 read 部分返回（票 hva9：响应跨 QUIC 包边界时
/// 旧单次 read 截断帧），此处按帧布局 `read_exact` 逐段消费：
/// `VER(1)+TYPE(1) | ASSOC(2)+PKT(2)+FRAG_TOTAL(1)+FRAG_ID(1)+SIZE(2) |
///  ADDR(变长) | DATA(SIZE)`。
///
/// 客户端（[`UniRespRouter`]）使用；服务端 uni 分支头已由
/// [`crate::server::read_uni_frame`] 消费，直接用 [`read_packet_payload`]。
pub(crate) async fn read_response_packet(recv: &mut quinn::RecvStream) -> Result<Packet> {
    let mut vt = [0u8; 2];
    recv.read_exact(&mut vt).await.map_err(quinn_read_exact_err)?;
    let mut vh: &[u8] = &vt;
    let type_byte = crate::protocol::parse_header(&mut vh)?;
    if type_byte != type_code::PACKET {
        return Err(TuicError::UnknownCommandType(type_byte));
    }
    read_packet_payload(recv).await
}

/// 读 Packet 负载（VER+TYPE 已被调用方消费）：ASSOC..DATA 逐段 `read_exact`。
pub(crate) async fn read_packet_payload(recv: &mut quinn::RecvStream) -> Result<Packet> {
    let mut fixed = [0u8; 8];
    recv.read_exact(&mut fixed).await.map_err(quinn_read_exact_err)?;
    let mut fb = &fixed[..];
    let assoc_id = fb.get_u16();
    let pkt_id = fb.get_u16();
    let frag_total = fb.get_u8();
    let frag_id = fb.get_u8();
    let size = fb.get_u16() as usize;
    if size > MAX_PACKET_PAYLOAD {
        return Err(TuicError::PacketTooLarge(size));
    }
    // ADDR：ATYP(1) + 体（布局见 protocol/address.rs）
    let mut atyp_b = [0u8; 1];
    recv.read_exact(&mut atyp_b).await.map_err(quinn_read_exact_err)?;
    let addr = match atyp_b[0] {
        // None 地址只有 1 字节（0xff）：spec「端口在域名/IP 之后」——无域名/IP
        // 即无端口（参考实现 tuic 5.0.0-pre-alpha6 / 第三方 sing-box 同款）。
        0xff => Address::None,
        0x00 => {
            let mut len_b = [0u8; 1];
            recv.read_exact(&mut len_b).await.map_err(quinn_read_exact_err)?;
            let mut name = vec![0u8; u32::from(len_b[0]) as usize];
            recv.read_exact(&mut name).await.map_err(quinn_read_exact_err)?;
            let mut port = [0u8; 2];
            recv.read_exact(&mut port).await.map_err(quinn_read_exact_err)?;
            Address::Domain(String::from_utf8_lossy(&name).into_owned(), u16::from_be_bytes(port))
        },
        0x01 => {
            let mut body = [0u8; 4 + 2];
            recv.read_exact(&mut body).await.map_err(quinn_read_exact_err)?;
            Address::Ipv4(
                std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                u16::from_be_bytes([body[4], body[5]]),
            )
        },
        0x02 => {
            let mut body = [0u8; 16 + 2];
            recv.read_exact(&mut body).await.map_err(quinn_read_exact_err)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            Address::Ipv6(
                std::net::Ipv6Addr::from(octets),
                u16::from_be_bytes([body[16], body[17]]),
            )
        },
        _ => return Err(TuicError::InvalidAddress("unknown atyp")),
    };
    // DATA（Vec → Bytes 零拷贝所有权转移）
    let mut data = vec![0u8; size];
    recv.read_exact(&mut data).await.map_err(quinn_read_exact_err)?;
    Ok(Packet { assoc_id, pkt_id, frag_total, frag_id, addr, data: Bytes::from(data) })
}

/// `ReadExactError` → `TuicError`（EOF 视为流正常关闭）。
pub(crate) fn quinn_read_exact_err(e: quinn::ReadExactError) -> TuicError {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => {
            TuicError::UnexpectedEof("udp response stream closed")
        },
        quinn::ReadExactError::ReadError(re) => TuicError::QuinnRead(re),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// 票 ieik①：native 分片仅首片带目标地址，非首片 addr=None（wire 0xff）。
    #[test]
    fn native_fragments_only_first_carries_address() {
        let target = Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let data = Bytes::from(vec![7u8; 100]);
        let frags = build_native_fragments(0x1234, 0x5678, &target, data, 30).expect("fragments");
        assert_eq!(frags.len(), 4, "ceil(100/30) = 4 片");
        for (i, f) in frags.iter().enumerate() {
            assert_eq!(f.assoc_id, 0x1234);
            assert_eq!(f.pkt_id, 0x5678);
            assert_eq!(f.frag_total, 4);
            assert_eq!(f.frag_id, i as u8);
        }
        // 首片带地址；其余片 addr=None
        assert_eq!(frags[0].addr, target);
        assert_eq!(frags[1].addr, Address::None);
        assert_eq!(frags[2].addr, Address::None);
        assert_eq!(frags[3].addr, Address::None);
        // Address::None 的 wire 首字节 = 0xff（票验收：分片 addr=0xff）
        let mut buf = Vec::new();
        frags[1].addr.write_to(&mut buf);
        assert_eq!(buf[0], 0xff);
    }

    /// 单包 ≤ frag_payload 时单片直发（FRAG_TOTAL=1，地址保留）。
    #[test]
    fn native_single_packet_keeps_address() {
        let target = Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let frags = build_native_fragments(1, 2, &target, Bytes::from_static(b"hello"), 64)
            .expect("fragments");
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].frag_total, 1);
        assert_eq!(frags[0].frag_id, 0);
        assert_eq!(frags[0].addr, target);
        assert_eq!(&frags[0].data[..], b"hello");
    }

    /// bd j7de2 F4 边界：单 datagram 容量 ±1 处的分片形态（阈值内 1 片、
    /// 阈值+1 切 2 片），且分片可被对端重组器还原为原载荷。
    #[test]
    fn native_fragment_threshold_boundary() {
        let target = Address::Ipv4(Ipv4Addr::new(192, 0, 2, 9), 53);
        let cap = 64usize;

        // 阈值 -1：单片
        let one = build_native_fragments(1, 1, &target, Bytes::from(vec![1u8; cap - 1]), cap)
            .expect("fragments");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].frag_total, 1);

        // 阈值：单片（≤ 判定）
        let at = build_native_fragments(1, 2, &target, Bytes::from(vec![2u8; cap]), cap)
            .expect("fragments");
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].frag_total, 1);

        // 阈值 +1：切 2 片
        let two = build_native_fragments(1, 3, &target, Bytes::from(vec![3u8; cap + 1]), cap)
            .expect("fragments");
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].frag_total, 2);
        assert_eq!(two[0].frag_id, 0);
        assert_eq!(two[1].frag_id, 1);
        // 后续片不带地址（spec：0xff None，仅 1 字节）
        assert_eq!(two[1].addr, Address::None);
        assert_eq!(two[1].addr.encoded_len(), 1);

        // 对端重组器还原（spec：按 frag_id 升序拼接）
        let mut asm = crate::protocol::packet::FragmentAssembler::new();
        let mut complete = None;
        for frag in two {
            complete = asm.feed(frag).expect("assemble");
        }
        let done = complete.expect("两片到齐必须产出完整包");
        assert_eq!(done.data.len(), cap + 1);
        assert!(done.data.iter().all(|b| *b == 3));
        assert_eq!(done.addr, target);
    }

    /// 借用载荷路径（`encode_native_frames`）与拥有化路径
    /// （`build_native_fragments` + `encode_packet_frame`）产出的 wire 字节逐字节一致
    /// —— 含空载荷（SIZE=0）与分片阈值 ±1 边界。
    #[test]
    fn encode_native_frames_matches_owned_path_bytes() {
        let target = Address::Ipv4(Ipv4Addr::new(203, 0, 113, 7), 5353);
        let cap = 64usize;
        for len in [0usize, 1, cap - 1, cap, cap + 1, 200] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let borrowed =
                encode_native_frames(9, 11, &target, &payload, cap).expect("borrowed encode");
            let owned: Vec<BytesMut> =
                build_native_fragments(9, 11, &target, Bytes::from(payload.clone()), cap)
                    .expect("fragments")
                    .iter()
                    .map(|f| encode_packet_frame(f).expect("owned encode"))
                    .collect();
            assert_eq!(borrowed.len(), owned.len(), "len={len} 帧数一致");
            for (i, (b, o)) in borrowed.iter().zip(owned.iter()).enumerate() {
                assert_eq!(b.as_ref(), o.as_ref(), "len={len} frag={i} 字节一致");
            }
            assert!(!borrowed.is_empty(), "len={len} 至少产出一帧");
        }
    }
}
