//! 中央 UDP dispatch session（bd b2e）。
//!
//! 对应 Go `transport/internet/udp/dispatcher.go`：每个 inbound UDP 会话
//! 创建一个 [`UdpDispatchSession`]，所有数据报经 [`DispatchHandler::dispatch`]
//! 走 routing 规则选择 outbound，不再直连 raw socket。
//!
//! ## Link 语义（与 freedom outbound 的 XUDP 帧约定一致）
//!
//! - `link.reader`：XUDP 帧流（session 写入请求帧，outbound 拆帧发送）
//! - `link.writer`：XUDP 帧流（outbound 装帧写入响应，session 拆帧收回包）
//!
//! ## cone NAT
//!
//! 单 session 只建立一个 dispatch link（首包目标决定 routing 与 outbound
//! default target）；后续帧在帧头携带各自真实目标，由 outbound 侧（如
//! freedom）从同一 socket 发出——天然 cone NAT，与 Go `udp.Dispatcher`
//! 单 connEntry 模型一致。
//!
//! ## ponytail: 无内置空闲超时
//!
//! Go `CancelAfterInactivity(1min)` 的会话淘汰由调用方生命周期管理
//! （SOCKS relay task 随 TCP 控制连接 abort；session drop → duplex 关闭 →
//! outbound relay EOF 退出）。若后续出现长生命周期无控制连接的 UDP 入站
//! （tun/fakeDNS），再补 idle deadline。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use xray_buf::{
    buffer::Buffer,
    io::{Reader, Writer, new_reader, new_writer},
    multi::MultiBuffer,
};
use xray_common::net::destination::Destination;
use xray_transport::{connection::Connection, link::Link};
use xray_xudp::packet::{FrameMetadata, PacketError, parse_packet_slice_at};

use crate::DispatchHandler;

/// duplex 单方向缓冲上限（单包 65535 + 帧头，留多包裕量）。
const DUPLEX_BUF: usize = 256 * 1024;

/// 单个 UDP 数据报上限。
const MAX_DATAGRAM: usize = 65535;

/// 响应读缓冲（会话期常驻）。取池化 Buffer 档 8KiB 而非 64KiB：帧解析走
/// `accum` 增量重组，大报文天然分多次读入——每会话常驻从 64KiB 降到 8KiB
/// （bd tini5：1200 会话 × 64KiB ≈ 65MB 常驻）。
const RECV_BUF: usize = 8 * 1024;

/// 进程级并发 UDP dispatch 会话上限（bd tini5：会话无上限即内存无上限）。
/// 4096 × (8KiB 读缓冲 + duplex 2×256KiB 上限) 属可控量级；超限 fail-visible
/// （调用方拿 io 错误而不是静默丢包）。
const MAX_UDP_SESSIONS: usize = 4096;

/// 当前存活会话数（`Inner::drop` 归还）。
static LIVE_SESSIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 已建立的 dispatch link 状态。
struct Inner {
    /// 首包目标（决定 routing 与 outbound default target）。
    dest: Destination,
    /// inbound → outbound 请求帧流写端。
    req: DuplexStream,
    /// outbound → inbound 响应帧流读端。
    resp: DuplexStream,
    /// 响应方向半帧累积缓冲。
    accum: Vec<u8>,
    /// 响应读缓冲（会话期常驻池化块：栈数组会把本 future 撑到 64KiB，构造期在调用方
    /// poll 栈上留同尺寸临时量 → 击穿 2MiB 线程栈；常驻省掉每包一次分配，池化再省掉
    /// 每会话一次 `vec![0u8; RECV_BUF]` 分配+清零，会话结束 `Drop` 回池复用）。
    buf: Buffer,
    /// 请求帧序列化 scratch（清空复用容量，免每包一次 `Vec` 分配）。
    frame: Vec<u8>,
    /// 首帧 GlobalID（随机 8 字节，对应 Go xudp）。
    global_id: [u8; 8],
    /// 是否已发送 New 帧。
    new_sent: bool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        LIVE_SESSIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// UDP dispatch 会话：inbound 包流 ↔ dispatcher XUDP 帧 Link 桥。
///
/// 用法（inbound UDP relay 循环）：
/// 1. `send_packet(&dest, payload)` 转发客户端数据报（首包懒建立 dispatch link）
/// 2. `recv_packet()` 收取 outbound 响应数据报（来源, payload），写回客户端
pub struct UdpDispatchSession {
    dispatcher: Arc<dyn DispatchHandler>,
    inner: Option<Inner>,
    /// §3.5.6 ①类托管：dispatch link 任务归本会话自持 scope——会话 Drop =
    /// 组件终，scope 兜底 abort 拆任务（无双份账本）。
    scope: xray_frame::compat::ManagedScope,
    /// 入站 access 上下文（bd kol4a）：`establish` 时经
    /// [`DispatchHandler::dispatch_with_access`] 下传——生产链终点
    /// `MuxBridge::dispatch_with_access` 按它派生 XUDP GlobalID（cone 语义，
    /// Go `xudp.GetGlobalID`）。`None` = 无源 dispatch（等价旧行为）。
    ///
    /// `Mutex` 而非裸 `Option`：socks ASSOCIATE 的入站源是**首个数据报的源
    /// 地址**（Go `handleUDPPayload` 的 `conn.RemoteAddr()`），建会话时未知
    /// → 收包后才装填（[`Self::set_access`]），此时 `establish` 尚未触发
    /// （首包 `send_packet` 才建 link），时序安全。
    access: parking_lot::Mutex<Option<crate::default::AccessContext>>,
}

impl UdpDispatchSession {
    /// 创建会话。`dispatcher` 为生产路由 handler 或任意支持 UDP 目标的
    /// [`DispatchHandler`]（outbound 侧须按 XUDP 帧约定消费 link，如 freedom）。
    pub fn new(dispatcher: Arc<dyn DispatchHandler>) -> Self {
        Self {
            dispatcher,
            inner: None,
            access: parking_lot::Mutex::new(None),
            scope: xray_frame::compat::ManagedScope::new("udp-dispatch"),
        }
    }

    /// 携带入站 access 上下文（客户端源地址 + 入站协议名）。UDP relay 调用方
    /// 在建会话前链式调用；字段语义见 [`crate::default::AccessContext`]。
    #[must_use]
    pub fn with_access(self, access: crate::default::AccessContext) -> Self {
        self.set_access(access);
        self
    }

    /// 后置装填入站 access 上下文（建会话时源地址未知的入口用，如 socks
    /// ASSOCIATE）。`establish` 会取走它，故必须在首包 `send_packet` 之前调用。
    pub fn set_access(&self, access: crate::default::AccessContext) {
        *self.access.lock() = Some(access);
    }

    /// 发送一个 UDP 数据报。
    ///
    /// 首包懒建立 dispatch link：两条 duplex 管道 + 后台 `dispatch(dest, link)`。
    /// 首帧 XUDP `New`（含随机 GlobalID），后续 `Keep`（帧头带各自真实目标，
    /// 由 outbound per-packet 路由）。
    pub async fn send_packet(&mut self, dest: &Destination, payload: &[u8]) -> io::Result<()> {
        // 零长/超长静默跳过 = Go xudp PacketWriter 同款（xudp.go:100
        // `length == 0 || length+666 > buf.Size → continue`，iq1o 核对）。
        // 空 datagram 不进 dispatch link，响应侧照发语义不受影响。
        if payload.is_empty() || payload.len() > MAX_DATAGRAM {
            return Ok(());
        }
        if self.inner.is_none() {
            self.establish(dest.clone())?;
        }
        let inner = self.inner.as_mut().expect("established above");

        let meta = if inner.new_sent {
            FrameMetadata::keep_udp(dest.address().clone(), dest.port())
        } else {
            inner.new_sent = true;
            FrameMetadata::new_udp(dest.address().clone(), dest.port(), inner.global_id)
        };
        // 帧序列化进会话常驻 scratch（clear 复用容量，免每包一次分配）。
        // bd 1fm1l W5：`write_bytes_into` 直写替代 `write_to`——后者走
        // `to_bytes()`，每包多「临时 Vec + 32B 地址暂存 Buffer」两次分配；
        // frame 此时为空，clear 语义等价（`Vec` 的 write_all 不可能失败，
        // 原 map_err 是死分支）。
        let Inner { frame, req, .. } = inner;
        meta.write_bytes_into(frame);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        // 帧头与载荷分两次写（bd x6fkn）：duplex 是字节流，读侧按 `accum` 增量
        // 重组，语义与单次写等价；省掉「payload → frame」整载拷贝，与 Go
        // xudp `PacketWriter` 的单拷贝（MergeBytes 后一次写）同档。
        // ponytail: 极端栈/背压下两次 write_all 之间可被读侧观察，无害（流语义）。
        req.write_all(frame).await?;
        req.write_all(payload).await
    }

    /// 接收一个响应数据报 `(来源, payload)`。
    ///
    /// `Ok(None)`：outbound 已关闭（会话结束）。未建立 link（尚未发包）时
    /// 永久挂起——供 `select!` 与 inbound socket 读竞争。
    pub async fn recv_packet(&mut self) -> io::Result<Option<(Destination, Vec<u8>)>> {
        let inner = match self.inner.as_mut() {
            Some(i) => i,
            None => {
                std::future::pending::<()>().await;
                unreachable!()
            },
        };
        loop {
            if !inner.accum.is_empty() {
                // 借用式就地解析（bd lppdz）：不再为帧头/meta 落中间 Vec（旧的
                // Cursor + PacketReader 路径每帧 2 次分配 + 2 次拷贝）。
                // 载荷仍需**拥有型 Vec** 返回给调用方（本 API 契约：10+ 调用方
                // 依赖 `(Destination, Vec<u8>)`，含 xray-core 红线文件）→ 载荷
                // 一次分配 + 一次拷贝（残留 1 分配，报告登记）。
                let parsed = match parse_packet_slice_at(&inner.accum[..]) {
                    (Ok(p), _) => p,
                    (Err(PacketError::Io(e)), _)
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        // 半帧：等更多字节
                        None
                    },
                    (Err(e), consumed) => {
                        // qyn8：协议解析错误先 drain 已消费的坏帧字节再报错。
                        // 解析错误发生时至少已消费 2B 长度头，不 drain
                        // 则坏帧永久滞留 accum，容忍型调用方 continue 即在同一
                        // 字节上无限 Err（同步忙旋 100% CPU）。传输层错误不经
                        // 此路径（resp.read 的 io Err 由下方 `?` 直接传播）。
                        inner.accum.drain(..consumed.min(inner.accum.len()));
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        ));
                    },
                };
                if let Some(pkt) = parsed {
                    let consumed = pkt.consumed;
                    // 残留 1 分配 + 1 拷贝（bd lppdz 登记）：本 API 的返回契约是
                    // `(Destination, Vec<u8>)`，载荷必须脱开 `accum` 独立存活
                    // （借用与 `accum.drain` 互斥）→ 拥有型 Vec 无法零拷贝。要归零
                    // 需改 recv_packet 签名（10+ 调用方，含 xray-core
                    // inbound/outbound 红线文件），不属本票。
                    #[allow(
                        clippy::disallowed_methods,
                        reason = "bd lppdz 残留：recv_packet 契约要求拥有型载荷 Vec，借用无法跨 accum.drain 存活"
                    )]
                    let data = pkt.data.to_vec();
                    let target = pkt.target;
                    inner.accum.drain(..consumed);
                    let source = target.unwrap_or_else(|| inner.dest.clone());
                    return Ok(Some((source, data)));
                }
            }
            inner.buf.clear();
            let n = inner.buf.read_from(&mut inner.resp, RECV_BUF).await?;
            if n == 0 {
                return Ok(None); // outbound 关闭
            }
            inner.accum.extend_from_slice(inner.buf.bytes());
        }
    }

    /// 建立到 outbound 的 dispatch link（两条 duplex：请求/响应）。
    ///
    /// 并发会话数受 [`MAX_UDP_SESSIONS`] 约束：超限返回 `io::Error`
    /// （fail-visible，不静默丢弃数据报）。
    fn establish(&mut self, dest: Destination) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        let live = LIVE_SESSIONS.fetch_add(1, Ordering::Relaxed) + 1;
        if live > MAX_UDP_SESSIONS {
            LIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
            return Err(io::Error::other(format!(
                "udp dispatch sessions exceeded {MAX_UDP_SESSIONS}"
            )));
        }
        let (req_local, req_link) = tokio::io::duplex(DUPLEX_BUF);
        let (resp_link, resp_local) = tokio::io::duplex(DUPLEX_BUF);
        let link = Link::new(new_reader(req_link), new_writer(resp_link));
        let udp_dest = Destination::udp(dest.address().clone(), dest.port());
        let dispatcher = Arc::clone(&self.dispatcher);
        let access = self.access.lock().take();
        // §3.5.6 ①类托管：dispatch link 任务归本会话自持 scope（会话 Drop 即
        // abort，随组件停机取消）。闸关不可达（scope 无显式 close），拒发按
        // fail-visible 计数回滚处理（禁静默）。
        if self
            .scope
            .spawn(async move {
                // bd kol4a：有源走 dispatch_with_access（GlobalID 派生在出站
                // MuxBridge 终点），无源保持旧 dispatch（语义不变）。
                match access {
                    Some(access) => dispatcher.dispatch_with_access(&udp_dest, link, access).await,
                    None => dispatcher.dispatch(&udp_dest, link).await,
                }
            })
            .is_err()
        {
            LIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
            return Err(io::Error::other("udp dispatch scope closed"));
        }
        self.inner = Some(Inner {
            dest,
            req: req_local,
            resp: resp_local,
            accum: Vec::new(),
            buf: Buffer::new_pooled(RECV_BUF),
            frame: Vec::with_capacity(666),
            global_id: rand::random(),
            new_sent: false,
        });
        Ok(())
    }
}

// ========== Link 表示转换（隧道 / mux 跨实现边界，bd t0ls1） ==========
//
// 两套互不兼容的内部表示：
// - **内部 dispatch link**（本文件 `UdpDispatchSession` 写入、freedom/dns/ hysteria/tuic/ss/wg
//   六族消费）跑的是 **XUDP 帧**（自带 per-packet 目标 + GlobalID）。
// - **隧道 wire / mux carrier** 跑的是 **裸载荷**（Go `transport/internet/udp/dispatcher.go:117`
//   形态；VLESS/VMess plain 模式 `[2B len]` 前缀、Trojan `[addr][len][CRLF]`、mux data 段）。
//
// 旧实现把 link 字节流原样搬到 wire（帧头一起上线 → 对端把整帧当载荷），
// 跨实现双向皆废（见 `reports/audit-2026-10-31-perf-mem-wiring/round4/Verify-XUDP.md`）。
// 本节的四个适配件在**边界**上做表示转换，内部 link 契约不变。

/// 探测到的 XUDP 帧边界。
///
/// 帧线格式（`xray-xudp/src/packet.rs`）：`[2B meta_len][meta][?2B data_len][data]`，
/// data 段仅在 `opt & OPT_DATA` 置位时存在。载荷偏移由 meta_len 直接算出，
/// **不解析地址**——拆帧路径零分配、零摊平。
struct FrameHead {
    /// 帧头字节数（含 2B data_len，若存在）。
    header_len: usize,
    data_len: usize,
}

/// meta 段上限：XUDP meta 含域名地址时最长 ~270B，512 足量。超限即判流损坏，
/// 避免对垃圾字节无限等一个 64KiB meta。
const MAX_XUDP_META: usize = 512;

/// 在字节切片上探测一个完整 XUDP 帧。`Ok(None)` = 数据不足一帧。
fn probe_xudp_frame(data: &[u8]) -> Result<Option<FrameHead>, PacketError> {
    if data.len() < 6 {
        return Ok(None);
    }
    let meta_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if !(MIN_META_LEN..=MAX_XUDP_META).contains(&meta_len) {
        return Err(PacketError::MetadataTooShort(meta_len));
    }
    if data.len() < 2 + meta_len {
        return Ok(None);
    }
    // meta 布局：[2B len][2B session][1B status][1B opt]… → opt 在 data[5]
    if data[5] & 1 == 0 {
        // 无 data 段的控制帧（End/KeepAlive）：整帧跳过
        return Ok(Some(FrameHead { header_len: 2 + meta_len, data_len: 0 }));
    }
    if data.len() < 4 + meta_len {
        return Ok(None);
    }
    let data_len = usize::from(u16::from_be_bytes([data[2 + meta_len], data[3 + meta_len]]));
    if data.len() < 4 + meta_len + data_len {
        return Ok(None);
    }
    Ok(Some(FrameHead { header_len: 4 + meta_len, data_len }))
}

/// XUDP 帧长度字段下界（`[2B session][1B status][1B opt]`）。
const MIN_META_LEN: usize = 4;

/// 池化 Buffer 装一段拷贝（免 `to_vec` 扁平化禁忌；容量按需，超池档走裸分配）。
fn buffer_from_slice(src: &[u8]) -> Buffer {
    // 走分层池取块（`new_pooled` → `alloc(size)` 向上取整到 tier 档）：
    // `with_capacity` 的精确容量（如 100B）在 release 时因 `capacity != TIER_SIZES[tier]`
    // 被丢弃（alloc.rs 的「缓冲池丢弃非标准容量块」分支）→ 每包分配一次丢一次；
    // 池化块容量恒等于 tier 大小，归还即回收。
    let mut b = Buffer::new_pooled(src.len().max(1));
    // 池化块容量 >= 请求量 ⇒ 恒写满；写不满即本函数的构造不变式被破坏，
    // 而载荷截断不报错（debug_assert 在 release 下消失）→ 用 release 也生效的断言。
    let written = b.write_from(src);
    assert_eq!(written, src.len(), "Buffer::new_pooled 已按载荷取块");
    b
}

/// 帧解析错误 → link 读错误（拆帧路径的流损坏一律 fail-visible）。
fn frame_err(e: PacketError) -> xray_buf::io::Error {
    xray_buf::io::Error::ReadError(format!("xudp frame: {e}"))
}

/// XUDP 上行拆帧器：把 Link 字节流切回逐包裸载荷。
///
/// 帧完整落在单次输入内时**零拷贝**（直接在入参切片上切，仅回调切片）；
/// 只有跨 Buffer 边界的半帧才并入 `accum` 留待下次（一次拷贝）。
#[derive(Debug, Default)]
pub struct XudpUnframer {
    /// 跨 Buffer 的半帧残留（常态空）。
    accum: Vec<u8>,
}

impl XudpUnframer {
    /// 新建拆帧器。
    #[must_use]
    pub fn new() -> Self {
        Self { accum: Vec::new() }
    }

    /// 是否有未成帧的残留字节。
    #[must_use]
    pub fn pending(&self) -> bool {
        !self.accum.is_empty()
    }

    /// 把一段裸字节并入残留（调用方已自行切走完整帧时用）。
    fn push_tail(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.accum.extend_from_slice(bytes);
        }
    }

    /// 喂入一段字节；每个完整数据帧回调 `(meta 字节, 载荷)`。
    ///
    /// `meta` 为 `[2B meta_len][meta body]`（可直接喂 `FrameMetadata::from_bytes`）。
    pub fn feed<F>(&mut self, bytes: &[u8], mut emit: F) -> Result<(), PacketError>
    where
        F: FnMut(&[u8], &[u8]),
    {
        if bytes.is_empty() {
            return Ok(());
        }
        // 无残留 → 直接在入参切片上切（零拷贝）；有残留 → 并进 accum 一次性切。
        if self.accum.is_empty() {
            let mut off = 0;
            while let Some(h) = probe_xudp_frame(&bytes[off..])? {
                let end = off + h.header_len + h.data_len;
                if h.data_len > 0 {
                    emit(&bytes[off..off + h.header_len - 2], &bytes[off + h.header_len..end]);
                }
                off = end;
            }
            self.push_tail(&bytes[off..]);
            return Ok(());
        }
        self.accum.extend_from_slice(bytes);
        let mut off = 0;
        while let Some(h) = probe_xudp_frame(&self.accum[off..])? {
            let end = off + h.header_len + h.data_len;
            if h.data_len > 0 {
                emit(
                    &self.accum[off..off + h.header_len - 2],
                    &self.accum[off + h.header_len..end],
                );
            }
            off = end;
        }
        if off > 0 {
            self.accum.drain(..off);
        }
        Ok(())
    }
}

/// 解析帧头里的目标地址（trojan 上行按包目标用；vless/vmess plain 模式忽略）。
pub fn xudp_frame_target(meta: &[u8]) -> Result<Option<Destination>, PacketError> {
    let (m, _) = FrameMetadata::from_bytes(meta)?;
    Ok(m.target().cloned())
}

/// XUDP 下行裹帧器：逐包裸载荷 → XUDP 帧头（New 首帧 → Keep 后续）。
///
/// 回程目标只能取会话目标（wire 上不携带响应来源，与 Go plain 模式同局限）；
/// 支持 per-packet 目标覆盖（trojan 每包自描述地址）。
pub struct XudpReframer {
    dest: Destination,
    global_id: [u8; 8],
    new_sent: bool,
}

impl XudpReframer {
    /// 以会话目标构造；GlobalID 每会话随机（对齐 `UdpDispatchSession`）。
    #[must_use]
    pub fn new(dest: Destination) -> Self {
        Self { dest, global_id: rand::random(), new_sent: false }
    }

    /// 生成下一响应帧头（meta + 2B 载荷长度）写入 `out`（清空后写）。
    pub fn write_header(
        &mut self,
        payload_len: usize,
        target: Option<&Destination>,
        out: &mut Vec<u8>,
    ) -> Result<(), PacketError> {
        let dest = target.unwrap_or(&self.dest);
        let meta = if self.new_sent {
            FrameMetadata::keep_udp(dest.address().clone(), dest.port())
        } else {
            self.new_sent = true;
            FrameMetadata::new_udp(dest.address().clone(), dest.port(), self.global_id)
        };
        out.clear();
        meta.write_to(out)?;
        out.extend_from_slice(&(payload_len.min(usize::from(u16::MAX)) as u16).to_be_bytes());
        Ok(())
    }
}

/// Link 上行剥帧读端：把 XUDP 帧流交付为逐包裸载荷（一包一 Buffer）。
///
/// 一包一 Buffer 是 mux `TransferType::Packet` 写端的硬前提（它按 Buffer
/// 切帧——多包同 Buffer 会被拼进同一帧、单包跨 Buffer 会被拆成多帧）。
pub struct XudpUnframingReader {
    inner: Box<dyn Reader>,
    unframer: XudpUnframer,
}

impl XudpUnframingReader {
    /// 包装内层读端。
    #[must_use]
    pub fn new(inner: Box<dyn Reader>) -> Self {
        Self { inner, unframer: XudpUnframer::new() }
    }
}

impl Reader for XudpUnframingReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            loop {
                let mut out = MultiBuffer::new();
                // 残留半帧在补入更多字节前切不出东西 → 先读一批
                let mb = self.inner.read_multi_buffer().await?;
                if mb.is_empty() {
                    return Ok(MultiBuffer::new()); // 内层 EOF
                }
                for mut buf in mb.into_buffers() {
                    if self.unframer.pending() {
                        // 半帧路径：并入 accum 后整段切（拷贝）
                        self.unframer
                            .feed(buf.bytes(), |_, payload| {
                                out.push(buffer_from_slice(payload));
                            })
                            .map_err(frame_err)?;
                        continue;
                    }
                    // 常态路径：Buffer 原地剥头 + split_to 取载荷（零拷贝）
                    loop {
                        match probe_xudp_frame(buf.bytes()).map_err(frame_err)? {
                            Some(h) => {
                                buf.advance(h.header_len);
                                let payload = buf.split_to(h.data_len);
                                if !payload.is_empty() {
                                    out.push(payload);
                                }
                            },
                            None => {
                                self.unframer.push_tail(buf.bytes());
                                break;
                            },
                        }
                    }
                }
                if !out.is_empty() {
                    return Ok(out);
                }
            }
        })
    }
}

/// Link 下行裹帧写端：每次 `write_multi_buffer` = 一个数据报。
///
/// 调用方按包写（mux Keep 帧 / 隧道 wire 包），故一次调用即一帧；载荷
/// Buffer 原样挂到帧头之后（零拷贝，仅帧头进池化 Buffer）。
pub struct XudpFramingWriter {
    inner: Box<dyn Writer>,
    reframer: XudpReframer,
    scratch: Vec<u8>,
}

impl XudpFramingWriter {
    /// 以会话目标包装内层写端。
    #[must_use]
    pub fn new(inner: Box<dyn Writer>, dest: Destination) -> Self {
        Self { inner, reframer: XudpReframer::new(dest), scratch: Vec::with_capacity(64) }
    }
}

impl Writer for XudpFramingWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            if mb.is_empty() {
                return Ok(());
            }
            if mb.len() > usize::from(u16::MAX) {
                return Err(xray_buf::io::Error::WriteError(format!(
                    "xudp frame payload {} exceeds u16 length",
                    mb.len()
                )));
            }
            self.reframer
                .write_header(mb.len(), None, &mut self.scratch)
                .map_err(|e| xray_buf::io::Error::WriteError(format!("xudp frame header: {e}")))?;
            let mut frame = Buffer::new();
            let written = frame.write_from(&self.scratch);
            assert_eq!(written, self.scratch.len(), "xudp frame header exceeds buffer capacity");
            let mut out = MultiBuffer::with_capacity(mb.buffer_count() + 1);
            out.push(frame);
            for buf in mb.into_buffers() {
                out.push(buf);
            }
            self.inner.write_multi_buffer(out).await
        })
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }

    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        self.inner.shutdown_flush()
    }
}

/// 「XUDP link 表示 ↔ `[2B BE len][裸载荷]` wire 表示」适配连接。
///
/// 覆盖两种 wire 帧格式完全相同的承载：
/// - **VLESS UDP**（Go `MultiLengthPacketWriter`/`LengthPacketReader`）；
/// - **AnyTLS UoT v2**（sing `common/uot` `isConnect=true` 模式：`[2B len][payload]`）。
///
/// 上行：link 的 XUDP 帧逐包剥成裸载荷，按 `[2B len][payload]` 写 wire（零额外
/// 拷贝——载荷切片直接进 wire 缓冲）；下行：wire 的 `[2B len][payload]` 逐包裹回
/// XUDP 帧写 link（载荷原地留在读缓冲，按段交付，帧头先行）。
pub struct XudpWireConn<C> {
    inner: C,
    /// 上行剥帧：XUDP 帧流 → 裸载荷
    unframer: XudpUnframer,
    /// 下行裹帧：裸载荷 → XUDP 帧流
    reframer: XudpReframer,
    /// 读侧缓冲：`rview == 0` 时为原始 wire 字节（攒帧），`rview > 0` 时
    /// `rbuf[..rview]` 为当前包尚未交付的 payload。
    rbuf: Vec<u8>,
    rview: usize,
    /// 待发的 XUDP 帧头（meta + 2B 载荷长度）
    hdr: Vec<u8>,
    hpos: usize,
    /// 待写完的 wire 帧（UDP 帧不可分，部分写时缓存剩余）
    wpending: Vec<u8>,
    wpos: usize,
    /// 本轮 poll_write 已收下的字节数（返回 Pending 后重入不再重复喂）
    fed: usize,
}

impl<C> XudpWireConn<C> {
    /// 以会话目标构造（wire 不携带回程来源，回程帧目标取它）。
    #[must_use]
    pub fn new(inner: C, dest: Destination) -> Self {
        Self {
            inner,
            unframer: XudpUnframer::new(),
            reframer: XudpReframer::new(dest),
            rbuf: Vec::new(),
            rview: 0,
            hdr: Vec::with_capacity(64),
            hpos: 0,
            wpending: Vec::new(),
            wpos: 0,
            fed: 0,
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for XudpWireConn<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // 1) 待发的 XUDP 帧头优先（帧头必须排在载荷之前）
            if this.hpos < this.hdr.len() {
                let n = (this.hdr.len() - this.hpos).min(buf.remaining());
                buf.put_slice(&this.hdr[this.hpos..this.hpos + n]);
                this.hpos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) 当前包有未交付 payload → 先交付（ReadBuf 满时保留剩余，不丢数据）
            if this.rview > 0 {
                let n = this.rview.min(buf.remaining());
                buf.put_slice(&this.rbuf[..n]);
                this.rbuf.drain(..n);
                this.rview -= n;
                return Poll::Ready(Ok(()));
            }
            // 3) 攒帧：够帧头且够 payload → 剥前缀、裹 XUDP 帧头后交付
            if this.rbuf.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([this.rbuf[0], this.rbuf[1]]));
                if this.rbuf.len() >= 2 + len {
                    this.rbuf.drain(..2);
                    // 空载荷帧会让下游 PacketReader 判流结束，直接跳过
                    if len == 0 {
                        continue;
                    }
                    let mut hdr = std::mem::take(&mut this.hdr);
                    let res = this.reframer.write_header(len, None, &mut hdr);
                    this.hdr = hdr;
                    this.hpos = 0;
                    res.map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("udp wire: XUDP 应答帧头: {e}"),
                        )
                    })?;
                    this.rview = len;
                    continue;
                }
            }
            // 4) 不足一帧 → 从 inner 补读
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb)? {
                Poll::Ready(()) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return if this.rbuf.is_empty() {
                            Poll::Ready(Ok(())) // EOF：干净关闭
                        } else {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "udp wire: truncated frame",
                            )))
                        };
                    }
                    this.rbuf.extend_from_slice(filled);
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for XudpWireConn<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 上一轮已收下 buf（Pending 重入）→ 只排干，不再重复喂
        if this.fed == 0 {
            let mut framed = std::mem::take(&mut this.wpending);
            framed.clear();
            this.wpos = 0;
            let fed = buf.len();
            let res = this.unframer.feed(buf, |_, payload| {
                framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                framed.extend_from_slice(payload);
            });
            this.wpending = framed;
            res.map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("udp wire: XUDP 帧解析: {e}"))
            })?;
            this.fed = fed;
        }
        // 排干 pending 帧（UDP 帧不可分）
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut this.inner).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "udp wire: frame write stalled",
                )));
            }
            this.wpos += n;
        }
        let fed = this.fed;
        this.fed = 0;
        this.wpending.clear();
        this.wpos = 0;
        Poll::Ready(Ok(fed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<C: Connection> Connection for XudpWireConn<C> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv4Addr;

    use xray_common::net::{address::Address, port::Port};
    // PacketReader 只剩测试在用（生产收包路径已换借用式 parse_packet_slice_at）
    use xray_xudp::packet::PacketReader;

    use super::*;

    /// Echo handler：读首帧 → 验证 target → 回写一帧（来源 = 请求 target）。
    struct EchoHandler;

    impl std::fmt::Debug for EchoHandler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("EchoHandler")
        }
    }

    impl DispatchHandler for EchoHandler {
        fn tag(&self) -> &str {
            "echo"
        }

        fn dispatch(&self, dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
            let dest = dest.clone();
            Box::pin(async move {
                use xray_buf::io::Reader;
                // 读首帧（XUDP New 帧）
                let mut reader = link.reader;
                let mb = match reader.read_multi_buffer().await {
                    Ok(mb) => mb,
                    Err(_) => return,
                };
                // q1r4q：首帧直接在 MultiBuffer 片段链上解析——PacketReader 本就
                // 泛型 over R: Read，ChainCursor 把片段链暴露为流，免 to_vec 摊平
                //（原 P1 收口点：UDP 小包 relay bench，oracle §7 Phase 1）。
                let bufs = mb.into_buffers();
                let mut cursor = ChainCursor::new(&bufs);
                let mut pr = PacketReader::new(&mut cursor);
                let pkt = match pr.read_packet() {
                    Ok(Some(p)) => p,
                    _ => return,
                };
                let (data, target) = pkt.into_parts();
                let echo_from = target.unwrap_or(dest);
                // 回写一帧（来源 = 请求目标）
                let mut frame = Vec::new();
                let meta =
                    FrameMetadata::new_udp(echo_from.address().clone(), echo_from.port(), [0u8; 8]);
                meta.write_to(&mut frame).unwrap();
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(&data);
                let mut out = xray_buf::multi::MultiBuffer::new();
                out.merge_bytes(&frame);
                use xray_buf::io::Writer;
                let mut writer = link.writer;
                let _ = writer.write_multi_buffer(out).await;
            })
        }
    }

    fn udp_dest(ip: [u8; 4], port: u16) -> Destination {
        Destination::udp(Address::IPv4(Ipv4Addr::from(ip)), Port::new(port))
    }

    // ── t0ls1：Link 表示转换（XUDP 帧 ↔ 裸载荷）──

    fn udp_frame(payload: &[u8], ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        FrameMetadata::new_udp(udp_dest(ip, port).address().clone(), Port::new(port), [7u8; 8])
            .write_to(&mut f)
            .unwrap();
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// 按 `chunk` 给定的分段长度循环喂入拆帧器，返回切出的载荷。
    fn unframe_in_chunks(stream: &[u8], chunk: impl Fn(usize) -> usize) -> Vec<Vec<u8>> {
        let mut uf = XudpUnframer::new();
        let mut got = Vec::new();
        let mut off = 0;
        let mut i = 0;
        while off < stream.len() {
            let n = chunk(i).clamp(1, stream.len() - off);
            uf.feed(&stream[off..off + n], |_, payload| got.push(payload.to_vec())).unwrap();
            off += n;
            i += 1;
        }
        assert!(!uf.pending(), "完整流喂完后不得留半帧");
        got
    }

    /// 拆帧结果对分段方式不变：整段、1 字节、3 字节碎片、对半切结果一致。
    #[test]
    fn xudp_unframer_segmentation_invariant() {
        let mut stream = udp_frame(b"first-payload", [8, 8, 8, 8], 53);
        stream.extend_from_slice(&udp_frame(b"p2", [1, 0, 0, 1], 443));
        let expect = vec![b"first-payload".to_vec(), b"p2".to_vec()];

        assert_eq!(unframe_in_chunks(&stream, |_| stream.len()), expect, "整段喂入");
        assert_eq!(unframe_in_chunks(&stream, |_| 1), expect, "1 字节碎片");
        assert_eq!(unframe_in_chunks(&stream, |_| 3), expect, "3 字节碎片（错位帧边界）");
        let half = stream.len() / 2;
        assert_eq!(
            unframe_in_chunks(&stream, |i| if i == 0 { half } else { stream.len() }),
            expect
        );
    }

    /// 空载荷帧与残留不串包：喂入半帧时拆帧器只留残留、不吐包。
    #[test]
    fn xudp_unframer_holds_partial_frame() {
        let mut frame = udp_frame(b"abcd", [8, 8, 8, 8], 53);
        let head = frame.len() - 2;
        let mut uf = XudpUnframer::new();
        let mut got = Vec::new();
        uf.feed(&frame[..head], |_, p| got.push(p.to_vec())).unwrap();
        assert!(got.is_empty(), "半帧不得交付");
        assert!(uf.pending(), "半帧必须留残留");
        frame.drain(..head);
        uf.feed(&frame, |_, p| got.push(p.to_vec())).unwrap();
        assert_eq!(got, vec![b"abcd".to_vec()]);
        assert!(!uf.pending());
    }

    /// 写端裹帧 → 读端拆帧往返：首帧 New、后续 Keep，载荷逐字节一致。
    #[tokio::test]
    async fn xudp_framing_writer_roundtrip_new_then_keep() {
        #[derive(Clone)]
        struct Capture(std::sync::Arc<parking_lot::Mutex<Vec<u8>>>);
        impl Writer for Capture {
            fn write_multi_buffer(
                &mut self,
                mb: MultiBuffer,
            ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
                Box::pin(async move {
                    let mut g = self.0.lock();
                    for b in mb.iter() {
                        g.extend_from_slice(b.bytes());
                    }
                    Ok(())
                })
            }
        }

        let cap = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut w = XudpFramingWriter::new(
            Box::new(Capture(std::sync::Arc::clone(&cap))),
            udp_dest([8, 8, 8, 8], 53),
        );
        for payload in [b"dns-query".as_slice(), b"second".as_slice()] {
            let mut mb = MultiBuffer::new();
            mb.push(xray_buf::buffer::Buffer::from_vec(payload.to_vec()));
            w.write_multi_buffer(mb).await.unwrap();
        }

        let bytes = cap.lock().clone();
        let (first, _) = FrameMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(first.status(), xray_xudp::packet::FrameStatus::New, "首帧必须是 New");
        assert!(first.global_id().is_some(), "New 帧必须带 GlobalID");
        assert_eq!(first.target(), Some(&udp_dest([8, 8, 8, 8], 53)), "帧目标 = 会话目标");
        let h1 = probe_xudp_frame(&bytes).unwrap().expect("首帧完整");
        let (second, _) = FrameMetadata::from_bytes(&bytes[h1.header_len + h1.data_len..]).unwrap();
        assert_eq!(second.status(), xray_xudp::packet::FrameStatus::Keep, "后续帧必须是 Keep");

        // 拆帧还原：载荷逐字节一致（New/Keep 都是数据帧）
        assert_eq!(
            unframe_in_chunks(&bytes, |_| bytes.len()),
            vec![b"dns-query".to_vec(), b"second".to_vec()]
        );
    }

    /// q1r4q：把不连续 Buffer 片段链暴露为 `io::Read`，让 `PacketReader`
    /// （`R: Read` 泛型）跨片段解析，免 to_vec 摊平拷贝。持 `&[Buffer]`
    /// 单一借用（而非 Vec<&[u8]> scratch）：解析尝试之间会 advance/drain
    /// `accum`，单借用随解析块结束即失效，不与突变冲突。
    struct ChainCursor<'a> {
        bufs: &'a [xray_buf::buffer::Buffer],
        idx: usize,
        off: usize,
        /// 全局已消费字节数（帧累积消费 advance/drain 的依据）。
        pos: usize,
    }

    impl<'a> ChainCursor<'a> {
        fn new(bufs: &'a [xray_buf::buffer::Buffer]) -> Self {
            Self { bufs, idx: 0, off: 0, pos: 0 }
        }
    }

    impl io::Read for ChainCursor<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            // 跳过耗尽的片段（含零长片段）
            while self.idx < self.bufs.len() && self.off >= self.bufs[self.idx].len() {
                self.idx += 1;
                self.off = 0;
            }
            if out.is_empty() || self.idx == self.bufs.len() {
                return Ok(0); // EOF：read_exact 转 UnexpectedEof（半帧语义不变）
            }
            let cur = self.bufs[self.idx].bytes();
            let n = cur.len().saturating_sub(self.off).min(out.len());
            out[..n].copy_from_slice(&cur[self.off..self.off + n]);
            self.off += n;
            self.pos += n;
            Ok(n)
        }
    }

    #[tokio::test]
    async fn send_recv_roundtrip() {
        let mut session = UdpDispatchSession::new(Arc::new(EchoHandler));
        let dest = udp_dest([8, 8, 4, 4], 53);
        session.send_packet(&dest, b"dns-query").await.expect("send failed");

        let (source, payload) =
            session.recv_packet().await.expect("recv failed").expect("session ended");
        assert_eq!(payload, b"dns-query");
        assert_eq!(source, dest, "echo source should carry per-packet target");
    }

    /// bd kol4a：`with_access` 的会话 establish 必须走 `dispatch_with_access`
    /// 且原样携带 `from`/`inbound_name`（GlobalID 派生链第一环——生产链终点
    /// `MuxBridge::dispatch_with_access` 按它们算 XUDP GlobalID）；无 access
    /// 的会话保持旧 `dispatch`（不记次数）。
    #[tokio::test]
    async fn with_access_routes_through_dispatch_with_access() {
        #[derive(Debug)]
        struct AccessCapture {
            seen: std::sync::Arc<parking_lot::Mutex<Vec<crate::default::AccessContext>>>,
        }

        impl DispatchHandler for AccessCapture {
            fn tag(&self) -> &str {
                "access-capture"
            }

            fn dispatch(&self, _dest: &Destination, _link: Link) -> crate::default::PinFuture<()> {
                Box::pin(async move {})
            }

            fn dispatch_with_access(
                &self,
                _dest: &Destination,
                _link: Link,
                access: crate::default::AccessContext,
            ) -> crate::default::PinFuture<()> {
                self.seen.lock().push(access);
                Box::pin(async move {})
            }
        }

        let seen = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let handler: Arc<dyn DispatchHandler> =
            Arc::new(AccessCapture { seen: std::sync::Arc::clone(&seen) });
        let mut session =
            UdpDispatchSession::new(handler).with_access(crate::default::AccessContext {
                from: "10.0.0.9:5555".to_string(),
                inbound_name: "socks".to_string(),
                ..crate::default::AccessContext::default()
            });
        session.send_packet(&udp_dest([8, 8, 8, 8], 53), b"probe").await.expect("send failed");

        // establish 的 spawn 与断言并发——按截止时间轮询，不 sleep 固定值
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            {
                // 内层块：MutexGuard 不得跨 await（clippy await_holding_lock）
                let snapshot = seen.lock();
                if !snapshot.is_empty() || std::time::Instant::now() > deadline {
                    assert_eq!(snapshot.len(), 1, "establish 必须恰好 dispatch_with_access 一次");
                    assert_eq!(snapshot[0].from, "10.0.0.9:5555");
                    assert_eq!(snapshot[0].inbound_name, "socks");
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn second_packet_uses_keep_frame_with_target() {
        #[derive(Debug)]
        struct CaptureHandler(std::sync::Arc<parking_lot::Mutex<Vec<(Destination, Vec<u8>)>>>);

        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(&self, _dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
                let captured = std::sync::Arc::clone(&self.0);
                Box::pin(async move {
                    use xray_buf::io::{Reader, Writer};
                    let mut reader = link.reader;
                    let mut writer = link.writer;
                    // q1r4q：Buffer 片段链累积（原 Vec 连续化 + to_vec+extend 双拷贝，
                    // P1 收口点：udp relay bench 轮次）
                    let mut accum: Vec<_> = Vec::new();
                    loop {
                        let mb = match reader.read_multi_buffer().await {
                            Ok(mb) => mb,
                            Err(_) => break,
                        };
                        accum.extend(mb.into_buffers());
                        loop {
                            let (r, consumed) = {
                                let mut cursor = ChainCursor::new(&accum);
                                let mut pr = PacketReader::new(&mut cursor);
                                let r = pr.read_packet();
                                (r, cursor.pos)
                            };
                            match r {
                                Ok(Some(pkt)) => {
                                    let (data, target) = pkt.into_parts();
                                    if let Some(t) = target {
                                        captured.lock().push((t, data));
                                        // 每捕获一包回一帧（Keep，来源 = 固定地址）
                                        let mut frame = Vec::new();
                                        FrameMetadata::keep_udp(
                                            Address::IPv4(Ipv4Addr::new(1, 1, 1, 1)),
                                            Port::new(53),
                                        )
                                        .write_to(&mut frame)
                                        .unwrap();
                                        frame.extend_from_slice(&1u16.to_be_bytes());
                                        frame.extend_from_slice(b"x");
                                        let mut out = xray_buf::multi::MultiBuffer::new();
                                        out.merge_bytes(&frame);
                                        if writer.write_multi_buffer(out).await.is_err() {
                                            break;
                                        }
                                    }
                                    // 消费已解析前缀：整 Buffer 弹出、半 Buffer advance
                                    //（指针级前进，免字节级 drain 搬移；qyn8 语义不变）
                                    let mut left = consumed;
                                    let mut done = 0;
                                    while left > 0 {
                                        let l = accum[done].len();
                                        if l <= left {
                                            done += 1;
                                            left -= l;
                                        } else {
                                            accum[done].advance(left);
                                            left = 0;
                                        }
                                    }
                                    accum.drain(..done);
                                },
                                _ => break,
                            }
                        }
                    }
                })
            }
        }

        let store = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let handler: std::sync::Arc<dyn DispatchHandler> =
            std::sync::Arc::new(CaptureHandler(std::sync::Arc::clone(&store)));
        let mut session = UdpDispatchSession::new(handler);
        let d1 = udp_dest([8, 8, 8, 8], 53);
        let d2 = udp_dest([1, 0, 0, 1], 53);
        session.send_packet(&d1, b"first").await.unwrap();
        session.send_packet(&d2, b"second").await.unwrap();
        // 收两个回包（清空响应管道）
        let _ = session.recv_packet().await.unwrap();
        let _ = session.recv_packet().await.unwrap();
        let got = store.lock();
        assert_eq!(got.len(), 2, "both packets should reach outbound");
        assert_eq!(got[0].0, d1);
        assert_eq!(got[1].0, d2, "Keep frame must carry real per-packet target");
        assert_eq!(got[1].1, b"second");
    }

    #[tokio::test]
    async fn recv_before_send_pends() {
        // 未建立 link 时 recv_packet 挂起（不 panic、不返回）
        let mut session = UdpDispatchSession::new(Arc::new(EchoHandler));
        let r =
            tokio::time::timeout(std::time::Duration::from_millis(50), session.recv_packet()).await;
        assert!(r.is_err(), "recv before send must pend");
    }

    /// qyn8：只写坏帧且保持写端打开的 handler。
    #[derive(Debug)]
    struct BadFrameHandler;

    impl DispatchHandler for BadFrameHandler {
        fn tag(&self) -> &str {
            "badframe"
        }

        fn dispatch(&self, _dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
            Box::pin(async move {
                use xray_buf::io::Writer;
                let mut out = xray_buf::multi::MultiBuffer::new();
                // 坏帧：长度头声明 body_len=3 < MIN_META_LEN(4) → MetadataTooShort
                out.merge_bytes(&[0x00u8, 0x03]);
                let mut writer = link.writer;
                let _ = writer.write_multi_buffer(out).await;
                // 保持写端打开：EOF 会把忙旋误判成正常关会话
                std::future::pending::<()>().await;
            })
        }
    }

    #[tokio::test]
    async fn bad_frame_errs_once_then_blocks() {
        // qyn8 回归：坏帧 → recv_packet Err；Err 分支 drain 坏帧后 accum 前进，
        // 下一次 recv 阻塞等新数据。修复前坏帧滞留 accum，重解析同一字节无限
        // Err（调用方 continue 即同步忙旋 100% CPU）。
        let mut session = UdpDispatchSession::new(Arc::new(BadFrameHandler));
        let dest = udp_dest([8, 8, 4, 4], 53);
        session.send_packet(&dest, b"ping").await.expect("send failed");

        let err = session.recv_packet().await.expect_err("bad frame must err");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let spin =
            tokio::time::timeout(std::time::Duration::from_millis(150), session.recv_packet())
                .await;
        assert!(
            spin.is_err(),
            "recv_packet must block after draining bad frame (busy-spin regression)"
        );
    }

    /// q1r4q 回归钉：同一 UDP 帧流按不同分段方式（单段/碎片边界任意错位）
    /// 经片段链重组解析，结果逐字节相同（帧数/载荷/target 全等）。
    #[test]
    fn chain_parse_reassembly_is_segmentation_invariant() {
        let build_frame = |payload: &[u8], ip: [u8; 4]| -> Vec<u8> {
            let mut f = Vec::new();
            FrameMetadata::new_udp(udp_dest(ip, 53).address().clone(), Port::new(53), [7u8; 8])
                .write_to(&mut f)
                .unwrap();
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            f.extend_from_slice(payload);
            f
        };
        let mut stream = build_frame(b"first-payload", [8, 8, 8, 8]);
        stream.extend_from_slice(&build_frame(b"p2", [1, 0, 0, 1]));

        let to_bufs = |chunks: &[&[u8]]| -> Vec<xray_buf::buffer::Buffer> {
            // from_vec = Frozen 语义：非池来源永不回池，无假池污染面
            chunks.iter().map(|c| xray_buf::buffer::Buffer::from_vec(c.to_vec())).collect()
        };
        let parse_all = |bufs: &[xray_buf::buffer::Buffer]| -> Vec<(Vec<u8>, Option<Destination>)> {
            let mut cursor = ChainCursor::new(bufs);
            let mut pr = PacketReader::new(&mut cursor);
            let mut got = Vec::new();
            while let Ok(Some(pkt)) = pr.read_packet() {
                got.push(pkt.into_parts());
            }
            got
        };

        let whole = parse_all(&to_bufs(&[&stream]));
        assert_eq!(whole.len(), 2, "两条帧都应解出");

        // 3 字节碎片：片段边界与帧边界错位
        let frags: Vec<&[u8]> = stream.chunks(3).collect();
        assert_eq!(parse_all(&to_bufs(&frags)), whole, "3 字节碎片重组必须逐字节一致");

        // 1 字节 + 剩余：切进 2B 长度头内部
        let head1 = [&stream[..1], &stream[1..]];
        assert_eq!(parse_all(&to_bufs(&head1)), whole, "1 字节分段重组必须逐字节一致");

        // 对半切
        let half = stream.len() / 2;
        let halves = [&stream[..half], &stream[half..]];
        assert_eq!(parse_all(&to_bufs(&halves)), whole, "对半分段重组必须逐字节一致");
    }

    // ── q1r4q 分配取证：线程归属计数分配器（libtest 并行下他线程分配不串扰）──

    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    thread_local! {
        // pub(crate)：本 crate 其他测试模块复用此计数（一个二进制只能有一个
        // `#[global_allocator]`，故计数源共享而非各造一份）。
        pub(crate) static THREAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
    }

    struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // try_with：TLS 析构期分配无法归属任何线程，跳过记账（分配器内禁 panic）
            let _ = THREAD_ALLOCS.try_with(|c| c.set(c.get() + 1));
            // SAFETY: 透传 System，布局合法性由 GlobalAlloc 契约保证
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: 指针/布局配对由 GlobalAlloc 契约保证
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static Q1R4Q_ALLOC: CountingAlloc = CountingAlloc;

    /// q1r4q 分配取证：同一帧流上旧路径（to_vec 摊平 + Cursor）与新路径
    /// （片段链直读）的每包堆分配次数对比。数据帧到达本身（池化 Buffer
    /// 移交）在两路径下都零分配，已在窗口外构造以排除干扰。
    // lib.rs:8 的 warn(print_stdout) 排在 :7 test 级 allow 之后将其覆盖，
    // 本测试取证数字须打印——按仓规显式 allow + 理由。
    #[allow(clippy::print_stdout)]
    #[test]
    fn chain_parse_allocs_per_packet_drop() {
        const PACKETS: usize = 128;
        let mut stream = Vec::new();
        for i in 0..PACKETS {
            let mut f = Vec::new();
            FrameMetadata::new_udp(
                udp_dest([10, 0, 0, (i % 254 + 1) as u8], 53).address().clone(),
                Port::new(53),
                [i as u8; 8],
            )
            .write_to(&mut f)
            .unwrap();
            f.extend_from_slice(&16u16.to_be_bytes());
            f.extend_from_slice(&[0u8; 16]);
            stream.extend_from_slice(&f);
        }

        let before = THREAD_ALLOCS.with(|c| c.get());
        // 旧路径（改前 CaptureHandler 每读一轮）：to_vec 摊平 + Cursor 重扫
        for _ in 0..PACKETS {
            let flat = stream.clone(); // ≙ mb.to_vec()：整帧堆分配 + 拷贝
            let mut cursor = std::io::Cursor::new(&flat[..]);
            let mut pr = PacketReader::new(&mut cursor);
            assert!(pr.read_packet().is_ok_and(|o| o.is_some()));
        }
        let old_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        // 新路径（改后）：到达帧 = Buffer 移交（窗口外预构造），链上直读
        let arrived: Vec<_> =
            (0..PACKETS).map(|_| xray_buf::buffer::Buffer::from_vec(stream.clone())).collect();
        let mut bufs: Vec<xray_buf::buffer::Buffer> = Vec::new();
        let before = THREAD_ALLOCS.with(|c| c.get());
        for buf in arrived {
            bufs.clear();
            bufs.push(buf);
            let parsed = {
                let mut cursor = ChainCursor::new(&bufs);
                let mut pr = PacketReader::new(&mut cursor);
                pr.read_packet().is_ok_and(|o| o.is_some())
            };
            assert!(parsed);
        }
        let new_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        let old_pp = old_allocs / PACKETS;
        let new_pp = new_allocs / PACKETS;
        println!("q1r4q per-packet allocs: old(to_vec+Cursor)={old_pp} new(chain)={new_pp}");
        assert_eq!(old_pp, 3, "旧路径每包 3 次分配（to_vec + reader scratch + 载荷 Vec）");
        assert_eq!(new_pp, 2, "新路径每包 2 次分配（摊平分配已删，剩 scratch + 载荷）");
    }

    /// bd lppdz 分配取证：`recv_packet` 收包内层（解析一帧 + 取出载荷 + 前进
    /// accum）的 A/B。旧路径（Cursor + `PacketReader::into_parts`）= 2 次/包
    /// （reader scratch + 载荷 Vec）；新路径（借用式 `parse_packet_slice_at`）
    /// 只剩载荷 `to_vec` 的 1 次——那是 `recv_packet` 返回
    /// `(Destination, Vec<u8>)` 的契约成本（借用活不过 `accum.drain`），
    /// 归零需改 API 签名（10+ 调用方含 xray-core 红线文件），不属本票。
    // 取证数字须打印（同 q1r4q 先例：显式 allow + 理由）。
    #[allow(clippy::print_stdout)]
    #[test]
    fn recv_parse_allocs_per_packet_ab() {
        const PACKETS: usize = 256;
        let mut stream = Vec::new();
        for i in 0..PACKETS {
            let mut f = Vec::new();
            FrameMetadata::new_udp(
                udp_dest([10, 0, 0, (i % 254 + 1) as u8], 53).address().clone(),
                Port::new(53),
                [i as u8; 8],
            )
            .write_to(&mut f)
            .unwrap();
            f.extend_from_slice(&16u16.to_be_bytes());
            f.extend_from_slice(&[0u8; 16]);
            stream.extend_from_slice(&f);
        }

        // A（改前）：Cursor + PacketReader → into_parts → drain(position)
        let mut accum = stream.clone();
        let before = THREAD_ALLOCS.with(|c| c.get());
        while !accum.is_empty() {
            let mut cursor = std::io::Cursor::new(&accum[..]);
            let (data, _target) = {
                let mut pr = PacketReader::new(&mut cursor);
                pr.read_packet().expect("read").expect("packet").into_parts()
            };
            let pos = cursor.position() as usize;
            std::hint::black_box(&data);
            accum.drain(..pos);
        }
        let old_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        // B（改后）：借用式解析 → 载荷 to_vec（契约成本）
        let mut accum = stream.clone();
        let before = THREAD_ALLOCS.with(|c| c.get());
        while !accum.is_empty() {
            let pkt = match parse_packet_slice_at(&accum[..]).0 {
                Ok(Some(p)) => p,
                other => panic!("unexpected parse result: {other:?}"),
            };
            let consumed = pkt.consumed;
            let data = pkt.data.to_vec();
            let _target = pkt.target;
            std::hint::black_box(&data);
            accum.drain(..consumed);
        }
        let new_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        let old_pp = old_allocs / PACKETS;
        let new_pp = new_allocs / PACKETS;
        println!(
            "lppdz recv per-packet allocs: old(PacketReader)={old_pp} new(slice+to_vec)={new_pp}"
        );
        assert_eq!(old_pp, 2, "旧收包路径每包 2 次分配（reader scratch + 载荷 Vec）");
        assert_eq!(new_pp, 1, "新收包路径每包 1 次分配（仅载荷 to_vec 契约成本）");
    }
}
