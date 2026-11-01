//! XUDP 帧编解码
//!
//! 对应 Go 版本 `common/xudp/xudp.go` 中的 PacketWriter 和 PacketReader。
//!
//! # 帧格式
//!
//! 所有帧共享头部：`length(2B BE) + session_id(2B=0) + status(1B) + opt(1B)`
//!
//! | 类型      | status | opt | 载荷                                                                 |
//! |-----------|--------|-----|----------------------------------------------------------------------|
//! | New       | 1      | 1   | network(1B=2) + PortThenAddress + GlobalID(8B) + data_len(2B) + data |
//! | Keep      | 2      | 1   | network(1B=2) + PortThenAddress + data_len(2B) + data               |
//! | KeepAlive | 4      | 0   | (无)                                                                 |

use std::io::{self, Read, Write};

use xray_buf::buffer::Buffer;
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    protocol::address_parser::{AddressParser, AddressSerializer},
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPT_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;
const MIN_META_LEN: usize = 4;
const GLOBAL_ID_LEN: usize = 8;
/// 载荷上限 = u16 上限（帧 `data_len` 字段宽度的物理极限）。
///
/// 历史值 `8192-666 = 7526` 抄自 Go `common/xudp/xudp.go:100`
/// （`length+666 > buf.Size`）——但那是 **Go wire 侧**（mux 帧承载）的约束，
/// Rust 的 XUDP 帧只跑**内部 dispatch link**（freedom/dns/hysteria/tuic/ss/wg
/// 六族消费），隧道/mux 的 wire 表示已改由各协议自己的 framing 层负责。
/// 照抄该值会让 >7526B 的 UDP 应答在写侧被静默跳过（bd zu7tk：socks5 UDP
/// 7600B 起全无回包，Go 侧 8000B 正常）。超限帧仍静默跳过（Go 同语义）；
/// 7526 < 65535 之外的超限在 UDP 面上不可达（单数据报 ≤ 65507）。
const MAX_DATA_LEN: usize = u16::MAX as usize;

/// XUDP 帧编解码错误
#[derive(thiserror::Error, Debug)]
pub enum PacketError {
    #[error("metadata too short: {0} bytes, minimum {MIN_META_LEN}")]
    MetadataTooShort(usize),
    #[error("invalid session status: 0x{0:02x}")]
    InvalidStatus(u8),
    #[error("address parse failed: {0}")]
    AddressParseFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// 帧会话状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
    /// 首帧，携带目标地址和 GlobalID
    New,
    /// 后续帧，仅携带目标地址
    Keep,
    /// 保活帧，无载荷
    KeepAlive,
}

impl FrameStatus {
    /// 转换为字节表示
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::New => STATUS_NEW,
            Self::Keep => STATUS_KEEP,
            Self::KeepAlive => STATUS_KEEP_ALIVE,
        }
    }

    /// 从字节解析，无效值返回 `None`
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            STATUS_NEW => Some(Self::New),
            STATUS_KEEP => Some(Self::Keep),
            STATUS_KEEP_ALIVE => Some(Self::KeepAlive),
            _ => None,
        }
    }
}

/// XUDP 帧元数据
#[derive(Debug, Clone, PartialEq)]
pub struct FrameMetadata {
    status: FrameStatus,
    has_data: bool,
    target: Option<Destination>,
    global_id: Option<[u8; GLOBAL_ID_LEN]>,
}

impl FrameMetadata {
    /// 创建 New 类型的 UDP 帧元数据（首帧，含 GlobalID）
    #[must_use]
    pub fn new_udp(address: Address, port: Port, global_id: [u8; GLOBAL_ID_LEN]) -> Self {
        Self {
            status: FrameStatus::New,
            has_data: true,
            target: Some(Destination::udp(address, port)),
            global_id: Some(global_id),
        }
    }

    /// 创建 Keep 类型的 UDP 帧元数据（后续帧，无 GlobalID）
    #[must_use]
    pub fn keep_udp(address: Address, port: Port) -> Self {
        Self {
            status: FrameStatus::Keep,
            has_data: true,
            target: Some(Destination::udp(address, port)),
            global_id: None,
        }
    }

    /// 创建 KeepAlive 帧元数据（保活，无载荷）
    #[must_use]
    pub fn keep_alive() -> Self {
        Self { status: FrameStatus::KeepAlive, has_data: false, target: None, global_id: None }
    }

    /// 返回帧状态
    #[must_use]
    pub fn status(&self) -> FrameStatus {
        self.status
    }

    /// 是否包含数据载荷
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.has_data
    }

    /// 返回目标地址（如有）
    #[must_use]
    pub fn target(&self) -> Option<&Destination> {
        self.target.as_ref()
    }

    /// 返回 GlobalID（仅 New 帧有值）
    #[must_use]
    pub fn global_id(&self) -> Option<&[u8; GLOBAL_ID_LEN]> {
        self.global_id.as_ref()
    }

    /// 设置目标地址
    pub fn set_target(&mut self, t: Destination) {
        self.target = Some(t);
    }

    /// 设置 GlobalID
    pub fn set_global_id(&mut self, id: [u8; GLOBAL_ID_LEN]) {
        self.global_id = Some(id);
    }

    /// 序列化为字节向量
    ///
    /// 格式：`length(2B) + session_id(2B) + status(1B) + opt(1B) + ...`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        self.write_bytes_into(&mut buf);
        buf
    }

    /// 序列化进调用方 scratch（clear + 写入，容量跨包复用，免每包 `Vec` 堆分配）。
    ///
    /// 线格式与 [`Self::to_bytes`] 完全一致。
    pub fn write_bytes_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(64);
        let mut buf = Buffer::new_pooled(64);
        self.write_into_buffer(&mut buf);
        out.extend_from_slice(buf.bytes());
    }

    /// 序列化核心：直写进池化 [`Buffer`]（bd 1fm1l W5 零中间分配——`Vec` 版每次
    /// 调用要新建 32B 地址暂存 Buffer，`to_bytes` 再多一次 `Vec` 分配；UDP 数据面
    /// 逐包调用时这两次都省不掉）。线格式与 [`Self::to_bytes`] 完全一致。
    ///
    /// 要求 `out` 剩余容量 ≥ 帧头全长（不足时 `write_from` 静默截断 → 畸形帧），
    /// 调用方按 [`MAX_FRAME_OVERHEAD`](self::MAX_FRAME_OVERHEAD) 取池。
    pub fn write_into_buffer(&self, out: &mut Buffer) {
        out.clear();
        // 占位 length(2B) + session_id(2B=0)
        out.write_from(&[0u8; 4]);
        // status + opt
        out.write_from(&[self.status.to_byte(), if self.has_data { OPT_DATA } else { 0 }]);
        // target
        if let Some(t) = &self.target {
            if t.network() == Network::UDP {
                out.write_from(&[NETWORK_UDP]);
                AddressSerializer::write_port_address(out, t.port(), t.address());
            }
        }
        // GlobalID（仅 New 帧）
        if self.status == FrameStatus::New {
            if let Some(gid) = &self.global_id {
                out.write_from(gid);
            }
        }
        // 回写 length = body 长度（不含 length 字段自身）
        let body_len = (out.len() - 2) as u16;
        let bl = body_len.to_be_bytes();
        out.set_byte(0, bl[0]);
        out.set_byte(1, bl[1]);
    }

    /// 写入到实现 `Write` 的目标
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), PacketError> {
        w.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// 从字节切片解析帧元数据
    ///
    /// 返回 `(FrameMetadata, consumed)` 其中 consumed 为已消费的字节数。
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), PacketError> {
        if data.len() < 2 {
            return Err(PacketError::MetadataTooShort(data.len()));
        }
        let body_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if body_len < MIN_META_LEN {
            return Err(PacketError::MetadataTooShort(body_len));
        }
        if data.len() < 2 + body_len {
            return Err(PacketError::MetadataTooShort(data.len()));
        }

        let body = &data[2..2 + body_len];
        let status_byte = body[2];
        let status =
            FrameStatus::from_byte(status_byte).ok_or(PacketError::InvalidStatus(status_byte))?;
        let has_data = (body[3] & OPT_DATA) != 0;

        let (target, global_id) = parse_body_target(body, status)?;

        Ok((Self { status, has_data, target, global_id }, 2 + body_len))
    }

    /// 从实现 `Read` 的源读取帧元数据
    pub fn read_from(r: &mut impl Read) -> Result<Self, PacketError> {
        let mut len_buf = [0u8; 2];
        r.read_exact(&mut len_buf)?;
        let body_len = u16::from_be_bytes(len_buf) as usize;
        if body_len < MIN_META_LEN {
            return Err(PacketError::MetadataTooShort(body_len));
        }

        let mut body = vec![0u8; body_len];
        r.read_exact(&mut body)?;

        let status_byte = body[2];
        let status =
            FrameStatus::from_byte(status_byte).ok_or(PacketError::InvalidStatus(status_byte))?;
        let has_data = (body[3] & OPT_DATA) != 0;

        let (target, global_id) = parse_body_target(&body, status)?;

        Ok(Self { status, has_data, target, global_id })
    }
}

/// 解析帧体中的目标地址和 GlobalID
fn parse_body_target(
    body: &[u8],
    status: FrameStatus,
) -> Result<(Option<Destination>, Option<[u8; GLOBAL_ID_LEN]>), PacketError> {
    let mut off = 4;
    let mut target = None;
    let mut global_id = None;

    match status {
        FrameStatus::New => {
            if off < body.len() && body[off] == NETWORK_UDP {
                off += 1;
                let (port, addr, consumed) = AddressParser::parse_port_address(&body[off..])
                    .ok_or_else(|| PacketError::AddressParseFailed("New frame".into()))?;
                target = Some(Destination::udp(addr, port));
                off += consumed;

                if off + GLOBAL_ID_LEN <= body.len() {
                    let mut gid = [0u8; GLOBAL_ID_LEN];
                    gid.copy_from_slice(&body[off..off + GLOBAL_ID_LEN]);
                    global_id = Some(gid);
                }
            }
        },
        FrameStatus::Keep => {
            if off < body.len() && body[off] == NETWORK_UDP {
                off += 1;
                let (port, addr, _consumed) = AddressParser::parse_port_address(&body[off..])
                    .ok_or_else(|| PacketError::AddressParseFailed("Keep frame".into()))?;
                target = Some(Destination::udp(addr, port));
            }
        },
        FrameStatus::KeepAlive => {},
    }

    Ok((target, global_id))
}

/// 帧头+地址段字节数上界（bd 1fm1l W5）：`length(2)+session_id(2)+status(1)+
/// opt(1)+network(1)+port(2)+addr_type(1)+addr(16 IPv6 / 1+255 domain)+
/// global_id(8)` = 273，取整留 1B 余量。
pub const MAX_FRAME_OVERHEAD: usize = 4 + 1 + 1 + 1 + 2 + 1 + 256 + 8;

/// 把一个数据报按 XUDP 帧直序进池化 [`Buffer`]（bd 1fm1l W5 UDP 数据面快路径）。
///
/// 与 [`PacketWriter::write_packet`] 逐字节同构（`packet_buffer_matches_writer`
/// 契约测试锁定），但不构造 PacketWriter、不经 meta scratch / `Vec` 中转：meta 由
/// [`FrameMetadata::write_into_buffer`] 直写、载荷随后直写——配合调用方
/// `Buffer::new_pooled` 借还，稳态每数据报 0 次堆分配。New/Keep 状态由调用方
/// 跨包持有（`new_sent`：首次写发 New+GlobalID，其后 Keep），跳过语义同
/// [`PacketWriter::write_packet`]（空载荷 / 超 [`MAX_DATA_LEN`] 静默返回）。
///
/// # Errors
/// `frame` 剩余容量不足容纳整帧（调用方按 `MAX_FRAME_OVERHEAD + 2 + 载荷长`
/// 取池即可满足）时返回 [`PacketError::Io`]——拒绝静默截断（截断帧会打爆读端解析）。
pub fn write_packet_into_buffer(
    frame: &mut Buffer,
    new_sent: &mut bool,
    dest: &Destination,
    global_id: [u8; GLOBAL_ID_LEN],
    data: &[u8],
) -> Result<(), PacketError> {
    if data.is_empty() || data.len() > MAX_DATA_LEN {
        return Ok(());
    }
    let meta = if !*new_sent && dest.network() == Network::UDP {
        *new_sent = true;
        FrameMetadata::new_udp(dest.address().clone(), dest.port(), global_id)
    } else {
        FrameMetadata::keep_udp(dest.address().clone(), dest.port())
    };
    let need = MAX_FRAME_OVERHEAD + 2 + data.len();
    if frame.free() < need {
        return Err(PacketError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("xudp frame buffer too small: free={} need={need}", frame.free()),
        )));
    }
    meta.write_into_buffer(frame);
    frame.write_from(&(data.len() as u16).to_be_bytes());
    frame.write_from(data);
    Ok(())
}

/// XUDP 数据包写入器
///
/// 首次写入发送 New 帧（含目标地址和 GlobalID），后续写入发送 Keep 帧。
pub struct PacketWriter<W> {
    writer: W,
    dest: Destination,
    global_id: [u8; GLOBAL_ID_LEN],
    new_sent: bool,
    /// meta 序列化 scratch（clear + 复用容量，免每包 `Vec` 堆分配）。
    scratch: Vec<u8>,
}

impl<W: Write> PacketWriter<W> {
    /// 创建写入器
    ///
    /// scratch 预留 64B：写路径每包分配基线由 bd 1fm1l W5 的
    /// `framing_allocs_per_packet_ab` A/B 对照锁定；逐包构造 PacketWriter 的
    /// 调用面应改走 [`write_packet_into_buffer`]（池化帧缓冲 + 直序 = 0 分配）。
    #[must_use]
    pub fn new(writer: W, dest: Destination, global_id: [u8; GLOBAL_ID_LEN]) -> Self {
        Self { writer, dest, global_id, new_sent: false, scratch: Vec::with_capacity(64) }
    }

    /// 写入一个数据包
    ///
    /// 空数据或超过最大长度的数据会被静默跳过。
    pub fn write_packet(&mut self, data: &[u8]) -> Result<(), PacketError> {
        if data.is_empty() || data.len() > MAX_DATA_LEN {
            return Ok(());
        }

        if !self.new_sent && self.dest.network() == Network::UDP {
            self.new_sent = true;
            FrameMetadata::new_udp(self.dest.address().clone(), self.dest.port(), self.global_id)
                .write_bytes_into(&mut self.scratch);
        } else {
            FrameMetadata::keep_udp(self.dest.address().clone(), self.dest.port())
                .write_bytes_into(&mut self.scratch);
        }
        self.writer.write_all(&self.scratch)?;

        self.writer.write_all(&(data.len() as u16).to_be_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// 写入一个数据包，使用指定的 UDP 目标地址
    ///
    /// 首次写入仍使用构造时的 `dest`，后续使用传入的 `udp`。
    pub fn write_packet_with_udp_target(
        &mut self,
        data: &[u8],
        udp: &Destination,
    ) -> Result<(), PacketError> {
        if data.is_empty() || data.len() > MAX_DATA_LEN {
            return Ok(());
        }

        if !self.new_sent && self.dest.network() == Network::UDP {
            self.new_sent = true;
            FrameMetadata::new_udp(self.dest.address().clone(), self.dest.port(), self.global_id)
                .write_bytes_into(&mut self.scratch);
        } else {
            FrameMetadata::keep_udp(udp.address().clone(), udp.port())
                .write_bytes_into(&mut self.scratch);
        }
        self.writer.write_all(&self.scratch)?;

        self.writer.write_all(&(data.len() as u16).to_be_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// 返回内部写入器
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// 读取到的数据包
#[derive(Debug, Clone)]
pub struct PacketData {
    data: Vec<u8>,
    udp_target: Option<Destination>,
}

impl PacketData {
    /// 返回数据载荷
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// 返回 UDP 目标地址（仅 Keep 帧有值）
    #[must_use]
    pub fn udp_target(&self) -> Option<&Destination> {
        self.udp_target.as_ref()
    }

    /// 消费数据包，返回数据载荷和可选的 UDP 目标地址
    pub fn into_parts(self) -> (Vec<u8>, Option<Destination>) {
        (self.data, self.udp_target)
    }
}

/// 借用式帧解析结果（`data` 借用调用方缓冲 → 零分配零拷贝）。
///
/// 与写侧对称：`FrameMetadata::write_into_buffer` 直写调用方缓冲 ↔ 本结构
/// 直读调用方缓冲（`parse_packet_slice`）。`target` 仍是拥有值（域名目标含一次
/// `String` 分配，与 `PacketReader::read_packet` 同）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlicePacket<'a> {
    /// 帧内目标/来源地址（`None` = 该帧无地址）。
    pub target: Option<Destination>,
    /// 载荷（**借用**调用方缓冲，不复制）。
    pub data: &'a [u8],
    /// 本帧占用的字节数（调用方据此推进游标 / 清理缓冲；含被跳过的 KeepAlive 帧）。
    pub consumed: usize,
}

/// 从调用方缓冲**就地**解析一个 XUDP 帧（借用语义：不落中间 Vec）。
///
/// 与 [`PacketReader::read_packet`] 同一帧格式、同一元数据解析器
/// （[`FrameMetadata::from_bytes`]），错误分类逐条相同：
/// - 缓冲不足 → [`PacketError::Io`]（`UnexpectedEof`，= 半帧，调用方等更多字节）；
/// - 长度字段 < `MIN_META_LEN` → [`PacketError::MetadataTooShort`]；
/// - 状态字节非法 → [`PacketError::InvalidStatus`]；地址非法 →
///   [`PacketError::AddressParseFailed`]；
/// - KeepAlive 帧自动跳过（与 `read_packet` 同：`consumed` 含被跳过的帧）；
/// - 非数据帧（零长载荷且非 KeepAlive）→ `Ok(None)`（调用方按“流结束”处理）。
///
/// 与 `read_packet` 的两处**刻意**差异（`slice_parse_error_semantics_match_stream_reader`
/// 逐条断言钉住，非放宽校验）：
/// 1. **缓冲耗尽**：流式读端把「没有更多字节」当流结束（`Ok(None)`）；本函数无从 判断流是否结束 →
///    报 `Io(UnexpectedEof)`，由调用方按传输层读到的 EOF 决定终止 （三个调用面都先判 accum 空/读到
///    0 字节再退出，无悬空等待）；
/// 2. **半截字段的 consumed**：只前进到最后一个**完整字段边界**，流式路径已读走的
///    半截字段字节这里保留（`consumed` ≤ `cursor.position()`，绝不吞后续帧的字节）。
///
/// 载荷所有权是另一处差别：`data` 借用入参缓冲，调用方**不得**在 `data` 存活期间
/// 修改该缓冲（典型用法：解析 → 用完 → 再清理）。
///
/// # Errors
/// 见上（错误分类与流式读取路径一致，不放宽任何既有校验）。
pub fn parse_packet_slice(buf: &[u8]) -> Result<Option<SlicePacket<'_>>, PacketError> {
    parse_packet_slice_at(buf).0
}

/// 同 [`parse_packet_slice`]，额外返回「已消费的字节数」（成功与失败都返回）。
///
/// 供调用方在**错误路径**按已消费字节清理缓冲——否则坏帧会留在缓冲里被反复
/// 重解析（同一字节上无限 Err）。与流式路径 `cursor.position()` 的差别见
/// [`parse_packet_slice`] 第 2 条（半截字段不吞）。
///
/// 成功时的返回值：`(Ok(Some(帧)), 帧.consumed)`；`Ok(None)`（非数据帧）时
/// consumed = 该非数据帧已消费的字节数。
pub fn parse_packet_slice_at(buf: &[u8]) -> (Result<Option<SlicePacket<'_>>, PacketError>, usize) {
    let mut off = 0usize;
    loop {
        if buf.len() < off + 2 {
            return (
                Err(PacketError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "xudp frame length",
                ))),
                off,
            );
        }
        let body_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if body_len < MIN_META_LEN {
            return (Err(PacketError::MetadataTooShort(body_len)), off);
        }
        if buf.len() < off + body_len {
            return (
                Err(PacketError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "xudp frame meta",
                ))),
                off,
            );
        }
        let meta_end = off + body_len;
        let (meta, _) = match FrameMetadata::from_bytes(&buf[off - 2..meta_end]) {
            Ok(v) => v,
            Err(e) => return (Err(e), meta_end),
        };
        // New/Keep 帧都带目标地址（Go xudp 读端对两者同样提取）
        let target = meta.target().cloned();
        let mut cur = meta_end;
        if meta.has_data() {
            if buf.len() < cur + 2 {
                return (
                    Err(PacketError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "xudp frame data length",
                    ))),
                    cur,
                );
            }
            let len = u16::from_be_bytes([buf[cur], buf[cur + 1]]) as usize;
            cur += 2;
            if buf.len() < cur + len {
                return (
                    Err(PacketError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "xudp frame data",
                    ))),
                    cur,
                );
            }
            if len > 0 {
                return (
                    Ok(Some(SlicePacket {
                        target,
                        data: &buf[cur..cur + len],
                        consumed: cur + len,
                    })),
                    cur + len,
                );
            }
        }
        if meta.status() == FrameStatus::KeepAlive {
            off = cur;
            continue;
        }
        return (Ok(None), cur);
    }
}

/// XUDP 数据包读取器
pub struct PacketReader<R> {
    reader: R,
    /// 帧读取 scratch（长度前缀 + meta body 复用容量，免每包 `Vec` 堆分配）。
    frame_scratch: Vec<u8>,
}

impl<R: Read> PacketReader<R> {
    /// 创建读取器
    ///
    /// scratch 预留 64B（典型 IPv4/域名 meta 一帧装下，无二次扩容）：读路径
    /// 每帧一次分配的基线由 q1r4q 取证测试锁定（`chain_parse_allocs_per_packet_drop`），
    /// 勿在此改分配行为。
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { reader, frame_scratch: Vec::with_capacity(64) }
    }

    /// 读取一个数据包
    ///
    /// 返回 `Ok(Some(PacketData))` 表示读到有效数据，
    /// `Ok(None)` 表示流结束（UnexpectedEof），
    /// KeepAlive 帧会被自动跳过。
    pub fn read_packet(&mut self) -> Result<Option<PacketData>, PacketError> {
        loop {
            let mut len_buf = [0u8; 2];
            match self.reader.read_exact(&mut len_buf) {
                Ok(()) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e.into()),
            }
            let body_len = u16::from_be_bytes(len_buf) as usize;
            if body_len < MIN_META_LEN {
                return Err(PacketError::MetadataTooShort(body_len));
            }

            // 帧头+meta 读进 scratch（容量跨包复用），解析走 from_bytes
            self.frame_scratch.clear();
            self.frame_scratch.extend_from_slice(&len_buf);
            self.frame_scratch.resize(2 + body_len, 0);
            self.reader.read_exact(&mut self.frame_scratch[2..])?;
            let (meta, _) = FrameMetadata::from_bytes(&self.frame_scratch)?;

            // New/Keep 帧都带目标地址（Go xudp 读端对两者同样提取）
            let udp_target = meta.target().cloned();

            if meta.has_data() {
                let mut dl = [0u8; 2];
                self.reader.read_exact(&mut dl)?;
                let len = u16::from_be_bytes(dl) as usize;
                if len > 0 {
                    let mut data = vec![0u8; len];
                    self.reader.read_exact(&mut data)?;
                    return Ok(Some(PacketData { data, udp_target }));
                }
            }

            if meta.status() == FrameStatus::KeepAlive {
                continue;
            }

            return Ok(None);
        }
    }

    /// 返回内部读取器
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// 辅助：构造 IPv4 Destination
    fn ipv4_dest(ip: &str, port: u16) -> Destination {
        let addr = Address::ipv4(ip.parse().expect("valid ipv4"));
        Destination::udp(addr, Port::new(port))
    }

    /// 辅助：构造 IPv6 Destination
    fn ipv6_dest(ip: &str, port: u16) -> Destination {
        let addr = Address::ipv6(ip.parse().expect("valid ipv6"));
        Destination::udp(addr, Port::new(port))
    }

    /// 辅助：构造 Domain Destination
    fn domain_dest(domain: &str, port: u16) -> Destination {
        let addr = Address::new_domain(domain.to_string());
        Destination::udp(addr, Port::new(port))
    }

    /// 辅助：默认 GlobalID
    fn test_global_id() -> [u8; GLOBAL_ID_LEN] {
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    // ── FrameStatus ──────────────────────────────────────────────

    #[test]
    fn test_frame_status_roundtrip() {
        for status in [FrameStatus::New, FrameStatus::Keep, FrameStatus::KeepAlive] {
            assert_eq!(FrameStatus::from_byte(status.to_byte()), Some(status));
        }
        assert_eq!(FrameStatus::from_byte(0), None);
        assert_eq!(FrameStatus::from_byte(255), None);
    }

    // ── FrameMetadata to_bytes / from_bytes 往返 ────────────────

    #[test]
    fn test_metadata_roundtrip_ipv4() {
        let dest = ipv4_dest("127.0.0.1", 1234);
        let meta = FrameMetadata::new_udp(dest.address().clone(), dest.port(), test_global_id());
        let bytes = meta.to_bytes();
        let (parsed, consumed) = FrameMetadata::from_bytes(&bytes).expect("parse");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.status(), FrameStatus::New);
        assert!(parsed.has_data());
        assert_eq!(parsed.global_id(), Some(&test_global_id()));
        let t = parsed.target().expect("target");
        assert_eq!(t.port(), dest.port());
    }

    #[test]
    fn test_metadata_roundtrip_ipv6() {
        let dest = ipv6_dest("::1", 5678);
        let meta = FrameMetadata::new_udp(dest.address().clone(), dest.port(), test_global_id());
        let bytes = meta.to_bytes();
        let (parsed, consumed) = FrameMetadata::from_bytes(&bytes).expect("parse");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.status(), FrameStatus::New);
        assert_eq!(parsed.global_id(), Some(&test_global_id()));
        let t = parsed.target().expect("target");
        assert_eq!(t.port(), dest.port());
    }

    #[test]
    fn test_metadata_roundtrip_domain() {
        let dest = domain_dest("example.com", 443);
        let meta = FrameMetadata::keep_udp(dest.address().clone(), dest.port());
        let bytes = meta.to_bytes();
        let (parsed, consumed) = FrameMetadata::from_bytes(&bytes).expect("parse");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.status(), FrameStatus::Keep);
        assert!(parsed.has_data());
        assert!(parsed.global_id().is_none());
        let t = parsed.target().expect("target");
        assert_eq!(t.port(), dest.port());
    }

    #[test]
    fn test_metadata_keep_alive() {
        let meta = FrameMetadata::keep_alive();
        let bytes = meta.to_bytes();
        let (parsed, consumed) = FrameMetadata::from_bytes(&bytes).expect("parse");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.status(), FrameStatus::KeepAlive);
        assert!(!parsed.has_data());
        assert!(parsed.target().is_none());
        assert!(parsed.global_id().is_none());
    }

    // ── PacketWriter + PacketReader 往返 ─────────────────────────

    #[test]
    fn test_writer_reader_single_packet() {
        let dest = ipv4_dest("192.168.1.1", 8080);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"hello").expect("write");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(pkt.data(), b"hello");
    }

    #[test]
    fn test_writer_reader_multiple_packets() {
        let dest = ipv4_dest("10.0.0.1", 3000);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"first").expect("write1");
            writer.write_packet(b"second").expect("write2");
            writer.write_packet(b"third").expect("write3");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let p1 = reader.read_packet().expect("read1").expect("some");
        assert_eq!(p1.data(), b"first");

        let p2 = reader.read_packet().expect("read2").expect("some");
        assert_eq!(p2.data(), b"second");

        let p3 = reader.read_packet().expect("read3").expect("some");
        assert_eq!(p3.data(), b"third");

        assert!(reader.read_packet().expect("eof").is_none());
    }

    #[test]
    fn test_writer_reader_ipv6() {
        let dest = ipv6_dest("fe80::1", 9999);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"ipv6 data").expect("write");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(pkt.data(), b"ipv6 data");
    }

    #[test]
    fn test_writer_reader_domain() {
        let dest = domain_dest("test.example.org", 443);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"domain data").expect("write");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(pkt.data(), b"domain data");
    }

    #[test]
    fn test_write_packet_with_udp_target() {
        let dest = ipv4_dest("1.2.3.4", 100);
        let alt = ipv4_dest("5.6.7.8", 200);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"first").expect("w1");
            writer.write_packet_with_udp_target(b"second", &alt).expect("w2");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let p1 = reader.read_packet().expect("r1").expect("some");
        assert_eq!(p1.data(), b"first");

        let p2 = reader.read_packet().expect("r2").expect("some");
        assert_eq!(p2.data(), b"second");
        // 第二个包是 Keep 帧，应携带 udp_target
        assert!(p2.udp_target().is_some());
    }

    #[test]
    fn test_empty_data_skipped() {
        let dest = ipv4_dest("127.0.0.1", 80);
        let mut buf = Vec::new();
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(b"").expect("empty");
            writer.write_packet(b"data").expect("data");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(pkt.data(), b"data");
    }

    // ── 载荷上限 = u16 上限（内部 link 专属；bd zu7tk 撤回 Go wire 侧 7526 抄值）──

    #[test]
    fn max_data_len_is_u16_ceiling() {
        // 历史值 7526 来自 Go **wire 侧** `length+666 > buf.Size(8192)`；Rust 的
        // XUDP 帧只跑内部 dispatch link（隧道/mux 的 wire 表示由各协议 framing
        // 层负责），照抄会让 >7526B 的 UDP 应答在写侧被静默跳过（socks5 UDP
        // 7600B 起全无回包）。上限取 data_len 字段宽度极限。
        assert_eq!(MAX_DATA_LEN, usize::from(u16::MAX));
    }

    #[test]
    fn test_large_packet_roundtrip_past_old_7526_limit() {
        // 8000B（Go 侧正常回显的档位）必须能装帧并读回逐字节一致
        let dest = ipv4_dest("127.0.0.1", 80);
        let mut buf = Vec::new();
        let payload = vec![0xCD_u8; 8_000];
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(&payload).expect("8000B written");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(pkt.data(), &payload[..]);
        assert!(reader.read_packet().expect("eof").is_none());
    }

    #[test]
    fn test_oversized_packet_skipped_go_parity() {
        let dest = ipv4_dest("127.0.0.1", 80);
        let mut buf = Vec::new();
        let boundary = vec![0xAB_u8; MAX_DATA_LEN];
        let oversized = vec![0xCD_u8; MAX_DATA_LEN + 1];
        {
            let mut writer = PacketWriter::new(&mut buf, dest.clone(), test_global_id());
            writer.write_packet(&oversized).expect("oversized silently skipped");
            writer.write_packet(&boundary).expect("boundary written");
        }

        let mut reader = PacketReader::new(Cursor::new(buf));
        let pkt = reader.read_packet().expect("read").expect("some");
        assert_eq!(
            pkt.data().len(),
            MAX_DATA_LEN,
            "上限通过；上限+1 静默跳过（Go continue 同语义）"
        );
        assert!(reader.read_packet().expect("eof").is_none());
    }

    // ── 错误场景 ─────────────────────────────────────────────────

    #[test]
    fn test_from_bytes_too_short() {
        let result = FrameMetadata::from_bytes(&[0x00]);
        assert!(matches!(result, Err(PacketError::MetadataTooShort(1))));

        let result = FrameMetadata::from_bytes(&[0x00, 0x04, 0x00, 0x00]);
        assert!(matches!(result, Err(PacketError::MetadataTooShort(_))));
    }

    #[test]
    fn test_from_bytes_invalid_status() {
        // length=4, session_id=0, status=0x99 (invalid), opt=0
        let data: &[u8] = &[0x00, 0x04, 0x00, 0x00, 0x99, 0x00];
        let result = FrameMetadata::from_bytes(data);
        assert!(matches!(result, Err(PacketError::InvalidStatus(0x99))));
    }

    #[test]
    fn test_reader_eof() {
        let mut reader = PacketReader::new(Cursor::new(Vec::<u8>::new()));
        let result = reader.read_packet().expect("read");
        assert!(result.is_none());
    }

    /// bd 1fm1l W5 契约：`write_packet_into_buffer` 与 `PacketWriter` 逐字节同构
    /// （多目标 / 多载荷 / IPv6 / 域名 / 空载荷跳过 / New→Keep 序）。快路径是
    /// 「一数据报一缓冲」语义（写入前清空 frame），逐帧对比 writer 的输出切片。
    #[test]
    fn packet_buffer_matches_writer_byte_for_byte() {
        let gid = test_global_id();
        let dests = [
            ipv4_dest("10.0.0.1", 53),
            ipv6_dest("fe80::7", 5353),
            domain_dest("a.example.org", 443),
        ];
        let payloads: [&[u8]; 4] = [b"first-query", b"", b"third-query", &[0xAB_u8; 8000]];

        // PacketWriter 基准：4 帧连写进同一 Vec。
        let mut writer_out = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut writer_out, dests[0].clone(), gid);
            pw.write_packet(payloads[0]).expect("write 0");
            pw.write_packet(payloads[1]).expect("write 1（空载荷跳过）");
            pw.write_packet_with_udp_target(payloads[2], &dests[1]).expect("write 2");
            pw.write_packet_with_udp_target(payloads[3], &dests[2]).expect("write 3");
        }

        // 快路径：同一序列，逐帧独立缓冲（一数据报一缓冲语义）后拼接。
        // writer 侧 New 只在帧 0（dests[0]），其后 Keep 用逐帧目标（帧 1 空载荷
        // 被跳过，目标无所谓）→ 帧目标映射 [0,0,1,2]，new_sent 映射 [F,T,T,T]。
        let frame_dests = [dests[0].clone(), dests[0].clone(), dests[1].clone(), dests[2].clone()];
        let mut fast_out = Vec::new();
        for i in 0..4 {
            let mut frame = Buffer::new_pooled(MAX_FRAME_OVERHEAD + 2 + payloads[i].len());
            let mut new_sent = i != 0;
            write_packet_into_buffer(&mut frame, &mut new_sent, &frame_dests[i], gid, payloads[i])
                .expect("fast frame");
            fast_out.extend_from_slice(frame.bytes());
        }

        assert_eq!(fast_out, writer_out, "快路径必须与 PacketWriter 逐字节一致");
    }

    /// 帧缓冲容量不足必须显式报错，不得静默截断（截断帧打爆读端解析）。
    #[test]
    fn packet_buffer_rejects_undersized_frame() {
        let dest = ipv4_dest("10.0.0.9", 53);
        let payload = [0x5A_u8; 512];
        let mut frame = Buffer::with_capacity(64); // 精确容量 < MAX_FRAME_OVERHEAD+2+512
        let mut new_sent = false;
        let r =
            write_packet_into_buffer(&mut frame, &mut new_sent, &dest, test_global_id(), &payload);
        assert!(r.is_err(), "undersized frame buffer must error, not truncate");
        assert!(frame.bytes().is_empty(), "报错路径不得写入半个帧");
    }

    /// 写入后的帧必须能被 PacketReader 原样读回（快路径 → 读端闭环）。
    #[test]
    fn packet_buffer_roundtrips_through_reader() {
        let dest = ipv4_dest("10.0.0.3", 9999);
        let payload = b"roundtrip-payload";
        let mut frame = Buffer::new_pooled(MAX_FRAME_OVERHEAD + 2 + payload.len());
        let mut new_sent = false;
        write_packet_into_buffer(&mut frame, &mut new_sent, &dest, test_global_id(), payload)
            .expect("frame");
        let mut reader = PacketReader::new(Cursor::new(frame.bytes().to_vec()));
        let pkt = reader.read_packet().expect("read").expect("packet");
        let (data, target) = pkt.into_parts();
        assert_eq!(data.as_slice(), payload.as_slice());
        assert_eq!(target.as_ref(), Some(&dest));
    }

    // ===== bd 1fm1l W5：帧化路径分配数 A/B 对照（无 IO 噪声，单线程确定）=====

    // 计数分配器：只统计测量窗口内、当前线程的堆分配次数（thread_local const
    // 初始化 = 无惰性分配 = 无重入）。
    thread_local! {
        static AB_MEASURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static AB_ALLOCS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    struct CountingAlloc;

    unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            if AB_MEASURE.with(|m| m.get()) {
                AB_ALLOCS.with(|c| c.set(c.get() + 1));
            }
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
            unsafe { std::alloc::System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(
            &self,
            ptr: *mut u8,
            layout: std::alloc::Layout,
            new_size: usize,
        ) -> *mut u8 {
            if AB_MEASURE.with(|m| m.get()) {
                AB_ALLOCS.with(|c| c.set(c.get() + 1));
            }
            unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static FRAME_PROOF_ALLOC: CountingAlloc = CountingAlloc;

    /// 帧化每包堆分配 A/B：旧形态（逐包 `PacketWriter::new` + 临时 Vec，修前
    /// freedom/socks pump_response 的每包形态）≥ 3 次/包；新快路径
    /// （`write_packet_into_buffer` + 池化帧缓冲借还）= 0 次/包。
    // 取证数字须打印（同 xray-app-dispatcher q1r4q 先例：显式 allow + 理由）。
    #[allow(clippy::print_stdout)]
    #[test]
    fn framing_allocs_per_packet_ab() {
        const WARMUP: usize = 64;
        const N: usize = 256;

        let gid = test_global_id();
        let dest = ipv4_dest("10.0.0.7", 53);
        let payload = [0x77_u8; 512];

        // B（新快路径）先预热：池块进入本线程 TLS 缓存，稳态零新鲜分配。
        for _ in 0..WARMUP {
            let mut frame = Buffer::new_pooled(MAX_FRAME_OVERHEAD + 2 + payload.len());
            let mut sent = false;
            write_packet_into_buffer(&mut frame, &mut sent, &dest, gid, &payload)
                .expect("fast frame");
            std::hint::black_box(frame.bytes());
        }

        AB_MEASURE.with(|m| m.set(true));
        AB_ALLOCS.with(|c| c.set(0));
        for _ in 0..N {
            let mut frame = Buffer::new_pooled(MAX_FRAME_OVERHEAD + 2 + payload.len());
            let mut sent = false;
            write_packet_into_buffer(&mut frame, &mut sent, &dest, gid, &payload)
                .expect("fast frame");
            std::hint::black_box(frame.bytes());
        }
        let b_allocs = AB_ALLOCS.with(|c| c.get());

        // A（旧形态）：每包新建 PacketWriter + 临时 Vec 装帧。
        AB_ALLOCS.with(|c| c.set(0));
        for _ in 0..N {
            let mut frame = Vec::new();
            {
                let mut pw = PacketWriter::new(&mut frame, dest.clone(), gid);
                pw.write_packet(&payload).expect("writer frame");
            }
            std::hint::black_box(&frame);
        }
        let a_allocs = AB_ALLOCS.with(|c| c.get());
        AB_MEASURE.with(|m| m.set(false));

        println!(
            "framing allocs/packet over {N} pkts: old(PacketWriter per-packet + temp Vec) = \
             {a_allocs} ({:.2}/pkt), new(into_buffer + pooled) = {b_allocs} ({:.2}/pkt)",
            a_allocs as f64 / N as f64,
            b_allocs as f64 / N as f64
        );
        assert_eq!(b_allocs, 0, "新快路径稳态必须 0 堆分配/包（实测 {b_allocs}/{N}）");
        assert!(
            a_allocs >= 3 * N as u64,
            "旧形态对照基准应 ≥3 次分配/包（实测 {a_allocs}/{N} = {:.2}/包）",
            a_allocs as f64 / N as f64
        );
    }

    /// bd lppdz：**解析侧**分配 A/B（同 harness 口径）。
    ///
    /// 旧形态（流式 `PacketReader`）：每帧 1 次 scratch Vec + 1 次载荷 Vec = 2 次
    /// 分配 + 2 次拷贝；新形态（借用式 `parse_packet_slice`）：0 分配 0 拷贝
    /// （载荷借用调用方缓冲）。与写侧 `write_into_buffer` 对称。
    #[allow(clippy::print_stdout)]
    #[test]
    fn parse_allocs_per_packet_ab() {
        const WARMUP: usize = 64;
        const N: usize = 256;

        let dest = ipv4_dest("10.0.0.7", 53);
        let payload = [0x77_u8; 512];
        // 构造一帧 xudp 帧（meta + data_len + data）——与写侧同布局
        let mut wire = Vec::new();
        FrameMetadata::new_udp(dest.address().clone(), dest.port(), test_global_id())
            .write_bytes_into(&mut wire);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&payload);

        // B（新借用式解析）预热 + 计量
        for _ in 0..WARMUP {
            let pkt = parse_packet_slice(&wire).expect("parse").expect("packet");
            std::hint::black_box(pkt.data);
        }
        AB_MEASURE.with(|m| m.set(true));
        AB_ALLOCS.with(|c| c.set(0));
        for _ in 0..N {
            let pkt = parse_packet_slice(&wire).expect("parse").expect("packet");
            std::hint::black_box(pkt.data);
        }
        let b_allocs = AB_ALLOCS.with(|c| c.get());

        // A（旧流式解析）：PacketReader::new（scratch）+ read_packet（载荷 Vec）
        AB_ALLOCS.with(|c| c.set(0));
        for _ in 0..N {
            let mut cursor = Cursor::new(wire.as_slice());
            let mut pr = PacketReader::new(&mut cursor);
            let pkt = pr.read_packet().expect("read").expect("packet");
            std::hint::black_box(pkt.data());
        }
        let a_allocs = AB_ALLOCS.with(|c| c.get());
        AB_MEASURE.with(|m| m.set(false));

        println!(
            "parse allocs/packet over {N} pkts: old(PacketReader scratch + payload Vec) = \
             {a_allocs} ({:.2}/pkt), new(slice borrow) = {b_allocs} ({:.2}/pkt)",
            a_allocs as f64 / N as f64,
            b_allocs as f64 / N as f64
        );
        assert_eq!(b_allocs, 0, "借用式解析稳态必须 0 堆分配/包（实测 {b_allocs}/{N}）");
        assert!(
            a_allocs >= 2 * N as u64,
            "旧形态对照基准应 ≥2 次分配/包（实测 {a_allocs}/{N} = {:.2}/包）",
            a_allocs as f64 / N as f64
        );
    }

    /// 借用式解析与流式解析语义一致（同帧 → 同 target/data/consumed）。
    #[test]
    fn slice_parse_matches_stream_reader_semantics() {
        let dest = ipv4_dest("10.0.0.7", 53);
        let payload = b"slice-parse-payload";
        let mut wire = Vec::new();
        FrameMetadata::new_udp(dest.address().clone(), dest.port(), test_global_id())
            .write_bytes_into(&mut wire);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);

        let sliced = parse_packet_slice(&wire).expect("parse").expect("packet");
        let mut cursor = Cursor::new(wire.as_slice());
        let mut pr = PacketReader::new(&mut cursor);
        let streamed = pr.read_packet().expect("read").expect("packet");

        assert_eq!(sliced.data, streamed.data());
        assert_eq!(sliced.target, streamed.udp_target().cloned());
        assert_eq!(sliced.consumed, wire.len());
    }

    /// 新旧 API 错误语义逐条对照（bd lppdz，不许「换实现顺带放宽校验」）：
    /// 同一段字节上 `parse_packet_slice_at` 与流式 `PacketReader::read_packet`
    /// 必须给出**同一分类**，且 `consumed` 必须等于流式路径的
    /// `cursor.position()`——错误路径的数字同样要对齐，否则调用方按 consumed
    /// 清缓冲时会与旧路径 drain 不同字节（坏帧滞留 → qyn8 类忙旋，或过量丢弃）。
    #[test]
    fn slice_parse_error_semantics_match_stream_reader() {
        /// 分类（不含载荷，便于跨两 API 比对）
        #[derive(Debug, PartialEq, Eq)]
        enum Sem {
            Data,
            NoFrame,
            IoEof,
            TooShort(usize),
            BadStatus(u8),
            BadAddr,
        }

        fn classify(r: &Result<Option<()>, PacketError>) -> Sem {
            match r {
                Ok(Some(())) => Sem::Data,
                Ok(None) => Sem::NoFrame,
                Err(PacketError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    Sem::IoEof
                },
                Err(PacketError::MetadataTooShort(n)) => Sem::TooShort(*n),
                Err(PacketError::InvalidStatus(b)) => Sem::BadStatus(*b),
                Err(PacketError::AddressParseFailed(_)) => Sem::BadAddr,
                Err(PacketError::Io(_)) => panic!("非 EOF 的 IO 错误不在对照表内"),
            }
        }

        fn old_sem(bytes: &[u8]) -> (Sem, usize) {
            let mut cursor = Cursor::new(bytes);
            let r = {
                let mut pr = PacketReader::new(&mut cursor);
                pr.read_packet()
            };
            let mapped = r.map(|o| o.map(|_| ()));
            (classify(&mapped), cursor.position() as usize)
        }

        fn new_sem(bytes: &[u8]) -> (Sem, usize) {
            let (r, consumed) = parse_packet_slice_at(bytes);
            let mapped = r.map(|o| o.map(|_| ()));
            (classify(&mapped), consumed)
        }

        // 构造裸帧：body = session_id(2) + status + opt + tail，前缀 body 长度
        let frame = |status: u8, opt: u8, tail: &[u8]| -> Vec<u8> {
            let mut body = vec![0u8, 0, status, opt];
            body.extend_from_slice(tail);
            let mut w = (body.len() as u16).to_be_bytes().to_vec();
            w.extend_from_slice(&body);
            w
        };

        // 一条完整数据帧（真实写端构造，作正例）
        let dest = ipv4_dest("10.0.0.7", 53);
        let payload = b"semantics";
        let mut good = Vec::new();
        FrameMetadata::new_udp(dest.address().clone(), dest.port(), test_global_id())
            .write_bytes_into(&mut good);
        good.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        good.extend_from_slice(payload);

        // 数据长度字段只到了 1B
        let mut dl_trunc = frame(2, 0x01, &[2, 0x00, 53, 1, 127, 0, 0, 1]);
        dl_trunc.push(0x00);
        // 数据体截断：声明 16B 实到 4B
        let mut data_trunc = frame(2, 0x01, &[2, 0x00, 53, 1, 127, 0, 0, 1]);
        data_trunc.extend_from_slice(&16u16.to_be_bytes());
        data_trunc.extend_from_slice(&[0u8; 4]);
        // 零长数据 + 非 KeepAlive status → 协议层终止帧（Ok(None)）
        let mut zero_data = frame(2, 0x01, &[2, 0x00, 53, 1, 127, 0, 0, 1]);
        zero_data.extend_from_slice(&0u16.to_be_bytes());
        // KeepAlive 后再无字节（缓冲耗尽）
        let keepalive_tail = frame(4, 0x00, &[]);

        /// 对照用例：`stray` = 流式路径额外吃掉的半截字段字节数（0 = 两条路径
        /// consumed 必须逐字节相同）。
        struct Case {
            name: &'static str,
            bytes: Vec<u8>,
            stray: usize,
        }

        let cases: Vec<Case> = vec![
            Case { name: "完整数据帧", bytes: good, stray: 0 },
            Case {
                name: "半帧：长度头声明 32B meta，实到 0B", bytes: vec![0x00, 0x20], stray: 0
            },
            Case { name: "长度字段 < MIN_META_LEN", bytes: vec![0x00, 0x01, 0x00], stray: 0 },
            Case { name: "status 字节非法", bytes: frame(0x99, 0x01, &[]), stray: 0 },
            Case {
                name: "地址字段缺失（New 帧 net=UDP 但无 port/addr）",
                bytes: frame(1, 0x01, &[2]),
                stray: 0,
            },
            Case { name: "数据长度字段截断（2B 只到 1B）", bytes: dl_trunc, stray: 1 },
            Case { name: "数据体截断（声明 16B 实到 4B）", bytes: data_trunc, stray: 4 },
            Case {
                name: "零长数据非 KeepAlive（协议层终止帧）", bytes: zero_data, stray: 0
            },
        ];

        for c in &cases {
            let (old_kind, old_pos) = old_sem(&c.bytes);
            let (new_kind, new_consumed) = new_sem(&c.bytes);
            assert_eq!(old_kind, new_kind, "{}: 错误分类与流式路径不一致", c.name);
            if c.stray == 0 {
                assert_eq!(old_pos, new_consumed, "{}: consumed 与 cursor.position 不一致", c.name);
            } else {
                // 半截字段：流式读端把半截字段的字节也读走了（cursor 前进到出错点），
                // 缓冲解析端只前进到最后一个**完整字段边界** —— stray 字节留给下一轮。
                assert_eq!(
                    old_pos,
                    c.bytes.len(),
                    "{}: 流式路径应吃掉全部字节（含半截字段）",
                    c.name
                );
                assert_eq!(
                    new_consumed,
                    c.bytes.len() - c.stray,
                    "{}: 新路径应只前进到完整字段边界（不吞半截字段）",
                    c.name
                );
            }
        }

        // 显式钉住具体分类（防两条路径一起跑偏）
        assert_eq!(new_sem(&cases[0].bytes).0, Sem::Data);
        assert_eq!(new_sem(&cases[1].bytes).0, Sem::IoEof);
        assert_eq!(new_sem(&cases[2].bytes).0, Sem::TooShort(1));
        assert_eq!(new_sem(&cases[3].bytes).0, Sem::BadStatus(0x99));
        assert_eq!(new_sem(&cases[4].bytes).0, Sem::BadAddr);
        assert_eq!(new_sem(&cases[5].bytes).0, Sem::IoEof);
        assert_eq!(new_sem(&cases[6].bytes).0, Sem::IoEof);
        assert_eq!(new_sem(&cases[7].bytes).0, Sem::NoFrame);

        // 唯一一处设计差异（不是放宽，是职责分层）：**缓冲耗尽**。
        // 流式读端把「没有更多字节」当流结束（Ok(None)），缓冲解析端无从判断
        // 流是否结束 → 必须报「需要更多字节」（Io/UnexpectedEof），由调用方按
        // 传输层读到的 EOF 决定终止。三个调用面都已按此接线（accum 为空不解析；
        // 半帧 → 继续读；read==0 → 会话结束），故无悬空等待。
        for bytes in [&[][..], &[0x00][..], &keepalive_tail[..]] {
            assert_eq!(old_sem(bytes).0, Sem::NoFrame, "旧路径把耗尽当 EOF");
            assert_eq!(new_sem(bytes).0, Sem::IoEof, "新路径把耗尽当「需要更多字节」");
        }
    }
}
