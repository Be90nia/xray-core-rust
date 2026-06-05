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
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::protocol::address_parser::{AddressParser, AddressSerializer};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPT_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;
const MIN_META_LEN: usize = 4;
const GLOBAL_ID_LEN: usize = 8;
const MAX_DATA_LEN: usize = 2_097_152 - 666;

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
        Self {
            status: FrameStatus::KeepAlive,
            has_data: false,
            target: None,
            global_id: None,
        }
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
        // 占位 length(2B) + session_id(2B=0)
        buf.extend_from_slice(&[0u8; 4]);
        // status
        buf.push(self.status.to_byte());
        // opt
        buf.push(if self.has_data { OPT_DATA } else { 0 });
        // target
        if let Some(ref t) = self.target {
            if t.network() == Network::UDP {
                buf.push(NETWORK_UDP);
                let mut addr_buf = Buffer::with_capacity(32);
                AddressSerializer::write_port_address(&mut addr_buf, t.port(), t.address());
                buf.extend_from_slice(addr_buf.bytes());
            }
        }
        // GlobalID（仅 New 帧）
        if self.status == FrameStatus::New {
            if let Some(ref gid) = self.global_id {
                buf.extend_from_slice(gid);
            }
        }
        // 回写 length = body 长度（不含 length 字段自身）
        let body_len = (buf.len() - 2) as u16;
        buf[0..2].copy_from_slice(&body_len.to_be_bytes());
        buf
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
        let status = FrameStatus::from_byte(status_byte)
            .ok_or(PacketError::InvalidStatus(status_byte))?;
        let has_data = (body[3] & OPT_DATA) != 0;

        let (target, global_id) = parse_body_target(body, status)?;

        Ok((
            Self {
                status,
                has_data,
                target,
                global_id,
            },
            2 + body_len,
        ))
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
        let status = FrameStatus::from_byte(status_byte)
            .ok_or(PacketError::InvalidStatus(status_byte))?;
        let has_data = (body[3] & OPT_DATA) != 0;

        let (target, global_id) = parse_body_target(&body, status)?;

        Ok(Self {
            status,
            has_data,
            target,
            global_id,
        })
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
                let (port, addr, consumed) =
                    AddressParser::parse_port_address(&body[off..]).ok_or_else(|| {
                        PacketError::AddressParseFailed("New frame".into())
                    })?;
                target = Some(Destination::udp(addr, port));
                off += consumed;

                if off + GLOBAL_ID_LEN <= body.len() {
                    let mut gid = [0u8; GLOBAL_ID_LEN];
                    gid.copy_from_slice(&body[off..off + GLOBAL_ID_LEN]);
                    global_id = Some(gid);
                }
            }
        }
        FrameStatus::Keep => {
            if off < body.len() && body[off] == NETWORK_UDP {
                off += 1;
                let (port, addr, _consumed) =
                    AddressParser::parse_port_address(&body[off..]).ok_or_else(|| {
                        PacketError::AddressParseFailed("Keep frame".into())
                    })?;
                target = Some(Destination::udp(addr, port));
            }
        }
        FrameStatus::KeepAlive => {}
    }

    Ok((target, global_id))
}

/// XUDP 数据包写入器
///
/// 首次写入发送 New 帧（含目标地址和 GlobalID），后续写入发送 Keep 帧。
pub struct PacketWriter<W> {
    writer: W,
    dest: Destination,
    global_id: [u8; GLOBAL_ID_LEN],
    new_sent: bool,
}

impl<W: Write> PacketWriter<W> {
    /// 创建写入器
    #[must_use]
    pub fn new(writer: W, dest: Destination, global_id: [u8; GLOBAL_ID_LEN]) -> Self {
        Self {
            writer,
            dest,
            global_id,
            new_sent: false,
        }
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
            FrameMetadata::new_udp(
                self.dest.address().clone(),
                self.dest.port(),
                self.global_id,
            )
            .write_to(&mut self.writer)?;
        } else {
            FrameMetadata::keep_udp(self.dest.address().clone(), self.dest.port())
                .write_to(&mut self.writer)?;
        }

        self.writer
            .write_all(&(data.len() as u16).to_be_bytes())?;
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
            FrameMetadata::new_udp(
                self.dest.address().clone(),
                self.dest.port(),
                self.global_id,
            )
            .write_to(&mut self.writer)?;
        } else {
            FrameMetadata::keep_udp(udp.address().clone(), udp.port())
                .write_to(&mut self.writer)?;
        }

        self.writer
            .write_all(&(data.len() as u16).to_be_bytes())?;
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

/// XUDP 数据包读取器
pub struct PacketReader<R> {
    reader: R,
}

impl<R: Read> PacketReader<R> {
    /// 创建读取器
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// 读取一个数据包
    ///
    /// 返回 `Ok(Some(PacketData))` 表示读到有效数据，
    /// `Ok(None)` 表示流结束（UnexpectedEof），
    /// KeepAlive 帧会被自动跳过。
    pub fn read_packet(&mut self) -> Result<Option<PacketData>, PacketError> {
        loop {
            let meta = match FrameMetadata::read_from(&mut self.reader) {
                Ok(m) => m,
                Err(PacketError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(None)
                }
                Err(e) => return Err(e),
            };

            let udp_target = if meta.status() == FrameStatus::Keep {
                meta.target().cloned()
            } else {
                None
            };

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
    use super::*;
    use std::io::Cursor;

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
        let meta = FrameMetadata::new_udp(
            dest.address().clone(),
            dest.port(),
            test_global_id(),
        );
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
        let meta = FrameMetadata::new_udp(
            dest.address().clone(),
            dest.port(),
            test_global_id(),
        );
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
        let meta = FrameMetadata::keep_udp(
            dest.address().clone(),
            dest.port(),
        );
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
}

