//! Mux 帧格式定义与序列化
//!
//! 对应 Go 版本 `common/mux/frame.go` 和 `common/mux/protocol.go`，
//! 定义 Mux 多路复用协议的帧元数据结构及其线格式编解码。
//!
//! # 线格式
//!
//! ```text
//! 2 bytes - length (大端序, 后续内容长度)
//! 2 bytes - session id (大端序)
//! 1 byte  - session status
//! 1 byte  - option (bitmask)
//!
//! // 仅当 SessionStatus == New 时:
//! 1 byte  - target network (TCP=0x01, UDP=0x02)
//! port(2B BE) + address(variable)  // PortThenAddress 格式
//!
//! // 当 SessionStatus == Keep 且第5字节 == UDP 时:
//! 1 byte  - target network
//! port(2B BE) + address(variable)
//! ```

use std::io::{self, Read, Write};

use xray_buf::buffer::Buffer;
use xray_common::{
    bitmask::Bitmask,
    net::{address::Address, destination::Destination, network::Network},
    protocol::address_parser::{AddressParser, AddressSerializer},
    serial,
};

// ========== 协议常量 ==========

/// 帧元数据最大长度（字节）。
pub(crate) const MAX_METADATA_LEN: usize = 512;

/// Option 位掩码：数据帧。
pub const OPTION_DATA: u8 = 0x01;

/// Option 位掩码：错误帧。
pub const OPTION_ERROR: u8 = 0x02;

// ========== 枚举类型 ==========

/// Mux 会话状态。
///
/// 对应 Go 版本 `SessionStatus`，标识帧在会话生命周期中的角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionStatus {
    /// 新建会话，携带目标地址。
    New = 0x01,
    /// 保持会话，可携带数据或 UDP 目标更新。
    Keep = 0x02,
    /// 结束会话。
    End = 0x03,
    /// 保活心跳。
    KeepAlive = 0x04,
}

impl SessionStatus {
    /// 从线格式字节值解析会话状态。
    ///
    /// 返回 `None` 如果字节值不对应任何有效状态。
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::New),
            0x02 => Some(Self::Keep),
            0x03 => Some(Self::End),
            0x04 => Some(Self::KeepAlive),
            _ => None,
        }
    }

    /// 转换为线格式字节值。
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Mux 数据类型。
///
/// 对应 Go 版本 `DataType`，区分流式和包式传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DataType {
    /// 流式数据（TCP）。
    Stream = 0x01,
    /// 包式数据（UDP）。
    Packet = 0x02,
}

impl DataType {
    /// 从线格式字节值解析数据类型。
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Stream),
            0x02 => Some(Self::Packet),
            _ => None,
        }
    }

    /// 转换为线格式字节值。
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// 从网络类型推断数据类型。
    #[must_use]
    pub fn from_network(network: Network) -> Option<Self> {
        match network {
            Network::TCP => Some(Self::Stream),
            Network::UDP => Some(Self::Packet),
            Network::Unix => None,
        }
    }
}

/// 线格式目标网络标识。
///
/// 在帧线格式中，网络类型用单字节表示：TCP=0x01, UDP=0x02。
/// 这与 [`Network`] 枚举不同，后者还包含 Unix 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TargetNetwork {
    /// TCP 网络。
    TCP = 0x01,
    /// UDP 网络。
    UDP = 0x02,
}

impl TargetNetwork {
    /// 从线格式字节值解析。
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::TCP),
            0x02 => Some(Self::UDP),
            _ => None,
        }
    }

    /// 转换为线格式字节值。
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// 从 [`Network`] 转换，Unix 类型返回 `None`。
    #[must_use]
    pub fn from_network(network: Network) -> Option<Self> {
        match network {
            Network::TCP => Some(Self::TCP),
            Network::UDP => Some(Self::UDP),
            Network::Unix => None,
        }
    }

    /// 转换为 [`Network`]。
    #[must_use]
    pub fn to_network(self) -> Network {
        match self {
            Self::TCP => Network::TCP,
            Self::UDP => Network::UDP,
        }
    }
}

// ========== 错误类型 ==========

/// Mux 帧协议错误。
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum MuxError {
    /// 帧元数据长度超过最大限制 (512 字节)。
    #[error("metadata length {0} exceeds maximum {MAX_METADATA_LEN}")]
    MetadataTooLong(usize),
    /// 无效的会话状态字节值。
    #[error("invalid session status byte: 0x{0:02X}")]
    InvalidSessionStatus(u8),
    /// 无效的目标网络字节值。
    #[error("invalid target network byte: 0x{0:02X}")]
    InvalidTargetNetwork(u8),
    /// 地址解析失败。
    #[error("failed to parse address from frame data")]
    AddressParseFailed,
    /// I/O 读写错误。
    #[error("I/O error: {0}")]
    Io(String),
    /// 帧数据不足，无法解析完整元数据。
    #[error("insufficient data: expected {expected} bytes, got {actual}")]
    InsufficientData {
        /// 期望的字节数。
        expected: usize,
        /// 实际可用的字节数。
        actual: usize,
    },
}

impl From<io::Error> for MuxError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

// ========== 内部辅助函数 ==========

/// 将目标地址写入 Vec<u8>（线格式：network + port + address）。
///
/// 域名超长（>255，u8 len 前缀装不下）报错——修复前 addr_buf(32B) 会
/// 静默截断域名，写出 len 与数据不符的坏帧（bd n43f desync 根源）。
fn write_target_to_vec(buf: &mut Vec<u8>, target: &Destination) -> Result<(), MuxError> {
    // Go 写帧直接编码 network string（无 panic 路径）；Unix 目标在 Rust 侧
    // 无法编码为线格式单字节，显式拒绝而非 panic（远程可达：Unix 入站目标
    // 经 mux 转发即触发）。
    let net = TargetNetwork::from_network(target.network()).ok_or_else(|| {
        MuxError::Io(format!("unsupported mux target network: {:?}", target.network()))
    })?;
    buf.push(net.to_byte());

    // 按地址实际线格式精确预分配，杜绝 Buffer 截断：
    // port(2) + type(1) + [IPv4 4 | IPv6 16 | len(1)+domain]
    let addr_wire_len = match target.address() {
        Address::IPv4(_) => 4,
        Address::IPv6(_) => 16,
        Address::Domain(d) => {
            if d.len() > 255 {
                return Err(MuxError::MetadataTooLong(4 + 3 + d.len()));
            }
            1 + d.len()
        },
    };
    let mut addr_buf = Buffer::with_capacity(2 + 1 + addr_wire_len);
    AddressSerializer::write_port_address(&mut addr_buf, target.port(), target.address());
    buf.extend_from_slice(addr_buf.bytes());
    Ok(())
}

/// 从字节切片读取目标地址（线格式：network + port + address）。
///
/// 返回 `(Destination, consumed_bytes)`。
fn read_target(data: &[u8]) -> Result<(Destination, usize), MuxError> {
    if data.is_empty() {
        return Err(MuxError::InsufficientData { expected: 1, actual: 0 });
    }

    let net =
        TargetNetwork::from_byte(data[0]).ok_or_else(|| MuxError::InvalidTargetNetwork(data[0]))?;
    let network = net.to_network();

    // PortThenAddress 格式：port(2B) + address(variable)
    let (port, addr, addr_consumed) =
        AddressParser::parse_port_address(&data[1..]).ok_or(MuxError::AddressParseFailed)?;

    let target = Destination::new(addr, port, network);
    Ok((target, 1 + addr_consumed))
}

/// Reverse-mux source/local 写出（Go frame.go:88-99）。
///
/// local 嵌套于 source 网络有效时；Unix 网络视同无效跳过（Go 仅判
/// TCP/UDP）。
fn write_inbound_to_vec(
    buf: &mut Vec<u8>,
    source: &Destination,
    local: Option<&Destination>,
) -> Result<(), MuxError> {
    if TargetNetwork::from_network(source.network()).is_none() {
        return Ok(());
    }
    write_target_to_vec(buf, source)?;
    if let Some(local) = local {
        if TargetNetwork::from_network(local.network()).is_some() {
            write_target_to_vec(buf, local)?;
        }
    }
    Ok(())
}

/// 解析 Reverse-mux New 帧的 source/local（Go frame.go:167-213）。
///
/// 逐段可选：剩余字节耗尽或 network 字节为 0（padding，Go :174-175/:195-196）
/// 即终止；心跳等空帧 target 后无内容（Go :170-171）。
fn parse_source_and_local(meta: &mut FrameMetadata, data: &[u8]) -> Result<(), MuxError> {
    let mut offset = 0;
    if offset >= data.len() || data[offset] == 0 {
        return Ok(());
    }
    let (source, consumed) = read_target(&data[offset..])?;
    meta.source = Some(source);
    offset += consumed;
    if offset >= data.len() || data[offset] == 0 {
        return Ok(());
    }
    let (local, _) = read_target(&data[offset..])?;
    meta.local = Some(local);
    Ok(())
}

// ========== 帧元数据 ==========

/// Mux 帧元数据。
///
/// 对应 Go 版本 `FrameMetadata`，描述一个 Mux 帧的控制信息。
/// 帧元数据在线格式中以长度前缀编码，后接可选的目标地址信息。
#[derive(Debug, Clone, PartialEq)]
pub struct FrameMetadata {
    /// 会话 ID。
    session_id: u16,
    /// 会话状态。
    session_status: SessionStatus,
    /// 选项位掩码（Data/Error）。
    option: Bitmask,
    /// 目标地址，仅在 New 状态或 Keep+UDP 时存在。
    target: Option<Destination>,
    /// Reverse-mux 入站源地址（Go `FrameMetadata.Inbound.Source`）。
    source: Option<Destination>,
    /// Reverse-mux 入站本地地址（Go `FrameMetadata.Inbound.Local`）。
    local: Option<Destination>,
    /// 全局 ID，用于 UDP 会话的源追踪（8 字节）。
    global_id: Option<[u8; 8]>,
}

impl FrameMetadata {
    /// 创建新的帧元数据。
    #[must_use]
    pub fn new(session_id: u16, session_status: SessionStatus, option: Bitmask) -> Self {
        Self {
            session_id,
            session_status,
            option,
            target: None,
            global_id: None,
            source: None,
            local: None,
        }
    }

    /// 创建 New 状态的帧元数据，携带目标地址。
    #[must_use]
    pub fn new_session(session_id: u16, target: Destination) -> Self {
        let mut option = Bitmask::default();
        option.set(OPTION_DATA);
        Self {
            session_id,
            session_status: SessionStatus::New,
            option,
            target: Some(target),
            global_id: None,
            source: None,
            local: None,
        }
    }

    /// 创建 End 状态的帧元数据。
    #[must_use]
    pub fn end_session(session_id: u16) -> Self {
        Self {
            session_id,
            session_status: SessionStatus::End,
            option: Bitmask::default(),
            target: None,
            global_id: None,
            source: None,
            local: None,
        }
    }

    /// 创建 KeepAlive 状态的帧元数据。
    #[must_use]
    pub fn keep_alive(session_id: u16) -> Self {
        Self {
            session_id,
            session_status: SessionStatus::KeepAlive,
            option: Bitmask::default(),
            target: None,
            global_id: None,
            source: None,
            local: None,
        }
    }

    /// 创建 Keep 状态的帧元数据，携带 UDP 目标更新。
    #[must_use]
    pub fn keep_with_udp_target(session_id: u16, target: Destination) -> Self {
        let mut option = Bitmask::default();
        option.set(OPTION_DATA);
        Self {
            session_id,
            session_status: SessionStatus::Keep,
            option,
            target: Some(target),
            global_id: None,
            source: None,
            local: None,
        }
    }

    /// 获取会话 ID。
    #[must_use]
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// 获取会话状态。
    #[must_use]
    pub fn session_status(&self) -> SessionStatus {
        self.session_status
    }

    /// 获取选项位掩码。
    #[must_use]
    pub fn option(&self) -> Bitmask {
        self.option
    }

    /// 获取目标地址的引用。
    #[must_use]
    pub fn target(&self) -> Option<&Destination> {
        self.target.as_ref()
    }

    /// 获取全局 ID。
    #[must_use]
    pub fn global_id(&self) -> Option<&[u8; 8]> {
        self.global_id.as_ref()
    }

    /// 获取 Reverse-mux 入站源地址。
    #[must_use]
    pub fn source(&self) -> Option<&Destination> {
        self.source.as_ref()
    }

    /// 获取 Reverse-mux 入站本地地址。
    #[must_use]
    pub fn local(&self) -> Option<&Destination> {
        self.local.as_ref()
    }

    /// 设置 Reverse-mux 入站源/本地地址（Go `NewWriter` 的 `inbound` 参数）。
    ///
    /// 设置后 New 帧写出 source/local（Go frame.go:87-99），与 GlobalID
    /// 互斥（Go frame.go:100 else 分支）。
    pub fn set_inbound(&mut self, source: Destination, local: Destination) {
        self.source = Some(source);
        self.local = Some(local);
    }

    /// 设置目标地址。
    pub fn set_target(&mut self, target: Destination) {
        self.target = Some(target);
    }

    /// 设置全局 ID。
    pub fn set_global_id(&mut self, id: [u8; 8]) {
        self.global_id = Some(id);
    }

    /// 设置选项位。
    pub fn set_option(&mut self, bit: u8) {
        self.option.set(bit);
    }

    /// 是否包含数据标志。
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.option.has(OPTION_DATA)
    }

    /// 是否包含错误标志。
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.option.has(OPTION_ERROR)
    }

    /// 是否为 UDP 目标。
    #[must_use]
    pub fn is_udp_target(&self) -> bool {
        self.target.as_ref().is_some_and(|t| t.network() == Network::UDP)
    }

    // ========== 序列化 ==========

    /// 将帧元数据序列化为字节向量（线格式）。
    ///
    /// 线格式：`length(2B) + session_id(2B) + status(1B) + option(1B) + [target...]`。
    ///
    /// 总长超过 `MAX_METADATA_LEN` 报错（对齐 Go frame.go:119-121 读侧
    /// 512 硬顶）：写出超长帧对端必拒收并永久 desync，本端必须早失败
    /// 而非静默饱和 length 字段（bd n43f）。
    pub fn to_bytes(&self) -> Result<Vec<u8>, MuxError> {
        let mut buf = Vec::with_capacity(64);
        // 预留 2 字节 length
        buf.extend_from_slice(&[0u8; 2]);

        // session_id (2B BE)
        buf.extend_from_slice(&serial::write_uint16(self.session_id));

        // session_status (1B)
        buf.push(self.session_status.to_byte());

        // option (1B)
        buf.push(self.option.bits());

        // 目标地址
        if self.session_status == SessionStatus::New {
            if let Some(target) = &self.target {
                write_target_to_vec(&mut buf, target)?;
            }
            if let Some(source) = &self.source {
                // Go frame.go:87-99：Reverse-mux 场景写 source/local，
                // 与 GlobalID 互斥（Go :100 else 分支）
                write_inbound_to_vec(&mut buf, source, self.local.as_ref())?;
            } else if self.is_udp_target() {
                if let Some(gid) = &self.global_id {
                    buf.extend_from_slice(gid);
                }
            }
        } else if self.session_status == SessionStatus::Keep {
            if let Some(target) = &self.target {
                if target.network() == Network::UDP {
                    write_target_to_vec(&mut buf, target)?;
                }
            }
        }

        // 回填 length（length 字段后的所有内容长度）。
        // 512 检查通过则 content_len ≤ 512 < u16::MAX，转换无截断。
        let content_len = buf.len() - 2;
        if content_len > MAX_METADATA_LEN {
            return Err(MuxError::MetadataTooLong(content_len));
        }
        buf[0..2].copy_from_slice(&serial::write_uint16(content_len as u16));

        Ok(buf)
    }

    /// 将帧元数据写入 `Write` trait 对象。
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), MuxError> {
        let bytes = self.to_bytes()?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    // ========== 反序列化 ==========

    /// 从字节切片解析帧元数据。
    ///
    /// 返回解析后的 `FrameMetadata` 和消耗的总字节数（含 length 字段）。
    pub fn read_from_bytes(data: &[u8]) -> Result<(Self, usize), MuxError> {
        Self::read_from_bytes_impl(data, false)
    }

    /// 解析带 Reverse-mux source/local 的帧元数据（Go `Unmarshal` 的
    /// `readSourceAndLocal=true`；仅 reverse-mux 对端会携带这些可选字段）。
    pub fn read_from_bytes_with_source(data: &[u8]) -> Result<(Self, usize), MuxError> {
        Self::read_from_bytes_impl(data, true)
    }

    fn read_from_bytes_impl(
        data: &[u8],
        read_source_and_local: bool,
    ) -> Result<(Self, usize), MuxError> {
        if data.len() < 2 {
            return Err(MuxError::InsufficientData { expected: 2, actual: data.len() });
        }

        let meta_len = serial::read_uint16(data)
            .ok_or_else(|| MuxError::InsufficientData { expected: 2, actual: data.len().min(2) })?
            as usize;

        if meta_len > MAX_METADATA_LEN {
            return Err(MuxError::MetadataTooLong(meta_len));
        }

        if data.len() < 2 + meta_len {
            return Err(MuxError::InsufficientData { expected: 2 + meta_len, actual: data.len() });
        }

        let body = &data[2..2 + meta_len];
        let meta = Self::parse_body(body, read_source_and_local)?;

        Ok((meta, 2 + meta_len))
    }

    /// 从 `Read` trait 对象读取帧元数据。
    pub fn read_from(reader: &mut impl Read) -> Result<Self, MuxError> {
        // 读取 length (2B)
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)?;
        let meta_len = u16::from_be_bytes(len_buf) as usize;

        if meta_len > MAX_METADATA_LEN {
            return Err(MuxError::MetadataTooLong(meta_len));
        }

        // 读取 body
        let mut body = vec![0u8; meta_len];
        reader.read_exact(&mut body)?;

        Self::parse_body(&body, false)
    }

    /// 解析帧体（不含 length 前缀）。
    fn parse_body(body: &[u8], read_source_and_local: bool) -> Result<Self, MuxError> {
        if body.len() < 4 {
            return Err(MuxError::InsufficientData { expected: 4, actual: body.len() });
        }

        // session_id (2B)
        let session_id = u16::from_be_bytes([body[0], body[1]]);

        // session_status (1B)
        let session_status = SessionStatus::from_byte(body[2])
            .ok_or_else(|| MuxError::InvalidSessionStatus(body[2]))?;

        // option (1B)
        let option = Bitmask::new(body[3]);

        let mut meta = Self {
            session_id,
            session_status,
            option,
            target: None,
            global_id: None,
            source: None,
            local: None,
        };

        let mut offset = 4;

        // 解析目标地址
        if session_status == SessionStatus::New {
            if offset < body.len() {
                let (target, consumed) = read_target(&body[offset..])?;
                meta.target = Some(target);
                offset += consumed;
            }
            if read_source_and_local {
                parse_source_and_local(&mut meta, &body[offset..])?;
                // Go frame.go:212 提前返回：source/local 帧不再读 GlobalID
                return Ok(meta);
            }
            // 解析 GlobalID（New + Data + UDP + 剩余>=8）
            if meta.has_data() && meta.is_udp_target() && body.len().saturating_sub(offset) >= 8 {
                let mut gid = [0u8; 8];
                gid.copy_from_slice(&body[offset..offset + 8]);
                meta.global_id = Some(gid);
            }
        } else if session_status == SessionStatus::Keep && offset < body.len() {
            // Keep 状态：检查第5字节是否为 UDP 目标
            let net = TargetNetwork::from_byte(body[offset]);
            if net == Some(TargetNetwork::UDP) {
                let (target, _consumed) = read_target(&body[offset..])?;
                meta.target = Some(target);
            }
        }

        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use xray_common::net::{address::Address, port::Port};

    use super::*;

    // ========== 枚举测试 ==========

    #[test]
    fn test_session_status_roundtrip() {
        let values =
            [SessionStatus::New, SessionStatus::Keep, SessionStatus::End, SessionStatus::KeepAlive];
        for status in values {
            assert_eq!(SessionStatus::from_byte(status.to_byte()), Some(status));
        }
    }

    #[test]
    fn test_session_status_invalid_byte() {
        assert_eq!(SessionStatus::from_byte(0x00), None);
        assert_eq!(SessionStatus::from_byte(0x05), None);
        assert_eq!(SessionStatus::from_byte(0xFF), None);
    }

    #[test]
    fn test_data_type_roundtrip() {
        assert_eq!(DataType::from_byte(DataType::Stream.to_byte()), Some(DataType::Stream));
        assert_eq!(DataType::from_byte(DataType::Packet.to_byte()), Some(DataType::Packet));
        assert_eq!(DataType::from_byte(0x00), None);
    }

    #[test]
    fn test_target_network_roundtrip() {
        assert_eq!(
            TargetNetwork::from_byte(TargetNetwork::TCP.to_byte()),
            Some(TargetNetwork::TCP)
        );
        assert_eq!(
            TargetNetwork::from_byte(TargetNetwork::UDP.to_byte()),
            Some(TargetNetwork::UDP)
        );
        assert_eq!(TargetNetwork::from_byte(0x00), None);
    }

    #[test]
    fn test_target_network_from_network() {
        assert_eq!(TargetNetwork::from_network(Network::TCP), Some(TargetNetwork::TCP));
        assert_eq!(TargetNetwork::from_network(Network::UDP), Some(TargetNetwork::UDP));
        assert_eq!(TargetNetwork::from_network(Network::Unix), None);
    }

    // ========== 帧序列化/反序列化 roundtrip ==========

    #[test]
    fn test_new_tcp_frame_roundtrip() {
        let target = Destination::tcp(Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)), Port::new(443));
        let meta = FrameMetadata::new_session(42, target);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, consumed) =
            FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.session_id(), 42);
        assert_eq!(parsed.session_status(), SessionStatus::New);
        assert!(parsed.has_data());
        assert!(parsed.target().is_some());
        let t = parsed.target().unwrap();
        assert_eq!(t.network(), Network::TCP);
        assert_eq!(t.port(), Port::new(443));
        assert_eq!(*t.address(), Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_new_udp_frame_roundtrip() {
        let target = Destination::udp(Address::new_domain("dns.server"), Port::new(53));
        let meta = FrameMetadata::new_session(100, target);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, consumed) =
            FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.session_id(), 100);
        assert_eq!(parsed.session_status(), SessionStatus::New);
        assert!(parsed.is_udp_target());
        let t = parsed.target().unwrap();
        assert_eq!(t.network(), Network::UDP);
        assert_eq!(t.port(), Port::new(53));
    }

    #[test]
    fn test_new_udp_frame_with_global_id_roundtrip() {
        let target = Destination::udp(Address::ipv4(Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let mut meta = FrameMetadata::new_session(7, target);
        let gid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        meta.set_global_id(gid);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert!(parsed.is_udp_target());
        assert!(parsed.global_id().is_some());
        assert_eq!(*parsed.global_id().unwrap(), gid);
    }

    /// Reverse-mux New 帧样例：source+local 逐字节对拍 + 两种 flag 解析
    /// （Go frame.go:87-99 写 / :167-213 读）。
    #[test]
    fn test_reverse_new_frame_source_local_parse() {
        let source = Destination::tcp(Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)), Port::new(5555));
        let local = Destination::tcp(Address::ipv4(Ipv4Addr::new(127, 0, 0, 1)), Port::new(1080));
        let mut meta = FrameMetadata::new_session(
            7,
            Destination::tcp(Address::ipv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(443)),
        );
        meta.set_inbound(source.clone(), local.clone());

        let bytes = meta.to_bytes().unwrap();
        // 逐字节对拍：4B 头 + 每段 8B（net 1B + port 2B BE + addr family 1B +
        // IPv4 4B）
        assert_eq!(&bytes[2..4], &[0x00, 0x07]);
        assert_eq!(bytes[4], 0x01); // status New
        assert_eq!(bytes[5], 0x01); // option Data
        // target
        assert_eq!(bytes[6], 0x01); // net TCP
        assert_eq!(&bytes[7..9], &[0x01, 0xBB]); // 443
        assert_eq!(&bytes[9..14], &[0x01, 1, 2, 3, 4]);
        // source
        assert_eq!(bytes[14], 0x01); // net TCP
        assert_eq!(&bytes[15..17], &[0x15, 0xB3]); // 5555
        assert_eq!(&bytes[17..22], &[0x01, 10, 0, 0, 1]);
        // local
        assert_eq!(bytes[22], 0x01); // net TCP
        assert_eq!(&bytes[23..25], &[0x04, 0x38]); // 1080
        assert_eq!(&bytes[25..30], &[0x01, 127, 0, 0, 1]);

        let (parsed, consumed) =
            FrameMetadata::read_from_bytes_with_source(&bytes).expect("parse should succeed");
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.source(), Some(&source));
        assert_eq!(parsed.local(), Some(&local));
        assert!(parsed.global_id().is_none(), "source 帧与 GlobalID 互斥");

        // 不开 flag（普通 mux 路径）：不解析 source/local
        let (plain, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");
        assert!(plain.source().is_none());
        assert!(plain.local().is_none());
    }

    /// Reverse-mux source 缺席变体：空尾帧（心跳，Go :170-171）与
    /// padding 帧（network 字节 0，Go :174-175）。
    #[test]
    fn test_reverse_new_frame_without_source_variants() {
        let meta = FrameMetadata::new(1, SessionStatus::New, Bitmask::default());
        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) =
            FrameMetadata::read_from_bytes_with_source(&bytes).expect("parse should succeed");
        assert!(parsed.source().is_none());

        let meta = FrameMetadata::new_session(
            2,
            Destination::tcp(Address::ipv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(443)),
        );
        let mut bytes = meta.to_bytes().unwrap();
        bytes.push(0x00); // padding
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) + 1;
        bytes[0..2].copy_from_slice(&len.to_be_bytes());
        let (parsed, consumed) =
            FrameMetadata::read_from_bytes_with_source(&bytes).expect("parse should succeed");
        assert_eq!(consumed, bytes.len());
        assert!(parsed.source().is_none());
    }

    #[test]
    fn test_end_frame_roundtrip() {
        let meta = FrameMetadata::end_session(42);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, consumed) =
            FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.session_id(), 42);
        assert_eq!(parsed.session_status(), SessionStatus::End);
        assert!(parsed.target().is_none());
        assert!(!parsed.has_data());
    }

    #[test]
    fn test_keepalive_frame_roundtrip() {
        let meta = FrameMetadata::keep_alive(999);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(parsed.session_id(), 999);
        assert_eq!(parsed.session_status(), SessionStatus::KeepAlive);
        assert!(parsed.target().is_none());
    }

    #[test]
    fn test_keep_udp_target_roundtrip() {
        let target = Destination::udp(Address::new_domain("example.com"), Port::new(8080));
        let meta = FrameMetadata::keep_with_udp_target(55, target);

        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");

        assert_eq!(parsed.session_status(), SessionStatus::Keep);
        assert!(parsed.target().is_some());
        let t = parsed.target().unwrap();
        assert_eq!(t.network(), Network::UDP);
        assert_eq!(t.port(), Port::new(8080));
    }

    #[test]
    fn test_write_to_and_read_from() {
        let target = Destination::tcp(
            Address::ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            Port::new(8080),
        );
        let meta = FrameMetadata::new_session(1234, target);

        let mut buf = Vec::new();
        meta.write_to(&mut buf).expect("write should succeed");

        let mut cursor = Cursor::new(&buf);
        let parsed = FrameMetadata::read_from(&mut cursor).expect("read should succeed");

        assert_eq!(parsed.session_id(), 1234);
        assert_eq!(parsed.session_status(), SessionStatus::New);
        assert!(parsed.target().is_some());
        let t = parsed.target().unwrap();
        assert_eq!(t.network(), Network::TCP);
    }

    // ========== 边界条件 ==========

    #[test]
    fn test_max_session_id() {
        let meta = FrameMetadata::end_session(u16::MAX);
        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");
        assert_eq!(parsed.session_id(), u16::MAX);
    }

    #[test]
    fn test_error_option_flag() {
        let mut meta = FrameMetadata::new(1, SessionStatus::End, Bitmask::default());
        meta.set_option(OPTION_ERROR);
        assert!(meta.has_error());
        assert!(!meta.has_data());

        let bytes = meta.to_bytes().unwrap();
        let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).expect("parse should succeed");
        assert!(parsed.has_error());
        assert!(!parsed.has_data());
    }

    // ========== 错误情况 ==========

    #[test]
    fn test_parse_empty_data() {
        let result = FrameMetadata::read_from_bytes(&[]);
        assert!(matches!(result, Err(MuxError::InsufficientData { expected: 2, actual: 0 })));
    }

    #[test]
    fn test_parse_insufficient_body() {
        // length=10 但只有 4 字节 body
        let data = [0x00, 0x0A, 0x00, 0x01, 0x01, 0x01];
        let result = FrameMetadata::read_from_bytes(&data);
        assert!(matches!(result, Err(MuxError::InsufficientData { .. })));
    }

    #[test]
    fn test_parse_invalid_session_status() {
        // body: session_id=1, status=0xFF (invalid), option=0
        let body = [0x00, 0x01, 0xFF, 0x00];
        let len_bytes = serial::write_uint16(body.len() as u16);
        let mut data = len_bytes.to_vec();
        data.extend_from_slice(&body);
        let result = FrameMetadata::read_from_bytes(&data);
        assert!(matches!(result, Err(MuxError::InvalidSessionStatus(0xFF))));
    }

    #[test]
    fn test_parse_metadata_too_long() {
        let len_bytes = serial::write_uint16(513);
        let result = FrameMetadata::read_from_bytes(&len_bytes);
        assert!(matches!(result, Err(MuxError::MetadataTooLong(513))));
    }

    #[test]
    fn test_read_from_insufficient_reader() {
        let data = [0x00];
        let mut cursor = Cursor::new(&data[..]);
        let result = FrameMetadata::read_from(&mut cursor);
        assert!(matches!(result, Err(MuxError::Io(_))));
    }

    // ========== 线格式验证 ==========

    #[test]
    fn test_wire_format_new_tcp_ipv4() {
        let target = Destination::tcp(Address::ipv4(Ipv4Addr::new(127, 0, 0, 1)), Port::new(80));
        let meta = FrameMetadata::new_session(1, target);
        let bytes = meta.to_bytes().unwrap();

        // length 字段 (2B): body 长度 = 4(固定) + 1(network) + 2(port) + 1(type) + 4(ipv4) = 12
        let expected_len = 12u16;
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), expected_len);

        // session_id
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 1);

        // session_status = New
        assert_eq!(bytes[4], 0x01);

        // option = Data
        assert_eq!(bytes[5], 0x01);

        // target network = TCP
        assert_eq!(bytes[6], 0x01);

        // port = 80 (BE)
        assert_eq!(u16::from_be_bytes([bytes[7], bytes[8]]), 80);

        // address type = IPv4
        assert_eq!(bytes[9], 0x01);

        // IPv4 octets
        assert_eq!(&bytes[10..14], &[127, 0, 0, 1]);
    }

    /// F5/n43f：超长 meta 的 to_bytes 必须显式报错（对齐 Go frame.go:119-121
    /// 读侧 512 硬顶策略）。修复前：addr_buf(32B) 静默截断域名写出坏帧
    /// （domain len 与数据不符 → 对端 desync），body 永远 < 512 检查不到。
    #[test]
    fn test_to_bytes_oversized_meta_errors() {
        // 域名 >255：u8 len 前缀装不下，write_target_to_vec 直接报错
        //（值为单地址贡献 4+3+len，允许 < 512）。
        let source = Destination::tcp(Address::new_domain("a".repeat(300)), Port::new(443));
        let local = Destination::tcp(Address::new_domain("b".repeat(300)), Port::new(8080));
        let mut meta = FrameMetadata::new_session(
            1,
            Destination::tcp(Address::new_domain("example.com"), Port::new(80)),
        );
        meta.set_inbound(source, local);
        let err = meta.to_bytes().expect_err("oversized meta must error");
        assert!(matches!(err, MuxError::MetadataTooLong(_)), "unexpected error: {err}");
    }

    /// 各段合法（≤255B）但帧总量 >512：对齐 Go 读侧 512 硬顶，
    /// 写路径早失败避免对端拒收 desync（审计 518B 场景）。
    #[test]
    fn test_to_bytes_total_over_512_errors() {
        let source = Destination::tcp(Address::new_domain("a".repeat(255)), Port::new(443));
        let local = Destination::tcp(Address::new_domain("b".repeat(255)), Port::new(8080));
        let mut meta = FrameMetadata::new_session(
            1,
            Destination::tcp(Address::new_domain("example.com"), Port::new(80)),
        );
        meta.set_inbound(source, local);
        let err = meta.to_bytes().expect_err("total >512 must error");
        assert!(
            matches!(err, MuxError::MetadataTooLong(n) if n > MAX_METADATA_LEN),
            "unexpected error: {err}"
        );
    }

    /// 域名 255B 边界：单 source 帧合法（body < 512）必须照常完整写出，
    /// 防止超长修复误伤合法 reverse-mux 流量。
    #[test]
    fn test_to_bytes_domain_255_boundary_ok() {
        let source = Destination::tcp(Address::new_domain("a".repeat(255)), Port::new(443));
        let local = Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(1));
        let mut meta = FrameMetadata::new_session(
            1,
            Destination::tcp(Address::new_domain("example.com"), Port::new(80)),
        );
        meta.set_inbound(source, local);
        let bytes = meta.to_bytes().expect("255B domain + v4 local is legal");
        assert_eq!(
            u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
            bytes.len() - 2,
            "length field must match body exactly (no truncation)"
        );
    }
}
