//! 协议核心类型
//!
//! 对应 Go 版本 `common/protocol/` 包，定义安全类型、命令、ID 和请求/响应头。

pub mod user;
pub mod server_spec;
pub mod address_parser;

use serde::{Deserialize, Serialize};

use crate::bitmask::Bitmask;

use crate::net::address::Address;
use crate::net::destination::Destination;
use crate::uuid::UUID;

use self::user::MemoryUser;

// ========== 安全类型 ==========

/// 加密安全类型。
///
/// 对应 Go 版本的 `SecurityType` 枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityType {
    /// 未知安全类型
    Unknown = 0,
    /// 遗留加密（AES-128-CFB）
    Legacy = 1,
    /// 自动选择
    Auto = 2,
    /// AES-128-GCM
    Aes128Gcm = 3,
    /// ChaCha20-Poly1305
    Chacha20Poly1305 = 4,
    /// 零加密（无加密但保留协议头）
    Zero = 5,
    /// 无加密
    None = 6,
}

impl SecurityType {
    /// 转换为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Legacy),
            2 => Some(Self::Auto),
            3 => Some(Self::Aes128Gcm),
            4 => Some(Self::Chacha20Poly1305),
            5 => Some(Self::Zero),
            6 => Some(Self::None),
            _ => None,
        }
    }
}

impl std::fmt::Display for SecurityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Legacy => write!(f, "legacy"),
            Self::Auto => write!(f, "auto"),
            Self::Aes128Gcm => write!(f, "aes-128-gcm"),
            Self::Chacha20Poly1305 => write!(f, "chacha20-poly1305"),
            Self::Zero => write!(f, "zero"),
            Self::None => write!(f, "none"),
        }
    }
}

// ========== 传输类型 ==========

/// 数据传输类型。
///
/// 对应 Go 版本的 `TransferType`，区分流式和包式传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransferType {
    /// 流式传输（TCP）
    Stream = 0,
    /// 包式传输（UDP）
    Packet = 1,
}

impl TransferType {
    /// 转换为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Stream),
            1 => Some(Self::Packet),
            _ => None,
        }
    }
}

impl std::fmt::Display for TransferType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream => write!(f, "stream"),
            Self::Packet => write!(f, "packet"),
        }
    }
}

impl Default for TransferType {
    fn default() -> Self {
        Self::Stream
    }
}

// ========== 地址类型 ==========

/// 地址类型。
///
/// 对应 Go 版本的 `AddressType`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressType {
    /// IPv4 地址
    IPv4 = 1,
    /// 域名地址
    Domain = 2,
    /// IPv6 地址
    IPv6 = 3,
}

impl AddressType {
    /// 转换为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::IPv4),
            2 => Some(Self::Domain),
            3 => Some(Self::IPv6),
            _ => None,
        }
    }
}

// ========== 命令类型 ==========

/// 协议命令类型。
///
/// 对应 Go 版本的 `Command` 枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    /// TCP 代理
    Tcp = 1,
    /// UDP 代理
    Udp = 2,
    /// 多路复用
    Mux = 3,
}

/// VMess 响应命令。
///
/// 对应 Go `protocol.ResponseCommand`。
/// 响应头可携带命令，用于动态控制客户端行为。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCommand {
    /// 无命令
    None,
    /// 切换账户：指示客户端切换到另一个入站处理器
    SwitchAccount(SwitchAccountCommand),
}

/// SwitchAccount 命令参数。
///
/// 携带目标入站的 host/port/security/alterID 等信息，
/// 客户端收到后应切换到指定入站。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchAccountCommand {
    /// 目标地址
    pub host: Option<Address>,
    /// 目标端口
    pub port: u16,
    /// detour tag（指向另一个入站处理器）
    pub detour_tag: Option<String>,
}

impl Command {
    /// 转换为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Mux),
            _ => None,
        }
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Mux => write!(f, "mux"),
        }
    }
}

// ========== ID 类型 ==========

/// 协议 ID，包含 UUID、命令密钥和替代 ID 列表。
///
/// 对应 Go 版本的 `ID` 结构体，用于 VMess 等协议的身份标识。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ID {
    uuid: UUID,
    cmd_key: [u8; 16],
    alter_ids: Vec<ID>,
}

impl ID {
    /// 从 UUID 创建新 ID。
    ///
    /// 自动派生命令密钥。
    #[must_use]
    pub fn new(uuid: UUID) -> Self {
        let cmd_key = uuid.cmd_key();
        Self {
            uuid,
            cmd_key,
            alter_ids: Vec::new(),
        }
    }

    /// 添加替代 ID。
    #[must_use]
    pub fn with_alter_ids(mut self, alter_ids: Vec<ID>) -> Self {
        self.alter_ids = alter_ids;
        self
    }

    /// 获取 UUID 引用。
    #[must_use]
    pub fn uuid(&self) -> &UUID {
        &self.uuid
    }

    /// 获取命令密钥。
    #[must_use]
    pub fn cmd_key(&self) -> &[u8; 16] {
        &self.cmd_key
    }

    /// 获取替代 ID 列表引用。
    #[must_use]
    pub fn alter_ids(&self) -> &[ID] {
        &self.alter_ids
    }

    /// 检查此 ID 是否与给定 UUID 匹配（包括替代 ID）。
    pub fn equals(&self, uuid: &UUID) -> bool {
        if &self.uuid == uuid {
            return true;
        }
        self.alter_ids.iter().any(|id| id.equals(uuid))
    }
}

impl std::hash::Hash for ID {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uuid.hash(state);
    }
}

// ========== 请求头 ==========

/// 协议请求头。
///
/// 对应 Go 版本的 `RequestHeader`，包含完整的请求元数据。
#[derive(Debug, Clone)]
pub struct RequestHeader {
    /// 协议版本
    pub version: u8,
    /// 用户信息
    pub user: Option<MemoryUser>,
    /// 命令类型
    pub command: Command,
    /// 目的地
    pub destination: Destination,
    /// 安全类型
    pub security: SecurityType,
    /// 选项位掩码
    pub option: Bitmask,
}

impl RequestHeader {
    /// 创建新的请求头。
    #[must_use]
    pub fn new(
        version: u8,
        command: Command,
        destination: Destination,
        security: SecurityType,
    ) -> Self {
        Self {
            version,
            user: None,
            command,
            destination,
            security,
            option: Bitmask::default(),
        }
    }

    /// 设置用户，返回新的 RequestHeader。
    #[must_use]
    pub fn with_user(mut self, user: MemoryUser) -> Self {
        self.user = Some(user);
        self
    }

    /// 设置选项，返回新的 RequestHeader。
    #[must_use]
    pub fn with_option(mut self, option: Bitmask) -> Self {
        self.option = option;
        self
    }
}

// ========== 响应头 ==========

/// 协议响应头。
///
/// 对应 Go 版本的 `ResponseHeader`。
#[derive(Debug, Clone)]
pub struct ResponseHeader {
    /// 命令类型
    pub command: Command,
    /// 选项位掩码
    pub option: Bitmask,
    /// 响应命令（SwitchAccount 等）
    pub response_command: ResponseCommand,
}

impl ResponseHeader {
    /// 创建新的响应头。
    #[must_use]
    pub fn new(command: Command) -> Self {
        Self {
            command,
            option: Bitmask::default(),
            response_command: ResponseCommand::None,
        }
    }

    /// 设置选项，返回新的 ResponseHeader。
    #[must_use]
    pub fn with_option(mut self, option: Bitmask) -> Self {
        self.option = option;
        self
    }

    /// 设置响应命令，返回新的 ResponseHeader。
    #[must_use]
    pub fn with_response_command(mut self, cmd: ResponseCommand) -> Self {
        self.response_command = cmd;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::address::Address;
    use crate::net::port::Port;
    use std::net::Ipv4Addr;

    // ========== SecurityType 测试 ==========

    #[test]
    fn test_security_type_as_u8() {
        assert_eq!(SecurityType::Unknown.as_u8(), 0);
        assert_eq!(SecurityType::Legacy.as_u8(), 1);
        assert_eq!(SecurityType::Auto.as_u8(), 2);
        assert_eq!(SecurityType::Aes128Gcm.as_u8(), 3);
        assert_eq!(SecurityType::Chacha20Poly1305.as_u8(), 4);
        assert_eq!(SecurityType::Zero.as_u8(), 5);
        assert_eq!(SecurityType::None.as_u8(), 6);
    }

    #[test]
    fn test_security_type_from_u8() {
        assert_eq!(SecurityType::from_u8(0), Some(SecurityType::Unknown));
        assert_eq!(SecurityType::from_u8(3), Some(SecurityType::Aes128Gcm));
        assert_eq!(SecurityType::from_u8(6), Some(SecurityType::None));
        assert_eq!(SecurityType::from_u8(99), None);
    }

    #[test]
    fn test_security_type_roundtrip() {
        for value in 0u8..=6 {
            let st = SecurityType::from_u8(value).expect("valid");
            assert_eq!(st.as_u8(), value);
        }
    }

    #[test]
    fn test_security_type_display() {
        assert_eq!(format!("{}", SecurityType::Aes128Gcm), "aes-128-gcm");
        assert_eq!(format!("{}", SecurityType::Auto), "auto");
        assert_eq!(format!("{}", SecurityType::None), "none");
    }

    // ========== TransferType 测试 ==========

    #[test]
    fn test_transfer_type_as_u8() {
        assert_eq!(TransferType::Stream.as_u8(), 0);
        assert_eq!(TransferType::Packet.as_u8(), 1);
    }

    #[test]
    fn test_transfer_type_from_u8() {
        assert_eq!(TransferType::from_u8(0), Some(TransferType::Stream));
        assert_eq!(TransferType::from_u8(1), Some(TransferType::Packet));
        assert_eq!(TransferType::from_u8(2), None);
    }

    #[test]
    fn test_transfer_type_default() {
        assert_eq!(TransferType::default(), TransferType::Stream);
    }

    #[test]
    fn test_transfer_type_display() {
        assert_eq!(format!("{}", TransferType::Stream), "stream");
        assert_eq!(format!("{}", TransferType::Packet), "packet");
    }

    // ========== AddressType 测试 ==========

    #[test]
    fn test_address_type_as_u8() {
        assert_eq!(AddressType::IPv4.as_u8(), 1);
        assert_eq!(AddressType::Domain.as_u8(), 2);
        assert_eq!(AddressType::IPv6.as_u8(), 3);
    }

    #[test]
    fn test_address_type_from_u8() {
        assert_eq!(AddressType::from_u8(1), Some(AddressType::IPv4));
        assert_eq!(AddressType::from_u8(2), Some(AddressType::Domain));
        assert_eq!(AddressType::from_u8(3), Some(AddressType::IPv6));
        assert_eq!(AddressType::from_u8(0), None);
    }

    // ========== Command 测试 ==========

    #[test]
    fn test_command_as_u8() {
        assert_eq!(Command::Tcp.as_u8(), 1);
        assert_eq!(Command::Udp.as_u8(), 2);
        assert_eq!(Command::Mux.as_u8(), 3);
    }

    #[test]
    fn test_command_from_u8() {
        assert_eq!(Command::from_u8(1), Some(Command::Tcp));
        assert_eq!(Command::from_u8(2), Some(Command::Udp));
        assert_eq!(Command::from_u8(3), Some(Command::Mux));
        assert_eq!(Command::from_u8(0), None);
        assert_eq!(Command::from_u8(4), None);
    }

    #[test]
    fn test_command_roundtrip() {
        for value in 1u8..=3 {
            let cmd = Command::from_u8(value).expect("valid");
            assert_eq!(cmd.as_u8(), value);
        }
    }

    #[test]
    fn test_command_display() {
        assert_eq!(format!("{}", Command::Tcp), "tcp");
        assert_eq!(format!("{}", Command::Udp), "udp");
        assert_eq!(format!("{}", Command::Mux), "mux");
    }

    // ========== ID 测试 ==========

    #[test]
    fn test_id_new() {
        let uuid = UUID::new();
        let id = ID::new(uuid.clone());
        assert_eq!(id.uuid(), &uuid);
        assert!(id.alter_ids().is_empty());
    }

    #[test]
    fn test_id_cmd_key_deterministic() {
        let uuid = UUID::new();
        let id = ID::new(uuid.clone());
        assert_eq!(id.cmd_key(), &uuid.cmd_key());
    }

    #[test]
    fn test_id_equals_self() {
        let uuid = UUID::new();
        let id = ID::new(uuid.clone());
        assert!(id.equals(&uuid));
    }

    #[test]
    fn test_id_equals_alter_id() {
        let uuid1 = UUID::new();
        let uuid2 = UUID::new();
        let alter = ID::new(uuid2.clone());
        let id = ID::new(uuid1).with_alter_ids(vec![alter]);
        assert!(id.equals(&uuid2));
    }

    #[test]
    fn test_id_not_equals_different() {
        let uuid1 = UUID::new();
        let uuid2 = UUID::new();
        let id = ID::new(uuid1);
        assert!(!id.equals(&uuid2));
    }

    #[test]
    fn test_id_with_alter_ids() {
        let uuid = UUID::new();
        let alter_uuid = UUID::new();
        let alter = ID::new(alter_uuid);
        let id = ID::new(uuid).with_alter_ids(vec![alter]);
        assert_eq!(id.alter_ids().len(), 1);
    }

    // ========== RequestHeader 测试 ==========

    fn sample_destination() -> Destination {
        Destination::tcp(Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)), Port::new(443))
    }

    #[test]
    fn test_request_header_new() {
        let dest = sample_destination();
        let header = RequestHeader::new(1, Command::Tcp, dest.clone(), SecurityType::Auto);
        assert_eq!(header.version, 1);
        assert!(header.user.is_none());
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(header.destination, dest);
        assert_eq!(header.security, SecurityType::Auto);
    }

    #[test]
    fn test_request_header_with_user() {
        use crate::protocol::user::User;
        let user = MemoryUser::new(User::new("test@example.com"));
        let header = RequestHeader::new(1, Command::Tcp, sample_destination(), SecurityType::Auto)
            .with_user(user);
        assert!(header.user.is_some());
    }

    #[test]
    fn test_request_header_with_option() {
        let header = RequestHeader::new(1, Command::Tcp, sample_destination(), SecurityType::Auto)
            .with_option(Bitmask::new(0x01));
        assert!(header.option.has(0x01));
    }

    // ========== ResponseHeader 测试 ==========

    #[test]
    fn test_response_header_new() {
        let header = ResponseHeader::new(Command::Tcp);
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(header.option.bits(), 0);
    }

    #[test]
    fn test_response_header_with_option() {
        let header = ResponseHeader::new(Command::Udp).with_option(Bitmask::new(0x02));
        assert_eq!(header.command, Command::Udp);
        assert!(header.option.has(0x02));
    }

    // ========== 集成测试 ==========

    #[test]
    fn test_serde_roundtrip_security_type() {
        let st = SecurityType::Aes128Gcm;
        let json = serde_json::to_string(&st).expect("serialize");
        let deserialized: SecurityType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(st, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_command() {
        let cmd = Command::Mux;
        let json = serde_json::to_string(&cmd).expect("serialize");
        let deserialized: Command = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cmd, deserialized);
    }
}
