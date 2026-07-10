//! VMess 账户定义。
//!
//! 对应 Go 版本 `proxy/vmess/account.go`。`MemoryAccount` 是运行时账户形式，
//! `Account` 是 proto 序列化形式（用于配置传递）。
//!
//! # cmd_key 实现说明
//!
//! VMess 协议要求 `cmd_key = MD5(UUID.String())`，与 Go 端字节级对齐。
//! 但 `xray-common` 的 `UUID::cmd_key` 当前是 XOR 折叠占位实现（详见其 TODO），
//! 不能用于 VMess 协议。因此本 crate 内部使用 [`cmd_key_of`] 直接计算 MD5，
//! 不依赖 `protocol::ID::cmd_key()`。

use prost::Message;
use xray_common::protocol::{self, ID};
use xray_common::uuid::UUID;
use xray_proto::xray::common::protocol::SecurityConfig;
use xray_proto::xray::proxy::vmess::Account as ProtoAccount;

use crate::error::{Result, VmessError};

/// VMess 内存账户（运行时形式）。
///
/// 对应 Go `*MemoryAccount`。在 Rust 端不支持 Go interface，
/// 因此不复用 `protocol::MemoryUser`（其 `account` 字段是 `Option<TypedMessage>`），
/// 而是独立定义在此 crate 内部。
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    /// 主 ID（UUID + cmd_key 派生）。
    pub id: ID,
    /// 安全类型（仅用于客户端连接）。
    pub security: protocol::SecurityType,
    /// 启用 AuthenticatedLength 实验。
    pub authenticated_length_experiment: bool,
    /// 不发送 termination signal。
    pub no_termination_signal: bool,
}

impl MemoryAccount {
    /// 从 UUID 创建账户，默认 security=Auto、无实验特性。
    #[must_use]
    pub fn new(id: UUID) -> Self {
        Self {
            id: ID::new(id),
            security: protocol::SecurityType::Auto,
            authenticated_length_experiment: false,
            no_termination_signal: false,
        }
    }

    /// 设置 security 类型（builder 风格）。
    #[must_use]
    pub fn with_security(mut self, security: protocol::SecurityType) -> Self {
        self.security = security;
        self
    }

    /// 启用 AuthenticatedLength 实验（builder 风格）。
    #[must_use]
    pub fn with_authenticated_length(mut self) -> Self {
        self.authenticated_length_experiment = true;
        self
    }

    /// 启用 NoTerminationSignal（builder 风格）。
    #[must_use]
    pub fn with_no_termination_signal(mut self) -> Self {
        self.no_termination_signal = true;
        self
    }

    /// 与另一个账户比较 ID 是否相等（对应 Go `Equals`）。
    ///
    /// 注意：Go 端 `Equals` 接收 `protocol.Account` interface，
    /// Rust 端没有等价物，所以这里接收同类型。
    #[must_use]
    pub fn equals(&self, other: &Self) -> bool {
        self.id.uuid() == other.id.uuid()
    }

    /// 转换为 proto 序列化形式（对应 Go `ToProto`）。
    #[must_use]
    pub fn to_proto(&self) -> ProtoAccount {
        let mut tests = String::new();
        if self.authenticated_length_experiment {
            tests.push_str("AuthenticatedLength|");
        }
        if self.no_termination_signal {
            tests.push_str("NoTerminationSignal");
        }

        let security_settings = SecurityConfig {
            r#type: self.security.as_u8() as i32,
        };

        ProtoAccount {
            id: self.id.uuid().to_string(),
            tests_enabled: tests,
            security_settings: Some(security_settings),
        }
    }

    /// 从 proto 形式转换（对应 Go `AsAccount`）。
    ///
    /// # Errors
    ///
    /// - [`VmessError::InvalidUuid`]：UUID 字符串无法解析。
    pub fn from_proto(account: &ProtoAccount) -> Result<Self> {
        let uuid = UUID::parse(&account.id).ok_or_else(|| VmessError::InvalidUuid(account.id.clone()))?;
        let proto_id = ID::new(uuid);
        let authenticated_length = account.tests_enabled.contains("AuthenticatedLength");
        let no_termination_signal = account.tests_enabled.contains("NoTerminationSignal");

        let security = account
            .security_settings
            .as_ref()
            .map(|s| protocol::SecurityType::from_u8(u8::try_from(s.r#type).unwrap_or(0)))
            .unwrap_or(Some(protocol::SecurityType::Auto))
            .unwrap_or(protocol::SecurityType::Auto);

        Ok(Self {
            id: proto_id,
            security,
            authenticated_length_experiment: authenticated_length,
            no_termination_signal,
        })
    }

    /// 编码为字节（prost `encode_to_vec` 是 infallible）。
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    /// 从字节解码。
    ///
    /// # Errors
    ///
    /// - [`VmessError::ProstDecode`]：protobuf 解码失败。
    /// - [`VmessError::InvalidUuid`]：UUID 字符串无法解析。
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let account = ProtoAccount::decode(buf)?;
        Self::from_proto(&account)
    }

    /// 命令密钥（对应 Go `account.ID.CmdKey()`）。
    ///
    /// 使用 `cmd_key_of` = MD5(UUID.Bytes() + magic) 与 Go 字节级对齐。
    #[must_use]
    pub fn cmd_key(&self) -> [u8; 16] {
        cmd_key_of(self.id.uuid())
    }
}

/// 计算 VMess cmd_key = MD5(UUID.Bytes() || magic_uuid)。
///
/// 与 Go 端 `NewID` 字节级对齐：Go 用 `md5(uuid.Bytes() + "c48619fe-8f02-49e0-b9e9-edf763e17e21")`。
#[must_use]
pub fn cmd_key_of(uuid: &UUID) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_uuid() -> UUID {
        UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("valid uuid")
    }

    #[test]
    fn new_account_defaults() {
        let acc = MemoryAccount::new(sample_uuid());
        assert_eq!(acc.security, protocol::SecurityType::Auto);
        assert!(!acc.authenticated_length_experiment);
        assert!(!acc.no_termination_signal);
    }

    #[test]
    fn builders_set_fields() {
        let acc = MemoryAccount::new(sample_uuid())
            .with_security(protocol::SecurityType::Aes128Gcm)
            .with_authenticated_length()
            .with_no_termination_signal();
        assert_eq!(acc.security, protocol::SecurityType::Aes128Gcm);
        assert!(acc.authenticated_length_experiment);
        assert!(acc.no_termination_signal);
    }

    #[test]
    fn equals_same_uuid() {
        let a = MemoryAccount::new(sample_uuid());
        let b = MemoryAccount::new(sample_uuid());
        assert!(a.equals(&b));
    }

    #[test]
    fn not_equals_different_uuid() {
        let a = MemoryAccount::new(sample_uuid());
        let b = MemoryAccount::new(UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b58").expect("valid"));
        assert!(!a.equals(&b));
    }

    #[test]
    fn to_proto_basic() {
        let acc = MemoryAccount::new(sample_uuid());
        let p = acc.to_proto();
        assert_eq!(p.id, "66ad4540-b58c-4ad2-9926-ea63445a9b57");
        assert!(p.tests_enabled.is_empty());
        assert!(p.security_settings.is_some());
    }

    #[test]
    fn to_proto_with_flags() {
        let acc = MemoryAccount::new(sample_uuid())
            .with_authenticated_length()
            .with_no_termination_signal();
        let p = acc.to_proto();
        assert!(p.tests_enabled.contains("AuthenticatedLength"));
        assert!(p.tests_enabled.contains("NoTerminationSignal"));
    }

    #[test]
    fn to_proto_only_no_termination() {
        let acc = MemoryAccount::new(sample_uuid()).with_no_termination_signal();
        let p = acc.to_proto();
        assert!(!p.tests_enabled.contains("AuthenticatedLength"));
        assert!(p.tests_enabled.contains("NoTerminationSignal"));
    }

    #[test]
    fn roundtrip_via_proto() {
        let acc = MemoryAccount::new(sample_uuid())
            .with_security(protocol::SecurityType::Chacha20Poly1305)
            .with_authenticated_length();
        let p = acc.to_proto();
        let acc2 = MemoryAccount::from_proto(&p).expect("from_proto");
        assert_eq!(acc2.security, protocol::SecurityType::Chacha20Poly1305);
        assert!(acc2.authenticated_length_experiment);
        assert!(acc2.equals(&acc));
    }

    #[test]
    fn roundtrip_via_bytes() {
        let acc = MemoryAccount::new(sample_uuid());
        let bytes = acc.encode_to_vec();
        let acc2 = MemoryAccount::decode(&bytes).expect("decode");
        assert!(acc.equals(&acc2));
    }

    #[test]
    fn from_proto_invalid_uuid() {
        let p = ProtoAccount {
            id: "not-a-uuid".into(),
            tests_enabled: String::new(),
            security_settings: None,
        };
        let err = MemoryAccount::from_proto(&p).unwrap_err();
        assert!(matches!(err, VmessError::InvalidUuid(_)));
    }

    #[test]
    fn cmd_key_is_16_bytes() {
        let acc = MemoryAccount::new(sample_uuid());
        assert_eq!(acc.cmd_key().len(), 16);
    }

    #[test]
    fn cmd_key_deterministic_for_same_uuid() {
        let a = MemoryAccount::new(sample_uuid());
        let b = MemoryAccount::new(sample_uuid());
        assert_eq!(a.cmd_key(), b.cmd_key());
    }
}
