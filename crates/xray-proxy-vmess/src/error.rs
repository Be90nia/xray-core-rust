//! VMess 错误类型。
//!
//! 对应 Go 端散落在 `proxy/vmess/`、`proxy/vmess/aead/`、`proxy/vmess/encoding/` 的多个
//! `errors.New(...)` 调用，集中到一个 enum 方便上层 match 分发。

use xray_crypto::aead::CryptoError;

/// VMess 协议处理错误。
#[derive(Debug, thiserror::Error)]
pub enum VmessError {
    /// IO 错误（读写流）。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 加密原语错误。
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// protobuf 解码错误。
    #[error("prost decode error: {0}")]
    ProstDecode(#[from] prost::DecodeError),

    /// UUID 解析失败。
    #[error("failed to parse ID: {0}")]
    InvalidUuid(String),

    /// 用户不存在。
    #[error("user does not exist")]
    UserNotFound,

    /// 用户类型不正确（不是 VMess Account）。
    #[error("account type is incorrect")]
    InvalidAccountType,

    /// 时间戳为负。
    #[error("timestamp is negative")]
    NegativeTime,

    /// 时间戳无效（与服务器相差超过 120 秒）。
    #[error("invalid timestamp, perhaps unsynchronized time")]
    InvalidTime,

    /// 重放攻击。
    #[error("replayed request")]
    Replay,

    /// 重复 session id（可能重放）。
    #[error("duplicated session id, possibly under replay attack")]
    DuplicateSession,

    /// 命令过大（>255 字节）。
    #[error("command too large")]
    CommandTooLarge,

    /// 命令类型不匹配。
    #[error("command type mismatch")]
    CommandTypeMismatch,

    /// 命令认证失败（FNV1a 校验和不匹配）。
    #[error("invalid auth")]
    InvalidAuth,

    /// 长度不足。
    #[error("insufficient length")]
    InsufficientLength,

    /// 未知命令。
    #[error("unknown command")]
    UnknownCommand,

    /// 读取请求头失败。
    #[error("failed to read request header")]
    ReadRequestHeaderFailed,

    /// AEAD header 解密失败（Go server.go:165 `OpenVMessAEADHeader` 失败）。
    ///
    /// `should_drain`/`bytes_read` 透传给 inbound 的 drainer（Go server.go:167-169：
    /// shouldDrain 时按 AEAD 层精确已读字节数 AcknowledgeReceive）。
    #[error("AEAD read failed: {msg} (should_drain: {should_drain}, bytes_read: {bytes_read})")]
    AeadReadFailed {
        /// 错误详情。
        msg: String,
        /// 是否应 drain（Go encrypt.go：解密失败 true，读流失败 false）。
        should_drain: bool,
        /// AEAD 层已读字节数（不含 auth_id 的 16B）。
        bytes_read: usize,
    },

    /// 用户无效。
    #[error("invalid user: {0}")]
    InvalidUser(String),

    /// legacy VMess（alterId≠0）不支持——本实现 AEAD-only。
    ///
    /// Go v26 已整体删除 alterId（proto/JSON 全无此字段），legacy 请求在服务端
    /// 自然死于 "invalid user"；Rust 保留 alterId 兼容字段但在配置层显式拒绝。
    #[error("legacy VMess (alterId={0}) is not supported, this build is AEAD-only")]
    UnsupportedLegacyAlterId(i64),

    /// padding 读取失败。
    #[error("failed to read padding")]
    ReadPaddingFailed,

    /// checksum 读取失败。
    #[error("failed to read checksum")]
    ReadChecksumFailed,

    /// 远程地址无效。
    #[error("invalid remote address")]
    InvalidRemoteAddress,

    /// 安全类型未知。
    #[error("unknown security type: {0}")]
    UnknownSecurityType(i32),

    /// 读取响应头长度失败。
    #[error("unable to read response header length")]
    ReadResponseHeaderLengthFailed,

    /// 响应头长度解密失败。
    #[error("failed to decrypt response header length")]
    DecryptResponseHeaderLengthFailed,

    /// 读取响应头数据失败。
    #[error("unable to read response header data")]
    ReadResponseHeaderDataFailed,

    /// 响应头数据解密失败。
    #[error("failed to decrypt response header payload")]
    DecryptResponseHeaderPayloadFailed,

    /// 响应头读取失败（4 字节固定头）。
    #[error("failed to read response header")]
    ReadResponseHeaderFailed,

    /// 响应头首字节不匹配（期望 vs 实际）。
    #[error("unexpected response header. expecting {expected} but actually {actual}")]
    UnexpectedResponseHeader { expected: u8, actual: u8 },

    /// 响应命令读取失败。
    #[error("failed to read response command")]
    ReadResponseCommandFailed,

    /// 不支持的请求选项组合。
    #[error("invalid option: {0}")]
    InvalidOption(String),

    /// 行为种子初始化失败（drainer）。
    #[error("failed to initialize drainer: {0}")]
    DrainerInitFailed(String),

    /// 通用错误（兜底）。
    #[error("{0}")]
    Other(String),

    /// 当前实现尚未支持（IO 边界 stub）。
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// VMess crate 的统一 Result 类型别名。
pub type Result<T> = std::result::Result<T, VmessError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_io_error() {
        let err = VmessError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn display_user_not_found() {
        let err = VmessError::UserNotFound;
        assert_eq!(err.to_string(), "user does not exist");
    }

    #[test]
    fn display_replay() {
        let err = VmessError::Replay;
        assert_eq!(err.to_string(), "replayed request");
    }

    #[test]
    fn display_unexpected_response_header() {
        let err = VmessError::UnexpectedResponseHeader { expected: 1, actual: 2 };
        let s = err.to_string();
        assert!(s.contains("expecting 1"));
        assert!(s.contains("actually 2"));
    }

    #[test]
    fn display_unknown_security_type() {
        let err = VmessError::UnknownSecurityType(99);
        assert!(err.to_string().contains("99"));
    }

    #[test]
    fn from_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: VmessError = io.into();
        assert!(matches!(err, VmessError::Io(_)));
    }

    #[test]
    fn from_crypto_error() {
        let crypto_err = CryptoError::InvalidKeyLength(8);
        let err: VmessError = crypto_err.into();
        assert!(matches!(err, VmessError::Crypto(_)));
    }

    #[test]
    fn from_prost_decode_error_roundtrip() {
        use prost::Message;
        use xray_proto::xray::proxy::vmess::Account;
        // 截断的 protobuf：tag=1(string)，len=3 但只随 2 字节
        let buf: &[u8] = &[0x0A, 0x03, b'a', b'b'];
        let result = Account::decode(buf);
        let err: VmessError = result.unwrap_err().into();
        assert!(matches!(err, VmessError::ProstDecode(_)));
    }

    #[test]
    fn display_unsupported_legacy_alter_id() {
        let err = VmessError::UnsupportedLegacyAlterId(64);
        let msg = err.to_string();
        assert!(msg.contains("alterId=64") && msg.contains("AEAD-only"), "got: {msg}");
    }
}