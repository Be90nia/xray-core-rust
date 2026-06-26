//! VLESS 协议错误类型。
//!
//! 对应 Go 版本 `proxy/vless/` 各包用 `errors.New(...)` 表达的错误情况。

use std::io;

/// VLESS 协议所有错误变体。
#[derive(Debug, thiserror::Error)]
pub enum VlessError {
    /// UUID 字符串无法解析。
    #[error("failed to parse ID: {0}")]
    InvalidUuid(String),

    /// Account 字段值非法（如 `Encryption` 不支持）。
    #[error("invalid account: {0}")]
    InvalidAccount(String),

    /// 重复添加用户（email 冲突）。
    #[error("User {0} already exists.")]
    UserAlreadyExists(String),

    /// 按 email/UUID 查找用户时未找到。
    #[error("User {0} not found.")]
    UserNotFound(String),

    /// `Del` 调用时 email 为空。
    #[error("Email must not be empty.")]
    EmptyEmail,

    /// 请求版本字节不在支持范围内（当前仅支持 0）。
    #[error("invalid request version: {0}")]
    InvalidRequestVersion(u8),

    /// 请求头中的 UUID 在 validator 中查不到对应用户。
    #[error("invalid request user id: {0}")]
    InvalidRequestUserId(String),

    /// 请求头 command 字节非法。
    #[error("invalid request command: {0}")]
    InvalidRequestCommand(u8),

    /// 请求头地址解析失败或地址缺失。
    #[error("invalid request address")]
    InvalidRequestAddress,

    /// 读底层连接失败。
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// 写底层连接失败。
    #[error("failed to write: {0}")]
    WriteFailed(String),

    /// protobuf 编解码失败。
    #[error("protobuf error: {0}")]
    ProtoError(String),

    /// 响应版本与请求版本不匹配。
    #[error("unexpected response version. Expecting {expected} but actually {actual}")]
    UnexpectedResponseVersion { expected: u8, actual: u8 },

    /// IO 边界 trait 方法未实现（依赖未就绪）。
    #[error("operation not supported: {0}")]
    NotImplemented(String),

    /// 其他未分类错误。
    #[error("{0}")]
    Other(String),
}

/// `Result<T, VlessError>` 别名。
pub type Result<T> = std::result::Result<T, VlessError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_uuid() {
        let e = VlessError::InvalidUuid("not-a-uuid".into());
        assert!(format!("{e}").contains("failed to parse ID"));
    }

    #[test]
    fn display_user_already_exists() {
        let e = VlessError::UserAlreadyExists("test@example.com".into());
        let s = format!("{e}");
        assert!(s.contains("already exists"));
        assert!(s.contains("test@example.com"));
    }

    #[test]
    fn display_unexpected_response_version() {
        let e = VlessError::UnexpectedResponseVersion { expected: 0, actual: 1 };
        let s = format!("{e}");
        assert!(s.contains("Expecting 0"));
        assert!(s.contains("actually 1"));
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "short");
        let e: VlessError = io_err.into();
        assert!(matches!(e, VlessError::Io(_)));
        assert!(format!("{e}").contains("io error"));
    }
}
