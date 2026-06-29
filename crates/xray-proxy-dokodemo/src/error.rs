//! Dokodemo-door 代理错误类型。

use thiserror::Error;

/// Dokodemo 代理错误。
#[derive(Debug, Error)]
pub enum DokodemoError {
    /// 配置无效（如 rewrite_address 缺失但 follow_redirect=false）。
    #[error("invalid dokodemo config: {0}")]
    InvalidConfig(String),

    /// 上游连接失败。
    #[error("upstream connection failed: {0}")]
    UpstreamFailed(String),

    /// follow_redirect 模式下无法获取原始目标地址（SO_ORIGINAL_DST 失败）。
    #[error("get original destination failed: {0}")]
    GetOriginalDestFailed(String),

    /// 不允许的网络类型（如配置只允许 TCP 但收到 UDP）。
    #[error("network not allowed: {0}")]
    NetworkNotAllowed(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Dokodemo 操作 Result 别名。
pub type Result<T> = std::result::Result<T, DokodemoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = DokodemoError::InvalidConfig("missing rewrite_address".into());
        assert!(format!("{e}").contains("missing rewrite_address"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: DokodemoError = io_err.into();
        assert!(matches!(err, DokodemoError::Io(_)));
    }
}
