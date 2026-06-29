//! Freedom 代理错误类型。

use thiserror::Error;

/// Freedom 代理错误。
#[derive(Debug, Error)]
pub enum FreedomError {
    /// 配置无效（如 fragment range min > max）。
    #[error("invalid freedom config: {0}")]
    InvalidConfig(String),

    /// 拨号失败（目标不可达 / 超时）。
    #[error("dial failed: {0}")]
    DialFailed(String),

    /// 规则匹配失败（IP matcher 初始化错误）。
    #[error("rule match failed: {0}")]
    RuleMatchFailed(String),

    /// 策略限制（如超时、连接数限制）。
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Freedom 操作 Result 别名。
pub type Result<T> = std::result::Result<T, FreedomError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = FreedomError::InvalidConfig("bad fragment range".into());
        assert!(format!("{e}").contains("bad fragment range"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: FreedomError = io_err.into();
        assert!(matches!(err, FreedomError::Io(_)));
    }
}
