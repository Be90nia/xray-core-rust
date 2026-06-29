//! CLI 错误类型。

use thiserror::Error;

/// CLI 错误。
#[derive(Debug, Error)]
pub enum CliError {
    /// 配置文件未找到。
    #[error("config file not found: {0}")]
    ConfigNotFound(String),

    /// 配置文件加载/解析失败。
    #[error("failed to load config: {0}")]
    ConfigLoadFailed(String),

    /// 配置无效（语义错误）。
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// Xray 实例启动失败。
    #[error("failed to start xray: {0}")]
    StartFailed(String),

    /// 功能尚未实现（切片边界）。
    #[error("unimplemented: {what}; see P7-3 切片2 roadmap")]
    Unimplemented { what: &'static str },

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// CLI 操作 Result 别名。
pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = CliError::ConfigNotFound("/etc/xray/config.json".into());
        assert!(format!("{e}").contains("/etc/xray/config.json"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: CliError = io_err.into();
        assert!(matches!(err, CliError::Io(_)));
    }

    #[test]
    fn unimplemented_display_contains_what() {
        let e = CliError::Unimplemented {
            what: "full New(config) initialization",
        };
        assert!(format!("{e}").contains("New(config)"));
    }
}
