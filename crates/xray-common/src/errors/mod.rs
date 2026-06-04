//! 错误类型与定义
//!
//! 对应 Go 版本 `common/errors` 包，提供带前缀、消息、调用者信息、
//! 内部错误和严重级别的错误类型，以及日志记录构造器。

use std::fmt;

use crate::log::{self, Severity};

/// Xray 错误类型，包含上下文、严重级别和因果链。
///
/// 对应 Go 版本 `common/errors.Error`，提供丰富的错误信息追踪。
#[derive(Debug)]
pub struct Error {
    prefix: Option<String>,
    message: String,
    caller: Option<String>,
    inner: Option<Box<dyn std::error::Error + Send + Sync>>,
    severity: Severity,
}

impl Error {
    /// 创建新的错误（Info 级别）。
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            prefix: None,
            message: message.into(),
            caller: None,
            inner: None,
            severity: Severity::Info,
        }
    }

    /// 从标准错误创建（Info 级别）。
    pub fn base(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            prefix: None,
            message: source.to_string(),
            caller: None,
            inner: Some(Box::new(source)),
            severity: Severity::Info,
        }
    }

    /// 创建 Warning 级别的错误。
    pub fn new_warning(message: impl Into<String>) -> Self {
        Self {
            prefix: None,
            message: message.into(),
            caller: None,
            inner: None,
            severity: Severity::Warning,
        }
    }

    /// 创建 Error 级别的错误。
    pub fn new_error(message: impl Into<String>) -> Self {
        Self {
            prefix: None,
            message: message.into(),
            caller: None,
            inner: None,
            severity: Severity::Error,
        }
    }

    /// 设置前缀，用于链式调用。
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// 设置内部错误，用于链式调用。
    pub fn with_inner(mut self, inner: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.inner = Some(Box::new(inner));
        self
    }

    /// 设置严重级别，用于链式调用。
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// 返回错误消息。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// 返回前缀（如有）。
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// 返回严重级别。
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// 返回调用者信息（如有）。
    pub fn caller(&self) -> Option<&str> {
        self.caller.as_deref()
    }

    /// 返回内部错误的引用。
    pub fn inner(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
        self.inner.as_ref().map(|b| b.as_ref())
    }

    /// 获取根因：递归解包内部错误直到找到最内层的错误。
    pub fn cause(&self) -> &(dyn std::error::Error + Send + Sync) {
        match &self.inner {
            Some(inner) => {
                // 尝试向下转换为 Error 以递归查找
                let inner_err: &(dyn std::error::Error + Send + Sync) = inner.as_ref();
                // 如果内部错误也是 Error 类型，递归查找根因
                if let Some(inner_xray) = inner_err.downcast_ref::<Error>() {
                    inner_xray.cause()
                } else {
                    inner_err
                }
            }
            None => self,
        }
    }

    /// 创建错误并记录到日志（Info 级别）。
    pub fn log_new(message: impl Into<String>) -> Self {
        let msg = message.into();
        let err = Self::new(&msg);
        log::info(msg);
        err
    }

    /// 创建 Warning 级别错误并记录到日志。
    pub fn log_warning(message: impl Into<String>) -> Self {
        let msg = message.into();
        let err = Self::new_warning(&msg);
        log::warning(msg);
        err
    }

    /// 创建 Error 级别错误并记录到日志。
    pub fn log_error(message: impl Into<String>) -> Self {
        let msg = message.into();
        let err = Self::new_error(&msg);
        log::error(msg);
        err
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.prefix {
            Some(prefix) => {
                write!(f, "[{}] {}", prefix, self.message)?;
            }
            None => {
                write!(f, "{}", self.message)?;
            }
        }
        if let Some(inner) = &self.inner {
            write!(f, " > {}", inner)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .as_ref()
            .map(|b| b.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// 模块级便捷函数：创建新的 Error（Info 级别）。
pub fn new(message: impl Into<String>) -> Error {
    Error::new(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_new() {
        let err = Error::new("test error");
        assert_eq!(err.message(), "test error");
        assert_eq!(err.severity(), Severity::Info);
        assert!(err.prefix().is_none());
        assert!(err.inner().is_none());
    }

    #[test]
    fn test_error_base() {
        let err = Error::base(std::io::Error::new(std::io::ErrorKind::NotFound, "file missing"));
        assert_eq!(err.severity(), Severity::Info);
        assert!(err.inner().is_some());
    }

    #[test]
    fn test_error_new_warning() {
        let err = Error::new_warning("something off");
        assert_eq!(err.severity(), Severity::Warning);
        assert_eq!(err.message(), "something off");
    }

    #[test]
    fn test_error_new_error() {
        let err = Error::new_error("critical failure");
        assert_eq!(err.severity(), Severity::Error);
        assert_eq!(err.message(), "critical failure");
    }

    #[test]
    fn test_with_prefix() {
        let err = Error::new("msg").with_prefix("Module");
        assert_eq!(err.prefix(), Some("Module"));
        assert_eq!(format!("{}", err), "[Module] msg");
    }

    #[test]
    fn test_with_inner() {
        let err = Error::new("outer").with_inner(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "pipe broke",
        ));
        assert!(err.inner().is_some());
        let display = format!("{}", err);
        assert!(display.contains("outer"));
        assert!(display.contains("pipe broke"));
    }

    #[test]
    fn test_with_severity() {
        let err = Error::new("msg").with_severity(Severity::Error);
        assert_eq!(err.severity(), Severity::Error);
    }

    #[test]
    fn test_display_no_prefix_no_inner() {
        let err = Error::new("simple error");
        assert_eq!(format!("{}", err), "simple error");
    }

    #[test]
    fn test_display_with_prefix_and_inner() {
        let err = Error::new("outer")
            .with_prefix("Layer")
            .with_inner(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        let display = format!("{}", err);
        assert!(display.starts_with("[Layer] outer"));
        assert!(display.contains(" > "));
        assert!(display.contains("timeout"));
    }

    #[test]
    fn test_source() {
        let err = Error::new("outer").with_inner(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }

    #[test]
    fn test_cause_no_inner() {
        let err = Error::new("root");
        // 没有内部错误时，cause 返回自身
        let cause_msg = err.cause().to_string();
        assert_eq!(cause_msg, "root");
    }

    #[test]
    fn test_cause_with_inner() {
        let inner = Error::new("inner error");
        let outer = Error::new("outer error").with_inner(inner);
        // 内部是 Error 类型，递归到最内层
        let cause_msg = outer.cause().to_string();
        assert_eq!(cause_msg, "inner error");
    }

    #[test]
    fn test_cause_with_non_error_inner() {
        let err = Error::new("wrapper").with_inner(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
        let cause_msg = err.cause().to_string();
        assert!(cause_msg.contains("eof"));
    }

    #[test]
    fn test_cause_chain() {
        let deepest = Error::new("deepest");
        let middle = Error::new("middle").with_inner(deepest);
        let top = Error::new("top").with_inner(middle);
        let cause_msg = top.cause().to_string();
        assert_eq!(cause_msg, "deepest");
    }

    #[test]
    fn test_module_level_new() {
        let err = new("module level");
        assert_eq!(err.message(), "module level");
    }

    #[test]
    fn test_log_new() {
        // 不应 panic
        let err = Error::log_new("logged info");
        assert_eq!(err.severity(), Severity::Info);
    }

    #[test]
    fn test_log_warning() {
        let err = Error::log_warning("logged warning");
        assert_eq!(err.severity(), Severity::Warning);
    }

    #[test]
    fn test_log_error() {
        let err = Error::log_error("logged error");
        assert_eq!(err.severity(), Severity::Error);
    }

    #[test]
    fn test_error_chain_display() {
        let e1 = Error::new("level1");
        let e2 = Error::new("level2").with_inner(e1);
        let e3 = Error::new("level3").with_prefix("P").with_inner(e2);
        let display = format!("{}", e3);
        // 应包含前缀、最外层消息和内部错误链
        assert!(display.contains("[P] level3"));
        assert!(display.contains("level2"));
        assert!(display.contains("level1"));
    }
}
