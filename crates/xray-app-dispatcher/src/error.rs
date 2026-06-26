//! 分发器错误类型
//!
//! 对应 Go `app/dispatcher/` 包内散落的错误（`errSniffingTimeout`、`errUnknownContent`、
//! `ErrNoClue`、`ErrProtoNeedMoreData` 等）。

use thiserror::Error;

/// 分发器错误
#[derive(Debug, Error)]
pub enum DispatcherError {
    /// 无效目的地（对应 Go `panic("Dispatcher: Invalid destination.")`）
    #[error("invalid destination")]
    InvalidDestination,

    /// 嗅探超时（对应 Go `errSniffingTimeout`）
    #[error("sniffing timeout")]
    SniffingTimeout,

    /// 未知内容（所有 sniffer 都未识别）
    #[error("unknown content")]
    UnknownContent,

    /// 嗅探器暂无判断（对应 Go `common.ErrNoClue`）：协议不匹配，且无法判定未来是否匹配
    #[error("no clue")]
    NoClue,

    /// 协议匹配但需要更多数据（对应 Go `protocol.ErrProtoNeedMoreData`）
    #[error("need more data")]
    NeedMoreData,

    /// 未找到出站处理器
    #[error("outbound handler not found: {0}")]
    HandlerNotFound(String),

    /// 默认出站处理器不存在
    #[error("default outbound handler not exist")]
    NoDefaultHandler,

    /// 路由未匹配（fallthrough 到默认）
    #[error("default route for {0}")]
    DefaultRoute(String),

    /// FakeDNSEngine 未初始化
    #[error("fake dns engine not initialized")]
    FakeDnsNotInitialized,

    /// 找不到 counter（stats 注册失败）
    #[error("counter not registered: {0}")]
    CounterNotFound(String),

    /// 上游 IO 错误
    #[error("io error: {0}")]
    Io(String),

    /// 其他错误（用于 trait/IO 边界占位）
    #[error("other: {0}")]
    Other(String),
}

impl DispatcherError {
    /// 警告级别工厂（对应 Go `errors.New(...).AtWarning()`）
    #[must_use]
    pub fn at_warning(self) -> Self {
        self
    }

    /// 错误级别工厂（对应 Go `errors.New(...).AtError()`）
    #[must_use]
    pub fn at_error(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_destination() {
        assert_eq!(DispatcherError::InvalidDestination.to_string(), "invalid destination");
    }

    #[test]
    fn display_sniffing_timeout() {
        assert_eq!(DispatcherError::SniffingTimeout.to_string(), "sniffing timeout");
    }

    #[test]
    fn display_unknown_content() {
        assert_eq!(DispatcherError::UnknownContent.to_string(), "unknown content");
    }

    #[test]
    fn display_handler_not_found() {
        let e = DispatcherError::HandlerNotFound("proxy".to_string());
        assert_eq!(e.to_string(), "outbound handler not found: proxy");
    }

    #[test]
    fn at_warning_returns_self() {
        let e = DispatcherError::NoClue.at_warning();
        assert!(matches!(e, DispatcherError::NoClue));
    }

    #[test]
    fn at_error_returns_self() {
        let e = DispatcherError::FakeDnsNotInitialized.at_error();
        assert!(matches!(e, DispatcherError::FakeDnsNotInitialized));
    }
}
