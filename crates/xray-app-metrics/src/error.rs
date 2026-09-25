//! xray-app-metrics 错误类型。
//!
//! 对应 Go `app/metrics/metrics.go` 中通过 `errors.New`/`errors.LogInfo` 表达的失败路径。
//! 不直接打印日志，统一用 `at_warning`/`at_error` 由上层 `tracing` 订阅。

use thiserror::Error;

/// metrics crate 错误。
#[derive(Debug, Error)]
pub enum MetricsError {
    /// 监听地址已被占用或无效。
    #[error("metrics listen address invalid or already in use: {0}")]
    ListenInvalid(String),

    /// OutboundListener 已关闭，无法再接收连接。
    #[error("outbound listener closed")]
    ListenerClosed,

    /// StatsManager 缺失（必填依赖未注入）。
    #[error("stats manager not available")]
    StatsManagerMissing,

    /// OutboundManager 缺失（必填依赖未注入）。
    #[error("outbound manager not available")]
    OutboundManagerMissing,

    /// Observatory 缺失（可选依赖，缺失时不暴露 observatory 指标）。
    #[error("observatory not available")]
    ObservatoryMissing,

    /// 重复注册的 outbound tag。
    #[error("duplicate outbound tag: {0}")]
    DuplicateTag(String),

    /// HTTP server 注册失败（由上层 `HttpServerRegistrar` 实现）。
    #[error("http server registration failed: {0}")]
    HttpServerRegister(String),

    /// counter name 解析失败（非 `{type}>>>{tag_or_user}>>>traffic>>>{direction}` 形式）。
    #[error("invalid counter name (expected 4 >>>-separated parts): {0}")]
    InvalidCounterName(String),

    /// 其他内部错误，包装第三方错误时使用。
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// 记录 warning 级日志（保留 Go `errors.LogInfo` 语义）。
pub fn at_warning(err: &MetricsError) {
    tracing::warn!(target: "xray_app_metrics", "{err}");
}

/// 记录 error 级日志（保留 Go `errors.LogErrorInner` 语义）。
pub fn at_error(err: &MetricsError) {
    tracing::error!(target: "xray_app_metrics", "{err}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_listen_invalid() {
        let e = MetricsError::ListenInvalid("0.0.0.0:1".into());
        assert!(format!("{e}").contains("0.0.0.0:1"));
    }

    #[test]
    fn display_listener_closed() {
        let e = MetricsError::ListenerClosed;
        assert_eq!(format!("{e}"), "outbound listener closed");
    }

    #[test]
    fn display_stats_manager_missing() {
        let e = MetricsError::StatsManagerMissing;
        assert!(format!("{e}").contains("stats"));
    }

    #[test]
    fn display_outbound_manager_missing() {
        let e = MetricsError::OutboundManagerMissing;
        assert!(format!("{e}").contains("outbound"));
    }

    #[test]
    fn display_observatory_missing() {
        let e = MetricsError::ObservatoryMissing;
        assert!(format!("{e}").contains("observatory"));
    }

    #[test]
    fn display_duplicate_tag() {
        let e = MetricsError::DuplicateTag("metrics_out".into());
        assert!(format!("{e}").contains("metrics_out"));
    }

    #[test]
    fn display_http_server_register() {
        let e = MetricsError::HttpServerRegister("bind 127.0.0.1:9090".into());
        assert!(format!("{e}").contains("9090"));
    }

    #[test]
    fn display_invalid_counter_name() {
        let e = MetricsError::InvalidCounterName("foo".into());
        assert!(format!("{e}").contains("foo"));
    }

    #[test]
    fn other_wraps_dynamic_error() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
        let e: MetricsError = inner.into();
        assert!(format!("{e}").contains("boom"));
    }

    #[test]
    fn at_warning_does_not_panic() {
        at_warning(&MetricsError::ListenerClosed);
    }

    #[test]
    fn at_error_does_not_panic() {
        at_error(&MetricsError::ListenerClosed);
    }

    #[test]
    fn debug_repr_contains_variant() {
        let e = MetricsError::ListenerClosed;
        let s = format!("{e:?}");
        assert!(s.contains("ListenerClosed"));
    }
}
