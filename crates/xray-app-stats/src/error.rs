//! 统计应用服务的错误类型。
//!
//! 对应 Go `app/stats` 各 `errors.New("...")` 调用的具体化。
//! 主要包括 Manager 注册冲突、Channel 生命周期错误，以及 command 处理错误。

use thiserror::Error;

/// 统计应用服务错误。
///
/// 覆盖 `app/stats/{stats, channel, online_map, command}` 的所有错误路径。
/// 重新导出 features 层的 [`ChannelError`](xray_features::stats::ChannelError)
/// 与 [`ManagerError`](xray_features::stats::ManagerError) 以便调用方一处可见。
#[derive(Debug, Error)]
pub enum StatsError {
    /// Manager 层错误（重名 / 未实现）。
    #[error(transparent)]
    Manager(#[from] xray_features::stats::ManagerError),

    /// Channel 层错误（订阅 / 关闭 / 未启动）。
    #[error(transparent)]
    Channel(#[from] xray_features::stats::ChannelError),

    /// Command 处理时未找到指定资源。
    /// 对应 Go `status.Error(codes.NotFound, request.Name+" not found.")`。
    #[error("resource `{name}` not found")]
    NotFound { name: String },

    /// 内部 Tokio task join 失败。
    #[error("background task failed: {0}")]
    Task(String),
}

/// 警告级日志辅助（不返回错误，仅记录）。
///
/// 对应 Go `errors.LogDebug(context.Background(), "...")`。
/// 在 Rust 端用 `tracing::debug!`，由调用方按需启用。
pub fn log_warning(msg: impl AsRef<str>) {
    tracing::warn!("{}", msg.as_ref());
}

/// 错误级日志辅助。
pub fn log_error(msg: impl AsRef<str>) {
    tracing::error!("{}", msg.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_error_display_not_found() {
        let e = StatsError::NotFound {
            name: "user>>>traffic".into(),
        };
        assert_eq!(e.to_string(), "resource `user>>>traffic` not found");
    }

    #[test]
    fn stats_error_display_task() {
        let e = StatsError::Task("panic in broadcast".into());
        assert_eq!(e.to_string(), "background task failed: panic in broadcast");
    }

    #[test]
    fn stats_error_from_manager_already_registered() {
        let inner = xray_features::stats::ManagerError::AlreadyRegistered {
            kind: "Counter",
            name: "c1".into(),
        };
        let e: StatsError = inner.into();
        assert!(matches!(e, StatsError::Manager(_)));
        assert_eq!(e.to_string(), "Counter `c1` already registered");
    }

    #[test]
    fn stats_error_from_channel_closed() {
        let inner = xray_features::stats::ChannelError::Closed;
        let e: StatsError = inner.into();
        assert!(matches!(e, StatsError::Channel(_)));
        assert_eq!(e.to_string(), "channel closed");
    }

    #[test]
    fn stats_error_from_manager_not_implemented() {
        let inner = xray_features::stats::ManagerError::NotImplemented;
        let e: StatsError = inner.into();
        assert!(matches!(e, StatsError::Manager(_)));
        assert_eq!(e.to_string(), "not implemented");
    }

    #[test]
    fn stats_error_from_channel_subscribers_limit() {
        let inner = xray_features::stats::ChannelError::SubscribersLimitReached { limit: 5 };
        let e: StatsError = inner.into();
        assert!(matches!(e, StatsError::Channel(_)));
        assert_eq!(e.to_string(), "subscribers reached limit (5)");
    }

    #[test]
    fn log_helpers_do_not_panic() {
        log_warning("test warning");
        log_error("test error");
    }
}
