//! MetricsFeature —— 将 Metrics app 接入 Feature 系统。
//!
//! 对应 Go `app/metrics/metrics.go` 中 `Handler` 作为 `features.Feature`。
//!
//! ## 当前限制
//!
//! Go 版 `Start()` 需要 `outbound.Manager`（注册/移除 handler）+ HTTP server
//! + stats/observability 收集器。Rust 端这些通过 trait 注入，factory 无法
//! 在构造时获取——故 `start()` 暂不启动 HTTP listener。Handler 已构造并注册，
//! 待 Instance 接线后可由上层注入依赖并调用 `MetricsHandler::start(...)`。

use xray_features::{Feature, Result};

use crate::config::MetricsConfig;
use crate::metrics::MetricsHandler;

/// Metrics app Feature 实现。包装 [`MetricsHandler`]。
pub struct MetricsFeature {
    handler: MetricsHandler,
}

impl MetricsFeature {
    /// 从配置创建 MetricsFeature。
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            handler: MetricsHandler::new(config),
        }
    }

    /// 获取内部 MetricsHandler 引用（供 Instance 注入 http_server/stats 后启动）。
    pub fn handler(&self) -> &MetricsHandler {
        &self.handler
    }
}

impl Feature for MetricsFeature {
    fn feature_name(&self) -> &'static str {
        "metrics"
    }

    fn start(&self) -> Result<()> {
        // ponytail: HTTP server + stats collector + outbound registrar
        // injected from the instance. Not available at factory time.
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.handler.close();
        Ok(())
    }
}
