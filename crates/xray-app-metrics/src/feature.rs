//! MetricsFeature —— 将 Metrics app 接入 Feature 系统。
//!
//! 对应 Go `app/metrics/metrics.go` 中 `Handler` 作为 `features.Feature`。
//!
//! ## `Feature::start` 编排（对应 Go `MetricsHandler.Start`，metrics.go:87-123）
//!
//! 1. 若 `MetricsConfig::listen` 非空：`TokioHttpServer::start_http_listen` 绑端口 并
//!    `tokio::spawn` accept loop，处理 `GET /metrics` 返回 Prometheus 文本。
//! 2. 创建 `Outbound`（`OutboundListener` + tag）并经 registrar add。
//! 3. 幂等：第二次 `start` 仅返回 `Ok(())`，不重复 spawn。
//!
//! `Feature::start` 假设在 tokio runtime 内被调用（与 `Commander::start` 一致，
//! 由 `xray_core` Instance 保证）。
//!
//! ## 依赖注入
//!
//! 默认情况下 `MetricsFeature` 内部持有：
//! - [`TokioHttpServer`]：真实 HTTP server（已实现）。
//! - `EmptyStats` collector：返回空 `StatsSnapshot`；HTTP body 仅含 `# HELP`/`# TYPE` 头，仍能 curl
//!   到合法 Prometheus exposition format。
//! - `RecordingOutboundRegistrar`：仅记 tag。
//!
//! 上层可经 [`MetricsFeature::with_stats_collector`] / `with_obs_collector`
//! 注入真实 stats/observability 收集器。

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use xray_features::Feature;

use crate::{
    config::MetricsConfig,
    error::MetricsError,
    metrics::{
        MetricsHandler, ObservationCollector, RecordingOutboundRegistrar, StatsCollector,
        TokioHttpServer,
    },
};

/// 空 StatsCollector：返回空快照；HTTP body 仍含 `# HELP`/`# TYPE`。
struct EmptyStats;
impl StatsCollector for EmptyStats {
    fn collect(&self) -> crate::metrics::StatsSnapshot {
        crate::metrics::StatsSnapshot::default()
    }
}

/// Metrics app Feature 实现。包装 [`MetricsHandler`] + 默认依赖。
pub struct MetricsFeature {
    handler: MetricsHandler,
    http_server: TokioHttpServer,
    stats: parking_lot::RwLock<Arc<dyn StatsCollector>>,
    obs: parking_lot::RwLock<Option<Arc<dyn ObservationCollector>>>,
    registrar: Arc<RecordingOutboundRegistrar>,
    started: AtomicBool,
}

impl MetricsFeature {
    /// 从配置创建 MetricsFeature。
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            handler: MetricsHandler::new(config),
            http_server: TokioHttpServer::new(),
            stats: parking_lot::RwLock::new(Arc::new(EmptyStats)),
            obs: parking_lot::RwLock::new(None),
            registrar: Arc::new(RecordingOutboundRegistrar::new()),
            started: AtomicBool::new(false),
        }
    }

    /// 注入 stats 收集器（应在 `start` 前调用）。
    #[must_use]
    pub fn with_stats_collector(self, stats: Arc<dyn StatsCollector>) -> Self {
        *self.stats.write() = stats;
        self
    }

    /// 装配阶段注入 stats 收集器（`&self` 版本：Instance 持 `Arc<MetricsFeature>`
    /// 时调用，bd 3xmjx；内部 RwLock，start 前生效）。
    pub fn set_stats_collector(&self, stats: Arc<dyn StatsCollector>) {
        *self.stats.write() = stats;
    }

    /// 注入 observation 收集器。
    #[must_use]
    pub fn with_obs_collector(self, obs: Arc<dyn ObservationCollector>) -> Self {
        *self.obs.write() = Some(obs);
        self
    }

    /// 获取内部 MetricsHandler 引用。
    pub fn handler(&self) -> &MetricsHandler {
        &self.handler
    }
}

impl Feature for MetricsFeature {
    fn feature_name(&self) -> &'static str {
        "metrics"
    }

    fn start(&self) -> xray_features::Result<()> {
        // 幂等保护。
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let stats = self.stats.read().clone();
        let obs = self.obs.read().clone();
        self.handler.start(&self.http_server, stats, obs, self.registrar.as_ref()).map_err(
            |e: MetricsError| xray_features::FeatureError::StartFailed {
                name: "metrics",
                message: format!("{e}"),
            },
        )
    }

    fn close(&self) -> xray_features::Result<()> {
        self.started.store(false, Ordering::SeqCst);
        // 通知 http_server 释放后台 task（5s timeout）。
        let closer = self.http_server.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                closer.shutdown().await;
            });
        } else {
            // 不在 runtime 内：spawn 时再尝试，不阻塞 close。
            drop(closer);
        }
        self.handler.close();
        Ok(())
    }
}
