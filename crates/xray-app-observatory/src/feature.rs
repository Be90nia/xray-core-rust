//! ObservatoryFeature —— 将 Observatory app 接入 Feature 系统。
//!
//! 对应 Go `app/observatory/observer.go`：`Start()` 在 SubjectSelector 非空时
//! 启动 background 探测 goroutine；探测 IO（outbound.Manager 的 Select +
//! dispatcher dial）通过 [`Observer::start`] 的 trait 注入，实例装配阶段用
//! [`ObservatoryFeature::set_io`] 提供（对应 Go `New()` 里 RequireFeatures）。

use parking_lot::RwLock;
use std::sync::Arc;
use xray_features::{Feature, FeatureError, Result};

use crate::config::ObservatoryConfig;
use crate::observer::{Observer, OutboundSelector, ProbeExecutor};

/// Observatory app Feature 实现。包装 [`Observer`]。
pub struct ObservatoryFeature {
    observer: Observer,
    /// 探测 IO（selector + executor），set_io 注入后 start 才启动循环。
    io: RwLock<Option<(Arc<dyn OutboundSelector>, Arc<dyn ProbeExecutor>)>>,
}

impl ObservatoryFeature {
    /// 从配置创建 ObservatoryFeature。
    pub fn new(config: ObservatoryConfig) -> Self {
        Self {
            observer: Observer::new(config),
            io: RwLock::new(None),
        }
    }

    /// 获取内部 Observer 引用（读观测快照 / 上层桥接 ObservationProvider）。
    pub fn observer(&self) -> &Observer {
        &self.observer
    }

    /// 注入探测 IO（对应 Go `New()` 中 RequireFeatures 拿 outbound.Manager
    /// + dispatcher）。须在 `Feature::start` 前调用。
    pub fn set_io(
        &self,
        selector: Arc<dyn OutboundSelector>,
        executor: Arc<dyn ProbeExecutor>,
    ) {
        *self.io.write() = Some((selector, executor));
    }
}

impl Feature for ObservatoryFeature {
    fn feature_name(&self) -> &'static str {
        "observatory"
    }

    /// 对应 Go `Observer.Start()`（observer.go:49-55）：SubjectSelector 非空时
    /// 启动 background 探测循环。依赖未注入时保持注册但不启动（warn）。
    fn start(&self) -> Result<()> {
        let io = self.io.read().clone();
        match io {
            Some((selector, executor)) => {
                self.observer
                    .start(selector, executor)
                    .map_err(|e| FeatureError::StartFailed {
                        name: "observatory",
                        message: e.to_string(),
                    })?;
            }
            None => {
                if !self.observer.config().subject_selector.is_empty() {
                    tracing::warn!(
                        "observatory: selector/executor not injected, probe loop not started"
                    );
                }
            }
        }
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.observer
            .close()
            .map_err(|e| FeatureError::CloseFailed {
                name: "observatory",
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::{CountingProbeExecutor, NoopOutboundSelector};
    use std::sync::Arc;
    use std::time::Duration;

    fn fast_cfg() -> ObservatoryConfig {
        ObservatoryConfig {
            subject_selector: vec!["a".into()],
            probe_interval: 50,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn feature_start_spawns_probe_loop() {
        let f = ObservatoryFeature::new(fast_cfg());
        let executor = Arc::new(CountingProbeExecutor::new(true));
        f.set_io(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            executor.clone(),
        );
        f.start().unwrap();
        assert!(f.observer().is_started());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            executor.count() >= 1,
            "probe loop should run after Feature::start, got {}",
            executor.count()
        );
        let obs = f.observer().get_observation();
        assert!(obs.status.iter().any(|s| s.outbound_tag == "a" && s.alive));
    }

    #[tokio::test]
    async fn feature_close_cancels_probe_loop() {
        let f = ObservatoryFeature::new(fast_cfg());
        let executor = Arc::new(CountingProbeExecutor::new(true));
        f.set_io(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            executor.clone(),
        );
        f.start().unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(executor.count() >= 1);
        f.close().unwrap();
        let frozen = executor.count();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            executor.count(),
            frozen,
            "probe loop must stop after Feature::close"
        );
    }

    #[tokio::test]
    async fn feature_start_without_io_is_ok_not_started() {
        let f = ObservatoryFeature::new(fast_cfg());
        f.start().unwrap();
        assert!(!f.observer().is_started());
    }

    #[tokio::test]
    async fn feature_start_empty_subject_selector_noop() {
        // Go observer.go:50：SubjectSelector 空 → 不启动 background
        let cfg = ObservatoryConfig {
            probe_interval: 50,
            ..Default::default()
        };
        let f = ObservatoryFeature::new(cfg);
        let executor = Arc::new(CountingProbeExecutor::new(true));
        f.set_io(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            executor.clone(),
        );
        f.start().unwrap();
        assert!(!f.observer().is_started());
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(executor.count(), 0);
    }
}
