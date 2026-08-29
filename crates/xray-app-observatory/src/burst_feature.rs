//! BurstObservatoryFeature —— 将 burst Observatory app 接入 Feature 系统。
//!
//! 对应 Go `app/observatory/burst/burstobserver.go`：`Start()` 在
//! `SubjectSelector` 非空时启动 background 探测循环。
//!
//! IO 注入：
//! - selector：在 [`BurstObservatoryFeature::start`] 时用 `subject_selector`
//!   闭包构造（固定筛选，与 Go `SubjectSelector` 等价）。
//! - executor：通过 [`set_io`](Self::set_io) 在装配阶段注入
//!   （对应 Go `New()` 中 RequireFeatures 拿 outbound.Manager + dispatcher）。
//!
//! `set_io` 注入后 `start` 启动 `BurstObserver::start_scheduler`。
//! 未注入时 `start` 返 StartFailed——让 Instance 装配失败早暴露（f23r 模式）。

use std::sync::Arc;

use parking_lot::Mutex;

use xray_features::{Feature, FeatureError, Result};

use crate::burst::{BurstObserver, HealthPingConfig, HealthPingSettings};
use crate::observer::ProbeExecutor;

/// Burst Observatory app Feature 实现。包装 [`BurstObserver`] + 调度 IO。
pub struct BurstObservatoryFeature {
    observer: Arc<BurstObserver>,
    /// subject_outbound 标签（Go `Config.SubjectSelector`）。
    subject_outbound: String,
    /// 探测 executor，set_io 注入后 start 才启动循环。
    executor: Mutex<Option<Arc<dyn ProbeExecutor>>>,
}

impl BurstObservatoryFeature {
    /// 从配置创建 BurstObservatoryFeature。
    ///
    /// `subject_outbound` 是 Go `Config.SubjectSelector[0]`（逗号分隔字符串
    /// 的第一个 tag）——xray-conf 把它解析成单一字符串，本实装保持兼容。
    /// `ping_config` 是 JSON Value（BurstObservatoryConfig.ping_config），
    /// 反序列化为 [`HealthPingConfig`] 后用 [`HealthPingSettings::from_config`]
    /// 归一化（默认值/最小约束）。
    pub fn new(subject_outbound: String, ping_config: Option<&serde_json::Value>) -> Self {
        let hp_config = ping_config
            .and_then(|v| serde_json::from_value::<HealthPingConfig>(v.clone()).ok());
        let settings = HealthPingSettings::from_config(hp_config.as_ref());
        Self {
            observer: Arc::new(BurstObserver::new(settings)),
            subject_outbound,
            executor: Mutex::new(None),
        }
    }

    /// 获取内部 BurstObserver 引用（读观测快照）。
    pub fn observer(&self) -> &Arc<BurstObserver> {
        &self.observer
    }

    /// 注入探测 executor（对应 Go `New()` 中 RequireFeatures 拿 dispatcher）。
    /// 须在 `Feature::start` 前调用。
    pub fn set_io(&self, executor: Arc<dyn ProbeExecutor>) {
        *self.executor.lock() = Some(executor);
    }
}

impl Feature for BurstObservatoryFeature {
    fn feature_name(&self) -> &'static str {
        "burstObservatory"
    }

    /// 对应 Go `burstobserver.go:68-82 Start()`：
    /// - `SubjectSelector` 空 → 静默 no-op（与 Go observer.go:50 一致）。
    /// - `SubjectSelector` 非空但未注入 executor → StartFailed（f23r 模式）。
    /// - 正常启动 → `BurstObserver::start_scheduler` 进入循环。
    fn start(&self) -> Result<()> {
        if self.subject_outbound.is_empty() {
            return Ok(()); // 与 Go observer.go:50 一致
        }

        let executor = self.executor.lock().clone();
        match executor {
            Some(executor) => {
                let subject = self.subject_outbound.clone();
                let selector: Arc<dyn Fn() -> Vec<String> + Send + Sync> =
                    Arc::new(move || vec![subject.clone()]);
                self.observer
                    .clone()
                    .start_scheduler(selector, executor);
                Ok(())
            }
            None => Err(FeatureError::StartFailed {
                name: "burstObservatory",
                message: "executor not injected (call set_io before start)".to_string(),
            }),
        }
    }

    fn close(&self) -> Result<()> {
        self.observer.stop_scheduler();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProbeResult;
    use crate::observer::FixedProbeExecutor;

    #[test]
    fn new_empty_subject_noop() {
        let f = BurstObservatoryFeature::new(String::new(), None);
        assert!(f.start().is_ok(), "empty subject → noop");
    }

    #[test]
    fn start_without_executor_fails() {
        let f = BurstObservatoryFeature::new("out-a".into(), None);
        let err = f.start().expect_err("must fail without executor");
        assert!(matches!(err, FeatureError::StartFailed { .. }));
    }

    #[test]
    fn feature_name_is_burst_observatory() {
        let f = BurstObservatoryFeature::new(String::new(), None);
        assert_eq!(f.feature_name(), "burstObservatory");
    }

    #[tokio::test]
    async fn start_with_executor_runs_scheduler() {
        let f = BurstObservatoryFeature::new("out-a".into(), None);
        let executor: Arc<dyn ProbeExecutor> = Arc::new(
            FixedProbeExecutor::new().with_result("out-a", ProbeResult {
                alive: true,
                delay: 100,
                last_error_reason: String::new(),
            }),
        );
        f.set_io(executor);
        f.start().expect("with executor should start");
        assert!(f.observer.is_scheduler_running());
        f.close().expect("close");
        assert!(!f.observer.is_scheduler_running());
    }

    #[test]
    fn new_with_ping_config_applies_settings() {
        let ping = serde_json::json!({
            "destination": "https://custom.test/204",
            "interval": 15_000_000_000i64,
            "samplingCount": 5,
            "timeout": 3_000_000_000i64,
            "httpMethod": "GET",
        });
        let f = BurstObservatoryFeature::new("out-a".into(), Some(&ping));
        let s = f.observer.settings();
        assert_eq!(s.destination, "https://custom.test/204");
        assert_eq!(s.interval, 15_000_000_000);
        assert_eq!(s.timeout, 3_000_000_000);
        assert_eq!(s.http_method, "GET");
    }
}