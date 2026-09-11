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
use crate::observer::{HttpProbeExecutor, ProbeExecutor};

/// Burst Observatory app Feature 实现。包装 [`BurstObserver`] + 调度 IO。
pub struct BurstObservatoryFeature {
    observer: Arc<BurstObserver>,
    /// 受观察的 outbound tag 列表（Go `Config.SubjectSelector`）。
    subject_selector: Vec<String>,
    /// 探测 executor，set_io 注入后 start 才启动循环。
    executor: Mutex<Option<Arc<dyn ProbeExecutor>>>,
}

impl BurstObservatoryFeature {
    /// `subject_selector` 对应 Go `Config.SubjectSelector`（数组，bd z9ma；
    /// 此前是 `SubjectSelector[0]` 单值方言）。空列表 = 观测器 no-op
    /// （与 Go burstobserver.go:69 一致）。
    /// `ping_config` 是 JSON Value（BurstObservatoryConfig.ping_config），
    /// 反序列化为 [`HealthPingConfig`] 后用 [`HealthPingSettings::from_config`]
    /// 归一化（默认值/最小约束）。
    pub fn new(subject_selector: Vec<String>, ping_config: Option<&serde_json::Value>) -> Self {
        // u7nu：parse 失败时整体丢弃 → warn 后回退默认；不让子字段类型偏差
        // 致整段 pingConfig 静默弃用（如 Go `interval:"1m"` 字符串）。
        let hp_config = ping_config.and_then(|v| {
            match serde_json::from_value::<HealthPingConfig>(v.clone()) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(
                        "BurstObservatoryFeature: pingConfig parse failed: {e}, falling back to defaults"
                    );
                    None
                }
            }
        });
        let settings = HealthPingSettings::from_config(hp_config.as_ref());
        Self {
            observer: Arc::new(BurstObserver::new(settings)),
            subject_selector,
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
        if self.subject_selector.is_empty() {
            return Ok(()); // 与 Go burstobserver.go:69/observer.go:50 一致
        }

        let executor = self.executor.lock().clone();
        match executor {
            Some(executor) => {
                let subject = self.subject_selector.clone();
                let selector: Arc<dyn Fn() -> Vec<String> + Send + Sync> =
                    Arc::new(move || subject.clone());
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

    /// bd 2umqf：装配阶段接线（对应 Go RequireFeatures 拿 outbound.Manager +
    /// dispatcher）。`outbound_selector` 到场（`init_dependencies` 二次注入，
    /// functions.rs bag2）时用 health ping settings 构造 [`HttpProbeExecutor`]
    /// 直连兜底注入——subject 非空时 `start` 不再 StartFailed。
    ///
    /// soqc：**生产装配不走此兜底**——xray-core functions.rs 在 bag2 之前
    /// `set_io` 注入 [`RealOutboundProbeExecutor`](crate::observer::RealOutboundProbeExecutor)
    /// （经 outbound 拨号，对齐 Go ping.go:42 tagged.Dialer），已注入跳过保护
    /// 使兜底不覆盖。幂等：已注入跳过（f23r 双阶段注入惯例，factory 阶段仍
    /// 不注入）。
    fn init_dependencies(&self, deps: &xray_features::DepBag) {
        if deps.outbound_selector.is_none() || self.executor.lock().is_some() {
            return;
        }
        let s = self.observer.settings();
        let timeout_ms = (s.timeout / 1_000_000).max(1) as u64;
        self.set_io(Arc::new(HttpProbeExecutor::new(
            s.destination.clone(),
            s.http_method.clone(),
            timeout_ms,
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProbeResult;
    use crate::observer::FixedProbeExecutor;

    #[test]
    fn new_empty_subject_noop() {
        let f = BurstObservatoryFeature::new(Vec::new(), None);
        assert!(f.start().is_ok(), "empty subject → noop");
    }

    #[test]
    fn start_without_executor_fails() {
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], None);
        let err = f.start().expect_err("must fail without executor");
        assert!(matches!(err, FeatureError::StartFailed { .. }));
    }

    #[test]
    fn feature_name_is_burst_observatory() {
        let f = BurstObservatoryFeature::new(Vec::new(), None);
        assert_eq!(f.feature_name(), "burstObservatory");
    }

    #[tokio::test]
    async fn start_with_executor_runs_scheduler() {
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], None);
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
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], Some(&ping));
        let s = f.observer.settings();
        assert_eq!(s.destination, "https://custom.test/204");
        assert_eq!(s.interval, 15_000_000_000);
        assert_eq!(s.timeout, 3_000_000_000);
        assert_eq!(s.http_method, "GET");
    }

    struct NoTags;
    impl xray_features::OutboundTagSelector for NoTags {
        fn select_by_prefix(&self, _prefixes: &[String]) -> Vec<String> {
            Vec::new()
        }
    }

    /// bd 2umqf：init_dependencies 接线——DepBag 带 outbound_selector 时注入
    /// executor，subject 非空的 start 不再 StartFailed；无 selector 时仍
    /// fail-fast（factory 阶段无 DepBag 的 f23r 语义保持）。
    #[tokio::test]
    async fn init_dependencies_wires_executor_and_start_succeeds() {
        // destination 指向本地必败端口，探测循环不碰外网。
        let ping = serde_json::json!({
            "destination": "http://127.0.0.1:1/",
            "interval": 3_600_000_000_000i64,
            "timeout": 500_000_000i64,
        });
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], Some(&ping));
        f.start()
            .expect_err("without bag injection start must still fail");

        let sel: Arc<dyn xray_features::OutboundTagSelector> = Arc::new(NoTags);
        let bag = xray_features::DepBag::new().with_outbound_selector(sel);
        f.init_dependencies(&bag);
        f.start().expect("start after init_dependencies must succeed");
        assert!(f.observer.is_scheduler_running());
        f.close().expect("close");
    }

    #[test]
    fn init_dependencies_without_selector_stays_unwired() {
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], None);
        f.init_dependencies(&xray_features::DepBag::new());
        let err = f.start().expect_err("no selector → no executor → StartFailed");
        assert!(matches!(err, FeatureError::StartFailed { .. }));
    }
    #[test]
    fn new_with_unparseable_ping_config_falls_back_to_defaults() {
        // u7nu：parse 失败必须 warn 而非静默——用 garbage 字符串强制 parse 失败。
        let bad = serde_json::json!({"interval": "not-a-duration", "samplingCount": 5});
        let f = BurstObservatoryFeature::new(vec!["out-a".to_string()], Some(&bad));
        let s = f.observer.settings();
        // 整段丢弃 → 走默认（DEFAULT_DESTINATION / DEFAULT_SAMPLING_COUNT=10）。
        assert_eq!(s.sampling_count, crate::DEFAULT_SAMPLING_COUNT);
        assert_eq!(s.destination, crate::DEFAULT_DESTINATION);
    }
}