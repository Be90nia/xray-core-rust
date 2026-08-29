//! ObservatoryFeature —— 将 Observatory app 接入 Feature 系统。
//!
//! 对应 Go `app/observatory/observer.go`：`Start()` 在 SubjectSelector 非空时
//! 启动 background 探测 goroutine；探测 IO（outbound.Manager 的 Select +
//! dispatcher dial）通过 [`Observer::start`] 的 trait 注入，实例装配阶段用
//! [`ObservatoryFeature::set_io`] 提供（对应 Go `New()` 里 RequireFeatures）。
//!
//! # 装配路径（bd issue f23r wiring 双断点修复）
//!
//! - 直接构造后手动 [`set_io`](Self::set_io) 后 [`start`](Feature::start)；
//!   适用测试。
//! - 通过 [`init_dependencies`](Feature::init_dependencies) 走 [`DepBag`]：
//!   Instance 在所有 feature 注册完成后、start 前调用本方法，本方法
//!   从 bag 拿 `OutboundTagSelector` 后端并装配 [`RealOutboundSelector`] +
//!   [`HttpProbeExecutor::from_config`] 自动注入 IO。`bag.outbound_selector`
//!   为 `None`（proxyman 尚未装配）时 fail-fast：
//!   `SubjectSelector` 非空但缺 IO → 返 [`FeatureError::StartFailed`]；
//!   `SubjectSelector` 为空 → 与 Go observer.go:50 一致静默 no-op。

use parking_lot::RwLock;
use std::sync::Arc;
use xray_features::{DepBag, Feature, FeatureError, Result};

use crate::config::ObservatoryConfig;
use crate::observer::{HttpProbeExecutor, Observer, OutboundSelector, ProbeExecutor, RealOutboundSelector};

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
    ///
    /// 重复调用：后者覆盖前者（fail-fast 装配阶段使用）。
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
    /// 启动 background 探测循环。
    ///
    /// # 行为变化（bd issue f23r）
    ///
    /// 旧版：未注入 IO 时 `tracing::warn!` + `Ok(())`（探测静默失败）。
    /// 新版：`SubjectSelector` 非空但缺 IO → 返 [`FeatureError::StartFailed`]，
    /// 让 Instance 装配失败早暴露；`SubjectSelector` 空 → 静默 no-op（与 Go
    /// observer.go:50 一致，避免空配置误报）。
    fn start(&self) -> Result<()> {
        // 与 Go observer.go:50 一致：subject_selector 空时 background 永不启动，
        // 这里同样不报错（配置语义合法，只是没活可干）。
        if self.observer.config().subject_selector.is_empty() {
            return Ok(());
        }

        let io = self.io.read().clone();
        match io {
            Some((selector, executor)) => self
                .observer
                .start(selector, executor)
                .map_err(|e| FeatureError::StartFailed {
                    name: "observatory",
                    message: e.to_string(),
                }),
            None => Err(FeatureError::StartFailed {
                name: "observatory",
                message: "selector/executor not injected (call set_io before start, \
                          or wire init_dependencies with DepBag.outbound_selector)"
                    .to_string(),
            }),
        }
    }

    fn close(&self) -> Result<()> {
        self.observer
            .close()
            .map_err(|e| FeatureError::CloseFailed {
                name: "observatory",
                message: e.to_string(),
            })
    }

    /// 装配阶段依赖注入：若 bag 提供 `OutboundTagSelector` 则自动注入
    /// [`RealOutboundSelector`] + [`HttpProbeExecutor::from_config`]。
    ///
    /// 已有 IO（[`set_io`](Self::set_io) 显式调用过）不覆盖——便于测试 fixture
    /// 在构造后立即 `set_io` 的场景。
    ///
    /// `bag.outbound_selector` 为 `None` 时**不注入也不报错**——start 阶段
    /// 由 [`start`](Self::start) 负责 fail-fast 决策（IO 缺失 + selector 非空
    /// → StartFailed）。
    fn init_dependencies(&self, deps: &DepBag) {
        if self.io.read().is_some() {
            return; // 显式 set_io 优先
        }
        let Some(backend) = deps.outbound_selector.clone() else {
            return;
        };
        let selector: Arc<dyn OutboundSelector> =
            Arc::new(RealOutboundSelector::with_selector(backend));
        let executor: Arc<dyn ProbeExecutor> =
            Arc::new(HttpProbeExecutor::from_config(self.observer.config()));
        self.set_io(selector, executor);
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
    async fn feature_start_without_io_fails_fast_when_selector_nonempty() {
        // bd f23r：未 set_io + subject_selector 非空 → 返 StartFailed，
        // 旧版返回 Ok + warn 静默失败。改 fail-fast 让装配错误早暴露。
        let f = ObservatoryFeature::new(fast_cfg());
        let err = f.start().expect_err("start must fail without set_io");
        match err {
            xray_features::FeatureError::StartFailed { name, .. } => {
                assert_eq!(name, "observatory");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        assert!(!f.observer().is_started());
    }

    #[tokio::test]
    async fn feature_init_dependencies_with_outbound_backend_wires_io() {
        // bd f23r：init_dependencies(bag) + bag.outbound_selector=Some → 注入
        // RealOutboundSelector + HttpProbeExecutor，start 后能起循环。
        use xray_features::{DepBag, OutboundTagSelector};

        struct EchoSelector;
        impl OutboundTagSelector for EchoSelector {
            fn select_by_prefix(&self, prefixes: &[String]) -> Vec<String> {
                prefixes.to_vec()
            }
        }

        // probe_url 走 127.0.0.1 测试端口（start 之前 listener 可能未就绪，
        // 探测失败不算回归；只验 selector 路径被调用过）。
        let cfg = ObservatoryConfig {
            subject_selector: vec!["node1".into()],
            probe_url: "http://127.0.0.1:1/".into(), // 必连失败
            probe_interval: 60_000, // 长间隔防止探测跑（仅验 selector 路径）
            ..Default::default()
        };
        let f = ObservatoryFeature::new(cfg);
        let bag = DepBag::new()
            .with_outbound_selector(Arc::new(EchoSelector) as Arc<dyn OutboundTagSelector>);
        f.init_dependencies(&bag);
        // start 现在不返 Err（IO 已注入），即使探测失败也仅是单 round 失败。
        f.start().expect("start should succeed after init_dependencies wires IO");
        assert!(f.observer().is_started());
    }

    #[tokio::test]
    async fn feature_init_dependencies_without_backend_no_op() {
        // bag.outbound_selector=None → 不注入 IO，start 仍 fail-fast。
        use xray_features::DepBag;
        let f = ObservatoryFeature::new(fast_cfg());
        f.init_dependencies(&DepBag::new());
        let err = f.start().expect_err("start must still fail with no backend in bag");
        assert!(matches!(
            err,
            xray_features::FeatureError::StartFailed { name: "observatory", message: _ }
        ));
    }

    #[tokio::test]
    async fn feature_explicit_set_io_overrides_init_dependencies() {
        // 已 set_io → init_dependencies 不覆盖（显式优先）。
        use crate::observer::FixedProbeExecutor;
        use xray_features::{DepBag, OutboundTagSelector};
        struct BoomSelector;
        impl OutboundTagSelector for BoomSelector {
            fn select_by_prefix(&self, _p: &[String]) -> Vec<String> {
                panic!("init_dependencies should not call this when set_io is already set")
            }
        }
        let f = ObservatoryFeature::new(fast_cfg());
        let exec = Arc::new(FixedProbeExecutor::new().with_result(
            "a",
            crate::config::ProbeResult {
                alive: true,
                delay: 5,
                last_error_reason: String::new(),
            },
        ));
        f.set_io(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            exec.clone(),
        );
        f.init_dependencies(
            &DepBag::new()
                .with_outbound_selector(Arc::new(BoomSelector) as Arc<dyn xray_features::OutboundTagSelector>),
        );
        f.start().unwrap();
        assert!(f.observer().is_started());
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
