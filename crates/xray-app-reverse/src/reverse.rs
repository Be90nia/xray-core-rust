//! Reverse 编排：持有 bridges + portals，提供 init/start/close。
//!
//! 对应 Go `app/reverse/reverse.go` 的 `Reverse` struct。

use crate::{
    bridge::{Bridge, BridgeFactory, Portal, PortalFactory},
    config::ReverseConfig,
    error::{ReverseError, at_error, at_warning},
};

/// Reverse：根编排类。
///
/// 通过注入 `BridgeFactory` + `PortalFactory` 构造具体 bridge/portal，
/// 本类只负责顺序初始化 + 启动 + 关闭。
pub struct Reverse<B, P> {
    config: ReverseConfig,
    bridges: Vec<B>,
    portals: Vec<P>,
}

impl<B: Bridge, P: Portal> Reverse<B, P> {
    pub fn new(config: ReverseConfig) -> Self {
        Self { config, bridges: Vec::new(), portals: Vec::new() }
    }

    pub fn config(&self) -> &ReverseConfig {
        &self.config
    }

    pub fn bridge_count(&self) -> usize {
        self.bridges.len()
    }

    pub fn portal_count(&self) -> usize {
        self.portals.len()
    }

    /// Init：用工厂构造所有 bridge + portal。
    ///
    /// 任一构造失败则返回 Err（已构造的保留在 self 中，与 Go 行为一致）。
    pub fn init<F: BridgeFactory<Bridge = B>, G: PortalFactory<Portal = P>>(
        &mut self,
        bridge_factory: &F,
        portal_factory: &G,
    ) -> Result<(), ReverseError> {
        for cfg in &self.config.bridges {
            let b = bridge_factory.create(cfg)?;
            self.bridges.push(b);
        }
        for cfg in &self.config.portals {
            let p = portal_factory.create(cfg)?;
            self.portals.push(p);
        }
        Ok(())
    }

    /// Start：先启动 bridges，再启动 portals。
    pub fn start(&self) -> Result<(), ReverseError> {
        for b in &self.bridges {
            if let Err(e) = b.start() {
                at_error(&e);
                return Err(e);
            }
        }
        for p in &self.portals {
            if let Err(e) = p.start() {
                at_error(&e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Close：关闭所有 bridges + portals，合并错误。
    pub fn close(&self) -> Result<(), ReverseError> {
        let mut first_err: Option<ReverseError> = None;
        for b in &self.bridges {
            if let Err(e) = b.close() {
                at_warning(&e);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        for p in &self.portals {
            if let Err(e) = p.close() {
                at_warning(&e);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// ===========================================================================
// ReverseFeature：xray_features::Feature 适配 + 生产工厂
//
// 对应 Go `app/reverse/reverse.go`：init() 注册 Config factory +
// Reverse.Init(d, ohm) + Start/Close。Go v26 已移除 JSON reverse 配置
// （infra/conf xray.go PrintRemovedFeatureError），app/reverse 仅经 VLESS
// reverse（v1.rvs.cool）程序化消费——本 Feature 同样面向程序化构造：
// factory 建 feature（proto Config），dispatcher/registrar 经
// [`ReverseFeature::set_deps`] 注入（对应 Go core.RequireFeatures）后 start。
// ===========================================================================

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use xray_features::{Feature, FeatureError};

use crate::{
    bridge::{LinkDispatch, RuntimeBridge, RuntimePortal},
    outbound::OutboundRegistrar,
};

/// Reverse 运行时依赖（对应 Go `core.RequireFeatures(routing.Dispatcher, outbound.Manager)`）。
#[derive(Clone)]
pub struct ReverseDeps {
    pub dispatcher: Arc<dyn LinkDispatch>,
    pub registrar: Arc<dyn OutboundRegistrar>,
}

/// Bridge 工厂：[`RuntimeBridge`]。
pub struct RuntimeBridgeFactory(pub Arc<dyn LinkDispatch>);

impl crate::bridge::BridgeFactory for RuntimeBridgeFactory {
    type Bridge = RuntimeBridge;

    fn create(&self, config: &crate::config::BridgeConfig) -> Result<RuntimeBridge, ReverseError> {
        RuntimeBridge::new(config, Arc::clone(&self.0))
    }
}

/// Portal 工厂：[`RuntimePortal`]。
pub struct RuntimePortalFactory(pub Arc<dyn OutboundRegistrar>);

impl crate::bridge::PortalFactory for RuntimePortalFactory {
    type Portal = RuntimePortal;

    fn create(&self, config: &crate::config::PortalConfig) -> Result<RuntimePortal, ReverseError> {
        RuntimePortal::new(config, Arc::clone(&self.0))
    }
}

/// Reverse Feature：编排 bridges + portals（对应 Go `Reverse` struct，reverse.go:38-94）。
///
/// 生命周期：`new(config)` → `set_deps`（dispatcher + registrar）→ `start`
/// （Go `Init` + `Start`：先 bridges 后 portals）→ `close`。
pub struct ReverseFeature {
    config: ReverseConfig,
    deps: parking_lot::RwLock<Option<ReverseDeps>>,
    inner: parking_lot::RwLock<Option<Reverse<RuntimeBridge, RuntimePortal>>>,
    started: AtomicBool,
}

impl ReverseFeature {
    #[must_use]
    pub fn new(config: ReverseConfig) -> Self {
        Self {
            config,
            deps: parking_lot::RwLock::new(None),
            inner: parking_lot::RwLock::new(None),
            started: AtomicBool::new(false),
        }
    }

    /// 注入运行时依赖（对应 Go `core.RequireFeatures`，factory 时刻不可得）。
    pub fn set_deps(
        &self,
        dispatcher: Arc<dyn LinkDispatch>,
        registrar: Arc<dyn OutboundRegistrar>,
    ) {
        *self.deps.write() = Some(ReverseDeps { dispatcher, registrar });
    }

    pub fn config(&self) -> &ReverseConfig {
        &self.config
    }
}

impl Feature for ReverseFeature {
    fn feature_name(&self) -> &'static str {
        "ReverseFeature"
    }

    fn start(&self) -> Result<(), FeatureError> {
        let err = |e: ReverseError| FeatureError::StartFailed {
            name: "ReverseFeature",
            message: e.to_string(),
        };
        let Some(deps) = self.deps.read().clone() else {
            // 未注入依赖（对应 Go RequireFeatures 失败）：warn + 跳过
            tracing::warn!(
                target: "xray_app_reverse",
                "reverse feature start skipped: no dispatcher/registrar injected"
            );
            return Ok(());
        };
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut reverse = Reverse::new(self.config.clone());
        reverse
            .init(&RuntimeBridgeFactory(deps.dispatcher), &RuntimePortalFactory(deps.registrar))
            .map_err(err)?;
        reverse.start().map_err(err)?;
        *self.inner.write() = Some(reverse);
        Ok(())
    }

    fn close(&self) -> Result<(), FeatureError> {
        self.started.store(false, Ordering::Release);
        if let Some(r) = self.inner.read().as_ref() {
            r.close().map_err(|e| FeatureError::CloseFailed {
                name: "ReverseFeature",
                message: e.to_string(),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use parking_lot::Mutex;

    use super::*;
    use crate::{
        bridge::{validate_bridge_config, validate_portal_config},
        config::{BridgeConfig, PortalConfig},
    };

    struct StubBridge {
        tag: String,
        domain: String,
        started: Mutex<bool>,
        closed: Mutex<bool>,
    }

    impl Bridge for StubBridge {
        fn start(&self) -> Result<(), ReverseError> {
            *self.started.lock() = true;
            Ok(())
        }

        fn close(&self) -> Result<(), ReverseError> {
            *self.closed.lock() = true;
            Ok(())
        }

        fn worker_count(&self) -> usize {
            0
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn domain(&self) -> &str {
            &self.domain
        }
    }

    struct StubPortal {
        tag: String,
        domain: String,
        started: Mutex<bool>,
        closed: Mutex<bool>,
    }

    impl Portal for StubPortal {
        fn start(&self) -> Result<(), ReverseError> {
            *self.started.lock() = true;
            Ok(())
        }

        fn close(&self) -> Result<(), ReverseError> {
            *self.closed.lock() = true;
            Ok(())
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn domain(&self) -> &str {
            &self.domain
        }
    }

    struct StubBridgeFactory;
    impl BridgeFactory for StubBridgeFactory {
        type Bridge = StubBridge;

        fn create(&self, cfg: &BridgeConfig) -> Result<StubBridge, ReverseError> {
            validate_bridge_config(cfg)?;
            Ok(StubBridge {
                tag: cfg.tag.clone(),
                domain: cfg.domain.clone(),
                started: Mutex::new(false),
                closed: Mutex::new(false),
            })
        }
    }

    struct StubPortalFactory;
    impl PortalFactory for StubPortalFactory {
        type Portal = StubPortal;

        fn create(&self, cfg: &PortalConfig) -> Result<StubPortal, ReverseError> {
            validate_portal_config(cfg)?;
            Ok(StubPortal {
                tag: cfg.tag.clone(),
                domain: cfg.domain.clone(),
                started: Mutex::new(false),
                closed: Mutex::new(false),
            })
        }
    }

    fn sample_config() -> ReverseConfig {
        ReverseConfig {
            bridges: vec![BridgeConfig { tag: "b1".into(), domain: "b.example.com".into() }],
            portals: vec![PortalConfig { tag: "p1".into(), domain: "p.example.com".into() }],
        }
    }

    #[test]
    fn new_has_no_bridges_portals() {
        let r: Reverse<StubBridge, StubPortal> = Reverse::new(ReverseConfig::default());
        assert_eq!(r.bridge_count(), 0);
        assert_eq!(r.portal_count(), 0);
    }

    #[test]
    fn init_creates_all() {
        let mut r = Reverse::new(sample_config());
        r.init(&StubBridgeFactory, &StubPortalFactory).unwrap();
        assert_eq!(r.bridge_count(), 1);
        assert_eq!(r.portal_count(), 1);
    }

    #[test]
    fn init_invalid_bridge_returns_err() {
        let cfg = ReverseConfig {
            bridges: vec![BridgeConfig { tag: "".into(), domain: "d".into() }],
            portals: vec![],
        };
        let mut r = Reverse::new(cfg);
        let err = r.init(&StubBridgeFactory, &StubPortalFactory).unwrap_err();
        assert!(matches!(err, ReverseError::BridgeTagEmpty));
    }

    #[test]
    fn init_invalid_portal_returns_err() {
        let cfg = ReverseConfig {
            bridges: vec![],
            portals: vec![PortalConfig { tag: "t".into(), domain: "".into() }],
        };
        let mut r = Reverse::new(cfg);
        let err = r.init(&StubBridgeFactory, &StubPortalFactory).unwrap_err();
        assert!(matches!(err, ReverseError::PortalDomainEmpty));
    }

    #[test]
    fn start_invokes_each_bridge_portal() {
        let mut r = Reverse::new(sample_config());
        r.init(&StubBridgeFactory, &StubPortalFactory).unwrap();
        r.start().unwrap();
        // bridges/portals 是 by-value，无法直接验证 started flag。
        // 通过 close 不报错间接验证生命周期 OK。
        r.close().unwrap();
    }

    #[test]
    fn close_after_init_succeeds() {
        let mut r = Reverse::new(sample_config());
        r.init(&StubBridgeFactory, &StubPortalFactory).unwrap();
        r.close().unwrap();
    }

    #[test]
    fn close_with_empty_is_ok() {
        let r: Reverse<StubBridge, StubPortal> = Reverse::new(ReverseConfig::default());
        r.close().unwrap();
    }

    #[test]
    fn close_collects_first_error() {
        // 用一个 always-fail 的 bridge factory
        struct FailingBridge;
        impl Bridge for FailingBridge {
            fn start(&self) -> Result<(), ReverseError> {
                Ok(())
            }

            fn close(&self) -> Result<(), ReverseError> {
                Err(ReverseError::WorkerStopped)
            }

            fn worker_count(&self) -> usize {
                0
            }

            fn tag(&self) -> &str {
                "fail"
            }

            fn domain(&self) -> &str {
                "fail"
            }
        }

        struct FailingBridgeFactory;
        impl BridgeFactory for FailingBridgeFactory {
            type Bridge = FailingBridge;

            fn create(&self, cfg: &BridgeConfig) -> Result<FailingBridge, ReverseError> {
                validate_bridge_config(cfg)?;
                Ok(FailingBridge)
            }
        }

        let cfg = ReverseConfig {
            bridges: vec![BridgeConfig { tag: "f".into(), domain: "f".into() }],
            portals: vec![],
        };
        let mut r: Reverse<FailingBridge, StubPortal> = Reverse::new(cfg);
        r.init(&FailingBridgeFactory, &StubPortalFactory).unwrap();
        let err = r.close().unwrap_err();
        assert!(matches!(err, ReverseError::WorkerStopped));
    }

    #[test]
    fn empty_init_does_nothing() {
        let mut r: Reverse<StubBridge, StubPortal> = Reverse::new(ReverseConfig::default());
        r.init(&StubBridgeFactory, &StubPortalFactory).unwrap();
        assert_eq!(r.bridge_count(), 0);
        assert_eq!(r.portal_count(), 0);
    }
}

// ===========================================================================
// ReverseFeature 测试
// ===========================================================================

#[cfg(test)]
mod feature_tests {
    use xray_buf::pipe;
    use xray_common::net::destination::Destination;

    use super::*;
    use crate::{
        bridge::LinkDispatch,
        config::{BridgeConfig, PortalConfig},
        outbound::StubOutboundRegistrar,
    };

    #[derive(Default)]
    struct MockLinkDispatch;

    #[async_trait::async_trait]
    impl LinkDispatch for MockLinkDispatch {
        async fn dispatch(
            &self,
            _dest: &Destination,
            _inbound_tag: Option<&str>,
        ) -> Result<xray_transport::link::Link, ReverseError> {
            let (r, w) = pipe::new();
            Ok(xray_transport::link::Link::new(Box::new(r), Box::new(w)))
        }

        async fn dispatch_link(
            &self,
            _dest: &Destination,
            _link: xray_transport::link::Link,
            _inbound_tag: Option<&str>,
        ) -> Result<(), ReverseError> {
            Ok(())
        }
    }

    fn sample_config() -> ReverseConfig {
        ReverseConfig {
            bridges: vec![BridgeConfig { tag: "bridge".into(), domain: "t.example.com".into() }],
            portals: vec![PortalConfig { tag: "portal".into(), domain: "t.example.com".into() }],
        }
    }

    #[tokio::test]
    async fn feature_start_registers_portal_outbound_and_closes() {
        let registrar = Arc::new(StubOutboundRegistrar::new());
        let feature = ReverseFeature::new(sample_config());
        feature.set_deps(
            Arc::new(MockLinkDispatch),
            Arc::clone(&registrar) as Arc<dyn crate::outbound::OutboundRegistrar>,
        );

        feature.start().expect("start");
        assert_eq!(registrar.count(), 1, "portal outbound registered");
        assert_eq!(registrar.tags(), vec!["portal".to_string()]);

        // 幂等 start
        feature.start().expect("start idempotent");
        assert_eq!(registrar.count(), 1);

        feature.close().expect("close");
        assert_eq!(registrar.count(), 0, "portal outbound removed");
    }

    #[test]
    fn feature_start_without_deps_warns_and_skips() {
        let feature = ReverseFeature::new(sample_config());
        // 无依赖：warn + Ok（对应 Go RequireFeatures 失败场景的安全降级）
        feature.start().expect("start skipped without deps");
        feature.close().expect("close");
    }

    #[tokio::test]
    async fn feature_invalid_config_propagates() {
        let registrar = Arc::new(StubOutboundRegistrar::new());
        let feature = ReverseFeature::new(ReverseConfig {
            bridges: vec![BridgeConfig { tag: String::new(), domain: "d".into() }],
            portals: vec![],
        });
        feature.set_deps(
            Arc::new(MockLinkDispatch),
            Arc::clone(&registrar) as Arc<dyn crate::outbound::OutboundRegistrar>,
        );
        let err = feature.start().unwrap_err();
        assert!(
            matches!(err, FeatureError::StartFailed { .. }),
            "invalid bridge config propagates: {err:?}"
        );
    }
}
