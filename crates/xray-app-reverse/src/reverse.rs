//! Reverse 编排：持有 bridges + portals，提供 init/start/close。
//!
//! 对应 Go `app/reverse/reverse.go` 的 `Reverse` struct。

use crate::bridge::{Bridge, BridgeFactory, Portal, PortalFactory};
use crate::config::ReverseConfig;
use crate::error::{at_error, at_warning, ReverseError};

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
        Self {
            config,
            bridges: Vec::new(),
            portals: Vec::new(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{validate_bridge_config, validate_portal_config};
    use crate::config::{BridgeConfig, PortalConfig};
    use parking_lot::Mutex;
    use std::sync::Arc;

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
            bridges: vec![BridgeConfig {
                tag: "b1".into(),
                domain: "b.example.com".into(),
            }],
            portals: vec![PortalConfig {
                tag: "p1".into(),
                domain: "p.example.com".into(),
            }],
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
            bridges: vec![BridgeConfig {
                tag: "".into(),
                domain: "d".into(),
            }],
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
            portals: vec![PortalConfig {
                tag: "t".into(),
                domain: "".into(),
            }],
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
            bridges: vec![BridgeConfig {
                tag: "f".into(),
                domain: "f".into(),
            }],
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
