//! 负载均衡：Balancer + BalancingStrategy + RoundRobin + Override。
//!
//! 翻译自 `app/router/{balancing,balancing_override}.go`。
//!
//! # IO 边界 trait
//!
//! - `OutboundHandlerSelector`（Go `outbound.HandlerSelector`）
//! - `ObservationProvider`（Go `extension.Observatory`）
//! - 当前 stub 返回 `Err(NotHandlerSelector)` / `Err(ObservationUnavailable)`，
//!   上层接入时提供真实实现。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use xray_proto::xray::core::app::observatory::ObservationResult;

use crate::error::RouterError;

/// 出站管理器选择接口。
///
/// 对应 Go `outbound.HandlerSelector.Select(tags []string) ([]string, error)`。
pub trait OutboundHandlerSelector: Send + Sync {
    /// 返回在 `selectors` 中存在的出站 tag。
    fn select_outbounds(&self, selectors: &[String]) -> Result<Vec<String>, RouterError>;
}

/// 观测器接口。
///
/// 对应 Go `extension.Observatory.GetObservation(ctx) (*ObservationResult, error)`。
pub trait ObservationProvider: Send + Sync {
    /// 返回最近的观测结果。
    fn get_observation(&self) -> Result<ObservationResult, RouterError>;
}

/// 负载均衡策略 trait。
///
/// 对应 Go `router.BalancingStrategy`（仅 `PickOutbound()` 方法）。
pub trait BalancingStrategy: Send + Sync {
    /// 返回出站 tag。空字符串表示未选中。
    fn pick_outbound(&self) -> Result<String, RouterError>;
}

// ── Override ─────────────────────────────────────────────────

/// 平衡器目标覆盖（可被运行时命令修改）。
///
/// 对应 Go `balancing_override.override`。
#[derive(Debug, Default)]
pub struct Override {
    target: RwLock<String>,
}

impl Override {
    /// 创建空 override。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 返回当前覆盖目标（空字符串表示无覆盖）。
    #[must_use]
    pub fn get(&self) -> String {
        self.target.read().clone()
    }

    /// 设置覆盖目标。
    pub fn put(&self, target: impl Into<String>) {
        *self.target.write() = target.into();
    }

    /// 清除覆盖。
    pub fn clear(&self) {
        *self.target.write() = String::new();
    }
}

// ── RoundRobinStrategy ────────────────────────────────────────

/// 轮询策略。
///
/// 对应 Go `RoundRobinStrategy`：
/// - `observer` 存在时仅轮询 alive 的出站
/// - 否则轮询 `ohm.select_outbounds(selectors)` 的全部结果
pub struct RoundRobinStrategy {
    selectors: Vec<String>,
    ohm: Arc<dyn OutboundHandlerSelector>,
    observer: Option<Arc<dyn ObservationProvider>>,
    index: AtomicU32,
}

impl RoundRobinStrategy {
    /// 创建。
    pub fn new(
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Option<Arc<dyn ObservationProvider>>,
    ) -> Self {
        Self {
            selectors,
            ohm,
            observer,
            index: AtomicU32::new(0),
        }
    }

    /// 过滤出 alive 出站。
    ///
    /// 无 observer 返回 `ohm.select_outbounds` 的原结果。
    /// 有 observer 但拿不到观测结果同样返回原结果。
    fn alive_outbounds(&self) -> Result<Vec<String>, RouterError> {
        let selected = self.ohm.select_outbounds(&self.selectors)?;
        let Some(obs) = &self.observer else {
            return Ok(selected);
        };
        let observation = match obs.get_observation() {
            Ok(o) => o,
            Err(_) => return Ok(selected),
        };
        let alive: Vec<String> = selected
            .iter()
            .filter(|t| {
                observation
                    .status
                    .iter()
                    .any(|s| s.alive && s.outbound_tag == **t)
            })
            .cloned()
            .collect();
        if alive.is_empty() { Ok(selected) } else { Ok(alive) }
    }
}

impl BalancingStrategy for RoundRobinStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let outs = self.alive_outbounds()?;
        if outs.is_empty() {
            return Err(RouterError::EmptyBalancerResult);
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed);
        Ok(outs[(idx as usize) % outs.len()].clone())
    }
}

// ── Balancer ──────────────────────────────────────────────────

/// 平衡器。
///
/// 对应 Go `Balancer`。包装策略 + fallback + override。
#[allow(dead_code)]
pub struct Balancer {
    selectors: Vec<String>,
    strategy: Arc<dyn BalancingStrategy>,
    ohm: Arc<dyn OutboundHandlerSelector>,
    fallback_tag: String,
    override_target: Override,
}

impl Balancer {
    /// 创建。
    pub fn new(
        selectors: Vec<String>,
        strategy: Arc<dyn BalancingStrategy>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        fallback_tag: impl Into<String>,
    ) -> Self {
        Self {
            selectors,
            strategy,
            ohm,
            fallback_tag: fallback_tag.into(),
            override_target: Override::new(),
        }
    }

    /// 返回 selectors。
    #[must_use]
    pub fn selectors(&self) -> &[String] {
        &self.selectors
    }

    /// 返回 fallback tag。
    #[must_use]
    pub fn fallback_tag(&self) -> &str {
        &self.fallback_tag
    }

    /// 返回 override 句柄（供 Router.OverrideBalancer 使用）。
    #[must_use]
    pub fn override_handle(&self) -> &Override {
        &self.override_target
    }

    /// PickOutbound：override > strategy > fallback。
    ///
    /// 对应 Go `Balancer.PickOutbound`。
    pub fn pick_outbound(&self) -> Result<String, RouterError> {
        let ov = self.override_target.get();
        if !ov.is_empty() {
            return Ok(ov);
        }
        match self.strategy.pick_outbound() {
            Ok(tag) if !tag.is_empty() => Ok(tag),
            _ => {
                if self.fallback_tag.is_empty() {
                    Err(RouterError::EmptyBalancerResult)
                } else {
                    Ok(self.fallback_tag.clone())
                }
            }
        }
    }

    /// 显式覆盖目标。
    pub fn set_override_target(&self, target: impl Into<String>) {
        self.override_target.put(target);
    }

    /// 获取当前覆盖目标。
    #[must_use]
    pub fn get_override_target(&self) -> String {
        self.override_target.get()
    }
}

// ── NotImplemented stubs ──────────────────────────────────────

/// 未接入的 HandlerSelector。所有调用返回 `Err(NotHandlerSelector)`。
#[derive(Debug, Default)]
pub struct NotImplementedSelector;

impl OutboundHandlerSelector for NotImplementedSelector {
    fn select_outbounds(&self, _s: &[String]) -> Result<Vec<String>, RouterError> {
        Err(RouterError::NotHandlerSelector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Override ──

    #[test]
    fn test_override_default_empty() {
        let o = Override::new();
        assert!(o.get().is_empty());
    }

    #[test]
    fn test_override_put_get_clear() {
        let o = Override::new();
        o.put("target1");
        assert_eq!(o.get(), "target1");
        o.clear();
        assert!(o.get().is_empty());
    }

    // ── NotImplementedSelector ──

    #[test]
    fn test_not_implemented_selector_returns_err() {
        let s = NotImplementedSelector;
        let r = s.select_outbounds(&["x".into()]);
        assert!(matches!(r, Err(RouterError::NotHandlerSelector)));
    }

    // ── Balancer override + fallback ──

    /// 策略返回空 tag 的 stub。
    struct EmptyStrategy;
    impl BalancingStrategy for EmptyStrategy {
        fn pick_outbound(&self) -> Result<String, RouterError> {
            Ok(String::new())
        }
    }

    /// 策略返回固定 tag 的 stub。
    struct FixedStrategy(String);
    impl BalancingStrategy for FixedStrategy {
        fn pick_outbound(&self) -> Result<String, RouterError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn test_balancer_strategy_pick() {
        let b = Balancer::new(
            vec!["s".into()],
            Arc::new(FixedStrategy("out1".into())),
            Arc::new(NotImplementedSelector),
            "",
        );
        assert_eq!(b.pick_outbound().unwrap(), "out1");
    }

    #[test]
    fn test_balancer_fallback_when_strategy_empty() {
        let b = Balancer::new(
            vec!["s".into()],
            Arc::new(EmptyStrategy),
            Arc::new(NotImplementedSelector),
            "fallback",
        );
        assert_eq!(b.pick_outbound().unwrap(), "fallback");
    }

    #[test]
    fn test_balancer_override_wins_over_strategy_and_fallback() {
        let b = Balancer::new(
            vec![],
            Arc::new(EmptyStrategy),
            Arc::new(NotImplementedSelector),
            "fallback",
        );
        b.set_override_target("override");
        assert_eq!(b.pick_outbound().unwrap(), "override");
    }

    #[test]
    fn test_balancer_empty_no_fallback_errors() {
        let b = Balancer::new(
            vec![],
            Arc::new(EmptyStrategy),
            Arc::new(NotImplementedSelector),
            "",
        );
        assert!(matches!(b.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }
}
