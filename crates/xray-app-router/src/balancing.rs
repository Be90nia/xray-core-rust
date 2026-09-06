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

    /// 带 key 的选路：用于 ConsistentHashing 等需要稳定 affinity 的策略。
    ///
    /// 默认实现退化为 `pick_outbound()`（忽略 key，与现有策略行为一致）。
    /// Rust-only 扩展（Go 无此概念）——`LeastLoadStrategy` 在 ConsistentHashing
    /// 模式下 override 此方法，以实现 session-affinity 选路。
    fn pick_outbound_with_key(&self, _key: u64) -> Result<String, RouterError> {
        self.pick_outbound()
    }
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
        // Go 语义：仅当观测结果存在时按 alive 过滤；找不到/没数据就返回空 list
        // （非全部）。这样 RoundRobin 在所有出站都 dead 时返回空 → Balancer fallback。
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
        Ok(alive)
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
        self.pick_outbound_with_key(0)
    }

    /// 带 key 的 PickOutbound：override > strategy(with key) > fallback。
    ///
    /// key 仅对 override=空且策略支持 `pick_outbound_with_key` 的策略生效。
    /// 当前用于 LeastLoadStrategy ConsistentHashing 模式：同一 key 命中同一 tag，
    /// 实现 session-affinity。`key=0` 等价于 `pick_outbound()`（默认 trait 方法路径）。
    pub fn pick_outbound_with_key(&self, key: u64) -> Result<String, RouterError> {
        let ov = self.override_target.get();
        if !ov.is_empty() {
            return Ok(ov);
        }
        match self.strategy.pick_outbound_with_key(key) {
            Ok(tag) if !tag.is_empty() => Ok(tag),
            err => {
                // selector/策略出错（Err）或返回空 tag 均走 fallback（Go balancing.go:96-119
                // 的两个 fallback 分支），并记 warn 便于观测。
                if self.fallback_tag.is_empty() {
                    Err(match err {
                        Ok(_) => RouterError::EmptyBalancerResult,
                        Err(e) => e,
                    })
                } else {
                    tracing::warn!(fallback = %self.fallback_tag, "balancer fallback");
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

// ── SimpleSelector / MemoryObservationProvider ──────────────

/// 简单出站选择器：根据已知 tag 集过滤。
///
/// 对应 Go `outbound.HandlerSelector` 的基础实现。
/// 持有 `RwLock<HashSet<String>>` 存储可用 tag，`select_outbounds` 返回交集。
/// OHM 接入后用真实 handler 列表初始化。
#[derive(Debug, Default)]
pub struct SimpleSelector {
    tags: RwLock<std::collections::HashSet<String>>,
}

impl SimpleSelector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从迭代器构造。
    #[must_use]
    pub fn from_tags<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            tags: RwLock::new(iter.into_iter().map(Into::into).collect()),
        }
    }

    /// 运行时添加 tag。
    pub fn add_tag(&self, tag: impl Into<String>) {
        self.tags.write().insert(tag.into());
    }

    /// 运行时移除 tag。
    pub fn remove_tag(&self, tag: &str) {
        self.tags.write().remove(tag);
    }
}

impl OutboundHandlerSelector for SimpleSelector {
    fn select_outbounds(&self, selectors: &[String]) -> Result<Vec<String>, RouterError> {
        let tags = self.tags.read();
        Ok(selectors.iter().filter(|s| tags.contains(*s)).cloned().collect())
    }
}

/// 内存观测提供器：外部 feed 观测结果，策略读取。
///
/// 对应 Go `extension.Observatory` 的内存实现。
/// Observatory 扩展 ping 出站后将 `ObservationResult` 写入，
/// LeastPing/LeastLoad 策略从此读取。
#[derive(Debug, Default)]
pub struct MemoryObservationProvider {
    result: RwLock<Option<ObservationResult>>,
}

impl MemoryObservationProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 更新观测结果（Observatory 扩展调用）。
    pub fn update(&self, result: ObservationResult) {
        *self.result.write() = Some(result);
    }
}

impl ObservationProvider for MemoryObservationProvider {
    fn get_observation(&self) -> Result<ObservationResult, RouterError> {
        self.result
            .read()
            .clone()
            .ok_or(RouterError::Other("no observation available".into()))
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

    // ── SimpleSelector ──

    #[test]
    fn test_simple_selector_filters_known_tags() {
        let s = SimpleSelector::from_tags(["a", "b", "c"]);
        let r = s.select_outbounds(&["a".into(), "x".into(), "c".into()]).unwrap();
        assert_eq!(r, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn test_simple_selector_add_remove() {
        let s = SimpleSelector::new();
        s.add_tag("out1");
        s.add_tag("out2");
        assert_eq!(s.select_outbounds(&["out1".into()]).unwrap().len(), 1);
        s.remove_tag("out1");
        assert!(s.select_outbounds(&["out1".into()]).unwrap().is_empty());
    }

    // ── MemoryObservationProvider ──

    #[test]
    fn test_memory_observation_no_data_returns_err() {
        let p = MemoryObservationProvider::new();
        assert!(p.get_observation().is_err());
    }

    #[test]
    fn test_memory_observation_update_then_read() {
        use xray_proto::xray::core::app::observatory::ObservationResult;
        let p = MemoryObservationProvider::new();
        p.update(ObservationResult::default());
        assert!(p.get_observation().is_ok());
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

    #[test]
    fn test_balancer_override_wins_over_valid_strategy() {
        // override 在 strategy 返回有效 tag 时仍胜出（Go balancing.go:104-109）。
        let b = Balancer::new(
            vec![],
            Arc::new(FixedStrategy("strategy-out".into())),
            Arc::new(NotImplementedSelector),
            "fallback",
        );
        b.set_override_target("override-out");
        assert_eq!(b.pick_outbound().unwrap(), "override-out");
    }

    #[test]
    fn test_balancer_clear_override_restores_strategy() {
        // clear() 后 override 回退到空 → strategy 路径接管。
        let o = Override::new();
        o.put("temp");
        assert_eq!(o.get(), "temp");
        o.clear();
        assert!(o.get().is_empty());
        let b = Balancer::new(
            vec![],
            Arc::new(FixedStrategy("strategy-out".into())),
            Arc::new(NotImplementedSelector),
            "",
        );
        b.override_handle().put("override-out");
        assert_eq!(b.pick_outbound().unwrap(), "override-out");
        b.override_handle().clear();
        assert_eq!(b.pick_outbound().unwrap(), "strategy-out");
    }
}
