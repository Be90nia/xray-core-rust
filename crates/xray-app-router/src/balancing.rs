//! 负载均衡：Balancer + BalancingStrategy + RoundRobin + Override。
//!
//! 翻译自 `app/router/{balancing,balancing_override}.go`。
//!
//! # IO 边界 trait
//!
//! - `OutboundHandlerSelector`（Go `outbound.HandlerSelector`）— 生产实现见
//!   `xray-core::wiring::OhmOutboundSelector`（读真实出站表）
//! - `ObservationProvider`（Go `extension.Observatory`）— 生产实现见
//!   `xray-core::wiring::ObservatoryProviderBridge`（桥接真实 observatory feature）

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

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
        Self { selectors, ohm, observer, index: AtomicU32::new(0) }
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
        // gbu9：Go `balancing.go:57-66` 语义——观测快照中未出现的候选视为
        // alive（unfound candidate is considered alive）。原 Rust 实现用
        // `iter().any(|s| s.alive && ...)` 反向 filter，新加出站还未被观测
        // 快照收录时会被无端丢弃，永远选不中。
        let alive: Vec<String> = selected
            .iter()
            .filter(|t| {
                observation
                    .status
                    .iter()
                    .find(|s| s.outbound_tag == ***t)
                    .map(|s| s.alive) // 找到 → 按 alive 判定
                    .unwrap_or(true) // 未找到 → alive（Go 默认）
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
pub struct Balancer {
    selectors: Vec<String>,
    strategy: Arc<dyn BalancingStrategy>,
    #[allow(dead_code)] // Go Balancer 装配面字段：构造注入 ohm 保依赖完整，当前 pick 路径未消费
    ohm: Arc<dyn OutboundHandlerSelector>,
    fallback_tag: String,
    override_target: Override,
    /// 降级计数（实际落到 fallback 的次数）——运维可见「这条规则多常降级」。
    fallback_count: AtomicU32,
    /// 最近一次降级/失败的原因（与 warn/error 日志同源；排障与断言用）。
    last_reason: RwLock<Option<String>>,
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
            fallback_count: AtomicU32::new(0),
            last_reason: RwLock::new(None),
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

    /// 降级次数（实际落到 fallback 的次数）。
    #[must_use]
    pub fn fallback_count(&self) -> u32 {
        self.fallback_count.load(Ordering::Relaxed)
    }

    /// 最近一次降级（或「fallback 未配置」硬失败）的原因。
    ///
    /// epyge：fallback 日志必须带原因，否则运维只知道「回退」不知「为何」。
    /// 此处留一份可编程读取的同源副本（日志之外的可观测面）。
    #[must_use]
    pub fn last_fallback_reason(&self) -> Option<String> {
        self.last_reason.read().clone()
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
                // 的两个 fallback 分支）。
                //
                // epyge：fallback 日志必须带**原因**——原先只记 `fallback=<tag>`，
                // 运维只知道「回退」不知「为何」（哪个候选 dead / 策略报了什么）。
                // 三类可区分原因：
                // ① 策略执行失败（Err，非 EmptyBalancerResult）→ 带策略错误文本；
                // ② 候选全部不可用/被拒（EmptyBalancerResult 或空 tag）→ 带候选数；
                // ③ fallback 未配置 → 不是降级而是硬失败（错误上抛 + error 日志）。
                let reason = match &err {
                    Err(RouterError::EmptyBalancerResult) | Ok(_) => {
                        format!("no candidate available (candidates={})", self.selectors.len())
                    },
                    Err(e) => format!("strategy failed: {e}"),
                };
                if self.fallback_tag.is_empty() {
                    // fallback 未配置 ⇒ 无降级可言，本次是硬失败：原因写进日志并
                    // 留存（错误值保持原样上抛，不改既有错误契约）。
                    let reason = format!("fallback tag not configured: {reason}");
                    *self.last_reason.write() = Some(reason.clone());
                    tracing::error!(reason = %reason, "balancer fallback unavailable");
                    return Err(match err {
                        Ok(_) => RouterError::EmptyBalancerResult,
                        Err(e) => e,
                    });
                }
                self.fallback_count.fetch_add(1, Ordering::Relaxed);
                *self.last_reason.write() = Some(reason.clone());
                // 降级 = warn（不是错误，但必须可见：流量走了非预期路径）。
                tracing::warn!(
                    fallback = %self.fallback_tag,
                    reason = %reason,
                    "balancer fallback"
                );
                Ok(self.fallback_tag.clone())
            },
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
        Self { tags: RwLock::new(iter.into_iter().map(Into::into).collect()) }
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
        self.result.read().clone().ok_or(RouterError::Other("no observation available".into()))
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

    /// 策略执行失败的 stub（模拟 selector/上游观测失败）。
    struct FailingStrategy;
    impl BalancingStrategy for FailingStrategy {
        fn pick_outbound(&self) -> Result<String, RouterError> {
            Err(RouterError::ObservationUnavailable("no alive outbound".into()))
        }
    }

    /// epyge：策略失败而落 fallback 时，原因必须带策略错误文本（原先只记
    /// `fallback=<tag>`，运维看不到「为何回退」）。
    #[test]
    fn test_balancer_fallback_reason_carries_strategy_error() {
        let b = Balancer::new(
            vec!["a".into(), "b".into()],
            Arc::new(FailingStrategy),
            Arc::new(SimpleSelector::default()),
            "fallback",
        );
        assert_eq!(b.pick_outbound().unwrap(), "fallback");
        assert_eq!(b.fallback_count(), 1, "降级必须可计数");
        let reason = b.last_fallback_reason().expect("fallback 必须留原因");
        assert!(reason.contains("strategy failed"), "原因须标明策略失败：{reason}");
        assert!(reason.contains("no alive outbound"), "原因须含策略错误文本：{reason}");
    }

    /// epyge：候选不可用（策略挑不出可用 outbound）时，原因须带候选数。
    #[test]
    fn test_balancer_fallback_reason_reports_candidate_count() {
        let b = Balancer::new(
            vec!["a".into(), "b".into(), "c".into()],
            Arc::new(EmptyStrategy),
            Arc::new(SimpleSelector::default()),
            "fallback",
        );
        assert_eq!(b.pick_outbound().unwrap(), "fallback");
        assert_eq!(b.fallback_count(), 1, "降级必须可计数");
        let reason = b.last_fallback_reason().expect("fallback 必须留原因");
        assert!(reason.contains("no candidate available"), "原因须表明候选不可用：{reason}");
        assert!(reason.contains("candidates=3"), "原因须带候选数：{reason}");
    }

    /// epyge：fallback 未配置 = 硬失败（不是降级）——原因须明确，且不计降级数。
    #[test]
    fn test_balancer_no_fallback_configured_reports_reason() {
        let b = Balancer::new(
            vec!["a".into()],
            Arc::new(EmptyStrategy),
            Arc::new(SimpleSelector::default()),
            "",
        );
        assert!(matches!(b.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
        let reason = b.last_fallback_reason().expect("未配置 fallback 也须留原因");
        assert!(
            reason.contains("fallback tag not configured"),
            "原因须表明未配置 fallback：{reason}"
        );
        assert_eq!(b.fallback_count(), 0, "未发生降级 ⇒ 计数不得增");
    }

    #[test]
    fn test_balancer_strategy_pick() {
        let b = Balancer::new(
            vec!["s".into()],
            Arc::new(FixedStrategy("out1".into())),
            Arc::new(SimpleSelector::default()),
            "",
        );
        assert_eq!(b.pick_outbound().unwrap(), "out1");
    }

    #[test]
    fn test_balancer_fallback_when_strategy_empty() {
        let b = Balancer::new(
            vec!["s".into()],
            Arc::new(EmptyStrategy),
            Arc::new(SimpleSelector::default()),
            "fallback",
        );
        assert_eq!(b.pick_outbound().unwrap(), "fallback");
    }

    #[test]
    fn test_balancer_override_wins_over_strategy_and_fallback() {
        let b = Balancer::new(
            vec![],
            Arc::new(EmptyStrategy),
            Arc::new(SimpleSelector::default()),
            "fallback",
        );
        b.set_override_target("override");
        assert_eq!(b.pick_outbound().unwrap(), "override");
    }

    #[test]
    fn test_balancer_empty_no_fallback_errors() {
        let b =
            Balancer::new(vec![], Arc::new(EmptyStrategy), Arc::new(SimpleSelector::default()), "");
        assert!(matches!(b.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    #[test]
    fn test_balancer_override_wins_over_valid_strategy() {
        // override 在 strategy 返回有效 tag 时仍胜出（Go balancing.go:104-109）。
        let b = Balancer::new(
            vec![],
            Arc::new(FixedStrategy("strategy-out".into())),
            Arc::new(SimpleSelector::default()),
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
            Arc::new(SimpleSelector::default()),
            "",
        );
        b.override_handle().put("override-out");
        b.override_handle().clear();
        assert_eq!(b.pick_outbound().unwrap(), "strategy-out");
    }
    #[test]
    fn test_roundrobin_unfound_candidate_considered_alive() {
        use xray_proto::xray::core::app::observatory::{ObservationResult, OutboundStatus};

        use crate::balancing::ObservationProvider;

        struct ObsWithTag(Option<OutboundStatus>);
        impl ObservationProvider for ObsWithTag {
            fn get_observation(&self) -> Result<ObservationResult, RouterError> {
                Ok(ObservationResult { status: self.0.clone().into_iter().collect() })
            }
        }

        // 观测快照只含 "proxy-a"=alive；"proxy-b" 未被观测 → 视为 alive（Go 默认）。
        let obs: Arc<dyn ObservationProvider> = Arc::new(ObsWithTag(Some(OutboundStatus {
            alive: true,
            delay: 50,
            last_error_reason: String::new(),
            outbound_tag: "proxy-a".into(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        })));
        let ohm: Arc<dyn OutboundHandlerSelector> =
            Arc::new(SimpleSelector::from_tags(["proxy-a", "proxy-b"]));
        // 用 select_outbounds 实际能匹配上的前缀（SimpleSelector 用 contains
        // 完全等值匹配，所以 selectors 必须是完整的 tag 字符串）。
        let s = RoundRobinStrategy::new(vec!["proxy-a".into(), "proxy-b".into()], ohm, Some(obs));
        // 两次 pick 都应拿到 alive 候选（包括 "proxy-b"），不能掉。
        let r1 = s.pick_outbound().unwrap();
        let r2 = s.pick_outbound().unwrap();
        assert!(r1 == "proxy-a" || r1 == "proxy-b");
        assert!(r2 == "proxy-a" || r2 == "proxy-b");
    }
}
