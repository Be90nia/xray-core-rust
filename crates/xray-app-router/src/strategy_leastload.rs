//! 最小负载策略。
//!
//! 翻译自 `app/router/strategy_leastload.go`。
//!
//! 复杂的负载评估策略：根据预期节点数 + RTT baselines + tolerance 过滤
//! 后选最小负载节点。
//!
//! ## Baseline 模式（`BaselineMode`）
//!
//! Go 版本只暴露单一 `Baselines []int64` 选择模式。本实现保留该语义为
//! `Availability` 模式（默认），并扩展两个等价的 Rust-only 变体：
//!
//! - `Availability`：alive + RTT baselines + `costs` 加权（对应 Go `selectLeastLoad`）。
//! - `Adaptive`：滑动窗口 EMA 平滑 RTT-Deviation-Cost，session 内收敛到稳定分数，
//!   未启用在线调参（per-task 非目标）。
//! - `ConsistentHashing`：ring hash + 虚拟节点（虚拟节点数 = `vnodes`，默认 64）。 hash key
//!   由调用方经 `pick_outbound_with_key` 提供；走 trait 默认 `pick_outbound` 时退化为以 `(ns
//!   timestamp, candidates)` 派生 key， 跨会话亲和仅在显式 key 路径可用。
//!
//! ## IO 边界
//!
//! - `observer` 必须提供
//! - `ohm` 必须提供，用于过滤无延迟数据的节点

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::Arc,
};

use parking_lot::Mutex;
use rand::seq::IndexedRandom;
#[cfg(test)]
use xray_proto::xray::core::app::observatory::ObservationResult;
use xray_proto::xray::{
    app::router::StrategyLeastLoadConfig, core::app::observatory::OutboundStatus,
};

use crate::{
    balancing::{BalancingStrategy, ObservationProvider, OutboundHandlerSelector},
    error::RouterError,
    weight::WeightManager,
};

/// Go `node`：健康检查结果的最小拷贝（ms 值，与 baselines/maxRTT 同单位比较）。
#[derive(Debug, Clone)]
struct Node {
    tag: String,
    count_all: i64,
    count_fail: i64,
    rtt_average: i64,
    rtt_deviation_cost: f64,
}

/// Go `leastloadSort`：cost 升序 → RTTAverage 升序 → CountFail 升序 →
/// CountAll 降序 → Tag 升序。
fn leastload_sort(nodes: &mut [Node]) {
    nodes.sort_by(|a, b| {
        a.rtt_deviation_cost
            .partial_cmp(&b.rtt_deviation_cost)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rtt_average.cmp(&b.rtt_average))
            .then_with(|| a.count_fail.cmp(&b.count_fail))
            .then_with(|| b.count_all.cmp(&a.count_all))
            .then_with(|| a.tag.cmp(&b.tag))
    });
}

/// RTT-Deviation-Cost：Go `costs.Apply(tag, value) = value * sqrt(cost)`。
///
/// Go `getNodes`：有 health ping 时 `value = Deviation`，否则 `value = Delay`。
/// `costs` 缺省时权重 = 1.0 → RTT-Deviation-Cost = value。
fn rtt_deviation_cost(costs: Option<&WeightManager>, tag: &str, value: i64) -> f64 {
    let w = match costs {
        Some(wm) => wm.get(tag),
        None => 1.0,
    };
    (value as f64) * w.sqrt().max(0.0)
}

/// Baseline 模式枚举。Go 不暴露此枚举；扩展为 Rust-only 三种策略变体。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineMode {
    /// alive + RTT baselines + `costs` 加权（Go 等价）。
    Availability,
    /// 滑动窗口 EMA 平滑 RTT-Deviation-Cost。
    Adaptive,
    /// ring hash + 虚拟节点。
    ConsistentHashing,
}

impl Default for BaselineMode {
    fn default() -> Self {
        BaselineMode::Availability
    }
}

/// 最小负载负载均衡策略。
pub struct LeastLoadStrategy {
    selectors: Vec<String>,
    ohm: Arc<dyn OutboundHandlerSelector>,
    observer: Arc<dyn ObservationProvider>,
    /// RTT 基准线（ns）。空表示不过滤。
    baselines: Vec<i64>,
    /// 期望选中的节点数（1 表示选最佳；>1 表示择优中再取最佳）。
    expected: i32,
    /// 可接受的最大 RTT（ns），超过过滤。0 表示不过滤。
    max_rtt: i64,
    /// 失败率容忍（0..=1）。超过过滤。
    tolerance: f32,
    /// 权重管理（可选）。
    costs: Option<WeightManager>,
    /// Baseline 选择模式。
    mode: BaselineMode,
    /// EMA 平滑系数（0..=1）。仅 `Adaptive` 模式使用。默认 0.3。
    ema_alpha: f64,
    /// Adaptive 模式下的 EMA 状态（tag → 平滑后的 RTT-Deviation-Cost）。
    ema_state: Mutex<HashMap<String, f64>>,
    /// ConsistentHashing 模式下的环。每个虚拟节点对应一个 (u64 hash, tag) 槽位。
    hash_ring: Option<HashRing>,
    /// ConsistentHashing trait 默认 key 自增计数器。
    default_key_counter: Mutex<u64>,
}

impl LeastLoadStrategy {
    /// 从 proto `StrategyLeastLoadConfig` 构造。`mode = Availability`（Go 等价）。
    pub fn new(
        config: &StrategyLeastLoadConfig,
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Arc<dyn ObservationProvider>,
    ) -> Result<Self, regex::Error> {
        Self::with_mode(config, selectors, ohm, observer, BaselineMode::Availability, 0.3, None, 64)
    }

    /// 显式模式构造。
    ///
    /// `alpha` 仅 `Adaptive` 模式相关；`hash_key_seed` 仅 `ConsistentHashing` 模式相关。
    /// `vnodes` 仅 `ConsistentHashing` 模式相关。
    pub fn with_mode(
        config: &StrategyLeastLoadConfig,
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Arc<dyn ObservationProvider>,
        mode: BaselineMode,
        alpha: f64,
        hash_key_seed: Option<u64>,
        vnodes: usize,
    ) -> Result<Self, regex::Error> {
        let costs = if config.costs.is_empty() {
            None
        } else {
            Some(WeightManager::new(&config.costs, 1.0)?)
        };
        let hash_ring = match mode {
            BaselineMode::ConsistentHashing => {
                // 初始环为空；首次 `pick_outbound_with_key` 时根据可见候选建环。
                Some(HashRing::empty(vnodes, hash_key_seed.unwrap_or(0)))
            },
            _ => None,
        };
        Ok(Self {
            selectors,
            ohm,
            observer,
            // Go 依赖 conf 层保证顺序；此处排序保证 baseline 升序累计走查语义。
            baselines: {
                let mut b = config.baselines.clone();
                b.sort_unstable();
                b
            },
            expected: config.expected,
            max_rtt: config.max_rtt,
            tolerance: config.tolerance,
            costs,
            mode,
            ema_alpha: alpha.clamp(0.0, 1.0),
            ema_state: Mutex::new(HashMap::new()),
            hash_ring,
            default_key_counter: Mutex::new(0),
        })
    }

    /// 构造 Adaptive 模式。
    pub fn adaptive(
        config: &StrategyLeastLoadConfig,
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Arc<dyn ObservationProvider>,
    ) -> Result<Self, regex::Error> {
        Self::with_mode(config, selectors, ohm, observer, BaselineMode::Adaptive, 0.3, None, 64)
    }

    /// 构造 ConsistentHashing 模式。
    ///
    /// `vnodes` 每个 tag 的虚拟节点数；`seed` 派生虚拟节点哈希。
    pub fn consistent_hashing(
        config: &StrategyLeastLoadConfig,
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Arc<dyn ObservationProvider>,
        vnodes: usize,
    ) -> Result<Self, regex::Error> {
        Self::with_mode(
            config,
            selectors,
            ohm,
            observer,
            BaselineMode::ConsistentHashing,
            0.3,
            None,
            vnodes,
        )
    }

    /// Go `shouldSelectNode`：alive / maxRTT / candidates / tolerance 失败率过滤。
    ///
    /// tolerance 仅在 health ping 样本 > 0 且 tolerance > 0 时启用：
    /// `fail/all > tolerance` 的节点剔除。
    fn should_select_node(&self, v: &OutboundStatus, candidates: &[String]) -> bool {
        if !v.alive {
            return false;
        }
        if self.max_rtt != 0 && v.delay >= self.max_rtt {
            return false;
        }
        if !candidates.iter().any(|t| t == &v.outbound_tag) {
            return false;
        }
        if let Some(h) = &v.health_ping {
            if h.all > 0
                && self.tolerance > 0.0
                && h.fail as f64 / h.all as f64 > f64::from(self.tolerance)
            {
                return false;
            }
        }
        true
    }

    /// Go `getNodes`：过滤 + 构造节点 + `leastloadSort`。
    ///
    /// 无 health ping 的节点以 Delay 兜底（CountAll/CountFail 初始 1，Go 同值）；
    /// cost 取值：有 ping 用 Deviation，无 ping 用 Delay。
    fn get_nodes(&self) -> Result<Vec<Node>, RouterError> {
        let obs = self.observer.get_observation()?;
        let selected = self.ohm.select_outbounds(&self.selectors)?;
        let mut nodes: Vec<Node> = Vec::new();
        for status in &obs.status {
            if !self.should_select_node(status, &selected) {
                continue;
            }
            let (average, deviation, count_all, count_fail) = match &status.health_ping {
                Some(h) => (h.average, h.deviation, h.all, h.fail),
                None => (status.delay, status.delay, 1, 1),
            };
            let cost_value = if status.health_ping.is_some() { deviation } else { status.delay };
            let cost = rtt_deviation_cost(self.costs.as_ref(), &status.outbound_tag, cost_value);
            nodes.push(Node {
                tag: status.outbound_tag.clone(),
                count_all,
                count_fail,
                rtt_average: average,
                rtt_deviation_cost: cost,
            });
        }
        leastload_sort(&mut nodes);
        Ok(nodes)
    }

    /// Go `selectLeastLoad`：baselines 升序累计上限走查（`count >= expected` 即断）。
    ///
    /// - expected > 可用数 → 全量返回（Go line 103-105）
    /// - expected <= 0 → 按 1 处理
    /// - 无 baselines → 前 expected 个
    /// - 走查后 count < expected 且 Expected > 0 → 补到 expected（Go line 134-136）
    fn select_least_load<'a>(&self, nodes: &'a [Node]) -> &'a [Node] {
        if nodes.is_empty() {
            return &[];
        }
        let available = nodes.len();
        if self.expected > 0 && self.expected as usize > available {
            return nodes;
        }
        let expected = if self.expected > 0 { self.expected as usize } else { 1 };
        if self.baselines.is_empty() {
            return &nodes[..expected.min(available)];
        }
        let mut count = 0usize;
        for baseline in &self.baselines {
            let baseline = *baseline as f64;
            for i in count..available {
                if nodes[i].rtt_deviation_cost >= baseline {
                    break;
                }
                count = i + 1;
            }
            if count >= expected {
                break;
            }
        }
        if self.expected > 0 && count < expected {
            count = expected;
        }
        &nodes[..count.min(available)]
    }

    /// Availability 模式选择：在选中集内均匀随机（Go `PickOutbound` dice.Roll）。
    fn select_availability(&self, nodes: &[Node]) -> Option<String> {
        let selected = self.select_least_load(nodes);
        selected.choose(&mut rand::rng()).map(|n| n.tag.clone())
    }

    /// Adaptive 模式：用 EMA 平滑当前 cost，择最低分。
    fn select_adaptive(&self, nodes: &[Node]) -> Option<String> {
        if nodes.is_empty() {
            return None;
        }
        let mut state = self.ema_state.lock();
        let mut best: Option<(String, f64)> = None;
        for node in nodes {
            let prev = state.get(&node.tag).copied().unwrap_or(node.rtt_deviation_cost);
            let new_score =
                self.ema_alpha * node.rtt_deviation_cost + (1.0 - self.ema_alpha) * prev;
            state.insert(node.tag.clone(), new_score);
            if best.as_ref().map_or(true, |(_, b)| new_score < *b) {
                best = Some((node.tag.clone(), new_score));
            }
        }
        best.map(|(t, _)| t)
    }

    /// ConsistentHashing 模式：用 key 哈希 → 在环上顺时针查第一个候选。
    fn select_consistent_hashing(&self, nodes: &[Node], key: u64) -> Option<String> {
        if nodes.is_empty() {
            return None;
        }
        let tags: Vec<String> = nodes.iter().map(|n| n.tag.clone()).collect();
        // 重建环：成员变化时按当前 nodes 重建（轻量级；vnodes 数默认 64）。
        let ring = self.hash_ring.as_ref().expect("hash_ring set for ConsistentHashing");
        let mut ring = ring.clone();
        ring.rebuild(&tags);
        ring.lookup(key).map(|s| s.to_string())
    }

    /// trait 默认 key：自增计数器 → session 内稳定，跨调用单调递增。
    fn next_default_key(&self) -> u64 {
        let mut c = self.default_key_counter.lock();
        *c = c.wrapping_add(1);
        *c
    }
}

/// 一致性哈希环：每个真实 tag 派生 N 个虚拟节点 → u64 hash 升序排列。
#[derive(Debug, Clone)]
struct HashRing {
    vnodes: usize,
    seed: u64,
    /// 已排序的 (hash, tag) 列表。
    slots: Vec<(u64, String)>,
}

impl HashRing {
    fn empty(vnodes: usize, seed: u64) -> Self {
        Self { vnodes: vnodes.max(1), seed, slots: Vec::new() }
    }

    /// 重新建环：以给定 tags + 虚拟节点数派生 hash 槽。
    fn rebuild(&mut self, tags: &[String]) {
        self.slots.clear();
        for tag in tags {
            for i in 0..self.vnodes {
                let h = hash64(&format!("{}|{}|{}", self.seed, tag, i));
                self.slots.push((h, tag.clone()));
            }
        }
        self.slots.sort_by_key(|(h, _)| *h);
    }

    /// 顺时针查询第一个 tag。空环返回 None。
    fn lookup(&self, key: u64) -> Option<&str> {
        // 二分查找：第一个 hash >= key 的槽位；环回环到 0。
        let idx = match self.slots.binary_search_by_key(&key, |(h, _)| *h) {
            Ok(i) => i,
            Err(i) => i,
        };
        if self.slots.is_empty() {
            return None;
        }
        let pick = if idx >= self.slots.len() { 0 } else { idx };
        Some(&self.slots[pick].1)
    }
}

fn hash64(s: &str) -> u64 {
    let mut h: std::collections::hash_map::DefaultHasher =
        std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

impl BalancingStrategy for LeastLoadStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let nodes = self.get_nodes()?;
        let picked = match self.mode {
            BaselineMode::Availability => self.select_availability(&nodes),
            BaselineMode::Adaptive => self.select_adaptive(&nodes),
            BaselineMode::ConsistentHashing => {
                let key = self.next_default_key();
                self.select_consistent_hashing(&nodes, key)
            },
        };
        match picked {
            Some(tag) => Ok(tag),
            None => Err(RouterError::EmptyBalancerResult),
        }
    }

    /// ConsistentHashing 模式 override：传同一 key 总是选同一 tag。
    /// 其他模式退化为 `pick_outbound()`（忽略 key）。
    fn pick_outbound_with_key(&self, key: u64) -> Result<String, RouterError> {
        if self.mode != BaselineMode::ConsistentHashing {
            return self.pick_outbound();
        }
        let nodes = self.get_nodes()?;
        match self.select_consistent_hashing(&nodes, key) {
            Some(tag) => Ok(tag),
            None => Err(RouterError::EmptyBalancerResult),
        }
    }
}

#[cfg(test)]
mod tests {
    use xray_proto::xray::core::app::observatory::OutboundStatus;

    use super::*;
    use crate::balancing::NotImplementedSelector;

    struct FixedSelector(Vec<String>);
    impl OutboundHandlerSelector for FixedSelector {
        fn select_outbounds(&self, _s: &[String]) -> Result<Vec<String>, RouterError> {
            Ok(self.0.clone())
        }
    }

    struct FixedObs(ObservationResult);
    impl ObservationProvider for FixedObs {
        fn get_observation(&self) -> Result<ObservationResult, RouterError> {
            Ok(self.0.clone())
        }
    }

    fn status(tag: &str, alive: bool, delay: i64) -> OutboundStatus {
        OutboundStatus {
            alive,
            delay,
            last_error_reason: String::new(),
            outbound_tag: tag.into(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        }
    }

    fn cfg(
        baselines: Vec<i64>,
        expected: i32,
        max_rtt: i64,
        tolerance: f32,
    ) -> StrategyLeastLoadConfig {
        StrategyLeastLoadConfig { costs: vec![], baselines, expected, max_rtt, tolerance }
    }

    #[test]
    fn test_picks_least_load_single_node() {
        let obs = ObservationResult {
            status: vec![status("a", true, 100), status("b", true, 50), status("c", true, 200)],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_skips_unselected() {
        let obs = ObservationResult { status: vec![status("a", true, 10), status("b", true, 100)] };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["b".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_max_rtt_filter() {
        let obs =
            ObservationResult { status: vec![status("a", true, 1000), status("b", true, 50)] };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 100, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_no_alive_returns_error() {
        let obs = ObservationResult { status: vec![] };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec![])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    // ---- Adaptive mode ----

    #[test]
    fn test_adaptive_first_pick_initializes_ema() {
        // 首次调用：无历史 EMA 状态 → 用当前 RTT 直接选最小。
        let obs = ObservationResult {
            status: vec![status("a", true, 200), status("b", true, 50), status("c", true, 100)],
        };
        let s = LeastLoadStrategy::adaptive(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_adaptive_ema_tracks_lowest_smoothed_score() {
        // EMA 状态在两次 pick 之间保留：用状态计数器式 ObservationProvider
        // 验证 EMA 实际对 cost 序列收敛。
        let observations = vec![
            // 第一次 pick：b 最低。
            ObservationResult { status: vec![status("a", true, 200), status("b", true, 50)] },
            // 第二次 pick：两个 cost 翻转 → EMA 平滑使 "先前赢的 b" 的状态被攻击，
            // 但由于 alpha=0.3，b 仍以历史优势胜出。
            ObservationResult { status: vec![status("a", true, 50), status("b", true, 200)] },
        ];
        let obs_iter = Mutex::new(observations.into_iter());
        struct StepObs(Mutex<std::vec::IntoIter<ObservationResult>>);
        impl ObservationProvider for StepObs {
            fn get_observation(&self) -> Result<ObservationResult, RouterError> {
                Ok(self.0.lock().next().unwrap_or_else(|| ObservationResult { status: vec![] }))
            }
        }
        let s = LeastLoadStrategy::adaptive(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into()])),
            Arc::new(StepObs(obs_iter)),
        )
        .unwrap();
        let p1 = s.pick_outbound().unwrap();
        let p2 = s.pick_outbound().unwrap();
        // 第一轮 b (cost 50)；第二轮 EMA 让 b 仍然平滑胜出（历史 cost=50 vs a=200）。
        assert_eq!(p1, "b");
        assert_eq!(p2, "b");
    }

    #[test]
    fn test_adaptive_no_alive_returns_error() {
        let obs = ObservationResult { status: vec![] };
        let s = LeastLoadStrategy::adaptive(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec![])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    // ---- ConsistentHashing mode ----

    #[test]
    fn test_consistent_hashing_same_key_picks_same() {
        let obs = ObservationResult {
            status: vec![status("a", true, 50), status("b", true, 50), status("c", true, 50)],
        };
        let s = LeastLoadStrategy::consistent_hashing(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            Arc::new(FixedObs(obs)),
            64,
        )
        .unwrap();
        let k = 0xDEAD_BEEFu64;
        let p1 = s.pick_outbound_with_key(k).unwrap();
        let p2 = s.pick_outbound_with_key(k).unwrap();
        assert_eq!(p1, p2, "consistent hashing: same key must return same tag");
    }

    #[test]
    fn test_consistent_hashing_keys_distribute_across_tags() {
        let obs = ObservationResult {
            status: vec![status("a", true, 50), status("b", true, 50), status("c", true, 50)],
        };
        let s = LeastLoadStrategy::consistent_hashing(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            Arc::new(FixedObs(obs)),
            128,
        )
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        // 用散列扩列的 key 测试分布 → 直接连续 0..200 在 3 节点下可能全部撞同一标签。
        let mut k: u64 = 0x1234_5678_DEAD_BEEF;
        for _ in 0..200 {
            k = k.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            let p = s.pick_outbound_with_key(k).unwrap();
            seen.insert(p);
        }
        // ring 必须覆盖至少 2 个 tag（否则算法退化为固定常量映射）。
        assert!(seen.len() >= 2, "ring should cover multiple tags, got {:?}", seen);
    }

    // ---- Go 语义对拍（app/router/strategy_leastload.go）----

    /// 带 health ping 的 status 构造（Go observatory.OutboundStatus）。
    fn ping_status(
        tag: &str,
        alive: bool,
        delay: i64,
        average: i64,
        deviation: i64,
        all: i64,
        fail: i64,
    ) -> OutboundStatus {
        OutboundStatus {
            alive,
            delay,
            last_error_reason: String::new(),
            outbound_tag: tag.into(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: Some(
                xray_proto::xray::core::app::observatory::HealthPingMeasurementResult {
                    all,
                    fail,
                    deviation,
                    average,
                    ..Default::default()
                },
            ),
        }
    }

    /// tolerance = 失败率过滤：fail/all > tolerance 的节点剔除（Go shouldSelectNode）。
    #[test]
    fn test_tolerance_filters_high_failure_rate() {
        let obs = ObservationResult {
            status: vec![
                ping_status("fast_bad", true, 50, 50, 50, 10, 9),
                ping_status("slow_ok", true, 200, 200, 200, 10, 1),
            ],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.5),
            vec![],
            Arc::new(FixedSelector(vec!["fast_bad".into(), "slow_ok".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        // fast_bad 失败率 0.9 > 0.5 被过滤 → slow_ok 入选。
        assert_eq!(s.pick_outbound().unwrap(), "slow_ok");
    }

    /// tolerance = 0 → 失败率过滤不启用（Go `Tolerance > 0` 门）。
    #[test]
    fn test_tolerance_zero_disables_failure_filter() {
        let obs = ObservationResult {
            status: vec![
                ping_status("fast_bad", true, 50, 50, 50, 10, 10),
                ping_status("slow_ok", true, 200, 200, 200, 10, 0),
            ],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["fast_bad".into(), "slow_ok".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "fast_bad");
    }

    /// baselines 累计上限走查：乱序 baselines 构造时排序，选中集 = 前 count 个，
    /// 候选只在选中集内均匀随机（Go selectLeastLoad + PickOutbound）。
    #[test]
    fn test_baselines_walk_selects_prefix_set() {
        let obs = ObservationResult {
            status: vec![
                status("a", true, 50),
                status("b", true, 100),
                status("c", true, 200),
                status("d", true, 400),
            ],
        };
        // 排序后 baselines [60, 150]：walk 到 150 时 count=2 >= expected=2 即断。
        // 选中集 {a, b}，c/d 永不选中。
        let s = LeastLoadStrategy::new(
            &cfg(vec![150, 60], 2, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into(), "d".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        for _ in 0..40 {
            let p = s.pick_outbound().unwrap();
            assert!(p == "a" || p == "b", "picked {p} outside selected set");
        }
    }

    /// expected > 可用数 → 全量返回（Go line 103-105）。
    #[test]
    fn test_expected_gt_available_returns_all() {
        let obs = ObservationResult {
            status: vec![status("a", true, 50), status("b", true, 100), status("c", true, 200)],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 5, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..60 {
            seen.insert(s.pick_outbound().unwrap());
        }
        assert_eq!(seen.len(), 3, "all three should be pickable, got {seen:?}");
    }

    /// 排序键：cost/average 相同时 CountFail 升序（Go leastloadSort）。
    #[test]
    fn test_sort_prefers_lower_fail_count() {
        let obs = ObservationResult {
            status: vec![
                ping_status("many_fail", true, 100, 100, 100, 100, 80),
                ping_status("few_fail", true, 100, 100, 100, 100, 10),
            ],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["many_fail".into(), "few_fail".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "few_fail");
    }

    /// 排序键：cost/average/fail 相同时 CountAll 降序（Go leastloadSort）。
    #[test]
    fn test_sort_prefers_higher_sample_count() {
        let obs = ObservationResult {
            status: vec![
                ping_status("few_samples", true, 100, 100, 100, 20, 0),
                ping_status("many_samples", true, 100, 100, 100, 200, 0),
            ],
        };
        let s = LeastLoadStrategy::new(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["few_samples".into(), "many_samples".into()])),
            Arc::new(FixedObs(obs)),
        )
        .unwrap();
        assert_eq!(s.pick_outbound().unwrap(), "many_samples");
    }

    #[test]
    fn test_consistent_hashing_no_candidates_returns_error() {
        let obs = ObservationResult { status: vec![] };
        let s = LeastLoadStrategy::consistent_hashing(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec![])),
            Arc::new(FixedObs(obs)),
            64,
        )
        .unwrap();
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    #[test]
    fn test_consistent_hashing_default_pick_increments_key() {
        let obs = ObservationResult { status: vec![status("a", true, 50), status("b", true, 50)] };
        let s = LeastLoadStrategy::consistent_hashing(
            &cfg(vec![], 1, 0, 0.0),
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into()])),
            Arc::new(FixedObs(obs)),
            64,
        )
        .unwrap();
        // 默认 trait 调用走自增 key，不应 panic。
        let _ = s.pick_outbound().unwrap();
        let _ = s.pick_outbound().unwrap();
    }

    // 防 dead_code 警告
    #[test]
    fn test_dummy_use_selector() {
        let _ = NotImplementedSelector;
    }
}
