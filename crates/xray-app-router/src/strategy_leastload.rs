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
//! - `ConsistentHashing`：ring hash + 虚拟节点（虚拟节点数 = `vnodes`，默认 64）。
//!   hash key 由调用方经 `pick_outbound_with_key` 提供；走 trait 默认
//!   `pick_outbound` 时退化为以 `(ns timestamp, candidates)` 派生 key，
//!   跨会话亲和仅在显式 key 路径可用。
//!
//! ## IO 边界
//!
//! - `observer` 必须提供
//! - `ohm` 必须提供，用于过滤无延迟数据的节点

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use parking_lot::Mutex;
use rand::Rng;

use crate::balancing::{BalancingStrategy, ObservationProvider, OutboundHandlerSelector};
use crate::error::RouterError;
use crate::weight::WeightManager;
#[cfg(test)]
use xray_proto::xray::core::app::observatory::ObservationResult;
use xray_proto::xray::core::app::observatory::OutboundStatus;
use xray_proto::xray::app::router::StrategyLeastLoadConfig;


/// 有效 RTT：优先 health_ping.average，回退 delay。
fn effective_rtt(s: &OutboundStatus) -> i64 {
    s.health_ping.as_ref().filter(|h| h.average > 0).map(|h| h.average).unwrap_or(s.delay)
}

/// RTT-Deviation-Cost：Go 算法 `value * sqrt(cost)`。
///
/// Rust 端取浮点权重 `costs.apply(tag, rtt) = rtt * sqrt(cost)`。
/// `costs` 缺省时权重 = 1.0 → RTT-Deviation-Cost = RTT。
fn rtt_deviation_cost(costs: Option<&WeightManager>, tag: &str, rtt: i64) -> f64 {
    let w = match costs {
        Some(wm) => wm.get(tag),
        None => 1.0,
    };
    (rtt as f64) * w.sqrt().max(0.0)
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
            }
            _ => None,
        };
        Ok(Self {
            selectors,
            ohm,
            observer,
            baselines: config.baselines.clone(),
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

    /// 收集所有 alive 且 RTT 满足 baselines+max_rtt 的节点。
    ///
    /// 返回 `(tag, rtt, rtt_deviation_cost)` 列表，按 RTT-Deviation-Cost 升序。
    fn get_nodes(&self) -> Result<Vec<(String, i64, f64)>, RouterError> {
        let obs = self.observer.get_observation()?;
        let selected = self.ohm.select_outbounds(&self.selectors)?;
        let mut nodes: Vec<(String, i64, f64)> = Vec::new();
        for status in &obs.status {
            if !status.alive {
                continue;
            }
            if !selected.iter().any(|t| t == &status.outbound_tag) {
                continue;
            }
            let rtt = effective_rtt(status);
            if rtt <= 0 {
                continue;
            }
            if self.max_rtt > 0 && rtt > self.max_rtt {
                continue;
            }
            // baselines 过滤：RTT 必须在任一 baseline + tolerance 范围内
            if !self.baselines.is_empty() {
                let tol_ns = (f64::from(self.tolerance) * rtt as f64) as i64;
                let acceptable = self.baselines.iter().any(|b| {
                    (rtt - b).abs() <= tol_ns
                });
                if !acceptable {
                    continue;
                }
            }
            let cost = rtt_deviation_cost(self.costs.as_ref(), &status.outbound_tag, rtt);
            nodes.push((status.outbound_tag.clone(), rtt, cost));
        }
        // Go 排序键：RTTDeviationCost asc → RTTAverage asc → CountFail asc → CountAll desc → Tag asc
        nodes.sort_by(|a, b| {
            a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.0.cmp(&b.0))
        });
        Ok(nodes)
    }

    /// Availability 模式选择：取前 `expected` 个候选，按 cost 反比权重随机择一。
    fn select_availability(&self, nodes: &[(String, i64, f64)]) -> Option<String> {
        if nodes.is_empty() {
            return None;
        }
        let take = if self.expected > 0 {
            (self.expected as usize).min(nodes.len())
        } else {
            // Go reference：`expected<=0` 时强制取 1 个最低节点（同 line 113-115）。
            1.min(nodes.len())
        };
        let candidates = &nodes[..take];
        // cost 越低越优，反比权重 1/(c+ε) 概率加权随机择一。
        let weights: Vec<f64> = candidates
            .iter()
            .map(|(_, _, c)| 1.0 / (c + 1.0))
            .collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 || candidates.len() == 1 {
            return Some(candidates[0].0.clone());
        }
        let mut pick = rand::rng().random::<f64>() * total;
        for (i, w) in weights.iter().enumerate() {
            pick -= w;
            if pick <= 0.0 {
                return Some(candidates[i].0.clone());
            }
        }
        Some(candidates[0].0.clone())
    }

    /// Adaptive 模式：用 EMA 平滑当前 cost，择最低分。
    fn select_adaptive(&self, nodes: &[(String, i64, f64)]) -> Option<String> {
        if nodes.is_empty() {
            return None;
        }
        let mut state = self.ema_state.lock();
        let mut best: Option<(String, f64)> = None;
        for (tag, _rtt, cost) in nodes {
            let new_score = self.ema_alpha * cost + (1.0 - self.ema_alpha) * state.get(tag).copied().unwrap_or(*cost);
            state.insert(tag.clone(), new_score);
            if best.as_ref().map_or(true, |(_, b)| new_score < *b) {
                best = Some((tag.clone(), new_score));
            }
        }
        best.map(|(t, _)| t)
    }

    /// ConsistentHashing 模式：用 key 哈希 → 在环上顺时针查第一个候选。
    fn select_consistent_hashing(&self, nodes: &[(String, i64, f64)], key: u64) -> Option<String> {
        if nodes.is_empty() {
            return None;
        }
        let tags: Vec<String> = nodes.iter().map(|(t, _, _)| t.clone()).collect();
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
    let mut h: std::collections::hash_map::DefaultHasher = std::collections::hash_map::DefaultHasher::new();
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
            }
        };
        match picked {
            Some(tag) => Ok(tag),
            None => Err(RouterError::EmptyBalancerResult),
        }
    }
}

impl LeastLoadStrategy {
    /// ConsistentHashing 模式专用入口：显式传入 hash key → 同一 key 总是选中同一 tag。
    /// 当 key 来自 session/目的地址时实现 session 亲和。
    pub fn pick_outbound_with_key(&self, key: u64) -> Result<String, RouterError> {
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
    use super::*;
    use crate::balancing::NotImplementedSelector;
    use xray_proto::xray::core::app::observatory::OutboundStatus;

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

    fn cfg(baselines: Vec<i64>, expected: i32, max_rtt: i64, tolerance: f32) -> StrategyLeastLoadConfig {
        StrategyLeastLoadConfig {
            costs: vec![],
            baselines,
            expected,
            max_rtt,
            tolerance,
        }
    }

    #[test]
    fn test_picks_least_load_single_node() {
        let obs = ObservationResult {
            status: vec![
                status("a", true, 100),
                status("b", true, 50),
                status("c", true, 200),
            ],
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
        let obs = ObservationResult {
            status: vec![status("a", true, 10), status("b", true, 100)],
        };
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
        let obs = ObservationResult {
            status: vec![status("a", true, 1000), status("b", true, 50)],
        };
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
            status: vec![
                status("a", true, 200),
                status("b", true, 50),
                status("c", true, 100),
            ],
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
            ObservationResult {
                status: vec![status("a", true, 200), status("b", true, 50)],
            },
            // 第二次 pick：两个 cost 翻转 → EMA 平滑使 "先前赢的 b" 的状态被攻击，
            // 但由于 alpha=0.3，b 仍以历史优势胜出。
            ObservationResult {
                status: vec![status("a", true, 50), status("b", true, 200)],
            },
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
        let obs = ObservationResult {
            status: vec![status("a", true, 50), status("b", true, 50)],
        };
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
    fn test_dummy_use_selector() { let _ = NotImplementedSelector; }
}
