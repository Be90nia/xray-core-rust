//! 最小负载策略。
//!
//! 翻译自 `app/router/strategy_leastload.go`。
//!
//! 复杂的负载评估策略：根据预期节点数 + RTT baselines + tolerance 过滤
//! 后选最小负载节点。当前实现保留核心选择逻辑，`WeightManager` 应用为可选。
//!
//! # IO 边界
//!
//! - `observer` 必须提供
//! - `ohm` 必须提供，用于过滤无延迟数据的节点

use std::sync::Arc;

use crate::balancing::{BalancingStrategy, ObservationProvider, OutboundHandlerSelector};
use crate::error::RouterError;
use crate::weight::WeightManager;
#[cfg(test)]
use xray_proto::xray::core::app::observatory::ObservationResult;
use xray_proto::xray::app::router::StrategyLeastLoadConfig;

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
}

impl LeastLoadStrategy {
    /// 从 proto `StrategyLeastLoadConfig` 构造。
    pub fn new(
        config: &StrategyLeastLoadConfig,
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Arc<dyn ObservationProvider>,
    ) -> Result<Self, regex::Error> {
        let costs = if config.costs.is_empty() {
            None
        } else {
            Some(WeightManager::new(&config.costs, 1.0)?)
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
        })
    }

    /// 收集所有 alive 且 RTT 满足 baselines+max_rtt 的节点。
    ///
    /// 返回 `(tag, delay)` 列表，按 delay 升序。
    fn get_nodes(&self) -> Result<Vec<(String, i64)>, RouterError> {
        let obs = self.observer.get_observation()?;
        let selected = self.ohm.select_outbounds(&self.selectors)?;
        let mut nodes: Vec<(String, i64)> = Vec::new();
        for status in &obs.status {
            if !status.alive {
                continue;
            }
            if !selected.iter().any(|t| t == &status.outbound_tag) {
                continue;
            }
            if status.delay <= 0 {
                continue;
            }
            if self.max_rtt > 0 && status.delay > self.max_rtt {
                continue;
            }
            // baselines 过滤：delay 必须在任一 baseline + tolerance 范围内
            if !self.baselines.is_empty() {
                let tol_ns = (f64::from(self.tolerance) * status.delay as f64) as i64;
                let acceptable = self.baselines.iter().any(|b| {
                    (status.delay - b).abs() <= tol_ns
                });
                if !acceptable {
                    continue;
                }
            }
            nodes.push((status.outbound_tag.clone(), status.delay));
        }
        nodes.sort_by_key(|&(_, d)| d);
        Ok(nodes)
    }

    /// 选出期望节点数中权重最高的那个。
    ///
    /// `nodes` 必须已按 delay 升序排列。
    fn select_least_load<'a>(&self, nodes: &'a [(String, i64)]) -> Option<&'a str> {
        if nodes.is_empty() {
            return None;
        }
        let take = if self.expected > 0 {
            (self.expected as usize).min(nodes.len())
        } else {
            nodes.len()
        };
        let candidates = &nodes[..take];
        let mut best: Option<&str> = None;
        let mut best_weight = f64::MIN;
        for (tag, _delay) in candidates {
            let w = match &self.costs {
                Some(wm) => wm.get(tag),
                None => 1.0,
            };
            if best.is_none() || w > best_weight {
                best = Some(tag.as_str());
                best_weight = w;
            }
        }
        best
    }
}

impl BalancingStrategy for LeastLoadStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let nodes = self.get_nodes()?;
        match self.select_least_load(&nodes) {
            Some(tag) => Ok(tag.to_string()),
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
            Arc::new(FixedSelector(vec!["b".into()])), // 只允许 b
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
            &cfg(vec![], 1, 100, 0.0), // max_rtt=100ns 过滤 a
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

    // 防 dead_code 警告：测试不使用 NotImplementedSelector
    #[test]
    fn test_dummy_use_selector() { let _ = NotImplementedSelector; }
}
