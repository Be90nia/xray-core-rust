//! 最小延迟策略。
//!
//! 翻译自 `app/router/strategy_leastping.go`。
//!
//! 从 observer 拿到所有 alive 出站的 delay，返回 delay 最小的 tag。
//! 无 observer 或 observer 无 alive 结果时返回空（交给 Balancer fallback）。

use std::sync::Arc;

use crate::balancing::{BalancingStrategy, ObservationProvider};
use crate::error::RouterError;

/// 最小延迟负载均衡策略。
pub struct LeastPingStrategy {
    observer: Arc<dyn ObservationProvider>,
}

impl LeastPingStrategy {
    /// 创建。
    pub fn new(observer: Arc<dyn ObservationProvider>) -> Self {
        Self { observer }
    }
}

impl BalancingStrategy for LeastPingStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let obs = self.observer.get_observation()?;
        let mut best_tag = String::new();
        let mut best_rtt: Option<i64> = None;
        for s in &obs.status {
            // 仅考虑 alive 且有有效 delay（>0）
            if !s.alive || s.delay <= 0 {
                continue;
            }
            if best_rtt.is_none() || s.delay < best_rtt.unwrap() {
                best_rtt = Some(s.delay);
                best_tag = s.outbound_tag.clone();
            }
        }
        if best_tag.is_empty() {
            return Err(RouterError::EmptyBalancerResult);
        }
        Ok(best_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancing::NotImplementedSelector;
    use xray_proto::xray::core::app::observatory::{ObservationResult, OutboundStatus};

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

    #[test]
    fn test_picks_least_delay() {
        let obs = ObservationResult {
            status: vec![
                status("a", true, 100),
                status("b", true, 50),
                status("c", true, 200),
            ],
        };
        let s = LeastPingStrategy::new(Arc::new(FixedObs(obs)));
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_skips_dead() {
        let obs = ObservationResult {
            status: vec![status("a", false, 10), status("b", true, 100)],
        };
        let s = LeastPingStrategy::new(Arc::new(FixedObs(obs)));
        assert_eq!(s.pick_outbound().unwrap(), "b");
    }

    #[test]
    fn test_no_alive_returns_error() {
        let obs = ObservationResult { status: vec![] };
        let s = LeastPingStrategy::new(Arc::new(FixedObs(obs)));
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    // 让 NotImplementedSelector 不被 dead_code 警告（上述测试不使用）。
    #[test]
    fn test_dummy_use_selector() {
        let _ = NotImplementedSelector;
    }
}
