//! 最小延迟策略。
//!
//! 翻译自 `app/router/strategy_leastping.go`。
//!
//! 从 observer 拿到所有 alive 出站的 delay，返回 delay 最小的 tag。
//! 无 observer 或 observer 无 alive 结果时返回空（交给 Balancer fallback）。
//!
//! 当 `health_ping.average` 可用时优先使用它（多次测量均值比单次 delay 更稳定）。
//! 无 observer 或 observer 无 alive 结果时返回空（交给 Balancer fallback）。

use std::sync::Arc;

use crate::balancing::{BalancingStrategy, ObservationProvider};
use crate::error::RouterError;
use xray_proto::xray::core::app::observatory::OutboundStatus;


/// 最小延迟负载均衡策略。
/// 有效 RTT：优先 health_ping.average（多测量均值），回退 delay。
fn effective_rtt(s: &OutboundStatus) -> i64 {
    s.health_ping.as_ref().filter(|h| h.average > 0).map(|h| h.average).unwrap_or(s.delay)
}

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
            let rtt = effective_rtt(s);
            if best_rtt.is_none() || rtt < best_rtt.unwrap() {
                best_rtt = Some(rtt);
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
    use xray_proto::xray::core::app::observatory::{HealthPingMeasurementResult, ObservationResult, OutboundStatus};

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

    fn status_with_hp(tag: &str, alive: bool, delay: i64, avg: i64) -> OutboundStatus {
        OutboundStatus {
            alive,
            delay,
            last_error_reason: String::new(),
            outbound_tag: tag.into(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: Some(HealthPingMeasurementResult {
                all: 10,
                fail: 0,
                deviation: 5,
                average: avg,
                max: avg + 20,
                min: (avg - 20).max(0),
            }),
        }
    }

    #[test]
    fn test_health_ping_average_preferred_over_delay() {
        // a: delay=50 but health_ping.average=200 → effective RTT=200
        // b: delay=100 but health_ping.average=80  → effective RTT=80
        // b should win because avg(80) < avg(200)
        let obs = ObservationResult {
            status: vec![
                status_with_hp("a", true, 50, 200),
                status_with_hp("b", true, 100, 80),
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
