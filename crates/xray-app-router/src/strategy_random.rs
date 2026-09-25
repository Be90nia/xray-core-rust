//! 随机策略。
//!
//! 翻译自 `app/router/strategy_random.go`。
//!
//! 从 selector 选出的 outbounds 中均匀随机取一个。空候选返回
//! `EmptyBalancerResult`，由 Balancer 落 `fallbackTag`（Go `Balancer.PickOutbound`：
//! fallback 是 Balancer 职责，策略本身不掺 fallback）。

use std::sync::Arc;

use rand::seq::IndexedRandom;

use crate::{
    balancing::{BalancingStrategy, OutboundHandlerSelector},
    error::RouterError,
};

/// 随机负载均衡策略。
pub struct RandomStrategy {
    selectors: Vec<String>,
    ohm: Arc<dyn OutboundHandlerSelector>,
}

impl RandomStrategy {
    /// 创建。
    pub fn new(selectors: Vec<String>, ohm: Arc<dyn OutboundHandlerSelector>) -> Self {
        Self { selectors, ohm }
    }
}

impl BalancingStrategy for RandomStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let outs = self.ohm.select_outbounds(&self.selectors)?;
        if outs.is_empty() {
            return Err(RouterError::EmptyBalancerResult);
        }
        let mut rng = rand::rng();
        Ok(outs.choose(&mut rng).expect("non-empty checked").clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 返回固定列表的 selector。
    struct FixedSelector(Vec<String>);
    impl OutboundHandlerSelector for FixedSelector {
        fn select_outbounds(&self, _s: &[String]) -> Result<Vec<String>, RouterError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn test_random_picks_from_selected() {
        let s = RandomStrategy::new(
            vec![],
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
        );
        let pick = s.pick_outbound().unwrap();
        assert!(pick == "a" || pick == "b" || pick == "c");
    }

    #[test]
    fn test_random_empty_returns_error() {
        let s = RandomStrategy::new(vec![], Arc::new(FixedSelector(vec![])));
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    #[test]
    fn test_random_uniform_among_candidates_only() {
        // 候选集外的 tag 永不返回（50/50 fallback 杜撰语义已删）；
        // 单候选时恒返回该候选。
        let s = RandomStrategy::new(vec![], Arc::new(FixedSelector(vec!["a".into()])));
        for _ in 0..50 {
            assert_eq!(s.pick_outbound().unwrap(), "a");
        }
    }
}
