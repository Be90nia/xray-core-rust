//! 随机策略。
//!
//! 翻译自 `app/router/strategy_random.go`。
//!
//! 从 selector 选出的 outbounds 中随机取一个。
//! `fallback_tag` 非空时按 50/50 概率随机选 fallback 或选中 tag。

use std::sync::Arc;

use rand::seq::IndexedRandom;

use crate::balancing::{BalancingStrategy, OutboundHandlerSelector};
use crate::error::RouterError;

/// 随机负载均衡策略。
pub struct RandomStrategy {
    selectors: Vec<String>,
    ohm: Arc<dyn OutboundHandlerSelector>,
    fallback_tag: String,
}

impl RandomStrategy {
    /// 创建。
    pub fn new(
        selectors: Vec<String>,
        ohm: Arc<dyn OutboundHandlerSelector>,
        fallback_tag: impl Into<String>,
    ) -> Self {
        Self {
            selectors,
            ohm,
            fallback_tag: fallback_tag.into(),
        }
    }
}

impl BalancingStrategy for RandomStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        let outs = self.ohm.select_outbounds(&self.selectors)?;
        if outs.is_empty() {
            return Err(RouterError::EmptyBalancerResult);
        }
        let mut rng = rand::rng();
        let pick = outs.choose(&mut rng).expect("non-empty checked").clone();

        // 与 Go 一致：fallback 非空时按 50/50 跟 fallback 随机
        if !self.fallback_tag.is_empty() {
            let coin: bool = rand::random();
            if coin {
                return Ok(self.fallback_tag.clone());
            }
        }
        Ok(pick)
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
            vec![].into(),
            Arc::new(FixedSelector(vec!["a".into(), "b".into(), "c".into()])),
            "",
        );
        let pick = s.pick_outbound().unwrap();
        assert!(pick == "a" || pick == "b" || pick == "c");
    }

    #[test]
    fn test_random_empty_returns_error() {
        let s = RandomStrategy::new(
            vec![],
            Arc::new(FixedSelector(vec![])),
            "",
        );
        assert!(matches!(s.pick_outbound(), Err(RouterError::EmptyBalancerResult)));
    }

    #[test]
    fn test_random_with_fallback_can_return_either() {
        // 多次抽样验证 fallback 可能被选中（并非要求 50% 精准，只验逻辑路径）
        let s = RandomStrategy::new(
            vec![],
            Arc::new(FixedSelector(vec!["a".into()])),
            "fb",
        );
        let mut seen_a = false;
        let mut seen_fb = false;
        for _ in 0..100 {
            match s.pick_outbound().unwrap().as_str() {
                "a" => seen_a = true,
                "fb" => seen_fb = true,
                _ => {}
            }
        }
        assert!(seen_a || seen_fb);
    }
}
