//! Router 错误类型。
//!
//! 对应 Go 版本散落在 `app/router/*.go` 中通过 `errors.New(...)` 抛出的错误。

use thiserror::Error;

/// 路由器错误。对应 Go 中 router/balancer/rule 相关错误。
#[derive(Debug, Error)]
pub enum RouterError {
    /// 规则缺少有效字段（无任何 matcher 可构建）。
    #[error("this rule has no effective fields")]
    EmptyRule,

    /// 引用了不存在的 balancer tag。
    #[error("balancer {0} not found")]
    BalancerNotFound(String),

    /// 重复 balancer tag。
    #[error("duplicate balancer tag")]
    DuplicateBalancerTag,

    /// 重复 ruleTag。
    #[error("duplicate ruleTag {0}")]
    DuplicateRuleTag(String),

    /// 空 ruleTag（RemoveRule 入参校验）。
    #[error("empty tag name!")]
    EmptyTagName,

    /// 无法识别的负载均衡策略名。
    #[error("unrecognized balancer type")]
    UnknownBalancerType,

    /// `StrategyLeastLoadConfig` 类型不匹配。
    #[error("not a StrategyLeastLoadConfig")]
    InvalidLeastLoadConfig,

    /// AddRule 收到非 Config 类型的 TypedMessage。
    #[error("AddRule: config type error")]
    AddRuleConfigTypeError,

    /// 未找到任何匹配规则（对应 Go `common.ErrNoClue`）。
    #[error("no route matched")]
    NoClue,

    /// Balancer PickOutbound 返回空 tag。
    #[error("balancing strategy returns empty tag")]
    EmptyBalancerResult,

    /// 出站管理器不是 HandlerSelector。
    #[error("outbound.Manager is not a HandlerSelector")]
    NotHandlerSelector,

    /// 不支持 GetPrincipleTarget。
    #[error("unsupported GetPrincipleTarget")]
    UnsupportedPrincipleTarget,

    /// 找不到指定 tag（GetPrincipleTarget/SetOverrideTarget/GetOverrideTarget）。
    #[error("cannot find tag")]
    TagNotFound,

    /// geodata 构建匹配器失败。
    #[error("geodata build matcher failed: {0}")]
    GeodataBuild(String),

    /// webhook 配置或执行失败。
    #[error("webhook error: {0}")]
    Webhook(String),

    /// 观测器（Observatory）不可用。
    #[error("observation not available: {0}")]
    ObservationUnavailable(String),

    /// 规则/平衡器构建时的内部包装错误。
    #[error("{0}")]
    Other(String),
}

impl RouterError {
    /// 与 Go `errors.New(...).AtWarning()` 对应的工厂方法（仅语义保留，无级别传递）。
    #[must_use]
    pub fn at_warning(self) -> Self {
        self
    }

    /// 与 Go `errors.New(...).AtError()` 对应的工厂方法。
    #[must_use]
    pub fn at_error(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_empty_rule() {
        assert_eq!(RouterError::EmptyRule.to_string(), "this rule has no effective fields");
    }

    #[test]
    fn test_display_balancer_not_found() {
        let e = RouterError::BalancerNotFound("mybalancer".into());
        assert_eq!(e.to_string(), "balancer mybalancer not found");
    }

    #[test]
    fn test_display_no_clue() {
        assert_eq!(RouterError::NoClue.to_string(), "no route matched");
    }

    #[test]
    fn test_at_warning_returns_self() {
        let e = RouterError::EmptyRule.at_warning();
        assert!(matches!(e, RouterError::EmptyRule));
    }

    #[test]
    fn test_at_error_returns_self() {
        let e = RouterError::NoClue.at_error();
        assert!(matches!(e, RouterError::NoClue));
    }

    #[test]
    fn test_is_std_error() {
        let e = RouterError::EmptyRule;
        let _: &dyn std::error::Error = &e;
    }
}
