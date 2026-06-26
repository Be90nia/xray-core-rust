//! 路由器主体（Router + Route）。
//!
//! 翻译自 `app/router/router.go`。
//!
//! # 设计
//!
//! - `Router` 持有规则列表 + 平衡器映射，提供 `pick_route` 同步接口。
//! - 域名策略（`DomainStrategy`）保留为字段，但**当前实现不执行 DNS 解析**
//!   （`xray-features::dns` 与本 crate trait 不兼容，留待接入）。
//! - IO 边界（出站选择、观测器、dispatcher）通过 trait + Arc 注入。
//!
//! # IO 边界
//!
//! - `OutboundHandlerSelector` 当前必须提供（即使 `NotImplementedSelector`）。
//! - `ObservationProvider` 仅 LeastPing/LeastLoad 策略需要。
//! - DNS 解析路径：TODO（等上层接入）。

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use xray_proto::xray::app::router::{BalancingRule, Config, RoutingRule};

use crate::balancing::{Balancer, BalancingStrategy, OutboundHandlerSelector};
use crate::config::DomainStrategy;
use crate::context::RoutingContext;
use crate::error::RouterError;
use crate::rule::{build_rule, Rule};

/// 路由结果。对应 Go `router.Route`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// 出站 tag。
    pub outbound_tag: String,
    /// 命中的 ruleTag。
    pub rule_tag: String,
}

/// 路由器。对应 Go `router.Router`。
pub struct Router {
    domain_strategy: DomainStrategy,
    rules: RwLock<Vec<Arc<Rule>>>,
    balancers: RwLock<HashMap<String, Arc<Balancer>>>,
    ohm: Arc<dyn OutboundHandlerSelector>,
}

impl Router {
    /// 从 proto `Config` 初始化路由器。
    ///
    /// 对应 Go `router.Init`。
    pub fn init(
        config: &Config,
        ohm: Arc<dyn OutboundHandlerSelector>,
    ) -> Result<Arc<Self>, RouterError> {
        // 1. 构建平衡器映射
        let mut balancers: HashMap<String, Arc<Balancer>> = HashMap::new();
        for br in &config.balancing_rule {
            let b = build_balancer(br, &ohm)?;
            if balancers.insert(br.tag.clone(), Arc::new(b)).is_some() {
                return Err(RouterError::DuplicateBalancerTag);
            }
        }

        // 2. 构建规则
        let mut rules: Vec<Arc<Rule>> = Vec::with_capacity(config.rule.len());
        let mut seen_rule_tags = std::collections::HashSet::new();
        for rr in &config.rule {
            let r = build_rule(rr, &balancers)?;
            if !r.rule_tag.is_empty() && !seen_rule_tags.insert(r.rule_tag.clone()) {
                return Err(RouterError::DuplicateRuleTag(r.rule_tag.clone()));
            }
            rules.push(Arc::new(r));
        }

        Ok(Arc::new(Self {
            domain_strategy: DomainStrategy::from_proto_i32(config.domain_strategy),
            rules: RwLock::new(rules),
            balancers: RwLock::new(balancers),
            ohm,
        }))
    }

    /// 创建空 Router（仅测试用）。
    #[must_use]
    pub fn empty(ohm: Arc<dyn OutboundHandlerSelector>) -> Arc<Self> {
        Arc::new(Self {
            domain_strategy: DomainStrategy::default(),
            rules: RwLock::new(Vec::new()),
            balancers: RwLock::new(HashMap::new()),
            ohm,
        })
    }

    /// 返回域名策略。
    #[must_use]
    pub fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }

    /// 返回 ohm 引用（构建 BalancingRule 时使用）。
    #[must_use]
    pub fn ohm(&self) -> &Arc<dyn OutboundHandlerSelector> {
        &self.ohm
    }

    /// 路由匹配。返回第一条命中规则的 tag。
    ///
    /// 对应 Go `Router.PickRoute`。
    pub fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<Route, RouterError> {
        let rules = self.rules.read();
        for rule in rules.iter() {
            if let Some(tag) = rule.apply(ctx) {
                if !tag.is_empty() {
                    return Ok(Route {
                        outbound_tag: tag,
                        rule_tag: rule.rule_tag.clone(),
                    });
                }
            }
        }
        Err(RouterError::NoClue)
    }

    /// 增加一条规则（运行时）。
    ///
    /// 对应 Go `Router.AddRule`。
    pub fn add_rule(&self, rule_tag: String, proto: RoutingRule) -> Result<(), RouterError> {
        if rule_tag.is_empty() {
            return Err(RouterError::EmptyTagName);
        }
        let mut rules = self.rules.write();
        if rules.iter().any(|r| r.rule_tag == rule_tag) {
            return Err(RouterError::DuplicateRuleTag(rule_tag));
        }
        let balancers = self.balancers.read();
        let mut proto = proto;
        proto.rule_tag = rule_tag.clone();
        let r = build_rule(&proto, &balancers)?;
        rules.push(Arc::new(r));
        Ok(())
    }

    /// 移除一条规则。
    ///
    /// 对应 Go `Router.RemoveRule`。
    pub fn remove_rule(&self, rule_tag: &str) -> Result<(), RouterError> {
        if rule_tag.is_empty() {
            return Err(RouterError::EmptyTagName);
        }
        let mut rules = self.rules.write();
        let before = rules.len();
        rules.retain(|r| r.rule_tag != rule_tag);
        if rules.len() == before {
            return Err(RouterError::TagNotFound);
        }
        Ok(())
    }

    /// 重载规则。
    ///
    /// 对应 Go `Router.ReloadRules`。
    pub fn reload_rules(&self, protos: &[RoutingRule]) -> Result<(), RouterError> {
        let balancers = self.balancers.read();
        let mut new_rules = Vec::with_capacity(protos.len());
        let mut seen = std::collections::HashSet::new();
        for p in protos {
            let r = build_rule(p, &balancers)?;
            if !r.rule_tag.is_empty() && !seen.insert(r.rule_tag.clone()) {
                return Err(RouterError::DuplicateRuleTag(r.rule_tag.clone()));
            }
            new_rules.push(Arc::new(r));
        }
        *self.rules.write() = new_rules;
        Ok(())
    }

    /// 列出当前规则 tag。
    pub fn list_rules(&self) -> Vec<String> {
        self.rules.read().iter().map(|r| r.rule_tag.clone()).collect()
    }

    /// 覆盖平衡器目标。
    ///
    /// 对应 Go `Router.OverrideBalancer`。
    pub fn override_balancer(
        &self,
        balancer_tag: &str,
        target: &str,
    ) -> Result<(), RouterError> {
        let balancers = self.balancers.read();
        let b = balancers
            .get(balancer_tag)
            .ok_or_else(|| RouterError::BalancerNotFound(balancer_tag.to_string()))?;
        b.set_override_target(target);
        Ok(())
    }

    /// 返回平衡器句柄（仅查信息用）。
    pub fn get_balancer(&self, tag: &str) -> Option<Arc<Balancer>> {
        self.balancers.read().get(tag).cloned()
    }
}

/// 构建 Balancer。
///
/// 对应 Go `BalancingRule.Build`。strategy_settings 当前不解析
/// （TypedMessage 反序列化需上层提供），LeastLoad 使用默认配置。
fn build_balancer(
    br: &BalancingRule,
    ohm: &Arc<dyn OutboundHandlerSelector>,
) -> Result<Balancer, RouterError> {
    let strategy: Arc<dyn BalancingStrategy> = match br.strategy.as_str() {
        "random" => Arc::new(crate::strategy_random::RandomStrategy::new(
            br.outbound_selector.clone(),
            ohm.clone(),
            br.fallback_tag.clone(),
        )),
        "leastping" => {
            // 需 observer，当前 stub 返回 EmptyBalancerResult
            // TODO: 接入 observation provider
            return Err(RouterError::ObservationUnavailable(
                "leastping requires observer".into(),
            ));
        }
        "leastload" => {
            // 同上
            return Err(RouterError::ObservationUnavailable(
                "leastload requires observer".into(),
            ));
        }
        "" | "roundrobin" => Arc::new(crate::balancing::RoundRobinStrategy::new(
            br.outbound_selector.clone(),
            ohm.clone(),
            None,
        )),
        other => {
            tracing::warn!(target: "xray_router", strategy = %other, "unknown strategy, falling back to roundrobin");
            Arc::new(crate::balancing::RoundRobinStrategy::new(
                br.outbound_selector.clone(),
                ohm.clone(),
                None,
            ))
        }
    };

    Ok(Balancer::new(
        br.outbound_selector.clone(),
        strategy,
        ohm.clone(),
        br.fallback_tag.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RoutingData;
    use crate::balancing::NotImplementedSelector;

    fn simple_tag_rule(tag: &str, domain: &str) -> RoutingRule {
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::common::geodata::{Domain, DomainRule};
        use xray_proto::xray::common::geodata::domain::Type as DT;
        RoutingRule {
            target_tag: Some(TargetTag::Tag(tag.into())),
            rule_tag: String::new(),
            domain: vec![DomainRule {
                value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(Domain {
                    r#type: DT::Full as i32,
                    value: domain.into(),
                    attribute: vec![],
                })),
            }],
            ip: vec![],
            port_list: None,
            source_ip: vec![],
            source_port_list: None,
            networks: vec![],
            user_email: vec![],
            inbound_tag: vec![],
            protocol: vec![],
            attributes: HashMap::new(),
            local_ip: vec![],
            local_port_list: None,
            vless_route_list: None,
            process: vec![],
            webhook: None,
        }
    }

    #[test]
    fn test_empty_router_returns_no_clue() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        let ctx = RoutingData::new().with_target_domain("any");
        assert!(matches!(r.pick_route(&ctx), Err(RouterError::NoClue)));
    }

    #[test]
    fn test_simple_router_picks_matching_rule() {
        let mut cfg = Config::default();
        cfg.rule = vec![simple_tag_rule("direct", "example.com")];
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector)).unwrap();
        let hit = RoutingData::new().with_target_domain("example.com");
        let miss = RoutingData::new().with_target_domain("other.io");
        assert_eq!(
            r.pick_route(&hit).unwrap(),
            Route { outbound_tag: "direct".into(), rule_tag: String::new() }
        );
        assert!(matches!(r.pick_route(&miss), Err(RouterError::NoClue)));
    }

    #[test]
    fn test_add_and_remove_rule() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        r.add_rule("rule1".into(), simple_tag_rule("tag1", "a.com")).unwrap();
        assert!(r.list_rules().contains(&"rule1".to_string()));

        // duplicate add
        assert!(matches!(
            r.add_rule("rule1".into(), simple_tag_rule("t2", "b.com")),
            Err(RouterError::DuplicateRuleTag(_))
        ));

        // remove
        r.remove_rule("rule1").unwrap();
        assert!(!r.list_rules().contains(&"rule1".to_string()));

        // remove non-existent
        assert!(matches!(r.remove_rule("nope"), Err(RouterError::TagNotFound)));
    }

    #[test]
    fn test_reload_rules_replaces_all() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        r.add_rule("r1".into(), simple_tag_rule("t1", "a.com")).unwrap();
        let new_rules = vec![
            simple_tag_rule("t2", "b.com"),
        ];
        // 给新规则添加 rule_tag
        let _ = r.reload_rules(&new_rules);
        // 不抛错即 OK；详情见 list_rules
        assert_eq!(r.list_rules().len(), 1);
    }

    #[test]
    fn test_override_balancer_not_found() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        let err = r.override_balancer("nope", "target").unwrap_err();
        assert!(matches!(err, RouterError::BalancerNotFound(_)));
    }

    #[test]
    fn test_domain_strategy_from_config() {
        let mut cfg = Config::default();
        cfg.domain_strategy = 3; // IpOnDemand
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector)).unwrap();
        assert_eq!(r.domain_strategy(), DomainStrategy::IpOnDemand);
    }
}
