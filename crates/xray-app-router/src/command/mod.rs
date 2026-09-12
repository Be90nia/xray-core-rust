//! gRPC RoutingService — 接入 Router 的管理 RPC。
//!
//! 翻译自 `app/router/command/`。7 个 RPC 方法委托给 [`Router`]。
//! `subscribe_routing_stats` 的 channel 订阅与流式转发由 commander gRPC 层实现。
//!
//! # 架构
//!
//! [`RoutingService`] 持有 `Option<Arc<Router>>`：
//! - `new()` → `None`（向后兼容，方法返回 "router not configured"）
//! - `with_router(r)` → `Some(r)`（委托给 Router 实际方法）

use std::sync::Arc;

use crate::error::RouterError;
use crate::router::Router;

/// gRPC RoutingService 管理 RPC。
///
/// 对应 Go `app/router/command/command.go::routingServer`。
/// 持有 [`Router`] 引用，7 个 RPC 委托给 Router 方法。
pub struct RoutingService {
    router: Option<Arc<Router>>,
}

impl Default for RoutingService {
    fn default() -> Self {
        Self { router: None }
    }
}

impl RoutingService {
    /// 创建未配置 Router 的 stub（方法返回 "router not configured"）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 创建已注入 Router 的 RoutingService。
    #[must_use]
    pub fn with_router(router: Arc<Router>) -> Self {
        Self { router: Some(router) }
    }

    fn router(&self) -> Result<&Router, RouterError> {
        self.router
            .as_deref()
            .ok_or_else(|| RouterError::Other("router not configured in RoutingService".into()))
    }

    /// 获取平衡器信息（验证 tag 存在性）。
    pub fn get_balancer_info(&self, tag: &str) -> Result<(), RouterError> {
        let router = self.router()?;
        router
            .get_balancer(tag)
            .map(|_| ())
            .ok_or_else(|| RouterError::BalancerNotFound(tag.to_string()))
    }

    /// 获取平衡器覆盖目标（对应 Go `routingServer.GetBalancerInfo` 之 override
    /// 字段，即 `Router.GetOverrideTarget`，balancing.go:162-166）。
    ///
    /// 返回当前 override 值（空字符串 = 无覆盖，Go 同返回空串）。
    pub fn get_override_target(&self, tag: &str) -> Result<String, RouterError> {
        let router = self.router()?;
        router
            .get_balancer(tag)
            .map(|b| b.get_override_target())
            .ok_or_else(|| RouterError::BalancerNotFound(tag.to_string()))
    }

    /// 覆盖平衡器目标。委托 [`Router::override_balancer`]。
    pub fn override_balancer_target(
        &self,
        tag: &str,
        target: &str,
    ) -> Result<(), RouterError> {
        self.router()?.override_balancer(tag, target)
    }

    /// 移除规则。委托 [`Router::remove_rule`]。
    pub fn remove_rule(&self, tag: &str) -> Result<(), RouterError> {
        self.router()?.remove_rule(tag)
    }

    /// 列出规则 tag。委托 [`Router::list_rules`]。
    pub fn list_rule(&self) -> Result<Vec<String>, RouterError> {
        Ok(self.router()?.list_rules())
    }

    /// 测试路由（对应 Go `routingServer.TestRoute` / `Router.PickRoute`）。
    ///
    /// 接受一个 `&dyn RoutingContext`——gRPC 端将 `TestRouteRequest.RoutingContext`
    /// 解码为字段后构造 [`crate::context::RoutingData`] 再传入。本握手层面
    /// 仅暴露核心（dest/port/network/domain/user/inbound）路径：调用方组装。
    pub fn test_route(
        &self,
        ctx: &dyn crate::context::RoutingContext,
    ) -> Result<crate::router::Route, RouterError> {
        self.router()?.pick_route(ctx)
    }

    /// 添加规则（对应 Go `routingServer.AddRule` / `Router.AddRule`）。
    ///
    /// `rule_tag` 来自 proto `RoutingRule.rule_tag`（gRPC 端解码时填充）；
    /// `proto` 为 `xray_proto::xray::app::router::RoutingRule` 完整字段。
    pub fn add_rule(
        &self,
        rule_tag: String,
        proto: xray_proto::xray::app::router::RoutingRule,
    ) -> Result<(), RouterError> {
        self.router()?.add_rule(rule_tag, proto)
    }

    /// 获取平衡器原则目标（对应 Go `routingServer.GetBalancerInfo` 之 principle
    /// 字段，即 `(*RoundRobinStrategy).GetPrincipleTarget` 等）。
    ///
    /// 返回 balance `selectors` 经 [`OutboundHandlerSelector::select_outbounds`]
    /// 过滤后的 outbound 列表（顺序由 strategy 决定；当前实现直接走 selectors 顺序，
    /// 与 Go `RoundRobinStrategy.GetPrincipleTarget(strings) []string { return strings }`
    /// 的 Round-Robin 行为等价）。
    pub fn get_principle_target(
        &self,
        balancer_tag: &str,
    ) -> Result<Vec<String>, RouterError> {
        let router = self.router()?;
        let balancer = router
            .get_balancer(balancer_tag)
            .ok_or_else(|| RouterError::BalancerNotFound(balancer_tag.to_string()))?;
        let selects = router.ohm();
        let tags: Vec<String> = balancer.selectors().to_vec();
        selects
            .select_outbounds(&tags)
            .map_err(|e| RouterError::Other(format!("select_outbounds: {e}")))
    }

}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_router_returns_not_configured() {
        let s = RoutingService::new();
        let err = s.list_rule().unwrap_err();
        assert!(format!("{err}").contains("not configured"));
    }

    #[test]
    fn with_router_list_rule_returns_empty() {
        use crate::balancing::{NotImplementedSelector, OutboundHandlerSelector};
        let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);
        let router = Router::empty(ohm, None);
        let s = RoutingService::with_router(router);
        assert_eq!(s.list_rule().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn with_router_get_balancer_info_unknown_tag() {
        use crate::balancing::{NotImplementedSelector, OutboundHandlerSelector};
        let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);
        let router = Router::empty(ohm, None);
        let s = RoutingService::with_router(router);
        assert!(s.get_balancer_info("nonexistent").is_err());
    }

    #[test]
    fn test_route_without_matching_rule_returns_no_clue() {
        use crate::balancing::{NotImplementedSelector, OutboundHandlerSelector};
        use crate::context::RoutingData;
        let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);
        let router = Router::empty(ohm, None);
        let s = RoutingService::with_router(router);
        let ctx = RoutingData::new();
        let err = s.test_route(&ctx).unwrap_err();
        assert!(format!("{err}").contains("no route matched"));
    }

    /// add_rule: 接受 RoutingRule proto，注册后 list_rule 可见。
    #[test]
    fn add_rule_then_list_rule_contains_tag() {
        use crate::balancing::{NotImplementedSelector, OutboundHandlerSelector};
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::app::router::RoutingRule;
        use xray_proto::xray::common::geodata::domain::Type as DomainType;
        use xray_proto::xray::common::geodata::{Domain, DomainRule};
        let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);
        let router = Router::empty(ohm, None);
        let s = RoutingService::with_router(router);
        let mut proto = RoutingRule::default();
        proto.domain = vec![DomainRule {
            value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(
                Domain {
                    r#type: DomainType::Full as i32,
                    value: "example.com".into(),
                    attribute: vec![],
                },
            )),
        }];
        proto.target_tag = Some(TargetTag::Tag("out-A".into()));
        s.add_rule("rule-1".to_string(), proto).expect("add_rule");
        let tags = s.list_rule().unwrap();
        assert!(tags.contains(&"rule-1".to_string()));
    }

    /// get_principle_target: unknown balancer → BalancerNotFound 错误。
    #[test]
    fn get_principle_target_unknown_balancer_errors() {
        use crate::balancing::{NotImplementedSelector, OutboundHandlerSelector};
        let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);
        let router = Router::empty(ohm, None);
        let s = RoutingService::with_router(router);
        assert!(s.get_principle_target("missing").is_err());
    }

}
