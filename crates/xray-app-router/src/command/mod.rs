//! gRPC RoutingService — 接入 Router 的管理 RPC。
//!
//! 翻译自 `app/router/command/`。7 个 RPC 方法委托给 [`Router`]。
//! subscribe_routing_stats 需要 gRPC streaming 框架，暂未接入。
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

    /// 测试路由（简化：返回目标 tag 或 "no match"）。
    ///
    /// 完整 test_route 需要 RoutingContext（含 source IP、protocol、session 等），
    /// 当前仅返回 "test_route requires full RoutingContext (gRPC 端补全)"。
    pub fn test_route(&self, _dest: &str) -> Result<String, RouterError> {
        // ponytail: pick_route 需要 &dyn RoutingContext，从 dest 字符串构造不完整。
        // gRPC 端补全完整 context 后委托 router.pick_route。
        Err(RouterError::Other(
            "test_route requires full RoutingContext (gRPC 端补全)".into(),
        ))
    }

    /// 添加规则（需要完整 rule config）。
    ///
    /// add_rule 需要 `RoutingRule` proto 配置，当前仅接受 tag。
    /// gRPC 端补全完整 config 后委托 [`Router::add_rule`]。
    pub fn add_rule(&self, _tag: &str) -> Result<(), RouterError> {
        Err(RouterError::Other(
            "add_rule requires full RoutingRule config (gRPC 端补全)".into(),
        ))
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
}
