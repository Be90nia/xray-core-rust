//! gRPC RoutingService stub。
//!
//! 翻译自 `app/router/command/`。依赖 stats.Channel + gRPC 服务框架。
//!
//! **当前状态**：所有接口全 stub，仅保留 API 形状。
//!
//! # 计划接口（对应 Go `RoutingService`）
//!
//! - `get_balancer_info(tag) -> BalancerInfo`
//! - `override_balancer_target(tag, target)`
//! - `add_rule(tag, config)`
//! - `remove_rule(tag)`
//! - `list_rule() -> Vec<Rule>`
//! - `test_route(destination, session) -> Route`
//! - `subscribe_routing_stats() -> Stream<RoutingStats>`

use crate::error::RouterError;

/// gRPC RoutingService stub。
///
/// TODO: 接入 gRPC 框架后实现。
#[derive(Debug, Default)]
pub struct RoutingService;

impl RoutingService {
    /// 创建 stub。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取平衡器信息。
    pub fn get_balancer_info(&self, _tag: &str) -> Result<(), RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }

    /// 覆盖平衡器目标。
    pub fn override_balancer_target(
        &self,
        _tag: &str,
        _target: &str,
    ) -> Result<(), RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }

    /// 添加规则。
    pub fn add_rule(&self, _tag: &str) -> Result<(), RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }

    /// 移除规则。
    pub fn remove_rule(&self, _tag: &str) -> Result<(), RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }

    /// 列出规则。
    pub fn list_rule(&self) -> Result<Vec<String>, RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }

    /// 测试路由。
    pub fn test_route(&self, _dest: &str) -> Result<String, RouterError> {
        Err(RouterError::Other("RoutingService not implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_methods_return_not_implemented() {
        let s = RoutingService::new();
        assert!(s.get_balancer_info("x").is_err());
        assert!(s.override_balancer_target("x", "y").is_err());
        assert!(s.add_rule("x").is_err());
        assert!(s.remove_rule("x").is_err());
        assert!(s.list_rule().is_err());
        assert!(s.test_route("x").is_err());
    }
}
