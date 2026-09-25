//! Router trait for routing decisions.
//!
//! Corresponds to Go's `features/routing` package.

use async_trait::async_trait;
use xray_common::{net::destination::Destination, session::Session};

use crate::Feature;

/// Feature type identifier for Router.
pub const FEATURE_ROUTER: &str = "router";

/// Router trait for routing decisions.
///
/// Corresponds to Go's `features/routing.Router`.
#[async_trait]
pub trait Router: Send + Sync {
    /// Pick an outbound handler tag for the given destination and session.
    async fn pick_route(
        &self,
        destination: &Destination,
        session: &Session,
    ) -> Result<String, RoutingError>;

    /// Check if a destination should be routed through this router.
    fn has_rule_for(&self, destination: &Destination) -> bool;

    /// Get all outbound tags managed by this router.
    fn outbound_tags(&self) -> Vec<String>;
}

/// Routing error.
#[derive(Debug, Clone)]
pub enum RoutingError {
    /// No route found to the destination.
    NoRoute(String),
    /// Routing rule did not match.
    RuleMismatch,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::NoRoute(dest) => write!(f, "no route to destination: {}", dest),
            RoutingError::RuleMismatch => write!(f, "routing rule mismatch"),
        }
    }
}

impl std::error::Error for RoutingError {}

/// 默认 Router Feature 实现（essentialFeatures fallback）。
///
/// 当配置中没有指定 routing app 时，Instance 使用此空实现占位。
pub struct DefaultRouterFeature;

impl Feature for DefaultRouterFeature {
    fn feature_name(&self) -> &'static str {
        "default_router"
    }
}

#[cfg(test)]
mod tests {
    use xray_common::net::{address::Address, network::Network, port::Port};

    use super::*;

    #[test]
    fn test_feature_router_constant() {
        assert_eq!(FEATURE_ROUTER, "router");
    }

    #[test]
    fn test_routing_error_display() {
        assert_eq!(
            format!("{}", RoutingError::NoRoute("1.2.3.4".to_string())),
            "no route to destination: 1.2.3.4"
        );
        assert_eq!(format!("{}", RoutingError::RuleMismatch), "routing rule mismatch");
    }

    #[test]
    fn test_routing_error_is_std_error() {
        let err = RoutingError::RuleMismatch;
        let _: &dyn std::error::Error = &err;
    }

    /// Mock router for testing the trait is object-safe.
    struct MockRouter {
        tags: Vec<String>,
    }

    #[async_trait]
    impl Router for MockRouter {
        async fn pick_route(
            &self,
            _destination: &Destination,
            _session: &Session,
        ) -> Result<String, RoutingError> {
            self.tags.first().cloned().ok_or_else(|| RoutingError::NoRoute("no tags".to_string()))
        }

        fn has_rule_for(&self, _destination: &Destination) -> bool {
            true
        }

        fn outbound_tags(&self) -> Vec<String> {
            self.tags.clone()
        }
    }

    #[tokio::test]
    async fn test_mock_router_pick_route() {
        let router = MockRouter { tags: vec!["direct".to_string()] };
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let session = Session::new();
        let result = router.pick_route(&dest, &session).await;
        assert_eq!(result.unwrap(), "direct");
    }

    #[tokio::test]
    async fn test_mock_router_no_route() {
        let router = MockRouter { tags: vec![] };
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let session = Session::new();
        let result = router.pick_route(&dest, &session).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_router_has_rule() {
        let router = MockRouter { tags: vec!["proxy".to_string()] };
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        assert!(router.has_rule_for(&dest));
    }

    #[test]
    fn test_mock_router_outbound_tags() {
        let router = MockRouter { tags: vec!["direct".to_string(), "proxy".to_string()] };
        assert_eq!(router.outbound_tags(), vec!["direct", "proxy"]);
    }
}
