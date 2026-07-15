//! 路由集成：把 Router 规则匹配接入 dispatcher 的 handler 选择。
//!
//! 对应 Go `app/dispatcher/default.go::DefaultDispatcher.Dispatch` 中的路由环节：
//! 拨号前先查 router，命中规则则选 tagged outbound，否则走 default。
//!
//! # 设计
//!
//! [`RoutingHandler`] 包装在 SimpleOhm 的 default handler 外层：
//! - router 命中 → `ohm.get_handler(tag)`（tagged outbound）
//! - router miss → `inner_default`（原始 default outbound，避免循环）

use std::sync::Arc;

use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::{DispatchHandler, OutboundHandlerManager};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_transport::link::Link;

/// 路由查询 trait：给定目标，返回 outbound tag（None = 用 default）。
pub trait DispatchRouter: Send + Sync {
    fn pick_outbound_tag(&self, dest: &Destination) -> Option<String>;
}

/// 带路由的 DispatchHandler：包装在 default handler 外层。
pub struct RoutingHandler {
    ohm: Arc<SimpleOhm>,
    inner_default: Arc<dyn DispatchHandler>,
    router: Arc<dyn DispatchRouter>,
    tag: String,
}

impl RoutingHandler {
    #[must_use]
    pub fn new(
        ohm: Arc<SimpleOhm>,
        inner_default: Arc<dyn DispatchHandler>,
        router: Arc<dyn DispatchRouter>,
    ) -> Self {
        Self { ohm, inner_default, router, tag: "router".to_string() }
    }
}

impl std::fmt::Debug for RoutingHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingHandler").field("tag", &self.tag).finish()
    }
}

impl DispatchHandler for RoutingHandler {
    fn tag(&self) -> &str { &self.tag }

    fn dispatch(
        &self,
        dest: &Destination,
        link: Link,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        let ohm = Arc::clone(&self.ohm);
        let inner = Arc::clone(&self.inner_default);
        let router = Arc::clone(&self.router);
        let dest_clone = clone_destination(dest);
        Box::pin(async move {
            let tag_opt = router.pick_outbound_tag(&dest_clone);
            let handler = match &tag_opt {
                Some(tag) => ohm.get_handler(tag).unwrap_or_else(|| inner.clone()),
                None => inner.clone(),
            };
            tracing::debug!(
                target = ?dest_clone.address(),
                port = dest_clone.port().value(),
                routed = tag_opt.is_some(),
                "dispatch routed"
            );
            handler.dispatch(&dest_clone, link).await;
        })
    }
}

fn clone_destination(dest: &Destination) -> Destination {
    let address = match dest.address() {
        Address::IPv4(ip) => Address::IPv4(*ip),
        Address::IPv6(ip) => Address::IPv6(*ip),
        Address::Domain(d) => Address::Domain(d.clone()),
    };
    Destination::new(address, dest.port(), dest.network())
}

/// 简单 domain→tag 路由器（测试用 / 最简配置）。
pub struct TagRouter {
    rules: Vec<(String, String)>,
}

impl TagRouter {
    #[must_use]
    pub fn new(rules: Vec<(String, String)>) -> Self { Self { rules } }
}

impl DispatchRouter for TagRouter {
    fn pick_outbound_tag(&self, dest: &Destination) -> Option<String> {
        if let Address::Domain(d) = dest.address() {
            for (pattern, tag) in &self.rules {
                if d == pattern { return Some(tag.clone()); }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use xray_proxy_freedom::make_freedom_dial_fn;

    fn dummy_dest(domain: &str) -> Destination {
        Destination::new(Address::Domain(domain.to_string()), Port::new(80), Network::TCP)
    }

    #[test]
    fn tag_router_matches_domain() {
        let router = TagRouter::new(vec![
            ("blocked.com".to_string(), "proxy".to_string()),
            ("direct.com".to_string(), "direct".to_string()),
        ]);
        assert_eq!(router.pick_outbound_tag(&dummy_dest("blocked.com")), Some("proxy".to_string()));
    }

    #[test]
    fn tag_router_misses_unlisted_domain() {
        let router = TagRouter::new(vec![("a.com".to_string(), "proxy".to_string())]);
        assert!(router.pick_outbound_tag(&dummy_dest("b.com")).is_none());
    }

    #[test]
    fn tag_router_ignores_ip_destinations() {
        let router = TagRouter::new(vec![("a.com".to_string(), "proxy".to_string())]);
        let dest = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            Port::new(80),
            Network::TCP,
        );
        assert!(router.pick_outbound_tag(&dest).is_none());
    }

    #[test]
    fn routing_handler_tag_is_router() {
        let ohm = Arc::new(SimpleOhm::new());
        let freedom = Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))
            as Arc<dyn DispatchHandler>;
        ohm.set_default(freedom.clone());
        let router = Arc::new(TagRouter::new(vec![]));
        let routing = RoutingHandler::new(Arc::clone(&ohm), freedom, router);
        assert_eq!(routing.tag(), "router");
    }

    #[test]
    fn routing_handler_registered_as_default() {
        let ohm = Arc::new(SimpleOhm::new());
        let freedom = Arc::new(DialBridge::new("direct", make_freedom_dial_fn()))
            as Arc<dyn DispatchHandler>;
        ohm.set_default(freedom.clone());
        let router = Arc::new(TagRouter::new(vec![]));
        let routing = Arc::new(RoutingHandler::new(Arc::clone(&ohm), freedom, router))
            as Arc<dyn DispatchHandler>;
        ohm.set_default(routing);
        let handler = ohm.get_default_handler().expect("should have default");
        assert_eq!(handler.tag(), "router");
    }
}
