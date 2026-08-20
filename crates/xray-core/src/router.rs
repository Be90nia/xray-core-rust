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

    /// 带 DNS 解析的选路（routing domainStrategy）。
    ///
    /// 默认退化为同步 [`DispatchRouter::pick_outbound_tag`]（无 DNS 能力的 router
    /// 或 AsIs 策略等价）。
    fn pick_outbound_tag_resolved<'a>(
        &'a self,
        dest: &'a Destination,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move { self.pick_outbound_tag(dest) })
    }

    /// 注入 DNS 解析能力（domainStrategy IpOnDemand/IpIfNonMatch 用）。
    ///
    /// 默认 no-op——无 DNS 能力的实现（TagRouter/PatternRouter）保持 AsIs 行为。
    fn set_dns_client(&self, _dns: Arc<dyn xray_features::dns::DnsClient>) {}
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
            let tag_opt = router.pick_outbound_tag_resolved(&dest_clone).await;
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

/// 单条域名模式。
#[derive(Debug, Clone)]
enum DomainPattern {
    Exact(String),
    Suffix(String),
    Keyword(String),
}

impl DomainPattern {
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(d) => domain == d,
            Self::Suffix(s) => {
                // ponytail: 不用外部 crate，手写 case-insensitive suffix 匹配
                let domain_l = domain.to_lowercase();
                let suffix_l = s.to_lowercase();
                domain_l == suffix_l || domain_l.ends_with(&format!(".{suffix_l}"))
            }
            Self::Keyword(k) => domain.to_lowercase().contains(&k.to_lowercase()),
        }
    }
}

/// 单条 IP 模式（CIDR）。
#[derive(Debug, Clone)]
enum IpPattern {
    V4(std::net::Ipv4Addr, u8),
    V6(std::net::Ipv6Addr, u8),
}

impl IpPattern {
    fn matches(&self, ip: std::net::IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(net, bits), std::net::IpAddr::V4(addr)) => {
                cidr_v4_contains(*net, *bits, addr)
            }
            (Self::V6(net, bits), std::net::IpAddr::V6(addr)) => {
                cidr_v6_contains(*net, *bits, addr)
            }
            _ => false,
        }
    }
}

fn cidr_v4_contains(net: std::net::Ipv4Addr, bits: u8, addr: std::net::Ipv4Addr) -> bool {
    let net_int = u32::from(net);
    let addr_int = u32::from(addr);
    if bits == 0 { return true; }
    if bits > 32 { return false; }
    let mask = !0u32 << (32 - bits);
    (net_int & mask) == (addr_int & mask)
}

fn cidr_v6_contains(net: std::net::Ipv6Addr, bits: u8, addr: std::net::Ipv6Addr) -> bool {
    let net_b = net.octets();
    let addr_b = addr.octets();
    if bits == 0 { return true; }
    if bits > 128 { return false; }
    let full_bytes = usize::from(bits / 8);
    let rem_bits = bits % 8;
    if net_b[..full_bytes] != addr_b[..full_bytes] { return false; }
    if rem_bits == 0 { return true; }
    let mask = !0u8 << (8 - rem_bits);
    (net_b[full_bytes] & mask) == (addr_b[full_bytes] & mask)
}

fn parse_cidr(s: &str) -> Option<IpPattern> {
    let (ip_part, bits_part) = s.split_once('/') ?;
    let bits: u8 = bits_part.parse().ok()?;
    if let Ok(v4) = ip_part.parse::<std::net::Ipv4Addr>() {
        return Some(IpPattern::V4(v4, bits));
    }
    if let Ok(v6) = ip_part.parse::<std::net::Ipv6Addr>() {
        return Some(IpPattern::V6(v6, bits));
    }
    None
}

/// 单条路由规则。
#[derive(Debug, Clone)]
struct PatternRule {
    domains: Vec<DomainPattern>,
    ips: Vec<IpPattern>,
    outbound_tag: String,
}

impl PatternRule {
    fn matches(&self, dest: &Destination) -> bool {
        let domain_hit = !self.domains.is_empty() && match dest.address() {
            Address::Domain(d) => self.domains.iter().any(|p| p.matches(d)),
            _ => false,
        };
        if domain_hit { return true; }
        let ip_hit = !self.ips.is_empty() && match dest.address() {
            Address::IPv4(ip) => self.ips.iter().any(|p| p.matches(std::net::IpAddr::V4(*ip))),
            Address::IPv6(ip) => self.ips.iter().any(|p| p.matches(std::net::IpAddr::V6(*ip))),
            _ => false,
        };
        ip_hit
    }
}

/// JSON 路由配置文件驱动的 router（对应 Go `app/router/router.go` 的简版）。
///
/// 支持 `domain` / `domainSuffix` / `domainKeyword` / `ip` (CIDR) / `outboundTag` 字段。
/// 未支持：`port` / `network` / `protocol` / balancer（YAGNI，后续按需补）。
pub struct PatternRouter {
    rules: Vec<PatternRule>,
}

impl PatternRouter {
    /// 从 routing 配置 JSON（Go `RouterConfig`）构造。
    ///
    /// # Errors
    /// 返回 `ConfError::Build` 风格的 io 错误 如果 JSON 解析失败。
    pub fn from_json(data: &[u8]) -> std::io::Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| std::io::Error::other(format!("routing config JSON: {e}")))?;
        let mut rules = Vec::new();
        if let Some(arr) = v.get("rules").and_then(|r| r.as_array()) {
            for r in arr {
                let outbound_tag = r.get("outboundTag").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if outbound_tag.is_empty() {
                    // 可能是 balancerTag，跳过（未支持）
                    continue;
                }
                let mut domains = Vec::new();
                for d in json_str_iter(r.get("domain")) { domains.push(DomainPattern::Exact(d.to_string())); }
                for d in json_str_iter(r.get("domainSuffix")) { domains.push(DomainPattern::Suffix(d.to_string())); }
                for d in json_str_iter(r.get("domainKeyword")) { domains.push(DomainPattern::Keyword(d.to_string())); }
                let mut ips = Vec::new();
                for ip_str in json_str_iter(r.get("ip")) {
                    if let Some(p) = parse_cidr(ip_str) { ips.push(p); }
                }
                rules.push(PatternRule { domains, ips, outbound_tag });
            }
        }
        Ok(Self { rules })
    }
}

fn json_str_iter<'a>(v: Option<&'a serde_json::Value>) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    match v.and_then(|x| x.as_array()) {
        Some(arr) => Box::new(arr.iter().filter_map(|x| x.as_str())),
        None => Box::new(std::iter::empty()),
    }
}

impl DispatchRouter for PatternRouter {
    fn pick_outbound_tag(&self, dest: &Destination) -> Option<String> {
        for rule in &self.rules {
            if rule.matches(dest) {
                return Some(rule.outbound_tag.clone());
            }
        }
        None
    }
}
impl PatternRouter {
    /// 返回规则数 (仅供测试).
    pub fn rules_len_for_test(&self) -> usize { self.rules.len() }
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

    // ===== PatternRouter 测试 =====

    fn make_routing_json(rules_json: &str) -> Vec<u8> {
        format!("{{\"rules\":{rules_json}}}").into_bytes()
    }

    #[test]
    fn pattern_router_domain_exact_match() {
        let json = make_routing_json("[{\"outboundTag\":\"proxy\",\"domain\":[\"example.com\"]}]");
        let r = PatternRouter::from_json(&json).unwrap();
        let dest = dummy_dest("example.com");
        assert_eq!(r.pick_outbound_tag(&dest).as_deref(), Some("proxy"));
        // 子域名不匹配 exact
        let dest2 = dummy_dest("sub.example.com");
        assert!(r.pick_outbound_tag(&dest2).is_none());
    }

    #[test]
    fn pattern_router_domain_suffix_match() {
        let json = make_routing_json(
            "[{\"outboundTag\":\"proxy\",\"domainSuffix\":[\"google.com\"]}]",
        );
        let r = PatternRouter::from_json(&json).unwrap();
        assert_eq!(
            r.pick_outbound_tag(&dummy_dest("www.google.com")).as_deref(),
            Some("proxy")
        );
        assert_eq!(
            r.pick_outbound_tag(&dummy_dest("google.com")).as_deref(),
            Some("proxy")
        );
        assert!(r.pick_outbound_tag(&dummy_dest("bing.com")).is_none());
    }

    #[test]
    fn pattern_router_domain_keyword_match() {
        let json = make_routing_json(
            "[{\"outboundTag\":\"blocked\",\"domainKeyword\":[\"bad\"]}]",
        );
        let r = PatternRouter::from_json(&json).unwrap();
        assert_eq!(
            r.pick_outbound_tag(&dummy_dest("verybad.com")).as_deref(),
            Some("blocked")
        );
    }

    #[test]
    fn pattern_router_ip_cidr_match() {
        let json = make_routing_json(
            "[{\"outboundTag\":\"direct\",\"ip\":[\"10.0.0.0/8\"]}]",
        );
        let r = PatternRouter::from_json(&json).unwrap();
        let dest_in = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(10, 1, 2, 3)),
            Port::new(80),
            Network::TCP,
        );
        assert_eq!(r.pick_outbound_tag(&dest_in).as_deref(), Some("direct"));
        let dest_out = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            Port::new(80),
            Network::TCP,
        );
        assert!(r.pick_outbound_tag(&dest_out).is_none());
    }

    #[test]
    fn pattern_router_first_match_wins() {
        let json = make_routing_json(
            "[{\"outboundTag\":\"A\",\"domain\":[\"x.com\"]},
             {\"outboundTag\":\"B\",\"domain\":[\"x.com\"]}]",
        );
        let r = PatternRouter::from_json(&json).unwrap();
        assert_eq!(r.pick_outbound_tag(&dummy_dest("x.com")).as_deref(), Some("A"));
    }

    #[test]
    fn pattern_router_empty_rules_returns_none() {
        let json = make_routing_json("[]");
        let r = PatternRouter::from_json(&json).unwrap();
        assert!(r.pick_outbound_tag(&dummy_dest("anywhere.com")).is_none());
    }

    #[test]
    fn pattern_router_skips_rule_without_outbound_tag() {
        let json = make_routing_json("[{\"domain\":[\"x.com\"]}]");
        let r = PatternRouter::from_json(&json).unwrap();
        assert_eq!(r.rules_len_for_test(), 0);
    }
}
