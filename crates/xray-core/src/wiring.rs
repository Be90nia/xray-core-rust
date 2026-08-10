//! 接线适配器：把 `xray-app-router::Router` 接入 dispatcher 的路由 trait。
//!
//! 对应 Go `core.go` 中 routing 配置注入路径——Go 端通过 `r := router.FromConfig(cfg)` 构造
//! `*router.Router` 并传入 `dispatcher.Init(ohm, r)`。Rust 端因 crate 边界不同，
//! 用 [`RouterAdapter`] 桥接两套 `RoutingContext` trait：
//!
//! - `xray_app_dispatcher::default::RoutingContext`（dispatcher 内部）
//! - `xray_app_router::context::RoutingContext`（router 内部）
//!
//! 两者方法几乎一致，唯一差异：dispatcher 端 `get_vless_route() -> &str`，
//! router 端 `get_vless_route() -> Port`。适配时用 `Port::new(0)` 占位
//! （VLESS 路由 ID 当前 dispatcher 路径未填充）。

use std::sync::Arc;

use xray_app_dispatcher::default::{
    DispatcherContext, Route as DispRoute, RoutingContext as DispRoutingContext, RoutingRouter,
};
use xray_app_dispatcher::DispatcherError;
use xray_proto::xray::common::geodata::{Cidr, CidrRule};
use xray_app_router::balancing::NotImplementedSelector;
use xray_app_router::context::RoutingData as RouterRoutingData;
use xray_app_router::error::RouterError;
use xray_app_router::Router;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;

use crate::router::DispatchRouter;

/// 把 `xray_app_router::Router` 暴露为 dispatcher 的 [`RoutingRouter`]。
///
/// 同时实现 [`DispatchRouter`]，便于现有的 `start_full_with_router` 路径
/// （走 `RoutingHandler` 包装）直接使用，无需切换到 `DefaultDispatcher`。
pub struct RouterAdapter {
    router: Arc<Router>,
}

impl RouterAdapter {
    /// 用已构造的 Router 创建适配器。
    #[must_use]
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }

    /// 内部 Router 引用（供直接调用 add_rule / reload_rules 等 API）。
    #[must_use]
    pub fn inner(&self) -> &Arc<Router> {
        &self.router
    }
}

impl std::fmt::Debug for RouterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterAdapter")
            .field("rules", &self.router.list_rules())
            .finish()
    }
}

/// 把 dispatcher 的 `RoutingContext` 字段拷贝到 router 的 `RoutingData`。
fn bridge_context(ctx: &dyn DispRoutingContext) -> RouterRoutingData {
    RouterRoutingData {
        target_ips: ctx.get_target_ips().to_vec(),
        target_domain: ctx.get_target_domain().to_string(),
        target_port: ctx.get_target_port(),
        source_ips: ctx.get_source_ips().to_vec(),
        source_port: ctx.get_source_port(),
        local_ips: ctx.get_local_ips().to_vec(),
        local_port: ctx.get_local_port(),
        // dispatcher 端 vless_route 是 &str，router 端是 Port；当前 dispatcher
        // 路径未填充 vless route id，用 0 占位（VLESS ENC 路由接入后再补全）。
        vless_route: Port::new(0),
        network: ctx.get_network(),
        user: ctx.get_user().to_string(),
        attributes: ctx.get_attributes().clone(),
        inbound_tag: ctx.get_inbound_tag().to_string(),
        protocol: ctx.get_protocol().to_string(),
        skip_dns_resolve: ctx.get_skip_dns_resolve(),
    }
}

/// 把 router 的 `RouterError` 映射为 dispatcher 的 `DispatcherError`。
///
/// `NoClue`（无规则命中）映射为 `Other("no route matched")`——dispatch_link 的
/// 调用方（line ~689）对 `Err(_)` 统一降级到 default handler。
fn map_router_err(e: RouterError) -> DispatcherError {
    match e {
        RouterError::NoClue => DispatcherError::Other("no route matched".into()),
        other => DispatcherError::Other(format!("router: {other}")),
    }
}

impl RoutingRouter for RouterAdapter {
    fn pick_route(
        &self,
        ctx: &dyn DispRoutingContext,
    ) -> Result<DispRoute, DispatcherError> {
        let data = bridge_context(ctx);
        match self.router.pick_route(&data) {
            Ok(route) => Ok(DispRoute {
                outbound_tag: route.outbound_tag,
                rule_tag: route.rule_tag,
            }),
            Err(e) => Err(map_router_err(e)),
        }
    }
}

/// 同一适配器也实现 [`DispatchRouter`]——便于 `start_full_with_router` 现有路径
/// （走 `RoutingHandler`，不依赖 `DefaultDispatcher`）直接复用完整 Router。
impl DispatchRouter for RouterAdapter {
    fn pick_outbound_tag(&self, dest: &Destination) -> Option<String> {
        let data = dest_to_routing_data(dest);
        match self.router.pick_route(&data) {
            Ok(route) => Some(route.outbound_tag),
            Err(_) => None,
        }
    }
}

/// 从 `Destination` 构造 router 端 `RoutingData`（仅目标地址/端口/网络）。
fn dest_to_routing_data(dest: &Destination) -> RouterRoutingData {
    let mut data = RouterRoutingData::new()
        .with_target_port(dest.port())
        .with_network(dest.network());
    match dest.address() {
        Address::IPv4(ip) => data = data.with_target_ip(std::net::IpAddr::V4(*ip)),
        Address::IPv6(ip) => data = data.with_target_ip(std::net::IpAddr::V6(*ip)),
        Address::Domain(d) => data = data.with_target_domain(d.clone()),
    }
    data
}

/// 从路由配置 JSON 字节构造 [`RouterAdapter`]。
///
/// 解析 `domain` / `domainSuffix` / `domainKeyword` / `ip` (CIDR) / `outboundTag`
/// 为 proto `Config` → `Router::init`。其他 proto 字段（balancer、user、protocol 等）
/// 留空——这些字段在 dispatcher 提供完整 `RoutingContext` 时才会被规则匹配用到。
///
/// # Errors
///
/// - JSON 解析失败
/// - `Router::init` 失败（如重复 ruleTag、geoip 规则但无 loader）
pub fn build_router_adapter_from_json(
    routing_json: &[u8],
) -> Result<Arc<RouterAdapter>, WiringError> {
    let config = parse_routing_json_to_proto(routing_json)?;
    let ohm: Arc<dyn xray_app_router::balancing::OutboundHandlerSelector> =
        Arc::new(NotImplementedSelector);
    let router = Router::init(&config, ohm, None)
        .map_err(|e| WiringError::RouterInit(e.to_string()))?;
    Ok(Arc::new(RouterAdapter::new(router)))
}

/// JSON → proto `Config` 的最小转换：覆盖与 `PatternRouter` 相同的字段集合。
fn parse_routing_json_to_proto(
    json: &[u8],
) -> Result<xray_proto::xray::app::router::Config, WiringError> {
    use prost::Message;
    use xray_proto::xray::app::router::routing_rule::TargetTag;
    use xray_proto::xray::app::router::RoutingRule;
    use xray_proto::xray::common::geodata::{
        Cidr, CidrRule, Domain, DomainRule, IpRule,
    };
    use xray_proto::xray::common::geodata::domain::Type as DT;
    use xray_proto::xray::common::geodata::ip_rule::Value as IV;
    use xray_proto::xray::common::geodata::domain_rule::Value as DV;

    let v: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| WiringError::JsonParse(e.to_string()))?;

    let mut cfg = xray_proto::xray::app::router::Config::default();
    if let Some(arr) = v.get("rules").and_then(|r| r.as_array()) {
        for r in arr {
            let outbound_tag = r
                .get("outboundTag")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if outbound_tag.is_empty() {
                continue;
            }
            let mut domains = Vec::new();
            for d in json_str_iter(r.get("domain")) {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Full as i32,
                        value: d.to_string(),
                        attribute: vec![],
                    })),
                });
            }
            for d in json_str_iter(r.get("domainSuffix")) {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Domain as i32,
                        value: d.to_string(),
                        attribute: vec![],
                    })),
                });
            }
            for d in json_str_iter(r.get("domainKeyword")) {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Substr as i32,
                        value: d.to_string(),
                        attribute: vec![],
                    })),
                });
            }
            let mut ips = Vec::new();
            for ip_str in json_str_iter(r.get("ip")) {
                if let Some(custom) = parse_cidr_to_ip_rule(ip_str) {
                    ips.push(IpRule { value: Some(IV::Custom(custom)) });
                }
            }
            cfg.rule.push(RoutingRule {
                target_tag: Some(TargetTag::Tag(outbound_tag.to_string())),
                rule_tag: String::new(),
                domain: domains,
                ip: ips,
                ..Default::default()
            });
        }
    }

    // 编码再解码一次以验证 Config 结构合法（同 prost 语义）
    let _ = cfg.encode_to_vec();
    Ok(cfg)
}

fn json_str_iter<'a>(v: Option<&'a serde_json::Value>) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    match v.and_then(|x| x.as_array()) {
        Some(arr) => Box::new(arr.iter().filter_map(|x| x.as_str())),
        None => Box::new(std::iter::empty()),
    }
}

/// 把 "1.2.3.0/24" 解析为 `CidrRule`（IPRule.custom 变体），不依赖 geoip.dat。
fn parse_cidr_to_ip_rule(s: &str) -> Option<CidrRule> {
    use xray_proto::xray::common::geodata::{Cidr, CidrRule};
    let (ip_part, bits_part) = s.split_once('/')?;
    let bits: u32 = bits_part.parse().ok()?;
    let ip_vec: Vec<u8> = if let Ok(v4) = ip_part.parse::<std::net::Ipv4Addr>() {
        v4.octets().to_vec()
    } else if let Ok(v6) = ip_part.parse::<std::net::Ipv6Addr>() {
        v6.octets().to_vec()
    } else {
        return None;
    };
    let prefix = bits.min(u32::from(u8::MAX));
    Some(CidrRule {
        cidr: Some(Cidr { ip: ip_vec, prefix }),
        reverse_match: false,
    })
}

/// 接线错误。
#[derive(Debug, thiserror::Error)]
pub enum WiringError {
    /// JSON 解析失败。
    #[error("routing config JSON parse: {0}")]
    JsonParse(String),
    /// Router 初始化失败（重复 tag / geoip 规则缺 loader 等）。
    #[error("router init: {0}")]
    RouterInit(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_adapter_satisfies_routing_router() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        let adapter = RouterAdapter::new(r);
        let ctx = DispatcherContext::new().with_target_domain("test.com");
        let result = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx);
        assert!(result.is_err(), "empty router should return NoClue");
    }

    #[test]
    fn router_adapter_satisfies_dispatch_router() {
        use xray_common::net::network::Network;
        let r = Router::empty(Arc::new(NotImplementedSelector));
        let adapter = RouterAdapter::new(r);
        let dest = Destination::new(
            Address::Domain("test.com".into()),
            Port::new(80),
            Network::TCP,
        );
        // empty router → pick_outbound_tag 返回 None
        assert!(adapter.pick_outbound_tag(&dest).is_none());
    }

    #[test]
    fn router_adapter_debug_lists_rules() {
        let r = Router::empty(Arc::new(NotImplementedSelector));
        let adapter = RouterAdapter::new(r);
        let s = format!("{adapter:?}");
        assert!(s.contains("RouterAdapter"));
    }

    #[test]
    fn build_adapter_from_json_domain_rule_routes() {
        let json = br#"{"rules":[{"outboundTag":"proxy","domain":["example.com"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        use xray_common::net::network::Network;
        let dest = Destination::new(
            Address::Domain("example.com".into()),
            Port::new(443),
            Network::TCP,
        );
        assert_eq!(adapter.pick_outbound_tag(&dest).as_deref(), Some("proxy"));
    }

    #[test]
    fn build_adapter_from_json_skips_rule_without_outbound_tag() {
        let json = br#"{"rules":[{"domain":["x.com"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        use xray_common::net::network::Network;
        let dest = Destination::new(
            Address::Domain("x.com".into()),
            Port::new(80),
            Network::TCP,
        );
        assert!(adapter.pick_outbound_tag(&dest).is_none());
    }

    #[test]
    fn build_adapter_invalid_json_errors() {
        let err = build_router_adapter_from_json(b"not json").unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)));
    }
}
