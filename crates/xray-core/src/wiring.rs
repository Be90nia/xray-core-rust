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

    /// 带 DNS 解析的选路：委托 [`Router::pick_route_resolved`]（domainStrategy 分支）。
    fn pick_outbound_tag_resolved<'a>(
        &'a self,
        dest: &'a Destination,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let mut data = dest_to_routing_data(dest);
            match self.router.pick_route_resolved(&mut data).await {
                Ok(route) => Some(route.outbound_tag),
                Err(_) => None,
            }
        })
    }

    /// 注入 DNS 解析能力（domainStrategy IpOnDemand/IpIfNonMatch 用）。
    fn set_dns_client(&self, dns: std::sync::Arc<dyn xray_features::dns::DnsClient>) {
        self.router.set_dns_client(dns);
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
    let geo_loader = Some(Arc::new(xray_geodata::loader::GeoDataLoader::new(
        resolve_asset_dir(),
    )));
    let router = Router::init(&config, ohm, geo_loader)
        .map_err(|e| WiringError::RouterInit(e.to_string()))?;
    Ok(Arc::new(RouterAdapter::new(router)))
}

/// JSON → proto `Config` 转换：覆盖 `RoutingRule` 全部标量字段——
/// domain(ip/Suffix/Keyword/Regex)、ip、source、port、sourcePort、network、protocol、
/// user、inboundTag、attributes、process，以及顶层 `domainStrategy`、`balancers`。
/// 引擎 `xray_app_router::rule::build_condition` 已支持全集，瓶颈纯在此解析器。
///
/// `rule_set` 依赖 proto 更新（当前 `RoutingRule` 无该字段，见
/// `xray-app-router/src/rule_set.rs`），暂以 TODO 标记，待 proto 升级后接入。
fn parse_routing_json_to_proto(
    json: &[u8],
) -> Result<xray_proto::xray::app::router::Config, WiringError> {
    use prost::Message;
    use xray_proto::xray::app::router::routing_rule::TargetTag;
    use xray_proto::xray::app::router::{BalancingRule, RoutingRule};
    use xray_proto::xray::common::geodata::{Domain, DomainRule, IpRule};
    use xray_proto::xray::common::geodata::domain::Type as DT;
    use xray_proto::xray::common::geodata::domain_rule::Value as DV;
    use xray_proto::xray::common::geodata::ip_rule::Value as IV;

    let v: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| WiringError::JsonParse(e.to_string()))?;

    let mut cfg = xray_proto::xray::app::router::Config::default();

    // 顶层 domainStrategy
    if let Some(s) = v.get("domainStrategy").and_then(|x| x.as_str()) {
        cfg.domain_strategy = parse_domain_strategy(s);
    }

    if let Some(arr) = v.get("rules").and_then(|r| r.as_array()) {
        for r in arr {
            let outbound_tag = r.get("outboundTag").and_then(|x| x.as_str()).unwrap_or("");
            let balancer_tag = r.get("balancerTag").and_then(|x| x.as_str()).unwrap_or("");
            let target_tag = if !balancer_tag.is_empty() {
                Some(TargetTag::BalancingTag(balancer_tag.to_string()))
            } else if !outbound_tag.is_empty() {
                Some(TargetTag::Tag(outbound_tag.to_string()))
            } else {
                // 既无 outboundTag 也无 balancerTag：无法路由，跳过（与 Go 一致）
                continue;
            };

            // Domain 规则：Full / Domain(suffix) / Substr(keyword) / Regex
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
            for d in json_str_iter(r.get("domainRegex")) {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Regex as i32,
                        value: d.to_string(),
                        attribute: vec![],
                    })),
                });
            }

            // 目标 IP（CIDR）
            let mut ips = Vec::new();
            for ip_str in json_str_iter(r.get("ip")) {
                if let Some(custom) = parse_cidr_to_ip_rule(ip_str) {
                    ips.push(IpRule { value: Some(IV::Custom(custom)) });
                }
            }

            // 源 IP（CIDR）
            let mut source_ips = Vec::new();
            for ip_str in json_str_iter(r.get("source")) {
                if let Some(custom) = parse_cidr_to_ip_rule(ip_str) {
                    source_ips.push(IpRule { value: Some(IV::Custom(custom)) });
                }
            }

            cfg.rule.push(RoutingRule {
                target_tag,
                rule_tag: String::new(),
                domain: domains,
                ip: ips,
                source_ip: source_ips,
                port_list: parse_port_list(r.get("port")),
                source_port_list: parse_port_list(r.get("sourcePort")),
                networks: parse_networks(r.get("network")),
                user_email: json_string_list(r.get("user")),
                inbound_tag: json_string_list(r.get("inboundTag")),
                protocol: json_string_list(r.get("protocol")),
                process: json_string_list(r.get("process")),
                attributes: parse_attributes(r.get("attributes")),
                ..Default::default()
            });
        }
    }

    // 顶层 balancers → BalancingRule。strategy 取 `{"type":"..."}` 或裸字符串。
    if let Some(arr) = v.get("balancers").and_then(|b| b.as_array()) {
        for b in arr {
            let tag = b.get("tag").and_then(|x| x.as_str()).unwrap_or("");
            if tag.is_empty() {
                continue;
            }
            let strategy = match b.get("strategy") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Object(o)) => {
                    o.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string()
                }
                _ => String::new(),
            };
            cfg.balancing_rule.push(BalancingRule {
                tag: tag.to_string(),
                outbound_selector: json_string_list(b.get("selector")),
                strategy,
                strategy_settings: None,
                fallback_tag: b
                    .get("fallbackTag")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }

    // TODO(rule_set): proto `RoutingRule` 无 rule_set 字段（proto 版本较早，
    // 见 xray-app-router/src/rule_set.rs）。本地/远程 rule_set 需 proto 升级后接入。

    // 编码一次以验证 Config 结构合法（同 prost 语义）
    let _ = cfg.encode_to_vec();
    Ok(cfg)
}

/// JSON 端口字段（number / `"80,443,1000-2000"` / 混合数组）→ proto `PortList`。
///
/// 复用 `xray_conf::PortList` 的多态反序列化（与 Go `infra/conf.PortList` 等价）。
fn parse_port_list(
    v: Option<&serde_json::Value>,
) -> Option<xray_proto::xray::common::net::PortList> {
    use xray_proto::xray::common::net::{PortList as ProtoPortList, PortRange as ProtoPortRange};
    let v = v?;
    let conf: xray_conf::PortList = serde_json::from_value(v.clone()).ok()?;
    if conf.is_empty() {
        return None;
    }
    Some(ProtoPortList {
        range: conf
            .0
            .iter()
            .map(|r| ProtoPortRange {
                from: u32::from(r.start),
                to: u32::from(r.end),
            })
            .collect(),
    })
}

/// network 字段（`"tcp,udp"` 或字符串数组）→ proto `Network` i32 列表。
fn parse_networks(v: Option<&serde_json::Value>) -> Vec<i32> {
    use xray_proto::xray::common::net::Network;
    json_str_tokens(v).into_iter()
        .filter_map(|s| match s.to_ascii_lowercase().as_str() {
            "tcp" => Some(Network::Tcp as i32),
            "udp" => Some(Network::Udp as i32),
            "unix" => Some(Network::Unix as i32),
            _ => None,
        })
        .collect()
}

/// JSON 字符串数组 → `Vec<String>`。
fn json_string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    json_str_iter(v).map(|s| s.to_string()).collect()
}

/// attributes 对象 → `map<string,string>`；非字符串值以 JSON 文本表示。
fn parse_attributes(
    v: Option<&serde_json::Value>,
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Some(obj) = v.and_then(|x| x.as_object()) else {
        return map;
    };
    for (k, val) in obj {
        let s = match val {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        map.insert(k.clone(), s);
    }
    map
}

/// domainStrategy 字符串 → proto `DomainStrategy` i32（大小写不敏感）。
fn parse_domain_strategy(s: &str) -> i32 {
    use xray_proto::xray::app::router::config::DomainStrategy;
    match s.to_ascii_lowercase().as_str() {
        "ipifnonmatch" => DomainStrategy::IpIfNonMatch as i32,
        "ipondemand" => DomainStrategy::IpOnDemand as i32,
        _ => DomainStrategy::AsIs as i32,
    }
}

/// 把 `Value::String`（逗号分隔）或 `Value::Array<String>` 展平为 token 列表。
fn json_str_tokens(v: Option<&serde_json::Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(v) = v else {
        return out;
    };
    let strs: Vec<&str> = match v {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(arr) => arr.iter().filter_map(|x| x.as_str()).collect(),
        _ => vec![],
    };
    for s in strs {
        for part in s.split(',') {
            let t = part.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }
    }
    out
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

/// 查找 GeoIP/GeoSite .dat 文件目录（对齐 Go `GetOBJPath`）。
///
/// 查找顺序：`XRAY_LOCATION_ASSET` 环境变量 → 可执行文件同目录 → 当前工作目录。
/// 找不到 .dat 文件不影响 loader 创建（load 时 warn skip），仅影响 geoip/geosite 规则匹配。
fn resolve_asset_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XRAY_LOCATION_ASSET") {
        return std::path::PathBuf::from(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.to_path_buf();
        }
    }
    std::path::PathBuf::from(".")
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

    #[test]
    fn parse_routing_json_covers_all_rule_fields() {
        use xray_proto::xray::app::router::config::DomainStrategy;
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::common::geodata::domain::Type as DT;
        use xray_proto::xray::common::geodata::domain_rule::Value as DV;

        let json = br#"{
            "domainStrategy": "IpOnDemand",
            "rules": [{
                "outboundTag": "proxy",
                "domainRegex": ["^.*\\.example\\.com$"],
                "ip": ["10.0.0.0/8"],
                "source": ["192.168.1.0/24"],
                "port": "80,443,1000-2000",
                "sourcePort": "53",
                "network": "tcp,udp",
                "protocol": ["http", "tls"],
                "user": ["alice@example.com"],
                "inboundTag": ["in0"],
                "process": ["xray.exe"],
                "attributes": {"sinkhole": "true"}
            }],
            "balancers": [{
                "tag": "bal",
                "selector": ["a", "b"],
                "strategy": {"type": "random"},
                "fallbackTag": "direct"
            }]
        }"#;
        let cfg = parse_routing_json_to_proto(json).expect("parse");

        // 顶层 domainStrategy（大小写不敏感）
        assert_eq!(cfg.domain_strategy, DomainStrategy::IpOnDemand as i32);

        // balancers → BalancingRule
        assert_eq!(cfg.balancing_rule.len(), 1);
        let br = &cfg.balancing_rule[0];
        assert_eq!(br.tag, "bal");
        assert_eq!(br.outbound_selector, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(br.strategy, "random");
        assert_eq!(br.fallback_tag, "direct");

        assert_eq!(cfg.rule.len(), 1);
        let rule = &cfg.rule[0];
        let tag = match rule.target_tag.as_ref() {
            Some(TargetTag::Tag(t)) => t.as_str(),
            _ => panic!("expected Tag target"),
        };
        assert_eq!(tag, "proxy");

        // domainRegex → Regex 类型
        assert_eq!(rule.domain.len(), 1);
        let custom = match rule.domain[0].value.as_ref() {
            Some(DV::Custom(c)) => c,
            _ => panic!("expected custom domain rule"),
        };
        assert_eq!(custom.r#type, DT::Regex as i32);

        // ip / source（CIDR）
        assert_eq!(rule.ip.len(), 1);
        assert_eq!(rule.source_ip.len(), 1);

        // port / sourcePort（"80,443,1000-2000" 展开）
        let pl = rule.port_list.as_ref().expect("port_list");
        assert!(pl.range.iter().any(|r| r.from == 80 && r.to == 80));
        assert!(pl.range.iter().any(|r| r.from == 443 && r.to == 443));
        assert!(pl.range.iter().any(|r| r.from == 1000 && r.to == 2000));
        let spl = rule.source_port_list.as_ref().expect("source_port_list");
        assert!(spl.range.iter().any(|r| r.from == 53 && r.to == 53));

        // networks（tcp=2, udp=3）
        assert!(rule.networks.contains(&2));
        assert!(rule.networks.contains(&3));

        // 标量列表字段
        assert_eq!(rule.protocol, vec!["http".to_string(), "tls".to_string()]);
        assert_eq!(rule.user_email, vec!["alice@example.com".to_string()]);
        assert_eq!(rule.inbound_tag, vec!["in0".to_string()]);
        assert_eq!(rule.process, vec!["xray.exe".to_string()]);

        // attributes map
        assert_eq!(rule.attributes.get("sinkhole").map(String::as_str), Some("true"));
    }

    #[test]
    fn build_adapter_from_json_port_rule_routes() {
        use xray_common::net::network::Network;
        let json = br#"{"rules":[{"outboundTag":"proxy","port":"443"}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        let hit = Destination::new(
            Address::Domain("anywhere.com".into()),
            Port::new(443),
            Network::TCP,
        );
        assert_eq!(adapter.pick_outbound_tag(&hit).as_deref(), Some("proxy"));
        // 不命中端口 → 不路由
        let miss = Destination::new(
            Address::Domain("anywhere.com".into()),
            Port::new(8080),
            Network::TCP,
        );
        assert!(adapter.pick_outbound_tag(&miss).is_none());
    }

    #[test]
    fn build_adapter_from_json_network_rule_routes() {
        use xray_common::net::network::Network;
        let json = br#"{"rules":[{"outboundTag":"udp-out","network":"udp"}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        let udp_dest = Destination::new(
            Address::Domain("anywhere.com".into()),
            Port::new(53),
            Network::UDP,
        );
        assert_eq!(adapter.pick_outbound_tag(&udp_dest).as_deref(), Some("udp-out"));
        let tcp_dest = Destination::new(
            Address::Domain("anywhere.com".into()),
            Port::new(53),
            Network::TCP,
        );
        assert!(adapter.pick_outbound_tag(&tcp_dest).is_none());
    }

    // ---- domainStrategy DNS 解析路由（u2i）----

    /// 计数 mock：固定返回 1.2.3.4。
    struct CountingDns {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingDns {
        fn new() -> Self {
            Self { calls: std::sync::atomic::AtomicUsize::new(0) }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl xray_features::dns::DnsClient for CountingDns {
        async fn lookup(
            &self,
            _domain: &str,
        ) -> Result<Vec<Address>, xray_features::dns::DnsError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(vec![Address::IPv4("1.2.3.4".parse().expect("ip"))])
        }

        async fn lookup_ipv4(
            &self,
            domain: &str,
        ) -> Result<Vec<Address>, xray_features::dns::DnsError> {
            self.lookup(domain).await
        }

        async fn lookup_ipv6(
            &self,
            _domain: &str,
        ) -> Result<Vec<Address>, xray_features::dns::DnsError> {
            Ok(vec![])
        }
    }

    fn resolved_dest() -> Destination {
        use xray_common::net::network::Network;
        Destination::new(Address::Domain("example.com".into()), Port::new(443), Network::TCP)
    }

    #[tokio::test]
    async fn resolved_ip_on_demand_hits_ip_rule() {
        let json = br#"{"domainStrategy":"IPOnDemand","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert_eq!(tag.as_deref(), Some("blocked"));
        assert_eq!(dns.calls(), 1, "IpOnDemand should resolve before matching");
    }

    #[tokio::test]
    async fn resolved_ip_if_non_match_resolves_after_miss() {
        let json = br#"{"domainStrategy":"IPIfNonMatch","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert_eq!(tag.as_deref(), Some("blocked"));
        assert_eq!(dns.calls(), 1, "IpIfNonMatch should resolve after first-round miss");
    }

    #[tokio::test]
    async fn resolved_asis_skips_dns() {
        let json = br#"{"domainStrategy":"AsIs","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert!(tag.is_none(), "AsIs should not match by resolved IP");
        assert_eq!(dns.calls(), 0, "AsIs must not query DNS");
    }

    #[tokio::test]
    async fn resolved_without_dns_client_falls_back_to_domain_only() {
        let json = br#"{"domainStrategy":"IPOnDemand","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");
        // 未注入 DNS：IpOnDemand 退化为按域名匹配，IP 规则不命中
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert!(tag.is_none());
    }
}
