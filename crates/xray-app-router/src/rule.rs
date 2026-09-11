//! 路由规则：Rule + RoutingRuleExt::build_condition。
//!
//! 翻译自 `app/router/config.go` 中 `Rule` 与 `RoutingRule.BuildCondition`。

use std::sync::Arc;

use xray_common::net::network::Network;
use xray_common::net::port::{MemoryPortList, Port, PortRange};
use xray_geodata::loader::GeoDataLoader;
use xray_geodata::matcher::domain::{DomainRule as MatcherDomainRule, DomainType};
use xray_proto::xray::app::router::RoutingRule;
use xray_proto::xray::common::net::PortList;

use crate::balancing::Balancer;
use crate::condition::{Condition, ConditionChan, IpMatchAsType, PortMatchAsType, *};
use crate::error::RouterError;
use crate::webhook::WebhookNotifier;

/// 一条路由规则。
///
/// 对应 Go `Rule`。
pub struct Rule {
    /// 出站 tag（与 `balancer` 互斥）。
    pub tag: String,
    /// 规则 tag。
    pub rule_tag: String,
    /// 平衡器（与 `tag` 互斥）。
    pub balancer: Option<Arc<Balancer>>,
    /// 条件。空表示永真。
    pub condition: Option<Box<dyn Condition>>,
    /// Webhook 通知器。
    pub webhook: Option<Arc<WebhookNotifier>>,
}

impl Rule {
    /// 返回出站 tag：若有 balancer 则走 balancer.PickOutbound，否则返回 `tag`。
    ///
    /// 对应 Go `Rule.GetTag`。
    pub fn get_tag(&self) -> Result<String, RouterError> {
        if let Some(b) = &self.balancer {
            return b.pick_outbound();
        }
        Ok(self.tag.clone())
    }

    /// 带 ctx 的选路：balancer 走 `pick_outbound_with_key(ctx_derived_key)`，
    /// 支持 LeastLoadStrategy ConsistentHashing 等需要稳定 affinity 的策略。
    /// 无 ctx key 字段时退化为 `get_tag()`（等同未传 key）。
    pub fn get_tag_with_ctx(&self, ctx: &dyn crate::context::RoutingContext) -> Result<String, RouterError> {
        if let Some(b) = &self.balancer {
            let key = crate::router::ctx_hash_key(ctx);
            return b.pick_outbound_with_key(key);
        }
        Ok(self.tag.clone())
    }

    /// 对上下文应用规则。
    ///
    /// 返回 `Some(tag)` 表示命中；`None` 表示不命中。
    /// 命中时触发 webhook（fire-and-forget，错误忽略）。
    ///
    /// 对应 Go `Rule.Apply`。
    pub fn apply(&self, ctx: &dyn crate::context::RoutingContext) -> Option<String> {
        let hit = self
            .condition
            .as_ref()
            .map_or(true, |c| c.apply(ctx));
        if !hit {
            return None;
        }
        let tag = match self.get_tag_with_ctx(ctx) {
            Ok(t) => t,
            Err(_) => return None,
        };
        if let Some(wh) = &self.webhook {
            let ev = crate::webhook::WebhookEvent::hit(&tag, &self.rule_tag);
            let _ = wh.fire(&ev);
        }
        Some(tag)
    }
}

/// 将 proto `RoutingRule` 构造为 `Rule`。
///
/// 对应 Go `RoutingRule.BuildCondition` + 包装为 `Rule`。
pub fn build_rule(
    proto: &RoutingRule,
    balancers: &std::collections::HashMap<String, Arc<Balancer>>,
    geo_loader: Option<&GeoDataLoader>,
) -> Result<Rule, RouterError> {
    let cond = build_condition(proto, geo_loader)?;

    // 解析 target_tag oneof
    let (mut tag, mut balancer) = (String::new(), None);
    if let Some(t) = proto.target_tag.as_ref() {
        use xray_proto::xray::app::router::routing_rule::TargetTag as TT;
        match t {
            TT::Tag(s) => tag = s.clone(),
            TT::BalancingTag(s) => {
                balancer = Some(
                    balancers
                        .get(s)
                        .cloned()
                        .ok_or_else(|| RouterError::BalancerNotFound(s.clone()))?,
                );
            }
        }
    }

    // 构建 webhook（可选）
    let webhook = proto.webhook.as_ref().map(|c| Arc::new(WebhookNotifier::new(c)));

    Ok(Rule {
        tag,
        rule_tag: proto.rule_tag.clone(),
        balancer,
        condition: Some(cond),
        webhook,
    })
}

/// 从 proto `RoutingRule` 构造匹配器链。
///
/// 对应 Go `RoutingRule.BuildCondition`。
pub fn build_condition(
    proto: &RoutingRule,
    geo_loader: Option<&GeoDataLoader>,
) -> Result<Box<dyn Condition>, RouterError> {
    let mut chan = ConditionChan::new();
    if !proto.domain.is_empty() {
        // hn4i：parse_proto_domain_rules 现可返回 Err（fail-closed）。
        let rules = parse_proto_domain_rules(&proto.domain, geo_loader)?;
        if !rules.is_empty() {
            chan.add(Box::new(DomainMatcherCondition::new(rules)?));
        }
    }

    // Target IP
    if !proto.ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.ip, geo_loader)?;
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Target)?));
    }

    // Source IP
    if !proto.source_ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.source_ip, geo_loader)?;
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Source)?));
    }

    // Local IP
    if !proto.local_ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.local_ip, geo_loader)?;
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Local)?));
    }


    // Ports
    if let Some(pl) = proto.port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(to_mem_port_list(pl), PortMatchAsType::Target)));
    }
    if let Some(pl) = proto.source_port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(to_mem_port_list(pl), PortMatchAsType::Source)));
    }
    if let Some(pl) = proto.local_port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(to_mem_port_list(pl), PortMatchAsType::Local)));
    }
    if let Some(pl) = proto.vless_route_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(to_mem_port_list(pl), PortMatchAsType::VlessRoute)));
    }

    // Networks
    if !proto.networks.is_empty() {
        let nets = proto.networks.iter().filter_map(|&v| proto_network_to_native(v)).collect::<Vec<_>>();
        if !nets.is_empty() {
            chan.add(Box::new(NetworkMatcherCondition::new(&nets)));
        }
    }

    // User
    if !proto.user_email.is_empty() {
        chan.add(Box::new(UserMatcherCondition::new(proto.user_email.clone())));
    }

    // Inbound tag
    if !proto.inbound_tag.is_empty() {
        chan.add(Box::new(InboundTagMatcherCondition::new(proto.inbound_tag.clone())));
    }

    // Protocol
    if !proto.protocol.is_empty() {
        chan.add(Box::new(ProtocolMatcherCondition::new(proto.protocol.clone())));
    }

    // Attributes
    if !proto.attributes.is_empty() {
        chan.add(Box::new(AttributeMatcherCondition::new(proto.attributes.clone()).map_err(|e| {
            RouterError::GeodataBuild(e.to_string())
        })?));
    }

    // Process
    if !proto.process.is_empty() {
        chan.add(Box::new(ProcessNameMatcherCondition::new(proto.process.clone())));
    }

    if chan.is_empty() {
        return Err(RouterError::EmptyRule);
    }
    Ok(Box::new(chan))
}

/// 把 proto `PortList` 转为 `MemoryPortList`。
fn to_mem_port_list(pl: &PortList) -> MemoryPortList {
    let ranges: Vec<PortRange> = pl
        .range
        .iter()
        .map(|r| {
            PortRange::new(Port::new(r.from as u16), Port::new(r.to as u16))
        })
        .collect();
    MemoryPortList::new(ranges)
}

/// proto Network (i32) → 原生 `Network`。
///
/// Proto: Unknown=0, TCP=2, UDP=3, UNIX=4。
fn proto_network_to_native(v: i32) -> Option<Network> {
    match v {
        2 => Some(Network::TCP),
        3 => Some(Network::UDP),
        4 => Some(Network::Unix),
        _ => None,
    }
}

/// proto Domain.Type (i32) → matcher DomainType。
///
/// Proto: Substr=0, Regex=1, Domain=2, Full=3。
/// Matcher: Full=0, Domain=1, Substr=2, Regex=3。
fn proto_domain_type_to_matcher(v: i32) -> Option<DomainType> {
    match v {
        0 => Some(DomainType::Substr),
        1 => Some(DomainType::Regex),
        2 => Some(DomainType::Domain),
        3 => Some(DomainType::Full),
        _ => None,
    }
}

/**
 * 将 proto DomainRule 列表解析为 matcher DomainRule 列表。
 *
 * - `custom` 变体：直接转换。
 * - `geosite` 变体：调用 geo_loader.load_site 加载文件中的 GeoSite 条目；
 *   loader 缺失时 warn 并 skip。
 */
fn parse_proto_domain_rules(
    proto_rules: &[xray_proto::xray::common::geodata::DomainRule],
    geo_loader: Option<&GeoDataLoader>,
) -> Result<Vec<MatcherDomainRule>, RouterError> {
    use xray_proto::xray::common::geodata::domain_rule::Value as ProtoDV;
    let mut out: Vec<MatcherDomainRule> = Vec::new();
    for r in proto_rules {
        let Some(value) = r.value.as_ref() else { continue };
        match value {
            ProtoDV::Custom(d) => {
                let Some(dt) = proto_domain_type_to_matcher(d.r#type) else { continue };
                let idx = (out.len() + 1) as u32;
                out.push(MatcherDomainRule::new(dt, d.value.clone(), idx));
            }
            ProtoDV::Geosite(geosite_rule) => {
                let Some(loader) = geo_loader else {
                    // hn4i：fail-closed。无 loader → 配置错误，整条规则不能启用。
                    return Err(RouterError::GeodataBuild(format!(
                        "geosite rule present but no geo_loader configured: file={} code={}",
                        geosite_rule.file, geosite_rule.code
                    )));
                };
                match load_geosite_to_matcher_rules(geosite_rule, loader) {
                    Ok(rules) => out.extend(rules),
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(out)
}

/// 从 dat 文件加载 GeoSite 条目并转换为 matcher DomainRule 列表。
///
/// - `file` 为空时默认 `geosite.dat`。
/// - `code` 转大写（与 dat 文件中存储格式一致）。
/// - `attrs` 非空时按 `@` 分隔的属性 key 过滤 domain。
fn load_geosite_to_matcher_rules(
    geosite_rule: &xray_proto::xray::common::geodata::GeoSiteRule,
    loader: &GeoDataLoader,
) -> Result<Vec<MatcherDomainRule>, RouterError> {
    let file = if geosite_rule.file.is_empty() {
        "geosite.dat"
    } else {
        geosite_rule.file.as_str()
    };
    let code = geosite_rule.code.to_uppercase();
    let site = if geosite_rule.attrs.is_empty() {
        loader
            .load_site(file, &code)
            .map_err(|e| RouterError::GeodataBuild(format!("load geosite {file}:{code}: {e}")))?
    } else {
        loader
            .load_site_with_attrs(file, &code, &geosite_rule.attrs)
            .map_err(|e| RouterError::GeodataBuild(format!("load geosite {file}:{code}: {e}")))?
    };

    Ok(site
        .domain
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let dt = proto_domain_type_to_matcher(d.r#type).unwrap_or(DomainType::Full);
            MatcherDomainRule::new(dt, d.value.clone(), (i + 1) as u32)
        })
        .collect())
}

/// 将 proto `IpRule` 列表（`xray.common.geodata`）转换为 xray-geodata 的 `IpRule`（`xray.geodata`）。
///
/// 两个 crate 各自构建 proto，生成同名不同类型。此函数字段级复制。
/// - `Custom(CidrRule)` 变体：直接转换。
/// - `Geoip(GeoIPRule)` 变体：调用 geo_loader.load_ip 加载文件中的 GeoIP 条目，
///   展开 CIDR 列表为多个 Custom 变体；loader 缺失时 warn 并 skip。
fn convert_proto_ip_rules(
    proto_rules: &[xray_proto::xray::common::geodata::IpRule],
    geo_loader: Option<&GeoDataLoader>,
) -> Result<Vec<xray_geodata::pb::IpRule>, RouterError> {
    use xray_proto::xray::common::geodata::ip_rule::Value as ProtoIV;
    let mut out = Vec::with_capacity(proto_rules.len());
    for r in proto_rules {
        let Some(value) = r.value.as_ref() else { continue };
        match value {
            ProtoIV::Custom(c) => {
                let cidr = c.cidr.as_ref().map(|cc| xray_geodata::pb::Cidr {
                    ip: cc.ip.clone(),
                    prefix: cc.prefix,
                });
                out.push(xray_geodata::pb::IpRule {
                    value: Some(xray_geodata::pb::ip_rule::Value::Custom(
                        xray_geodata::pb::CidrRule {
                            cidr,
                            reverse_match: c.reverse_match,
                        },
                    )),
                });
            }
            ProtoIV::Geoip(geoip_rule) => {
                let Some(loader) = geo_loader else {
                    // hn4i：fail-closed（同 geosite）。无 loader 必须报错。
                    return Err(RouterError::GeodataBuild(format!(
                        "geoip rule present but no geo_loader configured: file={} code={}",
                        geoip_rule.file, geoip_rule.code
                    )));
                };
                match load_geoip_to_matcher_rules(geoip_rule, loader) {
                    Ok(rules) => out.extend(rules),
                    Err(e) => {
                        // hn4i：fail-closed（同 geosite）。
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// 从 dat 文件加载 GeoIP 条目并展开为多个 Custom IpRule。
///
/// - `file` 为空时默认 `geoip.dat`。
/// - `code` 转大写。
/// - 反向匹配 = rule.reverse_match XOR geoip.reverse_match（与 Go 行为一致）。
fn load_geoip_to_matcher_rules(
    geoip_rule: &xray_proto::xray::common::geodata::GeoIpRule,
    loader: &GeoDataLoader,
) -> Result<Vec<xray_geodata::pb::IpRule>, RouterError> {
    let file = if geoip_rule.file.is_empty() {
        "geoip.dat"
    } else {
        geoip_rule.file.as_str()
    };
    let code = geoip_rule.code.to_uppercase();
    let geoip = loader
        .load_ip(file, &code)
        .map_err(|e| RouterError::GeodataBuild(format!("load geoip {file}:{code}: {e}")))?;

    let reverse = geoip_rule.reverse_match ^ geoip.reverse_match;
    Ok(geoip
        .cidr
        .into_iter()
        .map(|cidr| xray_geodata::pb::IpRule {
            value: Some(xray_geodata::pb::ip_rule::Value::Custom(
                xray_geodata::pb::CidrRule {
                    cidr: Some(xray_geodata::pb::Cidr {
                        ip: cidr.ip,
                        prefix: cidr.prefix,
                    }),
                    reverse_match: reverse,
                },
            )),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RoutingData;
    use xray_proto::xray::app::router::RoutingRule;
    use xray_proto::xray::common::geodata::{Domain, DomainRule};
    use xray_proto::xray::common::geodata::domain::Type as DomainType;

    fn full_domain(value: &str) -> DomainRule {
        DomainRule {
            value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(Domain {
                r#type: DomainType::Full as i32,
                value: value.into(),
                attribute: vec![],
            })),
        }
    }

    #[test]
    fn test_build_condition_empty_rule_errors() {
        let proto = RoutingRule::default();
        let r = build_condition(&proto, None);
        assert!(matches!(r, Err(RouterError::EmptyRule)));
    }

    #[test]
    fn test_build_condition_domain_matcher() {
        let mut proto = RoutingRule::default();
        proto.domain = vec![full_domain("example.com")];
        let _ = build_condition(&proto, None).unwrap();
        let cond = build_condition(&proto, None).unwrap();
        let hit = RoutingData::new().with_target_domain("example.com");
        let miss = RoutingData::new().with_target_domain("other.io");
        assert!(cond.apply(&hit));
        assert!(!cond.apply(&miss));
    }

    #[test]
    fn test_build_condition_inbound_tag() {
        let mut proto = RoutingRule::default();
        proto.inbound_tag = vec!["in1".into()];
        let cond = build_condition(&proto, None).unwrap();
        let hit = RoutingData::new().with_inbound_tag("in1");
        let miss = RoutingData::new().with_inbound_tag("in2");
        assert!(cond.apply(&hit));
        assert!(!cond.apply(&miss));
    }

    #[test]
    fn test_proto_network_to_native() {
        assert_eq!(proto_network_to_native(0), None);
        assert_eq!(proto_network_to_native(2), Some(Network::TCP));
        assert_eq!(proto_network_to_native(3), Some(Network::UDP));
        assert_eq!(proto_network_to_native(4), Some(Network::Unix));
    }

    #[test]
    fn test_proto_domain_type_mapping() {
        use xray_geodata::matcher::domain::DomainType as MDT;
        assert_eq!(proto_domain_type_to_matcher(0), Some(MDT::Substr));
        assert_eq!(proto_domain_type_to_matcher(1), Some(MDT::Regex));
        assert_eq!(proto_domain_type_to_matcher(2), Some(MDT::Domain));
        assert_eq!(proto_domain_type_to_matcher(3), Some(MDT::Full));
    }

    #[test]
    fn test_to_mem_port_list() {
        use xray_proto::xray::common::net::{PortList as PList, PortRange as PRange};
        let pl = PList {
            range: vec![PRange { from: 80, to: 80 }, PRange { from: 443, to: 445 }],
        };
        let mem = to_mem_port_list(&pl);
        assert!(mem.contains(Port::new(80)));
        assert!(mem.contains(Port::new(444)));
        assert!(!mem.contains(Port::new(81)));
    }
}
