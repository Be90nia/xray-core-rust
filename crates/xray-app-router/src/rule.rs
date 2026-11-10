//! 路由规则：Rule + RoutingRuleExt::build_condition。
//!
//! 翻译自 `app/router/config.go` 中 `Rule` 与 `RoutingRule.BuildCondition`。

use std::sync::Arc;

use xray_common::net::{
    network::Network,
    port::{MemoryPortList, Port, PortRange},
};
use xray_geodata::loader::GeoDataLoader;
use xray_proto::xray::{app::router::RoutingRule, common::net::PortList};

use crate::{
    balancing::Balancer,
    condition::{Condition, ConditionChan, IpMatchAsType, PortMatchAsType, *},
    error::RouterError,
    webhook::WebhookNotifier,
};

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
    pub fn get_tag_with_ctx(
        &self,
        ctx: &dyn crate::context::RoutingContext,
    ) -> Result<String, RouterError> {
        if let Some(b) = &self.balancer {
            let key = crate::router::ctx_hash_key(ctx);
            return b.pick_outbound_with_key(key);
        }
        Ok(self.tag.clone())
    }

    /// 对上下文应用规则。
    ///
    /// - `Ok(Some(tag))` 命中；`Ok(None)` 不命中；`Err` 命中但选路失败。
    ///
    /// 对应 Go `Rule.Apply`（只测条件）+ `Router.PickRoute` 的
    /// `tag, err := rule.GetTag(); if err != nil { return nil, err }`：
    /// **balancer 失败不是「本条规则不命中」**，必须上抛给调用方走默认出站
    /// 并留可见日志；旧实现把它当成 `None` 继续试下一条规则，最坏静默落到
    /// `direct`（以为走了代理，实际直连）。
    ///
    /// Webhook 不在此触发（Go 在 `PickRoute` 里拿 tag 之后才 `Fire`）——见
    /// [`Router::pick_route`](crate::router::Router::pick_route)。
    pub fn apply(
        &self,
        ctx: &dyn crate::context::RoutingContext,
    ) -> Result<Option<String>, RouterError> {
        let hit = self.condition.as_ref().is_none_or(|c| c.apply(ctx));
        if !hit {
            return Ok(None);
        }
        Ok(Some(self.get_tag_with_ctx(ctx)?))
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
    build_rule_with_pool(proto, balancers, geo_loader, None)
}

/// [`build_rule`] 的互喂变体（xray-frame 任务书 P3-5）：`pool` 传 `Some` 时
/// domain matcher 构建在 [`RouterBuildPool`] worker 内执行；`None` 时与
/// [`build_rule`] 完全同路。匹配语义零变化。
pub fn build_rule_with_pool(
    proto: &RoutingRule,
    balancers: &std::collections::HashMap<String, Arc<Balancer>>,
    geo_loader: Option<&GeoDataLoader>,
    pool: Option<&RouterBuildPool>,
) -> Result<Rule, RouterError> {
    let cond = build_condition_with_pool(proto, geo_loader, pool)?;

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
            },
        }
    }

    // 构建 webhook（可选）
    let webhook = proto.webhook.as_ref().map(|c| Arc::new(WebhookNotifier::new(c)));

    Ok(Rule { tag, rule_tag: proto.rule_tag.clone(), balancer, condition: Some(cond), webhook })
}

/// 从 proto `RoutingRule` 构造匹配器链。
///
/// 对应 Go `RoutingRule.BuildCondition`。
pub fn build_condition(
    proto: &RoutingRule,
    geo_loader: Option<&GeoDataLoader>,
) -> Result<Box<dyn Condition>, RouterError> {
    build_condition_with_pool(proto, geo_loader, None)
}

/// [`build_condition`] 的互喂变体（xray-frame 任务书 P3-5）：`pool` 传 `Some`
/// 时 domain matcher 构建走 [`RouterBuildPool`]（构建才是 CPU 密集面；
/// `apply()` 数据面热路径零改动——契约坑约束 12）。`None` 时与
/// [`build_condition`] 完全同路。
pub fn build_condition_with_pool(
    proto: &RoutingRule,
    geo_loader: Option<&GeoDataLoader>,
    pool: Option<&RouterBuildPool>,
) -> Result<Box<dyn Condition>, RouterError> {
    let mut chan = ConditionChan::new();

    // LocalOS（Go a12801c1：BuildCondition 首个条件，运行时 OS 恒定 → 构造期解析）
    if !proto.local_os.is_empty() {
        chan.add(Box::new(LocalOsMatcherCondition::new(&proto.local_os)));
    }
    if !proto.domain.is_empty() {
        // 域名规则交给域名注册表（Go `DomainReg.BuildDomainMatcher`，bd ochlx）：
        // `geosite:` 的资产读取与展开只在注册表一处发生，重建沿用同一目录
        // ⇒ 热更直接生效。资产/代号缺失 ⇒ 构造期 Err（拒启，禁静默空集）。
        let datadir = geo_loader.map(GeoDataLoader::datadir);
        let cond = match pool {
            Some(p) => DomainMatcherCondition::new_pooled(
                p,
                proto.domain.clone(),
                datadir.map(std::path::Path::to_path_buf),
            )?,
            None => DomainMatcherCondition::new(&proto.domain, datadir)?,
        };
        chan.add(Box::new(cond));
    }

    // Target IP
    if !proto.ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.ip);
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Target)?));
    }

    // Source IP
    if !proto.source_ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.source_ip);
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Source)?));
    }

    // Local IP
    if !proto.local_ip.is_empty() {
        let rules = convert_proto_ip_rules(&proto.local_ip);
        chan.add(Box::new(IPMatcherCondition::new(rules, IpMatchAsType::Local)?));
    }

    // Ports
    if let Some(pl) = proto.port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(
            to_mem_port_list(pl),
            PortMatchAsType::Target,
        )));
    }
    if let Some(pl) = proto.source_port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(
            to_mem_port_list(pl),
            PortMatchAsType::Source,
        )));
    }
    if let Some(pl) = proto.local_port_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(to_mem_port_list(pl), PortMatchAsType::Local)));
    }
    if let Some(pl) = proto.vless_route_list.as_ref() {
        chan.add(Box::new(PortMatcherCondition::new(
            to_mem_port_list(pl),
            PortMatchAsType::VlessRoute,
        )));
    }

    // Networks
    if !proto.networks.is_empty() {
        let nets =
            proto.networks.iter().filter_map(|&v| proto_network_to_native(v)).collect::<Vec<_>>();
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
        chan.add(Box::new(
            AttributeMatcherCondition::new(proto.attributes.clone())
                .map_err(|e| RouterError::GeodataBuild(e.to_string()))?,
        ));
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
        .map(|r| PortRange::new(Port::new(r.from as u16), Port::new(r.to as u16)))
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

/// 将 proto `IpRule` 列表（`xray.common.geodata`）转换为 xray-geodata 的
/// `IpRule`（`xray.geodata`）。
///
/// 两个 crate 各自构建 proto，生成同名不同类型。此函数**只做变体复制**：
/// - `Custom(CidrRule)` / `Geoip(GeoIPRule)` 逐字段搬运，`geoip` 保持 tag 形态。
///
/// 资产解析不在这里做——`geoip` 由 [`IPMatcherCondition::new`] 登记进
/// `IP_REG` 后在**构造期**查表（Go `condition.go:87` `IPReg.BuildIPMatcher`）：
/// 提前展开成 CIDR 会丢 tag 身份，热更（`IpRegistry::reload`）无法就地重建。
/// 反向匹配只取规则侧 `reverse_match`（Go 从不读资产里的 `GeoIP.ReverseMatch`）。
fn convert_proto_ip_rules(
    proto_rules: &[xray_proto::xray::common::geodata::IpRule],
) -> Vec<xray_geodata::pb::IpRule> {
    use xray_proto::xray::common::geodata::ip_rule::Value as ProtoIV;
    let mut out = Vec::with_capacity(proto_rules.len());
    for r in proto_rules {
        let Some(value) = r.value.as_ref() else { continue };
        let value = match value {
            ProtoIV::Custom(c) => {
                xray_geodata::pb::ip_rule::Value::Custom(xray_geodata::pb::CidrRule {
                    cidr: c
                        .cidr
                        .as_ref()
                        .map(|cc| xray_geodata::pb::Cidr { ip: cc.ip.clone(), prefix: cc.prefix }),
                    reverse_match: c.reverse_match,
                })
            },
            ProtoIV::Geoip(g) => {
                xray_geodata::pb::ip_rule::Value::Geoip(xray_geodata::pb::GeoIpRule {
                    file: g.file.clone(),
                    code: g.code.clone(),
                    reverse_match: g.reverse_match,
                })
            },
        };
        out.push(xray_geodata::pb::IpRule { value: Some(value) });
    }
    out
}

#[cfg(test)]
mod tests {
    use xray_proto::xray::{
        app::router::RoutingRule,
        common::geodata::{Domain, DomainRule, domain::Type as DomainType},
    };

    use super::*;
    use crate::context::RoutingData;

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
        let proto =
            RoutingRule { domain: vec![full_domain("example.com")], ..RoutingRule::default() };
        let _ = build_condition(&proto, None).unwrap();
        let cond = build_condition(&proto, None).unwrap();
        let hit = RoutingData::new().with_target_domain("example.com");
        let miss = RoutingData::new().with_target_domain("other.io");
        assert!(cond.apply(&hit));
        assert!(!cond.apply(&miss));
    }

    #[test]
    fn test_build_condition_inbound_tag() {
        let proto = RoutingRule { inbound_tag: vec!["in1".into()], ..RoutingRule::default() };
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
    fn test_to_mem_port_list() {
        use xray_proto::xray::common::net::{PortList as PList, PortRange as PRange};
        let pl = PList { range: vec![PRange { from: 80, to: 80 }, PRange { from: 443, to: 445 }] };
        let mem = to_mem_port_list(&pl);
        assert!(mem.contains(Port::new(80)));
        assert!(mem.contains(Port::new(444)));
        assert!(!mem.contains(Port::new(81)));
    }
}
