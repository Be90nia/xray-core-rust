//! 路由器主体（Router + Route）。
//!
//! 翻译自 `app/router/router.go`。
//!
//! # 设计
//!
//! - `Router` 持有规则列表 + 平衡器映射，提供 `pick_route` 同步接口。
//! - 域名策略（`DomainStrategy`）保留为字段，但**当前实现不执行 DNS 解析**
//!   （`xray-features::dns` 与本 crate trait 不兼容，留待接入）。
//! - IO 边界（出站选择、观测器、dispatcher）通过 trait + Arc 注入。
//!
//! # IO 边界
//!
//! - `OutboundHandlerSelector` 当前必须提供（即使 `NotImplementedSelector`）。
//! - `ObservationProvider` 仅 LeastPing/LeastLoad 策略需要。
//! - DNS 解析路径：TODO（等上层接入）。

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use xray_geodata::loader::GeoDataLoader;
use xray_proto::xray::app::router::{BalancingRule, Config, RoutingRule};

use crate::balancing::{Balancer, BalancingStrategy, ObservationProvider, OutboundHandlerSelector};
use crate::config::DomainStrategy;
use crate::context::RoutingContext;
use crate::error::RouterError;
use crate::rule::{build_rule, Rule};

/// 路由结果。对应 Go `router.Route`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// 出站 tag。
    pub outbound_tag: String,
    /// 命中的 ruleTag。
    pub rule_tag: String,
}

/// 路由器。对应 Go `router.Router`。
pub struct Router {
    domain_strategy: DomainStrategy,
    rules: RwLock<Vec<Arc<Rule>>>,
    balancers: RwLock<HashMap<String, Arc<Balancer>>>,
    ohm: Arc<dyn OutboundHandlerSelector>,
    /// 可选观测器（仅 LeastPing/LeastLoad 策略需要）。
    ///
    /// 对应 Go `extension.Observatory`，由 core 装配时通过 `Router::init` 或
    /// `Router::set_observer` 注入。无观测器时 LeastPing/LeastLoad 策略在 `pick_outbound`
    /// 返回空 → Balancer 走 fallback_tag，匹配 Go 行为。
    observer: RwLock<Option<Arc<dyn ObservationProvider>>>,
    geo_loader: Option<Arc<GeoDataLoader>>,
    /// DNS 解析能力（domainStrategy IpOnDemand/IpIfNonMatch 用）。
    dns: RwLock<Option<Arc<dyn xray_features::dns::DnsClient>>>,
}

impl Router {
    /// 从 proto `Config` 初始化路由器。
    ///
    /// 对应 Go `router.Init`。
    ///
    /// `observer` 传入 `LeastPing` / `LeastLoad` 策略使用，传 `None` 时
    /// 这两个策略构建仍会成功，但 `pick_outbound` 调用时返回空 → `Balancer`
    /// 走 `fallback_tag` 分支（与 Go 无 observatory 时的行为一致）。
    pub fn init(
        config: &Config,
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Option<Arc<dyn ObservationProvider>>,
        geo_loader: Option<Arc<GeoDataLoader>>,
    ) -> Result<Arc<Self>, RouterError> {
        // 1. 构建平衡器映射
        let mut balancers: HashMap<String, Arc<Balancer>> = HashMap::new();
        for br in &config.balancing_rule {
            let b = build_balancer(br, &ohm, observer.as_ref().map(Arc::clone))?;
            if balancers.insert(br.tag.clone(), Arc::new(b)).is_some() {
                return Err(RouterError::DuplicateBalancerTag);
            }
        }

        // 2. 构建规则
        let mut rules: Vec<Arc<Rule>> = Vec::with_capacity(config.rule.len());
        let mut seen_rule_tags = std::collections::HashSet::new();
        for rr in &config.rule {
            let r = build_rule(rr, &balancers, geo_loader.as_deref())?;
            if !r.rule_tag.is_empty() && !seen_rule_tags.insert(r.rule_tag.clone()) {
                return Err(RouterError::DuplicateRuleTag(r.rule_tag.clone()));
            }
            rules.push(Arc::new(r));
        }

        Ok(Arc::new(Self {
            domain_strategy: DomainStrategy::from_proto_i32(config.domain_strategy),
            rules: RwLock::new(rules),
            balancers: RwLock::new(balancers),
            ohm,
            observer: RwLock::new(observer),
            geo_loader,
            dns: RwLock::new(None),
        }))
    }

    /// 创建空 Router（仅测试用）。
    #[must_use]
    pub fn empty(
        ohm: Arc<dyn OutboundHandlerSelector>,
        observer: Option<Arc<dyn ObservationProvider>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            domain_strategy: DomainStrategy::default(),
            rules: RwLock::new(Vec::new()),
            balancers: RwLock::new(HashMap::new()),
            ohm,
            observer: RwLock::new(observer),
            geo_loader: None,
            dns: RwLock::new(None),
        })
    }

    /// 注入观测器（对应 Go `extension.Observatory`）。
    ///
    /// 用于在 Router 已构建后再装配 observatory app。**注意**：已构建的
    /// LeastPing/LeastLoad 策略不会回填 observer；应在 `Router::init` 阶段传入，
    /// 或 rebuild 平衡器。此 setter 主要给 core 装配阶段使用。
    pub fn set_observer(&self, observer: Arc<dyn ObservationProvider>) {
        *self.observer.write() = Some(observer);
    }

    /// 返回观测器引用（仅查信息用）。
    #[must_use]
    pub fn observer(&self) -> Option<Arc<dyn ObservationProvider>> {
        self.observer.read().clone()
    }
    /// 注入 DNS 解析能力（对应 Go `r.dns`，由 core 装配时设置）。
    pub fn set_dns_client(&self, dns: Arc<dyn xray_features::dns::DnsClient>) {
        *self.dns.write() = Some(dns);
    }

    /// 返回域名策略。
    #[must_use]
    pub fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }

    /// 返回 ohm 引用（构建 BalancingRule 时使用）。
    #[must_use]
    pub fn ohm(&self) -> &Arc<dyn OutboundHandlerSelector> {
        &self.ohm
    }

    /// 路由匹配。返回第一条命中规则的 tag。
    ///
    /// 对应 Go `Router.PickRoute`。
    pub fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<Route, RouterError> {
        let rules = self.rules.read();
        for rule in rules.iter() {
            if let Some(tag) = rule.apply(ctx) {
                if !tag.is_empty() {
                    return Ok(Route {
                        outbound_tag: tag,
                        rule_tag: rule.rule_tag.clone(),
                    });
                }
            }
        }
        Err(RouterError::NoClue)
    }
    /// 带 DNS 解析的路由匹配。对应 Go `pickRouteInternal` 的 domainStrategy 分支。
    ///
    /// - `IpOnDemand`：匹配前先解析域名注入 target_ips（Go 用 ResolvableContext 懒解析，
    ///   此处 eager——结果等价，多解析由 DnsService 缓存兜住）。
    /// - `IpIfNonMatch`：第一轮全不中且目标为域名时，解析后重跑一轮。
    /// - `AsIs` / 无 dns / skip_dns_resolve：退化为 [`Router::pick_route`]。
    pub async fn pick_route_resolved(
        &self,
        ctx: &mut crate::context::RoutingData,
    ) -> Result<Route, RouterError> {
        let can_resolve = !ctx.get_skip_dns_resolve()
            && self.domain_strategy != DomainStrategy::AsIs
            && !ctx.get_target_domain().is_empty()
            && ctx.get_target_ips().is_empty();
        match self.domain_strategy {
            DomainStrategy::IpOnDemand if can_resolve => {
                self.resolve_into(ctx).await;
                self.pick_route(ctx)
            }
            DomainStrategy::IpIfNonMatch => {
                if let Ok(r) = self.pick_route(ctx) {
                    return Ok(r);
                }
                if can_resolve {
                    self.resolve_into(ctx).await;
                    return self.pick_route(ctx);
                }
                Err(RouterError::NoClue)
            }
            _ => self.pick_route(ctx),
        }
    }

    /// 解析 ctx.target_domain 注入 target_ips（失败保持原状，规则照域名匹配）。
    async fn resolve_into(&self, ctx: &mut crate::context::RoutingData) {
        use xray_features::dns::IpOption;
        let Some(dns) = self.dns.read().clone() else {
            return;
        };
        // Go ResolvableContext：IPOption{IPv4+IPv6, FakeDisable}
        // （app/router/router_test.go:176-179 同参数）。
        let option = IpOption {
            ipv4_enable: true,
            ipv6_enable: true,
            fake_enable: false,
        };
        match dns.lookup_ip(ctx.get_target_domain(), option).await {
            Ok((ips, _ttl)) => {
                if !ips.is_empty() {
                    ctx.target_ips = ips;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "router dns resolve failed, rules match by domain only");
            }
        }
    }

    /// 增加一条规则（运行时）。
    ///
    /// 对应 Go `Router.AddRule`。
    pub fn add_rule(&self, rule_tag: String, proto: RoutingRule) -> Result<(), RouterError> {
        if rule_tag.is_empty() {
            return Err(RouterError::EmptyTagName);
        }
        let mut rules = self.rules.write();
        if rules.iter().any(|r| r.rule_tag == rule_tag) {
            return Err(RouterError::DuplicateRuleTag(rule_tag));
        }
        let balancers = self.balancers.read();
        let mut proto = proto;
        proto.rule_tag = rule_tag.clone();
        let r = build_rule(&proto, &balancers, self.geo_loader.as_deref())?;
        rules.push(Arc::new(r));
        Ok(())
    }

    /// 移除一条规则。
    ///
    /// 对应 Go `Router.RemoveRule`。
    pub fn remove_rule(&self, rule_tag: &str) -> Result<(), RouterError> {
        if rule_tag.is_empty() {
            return Err(RouterError::EmptyTagName);
        }
        let mut rules = self.rules.write();
        let before = rules.len();
        rules.retain(|r| r.rule_tag != rule_tag);
        if rules.len() == before {
            return Err(RouterError::TagNotFound);
        }
        Ok(())
    }

    /// 重载规则。
    ///
    /// 对应 Go `Router.ReloadRules`。
    pub fn reload_rules(&self, protos: &[RoutingRule]) -> Result<(), RouterError> {
        let balancers = self.balancers.read();
        let mut new_rules = Vec::with_capacity(protos.len());
        let mut seen = std::collections::HashSet::new();
        for p in protos {
            let r = build_rule(p, &balancers, self.geo_loader.as_deref())?;
            if !r.rule_tag.is_empty() && !seen.insert(r.rule_tag.clone()) {
                return Err(RouterError::DuplicateRuleTag(r.rule_tag.clone()));
            }
            new_rules.push(Arc::new(r));
        }
        *self.rules.write() = new_rules;
        Ok(())
    }

    /// 列出当前规则 tag。
    pub fn list_rules(&self) -> Vec<String> {
        self.rules.read().iter().map(|r| r.rule_tag.clone()).collect()
    }

    /// 覆盖平衡器目标。
    ///
    /// 对应 Go `Router.OverrideBalancer`。
    pub fn override_balancer(
        &self,
        balancer_tag: &str,
        target: &str,
    ) -> Result<(), RouterError> {
        let balancers = self.balancers.read();
        let b = balancers
            .get(balancer_tag)
            .ok_or_else(|| RouterError::BalancerNotFound(balancer_tag.to_string()))?;
        b.set_override_target(target);
        Ok(())
    }

    /// 返回平衡器句柄（仅查信息用）。
    pub fn get_balancer(&self, tag: &str) -> Option<Arc<Balancer>> {
        self.balancers.read().get(tag).cloned()
    }
}

/// 从 RoutingContext 派生 stable hash key（用于 ConsistentHashing 等 affinity 策略）。
///
/// 优先级：target_ip → target_domain → source_ip → inbound_tag。
/// 同一 ctx 在进程内始终返回同一 key（确定性），跨进程可能因 SipHash seed 不同
/// 出现差异——对于 ConsistentHashing 同进程内 session-affinity 够用。
pub(crate) fn ctx_hash_key(ctx: &dyn RoutingContext) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    if let Some(ip) = ctx.get_target_ips().first() {
        ip.hash(&mut h);
    } else if !ctx.get_target_domain().is_empty() {
        ctx.get_target_domain().hash(&mut h);
    } else if let Some(ip) = ctx.get_source_ips().first() {
        ip.hash(&mut h);
    } else {
        ctx.get_inbound_tag().hash(&mut h);
    }
    h.finish()
}

/// 构建 Balancer。
///
/// 对应 Go `BalancingRule.Build`（`app/router/config.go:121-165`）：
/// - `random` / `""` / `roundrobin` 不依赖 observer
/// - `leastping` / `leastload` 依赖 observer。无 observer 时**仍构建**，但
///   策略在 `pick_outbound` 时返回空 → `Balancer` 走 `fallback_tag`（与 Go
///   无 observatory 时返回空字符串 → fallback 的行为一致）。
///
/// `strategy_settings`（TypedMessage 反序列化）当前不解析：LeastLoad 用
/// `StrategyLeastLoadConfig::default()` 兜底（同 Go 缺省值）。
fn build_balancer(
    br: &BalancingRule,
    ohm: &Arc<dyn OutboundHandlerSelector>,
    observer: Option<Arc<dyn ObservationProvider>>,
) -> Result<Balancer, RouterError> {
    let strategy: Arc<dyn BalancingStrategy> = match br.strategy.as_str() {
        "random" => Arc::new(crate::strategy_random::RandomStrategy::new(
            br.outbound_selector.clone(),
            ohm.clone(),
            br.fallback_tag.clone(),
        )),
        "leastping" => {
            // 始终构建；observer 缺失时 pick_outbound 返回 EmptyBalancerResult。
            if let Some(obs) = observer {
                Arc::new(crate::strategy_leastping::LeastPingStrategy::new(obs))
            } else {
                Arc::new(StubLeastPingStrategy)
            }
        }
        "leastload" => {
            // 同 leastping；observer 缺失时返回空 → fallback。
            if let Some(obs) = observer {
                let cfg = br
                    .strategy_settings
                    .as_ref()
                    .and_then(|ss| {
                        // 反序列化 TypedMessage → StrategyLeastLoadConfig。
                        // proto Any 解码需 xray-proto Any 支持；此处 try_decode 失败回退默认。
                        let any = &ss.value;
                        prost::Message::decode(any.as_slice()).ok()
                    })
                    .unwrap_or_default();
                Arc::new(
                    crate::strategy_leastload::LeastLoadStrategy::new(
                        &cfg,
                        br.outbound_selector.clone(),
                        ohm.clone(),
                        obs,
                    )
                    .map_err(|e| RouterError::Other(format!("leastload config: {e}")))?,
                )
            } else {
                Arc::new(StubLeastLoadStrategy)
            }
        }
        "" | "roundrobin" => Arc::new(crate::balancing::RoundRobinStrategy::new(
            br.outbound_selector.clone(),
            ohm.clone(),
            observer.clone(),
        )),
        other => {
            tracing::warn!(target: "xray_router", strategy = %other, "unknown strategy, falling back to roundrobin");
            Arc::new(crate::balancing::RoundRobinStrategy::new(
                br.outbound_selector.clone(),
                ohm.clone(),
                observer.clone(),
            ))
        }
    };

    Ok(Balancer::new(
        br.outbound_selector.clone(),
        strategy,
        ohm.clone(),
        br.fallback_tag.clone(),
    ))
}

/// 无 observer 时的 LeastPing 占位：始终返回空 → Balancer 走 fallback。
struct StubLeastPingStrategy;
impl BalancingStrategy for StubLeastPingStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        Err(RouterError::EmptyBalancerResult)
    }
}

/// 无 observer 时的 LeastLoad 占位：始终返回空 → Balancer 走 fallback。
struct StubLeastLoadStrategy;
impl BalancingStrategy for StubLeastLoadStrategy {
    fn pick_outbound(&self) -> Result<String, RouterError> {
        Err(RouterError::EmptyBalancerResult)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RoutingData;
    use crate::balancing::NotImplementedSelector;
    use std::net::{IpAddr, Ipv4Addr};

    fn simple_tag_rule(tag: &str, domain: &str) -> RoutingRule {
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::common::geodata::{Domain, DomainRule};
        use xray_proto::xray::common::geodata::domain::Type as DT;
        RoutingRule {
            target_tag: Some(TargetTag::Tag(tag.into())),
            rule_tag: String::new(),
            domain: vec![DomainRule {
                value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(Domain {
                    r#type: DT::Full as i32,
                    value: domain.into(),
                    attribute: vec![],
                })),
            }],
            ip: vec![],
            port_list: None,
            source_ip: vec![],
            source_port_list: None,
            networks: vec![],
            user_email: vec![],
            inbound_tag: vec![],
            protocol: vec![],
            attributes: HashMap::new(),
            local_ip: vec![],
            local_port_list: None,
            vless_route_list: None,
            process: vec![],
            webhook: None,
        }
    }

    #[test]
    fn test_empty_router_returns_no_clue() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        let ctx = RoutingData::new().with_target_domain("any");
        assert!(matches!(r.pick_route(&ctx), Err(RouterError::NoClue)));
    }

    #[test]
    fn test_simple_router_picks_matching_rule() {
        let mut cfg = Config::default();
        cfg.rule = vec![simple_tag_rule("direct", "example.com")];
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector), None, None).unwrap();
        let hit = RoutingData::new().with_target_domain("example.com");
        let miss = RoutingData::new().with_target_domain("other.io");
        assert_eq!(
            r.pick_route(&hit).unwrap(),
            Route { outbound_tag: "direct".into(), rule_tag: String::new() }
        );
        assert!(matches!(r.pick_route(&miss), Err(RouterError::NoClue)));
    }

    #[test]
    fn test_add_and_remove_rule() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        r.add_rule("rule1".into(), simple_tag_rule("tag1", "a.com")).unwrap();
        assert!(r.list_rules().contains(&"rule1".to_string()));

        // duplicate add
        assert!(matches!(
            r.add_rule("rule1".into(), simple_tag_rule("t2", "b.com")),
            Err(RouterError::DuplicateRuleTag(_))
        ));

        // remove
        r.remove_rule("rule1").unwrap();
        assert!(!r.list_rules().contains(&"rule1".to_string()));

        // remove non-existent
        assert!(matches!(r.remove_rule("nope"), Err(RouterError::TagNotFound)));
    }

    #[test]
    fn test_reload_rules_replaces_all() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        r.add_rule("r1".into(), simple_tag_rule("t1", "a.com")).unwrap();
        let new_rules = vec![
            simple_tag_rule("t2", "b.com"),
        ];
        // 给新规则添加 rule_tag
        let _ = r.reload_rules(&new_rules);
        // 不抛错即 OK；详情见 list_rules
        assert_eq!(r.list_rules().len(), 1);
    }

    #[test]
    fn test_override_balancer_not_found() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        let err = r.override_balancer("nope", "target").unwrap_err();
        assert!(matches!(err, RouterError::BalancerNotFound(_)));
    }

    #[test]
    fn test_domain_strategy_from_config() {
        let mut cfg = Config::default();
        cfg.domain_strategy = 3; // IpOnDemand
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector), None, None).unwrap();
        assert_eq!(r.domain_strategy(), DomainStrategy::IpOnDemand);
    }



    // ── GeoIP / GeoSite rule E2E ──
    //
    // 构造临时 dat 文件 → GeoDataLoader → Router 路由命中。
    // 验收要求：复杂规则集能正确路由（domain suffix、IP CIDR、geoip 等）。
    fn unique_dir(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "xray-router-e2e-{}-{label}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_geoip_dat() -> Vec<u8> {
        use prost::Message;
        use xray_proto::xray::common::geodata::{Cidr, GeoIpList, GeoIp};
        let cn = GeoIp {
            code: "CN".into(),
            cidr: vec![
                Cidr { ip: vec![192, 168, 0, 0], prefix: 16 },
                Cidr { ip: vec![10, 0, 0, 0], prefix: 8 },
            ],
            reverse_match: false,
        };
        let list = GeoIpList { entry: vec![cn] };
        list.encode_to_vec()
    }

    fn make_geosite_dat() -> Vec<u8> {
        use prost::Message;
        use xray_proto::xray::common::geodata::{Domain, GeoSite, GeoSiteList};
        let cn = GeoSite {
            code: "CN".into(),
            domain: vec![
                Domain { r#type: 3 /*Full*/ as i32, value: "baidu.com".into(), attribute: vec![] },
                Domain { r#type: 2 /*Domain*/ as i32, value: "qq.com".into(), attribute: vec![] },
            ],
        };
        let list = GeoSiteList { entry: vec![cn] };
        list.encode_to_vec()
    }

    fn geoip_rule() -> RoutingRule {
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::common::geodata::{GeoIpRule, IpRule};
        use xray_proto::xray::common::geodata::ip_rule::Value as IV;
        RoutingRule {
            target_tag: Some(TargetTag::Tag("cn_direct".into())),
            rule_tag: String::new(),
            ip: vec![IpRule {
                value: Some(IV::Geoip(GeoIpRule {
                    file: "geoip.dat".into(),
                    code: "cn".into(),
                    reverse_match: false,
                })),
            }],
            ..Default::default()
        }
    }

    fn geosite_rule() -> RoutingRule {
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        use xray_proto::xray::common::geodata::{DomainRule, GeoSiteRule};
        use xray_proto::xray::common::geodata::domain_rule::Value as DV;
        RoutingRule {
            target_tag: Some(TargetTag::Tag("cn_site".into())),
            rule_tag: String::new(),
            domain: vec![DomainRule {
                value: Some(DV::Geosite(GeoSiteRule {
                    file: "geosite.dat".into(),
                    code: "cn".into(),
                    attrs: String::new(),
                })),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_e2e_geoip_rule_routes_by_cidr() {
        use xray_geodata::loader::GeoDataLoader;
        let dir = unique_dir("geoip");
        std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
        let loader = Arc::new(GeoDataLoader::new(dir.clone()));

        let mut cfg = Config::default();
        cfg.rule = vec![geoip_rule()];
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector), None, Some(loader)).unwrap();

        // 命中 CN CIDR 192.168.0.0/16
        let hit = RoutingData::new().with_target_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let route = r.pick_route(&hit).unwrap();
        assert_eq!(route.outbound_tag, "cn_direct");

        // 不命中
        let miss = RoutingData::new().with_target_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(matches!(r.pick_route(&miss), Err(RouterError::NoClue)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_e2e_geosite_rule_routes_by_domain() {
        use xray_geodata::loader::GeoDataLoader;
        let dir = unique_dir("geosite");
        std::fs::write(dir.join("geosite.dat"), make_geosite_dat()).unwrap();
        let loader = Arc::new(GeoDataLoader::new(dir.clone()));

        let mut cfg = Config::default();
        cfg.rule = vec![geosite_rule()];
        let r = Router::init(&cfg, Arc::new(NotImplementedSelector), None, Some(loader)).unwrap();

        // baidu.com 是 Full 类型，应命中
        let hit_full = RoutingData::new().with_target_domain("baidu.com");
        assert_eq!(r.pick_route(&hit_full).unwrap().outbound_tag, "cn_site");

        // qq.com 是 Domain 类型，应命中本身与子域名
        let hit_sub = RoutingData::new().with_target_domain("www.qq.com");
        assert_eq!(r.pick_route(&hit_sub).unwrap().outbound_tag, "cn_site");

        // 不在 CN geosite
        let miss = RoutingData::new().with_target_domain("google.com");
        assert!(matches!(r.pick_route(&miss), Err(RouterError::NoClue)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_geo_rule_without_loader_skips_gracefully() {
        // loader = None 时 GeoIP/GeoSite 变体 warn 并 skip，不 panic
        let mut cfg = Config::default();
        cfg.rule = vec![geoip_rule()];
        // loader = None 时 GeoIP 变体被 skip，IPMatcher 收到空 vec 返回错（GeodataBuild）
        let result = Router::init(&cfg, Arc::new(NotImplementedSelector), None, None);
        assert!(result.is_err(), "expected error when geoip rule present but no loader");
    }

    // ── Balancer strategy 装配 ──
    //
    // 验证 build_balancer 不再拒绝 leastping/leastload（h81 修复点）：
    // - 有 observer：构建 + pick_outbound 返回正确 tag
    // - 无 observer：构建成功 + pick_outbound → fallback_tag

    use crate::balancing::{MemoryObservationProvider, SimpleSelector};
    use xray_proto::xray::core::app::observatory::{ObservationResult, OutboundStatus};
    /// 简单 tag 规则（domain="x.test" → tag）；用于挂上 BalancingRule。
    fn simple_balance_rule(balancer_tag: &str) -> RoutingRule {
        use xray_proto::xray::common::geodata::{Domain, DomainRule};
        use xray_proto::xray::common::geodata::domain::Type as DT;
        use xray_proto::xray::app::router::routing_rule::TargetTag;
        RoutingRule {
            target_tag: Some(TargetTag::BalancingTag(balancer_tag.into())),
            rule_tag: String::new(),
            domain: vec![DomainRule {
                value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(Domain {
                    r#type: DT::Full as i32,
                    value: "x.test".into(),
                    attribute: vec![],
                })),
            }],
            ..Default::default()
        }
    }

    fn balancing_rule_with(strategy: &str, tag: &str, fallback: &str) -> BalancingRule {
        BalancingRule {
            tag: tag.into(),
            outbound_selector: vec!["a".into(), "b".into(), "c".into()],
            strategy: strategy.into(),
            strategy_settings: None,
            fallback_tag: fallback.into(),
        }
    }

    fn obs_with_alive(tag: &str, alive: bool, delay: i64) -> OutboundStatus {
        OutboundStatus {
            alive,
            delay,
            last_error_reason: String::new(),
            outbound_tag: tag.into(),
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: None,
        }
    }

    #[test]
    fn test_build_balancer_leastping_with_observer_succeeds() {
        let mut cfg = Config::default();
        cfg.balancing_rule = vec![balancing_rule_with("leastping", "bl", "fb")];
        cfg.rule = vec![simple_balance_rule("bl")];

        let obs = Arc::new(MemoryObservationProvider::new());
        obs.update(ObservationResult {
            status: vec![
                obs_with_alive("a", true, 100),
                obs_with_alive("b", true, 50),
                obs_with_alive("c", true, 200),
            ],
        });

        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));
        let r = Router::init(&cfg, ohm, Some(obs), None).unwrap();

        let ctx = RoutingData::new().with_target_domain("x.test");
        // leastping 选最低延迟 → b
        assert_eq!(r.pick_route(&ctx).unwrap().outbound_tag, "b");
    }

    #[test]
    fn test_build_balancer_leastping_without_observer_falls_back() {
        let mut cfg = Config::default();
        cfg.balancing_rule = vec![balancing_rule_with("leastping", "bl", "fallback")];
        cfg.rule = vec![simple_balance_rule("bl")];

        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));
        // 无 observer：构建仍成功，pick 时走 fallback_tag
        let r = Router::init(&cfg, ohm, None, None).unwrap();
        let ctx = RoutingData::new().with_target_domain("x.test");
        assert_eq!(r.pick_route(&ctx).unwrap().outbound_tag, "fallback");
    }

    #[test]
    fn test_build_balancer_leastload_with_observer_succeeds() {
        // 不设置 strategy_settings → build_balancer 走 unwrap_or_default 路径。
        let mut cfg = Config::default();
        cfg.balancing_rule = vec![balancing_rule_with("leastload", "bl", "fb")];
        cfg.rule = vec![simple_balance_rule("bl")];

        let obs = Arc::new(MemoryObservationProvider::new());
        obs.update(ObservationResult {
            status: vec![
                obs_with_alive("a", true, 100),
                obs_with_alive("b", true, 50),
                obs_with_alive("c", true, 200),
            ],
        });
        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));
        let r = Router::init(&cfg, ohm, Some(obs), None).unwrap();

        let ctx = RoutingData::new().with_target_domain("x.test");
        // leastload 默认 expected=1 选最低延迟 → b
        assert_eq!(r.pick_route(&ctx).unwrap().outbound_tag, "b");
    }

    #[test]
    fn test_build_balancer_leastload_without_observer_falls_back() {
        let mut cfg = Config::default();
        cfg.balancing_rule = vec![balancing_rule_with("leastload", "bl", "fb-tag")];
        cfg.rule = vec![simple_balance_rule("bl")];

        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));
        let r = Router::init(&cfg, ohm, None, None).unwrap();
        let ctx = RoutingData::new().with_target_domain("x.test");
        assert_eq!(r.pick_route(&ctx).unwrap().outbound_tag, "fb-tag");
    }

    #[test]
    fn test_build_balancer_roundrobin_with_observer_filters_dead() {
        // 验证 roundrobin 在有 observer 时只轮询 alive（与 Go 一致）。
        let mut cfg = Config::default();
        cfg.balancing_rule = vec![balancing_rule_with("roundrobin", "bl", "fb")];
        cfg.rule = vec![simple_balance_rule("bl")];

        let obs = Arc::new(MemoryObservationProvider::new());
        // a 是死的，b/c alive
        obs.update(ObservationResult {
            status: vec![
                obs_with_alive("a", false, 9999),
                obs_with_alive("b", true, 50),
                obs_with_alive("c", true, 100),
            ],
        });
        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));
        let r = Router::init(&cfg, ohm, Some(obs), None).unwrap();

        let ctx = RoutingData::new().with_target_domain("x.test");
        // 第一轮：b 或 c（不会 a）。连点 4 次应只见 b/c
        let mut picks = std::collections::HashSet::new();
        for _ in 0..4 {
            picks.insert(r.pick_route(&ctx).unwrap().outbound_tag);
        }
        assert!(!picks.contains("a"), "dead outbound a should not be picked");
        assert!(picks.iter().all(|t| t == "b" || t == "c"));
    }

    /// 验证 `Router::pick_route(ctx)` 传递 ctx 到 ConsistentHashing 策略：
    /// 同一 ctx（同 target_ip）→ 同一 outbound（session-affinity）。
    /// 构造方式直接接 LeastLoadStrategy（proto StrategyLeastLoadConfig 不含 mode 字段，
    /// `build_balancer` 只能造 Availability 模式；mode=Rust-only 扩展，此处手装验证
    /// ctx → balancer.pick_outbound_with_key(ctx_hash_key(ctx)) 链通）。
    #[test]
    fn test_router_consistent_hashing_same_ctx_picks_same_outbound() {
        use crate::balancing::MemoryObservationProvider;
        use crate::strategy_leastload::LeastLoadStrategy;

        let obs = Arc::new(MemoryObservationProvider::new());
        obs.update(ObservationResult {
            status: vec![
                obs_with_alive("a", true, 50),
                obs_with_alive("b", true, 50),
                obs_with_alive("c", true, 50),
            ],
        });
        let ohm = Arc::new(SimpleSelector::from_tags(["a", "b", "c"]));

        // 手装 ConsistentHashing 策略 balancer。
        let cfg = xray_proto::xray::app::router::StrategyLeastLoadConfig::default();
        let strategy = Arc::new(
            LeastLoadStrategy::consistent_hashing(
                &cfg,
                vec!["a".into(), "b".into(), "c".into()],
                ohm.clone(),
                obs,
                64,
            )
            .unwrap(),
        );
        let balancer = Arc::new(Balancer::new(
            vec!["a".into(), "b".into(), "c".into()],
            strategy,
            ohm,
            "fb",
        ));

        // 直接构造 Rule 挂上该 balancer，绕过 build_balancer（其默认 Availability 模式）。
        let rule = Rule {
            tag: String::new(),
            rule_tag: String::new(),
            balancer: Some(balancer),
            condition: None,
            webhook: None,
        };
        let r = Router::empty(Arc::new(SimpleSelector::from_tags(["a", "b", "c"])), None);
        *r.rules.write() = vec![Arc::new(rule)];

        // 同一 ctx（target_ip）两次 pick_route → 同 outbound
        let ctx1 = RoutingData::new()
            .with_target_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let p1a = r.pick_route(&ctx1).unwrap().outbound_tag;
        let p1b = r.pick_route(&ctx1).unwrap().outbound_tag;
        assert_eq!(p1a, p1b, "same ctx must return same tag (session affinity)");
        assert!(["a", "b", "c"].contains(&p1a.as_str()));

        // 不同 ctx（不同 target_ip）→ 可能不同 outbound（ConsistentHashing 分布）
        let ctx2 = RoutingData::new()
            .with_target_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let ctx3 = RoutingData::new()
            .with_target_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        let p2 = r.pick_route(&ctx2).unwrap().outbound_tag;
        let p3 = r.pick_route(&ctx3).unwrap().outbound_tag;
        assert!(["a", "b", "c"].contains(&p2.as_str()));
        assert!(["a", "b", "c"].contains(&p3.as_str()));
        // 跨 3 段不同 IP 命中分布应至少 2 个不同 tag（hash 散开）
        let mut uniq = std::collections::HashSet::new();
        uniq.insert(p1a);
        uniq.insert(p2);
        uniq.insert(p3);
        assert!(
            uniq.len() >= 2,
            "consistent hashing should distribute across tags, got {:?}",
            uniq
        );
    }
}
