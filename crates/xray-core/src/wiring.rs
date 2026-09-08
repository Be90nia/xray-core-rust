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

use std::future::Future;
use std::sync::Arc;

use xray_app_dispatcher::default::{
    AccessContext, DefaultDispatcher, DispatcherContext, Route as DispRoute,
    RoutingContext as DispRoutingContext, RoutingRouter, SimpleOhm, SniffingRequest,
};
use xray_app_dispatcher::{maybe_wrap_reader, maybe_wrap_writer, DispatchHandler, DispatcherError};
use xray_proto::xray::common::geodata::CidrRule;
use xray_app_router::balancing::{NotImplementedSelector, ObservationProvider, OutboundHandlerSelector};
use xray_app_router::context::RoutingData as RouterRoutingData;
use xray_app_router::error::RouterError;
use xray_app_router::Router;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_transport::link::Link;

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
///
/// Go `routing.Context.GetTarget` 语义：`RouteTarget` 有效时优先（routeOnly：
/// 路由用嗅探域名，拨号保持原 dest）。
fn bridge_context(ctx: &dyn DispRoutingContext) -> RouterRoutingData {
    let mut data = RouterRoutingData {
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
    };
    if let Some(rt) = ctx.get_route_target() {
        match rt.address().ip() {
            Some(ip) => {
                data.target_ips = vec![ip];
                data.target_domain.clear();
            }
            None => {
                data.target_domain = rt.address().as_domain().unwrap_or("").to_string();
                data.target_ips.clear();
            }
        }
        data.target_port = rt.port();
    }
    data
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

    /// 带 DNS 解析的选路（domainStrategy IpOnDemand/IpIfNonMatch）：
    /// 委托 [`Router::pick_route_resolved`]，携带完整 RoutingContext
    /// （含 sniffed protocol / inbound tag）——生产 dispatch_link 的路由入口。
    fn pick_route_resolved<'a>(
        &'a self,
        ctx: &'a dyn DispRoutingContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<DispRoute, DispatcherError>> + Send + 'a>> {
        Box::pin(async move {
            let mut data = bridge_context(ctx);
            match self.router.pick_route_resolved(&mut data).await {
                Ok(route) => Ok(DispRoute {
                    outbound_tag: route.outbound_tag,
                    rule_tag: route.rule_tag,
                }),
                Err(e) => Err(map_router_err(e)),
            }
        })
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

// ========== 生产接线（方案 B）：DefaultDispatcher 入口桥 ==========

/// 把任意 [`DispatchRouter`] 暴露为 dispatcher 的 [`RoutingRouter`]。
///
/// `start_full_with_router(built, router: Arc<dyn DispatchRouter>)` 的适配层：
/// `pick_route` 走同步 `pick_outbound_tag`（仅目标地址），`pick_route_resolved`
/// 走 DNS 解析版。RouterAdapter 自身双 trait 实现时无需经过本桥。
pub struct DispatchRouterBridge {
    inner: Arc<dyn DispatchRouter>,
}

impl DispatchRouterBridge {
    #[must_use]
    pub fn new(inner: Arc<dyn DispatchRouter>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for DispatchRouterBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchRouterBridge").finish()
    }
}

/// 从 RoutingContext 提取目标 [`Destination`]（桥接用，仅目标地址/端口/网络）。
fn ctx_target_dest(ctx: &dyn DispRoutingContext) -> Destination {
    let addr = match ctx.get_target_ips().first() {
        Some(std::net::IpAddr::V4(ip)) => Address::IPv4(*ip),
        Some(std::net::IpAddr::V6(ip)) => Address::IPv6(*ip),
        None => Address::Domain(ctx.get_target_domain().to_string()),
    };
    Destination::new(addr, ctx.get_target_port(), ctx.get_network())
}

impl RoutingRouter for DispatchRouterBridge {
    fn pick_route(&self, ctx: &dyn DispRoutingContext) -> Result<DispRoute, DispatcherError> {
        match self.inner.pick_outbound_tag(&ctx_target_dest(ctx)) {
            Some(tag) => Ok(DispRoute::new(tag)),
            None => Err(DispatcherError::Other("no route matched".into())),
        }
    }

    fn pick_route_resolved<'a>(
        &'a self,
        ctx: &'a dyn DispRoutingContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<DispRoute, DispatcherError>> + Send + 'a>> {
        Box::pin(async move {
            let dest = ctx_target_dest(ctx);
            match self.inner.pick_outbound_tag_resolved(&dest).await {
                Some(tag) => Ok(DispRoute::new(tag)),
                None => Err(DispatcherError::Other("no route matched".into())),
            }
        })
    }
}

/// `BuiltInbound.sniffing` JSON → dispatcher [`SniffingRequest`]。
///
/// 字段映射对齐 Go `session.SniffingRequest` 构建（`infra/conf.SniffingConfig` →
/// destOverride / domainsExcluded / ipsExcluded / metadataOnly / routeOnly）。
/// 解析失败或无 sniffing 配置时返回 default（enabled=false，零行为变化）。
#[must_use]
pub fn sniffing_request_from_json(v: Option<&serde_json::Value>) -> SniffingRequest {
    let Some(cfg) = v
        .cloned()
        .and_then(|v| serde_json::from_value::<xray_conf::SniffingConfig>(v).ok())
    else {
        return SniffingRequest::default();
    };
    SniffingRequest {
        enabled: cfg.enabled,
        metadata_only: cfg.metadata_only,
        route_only: cfg.route_only,
        override_destination_for_protocol: cfg.dest_override.0.clone(),
        exclude_for_domain: cfg.domains_excluded.0.clone(),
        exclude_for_ip: cfg
            .ips_excluded
            .0
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
    }
}

/// 生产 default handler：经 [`DefaultDispatcher::dispatch_link`] 分发。
///
/// 对应 Go inbound → `dispatcher.Dispatch` 入口。每个 inbound 一个实例：
/// - 持该 inbound 的 sniffing 配置（首包嗅探 + dest 覆盖 + 回灌在 dispatch_link 内）
/// - 包 inbound counter（`inbound>>>{tag}>>>traffic>>>{uplink,downlink}`）：
///   uplink = inbound 写（link.writer），downlink = inbound 读（link.reader）
pub struct InboundDispatchHandler {
    dispatcher: Arc<DefaultDispatcher>,
    sniff: SniffingRequest,
    tag: String,
}

impl InboundDispatchHandler {
    #[must_use]
    pub fn new(dispatcher: Arc<DefaultDispatcher>, sniff: SniffingRequest, tag: &str) -> Self {
        Self {
            dispatcher,
            sniff,
            tag: tag.to_string(),
        }
    }

    /// 懒注册并取该 inbound 的方向 counter。
    fn inbound_counter(
        &self,
        direction: &str,
    ) -> Option<Arc<dyn xray_features::stats::Counter>> {
        self.dispatcher.stats.as_ref().and_then(|m| {
            xray_features::stats::get_or_register_counter(
                m.as_ref(),
                &format!("inbound>>>{}>>>traffic>>>{direction}", self.tag),
            )
            .ok()
        })
    }
}

impl std::fmt::Debug for InboundDispatchHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundDispatchHandler")
            .field("tag", &self.tag)
            .field("sniffing_enabled", &self.sniff.enabled)
            .finish()
    }
}

impl DispatchHandler for InboundDispatchHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(
        &self,
        dest: &Destination,
        link: Link,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // UDP relay（socks/dokodemo/ss）无协议层 access（from/email 留空），
        // 但 inbound_tag 必须补齐——否则 router 的 inboundTag 规则永不命中
        // （Go UDP dispatch 的 ctx 同样携带 inbound 信息）。
        let access = AccessContext {
            inbound_tag: self.tag.clone(),
            ..Default::default()
        };
        self.dispatch_internal(dest, link, Some(access))
    }

    /// 带 access 上下文（对应 Go ctx 携带 `log.AccessMessage`）：
    /// 协议层填充 from/email，此处补 inbound_tag 后进 dispatch_link。
    fn dispatch_with_access(
        &self,
        dest: &Destination,
        link: Link,
        access: AccessContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let access = AccessContext {
            inbound_tag: self.tag.clone(),
            ..access
        };
        self.dispatch_internal(dest, link, Some(access))
    }
}

impl InboundDispatchHandler {
    fn dispatch_internal(
        &self,
        dest: &Destination,
        link: Link,
        access: Option<AccessContext>,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let reader = maybe_wrap_reader(self.inbound_counter("downlink"), link.reader);
        let writer = maybe_wrap_writer(self.inbound_counter("uplink"), link.writer);
        let link = Link::new(reader, writer);
        // dispatch_link 内部 spawn（sniffing → routing → access log → outbound counter → handler），
        // 此处仅同步返回。
        if let Err(e) = self
            .dispatcher
            .dispatch_link(dest, link, &self.sniff, access, None)
        {
            tracing::warn!(tag = %self.tag, error = %e, "dispatch_link failed");
        }
        Box::pin(std::future::ready(()))
    }
}

/// [`SimpleOhm`] → `OutboundHandlerSelector` 适配器。
///
/// 对应 Go `outbound.HandlerSelector.Select`（app/proxyman/outbound/outbound.go:164）：
/// tagged handler 全集按 selectors 前缀匹配，返回排序后的 tag 列表；空 selectors
/// 返回空（走 Balancer fallback）。
struct OhmOutboundSelector {
    inner: *const SimpleOhm,
}

// Safety: SimpleOhm 是 Send + Sync；指针所指 ohm 由装配方持有（`start_full_dispatched`
// 的 `ohm: Arc<SimpleOhm>`）覆盖 RouterAdapter 整个生命周期（outbound.rs::OhmRef 同款）。
unsafe impl Send for OhmOutboundSelector {}
// Safety: 同上；内部仅读 RwLock（list_tags），无 &mut。
unsafe impl Sync for OhmOutboundSelector {}

impl OutboundHandlerSelector for OhmOutboundSelector {
    fn select_outbounds(&self, selectors: &[String]) -> Result<Vec<String>, RouterError> {
        // Safety: 指针在适配器生命周期内有效（见 unsafe impl 注释）
        let ohm: &SimpleOhm = unsafe { &*self.inner };
        let mut tags: Vec<String> = Vec::new();
        for tag in ohm.list_tags() {
            if selectors.iter().any(|s| tag.starts_with(s.as_str())) {
                tags.push(tag);
            }
        }
        tags.sort();
        Ok(tags)
    }
}

/// ObservatoryFeature 观测快照 → router `ObservationProvider` 桥
/// （leastping / leastload 的观测数据源）。
pub struct ObservatoryProviderBridge(pub Arc<xray_app_observatory::ObservatoryFeature>);

impl ObservationProvider for ObservatoryProviderBridge {
    fn get_observation(
        &self,
    ) -> Result<xray_proto::xray::core::app::observatory::ObservationResult, RouterError> {
        // observatory 内部自定义 ObservationResult → proto 形态（router 侧 trait 签名）
        Ok(self.0.observer().get_observation().to_proto())
    }
}

/// 从路由配置 JSON 字节构造 [`RouterAdapter`]。
///
/// 解析 `domain` / `domainSuffix` / `domainKeyword` / `ip` (CIDR) / `outboundTag`
/// 为 proto `Config` → `Router::init`。其他 proto 字段（balancer、user、protocol 等）
/// 留空——这些字段在 dispatcher 提供完整 `RoutingContext` 时才会被规则匹配用到。
///
/// balancer selector 为 `NotImplementedSelector`（无 ohm 可选）——balancer 规则
/// 一律走 fallback。生产装配用 [`build_router_adapter_from_json_with_ohm`]。
///
/// # Errors
///
/// - JSON 解析失败
/// - `Router::init` 失败（如重复 ruleTag、geoip 规则但无 loader）
pub fn build_router_adapter_from_json(
    routing_json: &[u8],
) -> Result<Arc<RouterAdapter>, WiringError> {
    build_adapter(
        parse_routing_json_to_proto(routing_json)?,
        Arc::new(NotImplementedSelector),
        None,
    )
}

/// 同 [`build_router_adapter_from_json`]，balancer selector 接真实 [`SimpleOhm`]
/// （Go `Balancer.SelectOutbounds` 语义），并传入观测器使 `leastping` / `leastload`
/// 策略能拿到观测数据。
///
/// `ohm` 必须在返回的 RouterAdapter 整个生命周期内存活（生产路径 `ohm: Arc<SimpleOhm>`
/// 由 Instance 持有，天然满足）。
///
/// # Errors
///
/// 同 [`build_router_adapter_from_json`]。
pub fn build_router_adapter_from_json_with_ohm(
    routing_json: &[u8],
    ohm: &SimpleOhm,
    observer: Option<Arc<dyn ObservationProvider>>,
) -> Result<Arc<RouterAdapter>, WiringError> {
    build_adapter(
        parse_routing_json_to_proto(routing_json)?,
        Arc::new(OhmOutboundSelector { inner: std::ptr::from_ref(ohm) }),
        observer,
    )
}

fn build_adapter(
    config: xray_proto::xray::app::router::Config,
    ohm: Arc<dyn OutboundHandlerSelector>,
    observer: Option<Arc<dyn ObservationProvider>>,
) -> Result<Arc<RouterAdapter>, WiringError> {
    let geo_loader = Some(Arc::new(xray_geodata::loader::GeoDataLoader::new(
        resolve_asset_dir(),
    )));
    let router = Router::init(&config, ohm, observer, geo_loader)
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

    // 顶层 balancers → BalancingRule。strategy 取 `{"type":"..."}` 或裸字符串；
    // strategy:{"type":"leastload", settings:{...}} 子对象 settings 经 JSON→proto 编码为
    // TypedMessage（rttb：原实现整段丢弃→LeastLoad 调优参数全部回落默认）。
    if let Some(arr) = v.get("balancers").and_then(|b| b.as_array()) {
        for b in arr {
            let tag = b.get("tag").and_then(|x| x.as_str()).unwrap_or("");
            if tag.is_empty() {
                continue;
            }
            let (strategy, strategy_settings) = match b.get("strategy") {
                Some(serde_json::Value::String(s)) => (s.clone(), None),
                Some(serde_json::Value::Object(o)) => {
                    let ty = o.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let settings = o.get("settings").and_then(|v| {
                        // leastload settings JSON → proto + TypedMessage.bytes
                        if ty == "leastload" {
                            leastload_settings_to_typed_message(v)
                        } else {
                            None
                        }
                    });
                    (ty, settings)
                }
                _ => (String::new(), None),
            };
            cfg.balancing_rule.push(BalancingRule {
                tag: tag.to_string(),
                outbound_selector: json_string_list(b.get("selector")),
                strategy,
                strategy_settings,
                fallback_tag: b
                    .get("fallbackTag")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    // kfbd：顶层 `ruleSet` JSON 数组 → 显式校验 + 加载。proto 暂未升级支持
    // RoutingRule.rule_set 引用字段（见 xray-app-router/src/rule_set.rs TODO），
    // 故 Registry 不会被 Router 使用；但配置错误必须现在就暴露，不能等到
    // 远端首次请求才发现错配。
    if let Some(arr) = v.get("ruleSet").and_then(|x| x.as_array()) {
        let mut registry = xray_app_router::RuleSetRegistry::new();
        let mut seen_tags: std::collections::HashSet<String> = std::collections::HashSet::new();
        for rs in arr {
            let tag = rs.get("tag").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if tag.is_empty() {
                return Err(WiringError::JsonParse("ruleSet entry missing tag".into()));
            }
            if !seen_tags.insert(tag.clone()) {
                return Err(WiringError::JsonParse(format!("duplicate ruleSet tag '{tag}'")));
            }
            let r#type = rs.get("type").and_then(|x| x.as_str()).unwrap_or("");
            let path = rs.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let url = rs.get("url").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let format = rs.get("format").and_then(|x| x.as_str()).unwrap_or("json");
            let (rs_type, rs_format) = match (r#type, format) {
                ("file", "json") | ("", "json") if !path.is_empty() => (
                    xray_app_router::RuleSetType::File,
                    xray_app_router::RuleSetFormat::Json,
                ),
                ("file", _) => {
                    return Err(WiringError::JsonParse(format!(
                        "ruleSet '{tag}': unsupported format '{format}', only 'json' is implemented"
                    )));
                }
                ("remote", _) | ("", _) if !url.is_empty() => {
                    return Err(WiringError::JsonParse(format!(
                        "ruleSet '{tag}': remote rule_set download is not implemented (set type='file' and provide path)"
                    )));
                }
                (other, _) => {
                    return Err(WiringError::JsonParse(format!(
                        "ruleSet '{tag}': unknown type '{other}', must be 'file' (path) or omit + provide path"
                    )));
                }
            };
            let cfg_rs = xray_app_router::RuleSetConfig {
                tag: tag.clone(),
                rule_set_type: rs_type,
                format: rs_format,
                path,
                url,
            };
            registry
                .load(&cfg_rs)
                .map_err(|e| WiringError::JsonParse(format!("ruleSet '{tag}': {e}")))?;
        }
    }

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

/// 把 `"1.2.3.0/24"` 或裸 IP `"1.2.3.4"` 解析为 `CidrRule`。
/// 裸 IP 自动取全前缀（IPv4=/32、IPv6=/128）。
///
/// tc33：原实现 `split_once('/')` 对裸 IP 返 None，整条规则静默丢失——
/// `ipsExcluded: ["8.8.8.8"]` 仅 IP 字面就静默失效。
fn parse_cidr_to_ip_rule(s: &str) -> Option<CidrRule> {
    use xray_proto::xray::common::geodata::{Cidr, CidrRule};
    let (ip_part, prefix) = match s.split_once('/') {
        Some((ip_s, bits_s)) => {
            let bits: u32 = bits_s.parse().ok()?;
            (ip_s, bits)
        }
        // tc33：裸 IP 自动全前缀（IPv4=/32、IPv6=/128）。
        None => (s, 0),
    };
    let (ip_vec, full_prefix) = if let Ok(v4) = ip_part.parse::<std::net::Ipv4Addr>() {
        (v4.octets().to_vec(), 32)
    } else if let Ok(v6) = ip_part.parse::<std::net::Ipv6Addr>() {
        (v6.octets().to_vec(), 128)
    } else {
        return None;
    };
    let final_prefix = if prefix == 0 { full_prefix } else { prefix.min(u32::from(u8::MAX)) };
    Some(CidrRule {
        cidr: Some(Cidr { ip: ip_vec, prefix: final_prefix }),
        reverse_match: false,
    })
}
/// rttb：JSON `strategy.settings`（leastload 调优参数）→ `StrategyLeastLoadConfig`
/// proto bytes，再包成 `TypedMessage`。
///
/// JSON 字段命名对齐 Go `infra/conf/router.go`：`baselines`/`expectedNodes`/
/// `maxRTT`/`tolerance`/`costs`（costs 子字段 `regexp`/`match`/`value`）。
/// 编码失败 → `None`（消费端走默认，避免 hard-error 阻断整个 balancer）。
fn leastload_settings_to_typed_message(v: &serde_json::Value) -> Option<xray_proto::xray::common::serial::TypedMessage> {
    use prost::Message;
    use xray_proto::xray::app::router::{StrategyLeastLoadConfig, StrategyWeight};
    let obj = v.as_object()?;
    let mut cfg = StrategyLeastLoadConfig::default();
    if let Some(arr) = obj.get("baselines").and_then(|x| x.as_array()) {
        cfg.baselines = arr
            .iter()
            .filter_map(|x| x.as_i64())
            .collect();
    }
    // Go `expectedNodes` → proto `expected`
    if let Some(n) = obj.get("expectedNodes").and_then(|x| x.as_i64()) {
        cfg.expected = n as i32;
    }
    if let Some(n) = obj.get("maxRTT").and_then(|x| x.as_i64()) {
        cfg.max_rtt = n;
    }
    if let Some(t) = obj.get("tolerance").and_then(|x| x.as_f64()) {
        cfg.tolerance = t as f32;
    }
    if let Some(arr) = obj.get("costs").and_then(|x| x.as_array()) {
        cfg.costs = arr
            .iter()
            .filter_map(|c| {
                let o = c.as_object()?;
                Some(StrategyWeight {
                    regexp: o.get("regexp").and_then(|v| v.as_bool()).unwrap_or(false),
                    r#match: o.get("match").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    value: o.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                })
            })
            .collect();
    }
    let mut buf = Vec::with_capacity(cfg.encoded_len());
    if prost::Message::encode(&cfg, &mut buf).is_err() {
        return None;
    }
    Some(xray_proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.router.StrategyLeastLoadConfig".to_string(),
        value: buf,
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
/// `xray.location.asset`（或 `XRAY_LOCATION_ASSET`）环境变量 → 可执行文件同目录。
/// 找不到 .dat 文件不影响 loader 创建（load 时 warn skip），仅影响 geoip/geosite 规则匹配。
fn resolve_asset_dir() -> std::path::PathBuf {
    xray_common::platform::get_resource_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试桩 handler：dispatch 即返回（SimpleOhm 注册用）。
    #[derive(Debug)]
    struct NullHandler(String);
    impl DispatchHandler for NullHandler {
        fn tag(&self) -> &str {
            &self.0
        }
        fn dispatch(
            &self,
            _dest: &Destination,
            _link: Link,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            Box::pin(std::future::ready(()))
        }
    }
    fn test_handler(tag: &str) -> Arc<dyn DispatchHandler> {
        Arc::new(NullHandler(tag.to_string()))
    }

    #[test]
    fn router_adapter_satisfies_routing_router() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        let adapter = RouterAdapter::new(r);
        let ctx = DispatcherContext::new().with_target_domain("test.com");
        let result = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx);
        assert!(result.is_err(), "empty router should return NoClue");
    }

    #[test]
    fn router_adapter_satisfies_dispatch_router() {
        use xray_common::net::network::Network;
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
        let adapter = RouterAdapter::new(r);
        let dest = Destination::new(
            Address::Domain("test".to_string()),
            Port::new(80),
            Network::TCP,
        );
        assert!(adapter.pick_outbound_tag(&dest).is_none());
    }

    #[test]
    fn router_adapter_debug_lists_rules() {
        let r = Router::empty(Arc::new(NotImplementedSelector), None);
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
    fn parse_routing_json_leastload_settings_serializes_to_typed_message() {
        // rttb：`strategy:{"type":"leastload", settings:{...}}` 必须把 settings
        // 序列化为 TypedMessage，否则消费端 build_balancer 走 default，
        // LeastLoad 调优参数全部静默回落。
        use prost::Message;
        let json = br#"{
            "balancers":[{
                "tag":"bl",
                "selector":["a","b"],
                "strategy":{
                    "type":"leastload",
                    "settings":{
                        "baselines":[100,200,300],
                        "expectedNodes":2,
                        "maxRTT":500,
                        "tolerance":0.5,
                        "costs":[{"match":"a","value":1.5},{"match":"b","value":2.0}]
                    }
                }
            }]
        }"#;
        let cfg = parse_routing_json_to_proto(json).expect("parse");
        let br = &cfg.balancing_rule[0];
        assert_eq!(br.strategy, "leastload");
        let ts = br.strategy_settings.as_ref().expect("strategy_settings must be Some");
        assert_eq!(ts.r#type, "xray.app.router.StrategyLeastLoadConfig");
        let cfg_decoded = xray_proto::xray::app::router::StrategyLeastLoadConfig::decode(ts.value.as_slice())
            .expect("decode");
        assert_eq!(cfg_decoded.baselines, vec![100, 200, 300]);
        assert_eq!(cfg_decoded.expected, 2);
        assert_eq!(cfg_decoded.max_rtt, 500);
        assert_eq!(cfg_decoded.costs.len(), 2);
        assert_eq!(cfg_decoded.costs[0].r#match, "a");
        assert!((cfg_decoded.costs[0].value - 1.5).abs() < 1e-5);

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
        async fn lookup_ip(
            &self,
            _domain: &str,
            _option: xray_features::dns::IpOption,
        ) -> Result<(Vec<std::net::IpAddr>, u32), xray_features::dns::DnsError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok((
                vec![std::net::IpAddr::V4("1.2.3.4".parse().expect("ip"))],
                60,
            ))
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

    // ---- balancer 策略 JSON 装配（h81 验收点）----

    /// JSON → RouterAdapter，传入 observer（h81：build_balancer 不再拒绝 leastping）。
    #[test]
    fn build_adapter_with_balancer_leastping_succeeds() {
        let json = br#"{
            "balancers":[{"tag":"bl","selector":["a","b","c"],"strategy":"leastping","fallbackTag":"fb"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let adapter = build_router_adapter_from_json_with_ohm(json, &SimpleOhm::new(), None)
            .expect("leastping balancer should build even without observer");
        // 没 observer → fallback
        let dest = Destination::new(
            Address::Domain("x.test".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        );
        assert_eq!(adapter.pick_outbound_tag(&dest).as_deref(), Some("fb"));
    }

    /// selector 适配器：SimpleOhm tagged handlers 按 selector 前缀匹配（Go
    /// `Manager.Select`），排序返回；random 策略在候选内均匀随机。
    #[test]
    fn build_adapter_with_ohm_random_strategy_picks_registered_tag() {
        let json = br#"{
            "balancers":[{"tag":"bl","selector":["proxy-"],"strategy":"random"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let ohm = SimpleOhm::new();
        ohm.add("proxy-a", test_handler("proxy-a"));
        ohm.add("proxy-b", test_handler("proxy-b"));
        ohm.add("direct", test_handler("direct"));
        let adapter = build_router_adapter_from_json_with_ohm(json, &ohm, None)
            .expect("random balancer with ohm should build");
        let dest = Destination::new(
            Address::Domain("x.test".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        );
        // "direct" 不匹配前缀 "proxy-"，永不选中；balancer 无 fallbackTag，
        // selector 返回空时才落 default——这里候选非空。
        for _ in 0..20 {
            let tag = adapter.pick_outbound_tag(&dest).expect("pick");
            assert!(
                tag == "proxy-a" || tag == "proxy-b",
                "unexpected tag {tag}"
            );
        }
    }

    /// JSON + observer 装配 → 命中最低延迟出站。
    #[test]
    fn build_adapter_with_balancer_leastping_and_observer_picks_least_delay() {
        use xray_app_router::balancing::ObservationProvider;

        struct InlineObs(xray_proto::xray::core::app::observatory::ObservationResult);
        impl ObservationProvider for InlineObs {
            fn get_observation(
                &self,
            ) -> Result<
                xray_proto::xray::core::app::observatory::ObservationResult,
                xray_app_router::RouterError,
            > {
                Ok(self.0.clone())
            }
        }
        let obs: Arc<dyn ObservationProvider> = Arc::new(InlineObs(
            xray_proto::xray::core::app::observatory::ObservationResult {
                status: vec![
                    xray_proto::xray::core::app::observatory::OutboundStatus {
                        outbound_tag: "a".into(),
                        alive: true,
                        delay: 100,
                        ..Default::default()
                    },
                    xray_proto::xray::core::app::observatory::OutboundStatus {
                        outbound_tag: "b".into(),
                        alive: true,
                        delay: 50,
                        ..Default::default()
                    },
                    xray_proto::xray::core::app::observatory::OutboundStatus {
                        outbound_tag: "c".into(),
                        alive: true,
                        delay: 200,
                        ..Default::default()
                    },
                ],
            },
        ));

        let json = br#"{
            "balancers":[{"tag":"bl","selector":["a","b","c"],"strategy":"leastping"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let adapter = build_router_adapter_from_json_with_ohm(json, &SimpleOhm::new(), Some(obs))
            .expect("leastping + observer should build");
        let dest = Destination::new(
            Address::Domain("x.test".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        );
        assert_eq!(adapter.pick_outbound_tag(&dest).as_deref(), Some("b"));
    }

    /// bridge_context 消费 route_target（Go `routing.Context.GetTarget`：
    /// RouteTarget 有效时优先于 Target——routeOnly 路由用嗅探域名）。
    #[test]
    fn pick_route_prefers_route_target_over_target() {
        let json = br#"{"rules":[{"outboundTag":"routed","domain":["sniffed.example.com"]}]}"#;
        let adapter = build_router_adapter_from_json(json).expect("build adapter");

        // routeOnly 形态：target 是 IP（无域名规则可命中），route_target 是嗅探域名。
        let mut ctx = DispatcherContext::new().with_target_port(Port::new(443));
        ctx.target_ips = vec![std::net::IpAddr::from([1, 2, 3, 4])];
        ctx.route_target = Some(Destination::new(
            Address::Domain("sniffed.example.com".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        ));
        let route = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx)
            .expect("route target domain rule should hit");
        assert_eq!(route.outbound_tag, "routed");

        // 无 route_target：仅 IP 的 ctx 不命中域名规则。
        let mut plain = DispatcherContext::new().with_target_port(Port::new(443));
        plain.target_ips = vec![std::net::IpAddr::from([1, 2, 3, 4])];
        assert!(<RouterAdapter as RoutingRouter>::pick_route(&adapter, &plain).is_err());
    }
}
