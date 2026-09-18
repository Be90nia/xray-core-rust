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
use std::pin::Pin;
use std::sync::Arc;

use xray_app_dispatcher::default::{
    AccessContext, DefaultDispatcher, DispatcherContext, ExcludeDomainMatcher,
    ExcludeIpMatcher, Route as DispRoute, RoutingContext as DispRoutingContext,
    RoutingRouter, SimpleOhm, SniffingRequest,
};
use xray_app_dispatcher::{maybe_wrap_reader, maybe_wrap_writer, DispatchHandler, DispatcherError};
use xray_mux::client::MUX_COOL_ADDRESS;
use xray_proto::xray::common::geodata::CidrRule;
use xray_app_router::balancing::{NotImplementedSelector, ObservationProvider, OutboundHandlerSelector};
use xray_app_router::context::RoutingData as RouterRoutingData;
use xray_app_router::error::RouterError;
use xray_app_router::Router;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_transport::link::Link;
use std::net::IpAddr;
use std::path::Path;
use xray_geodata::loader::GeoDataLoader;
use xray_geodata::matcher::domain::{self as geodata_domain, parse_domain as parse_geodata_domain};
use xray_geodata::matcher::ip::{GeneralMultiIPMatcher, HeuristicIPMatcher, IPMatcher as GeoIpMatcher};
use xray_geodata::matcher::{AnyMatcher, LinearAnyMatcher};
use xray_geodata::pb::domain_rule::Value as DomainRuleValue;
use xray_geodata::pb::ip_rule::Value as IpRuleValue;
use xray_geodata::rule_parser::{parse_domain_rule, parse_ip_rules};

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
/// destOverride 按 Go `SniffingConfig.Build`（infra/conf/xray.go:65-79）归一化：
/// 小写化 + `https`/`ssl` → `tls`、`fakedns+others` → `fakedns`（va51①：别名
/// 原样透传永不命中嗅探协议串）；未知值由 init.rs ValidationStage 硬拒，此处
/// 透传保持零行为差。domainsExcluded/ipsExcluded 经 geodata rule_parser 编译为
/// typed matcher（bd fv1g：字面量 contains / CIDR 静默滤掉的旧实现已废）。
/// 解析失败或无 sniffing 配置时返回 default（enabled=false，零行为变化）。
#[must_use]
pub fn sniffing_request_from_json(v: Option<&serde_json::Value>) -> SniffingRequest {
    sniffing_request_from_json_in(v, &resolve_asset_dir())
}

/// 同 [`sniffing_request_from_json`]，geodata 资产目录显式给定
/// （geoip:/geosite: 展开用；测试注入）。
fn sniffing_request_from_json_in(
    v: Option<&serde_json::Value>,
    datadir: &Path,
) -> SniffingRequest {
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
        override_destination_for_protocol: normalize_dest_override(&cfg.dest_override.0),
        exclude_for_domain: build_domain_excluder(&cfg.domains_excluded.0, datadir),
        exclude_for_ip: build_ip_excluder(&cfg.ips_excluded.0, datadir),
    }
}

/// destOverride 别名归一化（va51①，对照 Go `infra/conf/xray.go:65-79` switch）。
#[must_use]
fn normalize_dest_override(protocols: &[String]) -> Vec<String> {
    protocols
        .iter()
        .map(|p| match p.to_ascii_lowercase().as_str() {
            "tls" | "https" | "ssl" => "tls".to_string(),
            "fakedns" | "fakedns+others" => "fakedns".to_string(),
            _ => p.clone(),
        })
        .collect()
}

/// proto `Domain.Type`（Substr=0/Regex=1/Domain=2/Full=3）→ matcher 层
/// `DomainType`（Full=0/Domain=1/Substr=2/Regex=3）。两套编号不同序
/// （对照 xray-app-router `proto_domain_type_to_matcher`）。
fn proto_domain_type_to_matcher(t: i32) -> Option<geodata_domain::DomainType> {
    match t {
        0 => Some(geodata_domain::DomainType::Substr),
        1 => Some(geodata_domain::DomainType::Regex),
        2 => Some(geodata_domain::DomainType::Domain),
        3 => Some(geodata_domain::DomainType::Full),
        _ => None,
    }
}

/// 把 proto `Domain` 编译进 matcher（Full/Domain/Substr 值小写化、Regex 原样
/// —— Go `parseDomain` 同语义）。
fn add_proto_domain(
    any: &mut LinearAnyMatcher,
    rule_id: u32,
    d: &xray_geodata::Domain,
) -> Result<(), String> {
    let Some(dt) = proto_domain_type_to_matcher(d.r#type) else {
        return Err(format!("unknown domain type {}", d.r#type));
    };
    let m = parse_geodata_domain(&geodata_domain::DomainRule::new(
        dt,
        d.value.clone(),
        rule_id,
    ))
    .map_err(|e| e.to_string())?;
    any.add(m);
    Ok(())
}

/// domainsExcluded → typed matcher（Go `proxyman.BuildSniffingRequest` →
/// `DomainReg.BuildDomainMatcher` 等价物）。
///
/// 规则形态：full:/domain:/regexp:/keyword: 前缀，无前缀 = Substr，
/// geosite:/ext: 经 loader 展开为域名列表。单条失败 `warn` 跳过（Go 为
/// Build 期硬错；本函数签名无 Result 且调用方在票外，降级为可见告警，
/// 不静默吞）。
fn build_domain_excluder(rules: &[String], datadir: &Path) -> Option<Arc<ExcludeDomainMatcher>> {
    if rules.is_empty() {
        return None;
    }
    let loader = GeoDataLoader::new(datadir.to_path_buf());
    let mut any = LinearAnyMatcher::new();
    let mut added = 0u32;
    for raw in rules {
        let rule = match parse_domain_rule(raw, xray_geodata::geosite::DomainType::Substr, datadir)
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target: "xray_core",
                    "sniffing domainsExcluded {raw:?} 解析失败，跳过: {e}");
                continue;
            }
        };
        match rule.value {
            Some(DomainRuleValue::Custom(d)) => match add_proto_domain(&mut any, added + 1, &d) {
                Ok(()) => added += 1,
                Err(e) => tracing::warn!(target: "xray_core",
                    "sniffing domainsExcluded {raw:?} 编译失败，跳过: {e}"),
            },
            Some(DomainRuleValue::Geosite(gs)) => {
                let site = if gs.attrs.is_empty() {
                    loader.load_site(&gs.file, &gs.code)
                } else {
                    loader.load_site_with_attrs(&gs.file, &gs.code, &gs.attrs)
                };
                let site = match site {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "xray_core",
                            "sniffing domainsExcluded {raw:?} 加载 {}:{} 失败，跳过: {e}",
                            gs.file, gs.code);
                        continue;
                    }
                };
                for d in &site.domain {
                    match add_proto_domain(&mut any, added + 1, d) {
                        Ok(()) => added += 1,
                        Err(e) => tracing::warn!(target: "xray_core",
                            "sniffing geosite {}:{} 条目编译失败，跳过: {e}", gs.file, gs.code),
                    }
                }
            }
            None => {}
        }
    }
    if added == 0 {
        return None;
    }
    let any = Arc::new(any);
    Some(Arc::new(move |domain: &str| any.match_any(domain)))
}

/// ipsExcluded → typed matcher（Go `IPReg.BuildIPMatcher` 等价物）。
///
/// 形态：CIDR（`10.0.0.0/8`，无 `/` 按单地址）与 `geoip:XX`（loader 展开为
/// CIDR 列表），`!` 反向前缀由 rule_parser 转为 reverse_match。单条失败
/// `warn` 跳过（理由同 [`build_domain_excluder`]）。
fn build_ip_excluder(rules: &[String], datadir: &Path) -> Option<Arc<ExcludeIpMatcher>> {
    if rules.is_empty() {
        return None;
    }
    let loader = GeoDataLoader::new(datadir.to_path_buf());
    let mut matchers: Vec<Box<dyn GeoIpMatcher>> = Vec::new();
    for raw in rules {
        let rule = match parse_ip_rules(std::slice::from_ref(raw), datadir) {
            Ok(mut v) if v.len() == 1 => v.remove(0),
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(target: "xray_core",
                    "sniffing ipsExcluded {raw:?} 解析失败，跳过: {e}");
                continue;
            }
        };
        match rule.value {
            Some(IpRuleValue::Custom(cr)) => {
                if let Some(cidr) = cr.cidr {
                    let mut m = HeuristicIPMatcher::from_cidrs(&[cidr]);
                    if cr.reverse_match {
                        m.set_reverse(true);
                    }
                    matchers.push(Box::new(m));
                }
            }
            Some(IpRuleValue::Geoip(gr)) => match loader.load_ip(&gr.file, &gr.code) {
                Ok(geoip) => {
                    let mut m = HeuristicIPMatcher::from_cidrs(&geoip.cidr);
                    if gr.reverse_match {
                        m.set_reverse(true);
                    }
                    matchers.push(Box::new(m));
                }
                Err(e) => tracing::warn!(target: "xray_core",
                    "sniffing ipsExcluded {raw:?} 加载 {}:{} 失败，跳过: {e}",
                    gr.file, gr.code),
            },
            None => {}
        }
    }
    if matchers.is_empty() {
        return None;
    }
    let multi = Arc::new(GeneralMultiIPMatcher::new(matchers));
    Some(Arc::new(move |ip: IpAddr| multi.match_ip(ip)))
}

/// Mux carrier 拦截装饰器：对应 Go proxyman always.go:89 `mux: mux.NewServer(ctx)`
/// ——每个 inbound worker 的 dispatcher 统一被 mux.Server 装饰。
///
/// destination 为 `v1.mux.cool` 的 carrier 由 mux `ServerWorker` 接管解帧，
/// 子会话再经 inner dispatch；其余 destination 原样透传。判定仅按域名（与
/// Go mux.Server 一致，不校验端口：vless Mux command 的 port 恒 0，socks
/// CONNECT 载 carrier 才带 9527）。socks/http 已在各自协议层拦截，此处覆盖
/// vless/trojan/ss 等其余 inbound（bd raw0：vless 入站 mux 曾用臆造 0xFF
/// 首字节判别，真实帧必拒）。
pub struct MuxCarrierHandler {
    inner: Arc<dyn DispatchHandler>,
}

impl MuxCarrierHandler {
    /// 包装生产 inbound dispatch handler（通常为 [`InboundDispatchHandler`]）。
    #[must_use]
    pub fn new(inner: Arc<dyn DispatchHandler>) -> Self {
        Self { inner }
    }

    fn intercept(
        &self,
        dest: &Destination,
        link: Link,
        access: Option<AccessContext>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        if is_mux_carrier(dest) {
            tokio::spawn(crate::inbound::handle_mux_inbound_link(
                link,
                Arc::clone(&self.inner),
                access.as_ref().and_then(|a| a.allowed_network),
            ));
            return Box::pin(std::future::ready(()));
        }
        match access {
            Some(a) => self.inner.dispatch_with_access(dest, link, a),
            None => self.inner.dispatch(dest, link),
        }
    }
}

/// mux.cool 信令地址判定（仅按域名，对齐 Go mux.Server.Dispatch）。
fn is_mux_carrier(dest: &Destination) -> bool {
    matches!(dest.address(), Address::Domain(d) if d == MUX_COOL_ADDRESS)
}

impl std::fmt::Debug for MuxCarrierHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxCarrierHandler")
            .field("tag", &self.inner.tag())
            .finish()
    }
}

impl DispatchHandler for MuxCarrierHandler {
    fn tag(&self) -> &str {
        self.inner.tag()
    }

    fn dispatch(
        &self,
        dest: &Destination,
        link: Link,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.intercept(dest, link, None)
    }

    fn dispatch_with_access(
        &self,
        dest: &Destination,
        link: Link,
        access: AccessContext,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.intercept(dest, link, Some(access))
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
    ///
    /// sm80①：受 `ForSystem().Stats.Inbound{Uplink,Downlink}` 门控（Go
    /// proxyman/inbound/always.go:26,34——tag 计数与 per-user 计数的门不同，
    /// 后者才用 `ForLevel().Stats.User*`）。门关时不懒注册，默认全 false 不计数。
    fn inbound_counter(
        &self,
        direction: &str,
    ) -> Option<Arc<dyn xray_features::stats::Counter>> {
        let sys = self
            .dispatcher
            .policy_manager
            .as_ref()
            .map_or_else(xray_features::policy::SystemStats::default, |pm| {
                pm.for_system()
            });
        let enabled = match direction {
            "uplink" => sys.inbound_uplink,
            "downlink" => sys.inbound_downlink,
            _ => false,
        };
        if !enabled {
            return None;
        }
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
        let mut access = access;
        if let Some(a) = access.as_mut() {
            // splice 下行入站计数器随 access 抵达 splice 泵（Go proxy.go:765
            // writeCounter.Add 等价）：下行直达 raw fd 绕过下方 dn_r 包装。
            a.splice_down_in = self.inbound_counter("downlink");
        }
        // 本 link 由 socks 层以客户端 socket 双半部构造：reader 承载客户端
        // →远端（uplink）字节流，writer 承载远端→客户端（downlink）字节流，
        // 计数器必须按真实流向挂接（此前挂反：Linux splice 下行绕过 writer
        // 致 uplink 计数恒 0，Windows 全泵路径因四端全 >0 而掩盖互换）。
        // Go 对照：inbound uplink = conn ReadCounter（读客户端字节），
        // inbound downlink = conn WriteCounter（写客户端字节）。
        let reader = maybe_wrap_reader(self.inbound_counter("uplink"), link.reader);
        let writer = maybe_wrap_writer(self.inbound_counter("downlink"), link.writer);
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

/// JSON → proto `Config` 转换（Go `infra/conf/router.go` `parseFieldRule` +
/// `geodata.ParseDomainRules/ParseIPRules` 的等价物）：覆盖 `RoutingRule` 全部
/// 标量字段——domain（Go 前缀语法 full:/domain:/regexp:/keyword:/geosite:/ext:，
/// 无前缀 = Substr；另保留 Rust 扩展别名键 domainSuffix/domainKeyword/domainRegex）、
/// ip / source（CIDR / geoip: / ext-ip: / `!` 反向）、port、sourcePort、network、
/// protocol、user、inboundTag、attributes、process，以及顶层 `domainStrategy`、
/// `balancers`。
///
/// 对齐 Go 语义：规则解析失败（未知前缀形态 / 非法 CIDR / geoip.dat 缺失或
/// 缺 code）返回 Err，由调用方拒启（Go Build 失败即拒绝启动），不再静默丢规则。
///
/// `rule_set` 依赖 proto 更新（当前 `RoutingRule` 无该字段，见
/// `xray-app-router/src/rule_set.rs`），暂以 TODO 标记，待 proto 升级后接入。
fn parse_routing_json_to_proto(
    json: &[u8],
) -> Result<xray_proto::xray::app::router::Config, WiringError> {
    parse_routing_json_to_proto_in(json, &resolve_asset_dir())
}

/// 同 [`parse_routing_json_to_proto`]，geodata 资产目录显式给定（测试注入用）。
fn parse_routing_json_to_proto_in(
    json: &[u8],
    datadir: &std::path::Path,
) -> Result<xray_proto::xray::app::router::Config, WiringError> {
    use prost::Message;
    use xray_proto::xray::app::router::routing_rule::TargetTag;
    use xray_proto::xray::app::router::{BalancingRule, RoutingRule};
    use xray_proto::xray::common::geodata::{Domain, DomainRule};
    use xray_proto::xray::common::geodata::domain::Type as DT;
    use xray_proto::xray::common::geodata::domain_rule::Value as DV;

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
            let target_tag = if !outbound_tag.is_empty() {
                Some(TargetTag::Tag(outbound_tag.to_string()))
            } else if !balancer_tag.is_empty() {
                Some(TargetTag::BalancingTag(balancer_tag.to_string()))
            } else {
                // 对齐 Go router.go:170-171：双 tag 缺失直接报错拒启
                // （此前静默 continue 丢规则）。
                return Err(WiringError::JsonParse(
                    "neither outboundTag nor balancerTag is specified in routing rule".into(),
                ));
            };

            // Domain 规则：Go 前缀语法（full:/domain:/regexp:/keyword:/geosite:/ext:，
            // 无前缀 = Substr），geosite 条目经 check_file 校验 geodata 资产可用性。
            let mut domains = Vec::new();
            let domain_list: Vec<&str> = match r.get("domains").and_then(|x| x.as_array()) {
                // Go router.go:182-188：`domains` 键存在时覆盖 `domain`。
                // 非字符串项硬错（Go StringList 解码期拒启 / rule_parser.go
                // 逐条失败即拒），不再 filter_map 静默丢弃。
                Some(arr) => arr
                    .iter()
                    .map(|x| {
                        x.as_str().ok_or_else(|| {
                            WiringError::JsonParse(format!(
                                "routing rule domain entry is not a string: {x}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<&str>, WiringError>>()?,
                None => json_str_iter(r.get("domain")).collect(),
            };
            for d in domain_list {
                let pb_rule = xray_geodata::rule_parser::parse_domain_rule(
                    d,
                    xray_geodata::geosite::DomainType::Substr,
                    datadir,
                )
                .map_err(|e| {
                    WiringError::JsonParse(format!("routing rule domain '{d}': {e}"))
                })?;
                domains.push(geodata_domain_rule_to_proto(pb_rule));
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

            // 目标 / 源 IP：Go `geodata.ParseIPRules` 等价（CIDR / geoip: / ext-ip: /
            // `!` 反向）。解析失败硬错——旧实现 geoip:/非法 CIDR 静默跳过（安全
            // 屏蔽规则失效的根因）。
            let mut ips = Vec::new();
            for p in xray_geodata::rule_parser::parse_ip_rules(
                &json_string_list(r.get("ip")),
                datadir,
            )
            .map_err(|e| WiringError::JsonParse(format!("routing rule ip: {e}")))?
            {
                ips.push(geodata_ip_rule_to_proto(p));
            }

            // Go router.go:206-208：`sourceIP` 优先，缺省回退 `source`。
            let source_key = if r.get("sourceIP").is_some() { "sourceIP" } else { "source" };
            let mut source_ips = Vec::new();
            for p in xray_geodata::rule_parser::parse_ip_rules(
                &json_string_list(r.get(source_key)),
                datadir,
            )
            .map_err(|e| WiringError::JsonParse(format!("routing rule {source_key}: {e}")))?
            {
                source_ips.push(geodata_ip_rule_to_proto(p));
            }

            // Go router.go:222-232：localIP / localPort。
            let mut local_ips = Vec::new();
            for p in xray_geodata::rule_parser::parse_ip_rules(
                &json_string_list(r.get("localIP")),
                datadir,
            )
            .map_err(|e| WiringError::JsonParse(format!("routing rule localIP: {e}")))?
            {
                local_ips.push(geodata_ip_rule_to_proto(p));
            }


            cfg.rule.push(RoutingRule {
                target_tag,
                rule_tag: r.get("ruleTag").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                domain: domains,
                ip: ips,
                source_ip: source_ips,
                port_list: parse_port_list(r.get("port"))?,
                source_port_list: parse_port_list(r.get("sourcePort"))?,
                local_ip: local_ips,
                local_port_list: parse_port_list(r.get("localPort"))?,
                vless_route_list: parse_port_list(r.get("vlessRoute"))?,
                networks: parse_networks(r.get("network"))
                    .map_err(|e| WiringError::JsonParse(format!("routing rule network: {e}")))?,
                user_email: json_string_list(r.get("user")),
                // Go NewInboundTagMatcher/NewProtocolMatcher 构造器
                // （condition.go:207-215/:237-245）过滤空串——空串条目在
                // Rust 匹配器里前缀恒真，必须剔除。
                inbound_tag: json_string_list(r.get("inboundTag"))
                    .into_iter()
                    .filter(|t| !t.is_empty())
                    .collect(),
                protocol: json_string_list(r.get("protocol"))
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .collect(),
                process: json_string_list(r.get("process")),
                // Go a12801c1：`localOS` → local_os（匹配 runtime.GOOS）。
                local_os: json_string_list(r.get("localOS")),
                // 对齐 Go router.go:147 json 键 `attrs`（`attributes` 仅作
                // Rust 旧方言别名保留）。
                attributes: parse_attributes(
                    if r.get("attrs").is_some() { r.get("attrs") } else { r.get("attributes") },
                ),
                // 对齐 Go router.go:264-270：webhook → WebhookConfig。
                webhook: r.get("webhook").and_then(parse_webhook_config),
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
                // Go router.go:30-32：空 tag 拒启，不再 continue 跳过。
                return Err(WiringError::JsonParse("empty balancer tag".into()));
            }
            let (mut strategy, strategy_settings) = match b.get("strategy") {
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
            // Go router.go:35-41：ToLower；""→random；仅 4 个合法值，未知拒启。
            strategy = strategy.to_ascii_lowercase();
            match strategy.as_str() {
                "" => strategy = "random".to_string(),
                "random" | "leastload" | "leastping" | "roundrobin" => {}
                other => {
                    return Err(WiringError::JsonParse(format!(
                        "unknown balancing strategy: {other}"
                    )));
                }
            }
            let selectors = json_string_list(b.get("selector"));
            if selectors.is_empty() {
                // Go router.go:33-35：空 selector 列表拒启。
                return Err(WiringError::JsonParse("empty selector list".into()));
            }
            cfg.balancing_rule.push(BalancingRule {
                tag: tag.to_string(),
                outbound_selector: selectors,
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
/// 解析失败硬错（Go router.go:236-238 解码期拒启）——返回 `None` 会使规则
/// 端口约束静默失效（匹配所有端口）。
fn parse_port_list(
    v: Option<&serde_json::Value>,
) -> Result<Option<xray_proto::xray::common::net::PortList>, WiringError> {
    use xray_proto::xray::common::net::{PortList as ProtoPortList, PortRange as ProtoPortRange};
    let Some(v) = v else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let conf: xray_conf::PortList = serde_json::from_value(v.clone())
        .map_err(|e| WiringError::JsonParse(format!("routing port list: {e}")))?;
    if conf.is_empty() {
        return Ok(None);
    }
    Ok(Some(ProtoPortList {
        range: conf
            .0
            .iter()
            .map(|r| ProtoPortRange {
                from: u32::from(r.start),
                to: u32::from(r.end),
            })
            .collect(),
    }))
}

/// `webhook` 字段 → proto `WebhookConfig`（对齐 Go router.go:126-130/264-270：
/// `{url, deduplication, headers}`，url 为空则不构建）。
fn parse_webhook_config(v: &serde_json::Value) -> Option<xray_proto::xray::app::router::WebhookConfig> {
    let obj = v.as_object()?;
    let url = obj.get("url").and_then(|x| x.as_str()).unwrap_or("");
    if url.is_empty() {
        return None;
    }
    let headers = obj
        .get("headers")
        .and_then(|x| x.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, val)| {
                    let s = match val {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), s)
                })
                .collect()
        })
        .unwrap_or_default();
    Some(xray_proto::xray::app::router::WebhookConfig {
        url: url.to_string(),
        deduplication: obj.get("deduplication").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        headers,
    })
}

/// network 字段（`"tcp,udp"` 或字符串数组）→ proto `Network` i32 列表。
///
/// 未知 token 启动硬错：Go Network.Build（infra/conf/common.go:81-92）保留
/// Network_Unknown → matcher 永不命中（规则 fail-closed）；Rust 若静默丢
/// token 会得到空列表 → 不加 network 条件 → 规则变全网络匹配（fail-open，
/// 屏蔽规则断网/分流规则劫持全部流量）。硬错较 Go 更严且与同文件 ip/domain
/// 路径对称。
fn parse_networks(v: Option<&serde_json::Value>) -> Result<Vec<i32>, String> {
    use xray_proto::xray::common::net::Network;
    json_str_tokens(v).into_iter()
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Network::Tcp as i32),
            "udp" => Ok(Network::Udp as i32),
            "unix" => Ok(Network::Unix as i32),
            other => Err(format!("unknown network token '{other}'")),
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

/// `xray_geodata::pb`（crate 自建 proto）→ `xray_proto`（Go 同源 proto）字段级
/// 转换。两 crate 各自生成同名类型，与 `xray-app-router/src/rule.rs` 的
/// `convert_proto_ip_rules` 互为逆向方向。
fn geodata_ip_rule_to_proto(
    r: xray_geodata::pb::IpRule,
) -> xray_proto::xray::common::geodata::IpRule {
    use xray_geodata::pb::ip_rule::Value as GV;
    use xray_proto::xray::common::geodata::ip_rule::Value as PV;
    let value = r.value.map(|v| match v {
        GV::Geoip(g) => PV::Geoip(xray_proto::xray::common::geodata::GeoIpRule {
            file: g.file,
            code: g.code,
            reverse_match: g.reverse_match,
        }),
        GV::Custom(c) => PV::Custom(xray_proto::xray::common::geodata::CidrRule {
            cidr: c.cidr.map(|cc| xray_proto::xray::common::geodata::Cidr {
                ip: cc.ip,
                prefix: cc.prefix,
            }),
            reverse_match: c.reverse_match,
        }),
    });
    xray_proto::xray::common::geodata::IpRule { value }
}

/// 同 [`geodata_ip_rule_to_proto`]，Domain 方向（geosite 引用 / 自定义匹配型）。
fn geodata_domain_rule_to_proto(
    r: xray_geodata::pb::DomainRule,
) -> xray_proto::xray::common::geodata::DomainRule {
    use xray_geodata::pb::domain_rule::Value as GV;
    use xray_proto::xray::common::geodata::domain_rule::Value as PV;
    let value = r.value.map(|v| match v {
        GV::Geosite(g) => PV::Geosite(xray_proto::xray::common::geodata::GeoSiteRule {
            file: g.file,
            code: g.code,
            attrs: g.attrs,
        }),
        GV::Custom(d) => PV::Custom(xray_proto::xray::common::geodata::Domain {
            r#type: d.r#type,
            value: d.value,
            attribute: d
                .attribute
                .into_iter()
                .map(|a| xray_proto::xray::common::geodata::domain::Attribute {
                    key: a.key,
                    typed_value: a.typed_value.map(|t| match t {
                        xray_geodata::pb::domain::attribute::TypedValue::BoolValue(b) => {
                            xray_proto::xray::common::geodata::domain::attribute::TypedValue::BoolValue(b)
                        }
                        xray_geodata::pb::domain::attribute::TypedValue::IntValue(i) => {
                            xray_proto::xray::common::geodata::domain::attribute::TypedValue::IntValue(i)
                        }
                    }),
                })
                .collect(),
        }),
    });
    xray_proto::xray::common::geodata::DomainRule { value }
}

/// rttb：JSON `strategy.settings`（leastload 调优参数）→ `StrategyLeastLoadConfig`
/// proto bytes，再包成 `TypedMessage`。
///
/// JSON 键对齐 Go `infra/conf/router_strategy.go:33-98`：`costs`/`baselines`/
/// `expected`/`maxRTT`/`tolerance`（`expectedNodes` 为 Rust 旧方言别名保留）。
/// `baselines`/`maxRTT` 接受 Go duration 字符串（`"400ms"`）或纳秒数字——
/// 此前只认 `as_i64`，Go 文档式配置整体静默丢弃（cb0q）。
/// 编码失败 → `None`（消费端走默认，避免 hard-error 阻断整个 balancer）。
fn leastload_settings_to_typed_message(v: &serde_json::Value) -> Option<xray_proto::xray::common::serial::TypedMessage> {
    use prost::Message;
    use xray_proto::xray::app::router::{StrategyLeastLoadConfig, StrategyWeight};
    let obj = v.as_object()?;
    let mut cfg = StrategyLeastLoadConfig::default();
    if let Some(arr) = obj.get("baselines").and_then(|x| x.as_array()) {
        // Go router_strategy.go:92-98：非正值跳过。
        cfg.baselines = arr
            .iter()
            .filter_map(parse_duration_ns)
            .filter(|&ns| ns > 0)
            .collect();
    }
    // Go json 键 `expected`（router_strategy.go:39）；`expectedNodes` 为兼容别名。
    if let Some(n) = obj
        .get("expected")
        .or_else(|| obj.get("expectedNodes"))
        .and_then(|x| x.as_i64())
    {
        // Go router_strategy.go:85-87：负值归 0。
        cfg.expected = n.clamp(0, i32::MAX as i64) as i32;
    }
    if let Some(ns) = obj.get("maxRTT").and_then(parse_duration_ns) {
        // Go router_strategy.go:89-91：负值归 0。
        cfg.max_rtt = ns.max(0);
    }
    if let Some(t) = obj.get("tolerance").and_then(|x| x.as_f64()) {
        // Go router_strategy.go:78-83：clamp 到 [0, 1]。
        cfg.tolerance = t.clamp(0.0, 1.0) as f32;
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

/// Go `cfgcommon/duration.Duration`：JSON 数字 = 纳秒，字符串 = Go duration
/// 语法（`"300ms"` / `"1.5h"` / `"2h45m"`，支持 ns/us/ms/s/m/h；Go 的 `µs`
/// 记为 `us`）。无法解析 → `None`。
fn parse_duration_ns(v: &serde_json::Value) -> Option<i64> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        serde_json::Value::String(s) => parse_go_duration_str(s),
        _ => None,
    }
}

pub(crate) fn parse_go_duration_str(s: &str) -> Option<i64> {
    let neg = s.trim_start().starts_with('-');
    let s = s.trim().trim_start_matches(['-', '+']);
    let mut total: f64 = 0.0;
    let mut rest = s;
    while !rest.is_empty() {
        let idx = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
        if idx == 0 {
            return None;
        }
        let num: f64 = rest[..idx].parse().ok()?;
        rest = &rest[idx..];
        let (mult, next) = if let Some(r) = rest.strip_prefix("ns") {
            (1.0, r)
        } else if let Some(r) = rest.strip_prefix("us") {
            (1e3, r)
        } else if let Some(r) = rest.strip_prefix("ms") {
            (1e6, r)
        } else if let Some(r) = rest.strip_prefix('s') {
            (1e9, r)
        } else if let Some(r) = rest.strip_prefix('m') {
            (6e10, r)
        } else if let Some(r) = rest.strip_prefix('h') {
            (3.6e12, r)
        } else {
            return None;
        };
        total += num * mult;
        rest = next;
    }
    if s.is_empty() {
        return None;
    }
    let v = total as i64;
    Some(if neg { -v } else { v })
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
    fn parse_routing_json_missing_both_tags_errors() {
        // 对齐 Go router.go:170-171：双 tag 缺失报错拒启（此前静默丢规则）。
        let json = br#"{"rules":[{"domain":["x.com"]}]}"#;
        let err = build_router_adapter_from_json(json).unwrap_err();
        assert!(
            err.to_string().contains("neither outboundTag nor balancerTag"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_routing_json_covers_2wse_fields() {
        // 对齐 Go infra/conf/router.go:132-273：ruleTag/localIP/localPort/
        // vlessRoute/attrs/webhook/sourceIP 别名。
        let json = br#"{
            "rules": [{
                "ruleTag": "rt1",
                "outboundTag": "proxy",
                "sourceIP": ["10.1.0.0/16"],
                "localIP": ["127.0.0.0/8"],
                "localPort": "8000-9000",
                "vlessRoute": "100-200",
                "attrs": {"env": "prod"},
                "webhook": {"url": "http://127.0.0.1:9911/hook", "deduplication": 3,
                            "headers": {"X-Test": "v"}}
            }]
        }"#;
        let cfg = parse_routing_json_to_proto(json).expect("parse");
        let rule = &cfg.rule[0];
        assert_eq!(rule.rule_tag, "rt1");
        assert_eq!(rule.local_ip.len(), 1, "localIP must parse");
        assert!(rule.local_port_list.is_some(), "localPort must parse");
        assert!(rule.vless_route_list.is_some(), "vlessRoute must parse");
        assert_eq!(rule.attributes.get("env").map(String::as_str), Some("prod"),
            "attrs 键必须被识别");
        let wh = rule.webhook.as_ref().expect("webhook must build");
        assert_eq!(wh.url, "http://127.0.0.1:9911/hook");
        assert_eq!(wh.deduplication, 3);
        assert_eq!(wh.headers.get("X-Test").map(String::as_str), Some("v"));
        // sourceIP 别名（而非 source）落入 source_ip。
        assert_eq!(rule.source_ip.len(), 1);
    }

    #[test]
    fn parse_routing_json_attrs_alias_keeps_attributes_fallback() {
        // attrs 优先；仅 attributes（旧方言）时仍回退可用，不破坏既有配置。
        let json = br#"{"rules":[{"outboundTag":"p","attributes":{"a":"1"}}]}"#;
        let cfg = parse_routing_json_to_proto(json).expect("parse");
        assert_eq!(cfg.rule[0].attributes.get("a").map(String::as_str), Some("1"));
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
    fn parse_routing_json_local_os_goos_match() {
        // Go a12801c1：`localOS` → proto local_os；匹配链以 runtime.GOOS 断言。
        let os = std::env::consts::OS;
        let json = format!(r#"{{"rules":[{{"outboundTag":"direct","localOS":["{os}"]}}]}}"#);
        let cfg = parse_routing_json_to_proto(json.as_bytes()).expect("parse");
        assert_eq!(cfg.rule[0].local_os, vec![os.to_string()]);
        let cond = xray_app_router::rule::build_condition(&cfg.rule[0], None).unwrap();
        assert!(
            cond.apply(&xray_app_router::context::RoutingData::new()),
            "本机 OS {os} 必须命中"
        );

        // 他 OS 名：规则仍合法（Go BuildCondition 同样构造恒假 matcher，配置可启动，
        // 仅规则永不命中）——不做编译期剔除。
        let wrong = if os == "windows" { "darwin" } else { "windows" };
        let json2 = format!(r#"{{"rules":[{{"outboundTag":"direct","localOS":["{wrong}"]}}]}}"#);
        let cfg2 = parse_routing_json_to_proto(json2.as_bytes()).expect("parse other os");
        let cond2 = xray_app_router::rule::build_condition(&cfg2.rule[0], None).unwrap();
        assert!(!cond2.apply(&xray_app_router::context::RoutingData::new()));
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
    fn parse_routing_json_leastload_official_keys_and_durations() {
        // cb0q：Go 文档式 leastload settings——`expected` 键 + duration 字符串
        // （"400ms"→4e5 纳秒），此前 expected 丢/baselines+maxRTT 字符串整体丢弃。
        use prost::Message;
        let json = br#"{
            "balancers":[{
                "tag":"bl",
                "selector":["a"],
                "strategy":{"type":"leastload","settings":{
                    "expected":6,
                    "baselines":["400ms","1s"],
                    "maxRTT":"1000ms",
                    "tolerance":1.5
                }}
            }]
        }"#;
        let cfg = parse_routing_json_to_proto(json).expect("parse");
        let ts = cfg.balancing_rule[0].strategy_settings.as_ref().expect("settings");
        let decoded = xray_proto::xray::app::router::StrategyLeastLoadConfig::decode(ts.value.as_slice())
            .expect("decode");
        assert_eq!(decoded.expected, 6, "官方 expected 键必须生效");
        assert_eq!(decoded.baselines, vec![400_000_000, 1_000_000_000],
            "duration 字符串必须转纳秒");
        assert_eq!(decoded.max_rtt, 1_000_000_000);
        // Go router_strategy.go:81-83：tolerance clamp 到 1。
        assert!((decoded.tolerance - 1.0).abs() < 1e-5, "tolerance 必须 clamp 到 [0,1]");
    }

    #[test]
    fn parse_duration_ns_go_syntax() {
        // Go duration 语法（cfgcommon/duration）：数字=纳秒；字符串支持单位拼接。
        assert_eq!(parse_duration_ns(&serde_json::json!(500)), Some(500));
        assert_eq!(parse_duration_ns(&serde_json::json!("400ms")), Some(400_000_000));
        assert_eq!(parse_duration_ns(&serde_json::json!("1s")), Some(1_000_000_000));
        assert_eq!(parse_duration_ns(&serde_json::json!("2h45m")), Some(9_900_000_000_000));
        assert_eq!(parse_duration_ns(&serde_json::json!("1.5h")), Some(5_400_000_000_000));
        assert_eq!(parse_duration_ns(&serde_json::json!("junk")), None);
        assert_eq!(parse_duration_ns(&serde_json::json!(true)), None);
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

    // ---- 路由 JSON Go 前缀语法（rs3e）----

    /// 伪造 geoip.dat（GeoIpList protobuf，与 xray-app-router 测试同配方）。
    fn make_geoip_dat() -> Vec<u8> {
        use prost::Message;
        use xray_proto::xray::common::geodata::{Cidr, GeoIp, GeoIpList};
        let private = GeoIp {
            code: "PRIVATE".into(),
            cidr: vec![
                Cidr { ip: vec![10, 0, 0, 0], prefix: 8 },
                Cidr { ip: vec![192, 168, 0, 0], prefix: 16 },
                Cidr { ip: vec![127, 0, 0, 0], prefix: 8 },
            ],
            reverse_match: false,
        };
        let cn = GeoIp {
            code: "CN".into(),
            cidr: vec![Cidr { ip: vec![1, 2, 3, 0], prefix: 24 }],
            reverse_match: false,
        };
        GeoIpList { entry: vec![private, cn] }.encode_to_vec()
    }

    /// 伪造 geosite.dat（GeoSiteList protobuf，code CN）。
    fn make_geosite_dat() -> Vec<u8> {
        use prost::Message;
        use xray_proto::xray::common::geodata::{Domain, GeoSite, GeoSiteList};
        let cn = GeoSite {
            code: "CN".into(),
            domain: vec![
                Domain { r#type: 2, value: "baidu.com".into(), attribute: vec![] },
                Domain { r#type: 3, value: "example.cn".into(), attribute: vec![] },
            ],
        };
        GeoSiteList { entry: vec![cn] }.encode_to_vec()
    }

    /// 独立临时资产目录（进程级唯一，测试间互不干扰）。
    fn temp_asset_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xray-wiring-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp asset dir");
        dir
    }

    /// Go 官方样例前缀形态逐项断言 proto 字段（Go 对照 infra/conf/router.go
    /// `parseFieldRule` → `geodata.ParseDomainRules(s, Domain_Substr)` /
    /// `ParseIPRules`）：full:/domain:/regexp:/keyword:/geosite:/无前缀=Substr、
    /// CIDR/geoip:/ext-ip:/`!` 反向，以及 Rust 别名键兼容。
    #[test]
    fn parse_routing_json_go_prefix_forms() {
        use xray_proto::xray::common::geodata::domain_rule::Value as DV;
        use xray_proto::xray::common::geodata::ip_rule::Value as IV;

        let dir = temp_asset_dir("prefix-forms");
        std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
        std::fs::write(dir.join("geosite.dat"), make_geosite_dat()).unwrap();

        let json = br#"{
            "rules": [{
                "outboundTag": "proxy",
                "domain": ["full:example.com", "domain:x.example.com",
                           "regexp:^mail\\.example\\.com$", "keyword:ads",
                           "geosite:cn", "plain.example.com"],
                "domainSuffix": ["alias-suffix.example"],
                "domainKeyword": ["alias-keyword"],
                "domainRegex": ["^alias-regex$"],
                "ip": ["geoip:private", "10.0.0.0/8", "ext-ip:geoip.dat:cn"],
                "source": ["!192.168.0.0/16"]
            }]
        }"#;
        let cfg = parse_routing_json_to_proto_in(json, &dir).expect("parse");

        assert_eq!(cfg.rule.len(), 1);
        let rule = &cfg.rule[0];

        // domain：6 条 Go 形态 + 3 条 Rust 别名
        assert_eq!(rule.domain.len(), 9);
        let custom = |i: usize| match rule.domain[i].value.as_ref() {
            Some(DV::Custom(c)) => c,
            _ => panic!("domain[{i}] expected custom"),
        };
        assert_eq!(custom(0).r#type, 3, "full: → Full");
        assert_eq!(custom(0).value, "example.com");
        assert_eq!(custom(1).r#type, 2, "domain: → Domain(suffix)");
        assert_eq!(custom(1).value, "x.example.com");
        assert_eq!(custom(2).r#type, 1, "regexp: → Regex");
        assert_eq!(custom(2).value, r"^mail\.example\.com$");
        assert_eq!(custom(3).r#type, 0, "keyword: → Substr");
        assert_eq!(custom(3).value, "ads");
        match rule.domain[4].value.as_ref() {
            Some(DV::Geosite(g)) => {
                assert_eq!(g.file, "geosite.dat");
                assert_eq!(g.code, "CN", "geosite code 转大写");
            }
            _ => panic!("domain[4] expected geosite reference"),
        }
        assert_eq!(custom(5).r#type, 0, "无前缀 → Substr（Go 默认）");
        assert_eq!(custom(5).value, "plain.example.com");
        assert_eq!(custom(6).r#type, 2, "domainSuffix 别名 → Domain");
        assert_eq!(custom(7).r#type, 0, "domainKeyword 别名 → Substr");
        assert_eq!(custom(8).r#type, 1, "domainRegex 别名 → Regex");

        // ip：geoip 引用 / CIDR / ext-ip
        assert_eq!(rule.ip.len(), 3);
        match rule.ip[0].value.as_ref() {
            Some(IV::Geoip(g)) => {
                assert_eq!(g.file, "geoip.dat");
                assert_eq!(g.code, "PRIVATE");
                assert!(!g.reverse_match);
            }
            _ => panic!("ip[0] expected geoip reference"),
        }
        match rule.ip[1].value.as_ref() {
            Some(IV::Custom(c)) => {
                let cidr = c.cidr.as_ref().expect("cidr");
                assert_eq!(cidr.ip, vec![10, 0, 0, 0]);
                assert_eq!(cidr.prefix, 8);
                assert!(!c.reverse_match);
            }
            _ => panic!("ip[1] expected custom CIDR"),
        }
        match rule.ip[2].value.as_ref() {
            Some(IV::Geoip(g)) => assert_eq!(g.code, "CN", "ext-ip:file:code"),
            _ => panic!("ip[2] expected ext-ip geoip reference"),
        }

        // source：`!` 反向 CIDR
        assert_eq!(rule.source_ip.len(), 1);
        match rule.source_ip[0].value.as_ref() {
            Some(IV::Custom(c)) => {
                assert_eq!(c.cidr.as_ref().expect("cidr").prefix, 16);
                assert!(c.reverse_match, "! 前缀 → reverse_match");
            }
            _ => panic!("source expected custom CIDR"),
        }
    }

    /// 解析失败必须硬错（对齐 Go Build 拒启）——旧实现对 geoip:/非法 CIDR
    /// 静默 continue，屏蔽类安全规则整条蒸发。
    #[test]
    fn parse_routing_json_bad_rules_hard_error() {
        let dir = temp_asset_dir("hard-error");
        std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
        std::fs::write(dir.join("geosite.dat"), make_geosite_dat()).unwrap();

        // geoip: code 不存在
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["geoip:nonexistent"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");

        // 非法 IP 字面（旧实现静默 skip 的形态）
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["300.1.2.3"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");

        // geosite: code 不存在
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["geosite:nonexistent"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");

        // geoip.dat 整体缺失 → 拒启（Go：Build 期 load 失败即拒启）
        let nodat = temp_asset_dir("hard-error-nodat");
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["geoip:private"]}]}"#,
            &nodat,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");

        // 对照：无前缀 domain 与纯 CIDR 不需要 geodata 资产
        parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["ok.example"],"ip":["1.2.3.4"]}]}"#,
            &nodat,
        )
        .expect("plain rules must not require geodata assets");
    }

    /// vrll⑤：routing 端口字段解析失败硬错（Go router.go:236-238 解码期拒启）
    /// ——旧实现 `.ok()?` 吞错 → None → 规则端口约束静默失效。
    #[test]
    fn parse_port_list_invalid_rejected_valid_ok() {
        // 非法：字符串 "abc" / 对象形态。
        for bad in [
            serde_json::json!("abc"),
            serde_json::json!({"port": 80}),
        ] {
            let err = super::parse_port_list(Some(&bad)).err().expect("must reject");
            assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");
        }
        // 合法：数字 / "80,443-53" 混合 / 缺失与 null → None。
        assert!(super::parse_port_list(None).unwrap().is_none());
        assert!(super::parse_port_list(Some(&serde_json::Value::Null)).unwrap().is_none());
        let ok = super::parse_port_list(Some(&serde_json::json!("80,443"))).unwrap().expect("ports");
        assert_eq!(ok.range.len(), 2);
    }

    /// vrll⑤ + uasr②：balancer 空 tag / 空 selector / 未知 strategy 硬错
    /// （Go router.go:30-41）；合法 balancer 通过且 strategy 规范化 random。
    #[test]
    fn balancer_config_hard_errors_and_normalization() {
        let dir = temp_asset_dir("balancer-hard");
        // 空 tag。
        let err = parse_routing_json_to_proto_in(
            br#"{"balancers":[{"selector":["a"]}],"rules":[{"balancerTag":"x","outboundTag":""}]}"#,
            &dir,
        )
        .err()
        .expect("empty tag must reject");
        assert!(err.to_string().contains("empty balancer tag"), "{err:?}");
        // 空 selector 列表。
        let err = parse_routing_json_to_proto_in(
            br#"{"balancers":[{"tag":"bl","selector":[]}]}"#,
            &dir,
        )
        .err()
        .expect("empty selector must reject");
        assert!(err.to_string().contains("empty selector list"), "{err:?}");
        // 未知 strategy。
        let err = parse_routing_json_to_proto_in(
            br#"{"balancers":[{"tag":"bl","selector":["a"],"strategy":{"type":"diceroll"}}]}"#,
            &dir,
        )
        .err()
        .expect("unknown strategy must reject");
        assert!(err.to_string().contains("unknown balancing strategy"), "{err:?}");
        // 合法 + 空缺省 strategy 规范化为 random。
        let cfg = parse_routing_json_to_proto_in(
            br#"{"balancers":[{"tag":"bl","selector":["a"]}]}"#,
            &dir,
        )
        .expect("valid balancer");
        assert_eq!(cfg.balancing_rule.len(), 1);
        assert_eq!(cfg.balancing_rule[0].strategy, "random");
    }

    /// 补票②：rules JSON domain 数组非字符串项硬错（Go StringList 解码期
    /// 拒启 / rule_parser 逐条失败即拒），不再 filter_map 静默丢弃。
    #[test]
    fn routing_domain_non_string_entry_rejected() {
        let dir = temp_asset_dir("domain-nonstring");
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domains":["ok.example",123]}]}"#,
            &dir,
        )
        .err()
        .expect("must reject");
        assert!(
            err.to_string().contains("domain entry is not a string"),
            "{err:?}"
        );
    }

    /// 补票①：inboundTag / protocol 空串条目过滤（Go condition.go:207-215 /
    /// :237-245 构造器语义——空串在 Rust 匹配器里前缀恒真）。
    #[test]
    fn routing_empty_string_tags_filtered() {
        let dir = temp_asset_dir("empty-tag-filter");
        let cfg = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","inboundTag":["in-1","","in-2"],"protocol":["","http"]}]}"#,
            &dir,
        )
        .expect("empty strings filtered, not fatal");
        assert_eq!(cfg.rule.len(), 1);
        assert_eq!(cfg.rule[0].inbound_tag, vec!["in-1".to_string(), "in-2".to_string()]);
        assert_eq!(cfg.rule[0].protocol, vec!["http".to_string()]);
    }

    /// 回归（bd yqm9）：未知 network token 硬错拒启。静默丢 token 会得到空
    /// 列表 → 不加 network 条件 → 规则变全网络匹配（fail-open：屏蔽规则断网/
    /// 分流规则劫持全部流量）。Go Network.Build（infra/conf/common.go:81-92）
    /// fail-closed（Unknown 永不命中），Rust 以启动硬错呈现，与同文件 ip/domain
    /// 硬错路径对称。
    #[test]
    fn parse_routing_json_unknown_network_token_hard_error() {
        let err = build_router_adapter_from_json(
            br#"{"rules":[{"outboundTag":"b","network":"tpc"}]}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown network token 'tpc'"),
            "unexpected error: {err}"
        );

        // 正常 token（大小写混合、逗号串）不受影响。
        use xray_proto::xray::common::net::Network;
        let cfg = parse_routing_json_to_proto(
            br#"{"rules":[{"outboundTag":"b","network":"TCP,udp"}]}"#,
        )
        .expect("valid tokens must pass");
        assert_eq!(
            cfg.rule[0].networks,
            vec![Network::Tcp as i32, Network::Udp as i32]
        );
    }

    // ---- sniffing_request_from_json（bd fv1g：domainsExcluded/ipsExcluded typed matcher）----

    /// Go 官方样例形态（infra/conf/xray_test.go:163-165）：full:/domain:/regexp:/
    /// 单 IP + CIDR，另加 keyword: 值小写化断言。纯 Custom 规则不触盘。
    #[test]
    fn sniffing_exclusions_four_forms_and_case_folding() {
        let json = serde_json::json!({
            "enabled": true,
            "destOverride": ["http", "tls"],
            "domainsExcluded": [
                "full:api.example.com",
                "domain:blocked.example",
                "regexp:^test[0-9]+\\.internal$",
                "keyword:ADS"
            ],
            "ipsExcluded": ["192.168.1.1", "2001:db8::/32"]
        });
        let req = sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"));
        assert!(req.enabled);
        let dom = req.exclude_for_domain.expect("domain matcher built");
        // full: 精确匹配（非后缀）
        assert!(dom("api.example.com"));
        assert!(!dom("sub.api.example.com"));
        // domain: 域名后缀（label 对齐，非子串）
        assert!(dom("blocked.example"));
        assert!(dom("www.blocked.example"));
        assert!(!dom("blocked.example.com"));
        assert!(!dom("xblocked.example"));
        // regexp: 正则（Go 把 ToLower 后的输入交给 matcher）
        assert!(dom("test42.internal"));
        assert!(!dom("test-42.internal"));
        // keyword: 子串；规则值 "ADS" 必须小写化为 "ads"（大小写混合断言）
        assert!(dom("www.ads.example.com"));
        assert!(!dom("example.org"));
        // IP：单地址形态（无 / 前缀）
        let ipm = req.exclude_for_ip.expect("ip matcher built");
        assert!(ipm("192.168.1.1".parse().unwrap()));
        assert!(!ipm("192.168.1.2".parse().unwrap()));
        // IP：CIDR 形态（此前被静默滤掉）
        assert!(ipm("2001:db8:aa::1".parse().unwrap()));
        assert!(!ipm("2001:db9::1".parse().unwrap()));
    }

    /// geoip: 前缀经 loader 展开为 CIDR（Go ParseIPRules → matcher 同路径）。
    #[test]
    fn sniffing_ip_exclude_geoip_expansion() {
        let dir = temp_asset_dir("sniff-geoip");
        std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
        let json = serde_json::json!({
            "enabled": true,
            "ipsExcluded": ["geoip:private"]
        });
        let req = sniffing_request_from_json_in(Some(&json), &dir);
        let ipm = req.exclude_for_ip.expect("geoip matcher built");
        assert!(ipm("10.1.2.3".parse().unwrap()));
        assert!(ipm("192.168.5.5".parse().unwrap()));
        assert!(ipm("127.0.0.1".parse().unwrap()));
        assert!(!ipm("8.8.8.8".parse().unwrap()));
    }

    /// 单条坏规则 warn 跳过、其余保留（Go 为 Build 期硬错；本函数签名无
    /// Result 且调用方在票外，降级为可见告警，不静默吞、不整表作废）。
    #[test]
    fn sniffing_exclusions_bad_rule_skipped_others_kept() {
        let json = serde_json::json!({
            "enabled": true,
            "domainsExcluded": ["full:good.example", "regexp:([bad"],
            "ipsExcluded": ["not-an-ip", "10.0.0.0/8"]
        });
        let req = sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"));
        let dom = req.exclude_for_domain.expect("good rule kept");
        assert!(dom("good.example"));
        assert!(!dom("anything-else"));
        let ipm = req.exclude_for_ip.expect("good cidr kept");
        assert!(ipm("10.1.2.3".parse().unwrap()));
        assert!(!ipm("11.1.2.3".parse().unwrap()));
    }

    /// 无排除配置 → matcher 为 None（Go nil），enabled 等字段照常透传。
    #[test]
    fn sniffing_no_exclusions_yields_none_matchers() {
        let json = serde_json::json!({ "enabled": true, "destOverride": ["http"] });
        let req = sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"));
        assert!(req.enabled);
        assert!(req.exclude_for_domain.is_none());
        assert!(req.exclude_for_ip.is_none());
        let none = sniffing_request_from_json_in(None, Path::new("/nonexistent"));
        assert!(!none.enabled);
        assert!(none.exclude_for_domain.is_none());
        assert!(none.exclude_for_ip.is_none());
    }

    /// va51①（Go infra/conf/xray.go:65-79）：destOverride 别名归一化——
    /// https/ssl/TLS → tls，fakedns+others → fakedns，小写化；已知直通不变。
    #[test]
    fn sniffing_dest_override_aliases_normalized() {
        let json = serde_json::json!({
            "enabled": true,
            "destOverride": ["https", "ssl", "TLS", "fakedns+others", "http", "quic"]
        });
        let req = sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"));
        assert_eq!(
            req.override_destination_for_protocol,
            ["tls", "tls", "tls", "fakedns", "http", "quic"]
        );
    }

    /// sm80①：wiring 层 inbound tag counter 受 ForSystem().Stats.Inbound*
    /// 门控（Go proxyman/inbound/always.go:26,34）——默认（无 policy manager）
    /// 不注册；mock 开启 inbound 两门后按方向注册。
    #[test]
    fn inbound_counter_gated_by_for_system() {
        struct InboundOnPm;
        impl xray_features::policy::PolicyManager for InboundOnPm {
            fn policy_for_level(&self, _level: u32) -> xray_features::policy::Policy {
                xray_features::policy::Policy::default()
            }
            fn for_system(&self) -> xray_features::policy::SystemStats {
                xray_features::policy::SystemStats {
                    inbound_uplink: true,
                    inbound_downlink: true,
                    ..Default::default()
                }
            }
        }

        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        d.stats = Some(stats);
        // 默认（无 pm）：两方向都不注册
        let h = InboundDispatchHandler::new(Arc::new(d), SniffingRequest::default(), "gated-in");
        assert!(h.inbound_counter("uplink").is_none(), "default: inbound counter must be gated off");
        assert!(h.inbound_counter("downlink").is_none(), "default: inbound counter must be gated off");

        // 开启 inbound 两门：按方向注册
        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        d.stats = Some(stats);
        d.set_policy_manager(Arc::new(InboundOnPm));
        let h = InboundDispatchHandler::new(Arc::new(d), SniffingRequest::default(), "gated-in");
        assert!(h.inbound_counter("uplink").is_some(), "inbound_uplink on: counter must register");
        assert!(h.inbound_counter("downlink").is_some(), "inbound_downlink on: counter must register");
    }
}
