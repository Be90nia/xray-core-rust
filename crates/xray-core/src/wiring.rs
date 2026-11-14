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
//! router 端 `get_vless_route() -> Port`。适配时把字符串解析为 Port（空串 → 0）。

use std::{collections::HashMap, future::Future, net::IpAddr, path::Path, pin::Pin, sync::Arc};

use xray_app_dispatcher::{
    DispatchHandler, DispatcherError,
    default::{
        AccessContext, DefaultDispatcher, ExcludeDomainMatcher, ExcludeIpMatcher,
        Route as DispRoute, RoutingContext as DispRoutingContext, RoutingRouter, SimpleOhm,
        SniffingRequest,
    },
    maybe_wrap_reader, maybe_wrap_writer,
};
use xray_app_router::{
    Router,
    balancing::{ObservationProvider, OutboundHandlerSelector},
    context::{RoutingContext as RouterRoutingContext, RoutingData as RouterRoutingData},
    error::RouterError,
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_geodata::{
    loader::GeoDataLoader,
    matcher::{
        AnyMatcher, LinearAnyMatcher,
        domain::{self as geodata_domain, parse_domain as parse_geodata_domain},
        ip::{GeneralMultiIPMatcher, HeuristicIPMatcher, IPMatcher as GeoIpMatcher},
    },
    pb::{domain_rule::Value as DomainRuleValue, ip_rule::Value as IpRuleValue},
    rule_parser::{parse_domain_rule, parse_ip_rules},
};
use xray_mux::client::MUX_COOL_ADDRESS;
use xray_transport::link::Link;

/// 把 `xray_app_router::Router` 暴露为 dispatcher 的 [`RoutingRouter`]。
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
        f.debug_struct("RouterAdapter").field("rules", &self.router.list_rules()).finish()
    }
}

/// dispatcher `RoutingContext` → router `RoutingContext` 的**零拷贝**借用桥。
///
/// 旧 `bridge_context` 每次路由把上下文深拷贝进 owned `RoutingData`（3×to_vec +
/// 4×to_string + attributes.clone，每连接 4-8 次堆分配）；本视图只持有
/// `&dyn DispRoutingContext`，getter 纯转发——router matcher 消费面本就是
/// `&dyn RoutingContext` 对象安全借用接口，无需 owned 数据。
///
/// RouteTarget 覆盖（Go `routing.Context.GetTarget`：`RouteTarget` 有效时优先，
/// routeOnly 路由用嗅探域名、拨号保持原 dest）在 getter 内即时生效，逐字段等价旧拷贝：
/// - `rt` 带 IP：`target_ips` 单元素覆盖、`target_domain` 清空；
/// - `rt` 无 IP（routeOnly，Go default.go:311-315）：`target_domain` 用 rt 域名， `GetTargetIPs`
///   仍读原 Target（features/routing/session/context.go:47-57）， IP/geoip 规则照常命中；
/// - 两态 `target_port` 均取 `rt.port()`。
struct BridgeCtx<'a> {
    ctx: &'a dyn DispRoutingContext,
    rt: Option<&'a Destination>,
    /// `rt.address().ip()` 预取：`get_target_ips` 返回借用切片，临时值不能落在栈上。
    rt_ip: Option<IpAddr>,
}

impl<'a> BridgeCtx<'a> {
    fn new(ctx: &'a dyn DispRoutingContext) -> Self {
        let rt = ctx.get_route_target();
        let rt_ip = rt.and_then(|d| d.address().ip());
        Self { ctx, rt, rt_ip }
    }
}

impl RouterRoutingContext for BridgeCtx<'_> {
    fn get_target_ips(&self) -> &[IpAddr] {
        match &self.rt_ip {
            Some(ip) => std::slice::from_ref(ip),
            None => self.ctx.get_target_ips(),
        }
    }

    fn get_target_domain(&self) -> &str {
        match self.rt {
            Some(rt) => match rt.address().ip() {
                Some(_) => "",
                None => rt.address().as_domain().unwrap_or(""),
            },
            None => self.ctx.get_target_domain(),
        }
    }

    fn get_target_port(&self) -> Port {
        match self.rt {
            Some(rt) => rt.port(),
            None => self.ctx.get_target_port(),
        }
    }

    fn get_source_ips(&self) -> &[IpAddr] {
        self.ctx.get_source_ips()
    }

    fn get_source_port(&self) -> Port {
        self.ctx.get_source_port()
    }

    fn get_local_ips(&self) -> &[IpAddr] {
        self.ctx.get_local_ips()
    }

    fn get_local_port(&self) -> Port {
        self.ctx.get_local_port()
    }

    /// dispatcher 端 vless_route 是 &str（Go `net.Port` 的字符串形态），router 端是
    /// Port。未填充（空串）时解析失败回落 0，等价 Go Port 零值。
    fn get_vless_route(&self) -> Port {
        self.ctx.get_vless_route().parse::<u16>().map_or(Port::new(0), Port::new)
    }

    fn get_network(&self) -> Network {
        self.ctx.get_network()
    }

    fn get_user(&self) -> &str {
        self.ctx.get_user()
    }

    fn get_attributes(&self) -> &HashMap<String, String> {
        self.ctx.get_attributes()
    }

    fn get_inbound_tag(&self) -> &str {
        self.ctx.get_inbound_tag()
    }

    fn get_protocol(&self) -> &str {
        self.ctx.get_protocol()
    }

    fn get_skip_dns_resolve(&self) -> bool {
        self.ctx.get_skip_dns_resolve()
    }
}

/// 把 router 的 `RouterError` 映射为 dispatcher 的 `DispatcherError`，
/// **并留可见日志**（trssj 收口点）。
///
/// `NoClue`（无规则命中）映射为 `Other("no route matched")`——dispatch_link 的
/// 调用方对 `Err(_)` 统一降级到 default handler。
/// Go `app/dispatcher/default.go:456-462`：`PickRoute` 失败时只有 `err != ErrNoClue`
/// 才打日志，随后一律走默认出站。「无规则命中」是正常态（debug）；balancer /
/// 观测器失败是异常态（warn）——此前两者都被沉默地映射成 `DispatcherError`，
/// 最坏把流量静默导到默认出站（含 `direct`，即「以为走了代理，实际直连」）。
fn map_router_err(e: RouterError) -> DispatcherError {
    match e {
        RouterError::NoClue => {
            tracing::debug!("routing: no rule matched, using default outbound");
            DispatcherError::Other("no route matched".into())
        },
        other => {
            tracing::warn!(error = %other, "routing failed, using default outbound");
            DispatcherError::Other(format!("router: {other}"))
        },
    }
}
impl RoutingRouter for RouterAdapter {
    fn pick_route(&self, ctx: &dyn DispRoutingContext) -> Result<DispRoute, DispatcherError> {
        let data = BridgeCtx::new(ctx);
        match self.router.pick_route(&data) {
            Ok(route) => {
                Ok(DispRoute { outbound_tag: route.outbound_tag, rule_tag: route.rule_tag })
            },
            Err(e) => Err(map_router_err(e)),
        }
    }

    /// 带 DNS 解析的选路（domainStrategy IpOnDemand/IpIfNonMatch）：
    /// 委托 [`Router::pick_route_resolved`]，携带完整 RoutingContext
    /// （含 sniffed protocol / inbound tag）——生产 dispatch_link 的路由入口。
    fn pick_route_resolved<'a>(
        &'a self,
        ctx: &'a dyn DispRoutingContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<DispRoute, DispatcherError>> + Send + 'a>>
    {
        Box::pin(async move {
            let data = BridgeCtx::new(ctx);
            match self.router.pick_route_resolved(&data).await {
                Ok(route) => {
                    Ok(DispRoute { outbound_tag: route.outbound_tag, rule_tag: route.rule_tag })
                },
                Err(e) => Err(map_router_err(e)),
            }
        })
    }
}

impl RouterAdapter {
    /// `Destination` 直查入口：仅目标地址/端口/网络（无 source/user 上下文）。
    ///
    /// 生产选路走 [`RoutingRouter`]（dispatcher 侧完整 `RoutingContext`）；本方法供
    /// 「给定目标地址选出站 tag」的直查场景（如 geoip 规则命中判定）。
    #[must_use]
    pub fn pick_outbound_tag(&self, dest: &Destination) -> Option<String> {
        let data = dest_to_routing_data(dest);
        match self.router.pick_route(&data) {
            Ok(route) => Some(route.outbound_tag),
            Err(_) => None,
        }
    }

    /// 带 DNS 解析的选路：委托 [`Router::pick_route_resolved`]（domainStrategy 分支）。
    pub fn pick_outbound_tag_resolved<'a>(
        &'a self,
        dest: &'a Destination,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let data = dest_to_routing_data(dest);
            match self.router.pick_route_resolved(&data).await {
                Ok(route) => Some(route.outbound_tag),
                Err(_) => None,
            }
        })
    }

    /// 注入 DNS 解析能力（domainStrategy IpOnDemand/IpIfNonMatch 用）。
    pub fn set_dns_client(&self, dns: std::sync::Arc<dyn xray_features::dns::DnsClient>) {
        self.router.set_dns_client(dns);
    }
}

/// 从 `Destination` 构造 router 端 `RoutingData`（仅目标地址/端口/网络）。
fn dest_to_routing_data(dest: &Destination) -> RouterRoutingData {
    let mut data =
        RouterRoutingData::new().with_target_port(dest.port()).with_network(dest.network());
    match dest.address() {
        Address::IPv4(ip) => data = data.with_target_ip(std::net::IpAddr::V4(*ip)),
        Address::IPv6(ip) => data = data.with_target_ip(std::net::IpAddr::V6(*ip)),
        Address::Domain(d) => data = data.with_target_domain(d.clone()),
    }
    data
}

// ========== 生产接线（方案 B）：DefaultDispatcher 入口桥 ==========

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
    match try_sniffing_request_from_json_in(v, &resolve_asset_dir()) {
        Ok(r) => r,
        Err(e) => {
            // 非装配门调用方（loopback 出站 / 框架装配路）没有错误返回面：
            // 降级为**全关嗅探**（enabled=false ⇒ 不改写目的地，fail-safe 方向），
            // 并显式 error 留痕——生产入站走 `try_sniffing_request_from_json` 拒启。
            tracing::error!(target: "xray_core", "sniffing config invalid, sniffing disabled: {e}");
            SniffingRequest::default()
        },
    }
}

/// `BuiltInbound.sniffing` JSON → [`SniffingRequest`]，解析失败即 Err（bd vdl95）。
///
/// 生产装配路径用本函数：排除规则（`domainsExcluded`/`ipsExcluded`）任一条解析
/// 失败、geoip/geosite 资产加载失败、或整表编译不出任何匹配器 ⇒ 返回 Err ⇒
/// 入站构造失败 ⇒ 启动拒启（Go `SniffingConfig.Build` 同为 Build 期硬错）。
///
/// # Errors
/// 排除规则解析/编译/资产加载失败，或 sniffing 段类型不符。
pub fn try_sniffing_request_from_json(
    v: Option<&serde_json::Value>,
) -> std::io::Result<SniffingRequest> {
    try_sniffing_request_from_json_in(v, &resolve_asset_dir())
}

/// 同 [`try_sniffing_request_from_json`]，geodata 资产目录显式给定
/// （geoip:/geosite: 展开用；测试注入）。
fn try_sniffing_request_from_json_in(
    v: Option<&serde_json::Value>,
    datadir: &Path,
) -> std::io::Result<SniffingRequest> {
    let Some(raw) = v else {
        return Ok(SniffingRequest::default());
    };
    // 有 sniffing 段但类型不符 ⇒ 硬错（Go 反序列化失败即拒启；旧实现 .ok() 静默
    // 降级为 default，等于"配置写错 = 嗅探静默消失"）。
    let cfg: xray_conf::SniffingConfig = serde_json::from_value(raw.clone()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("sniffing: {e}"))
    })?;
    Ok(SniffingRequest {
        enabled: cfg.enabled,
        metadata_only: cfg.metadata_only,
        route_only: cfg.route_only,
        override_destination_for_protocol: normalize_dest_override(&cfg.dest_override.0),
        exclude_for_domain: build_domain_excluder(&cfg.domains_excluded.0, datadir)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        exclude_for_ip: build_ip_excluder(&cfg.ips_excluded.0, datadir)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    })
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

/// 把 proto `Domain` 编译进 matcher（Full/Domain/Substr 值小写化、Regex 原样
/// —— Go `parseDomain` 同语义）。
fn add_proto_domain(
    any: &mut LinearAnyMatcher,
    rule_id: u32,
    d: &xray_geodata::Domain,
) -> Result<(), String> {
    let Some(dt) = geodata_domain::from_proto_type(d.r#type) else {
        return Err(format!("unknown domain type {}", d.r#type));
    };
    let m = parse_geodata_domain(&geodata_domain::DomainRule::new(dt, d.value.clone(), rule_id))
        .map_err(|e| e.to_string())?;
    any.add(m);
    Ok(())
}

/// domainsExcluded → typed matcher（Go `proxyman.BuildSniffingRequest` →
/// `DomainReg.BuildDomainMatcher` 等价物）。
///
/// 规则形态：full:/domain:/regexp:/keyword: 前缀，无前缀 = Substr，
/// geosite:/ext: 经 loader 展开为域名列表。
///
/// bd vdl95：任何一条规则解析/编译/资产加载失败即 **Err**（对齐 Go Build 期
/// 硬错）。旧实现逐条 warn+skip，最坏 `added == 0` ⇒ 整表失效而嗅探照开 ⇒
/// 本应排除的域名仍被 destOverride 改写目的地（安全面 fail-open）。
fn build_domain_excluder(
    rules: &[String],
    datadir: &Path,
) -> std::result::Result<Option<Arc<ExcludeDomainMatcher>>, String> {
    if rules.is_empty() {
        return Ok(None);
    }
    let loader = GeoDataLoader::new(datadir.to_path_buf());
    let mut any = LinearAnyMatcher::new();
    let mut added = 0u32;
    for raw in rules {
        let rule = parse_domain_rule(raw, xray_geodata::geosite::DomainType::Substr, datadir)
            .map_err(|e| format!("sniffing domainsExcluded {raw:?} 解析失败: {e}"))?;
        match rule.value {
            Some(DomainRuleValue::Custom(d)) => {
                add_proto_domain(&mut any, added + 1, &d)
                    .map_err(|e| format!("sniffing domainsExcluded {raw:?} 编译失败: {e}"))?;
                added += 1;
            },
            Some(DomainRuleValue::Geosite(gs)) => {
                let site = if gs.attrs.is_empty() {
                    loader.load_site(&gs.file, &gs.code)
                } else {
                    loader.load_site_with_attrs(&gs.file, &gs.code, &gs.attrs)
                };
                let site = site.map_err(|e| {
                    format!(
                        "sniffing domainsExcluded {raw:?} 加载 {}:{} 失败: {e}",
                        gs.file, gs.code
                    )
                })?;
                for d in &site.domain {
                    add_proto_domain(&mut any, added + 1, d).map_err(|e| {
                        format!("sniffing geosite {}:{} 条目编译失败: {e}", gs.file, gs.code)
                    })?;
                    added += 1;
                }
            },
            None => {},
        }
    }
    if added == 0 {
        return Err(format!("sniffing domainsExcluded 无任何可编译条目: {rules:?}"));
    }
    let any = Arc::new(any);
    Ok(Some(Arc::new(move |domain: &str| any.match_any(domain))))
}

/// ipsExcluded → typed matcher（Go `IPReg.BuildIPMatcher` 等价物）。
///
/// 形态：CIDR（`10.0.0.0/8`，无 `/` 按单地址）与 `geoip:XX`（loader 展开为
/// CIDR 列表），`!` 反向前缀由 rule_parser 转为 reverse_match。
///
/// bd vdl95：任一条失败即 **Err**（理由与 [`build_domain_excluder`] 同——跳过 =
/// 排除表缺项 = 嗅探改写不该改写的目的地）。
fn build_ip_excluder(
    rules: &[String],
    datadir: &Path,
) -> std::result::Result<Option<Arc<ExcludeIpMatcher>>, String> {
    if rules.is_empty() {
        return Ok(None);
    }
    let loader = GeoDataLoader::new(datadir.to_path_buf());
    let mut matchers: Vec<Box<dyn GeoIpMatcher>> = Vec::new();
    for raw in rules {
        let mut parsed = parse_ip_rules(std::slice::from_ref(raw), datadir)
            .map_err(|e| format!("sniffing ipsExcluded {raw:?} 解析失败: {e}"))?;
        if parsed.len() != 1 {
            return Err(format!(
                "sniffing ipsExcluded {raw:?} 应产出 1 条规则，实得 {}",
                parsed.len()
            ));
        }
        let rule = parsed.remove(0);
        match rule.value {
            Some(IpRuleValue::Custom(cr)) => {
                if let Some(cidr) = cr.cidr {
                    let mut m = HeuristicIPMatcher::from_cidrs(&[cidr]);
                    if cr.reverse_match {
                        m.set_reverse(true);
                    }
                    matchers.push(Box::new(m));
                }
            },
            Some(IpRuleValue::Geoip(gr)) => {
                let geoip = loader.load_ip(&gr.file, &gr.code).map_err(|e| {
                    format!("sniffing ipsExcluded {raw:?} 加载 {}:{} 失败: {e}", gr.file, gr.code)
                })?;
                let mut m = HeuristicIPMatcher::from_cidrs(&geoip.cidr);
                if gr.reverse_match {
                    m.set_reverse(true);
                }
                matchers.push(Box::new(m));
            },
            None => {},
        }
    }
    if matchers.is_empty() {
        return Err(format!("sniffing ipsExcluded 无任何可编译条目: {rules:?}"));
    }
    let multi = Arc::new(GeneralMultiIPMatcher::new(matchers));
    Ok(Some(Arc::new(move |ip: IpAddr| multi.match_ip(ip))))
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
    /// §3.5.6 ①类托管：mux carrier spawn ctx（scope 装配期登记进宿主
    /// `ArmScopeRegistry`，Instance::close 逆序关停）。
    plugin_ctx: Arc<xray_frame::PluginContext>,
}

impl MuxCarrierHandler {
    /// 包装生产 inbound dispatch handler（通常为 [`InboundDispatchHandler`]）。
    #[must_use]
    pub fn new(
        inner: Arc<dyn DispatchHandler>,
        plugin_ctx: Arc<xray_frame::PluginContext>,
    ) -> Self {
        Self { inner, plugin_ctx }
    }

    fn intercept(
        &self,
        dest: &Destination,
        link: Link,
        access: Option<AccessContext>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        if is_mux_carrier(dest) {
            // §3.5.6 ①类：mux carrier 连接任务归本 inbound 的托管 scope，停机随 scope 取消。
            let spawned = self.plugin_ctx.spawn(crate::inbound::handle_mux_inbound_link(
                link,
                Arc::clone(&self.inner),
                access.as_ref().and_then(|a| a.allowed_network),
            ));
            if spawned.is_err() {
                // 停机闸已关：link 随 drop 断开，留可诊断日志（禁静默丢）。
                tracing::warn!(
                    tag = self.inner.tag(),
                    "mux carrier: scope closed at shutdown, dropping link"
                );
            }
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
        f.debug_struct("MuxCarrierHandler").field("tag", &self.inner.tag()).finish()
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
/// - 包 inbound counter（`inbound>>>{tag}>>>traffic>>>{uplink,downlink}`）： uplink = inbound
///   写（link.writer），downlink = inbound 读（link.reader）
pub struct InboundDispatchHandler {
    dispatcher: Arc<DefaultDispatcher>,
    sniff: SniffingRequest,
    tag: String,
}

impl InboundDispatchHandler {
    #[must_use]
    pub fn new(dispatcher: Arc<DefaultDispatcher>, sniff: SniffingRequest, tag: &str) -> Self {
        Self { dispatcher, sniff, tag: tag.to_string() }
    }

    /// 懒注册并取该 inbound 的方向 counter。
    ///
    /// sm80①：受 `ForSystem().Stats.Inbound{Uplink,Downlink}` 门控（Go
    /// proxyman/inbound/always.go:26,34——tag 计数与 per-user 计数的门不同，
    /// 后者才用 `ForLevel().Stats.User*`）。门关时不懒注册，默认全 false 不计数。
    fn inbound_counter(&self, direction: &str) -> Option<Arc<dyn xray_features::stats::Counter>> {
        let sys = self
            .dispatcher
            .policy_manager
            .as_ref()
            .map_or_else(xray_features::policy::SystemStats::default, |pm| pm.for_system());
        let enabled = match direction {
            "uplink" => sys.inbound_uplink,
            "downlink" => sys.inbound_downlink,
            _ => false,
        };
        if !enabled {
            return None;
        }
        self.dispatcher.stats.as_ref().and_then(|m| {
            let name = format!("inbound>>>{}>>>traffic>>>{direction}", self.tag);
            // 不用 `.ok()` 吞错（bd 441no）：注册失败 = 该 inbound 无计数。
            // 可见信号在 manager 侧（触顶 warn-once），这里留 debug 轨迹。
            match xray_features::stats::get_or_register_counter(m.as_ref(), &name) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::debug!("stats counter `{name}` unavailable: {e}");
                    None
                },
            }
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
        let access = AccessContext { inbound_tag: self.tag.clone(), ..Default::default() };
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
        let access = AccessContext { inbound_tag: self.tag.clone(), ..access };
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
        // dispatch_link 内部 spawn（sniffing → routing → access log → outbound counter →
        // handler）， 此处仅同步返回。
        if let Err(e) = self.dispatcher.dispatch_link(dest, link, &self.sniff, access, None) {
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
///
/// 持 `Arc<SimpleOhm>`（而非裸指针）：适配器与被选表同生共死，无需调用方保证
/// 生命周期（先前的 `*const SimpleOhm` + `unsafe impl Send/Sync` 已随之删除）。
struct OhmOutboundSelector {
    inner: Arc<SimpleOhm>,
}

impl OutboundHandlerSelector for OhmOutboundSelector {
    fn select_outbounds(&self, selectors: &[String]) -> Result<Vec<String>, RouterError> {
        let mut tags: Vec<String> = Vec::new();
        for tag in self.inner.list_tags() {
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
/// balancer selector 接真实 [`SimpleOhm`]
/// （Go `Balancer.SelectOutbounds` 语义），并传入观测器使 `leastping` / `leastload`
/// 策略能拿到观测数据。
///
/// # Errors
///
/// - JSON 解析失败
/// - `Router::init` 失败（如重复 ruleTag、geoip 规则但无 loader）
pub fn build_router_adapter_from_json_with_ohm(
    routing_json: &[u8],
    ohm: Arc<SimpleOhm>,
    observer: Option<Arc<dyn ObservationProvider>>,
) -> Result<Arc<RouterAdapter>, WiringError> {
    build_adapter(
        parse_routing_json_to_proto(routing_json)?,
        Arc::new(OhmOutboundSelector { inner: ohm }),
        observer,
    )
}

fn build_adapter(
    config: xray_proto::xray::app::router::Config,
    ohm: Arc<dyn OutboundHandlerSelector>,
    observer: Option<Arc<dyn ObservationProvider>>,
) -> Result<Arc<RouterAdapter>, WiringError> {
    build_adapter_in(config, ohm, observer, &resolve_asset_dir())
}

/// [`build_adapter`] 的资产目录显式版（测试注入用）。
fn build_adapter_in(
    config: xray_proto::xray::app::router::Config,
    ohm: Arc<dyn OutboundHandlerSelector>,
    observer: Option<Arc<dyn ObservationProvider>>,
    datadir: &std::path::Path,
) -> Result<Arc<RouterAdapter>, WiringError> {
    let geo_loader = Some(Arc::new(GeoDataLoader::new(datadir.to_path_buf())));
    let router = Router::init(&config, ohm, observer, geo_loader).map_err(|e| match e {
        // proto 变体 geo 规则（GeoSiteRule/GeoIPRule 字段）在 init 期加载 .dat，
        // 失败同样拒启（bd il49）。
        RouterError::GeodataBuild(m) => WiringError::Geodata(format!(
            "{m}; asset dir: {} (place the .dat file there or set XRAY_LOCATION_ASSET)",
            datadir.display()
        )),
        other => WiringError::RouterInit(other.to_string()),
    })?;
    register_geodata_router_reload(&router, &config);
    Ok(Arc::new(RouterAdapter::new(router)))
}

/// 把 geodata 热更接到本 `Router`（bd 2bmns G-2）。
///
/// 路由的 geosite/geoip matcher 是装配期从 `.dat` **本地构建**的（不注册进
/// `DOMAIN_REG`/`IP_REG`），所以 cron 热更换了文件之后，只有重跑一次规则派生
/// 才会反映到匹配结果上——否则「下载了、swap 了，路由照旧」。
///
/// `Weak` 持有 Router：释放后监听自动 no-op（反复装配不累积活引用）。
fn register_geodata_router_reload(
    router: &Arc<Router>,
    config: &xray_proto::xray::app::router::Config,
) {
    let weak = Arc::downgrade(router);
    let config = config.clone();
    xray_app_geodata::register_reload_listener(Arc::new(move || {
        let Some(router) = weak.upgrade() else { return Ok(()) };
        router.reload_rules(&config, false).map_err(|e| {
            xray_app_geodata::GeodataError::ReloadFailed(format!(
                "router rules rebuild after geodata reload: {e}"
            ))
        })
    }));
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
/// `ruleSet` 顶层键：本仓自造扩展（Go 无），但 proto `RoutingRule` 无引用字段且
/// `protos/` 只读 —— 加载出来无人可引用，故非空即拒启（bd 2bmns G-1）。
///
/// 公开面（bd 9c8k6 ②）：`xray api adrules` 需要把 JSON 配置编译成与生产装配
/// **同一套** `xray.app.router.Config`（含 balancers），禁 CLI 侧自造方言。
pub fn parse_routing_json_to_proto(
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
    use xray_proto::xray::{
        app::router::{BalancingRule, RoutingRule, routing_rule::TargetTag},
        common::geodata::{Domain, DomainRule, domain::Type as DT, domain_rule::Value as DV},
    };

    let v: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| WiringError::JsonParse(e.to_string()))?;

    let mut cfg = xray_proto::xray::app::router::Config::default();

    // 顶层 domainStrategy
    if let Some(s) = v.get("domainStrategy").and_then(|x| x.as_str()) {
        cfg.domain_strategy = parse_domain_strategy(s);
    }

    // Go RouterConfig.script（infra/conf/router.go:75）走 Lua 路由脚本引擎；
    // Rust 无该运行时，非空 script 显式拒绝而非静默忽略（票 5std M3，alwc
    // fail-loud 模式——静默丢 = 路由走向与配置意图完全不同）。空串/null =
    // 未设置（Go `if c.Script != ""` 同语义），放行。
    if let Some(s) = v.get("script") {
        let requested = match s {
            serde_json::Value::String(x) => !x.is_empty(),
            serde_json::Value::Null => false,
            _ => true,
        };
        if requested {
            return Err(WiringError::JsonParse(
                "routing script (Lua) is not supported by this build; remove the \"script\" key or use \"rules\" instead".into(),
            ));
        }
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
            // Go router.go:182-188：`domains` 键存在时覆盖 `domain`；两者都是
            // `*StringList`（字符串形态按逗号切分，数组元素原样）。
            // Go `router.go:190-193`：`domains: null` == 未设置（Go 侧是 nil 指针 ⇒
            // 不覆盖 `domain`）。只判 `is_some()` 会把 null 当空列表，把规则从
            // 「限域名」放宽成「全域名」（fail-open，bd ix8xd D-8）。
            let domain_list: Vec<String> = match r.get("domains").filter(|v| !v.is_null()) {
                Some(v) => json_string_list(Some(v))?,
                None => json_string_list(r.get("domain"))?,
            };
            for d in &domain_list {
                let pb_rule = xray_geodata::rule_parser::parse_domain_rule(
                    d,
                    xray_geodata::geosite::DomainType::Substr,
                    datadir,
                )
                .map_err(|e| {
                    geo_asset_error(format!("routing rule domain '{d}'"), "geosite.dat", datadir, e)
                })?;
                domains.push(geodata_domain_rule_to_proto(pb_rule));
            }
            for d in json_string_list(r.get("domainSuffix"))? {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Domain as i32,
                        value: d.clone(),
                        attribute: vec![],
                    })),
                });
            }
            for d in json_string_list(r.get("domainKeyword"))? {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Substr as i32,
                        value: d.clone(),
                        attribute: vec![],
                    })),
                });
            }
            for d in json_string_list(r.get("domainRegex"))? {
                domains.push(DomainRule {
                    value: Some(DV::Custom(Domain {
                        r#type: DT::Regex as i32,
                        value: d.clone(),
                        attribute: vec![],
                    })),
                });
            }

            // 目标 / 源 IP：Go `geodata.ParseIPRules` 等价（CIDR / geoip: / ext-ip: /
            // `!` 反向）。解析失败硬错——旧实现 geoip:/非法 CIDR 静默跳过（安全
            // 屏蔽规则失效的根因）。
            let mut ips = Vec::new();
            for p in
                xray_geodata::rule_parser::parse_ip_rules(&json_string_list(r.get("ip"))?, datadir)
                    .map_err(|e| {
                        geo_asset_error("routing rule ip".into(), "geoip.dat", datadir, e)
                    })?
            {
                ips.push(geodata_ip_rule_to_proto(p));
            }

            // Go router.go:206-208：`sourceIP` 优先，缺省回退 `source`。
            let source_key = if r.get("sourceIP").is_some() { "sourceIP" } else { "source" };
            let mut source_ips = Vec::new();
            for p in xray_geodata::rule_parser::parse_ip_rules(
                &json_string_list(r.get(source_key))?,
                datadir,
            )
            .map_err(|e| {
                geo_asset_error(format!("routing rule {source_key}"), "geoip.dat", datadir, e)
            })? {
                source_ips.push(geodata_ip_rule_to_proto(p));
            }

            // Go router.go:222-232：localIP / localPort。
            let mut local_ips = Vec::new();
            for p in xray_geodata::rule_parser::parse_ip_rules(
                &json_string_list(r.get("localIP"))?,
                datadir,
            )
            .map_err(|e| geo_asset_error("routing rule localIP".into(), "geoip.dat", datadir, e))?
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
                user_email: json_string_list(r.get("user"))?,
                // Go NewInboundTagMatcher/NewProtocolMatcher 构造器
                // （condition.go:207-215/:237-245）过滤空串——空串条目在
                // Rust 匹配器里前缀恒真，必须剔除。
                inbound_tag: json_string_list(r.get("inboundTag"))?
                    .into_iter()
                    .filter(|t| !t.is_empty())
                    .collect(),
                protocol: json_string_list(r.get("protocol"))?
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .collect(),
                process: json_string_list(r.get("process"))?,
                // Go a12801c1：`localOS` → local_os（匹配 runtime.GOOS）。
                local_os: json_string_list(r.get("localOS"))?,
                // 对齐 Go router.go:147 json 键 `attrs`（`attributes` 仅作
                // Rust 旧方言别名保留）。
                attributes: parse_attributes(if r.get("attrs").is_some() {
                    r.get("attrs")
                } else {
                    r.get("attributes")
                }),
                // 对齐 Go router.go:264-270：webhook → WebhookConfig。
                webhook: r.get("webhook").and_then(parse_webhook_config),
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
                },
                _ => (String::new(), None),
            };
            // Go router.go:35-41：ToLower；""→random；仅 4 个合法值，未知拒启。
            strategy = strategy.to_ascii_lowercase();
            match strategy.as_str() {
                "" => strategy = "random".to_string(),
                "random" | "leastload" | "leastping" | "roundrobin" => {},
                other => {
                    return Err(WiringError::JsonParse(format!(
                        "unknown balancing strategy: {other}"
                    )));
                },
            }
            let selectors = json_string_list(b.get("selector"))?;
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
    // bd 2bmns G-1 裁决：`ruleSet` 是本仓自造扩展（Go 26.10.17 全仓零命中），而
    // proto `RoutingRule` 没有「引用某个 ruleSet 的 tag」字段（`protos/` 只读红线）。
    // 因此加载出来的规则集**不可能被任何规则引用**——此前"读文件 + 逐条校验 + 丢弃"
    // 会让用户以为它生效（且规则集文件坏了能拒启、好了却毫无作用）。改为出现即
    // 拒启：不支持的键必须 fail-visible，禁静默吞。
    if let Some(arr) = v.get("ruleSet").and_then(|x| x.as_array())
        && !arr.is_empty()
    {
        let tags: Vec<&str> =
            arr.iter().filter_map(|rs| rs.get("tag").and_then(|x| x.as_str())).collect();
        return Err(WiringError::JsonParse(format!(
            "routing.ruleSet is not supported in this build: proto RoutingRule has no \
             ruleSet reference field, so loaded sets can never be consulted by the router \
             (offending tags: [{}]). Remove the key or inline the rules under \"rules\"",
            tags.join(", ")
        )));
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
            .map(|r| ProtoPortRange { from: u32::from(r.start), to: u32::from(r.end) })
            .collect(),
    }))
}

/// `webhook` 字段 → proto `WebhookConfig`（对齐 Go router.go:126-130/264-270：
/// `{url, deduplication, headers}`，url 为空则不构建）。
fn parse_webhook_config(
    v: &serde_json::Value,
) -> Option<xray_proto::xray::app::router::WebhookConfig> {
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
    json_str_tokens(v)
        .into_iter()
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Network::Tcp as i32),
            "udp" => Ok(Network::Udp as i32),
            "unix" => Ok(Network::Unix as i32),
            other => Err(format!("unknown network token '{other}'")),
        })
        .collect()
}

/// JSON 值 → `Vec<String>`，对齐 Go `infra/conf.StringList.UnmarshalJSON`
/// （cfgcommon/common.go:28-46）：
///
/// - `Value::String` → 按 `,` 切分（`"a,b"` → `["a","b"]`）
/// - `Value::Array` → 元素**原样**（Go 只对字符串形态切分，数组元素内不再切）
/// - 数组内非字符串条目 → 硬错（Go 反序列化到 `[]string` 失败即拒启； 静默丢会让条件消失、规则变宽
///   = fail-open）
/// - 缺失 / null → 空列表
fn json_string_list(v: Option<&serde_json::Value>) -> Result<Vec<String>, WiringError> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    match v {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(s) => {
            // Go `strings.Split(rawstr, ",")`：不 trim、不丢空串。
            Ok(s.split(',').map(str::to_string).collect())
        },
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|x| {
                x.as_str().map(str::to_string).ok_or_else(|| {
                    WiringError::JsonParse(format!("string list entry is not a string: {x}"))
                })
            })
            .collect(),
        other => Err(WiringError::JsonParse(format!("expected string list, got: {other}"))),
    }
}

/// attributes 对象 → `map<string,string>`；非字符串值以 JSON 文本表示。
fn parse_attributes(v: Option<&serde_json::Value>) -> std::collections::HashMap<String, String> {
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
            cidr: c
                .cidr
                .map(|cc| xray_proto::xray::common::geodata::Cidr { ip: cc.ip, prefix: cc.prefix }),
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
fn leastload_settings_to_typed_message(
    v: &serde_json::Value,
) -> Option<xray_proto::xray::common::serial::TypedMessage> {
    use prost::Message;
    use xray_proto::xray::app::router::{StrategyLeastLoadConfig, StrategyWeight};
    let obj = v.as_object()?;
    let mut cfg = StrategyLeastLoadConfig::default();
    if let Some(arr) = obj.get("baselines").and_then(|x| x.as_array()) {
        // Go router_strategy.go:92-98：非正值跳过。
        cfg.baselines = arr.iter().filter_map(parse_duration_ns).filter(|&ns| ns > 0).collect();
    }
    // Go json 键 `expected`（router_strategy.go:39）；`expectedNodes` 为兼容别名。
    if let Some(n) =
        obj.get("expected").or_else(|| obj.get("expectedNodes")).and_then(|x| x.as_i64())
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

#[allow(clippy::question_mark)] // 存量清零批次
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
    /// geo 资产不可用（.dat 缺失 / code 不存在）。fail-closed 拒启——调用方
    /// 禁止回退 PatternRouter（那会把 geosite:/geoip: 规则静默降级为永不命中的
    /// 字面量，bd il49）。
    #[error("geo assets unavailable: {0}")]
    Geodata(String),
}

/// geo 资产错误分流：`FileCheckFailed`（.dat 缺失 / code 不存在）→
/// [`WiringError::Geodata`]（拒启，错误含规则原文 / 默认文件名 / 资产目录）；
/// 其余解析错误保持 [`WiringError::JsonParse`]。
fn geo_asset_error(
    context: String,
    default_file: &str,
    datadir: &Path,
    e: xray_geodata::rule_parser::RuleParserError,
) -> WiringError {
    match e {
        xray_geodata::rule_parser::RuleParserError::FileCheckFailed(m) => {
            WiringError::Geodata(format!(
                "{context}: {m}; missing {default_file} in asset dir {} (place the file there or set XRAY_LOCATION_ASSET)",
                datadir.display()
            ))
        },
        other => WiringError::JsonParse(format!("{context}: {other}")),
    }
}

/// 查找 GeoIP/GeoSite .dat 文件目录（对齐 Go `GetOBJPath`）。
///
/// `xray.location.asset`（或 `XRAY_LOCATION_ASSET`）环境变量 → 可执行文件同目录。
/// 找不到 .dat 文件不影响 loader 创建（load 时 warn skip），仅影响 geoip/geosite 规则匹配。
fn resolve_asset_dir() -> std::path::PathBuf {
    // 统一 platform 探测：env → exe 目录 → 非 Windows 共享安装路径（Go
    // others.go:15-32）。此前只用 env/exe，Linux 标准安装路径下 geoip/geosite
    // 规则加载 fail-closed 启动失败。
    xray_common::platform::get_asset_dir()
}

#[cfg(test)]
mod tests {
    use xray_app_dispatcher::default::DispatcherContext;
    use xray_app_router::balancing::SimpleSelector;

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
        let r = Router::empty(Arc::new(SimpleSelector::default()), None);
        let adapter = RouterAdapter::new(r);
        let ctx = DispatcherContext::new().with_target_domain("test.com");
        let result = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx);
        assert!(result.is_err(), "empty router should return NoClue");
    }

    #[test]
    fn router_adapter_satisfies_dispatch_router() {
        use xray_common::net::network::Network;
        let r = Router::empty(Arc::new(SimpleSelector::default()), None);
        let adapter = RouterAdapter::new(r);
        let dest =
            Destination::new(Address::Domain("test".to_string()), Port::new(80), Network::TCP);
        assert!(adapter.pick_outbound_tag(&dest).is_none());
    }

    #[test]
    fn router_adapter_debug_lists_rules() {
        let r = Router::empty(Arc::new(SimpleSelector::default()), None);
        let adapter = RouterAdapter::new(r);
        let s = format!("{adapter:?}");
        assert!(s.contains("RouterAdapter"));
    }

    #[test]
    fn build_adapter_from_json_domain_rule_routes() {
        let json = br#"{"rules":[{"outboundTag":"proxy","domain":["example.com"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        use xray_common::net::network::Network;
        let dest =
            Destination::new(Address::Domain("example.com".into()), Port::new(443), Network::TCP);
        assert_eq!(adapter.pick_outbound_tag(&dest).as_deref(), Some("proxy"));
    }

    #[test]
    fn parse_routing_json_missing_both_tags_errors() {
        // 对齐 Go router.go:170-171：双 tag 缺失报错拒启（此前静默丢规则）。
        let json = br#"{"rules":[{"domain":["x.com"]}]}"#;
        let err = build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
            .unwrap_err();
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
        assert_eq!(
            rule.attributes.get("env").map(String::as_str),
            Some("prod"),
            "attrs 键必须被识别"
        );
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
        let err =
            build_router_adapter_from_json_with_ohm(b"not json", Arc::new(SimpleOhm::new()), None)
                .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)));
    }

    #[test]
    fn parse_routing_json_covers_all_rule_fields() {
        use xray_proto::xray::{
            app::router::{config::DomainStrategy, routing_rule::TargetTag},
            common::geodata::{domain::Type as DT, domain_rule::Value as DV},
        };

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
        assert!(cond.apply(&xray_app_router::context::RoutingData::new()), "本机 OS {os} 必须命中");

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
        let cfg_decoded =
            xray_proto::xray::app::router::StrategyLeastLoadConfig::decode(ts.value.as_slice())
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
        let decoded =
            xray_proto::xray::app::router::StrategyLeastLoadConfig::decode(ts.value.as_slice())
                .expect("decode");
        assert_eq!(decoded.expected, 6, "官方 expected 键必须生效");
        assert_eq!(
            decoded.baselines,
            vec![400_000_000, 1_000_000_000],
            "duration 字符串必须转纳秒"
        );
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
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let hit =
            Destination::new(Address::Domain("anywhere.com".into()), Port::new(443), Network::TCP);
        assert_eq!(adapter.pick_outbound_tag(&hit).as_deref(), Some("proxy"));
        // 不命中端口 → 不路由
        let miss =
            Destination::new(Address::Domain("anywhere.com".into()), Port::new(8080), Network::TCP);
        assert!(adapter.pick_outbound_tag(&miss).is_none());
    }

    #[test]
    fn build_adapter_from_json_network_rule_routes() {
        use xray_common::net::network::Network;
        let json = br#"{"rules":[{"outboundTag":"udp-out","network":"udp"}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let udp_dest =
            Destination::new(Address::Domain("anywhere.com".into()), Port::new(53), Network::UDP);
        assert_eq!(adapter.pick_outbound_tag(&udp_dest).as_deref(), Some("udp-out"));
        let tcp_dest =
            Destination::new(Address::Domain("anywhere.com".into()), Port::new(53), Network::TCP);
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
            Ok((vec![std::net::IpAddr::V4("1.2.3.4".parse().expect("ip"))], 60))
        }
    }

    fn resolved_dest() -> Destination {
        use xray_common::net::network::Network;
        Destination::new(Address::Domain("example.com".into()), Port::new(443), Network::TCP)
    }

    #[tokio::test]
    async fn resolved_ip_on_demand_hits_ip_rule() {
        let json = br#"{"domainStrategy":"IPOnDemand","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert_eq!(tag.as_deref(), Some("blocked"));
        assert_eq!(dns.calls(), 1, "IpOnDemand should resolve before matching");
    }

    #[tokio::test]
    async fn resolved_ip_if_non_match_resolves_after_miss() {
        let json = br#"{"domainStrategy":"IPIfNonMatch","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert_eq!(tag.as_deref(), Some("blocked"));
        assert_eq!(dns.calls(), 1, "IpIfNonMatch should resolve after first-round miss");
    }

    /// 4jrf：skip_dns_resolve 门控阻断路由侧解析（Go router.go:203-216）——
    /// DNS 查询出站经路由时必须走此分支，否则域名 NS + 非 AsIs 策略递归查询。
    #[tokio::test]
    async fn resolved_skip_dns_resolve_suppresses_lookup() {
        let json = br#"{"domainStrategy":"IPIfNonMatch","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());

        let mut ctx = DispatcherContext::new()
            .with_target_domain("example.com")
            .with_target_port(Port::new(443));
        ctx.skip_dns_resolve = true;
        let res = <RouterAdapter as RoutingRouter>::pick_route_resolved(&adapter, &ctx).await;
        assert!(res.is_err(), "no domain rule + skip → no route");
        assert_eq!(dns.calls(), 0, "skip_dns_resolve must suppress routing DNS lookup");
    }

    #[tokio::test]
    async fn resolved_asis_skips_dns() {
        let json =
            br#"{"domainStrategy":"AsIs","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        let dns = std::sync::Arc::new(CountingDns::new());
        adapter.set_dns_client(dns.clone());
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert!(tag.is_none(), "AsIs should not match by resolved IP");
        assert_eq!(dns.calls(), 0, "AsIs must not query DNS");
    }

    #[tokio::test]
    async fn resolved_without_dns_client_falls_back_to_domain_only() {
        let json = br#"{"domainStrategy":"IPOnDemand","rules":[{"outboundTag":"blocked","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");
        // 未注入 DNS：IpOnDemand 退化为按域名匹配，IP 规则不命中
        let tag = adapter.pick_outbound_tag_resolved(&resolved_dest()).await;
        assert!(tag.is_none());
    }

    // ---- balancer 策略 JSON 装配（h81 验收点）----

    /// bd 2bmns G-7：`leastping` 缺 observatory 时**拒启**（Go `Router.Init` →
    /// `common.Must(core.RequireFeatures(observatory))` panic = 启动失败）。
    /// 此前静默回落 `fallbackTag`，用户配了 leastping 实际却固定走一个出站。
    #[test]
    fn build_adapter_with_balancer_leastping_without_observer_fails() {
        let json = br#"{
            "balancers":[{"tag":"bl","selector":["a","b","c"],"strategy":"leastping","fallbackTag":"fb"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let err = build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
            .map(|_| ())
            .expect_err("leastping without observatory must be rejected");
        assert!(
            err.to_string().contains("requires the observatory app"),
            "unexpected error: {err}"
        );
    }

    /// bd 2bmns G-7：`leastload` 同款——缺 observatory 拒启，不静默回落。
    #[test]
    fn build_adapter_with_balancer_leastload_without_observer_fails() {
        let json = br#"{
            "balancers":[{"tag":"bl","selector":["a","b"],"strategy":"leastload"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let err = build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
            .map(|_| ())
            .expect_err("leastload without observatory must be rejected");
        assert!(
            err.to_string().contains("requires the observatory app"),
            "unexpected error: {err}"
        );
    }

    /// selector 适配器：SimpleOhm tagged handlers 按 selector 前缀匹配（Go
    /// `Manager.Select`），排序返回；random 策略在候选内均匀随机。
    #[test]
    fn build_adapter_with_ohm_random_strategy_picks_registered_tag() {
        let json = br#"{
            "balancers":[{"tag":"bl","selector":["proxy-"],"strategy":"random"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let ohm = Arc::new(SimpleOhm::new());
        ohm.add("proxy-a", test_handler("proxy-a"));
        ohm.add("proxy-b", test_handler("proxy-b"));
        ohm.add("direct", test_handler("direct"));
        let adapter = build_router_adapter_from_json_with_ohm(json, Arc::clone(&ohm), None)
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
            assert!(tag == "proxy-a" || tag == "proxy-b", "unexpected tag {tag}");
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
        let obs: Arc<dyn ObservationProvider> =
            Arc::new(InlineObs(xray_proto::xray::core::app::observatory::ObservationResult {
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
            }));

        let json = br#"{
            "balancers":[{"tag":"bl","selector":["a","b","c"],"strategy":"leastping"}],
            "rules":[{"balancerTag":"bl","domain":["x.test"]}]
        }"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), Some(obs))
                .expect("leastping + observer should build");
        let dest = Destination::new(
            Address::Domain("x.test".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        );
        assert_eq!(adapter.pick_outbound_tag(&dest).as_deref(), Some("b"));
    }

    /// BridgeCtx 消费 route_target（Go `routing.Context.GetTarget`：
    /// RouteTarget 有效时优先于 Target——routeOnly 路由用嗅探域名）。
    #[test]
    fn pick_route_prefers_route_target_over_target() {
        let json = br#"{"rules":[{"outboundTag":"routed","domain":["sniffed.example.com"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");

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

    /// bvot：sourceIP/localIP 规则经 dispatcher 上下文命中
    /// （Go `GetSourceIPs`/`GetLocalIPs` → condition.go IP 条件）。
    #[test]
    fn pick_route_source_and_local_rules_hit() {
        let json = br#"{"rules":[{"outboundTag":"lan","source":["198.51.100.0/24"],"localIP":["127.0.0.1"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");

        let mut ctx = DispatcherContext::new().with_target_port(Port::new(80));
        ctx.source_ips = vec![std::net::IpAddr::from([198, 51, 100, 9])];
        ctx.local_ips = vec![std::net::IpAddr::from([127, 0, 0, 1])];
        let route = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx)
            .expect("source+local rule must hit");
        assert_eq!(route.outbound_tag, "lan");

        // 缺 localIP → 不命中。
        let mut miss = DispatcherContext::new().with_target_port(Port::new(80));
        miss.source_ips = vec![std::net::IpAddr::from([198, 51, 100, 9])];
        assert!(<RouterAdapter as RoutingRouter>::pick_route(&adapter, &miss).is_err());
    }

    /// bvot：routeOnly（RouteTarget=嗅探域名）时原目标 IP 仍参与 IP 规则匹配
    /// （Go `GetTargetIPs` 只读 Target；default.go:311-315 不改 Target）。
    #[test]
    fn pick_route_route_only_keeps_target_ips_for_ip_rules() {
        let json = br#"{"rules":[{"outboundTag":"direct-ip","ip":["1.2.3.0/24"]}]}"#;
        let adapter =
            build_router_adapter_from_json_with_ohm(json, Arc::new(SimpleOhm::new()), None)
                .expect("build adapter");

        let mut ctx = DispatcherContext::new().with_target_port(Port::new(443));
        ctx.target_ips = vec![std::net::IpAddr::from([1, 2, 3, 4])];
        ctx.route_target = Some(Destination::new(
            Address::Domain("sniffed.example.com".into()),
            Port::new(443),
            xray_common::net::network::Network::TCP,
        ));
        let route = <RouterAdapter as RoutingRouter>::pick_route(&adapter, &ctx)
            .expect("ip rule must hit while route_target is a domain");
        assert_eq!(route.outbound_tag, "direct-ip");
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

    /// geodata 热更监听是全进程表（bd 2bmns G-2）——热更类测试串行，避免互相触发。
    static RELOAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// bd 2bmns G-1：`ruleSet` 明示不接线——非空即拒启，不静默吞。
    ///
    /// 反向断言：删掉 `parse_routing_json_to_proto_in` 里的拒启块，本测试立刻变红
    /// （配置会被"读文件后丢弃"静默接受）。
    #[test]
    fn routing_rule_set_is_rejected_explicitly() {
        let dir = temp_asset_dir("ruleset");
        let json = br#"{
            "ruleSet": [{"tag": "geo", "type": "file", "format": "json", "path": "geo.json"}],
            "rules": [{"outboundTag": "proxy", "domain": ["example.com"]}]
        }"#;
        let err = parse_routing_json_to_proto_in(json, &dir).expect_err("ruleSet must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("routing.ruleSet is not supported"), "unexpected error: {msg}");
        assert!(msg.contains("geo"), "offending tag must be named: {msg}");

        // 空数组 = 未配置（等价 no-op），不得误伤。
        let ok = parse_routing_json_to_proto_in(br#"{"ruleSet":[],"rules":[]}"#, &dir);
        assert!(ok.is_ok(), "empty ruleSet must be a no-op");
    }

    /// bd 2bmns G-2：geodata 热更必须让**路由规则**跟着换。
    ///
    /// 装配期 matcher 是从 `.dat` 本地构建的（不注册进 `DOMAIN_REG`/`IP_REG`），
    /// 所以「下载 + swap .dat」本身不会改变匹配结果；只有热更回调里重跑规则派生
    /// 才行。此前 cron 热更后路由照旧 = 用户以为规则集更新了其实没有。
    ///
    /// 反向断言：删掉 `register_geodata_router_reload` 调用，第三段断言变红。
    #[test]
    fn geodata_reload_rebuilds_router_rules() {
        use xray_app_geodata::downloader::{GeodataReloader, ReloadBothRegistries};

        fn geosite_dat(domains: &[&str]) -> Vec<u8> {
            use prost::Message;
            use xray_proto::xray::common::geodata::{Domain, GeoSite, GeoSiteList};
            let hot = GeoSite {
                code: "HOT".into(),
                // r#type 3 = Full（`DomainType::from_proto_type`）
                domain: domains
                    .iter()
                    .map(|d| Domain { r#type: 3, value: (*d).into(), attribute: vec![] })
                    .collect(),
            };
            GeoSiteList { entry: vec![hot] }.encode_to_vec()
        }

        let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        xray_app_geodata::clear_reload_listeners();

        let dir = temp_asset_dir("geodata-reload");
        std::fs::write(dir.join("geosite.dat"), geosite_dat(&["old.example"])).unwrap();

        let json = br#"{"rules":[{"outboundTag":"routed","domain":["geosite:hot"]}]}"#;
        let cfg = parse_routing_json_to_proto_in(json, &dir).expect("parse routing json");
        let adapter = build_adapter_in(cfg, Arc::new(SimpleSelector::default()), None, &dir)
            .expect("adapter");

        let pick = |domain: &str| {
            let dest = Destination::new(
                Address::Domain(domain.into()),
                Port::new(443),
                xray_common::net::network::Network::TCP,
            );
            adapter.pick_outbound_tag(&dest)
        };

        assert_eq!(pick("old.example").as_deref(), Some("routed"), "初始 .dat 命中");
        assert_eq!(pick("new.example"), None, "新域名尚未进 .dat");

        // 热更：换文件 + 触发 reload（生产 = cron 回调 → ReloadBothRegistries）。
        std::fs::write(dir.join("geosite.dat"), geosite_dat(&["old.example", "new.example"]))
            .unwrap();
        ReloadBothRegistries.reload().expect("geodata reload");

        assert_eq!(
            pick("new.example").as_deref(),
            Some("routed"),
            "热更后路由规则必须用新 .dat 重建"
        );
        assert_eq!(pick("old.example").as_deref(), Some("routed"), "旧域名仍在（未丢规则）");

        xray_app_geodata::clear_reload_listeners();
    }

    /// 监听注册面自检（G-2 的第二半）：装配后必须恰好留下一个本 Router 的监听，
    /// 且 `reload_listener_count` 清空后归零（防全局表泄漏）。
    #[test]
    fn geodata_reload_listener_is_registered_and_clearable() {
        let _guard = RELOAD_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        xray_app_geodata::clear_reload_listeners();
        assert_eq!(xray_app_geodata::reload_listener_count(), 0);

        let dir = temp_asset_dir("geodata-listener");
        let json = br#"{"rules":[{"outboundTag":"x","domain":["a.example"]}]}"#;
        let cfg = parse_routing_json_to_proto_in(json, &dir).expect("parse");
        let adapter = build_adapter_in(cfg, Arc::new(SimpleSelector::default()), None, &dir)
            .expect("adapter");
        // 同进程并行的其它装配测试也可能注册（全局表），故断言 ≥1 而非 ==1。
        assert!(xray_app_geodata::reload_listener_count() >= 1, "装配必须注册热更监听");

        drop(adapter);
        xray_app_geodata::clear_reload_listeners();
        assert_eq!(xray_app_geodata::reload_listener_count(), 0);
    }

    /// Go 官方样例前缀形态逐项断言 proto 字段（Go 对照 infra/conf/router.go
    /// `parseFieldRule` → `geodata.ParseDomainRules(s, Domain_Substr)` /
    /// `ParseIPRules`）：full:/domain:/regexp:/keyword:/geosite:/无前缀=Substr、
    /// CIDR/geoip:/ext-ip:/`!` 反向，以及 Rust 别名键兼容。
    #[test]
    fn parse_routing_json_go_prefix_forms() {
        use xray_proto::xray::common::geodata::{domain_rule::Value as DV, ip_rule::Value as IV};

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
            },
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
            },
            _ => panic!("ip[0] expected geoip reference"),
        }
        match rule.ip[1].value.as_ref() {
            Some(IV::Custom(c)) => {
                let cidr = c.cidr.as_ref().expect("cidr");
                assert_eq!(cidr.ip, vec![10, 0, 0, 0]);
                assert_eq!(cidr.prefix, 8);
                assert!(!c.reverse_match);
            },
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
            },
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

        // geoip: code 不存在（文件在，code 缺）→ 资产不可用，同拒启
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["geoip:nonexistent"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::Geodata(_)), "{err:?}");

        // 非法 IP 字面（旧实现静默 skip 的形态）
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["300.1.2.3"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");

        // geosite: code 不存在 → 同拒启
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["geosite:nonexistent"]}]}"#,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::Geodata(_)), "{err:?}");

        // geoip.dat 整体缺失 → 拒启（Go：Build 期 load 失败即拒启）
        let nodat = temp_asset_dir("hard-error-nodat");
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":["geoip:private"]}]}"#,
            &nodat,
        )
        .unwrap_err();
        assert!(matches!(err, WiringError::Geodata(_)), "{err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("geoip.dat")
                && msg.contains(&nodat.to_string_lossy().to_string())
                && msg.contains("XRAY_LOCATION_ASSET"),
            "error must carry file name + asset dir + env hint: {msg}"
        );

        // 对照：无前缀 domain 与纯 CIDR 不需要 geodata 资产
        parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["ok.example"],"ip":["1.2.3.4"]}]}"#,
            &nodat,
        )
        .expect("plain rules must not require geodata assets");
    }

    /// bd il49 三态：①引用 geo + 资产缺失 → Err（拒启，错误含文件名/目录/env 提示）；
    /// ②引用 geo + 资产存在 → Ok；③未引用 geo → Ok 且零资产依赖。
    #[test]
    fn routing_geo_assets_three_states() {
        let json = br#"{"rules":[{"outboundTag":"b","ip":["geoip:private"]}]}"#;

        // ① 引用 + 缺失 → Err
        let empty = temp_asset_dir("three-missing");
        let err = parse_routing_json_to_proto_in(json, &empty).unwrap_err();
        assert!(matches!(err, WiringError::Geodata(_)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("geoip.dat") && msg.contains("XRAY_LOCATION_ASSET"), "{msg}");

        // ② 引用 + 存在 → Ok
        std::fs::write(empty.join("geoip.dat"), make_geoip_dat()).unwrap();
        parse_routing_json_to_proto_in(json, &empty).expect("assets present must parse");

        // ③ 未引用 + 缺失 → Ok（不加载、不报错）
        let bare = temp_asset_dir("three-unreferenced");
        parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["ok.example"]}]}"#,
            &bare,
        )
        .expect("unreferenced geo must not require assets");
    }

    /// vrll⑤：routing 端口字段解析失败硬错（Go router.go:236-238 解码期拒启）
    /// ——旧实现 `.ok()?` 吞错 → None → 规则端口约束静默失效。
    #[test]
    fn parse_port_list_invalid_rejected_valid_ok() {
        // 非法：字符串 "abc" / 对象形态。
        for bad in [serde_json::json!("abc"), serde_json::json!({"port": 80})] {
            #[allow(clippy::err_expect)] // 存量清零批次
            let err = super::parse_port_list(Some(&bad)).err().expect("must reject");
            assert!(matches!(err, WiringError::JsonParse(_)), "{err:?}");
        }
        // 合法：数字 / "80,443-53" 混合 / 缺失与 null → None。
        assert!(super::parse_port_list(None).unwrap().is_none());
        assert!(super::parse_port_list(Some(&serde_json::Value::Null)).unwrap().is_none());
        let ok =
            super::parse_port_list(Some(&serde_json::json!("80,443"))).unwrap().expect("ports");
        assert_eq!(ok.range.len(), 2);
    }

    /// vrll⑤ + uasr②：balancer 空 tag / 空 selector / 未知 strategy 硬错
    /// （Go router.go:30-41）；合法 balancer 通过且 strategy 规范化 random。
    #[test]
    #[allow(clippy::err_expect, clippy::question_mark)] // 存量清零批次：测试断言期 expect
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
        let err =
            parse_routing_json_to_proto_in(br#"{"balancers":[{"tag":"bl","selector":[]}]}"#, &dir)
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

    /// 补票②：rules JSON 字符串列表的非字符串项硬错（Go StringList 解码期
    /// 拒启 / rule_parser 逐条失败即拒），不再 filter_map 静默丢弃。
    #[test]
    #[allow(clippy::err_expect)] // 存量清零批次：测试断言期 expect
    fn routing_domain_non_string_entry_rejected() {
        let dir = temp_asset_dir("domain-nonstring");
        let err = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domains":["ok.example",123]}]}"#,
            &dir,
        )
        .err()
        .expect("must reject");
        assert!(err.to_string().contains("string list entry is not a string"), "{err:?}");
    }

    /// cpy3d 回归：Go `StringList` 的**字符串形态**（逗号切分）必须生效。
    ///
    /// 旧实现只认数组 ⇒ `"domain": "example.com"` 在 Go 生效、在 Rust 条件消失
    /// （规则变宽，屏蔽规则断网面扩大 / 分流规则劫持流量）。
    #[test]
    fn routing_string_form_domain_accepted() {
        let dir = temp_asset_dir("string-form-domain");
        let cfg = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":"full:example.com,keyword:ads"}]}"#,
            &dir,
        )
        .expect("字符串形态必须按逗号切分");
        assert_eq!(cfg.rule.len(), 1);
        let values: Vec<i32> = cfg.rule[0]
            .domain
            .iter()
            .filter_map(|r| match r.value.as_ref() {
                Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(d)) => {
                    Some(d.r#type)
                },
                _ => None,
            })
            .collect();
        assert_eq!(values.len(), 2, "两个逗号分隔 token 都要落规则");
    }

    /// cpy3d 回归：字符串形态同样适用于 `ip` / `sourceIP` / `localIP` / `domain`。
    #[test]
    fn routing_string_form_ip_accepted() {
        let dir = temp_asset_dir("string-form-ip");
        let cfg = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","ip":"10.0.0.0/8,192.168.0.0/16"}]}"#,
            &dir,
        )
        .expect("字符串形态 ip 必须按逗号切分");
        assert_eq!(cfg.rule[0].ip.len(), 2);
    }

    /// cpy3d 回归：**数组元素不切分**（Go 只对字符串形态做逗号切分）。
    #[test]
    fn routing_array_elements_not_comma_split() {
        let dir = temp_asset_dir("array-no-split");
        let cfg = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domains":["a.example,b.example"]}]}"#,
            &dir,
        )
        .expect("数组形态合法");
        assert_eq!(cfg.rule[0].domain.len(), 1, "数组元素内的逗号不得再切分");
        match cfg.rule[0].domain[0].value.as_ref() {
            Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(d)) => {
                assert_eq!(d.value, "a.example,b.example");
            },
            other => panic!("unexpected domain rule: {other:?}"),
        }
    }

    /// bd ix8xd D-8：Go `infra/conf/router.go:190-193` 的 `domains: null` 是 nil
    /// 指针 ⇒ **不覆盖** `domain`。旧实现只判 `is_some()`，null 当空列表 ⇒ 规则从
    /// 「限域名」放宽为「全域名」（fail-open：屏蔽规则断网面扩大）。
    #[test]
    fn routing_domains_null_keeps_domain_filter() {
        let dir = temp_asset_dir("domains-null");
        let cfg = parse_routing_json_to_proto_in(
            br#"{"rules":[{"outboundTag":"b","domain":["example.com"],"domains":null}]}"#,
            &dir,
        )
        .expect("domains:null 必须按未设置处理");
        assert_eq!(cfg.rule[0].domain.len(), 1, "domain 列表不得被 null 清空");
    }

    /// 票 5std M3：routing 顶层 `script`（Go Lua 路由脚本引擎）非空硬错，
    /// 不再静默丢（alwc fail-loud 模式）；空串 = 未设置，放行。
    #[test]
    #[allow(clippy::err_expect)] // 存量清零批次：测试断言期 expect
    fn routing_script_key_rejected_loudly() {
        let dir = temp_asset_dir("script-reject");
        let err = parse_routing_json_to_proto_in(br#"{"script":"route.lua"}"#, &dir)
            .err()
            .expect("non-empty script must reject");
        assert!(err.to_string().contains("script"), "{err:?}");
        parse_routing_json_to_proto_in(br#"{"script":""}"#, &dir)
            .expect("empty script = unset, passes");
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
        let err = build_router_adapter_from_json_with_ohm(
            br#"{"rules":[{"outboundTag":"b","network":"tpc"}]}"#,
            Arc::new(SimpleOhm::new()),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown network token 'tpc'"), "unexpected error: {err}");

        // 正常 token（大小写混合、逗号串）不受影响。
        use xray_proto::xray::common::net::Network;
        let cfg =
            parse_routing_json_to_proto(br#"{"rules":[{"outboundTag":"b","network":"TCP,udp"}]}"#)
                .expect("valid tokens must pass");
        assert_eq!(cfg.rule[0].networks, vec![Network::Tcp as i32, Network::Udp as i32]);
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
        let req = try_sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"))
            .expect("sniffing");
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
        let req = try_sniffing_request_from_json_in(Some(&json), &dir).expect("sniffing");
        let ipm = req.exclude_for_ip.expect("geoip matcher built");
        assert!(ipm("10.1.2.3".parse().unwrap()));
        assert!(ipm("192.168.5.5".parse().unwrap()));
        assert!(ipm("127.0.0.1".parse().unwrap()));
        assert!(!ipm("8.8.8.8".parse().unwrap()));
    }

    /// bd vdl95：**单条坏规则整表拒启**（Go Build 期硬错）。旧行为 warn+skip
    /// 让排除表缺项/整表失效而嗅探照开——安全面 fail-open，期望已反转。
    #[test]
    fn sniffing_exclusions_bad_rule_hard_error() {
        let bad_domain = serde_json::json!({
            "enabled": true,
            "domainsExcluded": ["full:good.example", "regexp:([bad"]
        });
        let err = try_sniffing_request_from_json_in(Some(&bad_domain), Path::new("/nonexistent"))
            .expect_err("bad domain rule must abort, not be skipped");
        assert!(err.to_string().contains("domainsExcluded"), "unexpected error: {err}");

        let bad_ip = serde_json::json!({
            "enabled": true,
            "ipsExcluded": ["not-an-ip", "10.0.0.0/8"]
        });
        let err = try_sniffing_request_from_json_in(Some(&bad_ip), Path::new("/nonexistent"))
            .expect_err("bad ip rule must abort, not be skipped");
        assert!(err.to_string().contains("ipsExcluded"), "unexpected error: {err}");
    }

    /// 无排除配置 → matcher 为 None（Go nil），enabled 等字段照常透传。
    #[test]
    fn sniffing_no_exclusions_yields_none_matchers() {
        let json = serde_json::json!({ "enabled": true, "destOverride": ["http"] });
        let req = try_sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"))
            .expect("sniffing");
        assert!(req.enabled);
        assert!(req.exclude_for_domain.is_none());
        assert!(req.exclude_for_ip.is_none());
        let none = try_sniffing_request_from_json_in(None, Path::new("/nonexistent"))
            .expect("absent sniffing section is not an error");
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
        let req = try_sniffing_request_from_json_in(Some(&json), Path::new("/nonexistent"))
            .expect("sniffing");
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
        assert!(
            h.inbound_counter("uplink").is_none(),
            "default: inbound counter must be gated off"
        );
        assert!(
            h.inbound_counter("downlink").is_none(),
            "default: inbound counter must be gated off"
        );

        // 开启 inbound 两门：按方向注册
        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        d.stats = Some(stats);
        d.set_policy_manager(Arc::new(InboundOnPm));
        let h = InboundDispatchHandler::new(Arc::new(d), SniffingRequest::default(), "gated-in");
        assert!(h.inbound_counter("uplink").is_some(), "inbound_uplink on: counter must register");
        assert!(
            h.inbound_counter("downlink").is_some(),
            "inbound_downlink on: counter must register"
        );
    }
}
