//! 默认分发器
//!
//! 对应 Go `app/dispatcher/default.go`。负责将入站连接按路由规则分发到出站处理器。
//!
//! ## 当前状态
//!
//! 业务核心（独立可测）：
//! - [`RoutingContext`] trait + [`DispatcherContext`] owned 实现 — 承载 Go `routing.Context` 语义
//! - [`should_override`] 函数 — sniff 域名是否覆盖原 IP 的判定逻辑
//! - [`SniffingRequest`] — 嗅探请求配置
//!
//! IO 边界（trait + NotImplemented 占位）：
//! - [`RoutingRouter`] / [`OutboundHandlerManager`] / [`DispatchHandler`] trait
//! - [`DefaultDispatcher::dispatch`] / [`DefaultDispatcher::dispatch_link`] — 依赖 pipe/transport 全链路
//! - [`CachedReader`] — 依赖 `pipe.Reader`，主体留 TODO

use crate::error::DispatcherError;
use crate::sniffer::SniffResult;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use xray_buf::multi::MultiBuffer;
use std::pin::Pin;
use std::sync::Arc;
use xray_common::net::destination::Destination;

// ========== UDP443 策略（bd g35） ==========

/// UDP/443（QUIC over XUDP）策略，对应 Go `mux` 配置的 `xudpProxyUDP443`。
///
/// Go 基准 `app/proxyman/outbound/handler.go:220-228`：仅当出站启用 mux 时生效——
/// - `Reject`：拒绝（`errors...AtInfo` + Interrupt 双向，Go 默认值）
/// - `Skip`：绕过 mux/xudp 直发（Go `goto out` → `proxy.Process`）
/// - `Allow`：走 xudp ClientManager（bd mbc/nww 接入前等价直发）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Udp443Policy {
    /// 拒绝 UDP/443（默认）。
    Reject,
    /// 绕过 mux/xudp 直发出站。
    Skip,
    /// 允许经 xudp 代理（暂等价直发，mbc/nww 后区分）。
    Allow,
}

impl Udp443Policy {
    /// 从 mux 配置构建策略。
    ///
    /// 对应 Go `infra/conf/xray.go MuxConfig.Build` 的空串→`"reject"` 规范化 +
    /// `NewHandler` 的 enabled 门控（mux 未启用时无 UDP443 检查）。
    /// 非法值返回 `None` 并告警（Go 为启动错误；校验归 conf Build 阶段，此处降级跳过）。
    #[must_use]
    pub fn from_mux(enabled: bool, xudp_proxy_udp_443: &str) -> Option<Self> {
        if !enabled {
            return None;
        }
        match xudp_proxy_udp_443 {
            "" | "reject" => Some(Self::Reject),
            "skip" => Some(Self::Skip),
            "allow" => Some(Self::Allow),
            other => {
                tracing::warn!(value = %other, r#"unknown "xudpProxyUDP443", ignoring"#);
                None
            }
        }
    }
}
use xray_common::net::network::Network;
use xray_common::net::port::Port;

// ========== RoutingContext ==========

/// 路由上下文 trait（对应 Go `routing.Context`）
///
/// Go 的 `routing.Context` 接口提供 14 个 getter，暴露给 Router 做规则匹配。
/// Rust 端 [`xray_features::routing::Router`] trait API 简化为 `(dest, session) -> tag`，
/// 不携带 source IP/user/protocol 等丰富字段；故本 crate 内部独立定义此 trait 保持语义。
pub trait RoutingContext: Send + Sync + Debug {
    fn get_target_ips(&self) -> &[IpAddr];
    fn get_target_domain(&self) -> &str;
    fn get_target_port(&self) -> Port;
    fn get_source_ips(&self) -> &[IpAddr];
    fn get_source_port(&self) -> Port;
    fn get_local_ips(&self) -> &[IpAddr];
    fn get_local_port(&self) -> Port;
    fn get_vless_route(&self) -> &str;
    fn get_network(&self) -> Network;
    fn get_user(&self) -> &str;
    fn get_attributes(&self) -> &HashMap<String, String>;
    fn get_inbound_tag(&self) -> &str;
    fn get_protocol(&self) -> &str;
    fn get_skip_dns_resolve(&self) -> bool;

    /// 路由目标覆盖（Go `session.Outbound.RouteTarget`：valid 时优先于 Target 参与
    /// 路由）。routeOnly 场景路由用嗅探域名、拨号保持原 dest。默认 None（等价
    /// Go RouteTarget 无效）。
    fn get_route_target(&self) -> Option<&xray_common::net::destination::Destination> {
        None
    }
}

/// 拥有所有字段的 [`RoutingContext`] 实现，用 builder 模式构造。
#[derive(Debug, Clone)]
pub struct DispatcherContext {
    /// 目标 IP 列表（可能多个，按 v4/v6 顺序）
    pub target_ips: Vec<IpAddr>,
    /// 目标域名
    pub target_domain: String,
    /// 目标端口
    pub target_port: Port,
    /// 来源 IP 列表
    pub source_ips: Vec<IpAddr>,
    /// 来源端口
    pub source_port: Port,
    /// 本地 IP 列表
    pub local_ips: Vec<IpAddr>,
    /// 本地端口
    pub local_port: Port,
    /// VLESS 路由字符串
    pub vless_route: String,
    /// 网络（TCP/UDP）
    pub network: Network,
    /// 用户标识
    pub user: String,
    /// 属性映射
    pub attributes: HashMap<String, String>,
    /// 入站 tag
    pub inbound_tag: String,
    /// 协议名（sniff 出来的）
    pub protocol: String,
    /// 是否跳过 DNS 解析
    pub skip_dns_resolve: bool,
    /// 路由目标覆盖（Go `RouteTarget`；Some 时路由用此目标，拨号仍用原 dest）。
    pub route_target: Option<xray_common::net::destination::Destination>,
}

impl Default for DispatcherContext {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatcherContext {
    #[must_use]
    pub fn new() -> Self {
        Self {
            target_ips: Vec::new(),
            target_domain: String::new(),
            target_port: Port::new(0),
            source_ips: Vec::new(),
            source_port: Port::new(0),
            local_ips: Vec::new(),
            local_port: Port::new(0),
            vless_route: String::new(),
            network: Network::TCP,
            user: String::new(),
            attributes: HashMap::new(),
            inbound_tag: String::new(),
            protocol: String::new(),
            skip_dns_resolve: false,
            route_target: None,
        }
    }

    pub fn with_target_domain(mut self, d: impl Into<String>) -> Self {
        self.target_domain = d.into();
        self
    }
    pub fn with_target_port(mut self, p: Port) -> Self {
        self.target_port = p;
        self
    }
    pub fn with_network(mut self, n: Network) -> Self {
        self.network = n;
        self
    }
    pub fn with_source_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.source_ips = ips;
        self
    }
    /// c10t：设置源端口。源端口解析来自 AccessContext.from `ip:port` 字段。
    pub fn with_source_port(mut self, p: Port) -> Self {
        self.source_port = p;
        self
    }
    pub fn with_inbound_tag(mut self, t: impl Into<String>) -> Self {
        self.inbound_tag = t.into();
        self
    }
    pub fn with_user(mut self, u: impl Into<String>) -> Self {
        self.user = u.into();
        self
    }
    pub fn with_protocol(mut self, p: impl Into<String>) -> Self {
        self.protocol = p.into();
        self
    }
}

impl RoutingContext for DispatcherContext {
    fn get_target_ips(&self) -> &[IpAddr] {
        &self.target_ips
    }
    fn get_target_domain(&self) -> &str {
        &self.target_domain
    }
    fn get_target_port(&self) -> Port {
        self.target_port
    }
    fn get_source_ips(&self) -> &[IpAddr] {
        &self.source_ips
    }
    fn get_source_port(&self) -> Port {
        self.source_port
    }
    fn get_local_ips(&self) -> &[IpAddr] {
        &self.local_ips
    }
    fn get_local_port(&self) -> Port {
        self.local_port
    }
    fn get_vless_route(&self) -> &str {
        &self.vless_route
    }
    fn get_network(&self) -> Network {
        self.network
    }
    fn get_user(&self) -> &str {
        &self.user
    }
    fn get_attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }
    fn get_inbound_tag(&self) -> &str {
        &self.inbound_tag
    }
    fn get_protocol(&self) -> &str {
        &self.protocol
    }
    fn get_skip_dns_resolve(&self) -> bool {
        self.skip_dns_resolve
    }
    fn get_route_target(&self) -> Option<&xray_common::net::destination::Destination> {
        self.route_target.as_ref()
    }
}

// ========== Router / Outbound traits ==========

/// 路由结果（对应 Go `Route{ outboundTag, ruleTag }`）
#[derive(Debug, Clone, Default)]
pub struct Route {
    /// 出站 tag
    pub outbound_tag: String,
    /// 命中规则 tag
    pub rule_tag: String,
}

impl Route {
    #[must_use]
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            outbound_tag: outbound_tag.into(),
            rule_tag: String::new(),
        }
    }

    pub fn get_outbound_tag(&self) -> &str {
        &self.outbound_tag
    }

    pub fn get_rule_tag(&self) -> &str {
        &self.rule_tag
    }
}

/// 路由器 trait（对应 Go `routing.Router`，但签名返回 [`Route`]）
///
/// 与 `xray_features::routing::Router` 区别：本 trait 接受 [`RoutingContext`]，保持 Go 语义。
pub trait RoutingRouter: Send + Sync + Debug {
    /// 选路。对应 Go `PickRoute(routing.Context) (Route, error)`。
    fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<Route, DispatcherError>;

    /// 带 DNS 解析的选路（routing domainStrategy IpOnDemand/IpIfNonMatch）。
    ///
    /// 默认退化为同步 [`RoutingRouter::pick_route`]——无 DNS 能力的 router
    /// 或 AsIs 策略等价。生产接线见 `xray-core/src/wiring.rs::RouterAdapter`。
    fn pick_route_resolved<'a>(
        &'a self,
        ctx: &'a dyn RoutingContext,
    ) -> Pin<Box<dyn Future<Output = Result<Route, DispatcherError>> + Send + 'a>> {
        Box::pin(async move { self.pick_route(ctx) })
    }
}

/// 出站 handler trait（对应 Go `outbound.Handler.Dispatch(ctx, link)`）
///
/// 与 `xray_features::outbound::OutboundHandler` 区别：本 trait 接受 [`xray_transport::Link`]，
/// 保持 Go `Dispatch(ctx, link)` 语义。
pub trait DispatchHandler: Send + Sync + Debug {
    /// 返回 handler tag。
    fn tag(&self) -> &str;

    /// 将 link 分发到出站，拨号到 dest 后双向桥接。
    /// 对应 Go `Handler.Dispatch(ctx, link)`——dest 从 ctx/session 获取。
    fn dispatch(
        &self,
        dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> PinFuture<()>;

    /// 带 access 上下文的 dispatch（对应 Go ctx 携带 `log.AccessMessage`）。
    ///
    /// 默认实现丢弃 access 上下文等价 [`Self::dispatch`]——与 Go 一致：
    /// 协议层未在 ctx 放 AccessMessage 时 dispatcher 不记 access log。
    /// 由 [`crate::wiring`] 之外的生产入口（InboundDispatchHandler）覆写。
    fn dispatch_with_access(
        &self,
        dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
        access: AccessContext,
    ) -> PinFuture<()> {
        let _ = access;
        self.dispatch(dest, link)
    }
}

/// 入站连接的 access 上下文（对应 Go ctx 中的 `log.AccessMessage`，协议层填充）。
///
/// `inbound_tag` 由生产入口（InboundDispatchHandler）填充，协议层只需给
/// `from`（客户端源地址）、`email`（认证用户，无认证协议留空）与 `level`
/// （用户策略层级，对应 Go `session.Inbound.User.Level`，默认 0）。
#[derive(Debug, Clone, Default)]
pub struct AccessContext {
    /// 客户端源地址（如 `1.2.3.4:1080`）。
    pub from: String,
    /// 认证用户 email（无认证留空）。
    pub email: String,
    /// 入站 tag（由 InboundDispatchHandler 填充）。
    pub inbound_tag: String,
    /// 认证用户策略层级（对应 Go `user.Level`，用于 per-user policy 查询）。
    pub level: u32,
}

/// 一次 access 记录（对应 Go `log.AccessMessage` 最终形态）。
#[derive(Debug, Clone, Default)]
pub struct AccessLogEntry {
    pub from: String,
    pub to: String,
    /// `"accepted"` / `"rejected"`。
    pub status: &'static str,
    pub reason: String,
    pub email: String,
    /// 命中出站（含 inTag 组合，规则同 Go default.go:488-502）。
    pub detour: String,
}

/// Access 日志记录 sink。
///
/// dispatcher crate 不依赖 xray-app-log（保持零新增依赖），由装配层
/// （xray-core functions.rs）注入 LogInstance 适配实现。
pub trait AccessLogSink: Send + Sync {
    fn record_access(&self, entry: &AccessLogEntry);
}

/// 出站处理器管理器（对应 Go `outbound.Manager`）
pub trait OutboundHandlerManager: Send + Sync + Debug {
    /// 按 tag 取 handler。
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>>;

    /// 默认 handler。
    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>>;
}

/// Boxed future 别名（手写风格，不依赖 `async_trait`）
pub type PinFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

// ========== 嗅探请求配置 ==========

/// 嗅探请求配置（对应 Go `session.SniffingRequest`）
///
/// 排除字段是 config 装配期编译好的 typed matcher（Go `proxyman.BuildSniffingRequest`
/// → `geodata.DomainReg.BuildDomainMatcher` / `IPReg.BuildIPMatcher` 同构）：
/// `None` = 无规则（Go nil），由 xray-core 的接线层经 geodata rule_parser 编译。
#[derive(Clone, Default)]
pub struct SniffingRequest {
    /// 是否启用嗅探
    pub enabled: bool,
    /// 仅嗅探元数据（不读 payload）
    pub metadata_only: bool,
    /// 仅对这些协议覆盖目的地
    pub override_destination_for_protocol: Vec<String>,
    /// 排除这些域名（不覆盖）。入参为小写化后的嗅探域名。
    pub exclude_for_domain: Option<Arc<ExcludeDomainMatcher>>,
    /// 排除这些 IP（不覆盖）。入参为原目的地 IP。
    pub exclude_for_ip: Option<Arc<ExcludeIpMatcher>>,
    /// 仅路由（不改 target）
    pub route_only: bool,
}

/// domainsExcluded 编译产物：config 层按 full:/domain:/regexp:/keyword:/无前缀
/// Substr（+ geosite: 展开）形态编译的域名排除判定，对应 Go `geodata.DomainMatcher`。
pub type ExcludeDomainMatcher = dyn Fn(&str) -> bool + Send + Sync;

/// ipsExcluded 编译产物（CIDR / geoip: 展开），对应 Go `geodata.IPMatcher`。
pub type ExcludeIpMatcher = dyn Fn(IpAddr) -> bool + Send + Sync;

impl Debug for SniffingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniffingRequest")
            .field("enabled", &self.enabled)
            .field("metadata_only", &self.metadata_only)
            .field(
                "override_destination_for_protocol",
                &self.override_destination_for_protocol,
            )
            .field("exclude_for_domain", &self.exclude_for_domain.is_some())
            .field("exclude_for_ip", &self.exclude_for_ip.is_some())
            .field("route_only", &self.route_only)
            .finish()
    }
}

// ========== should_override 核心逻辑 ==========

/// 判断 sniff 结果是否应覆盖原 destination
///
/// 对应 Go `(*DefaultDispatcher).shouldOverride`（default.go:232-264）。判定流程：
/// 1. domain 为空 → false
/// 2. domain 命中 exclude_for_domain（config 层编译的 typed matcher）→ false
/// 3. dest 是 IP 且命中 exclude_for_ip → false
/// 4. 对每个配置协议 p：
///    a. protocol 前缀互含（任一侧）→ true
///    b. bk8l：p == "fakedns" 且原 dest IP 在 fake 池（映射可能丢失）且协议非
///       bittorrent → true（"Using sniffer ... since the fake DNS missed"）
///    c. bk8l：result 是 DNSThenOthers（fakedns+others），其原始协议是 p 的
///       前缀子集（`SnifferIsProtoSubsetOf`）→ true
///
/// # 参数
/// - `result`: 嗅探结果
/// - `request`: 嗅探请求配置
/// - `dest_address`: 原目的地地址（用于 exclude_for_ip 判断）
/// - `protocol_for_domain`: 若 result 是 CompositeSniffResult，传 `Some(protocol_for_domain_result)`；
///   否则传 `None`，使用 `result.protocol()`
/// - `dest_ip_in_fake_pool`: 原目的地 IP 是否落在 FakeDNS 池区间（由调用方经
///   `FakeDnsEngine::is_ip_in_ip_pool` 判定后传入；Go 在本函数内查 fdns）
/// - `protocol_subset_of`: DNSThenOthersSniffResult 的原始协议名（Go
///   `IsProtoSubsetOf` 的 type-assert 等价；非该结果类型传 `None`）
pub fn should_override(
    result: &dyn SniffResult,
    request: &SniffingRequest,
    dest_address: Option<IpAddr>,
    protocol_for_domain: Option<&str>,
    dest_ip_in_fake_pool: bool,
    protocol_subset_of: Option<&str>,
) -> bool {
    let domain = result.domain();
    if domain.is_empty() {
        return false;
    }

    // exclude_for_domain：config 层编译的 typed matcher
    // （Go：request.ExcludeForDomain.MatchAny(strings.ToLower(domain))）
    if let Some(m) = &request.exclude_for_domain {
        if m(domain.to_lowercase().as_str()) {
            return false;
        }
    }

    // exclude_for_ip：仅当 dest 是 IP 且命中
    // （Go：destination.Address.Family().IsIP() 门控 + request.ExcludeForIP.Match(ip)）
    if let Some(addr) = dest_address {
        if let Some(m) = &request.exclude_for_ip {
            if m(addr) {
                return false;
            }
        }
    }

    // 主协议字符串（CompositeSniffResult 用 protocol_for_domain_result）
    let protocol_string = protocol_for_domain.unwrap_or_else(|| result.protocol());

    for p in &request.override_destination_for_protocol {
        if protocol_string.starts_with(p.as_str()) || p.starts_with(protocol_string) {
            return true;
        }
        // bk8l（Go default.go:251-255）：fake IP 在池但映射丢失时，内容嗅探出的
        // 任意协议（bittorrent 除外）都按 fakedns 兜底改写，避免向失效假 IP 拨号
        if dest_ip_in_fake_pool && p == "fakedns" && protocol_string != "bittorrent" {
            return true;
        }
        // bk8l（Go default.go:256-260）：fakedns+others 结果按原始协议子集命中
        if let Some(orig) = protocol_subset_of {
            if p.starts_with(orig) {
                return true;
            }
        }
    }

    false
}

// ========== Sniffing 辅助函数 ==========

/// 嗅探连接首包，返回可能被覆盖的 destination。
///
/// 对应 Go `(*DefaultDispatcher).sniffing` 方法。流程：
/// 1. 先做 FakeDns 元数据反查；metadataOnly 时据此早退（不读 payload，Go default.go:384-388）
/// 2. 从 CachedReader 读首包
/// 3. 构造 Sniffer 集合并嗅探
/// 4. 若 should_override → 用 sniffed domain 覆盖 dest 的 IP 为域名
async fn sniff_connection(
    cr: &mut CachedReader,
    dest: &xray_common::net::destination::Destination,
    req: &SniffingRequest,
    fdns: Option<&dyn crate::fakednssniffer::FakeDnsEngine>,
) -> Result<
    (
        xray_common::net::destination::Destination,
        Option<String>,
        Option<xray_common::net::destination::Destination>,
    ),
    DispatcherError,
> {
    // FakeDns metadata sniff：映射命中 → metadata_domain；仅 IP 在池（映射丢失，
    // fakedns 重启/换池）→ fakedns_ip_in_pool 兜底标志（bk8l）。
    let mut metadata_domain = String::new();
    let mut metadata_protocol = String::new();
    let mut fakedns_ip_in_pool = false;
    if let Some(engine) = fdns {
        if let Some(ip) = dest.address().ip() {
            let domain = engine.get_domain_from_fake_dns(&ip);
            if !domain.is_empty() {
                metadata_domain = domain;
                metadata_protocol = "fakedns".to_string();
            }
            // Go shouldOverride 每次都查 IsIPInIPPool，池内判定独立于映射命中
            fakedns_ip_in_pool = engine.is_ip_in_ip_pool(&ip);
        }
    }

    // m9si（Go default.go:384-388）：metadataOnly 时仅元数据嗅探（上方 fakedns
    // 反查，不读 payload），随后直接返回——内容嗅探不发生，target 不被 TLS 等
    // 内容域名改写；fakedns 命中时仍按 Go DispatchLink 对 metaresult 走
    // shouldOverride 评估（fakedns 拨号必须跟域名 → route_only 传 false）。
    if req.metadata_only {
        if !metadata_domain.is_empty() {
            let meta_result =
                crate::fakednssniffer::FakeDnsSniffResult::new(&metadata_domain);
            let dest_ip = dest.address().ip();
            if should_override(
                &meta_result,
                req,
                dest_ip,
                Some(&metadata_protocol),
                fakedns_ip_in_pool,
                None,
            ) {
                let (new_dest, route_target) =
                    override_dest(dest, &metadata_domain, false)?;
                return Ok((new_dest, Some(metadata_protocol), route_target));
            }
        }
        return Ok((dest.clone(), None, None));
    }

    let network = dest.network();
    let mut sniffer = crate::sniffer::new_default_sniffer_set();

    // va51④ + ny1g（Go default.go:390-424）：嗅探预算 200ms 固定递减（脱离用户级
    // 握手超时）；ErrNoClue / 空 payload 计入 totalAttempt（≥2 封顶 → 超时放弃），
    // NeedMoreData 不计数（协议已命中，读到预算耗尽为止）。
    let content_result: Result<Box<dyn SniffResult>, DispatcherError> = {
        let mut cache_deadline = std::time::Duration::from_millis(200);
        let mut total_attempt: u32 = 0;
        let mut first_read = true;
        loop {
            let caching_started = std::time::Instant::now();
            let read_fut = async {
                if first_read {
                    cr.read_first().await.map(|_| true)
                } else {
                    cr.read_more().await
                }
            };
            match tokio::time::timeout(cache_deadline, read_fut).await {
                Ok(Ok(true)) => {}
                Ok(Ok(false)) => {
                    break Err(DispatcherError::Io(
                        "sniffing: stream ended before protocol identified".into(),
                    ));
                }
                Ok(Err(e)) => break Err(e),
                Err(_) => break Err(DispatcherError::SniffingTimeout),
            }
            cache_deadline = cache_deadline.saturating_sub(caching_started.elapsed());
            first_read = false;

            let payload = cr.cached_bytes();
            if payload.is_empty() {
                total_attempt += 1;
            } else {
                match sniffer.sniff(&payload, network) {
                    Ok(result) => break Ok(result),
                    Err(DispatcherError::NoClue) => total_attempt += 1,
                    Err(DispatcherError::NeedMoreData) => {}
                    Err(e) => break Err(e),
                }
            }
            if total_attempt >= 2 || cache_deadline.is_zero() {
                break Err(DispatcherError::SniffingTimeout);
            }
        }
    };

    let dest_ip = dest.address().ip();
    match content_result {
        Ok(content) => {
            if !metadata_domain.is_empty() {
                // 两者都有 → CompositeSniffResult 语义
                // protocol_for_domain 用 metadata 侧的 protocol
                let composite = crate::sniffer::CompositeSniffResult::new(
                    Box::new(crate::fakednssniffer::FakeDnsSniffResult::new(&metadata_domain)) as Box<dyn SniffResult>,
                    content,
                );
                if should_override(
                    &composite,
                    req,
                    dest_ip,
                    Some(&metadata_protocol),
                    fakedns_ip_in_pool,
                    None,
                ) {
                    // fakedns 路径（Go default.go:311 判 protocol != "fakedns" 才走
                    // RouteOnly）：拨号必须跟域名（fake IP 不可直连）→ 按 false 传。
                    let (new_dest, route_target) =
                        override_dest(dest, &metadata_domain, false)?;
                    return Ok((new_dest, Some(metadata_protocol), route_target));
                }
            } else if fakedns_ip_in_pool {
                // bk8l（Go newFakeDNSThenOthers）：IP 在 fake 池但映射丢失 → 内容
                // 结果包成 fakedns+others（原始协议供 SnifferIsProtoSubsetOf 子集
                // 匹配），避免向失效假 IP 拨号黑洞。
                let wrapped = crate::fakednssniffer::DnsThenOthersSniffResult::new(
                    content.domain(),
                    content.protocol(),
                );
                if should_override(&wrapped, req, dest_ip, None, true, Some(content.protocol())) {
                    // Go DispatchLink：isFakeIP（池内）时即使 routeOnly 也拨号跟域名
                    let (new_dest, route_target) =
                        override_dest(dest, wrapped.domain(), false)?;
                    return Ok((
                        new_dest,
                        Some(wrapped.protocol().to_string()),
                        route_target,
                    ));
                }
            } else {
                // 仅 content 结果
                if should_override(content.as_ref(), req, dest_ip, None, false, None) {
                    let proto = content.protocol().to_string();
                    let domain = content.domain().to_string();
                    let (new_dest, route_target) =
                        override_dest(dest, &domain, req.route_only)?;
                    return Ok((new_dest, Some(proto), route_target));
                }
            }
        }
        Err(_) => {
            // content sniff 失败，仅用 metadata
            if !metadata_domain.is_empty() {
                let meta_result = crate::fakednssniffer::FakeDnsSniffResult::new(&metadata_domain);
                if should_override(
                    &meta_result,
                    req,
                    dest_ip,
                    Some(&metadata_protocol),
                    fakedns_ip_in_pool,
                    None,
                ) {
                    let (new_dest, route_target) =
                        override_dest(dest, &metadata_domain, false)?;
                    return Ok((new_dest, Some(metadata_protocol.clone()), route_target));
                }
            }
        }
    }

    Ok((dest.clone(), None, None))
}

/// 根据 sniffing 结果产出拨号目标与路由目标。
///
/// 对应 Go default.go:311-315：非 routeOnly → Target = 域名 dest（拨号与路由都用
/// 域名）；routeOnly → RouteTarget = 域名 dest（仅路由用嗅探域名），拨号保持原
/// dest。fakedns 路径拨号必须跟域名（fake IP 不可直连），由调用方以
/// `route_only=false` 传入。返回 `(拨号 dest, 路由覆盖 dest)`。
fn override_dest(
    dest: &xray_common::net::destination::Destination,
    domain: &str,
    route_only: bool,
) -> Result<
    (
        xray_common::net::destination::Destination,
        Option<xray_common::net::destination::Destination>,
    ),
    DispatcherError,
> {
    let new_addr = xray_common::net::address::Address::new_domain(domain.to_string());
    let domain_dest = xray_common::net::destination::Destination::new(
        new_addr, dest.port(), dest.network(),
    );
    if route_only {
        tracing::debug!(domain = %domain, "sniffed (route_only, dest unchanged, route target set)");
        return Ok((dest.clone(), Some(domain_dest)));
    }
    tracing::debug!(domain = %domain, "sniffed, overriding dest");
    Ok((domain_dest, None))
}

/// 从 destination + sniffing 结果构造 RoutingContext。
///
/// 对应 Go `routing_context` 构造。
fn build_routing_context(
    dest: &xray_common::net::destination::Destination,
    sniffed_protocol: Option<&str>,
) -> DispatcherContext {
    let mut ctx = DispatcherContext::new()
        .with_target_port(dest.port())
        .with_network(dest.network());

    // 地址
    match dest.address().ip() {
        Some(ip) => ctx.target_ips = vec![ip],
        None => ctx = ctx.with_target_domain(dest.address().as_domain().unwrap_or("")),
    }

    // protocol（从 sniffing 结果设置）
    if let Some(proto) = sniffed_protocol {
        ctx = ctx.with_protocol(proto);
    }

    ctx
}

/// 从 `from`（`ip:port`）解析源 IP。c10t：让 SourceIpMatcher 规则命中。
fn parse_from_ip(from: &str) -> Option<IpAddr> {
    from.rsplit_once(':').and_then(|(ip_s, _)| ip_s.parse().ok())
}

/// 从 `from`（`ip:port`）解析源端口。
fn parse_from_port(from: &str) -> Option<u16> {
    from.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// 懒注册并取 counter（对应 Go `stats.Manager.GetCounter` 的 create-if-missing 语义）。
///
/// Rust 端 [`xray_features::stats::Manager::get_counter`] 仅查询（miss 返回 None），
/// dispatcher 需要在首次包装时注册 counter 才能被 stats API 查到。
fn get_or_register_counter_opt(
    stats: Option<&Arc<dyn xray_features::stats::Manager>>,
    name: &str,
) -> Option<Arc<dyn xray_features::stats::Counter>> {
    stats.and_then(|m| {
        xray_features::stats::get_or_register_counter(m.as_ref(), name).ok()
    })
}

/// 从 access.from（`SocketAddr` 字符串形态）提取主机部分。
///
/// 对应 Go `sessionInbound.Source.Address.String()`：`1.2.3.4:80` → `1.2.3.4`、
/// `[::1]:80` → `[::1]`（带方括号，与 OnlineMap localhost 字面量形态一致）。
fn source_host(from: &str) -> &str {
    match from.rfind(':') {
        Some(i) => &from[..i],
        None => from,
    }
}

/// 在线 IP 引用计数守卫：连接 fut 结束（含 early return / panic unwind）时
/// 自动 remove_ip。对应 Go `context.AfterFunc(ctx, func() { om.RemoveIP(ip) })`
/// （default.go:224-229）。
struct OnlineIpGuard {
    om: Option<Arc<dyn xray_features::stats::OnlineMap>>,
    ip: String,
}

impl Drop for OnlineIpGuard {
    fn drop(&mut self) {
        if let Some(om) = &self.om {
            om.remove_ip(&self.ip);
        }
    }
}

// ========== DefaultDispatcher ==========

/// 默认分发器
///
/// 对应 Go `DefaultDispatcher struct { ohm, router, policy, stats, fdns }`。
pub struct DefaultDispatcher {
    /// 出站管理器
    pub ohm: Option<Arc<dyn OutboundHandlerManager>>,
    /// 路由器（可选）
    pub router: Option<Arc<dyn RoutingRouter>>,
    /// Policy manager（per-user 策略查询，对应 Go `policy.Manager`）。
    pub policy_manager: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    pub default_policy: xray_features::policy::Policy,
    /// Stats manager（对应 Go `stats.Manager`），用于按 tag 查 counter
    pub stats: Option<Arc<dyn xray_features::stats::Manager>>,
    /// FakeDnsEngine 引用
    pub fdns: Option<Arc<dyn crate::fakednssniffer::FakeDnsEngine>>,
    /// per-outbound-tag 的 UDP443（QUIC over XUDP）策略（bd g35）。
    ///
    /// 对应 Go `Handler.udp443`（`senderSettings.MultiplexSettings.XudpProxyUDP443`，
    /// 仅 mux enabled 时构建）。tag 无条目 = mux 未启用，不做 UDP443 检查。
    pub udp443_policies: HashMap<String, Udp443Policy>,
    /// Access 日志 sink（对应 Go dispatcher `log.Record(accessMessage)`，bd 4uu）。
    ///
    /// None = 不记 access log（等价 Go ctx 无 AccessMessage → 不 Record）。
    pub access_sink: Option<Arc<dyn AccessLogSink>>,
}

impl Debug for DefaultDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultDispatcher")
            .field("has_ohm", &self.ohm.is_some())
            .field("has_router", &self.router.is_some())
            .field("has_stats", &self.stats.is_some())
            .field("has_policy_manager", &self.policy_manager.is_some())
            .field("has_fdns", &self.fdns.is_some())
            .field("udp443_policies", &self.udp443_policies)
            .finish()
    }
}

impl Default for DefaultDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultDispatcher {
    /// 创建空 dispatcher。
    #[must_use]
    pub fn new() -> Self {
        Self {
            ohm: None,
            router: None,
            default_policy: xray_features::policy::Policy::default(),
            stats: None,
            fdns: None,
            policy_manager: None,
            udp443_policies: HashMap::new(),
            access_sink: None,
        }
    }

    /// 初始化。对应 Go `(*DefaultDispatcher).Init(config, om, router, pm, sm)`。
    pub fn init(
        &mut self,
        _config: &crate::Config,
        ohm: Arc<dyn OutboundHandlerManager>,
        router: Option<Arc<dyn RoutingRouter>>,
        default_policy: xray_features::policy::Policy,
        fdns: Option<Arc<dyn crate::fakednssniffer::FakeDnsEngine>>,
    ) {
        self.ohm = Some(ohm);
        self.router = router;
        self.default_policy = default_policy;
        self.fdns = fdns;
    }

    /// 设置 Policy Manager。对应 Go `(*DefaultDispatcher).Init` 传入 `pm policy.Manager`。
    ///
    /// 设置后，dispatch 用 `policy_for_level(user_level)` 动态查询策略，
    /// 而非使用硬编码 `default_policy`。当前 user_level 固定 0（dispatch 签名未携带用户信息）。
    pub fn set_policy_manager(&mut self, pm: Arc<dyn xray_features::policy::PolicyManager>) {
        self.policy_manager = Some(pm);
    }

    /// 注入 FakeDNS 引擎（对应 Go `DefaultDispatcher.fdns`，嗅探阶段反查 fake IP 域名）。
    pub fn set_fdns(&mut self, fdns: Option<Arc<dyn crate::fakednssniffer::FakeDnsEngine>>) {
        self.fdns = fdns;
    }

    /// Start 钩子（空操作）。对应 Go `(*DefaultDispatcher).Start()`。
    pub fn start(&self) -> Result<(), DispatcherError> {
        Ok(())
    }

    /// Close 钩子（空操作）。对应 Go `(*DefaultDispatcher).Close()`。
    pub fn close(&self) -> Result<(), DispatcherError> {
        Ok(())
    }

    /// 分发入站连接，返回 inbound Link 给 inbound handler。
    ///
    /// 对应 Go `(*DefaultDispatcher).Dispatch(ctx, destination) (*transport.Link, error)`。
    ///
    /// # 流程（对应 Go `getLink` + `routedDispatch`）
    /// 1. 创建两对 pipe：`uplink`（inbound → outbound 上行）+ `downlink`（outbound → inbound 下行）
    /// 2. 拼装 inbound Link（读 downlink/写 uplink）+ outbound Link（读 uplink/写 downlink）
    /// 3. 调 [`Self::dispatch_link`] 在后台 spawn outbound handler
    /// 4. 返回 inbound Link 给 inbound 端
    ///
    /// 当前切片不含 sniffing / routing；handler 选择由 [`Self::dispatch_link`] 内部完成。
    pub fn dispatch(
        &self,
        destination: &xray_common::net::destination::Destination,
        sniffing_request: &SniffingRequest,
        inbound_tag: Option<&str>,
        outbound_tag: Option<&str>,
    ) -> Result<xray_transport::link::Link, DispatcherError> {
        // ponytail: policy_manager 存在时用 policy_for_level(0) 动态查询策略，
        // 否则回退到 default_policy。per-user level 需 dispatch 签名变更（deferred）。
        let policy = self
            .policy_manager
            .as_ref()
            .map_or(self.default_policy.clone(), |pm| pm.policy_for_level(0));
        // pipe 选项对应 Go transport/pipe.OptionsFromContext：
        // buffer.PerConnection → WithSizeLimit（512KiB 背压上限）。
        let pipe_opt = xray_buf::pipe::PipeOption {
            limit: policy.buffer.connection as i64,
            idle_timeout: Some(policy.timeout.connection_idle),
            ..xray_buf::pipe::PipeOption::default()
        };
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);

        // 查 inbound/outbound counter（对应 Go routedDispatch 中 getStatCounter）
        // counter_name 规则："{kind}>>>{tag}>>>traffic>>>{direction}"
        // Go 的 stats.Manager.GetCounter 为 create-if-missing；Rust 端 get_counter 仅查询，
        // 故用 get_or_register_counter 保持懒注册语义。
        // Go: inbound uplink = inbound 写上行 = up_w
        // Go: inbound downlink = inbound 读下行 = dn_r
        // Go: outbound uplink = outbound 读上行 = up_r
        // Go: outbound downlink = outbound 写下行 = dn_w
        // sm80①（原 oz1t 误用 per-user 门）：per-tag 计数受 `ForSystem().Stats`
        // 四门门控（Go proxyman/inbound/always.go:26,34 + outbound/handler.go:39,47），
        // 默认全 false 不计数；`UserUplink/Downlink` 只门控 user>>>email 计数
        // （Go default.go:162-166）。计数范围含协议 overhead：`mb.len()` 已含
        // header+payload，SizeStatWriter/Reader 累加语义与 Go 一致。
        let sys = self
            .policy_manager
            .as_ref()
            .map_or_else(xray_features::policy::SystemStats::default, |pm| {
                pm.for_system()
            });
        let inbound_uplink = if sys.inbound_uplink {
             inbound_tag.and_then(|tag| {
                 get_or_register_counter_opt(
                     self.stats.as_ref(),
                     &format!("inbound>>>{tag}>>>traffic>>>uplink"),
                 )
             })
         } else {
             None
         };
        let inbound_downlink = if sys.inbound_downlink {
             inbound_tag.and_then(|tag| {
                 get_or_register_counter_opt(
                     self.stats.as_ref(),
                     &format!("inbound>>>{tag}>>>traffic>>>downlink"),
                 )
             })
         } else {
             None
         };
        let outbound_uplink = if sys.outbound_uplink {
             outbound_tag.and_then(|tag| {
                 get_or_register_counter_opt(
                     self.stats.as_ref(),
                     &format!("outbound>>>{tag}>>>traffic>>>uplink"),
                 )
             })
         } else {
             None
         };
        let outbound_downlink = if sys.outbound_downlink {
             outbound_tag.and_then(|tag| {
                 get_or_register_counter_opt(
                     self.stats.as_ref(),
                     &format!("outbound>>>{tag}>>>traffic>>>downlink"),
                 )
             })
         } else {
             None
         };

        // 包装 link 端的 writer/reader
        // inbound 端：写上行（uplink）+ 读下行（downlink）
        let inbound_writer = crate::stats::maybe_wrap_writer(inbound_uplink, Box::new(up_w));
        let inbound_reader = crate::stats::maybe_wrap_reader(inbound_downlink, Box::new(dn_r));
        // outbound 端：读上行（uplink）+ 写下行（downlink）
        let outbound_reader = crate::stats::maybe_wrap_reader(outbound_uplink, Box::new(up_r));
        let outbound_writer = crate::stats::maybe_wrap_writer(outbound_downlink, Box::new(dn_w));

        let inbound = xray_transport::link::Link::new(inbound_reader, inbound_writer);
        let outbound = xray_transport::link::Link::new(outbound_reader, outbound_writer);
        // 启动 outbound handler；dispatch_link 内部 spawn handler.dispatch(outbound)
        self.dispatch_link(destination, outbound, sniffing_request, None, None)?;
        Ok(inbound)
    }

    /// 经 forced tag 定向拨号（对应 Go `tagged/taggedimpl.DialTaggedOutbound`，bd kz1）。
    ///
    /// Go 语义（impl.go:15-36）：设 `Content.SkipDNSResolve=true` + forced outbound tag
    /// 后走 `dispatcher.Dispatch` 完整链，消费点在 routedDispatch（default.go:443-454）：
    /// tag 无效即丢弃链路、不落默认出站。返回 Link 等价 Go `cnc.NewConnection` 包装。
    ///
    /// `SkipDNSResolve` 无需传递：forced 分支不经过路由（其路由侧消费点天然跳过）；
    /// handler 侧 TargetStrategy 的 per-request skip 在 Rust dial_fn 链无 ctx 可传
    /// （gap 见 outbound.rs `wrap_dial_with_target_strategy` 注记）。
    ///
    /// Go 消费方：geodata 下载（download.go:76）/ observatory（observer.go:146）/
    /// burst ping（ping.go:42）。
    pub fn dispatch_tagged(
        &self,
        destination: &xray_common::net::destination::Destination,
        tag: &str,
    ) -> Result<xray_transport::link::Link, DispatcherError> {
        if tag.is_empty() {
            return Err(DispatcherError::Other("empty forced outbound tag".into()));
        }
        // pipe 选项与 dispatch() 一致（Go DialTaggedOutbound 经同一 Dispatch 入口建链）
        let policy = self
            .policy_manager
            .as_ref()
            .map_or(self.default_policy.clone(), |pm| pm.policy_for_level(0));
        let pipe_opt = xray_buf::pipe::PipeOption {
            limit: policy.buffer.connection as i64,
            idle_timeout: Some(policy.timeout.connection_idle),
            ..xray_buf::pipe::PipeOption::default()
        };
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        // inbound/outbound tag counter 均省略：Go ctx 无 session（DialTaggedOutbound 场景），
        // outbound counter 由 dispatch_link 尾段按命中 handler tag 懒注册。
        let inbound = xray_transport::link::Link::new(Box::new(dn_r), Box::new(up_w));
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));
        self.dispatch_link(
            destination,
            outbound,
            &SniffingRequest::default(),
            None,
            Some(tag),
        )?;
        Ok(inbound)
    }

    /// 分发已有 link。
    ///
    /// 对应 Go `(*DefaultDispatcher).DispatchLink(ctx, dest, outbound) error`。
    ///
    /// 流程（对应 Go `routedDispatch`）：
    /// 1. 若 sniffing 启用：用 CachedReader 包装 outbound reader，读首包 → sniff → 可能覆盖 dest
    /// 2. `forced_tag` 非空：按 tag 直取 handler，无效即 Err，不回退默认
    ///    （Go default.go:443-454 "platform initialized detour"，tag 不存在直接丢弃不落默认出站）
    /// 3. 若有 router：用 RoutingContext 调 router.pick_route() 选出站 handler
    /// 4. 无 router 或路由失败：用默认 handler
    /// 5. 记 access log（Accepted，含 detour 组合；对应 Go default.go:488-502）
    /// 6. spawn handler.dispatch(link)
    ///
    /// `access` 为 None 时不记（等价 Go ctx 无 AccessMessage）。
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_link(
        &self,
        destination: &xray_common::net::destination::Destination,
        outbound: xray_transport::link::Link,
        sniffing_request: &SniffingRequest,
        access: Option<AccessContext>,
        forced_tag: Option<&str>,
    ) -> Result<(), DispatcherError> {
        let ohm = self.ohm.as_ref().ok_or_else(|| {
            DispatcherError::Other("no outbound handler manager registered".into())
        })?;

        let forced_tag = forced_tag.map(str::to_string);
        // 预检查：forced tag 无效即同步 Err，绝不回退默认出站
        // （Go default.go:449-454 tag 不存在直接丢弃链路，DO NOT CHANGE 注释；
        // Rust 侧提升为同步错误，语义等价且调用方可提前感知）
        if !forced_tag.as_deref().unwrap_or_default().is_empty()
            && ohm.get_handler(forced_tag.as_deref().unwrap_or_default()).is_none()
        {
            return Err(DispatcherError::HandlerNotFound(
                forced_tag.unwrap_or_default(),
            ));
        }

        // 预检查：如果没有 router 也没有 default handler，直接报错
        // （sniffing 后路由可能找到非 default handler，但无 router 无 default = 必定失败）
        if forced_tag.as_deref().unwrap_or_default().is_empty()
            && self.router.is_none()
            && ohm.get_default_handler().is_none()
            // 无路由可用 → Rejected（Go 仅 errors log；rejected 记录为 assignment 要求的扩展）
        {
            if let (Some(sink), Some(ctx)) = (&self.access_sink, access) {
                sink.record_access(&AccessLogEntry {
                    from: ctx.from,
                    to: destination.to_string(),
                    status: "rejected",
                    reason: "no outbound handler available".into(),
                    email: ctx.email,
                    detour: ctx.inbound_tag,
                });
            }
            return Err(DispatcherError::HandlerNotFound("default".into()));
        }

        // 克隆必要数据进入 spawn
        let dest = destination.clone();
        let sniff_req = sniffing_request.clone();
        let router = self.router.clone();
        let fdns = self.fdns.clone();
        let stats = self.stats.clone();
        let udp443_policies = self.udp443_policies.clone();
        let ohm = Arc::clone(ohm);
        let access_sink = self.access_sink.clone();
        // per-user policy 层级（Go d.policy.ForLevel(user.Level)，default.go:162）：
        // access.level 缺省 0，无用户信息时与既有行为一致。
        let user_level = access.as_ref().map_or(0, |a| a.level);
        let policy = self
            .policy_manager
            .as_ref()
            .map_or(self.default_policy.clone(), |pm| {
                pm.policy_for_level(user_level)
            });
        // per-user stats 上下文（Go getLink default.go:161-185）：email 非空才挂接。
        let user_email = access.as_ref().map_or(String::new(), |a| a.email.clone());
        let user_host = access
            .as_ref()
            .map_or(String::new(), |a| source_host(&a.from).to_string());
        // sm80①：outbound tag counter 门控（Go proxyman/outbound/handler.go:39,47
        // ForSystem().Stats.Outbound{Uplink,Downlink}），spawn 前取快照进 async。
        let sys_stats = self
            .policy_manager
            .as_ref()
            .map_or_else(xray_features::policy::SystemStats::default, |pm| {
                pm.for_system()
            });
        let policy_stats = policy.stats.clone();
        let outbound_reader = outbound.reader;
        let outbound_writer = outbound.writer;
        let fut = async move {
            // ---- Phase 1: Sniffing ----
            let mut cr = CachedReader::with_inner(outbound_reader);
            let (final_dest, sniffed_protocol, route_target) = if sniff_req.enabled {
                match sniff_connection(
                    &mut cr, &dest, &sniff_req, fdns.as_deref(),
                ).await {
                    Ok((d, proto, rt)) => (d, proto, rt),
                    Err(e) => {
                        tracing::debug!(dest = %dest, error = %e, "sniffing failed, using original dest");
                        (dest.clone(), None, None)
                    }
                }
            } else {
                (dest.clone(), None, None)
            };
            // ---- Phase 2: Forced tag 旁路（Go default.go:443-454）----
            let (handler, routed_pick) = if !forced_tag.as_deref().unwrap_or_default().is_empty() {
                let tag = forced_tag.clone().unwrap_or_default();
                match ohm.get_handler(&tag) {
                    Some(h) => {
                        tracing::debug!(tag = %tag, "taking platform initialized detour for [%final_dest]");
                        (Some(h), false)
                    }
                    None => {
                        // Go DO NOT CHANGE 注释：指定 tag 不存在时不得落到默认出站
                        tracing::error!(tag = %tag, "non existing tag for platform initialized detour");
                        outbound_writer.shutdown();
                        // outbound_reader 随 drop 关闭上行
                        return;
                    }
                }
            }
            // ---- Phase 2: Routing（resolved：domainStrategy DNS 解析路径） ----
            // pick_route_resolved 默认退化为同步 pick_route；RouterAdapter 生产实现
            // 委托 xray_app_router::Router::pick_route_resolved（携带完整 RoutingContext）。
            else if let Some(r) = &router {
                let mut ctx = build_routing_context(&final_dest, sniffed_protocol.as_deref());
                // Go routing.Context 携带 inbound tag / source / user（c10t）：
                // InboundTagMatcher / SourceIpMatcher / UserMatcher 依赖这些字段；
                // 此前只回填 inbound_tag，source/user 静默失效 → 对应规则永不命中。
                if let Some(a) = &access {
                    ctx = ctx.with_inbound_tag(a.inbound_tag.as_str());
                    // c10t：源地址解析（`from` 是 "ip:port" 形态）；取 IP 部分。
                    if let Some(ip) = parse_from_ip(&a.from) {
                        ctx = ctx.with_source_ips(vec![ip]);
                    }
                    // c10t：源端口解析；同字符串 split。
                    if let Some(port) = parse_from_port(&a.from) {
                        ctx = ctx.with_source_port(xray_common::net::port::Port::new(port));
                    }
                    if !a.email.is_empty() {
                        ctx = ctx.with_user(a.email.as_str());
                    }
                }
                // routeOnly（Go default.go:311-315）：路由用嗅探域名（route_target），
                // 拨号保持 final_dest（原 dest）。
                if let Some(rt) = &route_target {
                    ctx.route_target = Some(rt.clone());
                }
                match r.pick_route_resolved(&ctx).await {
                    Ok(route) => match ohm.get_handler(&route.outbound_tag) {
                        Some(h) => (Some(h), true),
                        None => {
                            // Go default.go:469-470 DO NOT CHANGE：路由指定的 outboundTag
                            // 不存在时不得落默认出站（如 VLESS Reverse Proxy）。
                            tracing::warn!(tag = %route.outbound_tag, "non existing outTag");
                            outbound_writer.shutdown();
                            // outbound_reader 随 drop 关闭上行
                            return;
                        }
                    },
                    Err(_) => (ohm.get_default_handler(), false),
                }
            } else {
                (ohm.get_default_handler(), false)
            };

            let Some(handler) = handler else {
                // 无可用出站 → Rejected（Go 此处仅 errors log 后 return，bd 4uu 扩展记录）
                if let Some(sink) = &access_sink {
                    if let Some(ctx) = &access {
                        sink.record_access(&AccessLogEntry {
                            from: ctx.from.clone(),
                            to: final_dest.to_string(),
                            status: "rejected",
                            reason: "no outbound handler available".into(),
                            email: ctx.email.clone(),
                            detour: ctx.inbound_tag.clone(),
                        });
                    }
                }
                tracing::error!("no outbound handler available");
                return;
            };

            // ---- Access log（对应 Go default.go:488-502 routedDispatch 记录点） ----
            // Go: Record 发生在 handler.Dispatch 之前，detour 组合规则：
            //   inTag 空 → tag；isPickRoute=2（路由命中）→ "in -> tag"；其余 → "in >> tag"。
            if let (Some(sink), Some(ctx)) = (&access_sink, &access) {
                let out_tag_early = handler.tag();
                let detour = if out_tag_early.is_empty() {
                    String::new()
                } else if ctx.inbound_tag.is_empty() {
                    out_tag_early.to_string()
                } else if routed_pick {
                    format!("{} -> {}", ctx.inbound_tag, out_tag_early)
                } else {
                    format!("{} >> {}", ctx.inbound_tag, out_tag_early)
                };
                sink.record_access(&AccessLogEntry {
                    from: ctx.from.clone(),
                    to: final_dest.to_string(),
                    status: "accepted",
                    reason: String::new(),
                    email: ctx.email.clone(),
                    detour,
                });
            }
            // outbound counter（对应 Go routedDispatch 的 getStatCounter，按命中 tag 懒注册）：
            // uplink = outbound 读上行（reader），downlink = outbound 写下行（writer）
            let out_tag = handler.tag().to_string();
            // sm80①：同 dispatch()，outbound tag counter 受 ForSystem 门控（默认关）。
            let out_up = if sys_stats.outbound_uplink {
                get_or_register_counter_opt(
                    stats.as_ref(),
                    &format!("outbound>>>{out_tag}>>>traffic>>>uplink"),
                )
            } else {
                None
            };
            let out_dn = if sys_stats.outbound_downlink {
                get_or_register_counter_opt(
                    stats.as_ref(),
                    &format!("outbound>>>{out_tag}>>>traffic>>>downlink"),
                )
            } else {
                None
            };

            // CachedReader 始终包装 outbound_reader，sniffing 时回放缓存首包
            let mut reader: Box<dyn xray_buf::io::Reader> =
                crate::stats::maybe_wrap_reader(out_up, Box::new(cr));
            let mut writer = crate::stats::maybe_wrap_writer(out_dn, outbound_writer);

            // ---- per-user stats（对应 Go getLink default.go:161-185，email 非空挂接） ----
            // uplink：Go 包 inboundLink.Writer（上行 pipe 入站写端）；Rust inbound 端
            // 包装在生产入口（xray-core wiring），dispatch_link 仅持 outbound 端 →
            // 包 outbound reader（同一数据流的读出端，连接生命周期内计数等价，
            // 瞬时差 ≤ pipe 缓冲）。downlink：Go 包 outboundLink.Writer，同位。
            let _online_guard = if !user_email.is_empty() {
                if policy_stats.user_uplink {
                    let up = get_or_register_counter_opt(
                        stats.as_ref(),
                        &format!("user>>>{user_email}>>>traffic>>>uplink"),
                    );
                    reader = crate::stats::maybe_wrap_reader(up, reader);
                }
                if policy_stats.user_downlink {
                    let dn = get_or_register_counter_opt(
                        stats.as_ref(),
                        &format!("user>>>{user_email}>>>traffic>>>downlink"),
                    );
                    writer = crate::stats::maybe_wrap_writer(dn, writer);
                }
                // Go trackOnlineIP（default.go:224-229）：GetOrRegisterOnlineMap +
                // AddIP；RemoveIP 由 guard 在连接 fut 结束时执行（引用计数归零）。
                if policy_stats.user_online && !user_host.is_empty() {
                    let om = stats.as_ref().and_then(|m| {
                        xray_features::stats::get_or_register_online_map(
                            m.as_ref(),
                            &format!("user>>>{user_email}>>>online"),
                        )
                        .ok()
                    });
                    if let Some(om) = &om {
                        om.add_ip(&user_host);
                    }
                    Some(OnlineIpGuard {
                        om,
                        ip: user_host,
                    })
                } else {
                    None
                }
            } else {
                None
            };

            // ---- UDP443 policy（bd g35，Go handler.go:220-228） ----
            // 仅 mux 启用的出站有条目（Go h.udp443 只在 MultiplexSettings.Enabled 时设置）。
            if final_dest.network() == Network::UDP && final_dest.port().value() == 443 {
                match udp443_policies.get(handler.tag()) {
                    Some(Udp443Policy::Reject) => {
                        // Go: test(errors.New("XUDP rejected UDP/443 traffic").AtInfo()) → Interrupt 双向
                        tracing::info!(tag = %out_tag, "XUDP rejected UDP/443 traffic");
                        writer.shutdown(); // 关闭下行 → inbound reader EOF
                        return; // reader 随 drop 关闭上行
                    }
                    // skip（Go goto out 直发）/ allow（xudp dispatch，mbc/nww 接入前等价直发）
                    Some(_) | None => {}
                }
            }

            // ---- EndpointOverride（bd g35，Go handler.go:206-209） ----
            // UDP 且 sniffing 将 OriginalTarget 改写为 Target 时，改写 XUDP 帧携带的
            // 逐包地址：上行 original→override，下行 override→original。
            let (reader, writer) = if final_dest.network() == Network::UDP
                && final_dest.address() != dest.address()
            {
                let original = dest.address().clone();
                let target = final_dest.address().clone();
                (
                    Box::new(crate::endpoint_override::EndpointOverrideReader::new(
                        reader,
                        original.clone(),
                        target.clone(),
                    )) as Box<dyn xray_buf::io::Reader>,
                    Box::new(crate::endpoint_override::EndpointOverrideWriter::new(
                        writer,
                        target,
                        original,
                    )) as Box<dyn xray_buf::io::Writer>,
                )
            } else {
                (reader, writer)
            };
            let final_link = xray_transport::link::Link::new(reader, writer);

            let fut = handler.dispatch_with_access(&final_dest, final_link, access.unwrap_or_default());
            let _ = fut.await;
        };

        tokio::spawn(fut);
        Ok(())
    }
}

// ========== CachedReader ==========

/// 缓存 reader：嗅探时暂存 payload，避免数据丢失
///
/// 对应 Go `cachedReader struct { sync.Mutex; reader buf.TimeoutReader; cache buf.MultiBuffer }`。
///
/// 读首包时缓存到 `cache`，后续正常读取时先回放缓存再读 inner，确保数据不丢。
pub struct CachedReader {
    /// 内部 reader
    inner: Option<Box<dyn xray_buf::io::Reader>>,
    /// 已缓存的 MultiBuffer（sniffing 时暂存的首包）
    cache: Option<MultiBuffer>,
}

impl Debug for CachedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedReader")
            .field("has_inner", &self.inner.is_some())
            .field("has_cache", &self.cache.is_some())
            .finish()
    }
}

impl Default for CachedReader {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedReader {
    /// 创建空 cached reader。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: None,
            cache: None,
        }
    }

    /// 用 inner reader 构造。
    #[must_use]
    pub fn with_inner(r: Box<dyn xray_buf::io::Reader>) -> Self {
        Self {
            inner: Some(r),
            cache: None,
        }
    }

    /// 设置内部 reader。
    pub fn set_inner(&mut self, r: Box<dyn xray_buf::io::Reader>) {
        self.inner = Some(r);
    }

    /// 中断：清空 cache 并中断内部 reader。
    pub fn interrupt(&mut self) {
        self.cache = None;
    }

    /// 读首包并缓存。返回首包字节的引用（通过 cache）。
    ///
    /// 对应 Go `cachedReader.ReadFirst` — 读 MultiBuffer 存入 cache。
    pub async fn read_first(&mut self) -> Result<(), DispatcherError> {
        if self.cache.is_some() {
            return Ok(());
        }
        let inner = self.inner.as_mut().ok_or_else(|| {
            DispatcherError::Io("cached reader: no inner reader".into())
        })?;
        let mb = inner.read_multi_buffer().await.map_err(|e| {
            DispatcherError::Io(format!("cached reader read_first: {e}"))
        })?;
        if !mb.is_empty() {
            self.cache = Some(mb);
        }
        Ok(())
    }

    /// 在已缓存的首包后追加读一包（need-more 重试用）。返回是否实际读到字节。
    ///
    /// 对应 Go `cachedReader.ReadMore`：sniffer 返回 `ErrProtoNeedMoreData` 时
    /// 200ms×2 次重试预算，等客户端 ClientHello 后续分段到达。仅追加（不清空首包
    /// 缓存）；cache 为空等价单次 read（不视作首包保护，由调用方自决）。
    pub async fn read_more(&mut self) -> Result<bool, DispatcherError> {
        let inner = self.inner.as_mut().ok_or_else(|| {
            DispatcherError::Io("cached reader: no inner reader".into())
        })?;
        let mb = inner.read_multi_buffer().await.map_err(|e| {
            DispatcherError::Io(format!("cached reader read_more: {e}"))
        })?;
        if mb.is_empty() {
            return Ok(false);
        }
        if let Some(c) = self.cache.as_mut() {
            c.merge(mb);
        } else {
            self.cache = Some(mb);
        }
        Ok(true)
    }

    /// 取缓存的首包字节切片（用于 sniffing）。
    pub fn cached_bytes(&self) -> Vec<u8> {
        self.cache.as_ref().map_or(Vec::new(), |mb| mb.to_vec())
    }
}

impl xray_buf::io::Reader for CachedReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer, xray_buf::io::Error>> + Send + '_>> {
        Box::pin(async move {
            // 先回放缓存
            if let Some(cached) = self.cache.take() {
                if !cached.is_empty() {
                    return Ok(cached);
                }
            }
            // 缓存空，读 inner
            let inner = self.inner.as_mut().ok_or_else(|| {
                xray_buf::io::Error::ReadError("cached reader: no inner reader".into())
            })?;
            inner.read_multi_buffer().await
        })
    }
}

// ========== DialBridge：通用 Dial→Bridge adapter ==========

use xray_transport::bridge::{
    bridge_link_with_link, bridge_link_with_link_default, bridge_link_with_stream_full,
    bridge_link_with_stream_full_default,
};
use xray_transport::connection::Connection;

/// 拨号闭包类型：dest → Box<dyn Connection>
pub type DialFn = Arc<
    dyn Fn(&xray_common::net::destination::Destination) -> PinFuture<Result<Box<dyn Connection>, String>>
        + Send
        + Sync,
>;

/// 通用 dial→bridge adapter。
///
/// 接收一个拨号闭包（dest → Connection），impl [`DispatchHandler`]。
/// `dispatch(dest, link)` 内部：`dial(dest)` → [`bridge_link_with_stream`](link, remote)。
///
/// ## 代理链（Proxy Chain）
///
/// 对应 Go `OutboundHandlerEntry.dial()` 中 `senderSettings.ProxySettings.HasTag()` 逻辑。
/// 当 `proxy_chain_tag` 存在时，dispatch 不直接拨号，而是：
/// 1. 通过 `outbound_manager` 按 tag 查找 chained handler
/// 2. 创建 duplex pipe（client 端返回给调用者，proxy 端桥接到 chained handler）
/// 3. 将 link 桥接到 client 端，chained handler 处理真实拨号
pub struct DialBridge {
    tag: String,
    dial: DialFn,
    /// 代理链配置（对应 Go `senderSettings.ProxySettings`）。
    ///
    /// 用 `RwLock` 包裹以支持注册后设置（Phase 1 注册 handler，Phase 2 设置代理链）。
    proxy_chain: std::sync::RwLock<ProxyChainConfig>,
    /// 可选 policy：None 时 bridge 用 `TimeoutPolicy::default()`。
    /// 由 dispatcher 在装配时通过 [`Self::with_policy`] 注入，按 user_level 查询。
    policy: std::sync::RwLock<Option<xray_features::policy::TimeoutPolicy>>,
}

/// 代理链配置。
struct ProxyChainConfig {
    /// 代理链目标 tag（对应 Go `senderSettings.ProxySettings.Tag`）。
    chain_tag: Option<String>,
    /// 出站管理器引用（代理链拨号时查找 chained handler）。
    outbound_manager: Option<Arc<dyn OutboundHandlerManager>>,
}

impl DialBridge {
    #[must_use]
    pub fn new(tag: impl Into<String>, dial: DialFn) -> Self {
        Self {
            tag: tag.into(),
            dial,
            proxy_chain: std::sync::RwLock::new(ProxyChainConfig {
                chain_tag: None,
                outbound_manager: None,
            }),
            policy: std::sync::RwLock::new(None),
        }
    }

    /// 注入 per-dispatch 桥接 policy（bd 4-6：bridge 数据面超时接 policy）。
    /// 用 `&self` 因为注册 handler 之后仍可能需要按 per-dispatch 设置。
    pub fn with_policy(&self, p: xray_features::policy::TimeoutPolicy) {
        *self.policy.write().expect("DialBridge policy lock poisoned") = Some(p);
    }

    /// 取当前 policy（无显式设置时用 default）。
    fn current_policy(&self) -> xray_features::policy::TimeoutPolicy {
        self.policy
            .read()
            .expect("DialBridge policy lock poisoned")
            .clone()
            .unwrap_or_default()
    }

    /// 设置代理链 tag 和出站管理器。
    ///
    /// 对应 Go `senderSettings.ProxySettings.Tag`。
    /// 必须同时设置 `outbound_manager`，否则代理链无法查找 chained handler。
    ///
    /// 因为 `DialBridge` 在注册为 `DispatchHandler` 后仍需设置代理链，
    /// 此方法接受 `&self`（内部用 `RwLock` 保护）。
    pub fn set_proxy_chain(
        &self,
        chain_tag: impl Into<String>,
        manager: Arc<dyn OutboundHandlerManager>,
    ) {
        let mut guard = self.proxy_chain.write().expect("DialBridge proxy_chain lock poisoned");
        guard.chain_tag = Some(chain_tag.into());
        guard.outbound_manager = Some(manager);
    }

    /// 代理链 tag 是否已设置。
    #[must_use]
    pub fn has_proxy_chain(&self) -> bool {
        self.proxy_chain.read().expect("DialBridge proxy_chain lock poisoned").chain_tag.is_some()
    }

    /// 获取代理链配置的快照（chain_tag, outbound_manager clone）。
    fn get_proxy_chain(&self) -> (Option<String>, Option<Arc<dyn OutboundHandlerManager>>) {
        let guard = self.proxy_chain.read().expect("DialBridge proxy_chain lock poisoned");
        (guard.chain_tag.clone(), guard.outbound_manager.clone())
    }
}

impl std::fmt::Debug for DialBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let chain_tag = self.proxy_chain.read().ok().and_then(|g| g.chain_tag.clone());
        f.debug_struct("DialBridge")
            .field("tag", &self.tag)
            .field("proxy_chain_tag", &chain_tag)
            .finish()
    }
}

impl DispatchHandler for DialBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(
        &self,
        dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> PinFuture<()> {
        // 代理链：如果 proxy_chain_tag 存在，通过 chained handler 拨号
        let (chain_tag, ohm) = self.get_proxy_chain();
        if let Some(chain_tag) = chain_tag {
            return self.dispatch_via_chain(dest, link, chain_tag, ohm);
        }

        // 直接拨号
        let dial = Arc::clone(&self.dial);
        let tag = self.tag.clone();
        let dest = dest.clone();
        let policy = self.current_policy();
        Box::pin(async move {
            match dial(&dest).await {
                Ok(remote) => {
                    if let Err(e) = bridge_link_with_stream_full(link, remote, &policy).await {
                        tracing::warn!(tag = %tag, "bridge ended: {e}");
                    }
                }
                Err(e) => {
                    tracing::error!(tag = %tag, "dial failed: {e}");
                }
            }
        })
    }
}

impl DialBridge {
    /// 代理链 dispatch：通过 chained handler 拨号。
    ///
    /// 对应 Go `OutboundHandlerEntry.dial()` 中 `senderSettings.ProxySettings.HasTag()` 分支。
    /// 流程：
    /// 1. 通过 outbound_manager 按 chain_tag 查找 chained handler
    /// 2. 创建 duplex pipe（client 端桥接到 link，proxy 端交给 chained handler）
    /// 3. spawn 双向桥接：link ↔ client_stream ↔ proxy_stream ↔ chained handler
    fn dispatch_via_chain(
        &self,
        dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
        chain_tag: String,
        ohm: Option<Arc<dyn OutboundHandlerManager>>,
    ) -> PinFuture<()> {
        let tag = self.tag.clone();
        let dest = dest.clone();
        // 提前克隆 policy：避免 async move 持 &self 越界
        let policy = self.current_policy();

        Box::pin(async move {
            let Some(ohm) = ohm else {
                tracing::error!(tag = %tag, "proxy chain tag '{chain_tag}' set but no outbound manager");
                return;
            };
            let Some(chained_handler) = ohm.get_handler(&chain_tag) else {
                tracing::error!(
                    tag = %tag,
                    chain_tag = %chain_tag,
                    "proxy chain handler not found"
                );
                return;
            };

            // 用两对 pipe 代替 duplex，与 DefaultDispatcher::dispatch 一致
            let pipe_opt = xray_buf::pipe::PipeOption::default();
            let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
            let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);

            // client 端 link：读下行（dn_r）+ 写上行（up_w）
            // chained handler 端 link：读上行（up_r）+ 写下行（dn_w）
            let client_link = xray_transport::link::Link::new(
                Box::new(dn_r) as Box<dyn xray_buf::io::Reader>,
                Box::new(up_w) as Box<dyn xray_buf::io::Writer>,
            );
            let chained_link = xray_transport::link::Link::new(
                Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
                Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
            );

            // spawn chained handler dispatch
            let chained_tag = chained_handler.tag().to_string();
            let chained_fut = chained_handler.dispatch(&dest, chained_link);
            tokio::spawn(async move {
                let _ = chained_fut.await;
                tracing::trace!(tag = %chained_tag, "chained handler dispatch done");
            });
            // 桥接原始 link ↔ client_link
            // link.reader → client_link.writer（上行）
            // client_link.reader → link.writer（下行）
            if let Err(e) = bridge_link_with_link(link, client_link, &policy).await {
                tracing::warn!(tag = %tag, "proxy chain bridge ended: {e}");
            }
        })
    }
}

// ========== SimpleOhm：简单 OutboundHandlerManager ==========

/// 简单的 [`OutboundHandlerManager`]：RwLock<HashMap> + default。
///
/// 用于测试和简单场景。生产环境用 `proxyman::OutboundManager`。
pub struct SimpleOhm {
    default: std::sync::RwLock<Option<Arc<dyn DispatchHandler>>>,
    tagged: std::sync::RwLock<std::collections::HashMap<String, Arc<dyn DispatchHandler>>>,
}

impl SimpleOhm {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default: std::sync::RwLock::new(None),
            tagged: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn set_default(&self, handler: Arc<dyn DispatchHandler>) {
        *self.default.write().unwrap() = Some(handler);
    }

    /// 浅快照：共享全部 tagged/default handler（Arc clone），后续对快照的
    /// `set_default` 不影响原 ohm。
    ///
    /// 生产接线（`xray-core` 方案 B）用：每个 inbound 一份快照，default 替换为
    /// 携带该 inbound sniffing 配置的 wrapper，master ohm 的 default 保持真实出站。
    /// 若直接在 master 上 set_default 会造成 dispatch_link → get_default_handler
    /// → wrapper 的无限递归。
    #[must_use]
    pub fn snapshot(&self) -> SimpleOhm {
        Self {
            default: std::sync::RwLock::new(self.default.read().unwrap().clone()),
            tagged: std::sync::RwLock::new(self.tagged.read().unwrap().clone()),
        }
    }

    #[allow(dead_code)]
    pub fn add(&self, tag: &str, handler: Arc<dyn DispatchHandler>) {
        self.tagged.write().unwrap().insert(tag.to_string(), handler);
    }

    /// 移除 tag 对应的 handler。对应 Go `outbound.Manager.RemoveHandler`：
    /// default handler 的 tag 与之相同时 default 一并清空。
    /// 返回 tag 是否存在（不存在 = no-op，由调用方决定是否报错）。
    pub fn remove(&self, tag: &str) -> bool {
        let Some(_old) = self.tagged.write().unwrap().remove(tag) else {
            return false;
        };
        let default_matches = self
            .default
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|h| h.tag() == tag);
        if default_matches {
            *self.default.write().unwrap() = None;
        }
        true
    }

    /// 列出全部 tagged handler 的 tag（动态 AddOutbound/ListOutbounds 用）。
    pub fn list_tags(&self) -> Vec<String> {
        self.tagged.read().unwrap().keys().cloned().collect()
    }
}

impl std::fmt::Debug for SimpleOhm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleOhm").finish()
    }
}

impl Default for SimpleOhm {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundHandlerManager for SimpleOhm {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>> {
        self.tagged.read().unwrap().get(tag).cloned()
    }

    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
        self.default.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniffer::SniffResult;
    use xray_common::net::network::Network;

    /// sm80① 测试 mock：`for_system` 四门全开（tag counter 门控路径）。
    #[derive(Debug)]
    struct SystemStatsAllOnPolicyManager;
    impl xray_features::policy::PolicyManager for SystemStatsAllOnPolicyManager {
        fn policy_for_level(&self, _level: u32) -> xray_features::policy::Policy {
            xray_features::policy::Policy::default()
        }
        fn for_system(&self) -> xray_features::policy::SystemStats {
            xray_features::policy::SystemStats {
                inbound_uplink: true,
                inbound_downlink: true,
                outbound_uplink: true,
                outbound_downlink: true,
                ..Default::default()
            }
        }
    }

    /// sm80① 测试 mock：仅 outbound 两门开（验证门是逐方向的）。
    #[derive(Debug)]
    struct OutboundOnlyPolicyManager;
    impl xray_features::policy::PolicyManager for OutboundOnlyPolicyManager {
        fn policy_for_level(&self, _level: u32) -> xray_features::policy::Policy {
            xray_features::policy::Policy::default()
        }
        fn for_system(&self) -> xray_features::policy::SystemStats {
            xray_features::policy::SystemStats {
                outbound_uplink: true,
                outbound_downlink: true,
                ..Default::default()
            }
        }
    }
    use xray_common::net::address::Address;

    /// 测试用 SniffResult
    #[derive(Debug)]
    struct TestSniffResult {
        protocol: &'static str,
        domain: &'static str,
    }
    impl SniffResult for TestSniffResult {
        fn protocol(&self) -> &str {
            self.protocol
        }
        fn domain(&self) -> &str {
            self.domain
        }
    }

    fn make_sniff(protocol: &'static str, domain: &'static str) -> TestSniffResult {
        TestSniffResult { protocol, domain }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- DispatcherContext ----

    #[test]
    fn context_default_all_empty() {
        let c = DispatcherContext::default();
        assert!(c.get_target_ips().is_empty());
        assert!(c.get_target_domain().is_empty());
        assert!(c.get_user().is_empty());
        assert!(!c.get_skip_dns_resolve());
    }

    #[test]
    fn context_builder_sets_fields() {
        let c = DispatcherContext::new()
            .with_target_domain("example.com")
            .with_network(Network::TCP)
            .with_inbound_tag("inbound")
            .with_user("user@mail")
            .with_protocol("http");
        assert_eq!(c.get_target_domain(), "example.com");
        assert_eq!(c.get_network(), Network::TCP);
        assert_eq!(c.get_inbound_tag(), "inbound");
        assert_eq!(c.get_user(), "user@mail");
        assert_eq!(c.get_protocol(), "http");
    }

    // ---- should_override ----

    #[test]
    fn override_returns_false_when_domain_empty() {
        let r = make_sniff("http", "");
        let req = SniffingRequest::default();
        assert!(!should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_returns_false_when_excluded_by_domain() {
        let r = make_sniff("http", "blocked.example.com");
        let req = SniffingRequest {
            exclude_for_domain: Some(Arc::new(|d: &str| d.contains("blocked"))),
            ..Default::default()
        };
        assert!(!should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_returns_false_when_excluded_by_ip() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_ip: Some(Arc::new(|addr: IpAddr| addr == ip("1.2.3.4"))),
            ..Default::default()
        };
        assert!(!should_override(&r, &req, Some(ip("1.2.3.4")), None, false, None));
    }

    #[test]
    fn override_returns_false_when_no_protocol_match() {
        let r = make_sniff("tls", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_returns_true_when_protocol_prefix_matches() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_returns_true_when_protocol_is_prefix_of_request() {
        // 反向后缀：request="http", protocol="ht" — 用 starts_with 任一侧
        let r = make_sniff("ht", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_uses_protocol_for_domain_when_provided() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["fakedns".to_string()],
            ..Default::default()
        };
        // 传入 protocol_for_domain = "fakedns" 应命中
        assert!(should_override(&r, &req, None, Some("fakedns"), false, None));
    }

    #[test]
    fn override_skips_ip_exclude_when_dest_is_not_ip() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_ip: Some(Arc::new(|addr: IpAddr| addr == ip("1.2.3.4"))),
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        // dest = None 不命中 exclude_for_ip → 继续 protocol 检查 → true
        assert!(should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_domain_exclude_is_case_insensitive() {
        // fv1g：大小写混合嗅探域名经小写化后交给 matcher，同样命中排除
        let r = make_sniff("http", "WWW.Blocked.Example.COM");
        let req = SniffingRequest {
            exclude_for_domain: Some(Arc::new(|d: &str| d.ends_with("blocked.example.com"))),
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, None, None, false, None));
    }

    #[test]
    fn override_ip_exclude_supports_cidr_style_matcher() {
        // fv1g：CIDR 型 IP 排除；命中 → 不覆盖，未命中 → 正常覆盖
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_ip: Some(Arc::new(|addr: IpAddr| {
                matches!(addr, IpAddr::V4(v4) if v4.octets()[0] == 10)
            })),
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, Some(ip("10.1.2.3")), None, false, None));
        assert!(should_override(&r, &req, Some(ip("8.8.8.8")), None, false, None));
    }

    #[test]
    fn override_with_no_exclusions_still_overrides() {
        // None = 无规则（Go nil），覆盖判定不受影响
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_domain: None,
            exclude_for_ip: None,
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, Some(ip("1.2.3.4")), None, false, None));
    }

    /// bk8l（Go default.go:251-255 step2）：IP 在 fake 池、映射丢失，配置
    /// destOverride=["fakedns"] 时任意内容协议（bittorrent 除外）兜底命中
    #[test]
    fn override_fakedns_fallback_hits_when_ip_in_pool() {
        let r = make_sniff("tls", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["fakedns".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, Some(ip("198.51.100.7")), None, true, None));
        // 不在池 / 无池信息 → 不命中
        assert!(!should_override(&r, &req, Some(ip("198.51.100.7")), None, false, None));
        // bittorrent 例外（Go protocolString != "bittorrent" 门）
        let bt = make_sniff("bittorrent", "");
        assert!(!should_override(&bt, &req, Some(ip("198.51.100.7")), None, true, None));
    }

    /// bk8l（Go default.go:256-260 step3）：fakedns+others 结果按原始协议子集
    /// 命中 destOverride=["tls"]（SnifferIsProtoSubsetOf 落地）
    #[test]
    fn override_proto_subset_of_original_hits() {
        let wrapped = crate::fakednssniffer::DnsThenOthersSniffResult::new(
            "example.com",
            "tls",
        );
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["tls".to_string()],
            ..Default::default()
        };
        // protocol "fakedns+others" 与 "tls" 无前缀关系 → 靠子集判定命中
        assert!(should_override(&wrapped, &req, Some(ip("198.51.100.7")), None, true, Some("tls")));
    }
    // ---- DefaultDispatcher ----

    #[test]
    fn dispatcher_default_is_empty() {
        let d = DefaultDispatcher::default();
        assert!(d.ohm.is_none());
        assert!(d.router.is_none());
        assert!(d.stats.is_none());
        assert!(d.fdns.is_none());
    }

    #[test]
    fn dispatcher_start_close_are_noop() {
        let d = DefaultDispatcher::new();
        d.start().expect("start ok");
        d.close().expect("close ok");
    }

    // ---- CachedReader ----

    #[test]
    fn cached_reader_default_is_empty() {
        let r = CachedReader::default();
        assert!(r.inner.is_none());
        assert!(r.cache.is_none());
    }

    #[test]
    fn cached_reader_interrupt_clears_cache() {
        let mut r = CachedReader::new();
        r.cache = Some(MultiBuffer::default());
        r.interrupt();
        assert!(r.cache.is_none());
    }

    // ---- Route ----

    #[test]
    fn route_new_stores_tag() {
        let r = Route::new("proxy");
        assert_eq!(r.get_outbound_tag(), "proxy");
        assert_eq!(r.get_rule_tag(), "");
    }

    // ---- DefaultDispatcher::dispatch ----

    #[tokio::test]
    async fn dispatch_creates_pipe_pair_and_spawns_outbound_handler() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as StdArc;
        use std::time::Duration;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        // Mock DispatchHandler：递增 counter 证明 spawn 触发
        #[derive(Debug)]
        struct MockHandler {
            called: StdArc<AtomicU32>,
        }
        impl DispatchHandler for MockHandler {
            fn tag(&self) -> &str {
                "mock"
            }
            fn dispatch(&self, _dest: &xray_common::net::destination::Destination, _link: xray_transport::link::Link) -> PinFuture<()> {
                let c = self.called.clone();
                Box::pin(async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            }
        }
        // Mock OutboundHandlerManager 返回 MockHandler
        #[derive(Debug)]
        struct MockOhm {
            handler: StdArc<MockHandler>,
        }
        impl OutboundHandlerManager for MockOhm {
            fn get_handler(&self, _tag: &str) -> Option<Arc<dyn DispatchHandler>> {
                None
            }
            fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
                Some(self.handler.clone())
            }
        }

        let called = StdArc::new(AtomicU32::new(0));
        let handler = StdArc::new(MockHandler {
            called: called.clone(),
        });
        let ohm: Arc<dyn OutboundHandlerManager> = Arc::new(MockOhm { handler });
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(ohm);

        let dest = Destination::new(
            Address::new_domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let inbound = d
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        // inbound Link 字段非空（trait object 无法直接比较，仅验证存在）
        let _ = &inbound.reader;
        let _ = &inbound.writer;

        // 等 tokio::spawn 调度完成
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            called.load(Ordering::SeqCst),
            1,
            "dispatch_link should spawn handler.dispatch exactly once"
        );
    }

    #[tokio::test]
    async fn dispatch_errors_when_no_ohm() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        let d = DefaultDispatcher::new(); // 无 ohm
        let dest = Destination::new(
            Address::new_domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let r = d.dispatch(&dest, &SniffingRequest::default(), None, None);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn dispatch_errors_when_no_default_handler() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        #[derive(Debug)]
        struct EmptyOhm;
        impl OutboundHandlerManager for EmptyOhm {
            fn get_handler(&self, _tag: &str) -> Option<Arc<dyn DispatchHandler>> {
                None
            }
            fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
                None
            }
        }

        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(EmptyOhm));
        let dest = Destination::new(
            Address::new_domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let r = d.dispatch(&dest, &SniffingRequest::default(), None, None);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn dispatch_e2e_dial_bridge_to_echo_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use xray_transport::connection::TcpConnection;

        // 1. echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                }
            }
        });

        // 2. DialBridge with TCP connect
        let dial: DialFn = Arc::new(move |_dest: &Destination| {
            Box::pin(async move {
                let stream = TcpStream::connect(("127.0.0.1", echo_port))
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                Ok(Box::new(TcpConnection::new(stream)) as Box<dyn Connection>)
            })
        });

        // 3. dispatcher + SimpleOhm
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new("test-freedom", dial)));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));

        // 4. dispatch → inbound Link
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_port),
            Network::TCP,
        );
        let inbound = d
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        // 5. 写上行 → dispatcher spawn bridge → dial → echo → 读下行
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"e2e dispatch bridge");
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout waiting for echo response")
        .unwrap();

        assert_eq!(resp.to_vec(), b"e2e dispatch bridge");
        w.shutdown(); // 关闭触发 bridge 结束
    }

    use xray_features::stats::Manager as _;

    #[tokio::test]
    async fn pick_route_resolved_default_degenerates_to_sync() {
        #[derive(Debug)]
        struct SyncOnlyRouter;
        impl RoutingRouter for SyncOnlyRouter {
            fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<Route, DispatcherError> {
                Ok(Route::new(format!("sync-{}", ctx.get_target_domain())))
            }
            // 不覆盖 pick_route_resolved：验证 trait 默认实现退化为同步 pick_route
        }

        let ctx = DispatcherContext::new().with_target_domain("example.com");
        let route = SyncOnlyRouter.pick_route_resolved(&ctx).await.unwrap();
        assert_eq!(route.outbound_tag, "sync-example.com");
    }

    #[tokio::test]
    async fn dispatch_link_routes_resolved_and_counts_outbound_traffic() {
        use std::future::Future;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        /// 一次性 echo handler：记录 dispatch 到的 dest domain，读一段回写后关闭。
        #[derive(Debug)]
        struct EchoHandler {
            tag: &'static str,
            dest_domain: Arc<parking_lot::Mutex<Option<String>>>,
        }
        impl DispatchHandler for EchoHandler {
            fn tag(&self) -> &str {
                self.tag
            }
            fn dispatch(
                &self,
                dest: &Destination,
                link: xray_transport::link::Link,
            ) -> PinFuture<()> {
                let domain = dest.address().as_domain().map(str::to_string);
                let recorded = Arc::clone(&self.dest_domain);
                Box::pin(async move {
                    *recorded.lock() = domain;
                    let mut r = link.reader;
                    let mut w = link.writer;
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if !mb.is_empty() {
                            let _ = w.write_multi_buffer(mb).await;
                        }
                    }
                    w.shutdown();
                })
            }
        }

        /// resolved 版返回 tag-out；同步 pick_route 返回 should-not（若被调用即测试失败信号）。
        #[derive(Debug)]
        struct ResolvedRouter;
        impl RoutingRouter for ResolvedRouter {
            fn pick_route(&self, _ctx: &dyn RoutingContext) -> Result<Route, DispatcherError> {
                Ok(Route::new("should-not"))
            }
            fn pick_route_resolved<'a>(
                &'a self,
                _ctx: &'a dyn RoutingContext,
            ) -> Pin<Box<dyn Future<Output = Result<Route, DispatcherError>> + Send + 'a>> {
                Box::pin(async move { Ok(Route::new("tag-out")) })
            }
        }

        let ohm = SimpleOhm::new();
        let hit_out = Arc::new(parking_lot::Mutex::new(None));
        let hit_wrong = Arc::new(parking_lot::Mutex::new(None));
        ohm.add(
            "tag-out",
            Arc::new(EchoHandler { tag: "tag-out", dest_domain: Arc::clone(&hit_out) }),
        );
        ohm.add(
            "should-not",
            Arc::new(EchoHandler { tag: "should-not", dest_domain: Arc::clone(&hit_wrong) }),
        );

        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.router = Some(Arc::new(ResolvedRouter));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);
        // sm80①：outbound tag counter 受 ForSystem 门控——开启后本测试的
        // 懒注册断言才成立。
        d.set_policy_manager(Arc::new(SystemStatsAllOnPolicyManager));

        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));

        let dest = Destination::new(
            Address::new_domain("routed.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        d.dispatch_link(&dest, outbound, &SniffingRequest::default(), None, None)
            .expect("dispatch_link should spawn");

        // 写上行
        let mut w: Box<dyn xray_buf::io::Writer> = Box::new(up_w);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"hello routed");
        w.write_multi_buffer(mb).await.unwrap();

        // 读下行（echo 回来）
        let mut r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .unwrap();
        assert_eq!(resp.to_vec(), b"hello routed");

        // resolved 路径选中 tag-out；同步版标签未被使用
        assert_eq!(hit_out.lock().as_deref(), Some("routed.example.com"));
        assert!(hit_wrong.lock().is_none());

        // outbound counter 按命中 tag 懒注册并计数
        let up_ctr = stats
            .get_counter("outbound>>>tag-out>>>traffic>>>uplink")
            .expect("uplink counter should be lazily registered");
        let dn_ctr = stats
            .get_counter("outbound>>>tag-out>>>traffic>>>downlink")
            .expect("downlink counter should be lazily registered");
        assert!(up_ctr.value() > 0, "uplink counted {} bytes", up_ctr.value());
        assert!(dn_ctr.value() > 0, "downlink counted {} bytes", dn_ctr.value());
        w.shutdown();
    }

    // ---- per-user stats（cbnj，Go getLink default.go:161-185 + trackOnlineIP:224-229）----

    #[tokio::test]
    async fn dispatch_link_counts_per_user_traffic_and_online_ip() {
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        /// 一次性 echo handler：读一段回写后关闭。
        #[derive(Debug)]
        struct EchoOnce;
        impl DispatchHandler for EchoOnce {
            fn tag(&self) -> &str {
                "echo"
            }
            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> PinFuture<()> {
                Box::pin(async move {
                    let mut r = link.reader;
                    let mut w = link.writer;
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if !mb.is_empty() {
                            let _ = w.write_multi_buffer(mb).await;
                        }
                    }
                    w.shutdown();
                })
            }
        }

        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(EchoOnce));

        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);
        // Go policy level stats：user{Uplink,Downlink,Online} 三开关全开
        d.default_policy.stats.user_uplink = true;
        d.default_policy.stats.user_downlink = true;
        d.default_policy.stats.user_online = true;

        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));

        let dest = Destination::new(
            Address::new_domain("user.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let access = AccessContext {
            from: "203.0.113.7:4444".into(),
            email: "alice@x.com".into(),
            inbound_tag: "vless-in".into(),
            level: 0,
        };
        d.dispatch_link(&dest, outbound, &SniffingRequest::default(), Some(access), None)
            .expect("dispatch_link ok");

        // 在线 IP：连接建立后 map 出现且 count=1（host 提取剥端口）
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let om = stats
            .get_online_map("user>>>alice@x.com>>>online")
            .expect("online map should be lazily registered");
        assert_eq!(om.count(), 1, "source host 203.0.113.7 should be online");
        let mut seen_ip = String::new();
        om.for_each(&mut |ip, _| {
            seen_ip = ip.to_string();
            true
        });
        assert_eq!(seen_ip, "203.0.113.7", "port must be stripped from access.from");

        // 流量：写上行 → echo 回读 → per-user counter 增长
        let mut w: Box<dyn xray_buf::io::Writer> = Box::new(up_w);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"user traffic probe");
        w.write_multi_buffer(mb).await.unwrap();
        let mut r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .unwrap();
        assert_eq!(resp.to_vec(), b"user traffic probe");

        let up_ctr = stats
            .get_counter("user>>>alice@x.com>>>traffic>>>uplink")
            .expect("user uplink counter should be lazily registered");
        let dn_ctr = stats
            .get_counter("user>>>alice@x.com>>>traffic>>>downlink")
            .expect("user downlink counter should be lazily registered");
        assert!(up_ctr.value() > 0, "user uplink counted {} bytes", up_ctr.value());
        assert!(dn_ctr.value() > 0, "user downlink counted {} bytes", dn_ctr.value());

        // 连接结束 → guard remove_ip → 在线计数归零
        w.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(om.count(), 0, "online ip must be removed after connection ends");
    }

    #[tokio::test]
    async fn dispatch_link_skips_per_user_stats_when_policy_off() {
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        #[derive(Debug)]
        struct EchoOnce;
        impl DispatchHandler for EchoOnce {
            fn tag(&self) -> &str {
                "echo"
            }
            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> PinFuture<()> {
                Box::pin(async move {
                    let mut r = link.reader;
                    let mut w = link.writer;
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if !mb.is_empty() {
                            let _ = w.write_multi_buffer(mb).await;
                        }
                    }
                    w.shutdown();
                })
            }
        }

        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(EchoOnce));
        let stats = Arc::new(xray_app_stats::Manager::new_running());
        // 默认 policy stats 全 false：email 非空也不挂 per-user counter/online map
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);

        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));

        let dest = Destination::new(
            Address::new_domain("user.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let access = AccessContext {
            from: "198.51.100.9:5555".into(),
            email: "bob@x.com".into(),
            ..Default::default()
        };
        d.dispatch_link(&dest, outbound, &SniffingRequest::default(), Some(access), None)
            .expect("dispatch_link ok");

        let mut w: Box<dyn xray_buf::io::Writer> = Box::new(up_w);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"gated probe");
        w.write_multi_buffer(mb).await.unwrap();
        let mut r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .unwrap();
        assert_eq!(resp.to_vec(), b"gated probe");

        assert!(
            stats.get_counter("user>>>bob@x.com>>>traffic>>>uplink").is_none(),
            "policy off: user uplink counter must not be registered"
        );
        assert!(
            stats.get_online_map("user>>>bob@x.com>>>online").is_none(),
            "policy off: online map must not be registered"
        );
        w.shutdown();
    }

    /// sm80①：outbound tag counter 受 ForSystem().Stats 门控——
    /// 默认（无 policy manager，SystemStats 全 false）流量走完也不注册计数器；
    /// mock 开启 outbound 两门后按方向计数。
    #[tokio::test]
    async fn dispatch_link_tag_counters_default_off_until_for_system_enabled() {
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        #[derive(Debug)]
        struct EchoOnce;
        impl DispatchHandler for EchoOnce {
            fn tag(&self) -> &str {
                "echo"
            }
            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> PinFuture<()> {
                Box::pin(async move {
                    let mut r = link.reader;
                    let mut w = link.writer;
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if !mb.is_empty() {
                            let _ = w.write_multi_buffer(mb).await;
                        }
                    }
                    w.shutdown();
                })
            }
        }

        async fn run_echo_traffic(d: &DefaultDispatcher) {
            let (up_r, up_w) =
                xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
            let (dn_r, dn_w) =
                xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
            let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));
            let dest = Destination::new(
                Address::new_domain("gated.example.com".to_string()),
                Port::new(443),
                Network::TCP,
            );
            d.dispatch_link(&dest, outbound, &SniffingRequest::default(), None, None)
                .expect("dispatch_link ok");
            let mut w: Box<dyn xray_buf::io::Writer> = Box::new(up_w);
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(b"tag counter probe");
            w.write_multi_buffer(mb).await.unwrap();
            let mut r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
            let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
                .await
                .expect("timeout waiting echo")
                .unwrap();
            assert_eq!(resp.to_vec(), b"tag counter probe");
        }

        // 场景 A：默认（无 pm）不计数。
        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(EchoOnce));
        d.ohm = Some(Arc::new(ohm));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);
        run_echo_traffic(&d).await;
        assert!(
            stats.get_counter("outbound>>>echo>>>traffic>>>uplink").is_none(),
            "ForSystem default false: tag counter must NOT be registered"
        );
        assert!(
            stats.get_counter("outbound>>>echo>>>traffic>>>downlink").is_none(),
            "ForSystem default false: tag counter must NOT be registered"
        );

        // 场景 B：OutboundOnly mock 开启 outbound 两门 → 按方向计数。
        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(EchoOnce));
        d.ohm = Some(Arc::new(ohm));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);
        d.set_policy_manager(Arc::new(OutboundOnlyPolicyManager));
        run_echo_traffic(&d).await;
        let up = stats
            .get_counter("outbound>>>echo>>>traffic>>>uplink")
            .expect("outbound_uplink enabled: counter must be registered");
        let dn = stats
            .get_counter("outbound>>>echo>>>traffic>>>downlink")
            .expect("outbound_downlink enabled: counter must be registered");
        assert!(up.value() > 0, "uplink counted {} bytes", up.value());
        assert!(dn.value() > 0, "downlink counted {} bytes", dn.value());
    }

    // ---- DialTaggedOutbound（bd kz1，Go tagged/taggedimpl）----

    /// 定向命中：dispatch_tagged("beta") 恰好派发到 beta，alpha 不被触碰；
    /// 数据面经 pipe 回显证明 Link 双向接通（Go impl.go:25-35 Dispatch+NewConnection 等价）。
    #[tokio::test]
    async fn dispatch_tagged_routes_to_tag_handler_with_echo() {
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        let alpha_called = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ohm = SimpleOhm::new();
        ohm.add(
            "alpha",
            Arc::new(TaggedEchoHandler::new("alpha", alpha_called.clone())),
        );
        ohm.add(
            "beta",
            Arc::new(TaggedEchoHandler::new("beta", std::sync::Arc::new(
                std::sync::atomic::AtomicU32::new(0),
            ))),
        );
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::new_domain("geodata.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let link = d
            .dispatch_tagged(&dest, "beta")
            .expect("dispatch_tagged should route to beta");

        let mut w = link.writer;
        let mut r = link.reader;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"ping tagged");
        w.write_multi_buffer(mb).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .unwrap();
        assert_eq!(resp.to_vec(), b"ping tagged");
        w.shutdown();

        assert_eq!(
            alpha_called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "forced tag must not touch other handlers"
        );
    }

    /// 未命中：tag 不存在时同步 Err，绝不回退默认出站
    /// （Go default.go:449-454 + DO NOT CHANGE 注释语义）。
    #[tokio::test]
    async fn dispatch_tagged_missing_tag_errors_without_fallback() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;

        let default_called = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(TaggedEchoHandler::new(
            "default-out",
            default_called.clone(),
        )));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::new_domain("geodata.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let res = d.dispatch_tagged(&dest, "ghost");
        assert!(res.is_err(), "missing tag must be a sync error");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            default_called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "missing tag must NOT fall back to default handler"
        );
    }

    /// 集成：真实 DialBridge 数据面 + 定向 tag 命中（Go observatory/burst 经
    /// tagged.Dialer 拨指定出站的场景）：real 拨向 echo server，decoy 在册不被触碰。
    #[tokio::test]
    async fn dispatch_tagged_e2e_dial_bridge_to_echo_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use xray_buf::io::Writer;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use xray_transport::connection::TcpConnection;

        // 1. echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                }
            }
        });

        // 2. real：DialBridge → echo；decoy：计数 handler（在册，命中即计数）
        let dial: DialFn = Arc::new(move |_dest: &Destination| {
            Box::pin(async move {
                let stream = TcpStream::connect(("127.0.0.1", echo_port))
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                Ok(Box::new(TcpConnection::new(stream)) as Box<dyn Connection>)
            })
        });
        let decoy_called = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ohm = SimpleOhm::new();
        ohm.add("real-out", Arc::new(DialBridge::new("real-out", dial)));
        ohm.add(
            "decoy-out",
            Arc::new(TaggedEchoHandler::new("decoy-out", decoy_called.clone())),
        );
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));

        // 3. 定向拨号 real-out → 回显
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_port),
            Network::TCP,
        );
        let link = d
            .dispatch_tagged(&dest, "real-out")
            .expect("dispatch_tagged to real-out");
        let mut w = link.writer;
        let mut r = link.reader;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"hello tagged outbound");
        w.write_multi_buffer(mb).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .unwrap();
        assert_eq!(resp.to_vec(), b"hello tagged outbound");
        w.shutdown();

        assert_eq!(
            decoy_called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "decoy outbound must stay untouched"
        );
    }

    /// 可参数化 tag 的计数+回显 handler（kz1 定向拨号测试）。
    #[derive(Debug)]
    struct TaggedEchoHandler {
        tag: &'static str,
        called: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }
    impl TaggedEchoHandler {
        fn new(tag: &'static str, called: std::sync::Arc<std::sync::atomic::AtomicU32>) -> Self {
            Self { tag, called }
        }
    }
    impl DispatchHandler for TaggedEchoHandler {
        fn tag(&self) -> &str {
            self.tag
        }
        fn dispatch(
            &self,
            _dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            let called = std::sync::Arc::clone(&self.called);
            Box::pin(async move {
                called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut r = link.reader;
                let mut w = link.writer;
                if let Ok(mb) = r.read_multi_buffer().await {
                    if !mb.is_empty() {
                        let _ = w.write_multi_buffer(mb).await;
                    }
                }
                w.shutdown();
            })
        }
    }

    // ---- UDP443 策略（bd g35，Go handler.go:220-228） ----

    #[test]
    fn udp443_policy_from_mux_variants() {
        // mux 未启用：无策略（Go NewHandler 的 enabled 门控）
        assert_eq!(Udp443Policy::from_mux(false, "reject"), None);
        // 空串规范化为 reject（Go MuxConfig.Build）
        assert_eq!(Udp443Policy::from_mux(true, ""), Some(Udp443Policy::Reject));
        assert_eq!(Udp443Policy::from_mux(true, "reject"), Some(Udp443Policy::Reject));
        assert_eq!(Udp443Policy::from_mux(true, "skip"), Some(Udp443Policy::Skip));
        assert_eq!(Udp443Policy::from_mux(true, "allow"), Some(Udp443Policy::Allow));
        // 非法值：None（Go 为启动错误，此处降级告警跳过）
        assert_eq!(Udp443Policy::from_mux(true, "bogus"), None);
    }

    /// 计数 + 回显 handler：dispatch 计数，读一段回写后关闭。
    #[derive(Debug)]
    struct CountingEchoHandler {
        called: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }
    impl DispatchHandler for CountingEchoHandler {
        fn tag(&self) -> &str {
            "udp-out"
        }
        fn dispatch(
            &self,
            _dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            let called = std::sync::Arc::clone(&self.called);
            Box::pin(async move {
                called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut r = link.reader;
                let mut w = link.writer;
                if let Ok(mb) = r.read_multi_buffer().await {
                    if !mb.is_empty() {
                        let _ = w.write_multi_buffer(mb).await;
                    }
                }
                w.shutdown();
            })
        }
    }

    fn udp443_dispatcher(
        policy: Option<Udp443Policy>,
    ) -> (
        DefaultDispatcher,
        std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ohm = SimpleOhm::new();
        ohm.set_default(std::sync::Arc::new(CountingEchoHandler {
            called: std::sync::Arc::clone(&called),
        }));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(std::sync::Arc::new(ohm));
        if let Some(p) = policy {
            d.udp443_policies.insert("udp-out".to_string(), p);
        }
        (d, called)
    }

    fn udp_dest_port_443() -> xray_common::net::destination::Destination {
        use xray_common::net::address::Address;
        Destination::new(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(443), Network::UDP)
    }

    #[tokio::test]
    async fn udp443_reject_interrupts_udp_443_dispatch() {
        use xray_buf::io::Reader;
        let (d, called) = udp443_dispatcher(Some(Udp443Policy::Reject));

        let inbound = d
            .dispatch(&udp_dest_port_443(), &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        // 下行被关闭：inbound reader 收到 EOF（pipe 约定 Err(Eof)）
        let mut r = inbound.reader;
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout waiting EOF");
        assert!(
            matches!(res, Err(xray_buf::io::Error::Eof)),
            "reject should close downlink, got: {res:?}"
        );
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "reject must not reach handler"
        );
    }

    #[tokio::test]
    async fn udp443_skip_dispatches_udp_443_direct() {
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;
        let (d, called) = udp443_dispatcher(Some(Udp443Policy::Skip));

        let inbound = d
            .dispatch(&udp_dest_port_443(), &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"quic-ish");
        w.write_multi_buffer(mb).await.expect("write uplink");

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout waiting echo")
        .expect("read ok");
        assert_eq!(resp.to_vec(), b"quic-ish");
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "skip = goto out: traffic dispatched direct"
        );
    }

    // ---- EndpointOverride e2e（bd g35，Go handler.go:206-209） ----

    /// fakedns 引擎：198.51.100.7 → sniffed.example.com。
    #[derive(Debug)]
    struct FixedFakeDns;
    impl crate::fakednssniffer::FakeDnsEngine for FixedFakeDns {
        fn get_domain_from_fake_dns(&self, addr: &IpAddr) -> String {
            if *addr == IpAddr::from([198, 51, 100, 7]) {
                String::from("sniffed.example.com")
            } else {
                String::new()
            }
        }
    }

    /// bk8l 测试引擎：203.0.113.9 在 fake 池区间但映射丢失（fakedns 重启语义）。
    #[derive(Debug)]
    struct PoolOnlyFakeDns;
    impl crate::fakednssniffer::FakeDnsEngine for PoolOnlyFakeDns {
        fn get_domain_from_fake_dns(&self, _addr: &IpAddr) -> String {
            String::new()
        }

        fn is_ip_in_ip_pool(&self, addr: &IpAddr) -> bool {
            *addr == IpAddr::from([203, 0, 113, 9])
        }
    }

    /// 记录首帧目标并回写（target = 改写后 dest）的 handler。
    #[derive(Debug)]
    struct FrameEchoHandler {
        seen_target: Arc<parking_lot::Mutex<Option<xray_common::net::address::Address>>>,
    }
    impl DispatchHandler for FrameEchoHandler {
        fn tag(&self) -> &str {
            "frame-out"
        }
        fn dispatch(
            &self,
            dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            let seen = Arc::clone(&self.seen_target);
            let dest = dest.clone();
            Box::pin(async move {
                use xray_buf::io::Reader as _;
                let mut r = link.reader;
                let mut w = link.writer;
                // 累积读直到能解出一个 XUDP 帧
                let mut acc = Vec::new();
                let pkt = loop {
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if mb.is_empty() {
                            return;
                        }
                        acc.extend_from_slice(&mb.to_vec());
                    }
                    let mut pr = xray_xudp::packet::PacketReader::new(std::io::Cursor::new(&acc[..]));
                    if let Ok(Some(pkt)) = pr.read_packet() {
                        break pkt;
                    }
                };
                let (data, target) = pkt.into_parts();
                *seen.lock() = target.map(|t| t.address().clone());
                // 回写帧：target = 改写后 dest（模拟 outbound 从改写目标收包）
                let mut frame = Vec::new();
                let mut pw = xray_xudp::packet::PacketWriter::new(
                    &mut frame,
                    dest.clone(),
                    [0xAA; 8],
                );
                let _ = pw.write_packet(&data);
                drop(pw);
                let mut mb = xray_buf::multi::MultiBuffer::new();
                mb.merge_bytes(&frame);
                let _ = w.write_multi_buffer(mb).await;
                w.shutdown();
            })
        }
    }

    #[tokio::test]
    async fn dispatch_link_udp_endpoint_override_rewrites_xudp_frames() {
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let ohm = SimpleOhm::new();
        let seen_target = Arc::new(parking_lot::Mutex::new(None));
        ohm.set_default(Arc::new(FrameEchoHandler {
            seen_target: Arc::clone(&seen_target),
        }));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.fdns = Some(Arc::new(FixedFakeDns));

        let sniff = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["fakedns".to_string()],
            ..Default::default()
        };

        // 原始目标 fake IP 198.51.100.7:53 UDP；fakedns sniff 后改写为 domain
        let dest = Destination::new(
            Address::from_ipv4_bytes([198, 51, 100, 7]),
            Port::new(53),
            Network::UDP,
        );
        let inbound = d
            .dispatch(&dest, &sniff, None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        // 客户端写 XUDP New 帧（target = 198.51.100.7:53）
        let mut frame = Vec::new();
        {
            let mut pw = xray_xudp::packet::PacketWriter::new(
                &mut frame,
                Destination::udp(Address::from_ipv4_bytes([198, 51, 100, 7]), Port::new(53)),
                [0x11; 8],
            );
            pw.write_packet(b"udp-payload").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        w.write_multi_buffer(mb).await.expect("write uplink frame");

        // 读回包（下行帧来源应被改回原始 IP）
        let mut acc = Vec::new();
        let pkt = loop {
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                r.read_multi_buffer(),
            )
            .await
            .expect("timeout reading downlink");
            match resp {
                Ok(mb) if !mb.is_empty() => acc.extend_from_slice(&mb.to_vec()),
                _ => panic!("downlink closed before frame"),
            }
            let mut pr = xray_xudp::packet::PacketReader::new(std::io::Cursor::new(&acc[..]));
            if let Ok(Some(pkt)) = pr.read_packet() {
                break pkt;
            }
        };
        let (data, target) = pkt.into_parts();
        assert_eq!(data, b"udp-payload");
        assert_eq!(
            target.expect("downlink frame has source").address(),
            &Address::from_ipv4_bytes([198, 51, 100, 7]),
            "downlink frame source rewritten back to original"
        );

        // handler 侧：上行帧目标应已被改写为 sniffed domain
        let seen = seen_target.lock().clone();
        assert_eq!(
            seen,
            Some(Address::new_domain(String::from("sniffed.example.com"))),
            "uplink frame target rewritten to override dest"
        );
    }

    #[tokio::test]
    async fn udp443_no_policy_flows_untouched() {
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;
        let (d, called) = udp443_dispatcher(None);

        let inbound = d
            .dispatch(&udp_dest_port_443(), &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"quic");
        w.write_multi_buffer(mb).await.expect("write uplink");

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout waiting echo")
        .expect("read ok");
        assert_eq!(resp.to_vec(), b"quic");
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // ========== access log（bd 4uu，对应 Go default.go:488-502） ==========

    /// 捕获 AccessLogEntry 的 sink。
    #[derive(Debug, Clone)]
    struct CapturingSink(std::sync::Arc<parking_lot::Mutex<Vec<AccessLogEntry>>>);

    impl AccessLogSink for CapturingSink {
        fn record_access(&self, entry: &AccessLogEntry) {
            self.0.lock().push(entry.clone());
        }
    }

    /// dispatch 完成即发信号的 handler（让记录断言确定性）。
    #[derive(Debug)]
    struct SignalingHandler {
        tag: String,
        signal: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DispatchHandler for SignalingHandler {
        fn tag(&self) -> &str {
            &self.tag
        }
        fn dispatch(
            &self,
            _dest: &Destination,
            _link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            self.signal
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    fn access_dest() -> Destination {
        Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(8080),
            Network::TCP,
        )
    }

    #[tokio::test]
    async fn dispatch_link_records_accepted_access_with_detour() {
        use xray_buf::pipe;

        let sink = CapturingSink(Default::default());
        let called = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let ohm = SimpleOhm::new();
        ohm.set_default(std::sync::Arc::new(SignalingHandler {
            tag: "direct".into(),
            signal: called.clone(),
        }));

        let mut d = DefaultDispatcher::new();
        d.init(
            &crate::Config::default(),
            std::sync::Arc::new(ohm),
            None,
            xray_features::policy::Policy::default(),
            None,
        );
        d.access_sink = Some(std::sync::Arc::new(sink.clone()));

        let (_r, _w) = pipe::new();
        let link = xray_transport::link::Link::new(
            Box::new(_r) as Box<dyn xray_buf::io::Reader>,
            Box::new(_w) as Box<dyn xray_buf::io::Writer>,
        );
        let access = AccessContext {
            from: "1.2.3.4:1080".into(),
            email: "u@x.com".into(),
            inbound_tag: "socks-in".into(),
            level: 0,
        };
        d.dispatch_link(&access_dest(), link, &SniffingRequest::default(), Some(access), None)
            .expect("dispatch_link ok");

        // 等 handler 被调（record 严格发生在 handler.dispatch 之前）
        for _ in 0..100 {
            if called.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), 1);

        let entries = sink.0.lock().clone();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.status, "accepted");
        assert_eq!(e.from, "1.2.3.4:1080");
        assert_eq!(e.to, "tcp:127.0.0.1:8080");
        assert_eq!(e.email, "u@x.com");
        // 无 router → 默认出站组合 "in >> tag"（Go default.go:498）
        assert_eq!(e.detour, "socks-in >> direct");
    }

    #[tokio::test]
    async fn dispatch_link_without_access_ctx_records_nothing() {
        use xray_buf::pipe;

        let sink = CapturingSink(Default::default());
        let called = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let ohm = SimpleOhm::new();
        ohm.set_default(std::sync::Arc::new(SignalingHandler {
            tag: "direct".into(),
            signal: called.clone(),
        }));

        let mut d = DefaultDispatcher::new();
        d.init(
            &crate::Config::default(),
            std::sync::Arc::new(ohm),
            None,
            xray_features::policy::Policy::default(),
            None,
        );
        d.access_sink = Some(std::sync::Arc::new(sink.clone()));

        let (_r, _w) = pipe::new();
        let link = xray_transport::link::Link::new(
            Box::new(_r) as Box<dyn xray_buf::io::Reader>,
            Box::new(_w) as Box<dyn xray_buf::io::Writer>,
        );
        d.dispatch_link(&access_dest(), link, &SniffingRequest::default(), None, None)
            .expect("dispatch_link ok");

        for _ in 0..100 {
            if called.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Go 语义：ctx 无 AccessMessage → 不 Record
        assert!(sink.0.lock().is_empty());
    }

    #[tokio::test]
    async fn dispatch_link_records_rejected_when_no_handler() {
        let sink = CapturingSink(Default::default());
        let mut d = DefaultDispatcher::new();
        // 空 ohm：无 router 无 default → 同步 Err + Rejected 记录
        d.init(
            &crate::Config::default(),
            std::sync::Arc::new(SimpleOhm::new()),
            None,
            xray_features::policy::Policy::default(),
            None,
        );
        d.access_sink = Some(std::sync::Arc::new(sink.clone()));

        let link = xray_transport::link::Link::new(
            Box::new(xray_buf::pipe::new().0) as Box<dyn xray_buf::io::Reader>,
            Box::new(xray_buf::pipe::new().1) as Box<dyn xray_buf::io::Writer>,
        );
        let access = AccessContext {
            from: "1.2.3.4:1080".into(),
            email: String::new(),
            inbound_tag: "socks-in".into(),
            level: 0,
        };
        let res = d.dispatch_link(&access_dest(), link, &SniffingRequest::default(), Some(access), None);
        assert!(res.is_err(), "no handler should be a sync error");

        let entries = sink.0.lock().clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, "rejected");
        assert_eq!(entries[0].reason, "no outbound handler available");
        assert_eq!(entries[0].to, "tcp:127.0.0.1:8080");
    }

    // ---- routeOnly / tag 断链（批 3，Go default.go:311-315/469-470）----

    /// 构造最小 TLS ClientHello（含 SNI；sniffer.rs 测试同款构造）。
    fn build_minimal_client_hello(domain: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.push(0x01); // ClientHello

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.push(0x01); // compression_methods_len = 1
        body.push(0x00); // null compression

        let mut extensions = Vec::new();
        let mut sni_data = Vec::new();
        let sni_entry_len = 1 + 2 + domain.len();
        sni_data.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        sni_data.push(0x00); // host_name type
        sni_data.extend_from_slice(&(domain.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(domain);

        extensions.extend_from_slice(&[0x00, 0x00]); // extension type SNI
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len() as u32;
        hello.extend_from_slice(&body_len.to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    /// 记录 dispatch 收到的完整 dest 后关闭下行。
    #[derive(Debug)]
    struct RecordingHandler {
        tag: &'static str,
        seen_dest: Arc<parking_lot::Mutex<Option<xray_common::net::destination::Destination>>>,
    }
    impl DispatchHandler for RecordingHandler {
        fn tag(&self) -> &str {
            self.tag
        }
        fn dispatch(
            &self,
            dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            let seen = Arc::clone(&self.seen_dest);
            let dest = dest.clone();
            Box::pin(async move {
                *seen.lock() = Some(dest);
                link.writer.shutdown();
            })
        }
    }

    /// 记录路由上下文目标域名；域名命中 routed-tag，否则 ip-tag。
    #[derive(Debug)]
    struct DomainRouter {
        seen_domain: Arc<parking_lot::Mutex<Option<String>>>,
    }
    impl RoutingRouter for DomainRouter {
        fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<Route, DispatcherError> {
            // 模拟 RouterAdapter::bridge_context（Go GetTarget）：RouteTarget 有效时优先。
            let domain = ctx
                .get_route_target()
                .and_then(|rt| rt.address().as_domain().map(str::to_string))
                .unwrap_or_else(|| ctx.get_target_domain().to_string());
            *self.seen_domain.lock() = Some(domain.clone());
            if domain == "sniffed.example.com" {
                Ok(Route::new("routed-tag"))
            } else {
                Ok(Route::new("ip-tag"))
            }
        }
        fn pick_route_resolved<'a>(
            &'a self,
            ctx: &'a dyn RoutingContext,
        ) -> Pin<Box<dyn Future<Output = Result<Route, DispatcherError>> + Send + 'a>> {
            Box::pin(async move { self.pick_route(ctx) })
        }
    }

    /// routeOnly：路由用嗅探域名（命中域名规则），拨号保持原 dest（IP 不改写）。
    /// 对应 Go default.go:311-315。
    #[tokio::test]
    async fn dispatch_link_route_only_routes_by_sniffed_domain_dials_original_dest() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let ohm = SimpleOhm::new();
        let routed_dest = Arc::new(parking_lot::Mutex::new(None));
        let ip_dest = Arc::new(parking_lot::Mutex::new(None));
        ohm.add(
            "routed-tag",
            Arc::new(RecordingHandler { tag: "routed-tag", seen_dest: Arc::clone(&routed_dest) }),
        );
        ohm.add(
            "ip-tag",
            Arc::new(RecordingHandler { tag: "ip-tag", seen_dest: Arc::clone(&ip_dest) }),
        );
        let seen_domain = Arc::new(parking_lot::Mutex::new(None));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.router = Some(Arc::new(DomainRouter { seen_domain: Arc::clone(&seen_domain) }));

        let sniff = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["tls".to_string()],
            route_only: true,
            ..Default::default()
        };

        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([1, 2, 3, 4]),
            Port::new(443),
            Network::TCP,
        );
        let mut payload = vec![0x16, 0x03, 0x01];
        let hello = build_minimal_client_hello(b"sniffed.example.com");
        payload.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hello);

        let (up_r, mut up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));

        d.dispatch_link(&dest, outbound, &sniff, None, None)
            .expect("dispatch_link ok");

        // 发 ClientHello（嗅探读首包）
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&payload);
        up_w.write_multi_buffer(mb).await.unwrap();

        for _ in 0..200 {
            if routed_dest.lock().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(
            seen_domain.lock().as_deref(),
            Some("sniffed.example.com"),
            "routing must use sniffed domain under route_only"
        );
        let seen = routed_dest.lock().clone().expect("routed handler dispatched");
        assert_eq!(
            seen.address().ip(),
            Some(std::net::IpAddr::from([1, 2, 3, 4])),
            "dial dest must stay original under route_only"
        );
        assert!(ip_dest.lock().is_none(), "ip-tag must not be picked");
        let _ = dn_r;
        up_w.shutdown();
    }

    /// m9si（Go default.go:384-388）：metadataOnly=true 仅元数据嗅探——不读 payload，
    /// TLS ClientHello 不触发改写，target 保持原 IP 且 metadata 通道为空。
    #[tokio::test]
    async fn sniff_metadata_only_true_skips_payload_and_keeps_target() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let mut payload = vec![0x16, 0x03, 0x01];
        let hello = build_minimal_client_hello(b"sniffed.example.com");
        payload.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hello);

        let (r, mut w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&payload);
        w.write_multi_buffer(mb).await.unwrap();
        w.shutdown();

        let mut cr = CachedReader::with_inner(Box::new(r));
        let req = SniffingRequest {
            enabled: true,
            metadata_only: true,
            override_destination_for_protocol: vec!["tls".to_string()],
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([1, 2, 3, 4]),
            Port::new(443),
            Network::TCP,
        );

        let (final_dest, proto, route_target) =
            sniff_connection(&mut cr, &dest, &req, None)
                .await
                .expect("sniff ok");

        assert_eq!(
            final_dest.address().ip(),
            Some(std::net::IpAddr::from([1, 2, 3, 4])),
            "metadataOnly must not rewrite target from TLS payload"
        );
        assert!(proto.is_none(), "no metadata domain without fakedns");
        assert!(route_target.is_none());
        assert!(
            cr.cached_bytes().is_empty(),
            "payload must not be read under metadataOnly"
        );
    }

    /// 对照（Go default.go:390-424）：metadataOnly=false 行为不变——TLS payload
    /// 嗅探命中 SNI 并按 destOverride 改写 target。
    #[tokio::test]
    async fn sniff_metadata_only_false_still_rewrites_target() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let mut payload = vec![0x16, 0x03, 0x01];
        let hello = build_minimal_client_hello(b"sniffed.example.com");
        payload.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hello);

        let (r, mut w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&payload);
        w.write_multi_buffer(mb).await.unwrap();
        w.shutdown();

        let mut cr = CachedReader::with_inner(Box::new(r));
        let req = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["tls".to_string()],
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([1, 2, 3, 4]),
            Port::new(443),
            Network::TCP,
        );

        let (final_dest, proto, route_target) =
            sniff_connection(&mut cr, &dest, &req, None)
                .await
                .expect("sniff ok");

        assert_eq!(
            final_dest.address().as_domain(),
            Some("sniffed.example.com"),
            "content sniff must still rewrite target when metadataOnly=false"
        );
        assert_eq!(proto.as_deref(), Some("tls"));
        assert!(route_target.is_none());
    }

    /// m9si（Go default.go:384-388 + DispatchLink shouldOverride）：metadataOnly=true
    /// 时 fakedns 反查命中（元数据）仍参与改写——元数据可用，内容嗅探跳过。
    #[tokio::test]
    async fn sniff_metadata_only_true_fakedns_hit_applies_metadata() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let mut payload = vec![0x16, 0x03, 0x01];
        let hello = build_minimal_client_hello(b"other.example.com");
        payload.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hello);

        let (r, mut w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&payload);
        w.write_multi_buffer(mb).await.unwrap();
        w.shutdown();

        let mut cr = CachedReader::with_inner(Box::new(r));
        let req = SniffingRequest {
            enabled: true,
            metadata_only: true,
            override_destination_for_protocol: vec!["fakedns".to_string()],
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([198, 51, 100, 7]),
            Port::new(443),
            Network::TCP,
        );

        let (final_dest, proto, route_target) =
            sniff_connection(&mut cr, &dest, &req, Some(&FixedFakeDns))
                .await
                .expect("sniff ok");

        assert_eq!(
            final_dest.address().as_domain(),
            Some("sniffed.example.com"),
            "fakedns metadata hit must still rewrite under metadataOnly"
        );
        assert_eq!(proto.as_deref(), Some("fakedns"));
        assert!(route_target.is_none());
        assert!(
            cr.cached_bytes().is_empty(),
            "payload must not be read under metadataOnly even with fakedns hit"
        );
    }

    /// ny1g（Go default.go:390-424）：HTTP 请求行与 Host 分属两个 TCP 段 →
    /// 首轮 ErrNoClue 计入 totalAttempt 并重读，第二轮完成嗅探改写
    /// （旧实现首轮即放弃按原 IP 路由）。
    #[tokio::test]
    async fn sniff_http_host_in_second_segment_retries() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let (r, mut w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut first = MultiBuffer::new();
        first.merge_bytes(b"GET /path HTTP/1.1\r\n");
        w.write_multi_buffer(first).await.unwrap();
        let mut second = MultiBuffer::new();
        second.merge_bytes(b"Host: late.example.com\r\n\r\n");
        w.write_multi_buffer(second).await.unwrap();
        w.shutdown();

        let mut cr = CachedReader::with_inner(Box::new(r));
        let req = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([1, 2, 3, 4]),
            Port::new(80),
            Network::TCP,
        );

        let (final_dest, proto, route_target) =
            sniff_connection(&mut cr, &dest, &req, None).await.expect("sniff ok");

        assert_eq!(
            final_dest.address().as_domain(),
            Some("late.example.com"),
            "second-segment Host must be picked up after ErrNoClue retry",
        );
        assert_eq!(proto.as_deref(), Some("http1"));
        assert!(route_target.is_none());
    }

    /// va51④（Go default.go:391）：嗅探预算 200ms 固定——慢首字节在预算耗尽后
    /// 放弃（SniffingTimeout），不再借用用户级 60s 握手超时占住分发协程。
    #[tokio::test]
    async fn sniff_budget_is_fixed_200ms_not_handshake_timeout() {
        use xray_common::net::address::Address;

        // 永不出数据的 reader：read_first 挂到超时
        struct SilentReader;
        impl xray_buf::io::Reader for SilentReader {
            fn read_multi_buffer(
                &mut self,
            ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer, xray_buf::io::Error>> + Send + '_>>
            {
                Box::pin(async { loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; } })
            }
        }

        let mut cr = CachedReader::with_inner(Box::new(SilentReader));
        let req = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["tls".to_string()],
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([1, 2, 3, 4]),
            Port::new(443),
            Network::TCP,
        );

        let started = std::time::Instant::now();
        let result = sniff_connection(&mut cr, &dest, &req, None).await;
        let elapsed = started.elapsed();

        // 预算耗尽 → 放弃嗅探（既有契约：content 失败按原 dest 分发，Go
        // contentErr 同语义），target 不被改写
        let (final_dest, proto, route_target) = result.expect("sniff returns gracefully");
        assert!(proto.is_none() && route_target.is_none());
        assert_eq!(
            final_dest.address().ip(),
            Some(std::net::IpAddr::from([1, 2, 3, 4])),
            "budget exhausted must keep original dest"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(200)
                && elapsed < std::time::Duration::from_secs(5),
            "sniff budget must be ~200ms fixed, got {elapsed:?} (was handshake timeout before va51④)"
        );
    }

    /// bk8l（Go newFakeDNSThenOthers + DispatchLink isFakeIP 门）：IP 在 fake 池
    /// 但映射丢失 → 内容嗅探包成 fakedns+others 命中 destOverride=[fakedns]，
    /// 拨号改写跟域名（不向失效假 IP 黑洞），route_only 不生效。
    #[tokio::test]
    async fn sniff_fake_ip_pool_without_mapping_wraps_fakedns_others() {
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;

        let mut payload = vec![0x16, 0x03, 0x01];
        let hello = build_minimal_client_hello(b"recovered.example.com");
        payload.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        payload.extend_from_slice(&hello);

        let (r, mut w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&payload);
        w.write_multi_buffer(mb).await.unwrap();
        w.shutdown();

        let mut cr = CachedReader::with_inner(Box::new(r));
        let req = SniffingRequest {
            enabled: true,
            override_destination_for_protocol: vec!["fakedns".to_string()],
            route_only: true, // Go：isFakeIP 时 routeOnly 不拦拨号改写
            ..Default::default()
        };
        let dest = xray_common::net::destination::Destination::new(
            Address::from_ipv4_bytes([203, 0, 113, 9]),
            Port::new(443),
            Network::TCP,
        );

        let (final_dest, proto, route_target) = sniff_connection(
            &mut cr,
            &dest,
            &req,
            Some(&PoolOnlyFakeDns),
        )
        .await
        .expect("sniff ok");

        assert_eq!(
            final_dest.address().as_domain(),
            Some("recovered.example.com"),
            "dial target must follow sniffed domain when fake mapping is lost"
        );
        assert_eq!(proto.as_deref(), Some("fakedns+others"));
        assert!(route_target.is_none(), "isFakeIP overrides route_only");
    }

    /// 路由指定的 outboundTag 不存在 → 关闭下行不落默认出站
    /// （Go default.go:469-470 DO NOT CHANGE）。
    #[tokio::test]
    async fn dispatch_link_missing_routed_tag_shuts_down_instead_of_default() {
        #[derive(Debug)]
        struct MissingRouter;
        impl RoutingRouter for MissingRouter {
            fn pick_route(&self, _ctx: &dyn RoutingContext) -> Result<Route, DispatcherError> {
                Ok(Route::new("missing-tag"))
            }
            fn pick_route_resolved<'a>(
                &'a self,
                _ctx: &'a dyn RoutingContext,
            ) -> Pin<Box<dyn Future<Output = Result<Route, DispatcherError>> + Send + 'a>> {
                Box::pin(async move { Ok(Route::new("missing-tag")) })
            }
        }

        let ohm = SimpleOhm::new();
        let default_hit = Arc::new(parking_lot::Mutex::new(None));
        ohm.set_default(Arc::new(RecordingHandler {
            tag: "default-out",
            seen_dest: Arc::clone(&default_hit),
        }));
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::new(ohm));
        d.router = Some(Arc::new(MissingRouter));

        let dest = xray_common::net::destination::Destination::new(
            xray_common::net::address::Address::new_domain("x.test".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));

        d.dispatch_link(&dest, outbound, &SniffingRequest::default(), None, None)
            .expect("dispatch_link ok");
        let mut r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
        let eof = match tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer()).await {
            Err(_) => panic!("timeout waiting EOF"),
            Ok(Err(_)) => true, // writer shutdown → 管道 EOF

            Ok(Ok(mb)) => mb.is_empty(),
        };
        assert!(eof, "downlink should be EOF after missing-tag shutdown");

        // 默认出站不得被触发
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(default_hit.lock().is_none(), "must not fall back to default outbound");
        drop(up_w);
    }

    /// set_fdns 注入（对应 Go dispatcher.fdns）。
    #[test]
    fn set_fdns_stores_engine() {
        let mut d = DefaultDispatcher::new();
        assert!(d.fdns.is_none());
        d.set_fdns(Some(Arc::new(FixedFakeDns)));
        d.set_fdns(Some(Arc::new(FixedFakeDns)));
        assert!(d.fdns.is_some());
    }

    /// oz1t：per-tag 计数器在 policy gate（stats.user_uplink/user_downlink）
    /// 关闭时不懒注册、不包装——默认 Policy 默认 false → 计数器不存在。
    #[tokio::test]
    async fn dispatch_link_skips_per_tag_counters_when_policy_gate_off() {
        let (stats, d) = build_oz1t_dispatcher(false);
        let (up_w, dn_r) = drive_oz1t_traffic(&d, "gated.example.com", b"x").await;
        drop(up_w);
        drop(dn_r);
        assert!(stats.get_counter("outbound>>>tag-out>>>traffic>>>uplink").is_none());
        assert!(stats.get_counter("outbound>>>tag-out>>>traffic>>>downlink").is_none());
    }

    /// oz1t：policy gate 开启 → per-tag counter 正常懒注册并累计（含 overhead）。
    #[tokio::test]
    async fn dispatch_link_registers_per_tag_counters_when_policy_gate_on() {
        let (stats, d) = build_oz1t_dispatcher(true);
        let payload = b"with-overhead-12345";
        let (up_w, mut dn_r) = drive_oz1t_traffic(&d, "gated2.example.com", payload).await;
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("timeout")
            .unwrap();
        drop(up_w);
        assert_eq!(resp.to_vec(), payload);
        let up = stats
            .get_counter("outbound>>>tag-out>>>traffic>>>uplink")
            .expect("uplink counter");
        let dn = stats
            .get_counter("outbound>>>tag-out>>>traffic>>>downlink")
            .expect("downlink counter");
        assert!(up.value() >= payload.len() as i64, "uplink {} >= payload len", up.value());
        assert!(dn.value() >= payload.len() as i64, "downlink {} >= payload len", dn.value());
    }

    /// oz1t 共享测试装置：构造带 EchoHandler + ResolvedRouter 的 dispatcher，
    /// `gate_on=true` 时经 ForSystem 门开启 tag counter（sm80①：per-tag 计数
    /// 门 = ForSystem().Stats，原 oz1t 直改 default_policy.user_* 是错误的门）。
    fn build_oz1t_dispatcher(gate_on: bool) -> (
        Arc<xray_app_stats::Manager>,
        DefaultDispatcher,
    ) {
        use std::pin::Pin;

        #[derive(Debug)]
        struct EchoHandler {
            tag: &'static str,
        }
        impl DispatchHandler for EchoHandler {
            fn tag(&self) -> &str {
                self.tag
            }
            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> PinFuture<()> {
                Box::pin(async move {
                    let mut r = link.reader;
                    let mut w = link.writer;
                    if let Ok(mb) = r.read_multi_buffer().await {
                        if !mb.is_empty() {
                            let _ = w.write_multi_buffer(mb).await;
                        }
                    }
                    w.shutdown();
                })
            }
        }

        #[derive(Debug)]
        struct TagOutRouter;
        impl RoutingRouter for TagOutRouter {
            fn pick_route(&self, _ctx: &dyn RoutingContext) -> Result<Route, DispatcherError> {
                Ok(Route::new("tag-out"))
            }
            fn pick_route_resolved<'a>(
                &'a self,
                _ctx: &'a dyn RoutingContext,
            ) -> Pin<Box<dyn Future<Output = Result<Route, DispatcherError>> + Send + 'a>> {
                Box::pin(async move { Ok(Route::new("tag-out")) })
            }
        }

        let stats = Arc::new(xray_app_stats::Manager::new_running());
        let mut d = DefaultDispatcher::new();
        let mut ohm = SimpleOhm::new();
        ohm.add("tag-out", Arc::new(EchoHandler { tag: "tag-out" }));
        d.ohm = Some(Arc::new(ohm));
        d.router = Some(Arc::new(TagOutRouter));
        d.stats = Some(Arc::clone(&stats) as Arc<dyn xray_features::stats::Manager>);
        if gate_on {
            d.set_policy_manager(Arc::new(SystemStatsAllOnPolicyManager));
        }
        (stats, d)
    }

    /// oz1t 共享 helper：建链、写 payload、返回 writer/reader。
    async fn drive_oz1t_traffic(
        d: &DefaultDispatcher,
        domain: &str,
        payload: &[u8],
    ) -> (
        Box<dyn xray_buf::io::Writer>,
        Box<dyn xray_buf::io::Reader>,
    ) {
        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let outbound = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));
        let dest = Destination::new(
            xray_common::net::address::Address::new_domain(domain.to_string()),
            xray_common::net::port::Port::new(443),
            Network::TCP,
        );
        d.dispatch_link(&dest, outbound, &SniffingRequest::default(), None, None)
            .expect("dispatch_link");
        let mut w: Box<dyn xray_buf::io::Writer> = Box::new(up_w);
        let mut mb = xray_buf::multi::MultiBuffer::new();
        mb.merge_bytes(payload);
        w.write_multi_buffer(mb).await.unwrap();
        let r: Box<dyn xray_buf::io::Reader> = Box::new(dn_r);
        (w, r)
    }

    /// sm80③：DialBridge.with_policy 注入的 TimeoutPolicy 驱动 bridge 数据面——
    /// 静默远端 + 注入 connection_idle=100ms，bridge 必须在短窗内结束
    /// （无注入时 SessionDefault 300s，外层 5s 守卫必然超时 panic）。
    /// 证明装配层 `policy_for_level(level).timeout` 注入真实生效。
    #[tokio::test]
    async fn dial_bridge_with_policy_drives_conn_idle() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::port::Port;

        // dial 返回静默 duplex server 端；client 端 forget 保活防 EOF 提前结束。
        let dial: DialFn = Arc::new(move |_dest: &Destination| {
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(4096);
                std::mem::forget(client);
                let conn = Box::new(xray_transport::connection::DuplexConnection::new(server))
                    as Box<dyn Connection>;
                Ok(conn)
            })
        });
        let bridge = DialBridge::new("policy-bridge", dial);
        let mut policy = xray_features::policy::TimeoutPolicy::default();
        policy.connection_idle = std::time::Duration::from_millis(100);
        policy.uplink_only = std::time::Duration::from_millis(100);
        policy.downlink_only = std::time::Duration::from_millis(100);
        bridge.with_policy(policy);

        let (up_r, up_w) =
            xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) =
            xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        drop(up_w); // 上行无数据：conn_idle 从 bridge 启动起计
        drop(dn_r);
        let link = xray_transport::link::Link::new(
            Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
            Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
        );
        let dest = Destination::new(
            Address::new_domain("idle.example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let started = std::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(5), bridge.dispatch(&dest, link))
            .await
            .expect("bridge must end on injected conn_idle (100ms), not SessionDefault 300s");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "bridge must honor injected 100ms idle, elapsed {:?}",
            started.elapsed()
        );
    }
}

