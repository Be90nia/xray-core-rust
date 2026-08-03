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
#[derive(Debug, Clone, Default)]
pub struct SniffingRequest {
    /// 是否启用嗅探
    pub enabled: bool,
    /// 仅嗅探元数据（不读 payload）
    pub metadata_only: bool,
    /// 仅对这些协议覆盖目的地
    pub override_destination_for_protocol: Vec<String>,
    /// 排除这些域名（不覆盖）
    pub exclude_for_domain: Vec<String>,
    /// 排除这些 IP（不覆盖）
    pub exclude_for_ip: Vec<IpAddr>,
    /// 仅路由（不改 target）
    pub route_only: bool,
}

// ========== should_override 核心逻辑 ==========

/// 判断 sniff 结果是否应覆盖原 destination
///
/// 对应 Go `(*DefaultDispatcher).shouldOverride`。判定流程：
/// 1. domain 为空 → false
/// 2. domain 命中 exclude_for_domain（前缀小写匹配）→ false
/// 3. dest 是 IP 且命中 exclude_for_ip → false
/// 4. protocol 命中 override_destination_for_protocol 列表（前缀匹配任一侧）→ true
///
/// # 参数
/// - `result`: 嗅探结果
/// - `request`: 嗅探请求配置
/// - `dest_address`: 原目的地地址（用于 exclude_for_ip 判断）
/// - `protocol_for_domain`: 若 result 是 CompositeSniffResult，传 `Some(protocol_for_domain_result)`；
///   否则传 `None`，使用 `result.protocol()`
pub fn should_override(
    result: &dyn SniffResult,
    request: &SniffingRequest,
    dest_address: Option<IpAddr>,
    protocol_for_domain: Option<&str>,
) -> bool {
    let domain = result.domain();
    if domain.is_empty() {
        return false;
    }

    // exclude_for_domain：小写前缀匹配（Go 用 matcher.MatchAny）
    let domain_lower = domain.to_lowercase();
    for excl in &request.exclude_for_domain {
        if domain_lower.contains(excl.as_str()) {
            return false;
        }
    }

    // exclude_for_ip：仅当 dest 是 IP 且命中
    if let Some(addr) = dest_address {
        if request.exclude_for_ip.iter().any(|&ip| ip == addr) {
            return false;
        }
    }

    // 主协议字符串（CompositeSniffResult 用 protocol_for_domain_result）
    let protocol_string = protocol_for_domain.unwrap_or_else(|| result.protocol());

    for p in &request.override_destination_for_protocol {
        if protocol_string.starts_with(p.as_str()) || p.starts_with(protocol_string) {
            return true;
        }
    }

    false
}

// ========== Sniffing 辅助函数 ==========

/// 嗅探连接首包，返回可能被覆盖的 destination。
///
/// 对应 Go `(*DefaultDispatcher).sniffing` 方法。流程：
/// 1. 从 CachedReader 读首包
/// 2. 构造 Sniffer 集合并嗅探
/// 3. 若有 FakeDnsEngine，先做 metadata sniff
/// 4. 若 should_override → 用 sniffed domain 覆盖 dest 的 IP 为域名
async fn sniff_connection(
    cr: &mut CachedReader,
    dest: &xray_common::net::destination::Destination,
    req: &SniffingRequest,
    fdns: Option<&dyn crate::fakednssniffer::FakeDnsEngine>,
    handshake_timeout: std::time::Duration,
) -> Result<(xray_common::net::destination::Destination, Option<String>), DispatcherError> {
    // 读首包（带超时）
    let read_result = tokio::time::timeout(
        handshake_timeout,
        cr.read_first(),
    ).await;

    match read_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(DispatcherError::SniffingTimeout),
    }

    let payload = cr.cached_bytes();
    if payload.is_empty() {
        return Ok((dest.clone(), None));
    }
    let network = dest.network();

    // 构造嗅探器集合
    let mut sniffer = crate::sniffer::new_default_sniffer_set();

    // FakeDns metadata sniff
    let mut metadata_domain = String::new();
    let mut metadata_protocol = String::new();
    if let Some(engine) = fdns {
        if let Some(ip) = dest.address().ip() {
            let domain = engine.get_domain_from_fake_dns(&ip);
            if !domain.is_empty() {
                metadata_domain = domain;
                metadata_protocol = "fakedns".to_string();
            }
        }
    }

    // Content sniff
    let content_result = sniffer.sniff(&payload, network);

    // 组合结果并判断是否覆盖
    let dest_ip = dest.address().ip();

    match content_result {
        Ok(content) => {
            // 有 content 结果
            if !metadata_domain.is_empty() {
                // 两者都有 → CompositeSniffResult 语义
                // protocol_for_domain 用 metadata 侧的 protocol
                let composite = crate::sniffer::CompositeSniffResult::new(
                    Box::new(crate::fakednssniffer::FakeDnsSniffResult::new(&metadata_domain)) as Box<dyn SniffResult>,
                    content,
                );
                if should_override(&composite, req, dest_ip, Some(&metadata_protocol)) {
                    let new_dest = override_dest(dest, &metadata_domain, req)?;
                    return Ok((new_dest, Some(metadata_protocol)));
                }
            } else {
                // 仅 content 结果
                if should_override(content.as_ref(), req, dest_ip, None) {
                    let proto = content.protocol().to_string();
                    let domain = content.domain().to_string();
                    let new_dest = override_dest(dest, &domain, req)?;
                    return Ok((new_dest, Some(proto)));
                }
            }
        }
        Err(_) => {
            // content sniff 失败，仅用 metadata
            if !metadata_domain.is_empty() {
                let meta_result = crate::fakednssniffer::FakeDnsSniffResult::new(&metadata_domain);
                if should_override(&meta_result, req, dest_ip, Some(&metadata_protocol)) {
                    let new_dest = override_dest(dest, &metadata_domain, req)?;
                    return Ok((new_dest, Some(metadata_protocol.clone())));
                }
            }
        }
    }

    Ok((dest.clone(), None))
}

/// 根据 sniffing 结果覆盖 destination。
fn override_dest(
    dest: &xray_common::net::destination::Destination,
    domain: &str,
    req: &SniffingRequest,
) -> Result<xray_common::net::destination::Destination, DispatcherError> {
    if req.route_only {
        tracing::debug!(domain = %domain, "sniffed (route_only, dest unchanged)");
        return Ok(dest.clone());
    }
    let new_addr = xray_common::net::address::Address::new_domain(domain.to_string());
    let new_dest = xray_common::net::destination::Destination::new(
        new_addr, dest.port(), dest.network(),
    );
    tracing::debug!(domain = %domain, "sniffed, overriding dest");
    Ok(new_dest)
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
}

impl Debug for DefaultDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultDispatcher")
            .field("has_ohm", &self.ohm.is_some())
            .field("has_router", &self.router.is_some())
            .field("has_stats", &self.stats.is_some())
            .field("has_policy_manager", &self.policy_manager.is_some())
            .field("has_fdns", &self.fdns.is_some())
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
        let pipe_opt = xray_buf::pipe::PipeOption {
            idle_timeout: Some(policy.timeout.connection_idle),
            ..xray_buf::pipe::PipeOption::default()
        };
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);

        // 查 inbound/outbound counter（对应 Go routedDispatch 中 getStatCounter）
        // counter_name 规则："{kind}>>>{tag}>>>traffic>>>{direction}"
        // Go: inbound uplink = inbound 写上行 = up_w
        // Go: inbound downlink = inbound 读下行 = dn_r
        // Go: outbound uplink = outbound 读上行 = up_r
        // Go: outbound downlink = outbound 写下行 = dn_w
        let inbound_uplink = inbound_tag.and_then(|tag| {
            self.stats.as_ref().and_then(|m| {
                m.get_counter(&format!("inbound>>>{tag}>>>traffic>>>uplink"))
            })
        });
        let inbound_downlink = inbound_tag.and_then(|tag| {
            self.stats.as_ref().and_then(|m| {
                m.get_counter(&format!("inbound>>>{tag}>>>traffic>>>downlink"))
            })
        });
        let outbound_uplink = outbound_tag.and_then(|tag| {
            self.stats.as_ref().and_then(|m| {
                m.get_counter(&format!("outbound>>>{tag}>>>traffic>>>uplink"))
            })
        });
        let outbound_downlink = outbound_tag.and_then(|tag| {
            self.stats.as_ref().and_then(|m| {
                m.get_counter(&format!("outbound>>>{tag}>>>traffic>>>downlink"))
            })
        });

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
        self.dispatch_link(destination, outbound, sniffing_request)?;
        Ok(inbound)
    }

    /// 分发已有 link。
    ///
    /// 对应 Go `(*DefaultDispatcher).DispatchLink(ctx, dest, outbound) error`。
    ///
    /// 流程（对应 Go `routedDispatch`）：
    /// 1. 若 sniffing 启用：用 CachedReader 包装 outbound reader，读首包 → sniff → 可能覆盖 dest
    /// 2. 若有 router：用 RoutingContext 调 router.pick_route() 选出站 handler
    /// 3. 无 router 或路由失败：用默认 handler
    /// 4. spawn handler.dispatch(link)
    pub fn dispatch_link(
        &self,
        destination: &xray_common::net::destination::Destination,
        outbound: xray_transport::link::Link,
        sniffing_request: &SniffingRequest,
    ) -> Result<(), DispatcherError> {
        let ohm = self.ohm.as_ref().ok_or_else(|| {
            DispatcherError::Other("no outbound handler manager registered".into())
        })?;

        // 预检查：如果没有 router 也没有 default handler，直接报错
        // （sniffing 后路由可能找到非 default handler，但无 router 无 default = 必定失败）
        if self.router.is_none() && ohm.get_default_handler().is_none() {
            return Err(DispatcherError::HandlerNotFound("default".into()));
        }

        // 克隆必要数据进入 spawn
        let dest = destination.clone();
        let sniff_req = sniffing_request.clone();
        let router = self.router.clone();
        let fdns = self.fdns.clone();
        let ohm = Arc::clone(ohm);
        let policy = self
            .policy_manager
            .as_ref()
            .map_or(self.default_policy.clone(), |pm| pm.policy_for_level(0));
        let handshake_timeout = policy.timeout.handshake;

        let outbound_reader = outbound.reader;
        let outbound_writer = outbound.writer;

        let fut = async move {
            // ---- Phase 1: Sniffing ----
            let mut cr = CachedReader::with_inner(outbound_reader);
            let (final_dest, sniffed_protocol) = if sniff_req.enabled {
                match sniff_connection(
                    &mut cr, &dest, &sniff_req, fdns.as_deref(), handshake_timeout,
                ).await {
                    Ok((d, proto)) => (d, proto),
                    Err(e) => {
                        tracing::debug!(dest = %dest, error = %e, "sniffing failed, using original dest");
                        (dest.clone(), None)
                    }
                }
            } else {
                (dest.clone(), None)
            };

            // ---- Phase 2: Routing ----
            let handler = if let Some(ref r) = router {
                let ctx = build_routing_context(&final_dest, sniffed_protocol.as_deref());
                match r.pick_route(&ctx) {
                    Ok(route) => {
                        ohm.get_handler(&route.outbound_tag).or_else(|| {
                            tracing::warn!(tag = %route.outbound_tag, "routed handler not found, falling back to default");
                            ohm.get_default_handler()
                        })
                    }
                    Err(_) => ohm.get_default_handler(),
                }
            } else {
                ohm.get_default_handler()
            };

            let Some(handler) = handler else {
                tracing::error!("no outbound handler available");
                return;
            };

            // CachedReader 始终包装 outbound_reader，sniffing 时回放缓存首包
            let reader: Box<dyn xray_buf::io::Reader> = Box::new(cr);
            let final_link = xray_transport::link::Link::new(reader, outbound_writer);

            let fut = handler.dispatch(&final_dest, final_link);
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

use xray_transport::bridge::{bridge_link_with_link, bridge_link_with_stream_full};
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
        }
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
        Box::pin(async move {
            match dial(&dest).await {
                Ok(remote) => {
                    if let Err(e) = bridge_link_with_stream_full(link, remote).await {
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
            if let Err(e) = bridge_link_with_link(link, client_link).await {
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

    #[allow(dead_code)]
    pub fn add(&self, tag: &str, handler: Arc<dyn DispatchHandler>) {
        self.tagged.write().unwrap().insert(tag.to_string(), handler);
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
        assert!(!should_override(&r, &req, None, None));
    }

    #[test]
    fn override_returns_false_when_excluded_by_domain() {
        let r = make_sniff("http", "blocked.example.com");
        let req = SniffingRequest {
            exclude_for_domain: vec!["blocked".to_string()],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, None, None));
    }

    #[test]
    fn override_returns_false_when_excluded_by_ip() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_ip: vec![ip("1.2.3.4")],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, Some(ip("1.2.3.4")), None));
    }

    #[test]
    fn override_returns_false_when_no_protocol_match() {
        let r = make_sniff("tls", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(!should_override(&r, &req, None, None));
    }

    #[test]
    fn override_returns_true_when_protocol_prefix_matches() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, None, None));
    }

    #[test]
    fn override_returns_true_when_protocol_is_prefix_of_request() {
        // 反向后缀：request="http", protocol="ht" — 用 starts_with 任一侧
        let r = make_sniff("ht", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        assert!(should_override(&r, &req, None, None));
    }

    #[test]
    fn override_uses_protocol_for_domain_when_provided() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            override_destination_for_protocol: vec!["fakedns".to_string()],
            ..Default::default()
        };
        // 传入 protocol_for_domain = "fakedns" 应命中
        assert!(should_override(&r, &req, None, Some("fakedns")));
    }

    #[test]
    fn override_skips_ip_exclude_when_dest_is_not_ip() {
        let r = make_sniff("http", "example.com");
        let req = SniffingRequest {
            exclude_for_ip: vec![ip("1.2.3.4")],
            override_destination_for_protocol: vec!["http".to_string()],
            ..Default::default()
        };
        // dest = None 不命中 exclude_for_ip → 继续 protocol 检查 → true
        assert!(should_override(&r, &req, None, None));
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
}
