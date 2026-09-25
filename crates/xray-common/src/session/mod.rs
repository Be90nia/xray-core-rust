//! 会话管理与上下文
//!
//! 对应 Go 版本 `common/session` 包，定义会话 ID、入站/出站信息、
//! 内容类型和套接字选项等元数据。

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    net::{destination::Destination, network::Network, port::Port},
    protocol::user::User,
    signal::ActivityTimer,
    uuid::UUID,
};
pub mod context;

pub use context::{FullHandler, SessionDispatcher, TrackedRequestErrorFeedback};

// ========== SessionConn (type-erased raw conn for splice copy) ==========

/// 与 Go `net.Conn` 等价的最小 trait object。
///
/// xray-common 不依赖 xray-transport（反向依赖），无法直接引用 `Connection`。
/// `Session.inbound.conn` / `Session.outbound.conn` 字段需要 type-erased 形式
/// 持有原始连接（用于 splice copy 优化）。下游 `xray-transport::Connection`
/// 可在后续独立 issue 中为本 trait 提供 blanket impl（当前无 call site 触发）。
///
/// ponytail: 当前阶段 Session 字段仅占位。后续 splice copy 实装时再补 blanket impl。
pub trait SessionConn: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// 对端地址。底层未提供时返回 `Ok(None)`。
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    /// 本端地址。底层未提供时返回 `Ok(None)`。
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

// ========== SniffingRequest ==========

/// Sniffing 请求元数据（只读，来自入站配置）。
///
/// 对应 Go `common/session.SniffingRequest`（session.go:80-88）。xray-common 不依赖
/// xray-geodata（反向依赖），故将 `DomainMatcher` / `IPMatcher` 暂存为原始规则字符串，
/// 下游可通过 `xray-geodata::matcher::*` 编译为真实 matcher。
///
/// ponytail: 字段为 `Vec<String>` 占位。等 `xray-common` 解除 `xray-geodata` 反向依赖后
/// 再升级为 `Option<Box<dyn DomainMatcher>>` 形态。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniffingRequest {
    /// 排除嗅探的域名规则（原始字符串）。
    pub exclude_for_domain: Vec<String>,
    /// 排除嗅探的 IP CIDR 规则（原始字符串）。
    pub exclude_for_ip: Vec<String>,
    /// 按协议覆盖目标（如 "http" → destination 改写）。
    pub override_destination_for_protocol: Vec<String>,
    /// 是否启用嗅探。
    pub enabled: bool,
    /// 仅记录协议元数据，不重写目标。
    pub metadata_only: bool,
    /// 仅用于路由决策，不影响内容转发。
    pub route_only: bool,
}

impl SniffingRequest {
    /// 创建新的 SniffingRequest。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置启用标记。
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 设置域名排除规则。
    pub fn with_exclude_for_domain(mut self, rules: Vec<String>) -> Self {
        self.exclude_for_domain = rules;
        self
    }

    /// 设置 IP 排除规则。
    pub fn with_exclude_for_ip(mut self, rules: Vec<String>) -> Self {
        self.exclude_for_ip = rules;
        self
    }

    /// 设置协议目标覆盖。
    pub fn with_override_destination_for_protocol(mut self, protocols: Vec<String>) -> Self {
        self.override_destination_for_protocol = protocols;
        self
    }

    /// 设置 metadata_only。
    pub fn with_metadata_only(mut self, metadata_only: bool) -> Self {
        self.metadata_only = metadata_only;
        self
    }

    /// 设置 route_only。
    pub fn with_route_only(mut self, route_only: bool) -> Self {
        self.route_only = route_only;
        self
    }
}

/// 会话 ID，基于 UUID。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ID(UUID);

impl ID {
    /// 生成新的随机会话 ID。
    pub fn new() -> Self {
        Self(UUID::new())
    }

    /// 从 UUID 创建会话 ID。
    pub fn from_uuid(uuid: UUID) -> Self {
        Self(uuid)
    }

    /// 获取内部 UUID 引用。
    pub fn as_uuid(&self) -> &UUID {
        &self.0
    }

    /// 消费自身，返回内部 UUID。
    pub fn into_uuid(self) -> UUID {
        self.0
    }
}

impl Default for ID {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ========== Inbound ==========

/// 入站处理器信息。
///
/// 对应 Go `common/session.Inbound`（session.go:36-59）。所有字段均为可选；
/// 缺省值 `None` 表示该维度未填，与 Go zero value 一致。
pub struct Inbound {
    /// 入站处理器标签。
    pub tag: Option<String>,
    /// 入站处理器名称（Go session.go:46-47，每种 proxy 的 human-readable name）。
    pub name: Option<String>,
    /// 入站网络类型。
    pub network: Option<Network>,
    /// 入站目标地址（对应 Go session.Destination）。
    pub destination: Option<Destination>,
    /// 入站本地地址（对应 Go session.Local，session.go:40-41）。
    pub local: Option<Destination>,
    /// 连接来源地址（对应 Go session.Source）。
    pub source: Option<Destination>,
    /// 网关地址（对应 Go session.Gateway）。
    pub gateway: Option<Destination>,
    /// 认证用户（对应 Go session.User）。
    pub user: Option<User>,
    /// VLESS 路由字节（Go `VlessRoute net.Port`，session.go:50-51）。
    /// 实义为用户发送 VLESS UUID 的 7th<<8 | 8th 字节。
    pub vless_route: Option<Port>,
    /// 用于 splice copy 的原始连接（Go `Conn net.Conn`，session.go:52-53）。
    pub conn: Option<Arc<dyn SessionConn>>,
    /// 用于 splice copy 的入站 buf copier 计时器（Go `Timer
    /// *signal.ActivityTimer`，session.go:54-55）。
    pub timer: Option<Arc<ActivityTimer>>,
    /// splice copy 决策标志（Go `CanSpliceCopy int`，1=可，2=处理后可行，3=不可）。
    pub can_splice_copy: i32,
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound")
            .field("tag", &self.tag)
            .field("name", &self.name)
            .field("network", &self.network)
            .field("destination", &self.destination)
            .field("local", &self.local)
            .field("source", &self.source)
            .field("gateway", &self.gateway)
            .field("user", &self.user)
            .field("vless_route", &self.vless_route)
            .field("conn", &self.conn.as_ref().map(|_| "<Arc<dyn SessionConn>>"))
            .field("timer", &self.timer.as_ref().map(|_| "<Arc<ActivityTimer>>"))
            .field("can_splice_copy", &self.can_splice_copy)
            .finish()
    }
}

impl Clone for Inbound {
    fn clone(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            name: self.name.clone(),
            network: self.network,
            destination: self.destination.clone(),
            local: self.local.clone(),
            source: self.source.clone(),
            gateway: self.gateway.clone(),
            user: self.user.clone(),
            vless_route: self.vless_route,
            conn: self.conn.clone(),   // Arc<dyn ...>: Clone by Arc bump
            timer: self.timer.clone(), // Arc<ActivityTimer>: Clone by Arc bump
            can_splice_copy: self.can_splice_copy,
        }
    }
}

impl Inbound {
    /// 创建新的入站信息。
    pub fn new() -> Self {
        Self {
            tag: None,
            name: None,
            network: None,
            destination: None,
            local: None,
            source: None,
            gateway: None,
            user: None,
            vless_route: None,
            conn: None,
            timer: None,
            can_splice_copy: 0,
        }
    }

    /// 设置标签（builder 模式）。
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// 设置网络类型（builder 模式）。
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// 设置目标地址（builder 模式）。
    pub fn with_destination(mut self, dest: Destination) -> Self {
        self.destination = Some(dest);
        self
    }

    /// 设置来源地址（builder 模式）。
    pub fn with_source(mut self, source: Destination) -> Self {
        self.source = Some(source);
        self
    }

    /// 设置认证用户（builder 模式）。
    pub fn with_user(mut self, user: User) -> Self {
        self.user = Some(user);
        self
    }

    /// 设置名称（builder 模式）。
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置本地地址（builder 模式）。
    pub fn with_local(mut self, dest: Destination) -> Self {
        self.local = Some(dest);
        self
    }

    /// 设置网关地址（builder 模式）。
    pub fn with_gateway(mut self, dest: Destination) -> Self {
        self.gateway = Some(dest);
        self
    }

    /// 设置 VLESS 路由字节（builder 模式）。
    pub fn with_vless_route(mut self, port: Port) -> Self {
        self.vless_route = Some(port);
        self
    }

    /// 设置 splice 原始连接（builder 模式）。
    pub fn with_conn(mut self, conn: Arc<dyn SessionConn>) -> Self {
        self.conn = Some(conn);
        self
    }

    /// 设置 splice buf copier 计时器（builder 模式）。
    pub fn with_timer(mut self, timer: Arc<ActivityTimer>) -> Self {
        self.timer = Some(timer);
        self
    }

    /// 设置 splice 决策标志（builder 模式）。
    pub fn with_can_splice_copy(mut self, v: i32) -> Self {
        self.can_splice_copy = v;
        self
    }
}

impl Default for Inbound {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Outbound ==========

/// 出站处理器信息。
///
/// 对应 Go `common/session.Outbound`（session.go:61-78）。
pub struct Outbound {
    /// 出站处理器标签。
    pub tag: Option<String>,
    /// 出站处理器名称（Go session.go:71-72，每种 proxy 的 human-readable name）。
    pub name: Option<String>,
    /// 目的地覆盖（可选）。
    pub destination_override: Option<Destination>,
    /// 网关地址（对应 Go session.Gateway）。
    pub gateway: Option<Destination>,
    /// 最终目标地址（对应 Go session.Target）。
    pub target: Option<Destination>,
    /// 路由解析目标地址（Go `RouteTarget net.Destination`，session.go:66）。
    pub route_target: Option<Destination>,
    /// 原始目标地址（透明代理用，对应 Go session.OriginalTarget）。
    pub original_target: Option<Destination>,
    /// 用于 splice copy 的原始连接（Go `Conn net.Conn`，session.go:74）。
    pub conn: Option<Arc<dyn SessionConn>>,
    /// splice copy 决策标志（Go `CanSpliceCopy int`，session.go:75-77）。
    pub can_splice_copy: i32,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("tag", &self.tag)
            .field("name", &self.name)
            .field("destination_override", &self.destination_override)
            .field("gateway", &self.gateway)
            .field("target", &self.target)
            .field("route_target", &self.route_target)
            .field("original_target", &self.original_target)
            .field("conn", &self.conn.as_ref().map(|_| "<Arc<dyn SessionConn>>"))
            .field("can_splice_copy", &self.can_splice_copy)
            .finish()
    }
}

impl Clone for Outbound {
    fn clone(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            name: self.name.clone(),
            destination_override: self.destination_override.clone(),
            gateway: self.gateway.clone(),
            target: self.target.clone(),
            route_target: self.route_target.clone(),
            original_target: self.original_target.clone(),
            conn: self.conn.clone(),
            can_splice_copy: self.can_splice_copy,
        }
    }
}

impl Outbound {
    /// 创建新的出站信息。
    pub fn new() -> Self {
        Self {
            tag: None,
            name: None,
            destination_override: None,
            gateway: None,
            target: None,
            route_target: None,
            original_target: None,
            conn: None,
            can_splice_copy: 0,
        }
    }

    /// 设置标签（builder 模式）。
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// 设置目的地覆盖（builder 模式）。
    pub fn with_destination_override(mut self, dest: Destination) -> Self {
        self.destination_override = Some(dest);
        self
    }

    /// 设置网关地址（builder 模式）。
    pub fn with_gateway(mut self, gateway: Destination) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// 设置最终目标地址（builder 模式）。
    pub fn with_target(mut self, target: Destination) -> Self {
        self.target = Some(target);
        self
    }

    /// 设置原始目标地址（builder 模式）。
    pub fn with_original_target(mut self, target: Destination) -> Self {
        self.original_target = Some(target);
        self
    }

    /// 设置名称（builder 模式）。
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置路由解析目标地址（builder 模式）。
    pub fn with_route_target(mut self, dest: Destination) -> Self {
        self.route_target = Some(dest);
        self
    }

    /// 设置 splice 原始连接（builder 模式）。
    pub fn with_conn(mut self, conn: Arc<dyn SessionConn>) -> Self {
        self.conn = Some(conn);
        self
    }

    /// 设置 splice 决策标志（builder 模式）。
    pub fn with_can_splice_copy(mut self, v: i32) -> Self {
        self.can_splice_copy = v;
        self
    }
}

impl Default for Outbound {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Content ==========

/// 内容类型标识。
///
/// 对应 Go `common/session.Content`（session.go:90-102）。
pub struct Content {
    /// 内容协议字符串（Go `Protocol string`，session.go:93）。
    pub protocol: Option<String>,
    /// HTTP 嗅探头（Go `Attributes map[string]string`，session.go:98）。
    pub attributes: HashMap<String, String>,
    /// 嗅探请求（Go `SniffingRequest SniffingRequest`，session.go:95）。
    pub sniffing_request: SniffingRequest,
    /// DNS 模块标记，跳过本会话的 DNS 解析防 DOH 循环（Go `SkipDNSResolve
    /// bool`，session.go:100-101）。
    pub skip_dns_resolve: bool,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content")
            .field("protocol", &self.protocol)
            .field("attributes", &self.attributes)
            .field("sniffing_request", &self.sniffing_request)
            .field("skip_dns_resolve", &self.skip_dns_resolve)
            .finish()
    }
}

impl Clone for Content {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            attributes: self.attributes.clone(),
            sniffing_request: self.sniffing_request.clone(),
            skip_dns_resolve: self.skip_dns_resolve,
        }
    }
}

impl Content {
    /// 创建新的内容信息。
    pub fn new() -> Self {
        Self {
            protocol: None,
            attributes: HashMap::new(),
            sniffing_request: SniffingRequest::new(),
            skip_dns_resolve: false,
        }
    }

    /// 设置协议（builder 模式）。
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// 设置嗅探请求（builder 模式）。
    pub fn with_sniffing_request(mut self, req: SniffingRequest) -> Self {
        self.sniffing_request = req;
        self
    }

    /// 设置 SkipDNSResolve（builder 模式）。
    pub fn with_skip_dns_resolve(mut self, skip: bool) -> Self {
        self.skip_dns_resolve = skip;
        self
    }

    /// 设置内容类型（builder 模式，alias for `with_protocol`，兼容旧 API）。
    pub fn with_type(mut self, content_type: impl Into<String>) -> Self {
        self.protocol = Some(content_type.into());
        self
    }
}

impl Default for Content {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Sockopt ==========

/// 套接字选项。
#[derive(Debug, Clone)]
pub struct Sockopt {
    /// TCP 标记（用于路由）。
    pub mark: Option<u32>,
    /// TOS（服务类型）字段。
    pub tos: Option<u8>,
    /// TCP Fast Open。
    pub tcp_fast_open: bool,
    /// TCP Keep-Alive 间隔（秒）。
    pub tcp_keep_alive_interval: Option<u32>,
}

impl Sockopt {
    /// 创建新的套接字选项。
    pub fn new() -> Self {
        Self { mark: None, tos: None, tcp_fast_open: false, tcp_keep_alive_interval: None }
    }

    /// 设置 TCP 标记（builder 模式）。
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// 设置 TOS（builder 模式）。
    pub fn with_tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// 设置 TCP Fast Open（builder 模式）。
    pub fn with_tcp_fast_open(mut self, fast_open: bool) -> Self {
        self.tcp_fast_open = fast_open;
        self
    }

    /// 设置 TCP Keep-Alive 间隔（builder 模式）。
    pub fn with_tcp_keep_alive_interval(mut self, interval: u32) -> Self {
        self.tcp_keep_alive_interval = Some(interval);
        self
    }
}

impl Default for Sockopt {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Session ==========

/// 会话上下文，携带入站/出站/内容/套接字选项等元数据。
///
/// 对应 Go `common/session` 各子结构体（session.go:36-102）。HTTP 嗅探头已下沉到
/// [`Content::attributes`]（Go session.go:98）。
pub struct Session {
    /// 会话 ID。
    pub id: ID,
    /// 入站信息。
    pub inbound: Inbound,
    /// 出站信息。
    pub outbound: Outbound,
    /// 内容信息。
    pub content: Content,
    /// 套接字选项。
    pub sockopt: Sockopt,
    // ---- context.go 携带值（Go 经 context.Value 传递，Rust 落字段）----
    /// 是否反向 mux（Go `isReverseMuxKey`，context.go:78-87）。
    pub is_reverse_mux: bool,
    /// mux 子上下文标记：仅自身流量超时才取消（Go `timeoutOnlyKey`，context.go:141-150）。
    pub timeout_only: bool,
    /// muxcool 服务端允许的网络类型（Go `allowedNetworkKey`，context.go:152-161）。
    /// `None` 对应 Go `net.Network_Unknown`。
    pub allowed_network: Option<Network>,
    /// MITM ALPN 是否 http/1.1（Go `mitmAlpn11Key`，context.go:174-183）。
    pub mitm_alpn11: bool,
    /// MITM 服务器名（Go `mitmServerNameKey`，context.go:185-194）。空串为默认。
    pub mitm_server_name: String,
    /// ss2022 入站获取 dispatcher（Go `dispatcherKey`，context.go:130-139）。
    pub dispatcher: Option<Arc<dyn SessionDispatcher>>,
    /// outbound 完整 handler（Go `fullHandlerKey`，context.go:163-172）。
    pub full_handler: Option<Arc<dyn FullHandler>>,
    /// observer 回传出站错误的 tracker（Go `trackedConnectionErrorKey`，context.go:115-128）。
    pub error_tracker: Option<Arc<dyn TrackedRequestErrorFeedback>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("inbound", &self.inbound)
            .field("outbound", &self.outbound)
            .field("content", &self.content)
            .field("sockopt", &self.sockopt)
            .field("is_reverse_mux", &self.is_reverse_mux)
            .field("timeout_only", &self.timeout_only)
            .field("allowed_network", &self.allowed_network)
            .field("mitm_alpn11", &self.mitm_alpn11)
            .field("mitm_server_name", &self.mitm_server_name)
            .field("dispatcher", &self.dispatcher.as_ref().map(|_| "<Arc<dyn SessionDispatcher>>"))
            .field("full_handler", &self.full_handler.as_ref().map(|_| "<Arc<dyn FullHandler>>"))
            .field(
                "error_tracker",
                &self.error_tracker.as_ref().map(|_| "<Arc<dyn TrackedRequestErrorFeedback>>"),
            )
            .finish()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            inbound: self.inbound.clone(),
            outbound: self.outbound.clone(),
            content: self.content.clone(),
            sockopt: self.sockopt.clone(),
            is_reverse_mux: self.is_reverse_mux,
            timeout_only: self.timeout_only,
            allowed_network: self.allowed_network,
            mitm_alpn11: self.mitm_alpn11,
            mitm_server_name: self.mitm_server_name.clone(),
            dispatcher: self.dispatcher.clone(), // Arc<dyn ...>: Clone by Arc bump
            full_handler: self.full_handler.clone(), // Arc<dyn ...>: Clone by Arc bump
            error_tracker: self.error_tracker.clone(), // Arc<dyn ...>: Clone by Arc bump
        }
    }
}

impl Session {
    /// 创建新的会话。
    pub fn new() -> Self {
        Self {
            id: ID::new(),
            inbound: Inbound::new(),
            outbound: Outbound::new(),
            content: Content::new(),
            sockopt: Sockopt::new(),
            is_reverse_mux: false,
            timeout_only: false,
            allowed_network: None,
            mitm_alpn11: false,
            mitm_server_name: String::new(),
            dispatcher: None,
            full_handler: None,
            error_tracker: None,
        }
    }

    /// 设置入站信息（builder 模式）。
    pub fn with_inbound(mut self, inbound: Inbound) -> Self {
        self.inbound = inbound;
        self
    }

    /// 设置出站信息（builder 模式）。
    pub fn with_outbound(mut self, outbound: Outbound) -> Self {
        self.outbound = outbound;
        self
    }

    /// 设置内容信息（builder 模式）。
    pub fn with_content(mut self, content: Content) -> Self {
        self.content = content;
        self
    }

    /// 设置套接字选项（builder 模式）。
    pub fn with_sockopt(mut self, sockopt: Sockopt) -> Self {
        self.sockopt = sockopt;
        self
    }

    /// 设置属性。
    ///
    /// 对应 Go `Content.SetAttribute`（session.go:111-116）。属性存储于
    /// [`Content::attributes`]，本方法为兼容旧 API 的转发。
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.content.attributes.insert(key.into(), value.into());
    }

    /// 获取属性。
    ///
    /// 对应 Go `Content.Attribute`（session.go:118-124）。
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.content.attributes.get(key).map(|s| s.as_str())
    }

    /// 获取入站目标地址（对应 Go session.Destination）。
    ///
    /// 优先返回 `outbound.destination_override`（如果设置了），
    /// 否则返回 `inbound.destination`。
    pub fn destination(&self) -> Option<&Destination> {
        self.outbound.destination_override.as_ref().or(self.inbound.destination.as_ref())
    }

    /// 获取连接来源地址（对应 Go session.Source）。
    pub fn source(&self) -> Option<&Destination> {
        self.inbound.source.as_ref()
    }

    /// 获取认证用户（对应 Go session.User）。
    pub fn user(&self) -> Option<&User> {
        self.inbound.user.as_ref()
    }

    /// 获取网关地址（对应 Go session.Gateway）。
    pub fn gateway(&self) -> Option<&Destination> {
        self.outbound.gateway.as_ref()
    }

    /// 获取最终目标地址（对应 Go session.Target）。
    /// 优先返回 `outbound.target`，否则回退到 `destination()`。
    pub fn target(&self) -> Option<&Destination> {
        self.outbound.target.as_ref().or(self.destination())
    }

    /// 获取原始目标地址（透明代理用，对应 Go session.OriginalTarget）。
    pub fn original_target(&self) -> Option<&Destination> {
        self.outbound.original_target.as_ref()
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use super::*;
    use crate::net::{address::Address, port::Port};

    // ---- ID 测试 ----

    #[test]
    fn test_id_new() {
        let id = ID::new();
        assert!(!id.as_uuid().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_id_unique() {
        let a = ID::new();
        let b = ID::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_id_from_uuid() {
        let uuid = UUID::new();
        let id = ID::from_uuid(uuid.clone());
        assert_eq!(id.as_uuid(), &uuid);
    }

    #[test]
    fn test_id_display() {
        let id = ID::new();
        let display = format!("{id}");
        assert!(!display.is_empty());
        assert!(display.contains('-'));
    }

    #[test]
    fn test_id_default() {
        let id = ID::default();
        assert!(!id.as_uuid().as_bytes().iter().all(|&b| b == 0));
    }

    // ---- Inbound 测试 ----

    #[test]
    fn test_inbound_new() {
        let inbound = Inbound::new();
        assert!(inbound.tag.is_none());
        assert!(inbound.network.is_none());
    }

    #[test]
    fn test_inbound_with_tag() {
        let inbound = Inbound::new().with_tag("http-in");
        assert_eq!(inbound.tag, Some("http-in".to_string()));
    }

    #[test]
    fn test_inbound_with_network() {
        let inbound = Inbound::new().with_network(Network::TCP);
        assert_eq!(inbound.network, Some(Network::TCP));
    }

    #[test]
    fn test_inbound_default() {
        let inbound = Inbound::default();
        assert!(inbound.tag.is_none());
    }

    // ---- Outbound 测试 ----

    #[test]
    fn test_outbound_new() {
        let outbound = Outbound::new();
        assert!(outbound.tag.is_none());
        assert!(outbound.destination_override.is_none());
    }

    #[test]
    fn test_outbound_with_tag() {
        let outbound = Outbound::new().with_tag("proxy-out");
        assert_eq!(outbound.tag, Some("proxy-out".to_string()));
    }

    #[test]
    fn test_outbound_with_destination_override() {
        let dest = Destination::tcp(Address::ipv4(Ipv4Addr::new(127, 0, 0, 1)), Port::new(8080));
        let outbound = Outbound::new().with_destination_override(dest.clone());
        assert_eq!(outbound.destination_override, Some(dest));
    }

    #[test]
    fn test_outbound_default() {
        let outbound = Outbound::default();
        assert!(outbound.tag.is_none());
    }

    // ---- Content 测试 ----

    #[test]
    fn test_content_new() {
        let content = Content::new();
        assert!(content.protocol.is_none());
    }

    #[test]
    fn test_content_with_type() {
        let content = Content::new().with_type("application/json");
        assert_eq!(content.protocol, Some("application/json".to_string()));
    }

    #[test]
    fn test_content_default() {
        let content = Content::default();
        assert!(content.protocol.is_none());
    }

    // ---- Sockopt 测试 ----

    #[test]
    fn test_sockopt_new() {
        let sockopt = Sockopt::new();
        assert!(sockopt.mark.is_none());
        assert!(sockopt.tos.is_none());
        assert!(!sockopt.tcp_fast_open);
        assert!(sockopt.tcp_keep_alive_interval.is_none());
    }

    #[test]
    fn test_sockopt_with_mark() {
        let sockopt = Sockopt::new().with_mark(123);
        assert_eq!(sockopt.mark, Some(123));
    }

    #[test]
    fn test_sockopt_with_tos() {
        let sockopt = Sockopt::new().with_tos(0x10);
        assert_eq!(sockopt.tos, Some(0x10));
    }

    #[test]
    fn test_sockopt_with_tcp_fast_open() {
        let sockopt = Sockopt::new().with_tcp_fast_open(true);
        assert!(sockopt.tcp_fast_open);
    }

    #[test]
    fn test_sockopt_with_tcp_keep_alive_interval() {
        let sockopt = Sockopt::new().with_tcp_keep_alive_interval(30);
        assert_eq!(sockopt.tcp_keep_alive_interval, Some(30));
    }

    #[test]
    fn test_sockopt_default() {
        let sockopt = Sockopt::default();
        assert!(!sockopt.tcp_fast_open);
    }

    // ---- Session 测试 ----

    #[test]
    fn test_session_new() {
        let session = Session::new();
        assert!(!session.id.as_uuid().as_bytes().iter().all(|&b| b == 0));
        assert!(session.inbound.tag.is_none());
        assert!(session.outbound.tag.is_none());
        assert!(session.content.attributes.is_empty());
    }

    #[test]
    fn test_session_with_inbound() {
        let inbound = Inbound::new().with_tag("test-in");
        let session = Session::new().with_inbound(inbound.clone());
        assert_eq!(session.inbound.tag, inbound.tag);
    }

    #[test]
    fn test_session_with_outbound() {
        let outbound = Outbound::new().with_tag("test-out");
        let session = Session::new().with_outbound(outbound.clone());
        assert_eq!(session.outbound.tag, outbound.tag);
    }

    #[test]
    fn test_session_with_content() {
        let content = Content::new().with_type("text/html");
        let session = Session::new().with_content(content.clone());
        assert_eq!(session.content.protocol, content.protocol);
    }

    #[test]
    fn test_session_with_sockopt() {
        let sockopt = Sockopt::new().with_mark(255);
        let session = Session::new().with_sockopt(sockopt.clone());
        assert_eq!(session.sockopt.mark, sockopt.mark);
    }

    #[test]
    fn test_session_attributes() {
        let mut session = Session::new();
        session.set_attribute("key1", "value1");
        session.set_attribute("key2", "value2");

        assert_eq!(session.get_attribute("key1"), Some("value1"));
        assert_eq!(session.get_attribute("key2"), Some("value2"));
        assert_eq!(session.get_attribute("nonexistent"), None);
    }

    #[test]
    fn test_session_set_attribute_overwrite() {
        let mut session = Session::new();
        session.set_attribute("key", "value1");
        session.set_attribute("key", "value2");
        assert_eq!(session.get_attribute("key"), Some("value2"));
    }

    #[test]
    fn test_session_default() {
        let session = Session::default();
        assert!(session.content.attributes.is_empty());
    }

    #[test]
    fn test_session_clone() {
        let mut session = Session::new();
        session.set_attribute("key", "value");
        let cloned = session.clone();
        assert_eq!(cloned.get_attribute("key"), Some("value"));
    }

    #[test]
    fn test_session_builder_chain() {
        let session = Session::new()
            .with_inbound(Inbound::new().with_tag("in"))
            .with_outbound(Outbound::new().with_tag("out"))
            .with_content(Content::new().with_type("json"))
            .with_sockopt(Sockopt::new().with_mark(100));

        assert_eq!(session.inbound.tag, Some("in".to_string()));
        assert_eq!(session.outbound.tag, Some("out".to_string()));
        assert_eq!(session.content.protocol, Some("json".to_string()));
        assert_eq!(session.sockopt.mark, Some(100));
    }

    // ---- 新增 9 字段 round-trip 测试 ----

    /// 包装 `tokio::io::DuplexStream` 的 SessionConn 桩（用于 round-trip 字段赋值测试）。
    struct DummySessionConn(tokio::io::DuplexStream);
    impl SessionConn for DummySessionConn {}
    impl AsyncRead for DummySessionConn {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for DummySessionConn {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    fn dest(addr: &str, port: u16) -> Destination {
        Destination::tcp(Address::ipv4(addr.parse::<Ipv4Addr>().unwrap()), Port::new(port))
    }

    #[test]
    fn test_inbound_9_fields_roundtrip() {
        let local = dest("10.0.0.1", 8080);
        let timer = Arc::new(ActivityTimer::new(Duration::from_secs(60)));
        let conn: Arc<dyn SessionConn> = Arc::new(DummySessionConn(tokio::io::duplex(64).0));

        let inbound = Inbound::new()
            .with_name("vless-in")
            .with_local(local.clone())
            .with_vless_route(Port::new(0x1234))
            .with_conn(conn.clone())
            .with_timer(timer.clone())
            .with_can_splice_copy(2);

        // 读取断言
        assert_eq!(inbound.name.as_deref(), Some("vless-in"));
        assert_eq!(inbound.local, Some(local));
        assert_eq!(inbound.vless_route, Some(Port::new(0x1234)));
        assert!(Arc::ptr_eq(inbound.conn.as_ref().unwrap(), &conn,));
        assert!(Arc::ptr_eq(inbound.timer.as_ref().unwrap(), &timer,));
        assert_eq!(inbound.can_splice_copy, 2);

        // 默认可 clone（含 Arc<dyn SessionConn>）
        let cloned = inbound.clone();
        assert_eq!(cloned.name, inbound.name);
        assert_eq!(cloned.vless_route, inbound.vless_route);
    }

    #[test]
    fn test_outbound_new_fields_roundtrip() {
        let route_target = dest("8.8.8.8", 53);
        let conn: Arc<dyn SessionConn> = Arc::new(DummySessionConn(tokio::io::duplex(64).0));

        let outbound = Outbound::new()
            .with_name("freedom")
            .with_route_target(route_target.clone())
            .with_conn(conn.clone())
            .with_can_splice_copy(3);

        assert_eq!(outbound.name.as_deref(), Some("freedom"));
        assert_eq!(outbound.route_target, Some(route_target));
        assert!(Arc::ptr_eq(outbound.conn.as_ref().unwrap(), &conn));
        assert_eq!(outbound.can_splice_copy, 3);

        let cloned = outbound.clone();
        assert_eq!(cloned.route_target, outbound.route_target);
        assert_eq!(cloned.can_splice_copy, 3);
    }

    #[test]
    fn test_content_sniffing_and_skip_dns_roundtrip() {
        let sniff = SniffingRequest::new()
            .with_enabled(true)
            .with_exclude_for_domain(vec!["private.local".to_string()])
            .with_exclude_for_ip(vec!["10.0.0.0/8".to_string()])
            .with_override_destination_for_protocol(vec!["http".to_string(), "tls".to_string()])
            .with_metadata_only(true)
            .with_route_only(false);

        let content = Content::new()
            .with_protocol("http/1.1")
            .with_sniffing_request(sniff.clone())
            .with_skip_dns_resolve(true);

        assert_eq!(content.protocol.as_deref(), Some("http/1.1"));
        assert!(content.skip_dns_resolve);
        assert_eq!(content.sniffing_request, sniff);
        assert!(content.sniffing_request.enabled);
        assert_eq!(content.sniffing_request.exclude_for_domain, vec!["private.local".to_string()]);
        assert_eq!(content.sniffing_request.exclude_for_ip, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(
            content.sniffing_request.override_destination_for_protocol,
            vec!["http".to_string(), "tls".to_string()]
        );
        assert!(content.sniffing_request.metadata_only);
        assert!(!content.sniffing_request.route_only);

        let cloned = content.clone();
        assert_eq!(cloned.sniffing_request, sniff);
        assert!(cloned.skip_dns_resolve);
    }

    #[test]
    fn test_session_full_roundtrip() {
        // 整体 Session（含所有 9 字段）round-trip
        let local = dest("127.0.0.1", 443);
        let route_target = dest("1.1.1.1", 443);
        let timer = Arc::new(ActivityTimer::new(Duration::from_millis(100)));
        let conn: Arc<dyn SessionConn> = Arc::new(DummySessionConn(tokio::io::duplex(64).0));
        let sniff = SniffingRequest::new()
            .with_enabled(true)
            .with_exclude_for_domain(vec!["x.test".to_string()]);

        let session = Session::new()
            .with_inbound(
                Inbound::new()
                    .with_name("vless-in")
                    .with_local(local.clone())
                    .with_vless_route(Port::new(0x5678))
                    .with_conn(conn.clone())
                    .with_timer(timer.clone())
                    .with_can_splice_copy(1),
            )
            .with_outbound(
                Outbound::new()
                    .with_name("freedom")
                    .with_route_target(route_target.clone())
                    .with_conn(conn.clone())
                    .with_can_splice_copy(1),
            )
            .with_content(
                Content::new().with_sniffing_request(sniff.clone()).with_skip_dns_resolve(true),
            );

        // Inbound 6 字段
        assert_eq!(session.inbound.name.as_deref(), Some("vless-in"));
        assert_eq!(session.inbound.local, Some(local));
        assert_eq!(session.inbound.vless_route, Some(Port::new(0x5678)));
        assert!(Arc::ptr_eq(session.inbound.conn.as_ref().unwrap(), &conn));
        assert!(Arc::ptr_eq(session.inbound.timer.as_ref().unwrap(), &timer));
        assert_eq!(session.inbound.can_splice_copy, 1);
        // Outbound 3 新字段
        assert_eq!(session.outbound.name.as_deref(), Some("freedom"));
        assert_eq!(session.outbound.route_target, Some(route_target));
        assert!(Arc::ptr_eq(session.outbound.conn.as_ref().unwrap(), &conn));
        assert_eq!(session.outbound.can_splice_copy, 1);
        // Content 2 新字段
        assert_eq!(session.content.sniffing_request, sniff);
        assert!(session.content.skip_dns_resolve);

        // Clone 整体保持字段一致
        let cloned = session.clone();
        assert_eq!(cloned.inbound.name, session.inbound.name);
        assert_eq!(cloned.outbound.name, session.outbound.name);
        assert_eq!(cloned.content.sniffing_request, session.content.sniffing_request);
        assert!(cloned.content.skip_dns_resolve);
    }

    #[test]
    fn test_sniffing_request_default() {
        let r = SniffingRequest::default();
        assert!(!r.enabled);
        assert!(r.exclude_for_domain.is_empty());
        assert!(r.exclude_for_ip.is_empty());
        assert!(r.override_destination_for_protocol.is_empty());
        assert!(!r.metadata_only);
        assert!(!r.route_only);
    }

    #[test]
    fn test_session_default_skip_dns_resolve_false() {
        let s = Session::default();
        assert!(!s.content.skip_dns_resolve);
        assert!(!s.content.sniffing_request.enabled);
        assert_eq!(s.inbound.can_splice_copy, 0);
        assert_eq!(s.outbound.can_splice_copy, 0);
    }
}
