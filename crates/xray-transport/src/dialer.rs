//! 拨号器抽象：客户端 IO 边界。
//!
//! 对应 Go `transport/internet/dialer.go` 的 `Dialer` interface。
//!
//! **范围说明**：本模块仅定义 trait，不提供具体实现。Go 版本的 `Dialer`
//! 全局注册表（`transportDialerCache`）和 `redirect()` 机制依赖 Phase 4+
//! 未就绪的 `outbound.Manager` / `session.Outbound` / `pipe.New` / `dns.Client`，
//! 因此本会话只交付 trait 边界，让下游 crate 可引用类型；具体传输
//! （TCP/TLS/WebSocket/gRPC 等）在各协议 crate 内实现并通过下游显式构造
//! 注入。

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use xray_common::errors::removed_feature_message;
use xray_common::net::destination::Destination;

use crate::connection::Connection;

/// 客户端拨号器 trait。对应 Go `transport/internet/dialer.go::Dialer`。
///
/// Go 原型（有 3 个方法）：
/// ```text
/// type Dialer interface {
///     Dial(ctx context.Context, dest net.Destination) (stat.Connection, error)
///     DestIpAddress() net.IP
///     SetOutboundGateway(ctx context.Context, ob *session.Outbound)
/// }
/// ```
///
/// Rust 翻译取舍：
/// - `dial` 返回 `Box<dyn Connection>`（而非 Go 的 `stat.Connection`——那是
///   `net.Conn` 接口别名，统计包装通过 `CounterConnection` 装饰，不在 trait 级强制）
/// - `set_outbound_gateway` 依赖未实现的 `session.Outbound`，此处仅声明为
///   `&self` 可选项，下游实现可暂返回 `Ok(())` 或暂不实现直到 Phase 4+
///   Outbound 就绪。必要时后续拆成子 trait。
pub trait Dialer: Send + Sync {
    /// 向 `dest` 发起连接。返回的 Connection 对象以 trait object 形式交由上层多态使用。
    fn dial<'a>(
        &'a self,
        dest: &'a Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>>;

    /// 返回该拨号器将使用的出口 IP 地址（对应 Go `DestIpAddress()`）。
    /// Go 原型返回 `net.IP`，可能为 nil。Rust 翻译为 `Option<IpAddr>` 表达 nil 语义。
    fn dest_ip_address(&self) -> Option<IpAddr>;

    /// 配置出口网关（对应 Go `SetOutboundGateway`）。
    ///
    /// 当前为接口占位，下游实现可暂不实现（返回 `Ok(())`）——`session.Outbound`
    /// 类型在 Phase 4+ 才出现。后续在此 trait 升级为参数化的版本，或拆分为
    /// `GatewayAwareDialer` 子 trait。
    fn set_outbound_gateway(&self) -> io::Result<()> {
        // ponytail: 默认实现，等 Phase 4+ session.Outbound 就绪后细化
        Ok(())
    }
}

// ===== Transport Dialer 全局注册表 =====
//
// 对应 Go `dialer.go::transportDialerCache` + `RegisterTransportDialer` + `Dial`。
// 每个 transport 协议（tcp/tls/websocket/grpc/httpupgrade/splithttp/reality/kcp/hysteria）
// 在 init() 中注册自己的 dialFunc。上层拨号时按 streamSettings.ProtocolName 查找。

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

use crate::sockopt::{HappyEyeballsConfig, SocketOptions};

/// Transport 协议拨号函数签名。对应 Go `dialFunc`。
///
/// 每个协议注册一个此类型函数，接收目标地址 + socket 选项，返回包装后的 Connection。
/// Transport 协议拨号函数签名。对应 Go `dialFunc`。
///
/// 每个协议注册一个此类型函数，接收目标地址 + socket 选项 + streamSettings（含 transport/security 配置），
/// 返回包装后的 Connection。
pub type TransportDialFn = Arc<
    dyn Fn(&Destination, &SocketOptions, &StreamSettings) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send>>
        + Send
        + Sync,
>;

/// 传输层流设置。对应 Go `transport/internet/config.go::MemoryStreamConfig`（精简版）。
///
/// 承载拨号所需的全部上下文：协议名（tcp/websocket/grpc/...）、协议特定配置 JSON、
/// 安全设置（tls/reality/none）及其配置 JSON、socket 选项已由参数级 `SocketOptions` 承载。
///
/// `transport_json` / `security_json` 为原始 `serde_json::Value`，由各 transport crate 自行解析
/// 成自己的强类型 `Config`（与 Go 端 `ProtocolSettings proto.Message` 弱类型对应）。
#[derive(Debug, Clone, Default)]
pub struct StreamSettings {
    /// 传输协议名（`"tcp"` / `"websocket"` / `"grpc"` / `"httpupgrade"` / `"splithttp"` / ...）。
    /// 空字符串视为 `"tcp"`。
    pub protocol: String,
    /// 安全层名（`"none"` / `"tls"` / `"reality"`）。空或 `"none"` 表示无 TLS。
    pub security: String,
    /// 传输层配置 JSON（对应 Go `ProtocolSettings`）。各协议 crate 自行 `serde_json::from_value`。
    pub transport_json: Option<serde_json::Value>,
    /// 安全层配置 JSON（对应 Go TLS/Reality Config）。
    pub security_json: Option<serde_json::Value>,
    /// Socket 选项配置 JSON（对应 Go `StreamConfig.SocketConfig` / `sockopt`）。
    /// 由 sockopt 模块自行解析为 `SocketOptions`。
    pub sockopt_json: Option<serde_json::Value>,
    /// Finalmask 流量伪装配置 JSON（对应 Go `finalmask` 字段，本仓库 finalmask 模块）。
    pub finalmask_json: Option<serde_json::Value>,
}

impl StreamSettings {
    /// 构造默认 TCP + 无 TLS 的 stream settings（等价 Go `ToMemoryStreamConfig(nil)`）。
    #[must_use]
    pub fn tcp() -> Self {
        Self {
            protocol: "tcp".to_string(),
            security: String::new(),
            transport_json: None,
            security_json: None,
            sockopt_json: None,
            finalmask_json: None,
        }
    }

    /// 从 outbound/inbound 的 `streamSettings` JSON 对象解析。
    ///
    /// JSON 格式（Go `StreamConfig` JSON）：
    /// `{ "network": "ws", "security": "tls", "tlsSettings": {...}, "wsSettings": {...} }`
    ///
    /// # 参数
    /// - `json`：`Some(v)` 取 `network` / `security` / `<proto>Settings` / `tlsSettings` / `realitySettings`；
    ///   `None` 返回默认 TCP。
    pub fn from_json(json: Option<&serde_json::Value>) -> Self {
        let Some(v) = json else { return Self::tcp(); };
        // 已移除特性警告（Go infra/conf 硬报错；Rust 保留宽容行为：warn + 继续解析）。
        for w in removed_feature_warnings(v) {
            xray_common::log::warning(w);
        }
        let protocol = v.get("network").and_then(|n| n.as_str()).unwrap_or("tcp").to_string();
        let security = v.get("security").and_then(|s| s.as_str()).unwrap_or("").to_string();
        // 协议特定配置：尝试 `<protocol>Settings`（如 `wsSettings`/`grpcSettings`/`tcpSettings`）。
        // Go JSON 解析器约定 `network` 值与 settings 字段名对应（`tcp`→`tcpSettings`, `ws`→`wsSettings`, ...）。
        // ponytail: Go JSON 字段名约定 `<proto>Settings`，但 Go xhttp 网络对应的
        // JSON 字段是 `xhttpSettings`（与 splithttpSettings 都合法；客户端常混用）。
        // ponytail: 取两者之一，避免 xhttpSettings JSON 字段被丢弃导致 splithttp
        // 配置丢失（host/path/mode 等全部退化为默认 + dest fallback）。
        let transport_json = protocol_settings_key(&protocol)
            .and_then(|k| v.get(k).cloned())
            .or_else(|| v.get("xhttpSettings").cloned())
;
        let security_json = v.get("tlsSettings").cloned().or_else(|| v.get("realitySettings").cloned());
        // Socket 选项（`sockopt`）与 finalmask 流量伪装配置。
        let sockopt_json = v.get("sockopt").cloned();
        let finalmask_json = v.get("finalmask").cloned();
        Self { protocol, security, transport_json, security_json, sockopt_json, finalmask_json }
    }
    /// 是否启用 TLS（`security == "tls"` 或 `security == "reality"`）。
    #[must_use]
    pub fn is_tls(&self) -> bool {
        matches!(self.security.as_str(), "tls" | "reality")
    }

    /// 从 `sockopt_json` 解析 SocketOptions（对应 Go `SocketConfig`）。
    ///
    /// 支持字段：`mark` / `tcpFastOpen` / `tcpKeepAliveInterval`（秒）/
    /// `tcpKeepAliveIdle`（秒）/ `tcpMptcp` / `tcpCongestion` / `tproxy` / `reusePort` /
    /// `v6only` / `dialerProxy` / `happyEyeballs` / `domainStrategy` /
    /// `addressPortStrategy` / `trustedXForwardedFor` / `tcpWindowClamp` / `tcpMaxSeg` /
    /// `penetrate` / `tcpUserTimeout`（毫秒）/ `customSockopt`。
    /// 缺省字段用 [`SocketOptions::default`]。Go `interface`（接口名字符串）JSON 暂不
    /// 解析（[`SocketOptions::bind_if_index`](crate::sockopt::SocketOptions) 字段已备，
    /// 尚无 JSON 入口）。
    #[must_use]
    pub fn socket_options(&self) -> SocketOptions {
        let mut opts = SocketOptions::default();
        let Some(obj) = self.sockopt_json.as_ref().and_then(|v| v.as_object()) else {
            return opts;
        };
        if let Some(v) = obj.get("mark").and_then(|v| v.as_u64()) {
            opts.mark = v as u32;
        }
        // Go TFO 是 interface{}：JSON 常写 true/false 或 0/1。
        if let Some(v) = obj.get("tcpFastOpen") {
            let on = v.as_bool().unwrap_or_else(|| v.as_i64() == Some(1));
            opts.tcp_fast_open = on;
        }
        if let Some(v) = obj.get("tcpKeepAliveInterval").and_then(|v| v.as_u64()) {
            opts.tcp_keepalive_interval = std::time::Duration::from_secs(v);
        }
        if let Some(v) = obj.get("tcpKeepAliveIdle").and_then(|v| v.as_u64()) {
            opts.tcp_keepalive_idle = std::time::Duration::from_secs(v);
        }
        // MPTCP（bd 6tl，Go `SocketConfig.TcpMptcp` 字段 19，JSON `tcpMptcp`）。
        if let Some(v) = obj.get("tcpMptcp").and_then(|v| v.as_bool()) {
            opts.tcp_mptcp = v;
        }
        // TFO（Go `SocketConfig.Tfo` JSON `tcpFastOpen`）在 socket_options 已解析；其余
        // sockopt 字段（sockopt_linux.go:40-44 / :104-108 / sockopt_freebsd.go:128-132）：
        if let Some(v) = obj.get("tcpCongestion").and_then(|v| v.as_str()) {
            opts.tcp_congestion = Some(v.to_string());
        }
        // TCP_WINDOW_CLAMP / TCP_MAXSEG / penetrate / TCP_USER_TIMEOUT（Go
        // `SocketConfig` 字段 15/17/18/16，JSON tcpWindowClamp/tcpMaxSeg/penetrate/
        // tcpUserTimeout，infra/conf/transport_sockopt.go:55-58；三个 TCP 选项仅
        // Linux 应用，其余平台解析存储——见 sockopt 模块）。
        if let Some(v) = obj.get("tcpWindowClamp").and_then(|v| v.as_i64()) {
            opts.tcp_window_clamp = v as i32;
        }
        if let Some(v) = obj.get("tcpMaxSeg").and_then(|v| v.as_i64()) {
            opts.tcp_max_seg = v as i32;
        }
        if let Some(v) = obj.get("penetrate").and_then(|v| v.as_bool()) {
            opts.penetrate = v;
        }
        if let Some(v) = obj.get("tcpUserTimeout").and_then(|v| v.as_i64()) {
            opts.tcp_user_timeout = v as i32;
        }
        if let Some(v) = obj.get("tproxy").and_then(|v| v.as_bool()) {
            opts.tproxy = v;
        }
        if let Some(v) = obj.get("reusePort").and_then(|v| v.as_bool()) {
            opts.reuse_port = v;
        }
        if let Some(v) = obj.get("v6only").and_then(|v| v.as_bool()) {
            opts.ipv6_only = v;
        }
        if let Some(v) = obj.get("dialerProxy").and_then(|v| v.as_str()) {
            opts.dialer_proxy = v.to_string();
        }
        // Happy Eyeballs（bd 0ko，Go `SocketConfig.HappyEyeballs`）。
        // 缺省字段取 Go UnmarshalJSON 缺省值（transport_internet.go:1021）。
        if let Some(he) = obj.get("happyEyeballs").and_then(|v| v.as_object()) {
            let mut cfg = HappyEyeballsConfig::default();
            if let Some(v) = he.get("prioritizeIPv6").and_then(|v| v.as_bool()) {
                cfg.prioritize_ipv6 = v;
            }
            if let Some(v) = he.get("tryDelayMs").and_then(|v| v.as_u64()) {
                cfg.try_delay_ms = v;
            }
            if let Some(v) = he.get("interleave").and_then(|v| v.as_u64()) {
                cfg.interleave = v as u32;
            }
            if let Some(v) = he.get("maxConcurrentTry").and_then(|v| v.as_u64()) {
                cfg.max_concurrent_try = v as u32;
            }
            opts.happy_eyeballs = Some(cfg);
        }
        // domainStrategy（bd 5y8，Go infra/conf/transport_internet.go:1082-1108，
        // 大小写不敏感；Go conf 对非法值硬报错，此 JSON 层宽容回退 AsIs 并 warn）。
        if let Some(v) = obj.get("domainStrategy").and_then(|v| v.as_str()) {
            opts.domain_strategy = parse_domain_strategy(v);
        }
        // addressPortStrategy（bd 5y8，transport_internet.go:1124-1142，同上宽容）。
        if let Some(v) = obj.get("addressPortStrategy").and_then(|v| v.as_str()) {
            opts.address_port_strategy = parse_address_port_strategy(v);
        }
        // customSockopt（Go `SocketConfig.CustomSockopt` 字段 20，infra/conf
        // transport_sockopt.go:12-19/123-135；全 string 字段原样透传，应用层
        // `apply_custom_sockopt` 按 system/network 过滤后 setsockopt）。
        if let Some(arr) = obj.get("customSockopt").and_then(|v| v.as_array()) {
            opts.custom_sockopt = arr
                .iter()
                .filter_map(|c| {
                    let o = c.as_object()?;
                    Some(crate::sockopt::CustomSockopt {
                        system: o.get("system").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        network: o.get("network").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        level: o.get("level").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        opt: o.get("opt").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        value: o.get("value").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        r#type: o.get("type").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                    })
                })
                .collect();
        }

        // trustedXForwardedFor（Go `SocketConfig.TrustedXForwardedFor` 字段 23，
        // JSON 字符串数组；headers.go ApplyTrustedXForwardedFor 信任门控名单）。
        if let Some(v) = obj.get("trustedXForwardedFor").and_then(|v| v.as_array()) {
            opts.trusted_x_forwarded_for =
                v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
        }
         opts
     }
 }

/// `domainStrategy` 字符串 → 枚举。对应 Go transport_internet.go:1082-1108
/// 的 `strings.ToLower` switch；未知值 warn + AsIs（Go 在 conf Build 硬报错）。
fn parse_domain_strategy(s: &str) -> crate::sockopt::DomainStrategy {
    use crate::sockopt::DomainStrategy;
    match s.to_ascii_lowercase().as_str() {
        "asis" | "" => DomainStrategy::AsIs,
        "useip" => DomainStrategy::UseIP,
        "useipv4" => DomainStrategy::UseIPv4,
        "useipv6" => DomainStrategy::UseIPv6,
        "useipv4v6" => DomainStrategy::UseIPv4v6,
        "useipv6v4" => DomainStrategy::UseIPv6v4,
        "forceip" => DomainStrategy::ForceIP,
        "forceipv4" => DomainStrategy::ForceIPv4,
        "forceipv6" => DomainStrategy::ForceIPv6,
        "forceipv4v6" => DomainStrategy::ForceIPv4v6,
        "forceipv6v4" => DomainStrategy::ForceIPv6v4,
        other => {
            tracing::warn!(value = other, "unsupported domain strategy, fallback to AsIs");
            DomainStrategy::AsIs
        }
    }
}

/// `addressPortStrategy` 字符串 → 枚举。对应 Go transport_internet.go:1124-1142。
fn parse_address_port_strategy(s: &str) -> crate::sockopt::AddressPortStrategy {
    use crate::sockopt::AddressPortStrategy;
    match s.to_ascii_lowercase().as_str() {
        "none" | "" => AddressPortStrategy::None,
        "srvportonly" => AddressPortStrategy::SrvPortOnly,
        "srvaddressonly" => AddressPortStrategy::SrvAddressOnly,
        "srvportandaddress" => AddressPortStrategy::SrvPortAndAddress,
        "txtportonly" => AddressPortStrategy::TxtPortOnly,
        "txtaddressonly" => AddressPortStrategy::TxtAddressOnly,
        "txtportandaddress" => AddressPortStrategy::TxtPortAndAddress,
        other => {
            tracing::warn!(value = other, "unsupported address port strategy, fallback to None");
            AddressPortStrategy::None
        }
    }
}

/// 把 `network` 值映射到对应 JSON settings 字段名。
///
/// Go `infra/conf/transport_internet.go::transportConfigCreator` 按字符串名注册 creator，
/// JSON 字段名约定为 `<proto>Settings`。Rust 端镜像该映射。
fn protocol_settings_key(protocol: &str) -> Option<&'static str> {
    match protocol {
        "tcp" | "raw" => Some("tcpSettings"),
        "kcp" | "mkcp" => Some("kcpSettings"),
        "ws" | "websocket" => Some("wsSettings"),
        "http" | "h2" | "grpc" => Some("grpcSettings"),
        "httpupgrade" => Some("httpupgradeSettings"),
        "splithttp" | "xhttp" => Some("splithttpSettings"),
        "quic" => Some("quicSettings"),
        "domainsocket" => Some("dsSettings"),
        _ => None,
    }
}

/// 检查 `streamSettings` JSON 中已移除的特性，返回 Go 对齐警告文案。
///
/// Go 基准（`infra/conf/transport_internet.go`，均在 conf Build 硬报错）：
/// - `:988-989` `h2`/`h3`/`http` 传输 → HTTP transport（单一文案，三别名同触发）
/// - `:990-991` `quic` 传输 → QUIC transport
/// - `:1824-1827` finalmask `xdns` 的 `domain` 键（注：非 SOCKS 设置，
///   Go 侧属 finalmask tcp 链的 Xdns 配置）
/// - `:2048-2049` `security == "xtls"` → Legacy XTLS
///
/// Rust 保留现有宽容行为：`from_json` 仅 warn 不阻断，协议映射/安全层判定不变。
fn removed_feature_warnings(v: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let protocol = v.get("network").and_then(|n| n.as_str()).unwrap_or("tcp");
    match protocol.to_ascii_lowercase().as_str() {
        "http" | "h2" | "h3" => warnings.push(removed_feature_message(
            "HTTP transport (without header padding, etc.)",
            "XHTTP stream-one H2 & H3",
        )),
        "quic" => warnings.push(removed_feature_message(
            "QUIC transport (without web service, etc.)",
            "XHTTP stream-one H3",
        )),
        _ => {}
    }
    let security = v.get("security").and_then(|s| s.as_str()).unwrap_or("");
    if security.eq_ignore_ascii_case("xtls") {
        warnings.push(removed_feature_message(
            "Legacy XTLS",
            "xtls-rprx-vision with TLS or REALITY",
        ));
    }
    let tcp_masks = v
        .get("finalmask")
        .and_then(|f| f.get("tcp"))
        .and_then(|t| t.as_array());
    if let Some(entries) = tcp_masks {
        for entry in entries {
            let is_xdns = entry.get("type").and_then(|t| t.as_str()) == Some("xdns");
            let has_domain = entry
                .get("settings")
                .and_then(|s| s.get("domain"))
                .is_some();
            if is_xdns && has_domain {
                warnings.push(removed_feature_message(
                    "domain",
                    "domains(server) & resolvers(client)",
                ));
            }
        }
    }
    warnings
}

/// Transport dialer 全局注册表。对应 Go `transportDialerCache`。
static TRANSPORT_DIALER_CACHE: OnceLock<RwLock<HashMap<String, TransportDialFn>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<String, TransportDialFn>> {
    TRANSPORT_DIALER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Transport dialer 注册表最大条目数。
const MAX_DIALER_ENTRIES: usize = 256;

/// 注册 transport 协议拨号函数。对应 Go `RegisterTransportDialer`。
///
/// 同名协议重复注册返回错误。协议名大小写敏感（Go 端用 lowercase）。
pub fn register_transport_dialer(protocol: &str, dialer: TransportDialFn) -> io::Result<()> {
    let mut cache = cache().write();
    if cache.contains_key(protocol) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{protocol} dialer already registered"),
        ));
    }
    if cache.len() >= MAX_DIALER_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("transport dialer registry full ({MAX_DIALER_ENTRIES})"),
        ));
    }
    cache.insert(protocol.to_string(), dialer);
    Ok(())
}

/// 按 protocol 名查找 transport dialer。
///
/// 返回 `None` 表示该协议未注册。
#[must_use]
pub fn get_transport_dialer(protocol: &str) -> Option<TransportDialFn> {
    cache().read().get(protocol).cloned()
}

/// 上层 transport 拨号。对应 Go `dialer.go::Dial`。
///
/// 按 `protocol` 查找注册的 dialer，调用它建立连接。
/// TCP 协议（`"tcp"` / `"tls"`）用 [`system_dialer::dial_system`]。
///
/// # 错误
///
/// - `NotFound`：protocol 未注册
/// - dialer 内部错误透传
/// 上层 transport 拨号（旧入口，等价于 `dial_with_settings(dest, &StreamSettings::tcp(), sockopt)`）。
///
/// **新代码应优先使用 [`dial_with_settings`] / [`dial`]。** 本函数保留向后兼容。
pub async fn dial_transport(
    protocol: &str,
    destination: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    let settings = StreamSettings { protocol: protocol.to_string(), ..StreamSettings::tcp() };
    dial_with_settings(protocol, destination, sockopt, &settings).await
}

/// 按 protocol 名查 transport dialer 并传入完整 streamSettings 拨号。
///
/// 对应 Go `transportDialerCache[protocol](ctx, dest, streamSettings)`。
/// tcp/raw 默认注册了含 security 包装的 dialer（`xray-transport-tcp`），
/// 故 `network:"tcp", security:"tls"` 等配置会正确包装 TLS。未注册时
/// tcp/raw fallback 到 [`system_dialer::dial_system`]（裸 TCP，向后兼容）。
pub async fn dial_with_settings(
    protocol: &str,
    destination: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    // 先查注册的 transport dialer（tcp/ws/grpc/... 注册到全局表）。
    if let Some(dialer_fn) = get_transport_dialer(protocol) {
        return dialer_fn(destination, sockopt, settings).await;
    }
    // fallback：未注册协议（如未调用 register_dialer 的测试环境），
    // tcp/raw 走裸系统拨号，保持向后兼容。
    if protocol == "tcp" || protocol == "raw" {
        return crate::system_dialer::dial_system(destination, sockopt).await;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{protocol} dialer not registered"),
    ))
}

/// 顶层 transport 入口。对应 Go `transport/internet/dialer.go::Dial`。
///
/// 按 `settings.protocol` 查 transport dialer。`settings = None` 等价 TCP 裸连。
///
/// # 错误
///
/// - `NotFound`：protocol 未注册
/// - dialer 内部错误透传
pub async fn dial(
    destination: &Destination,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    dial_with_settings(&settings.protocol, destination, sockopt, settings).await
}

#[cfg(test)]
mod transport_cache_tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;
    use std::net::Ipv4Addr;


    // ===== removed_feature_warnings（Go infra/conf/transport_internet.go 对齐）=====

    fn rfw(json: &str) -> Vec<String> {
        removed_feature_warnings(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn removed_warnings_http_h2_h3_transport() {
        // Go :988-989（h2/h3/http 同一文案）
        for network in ["http", "h2", "h3", "H2"] {
            let warns = rfw(&format!(r#"{{"network":"{network}"}}"#));
            assert_eq!(
                warns,
                vec![
                    "The feature HTTP transport (without header padding, etc.) has been \
                     removed and migrated to XHTTP stream-one H2 & H3. Please update your \
                     config(s) according to release note and documentation."
                        .to_string()
                ],
                "network={network}"
            );
        }
    }

    #[test]
    fn removed_warnings_quic_transport() {
        // Go :990-991
        assert_eq!(
            rfw(r#"{"network":"quic"}"#),
            vec![
                "The feature QUIC transport (without web service, etc.) has been removed \
                 and migrated to XHTTP stream-one H3. Please update your config(s) \
                 according to release note and documentation."
                    .to_string()
            ]
        );
    }

    #[test]
    fn removed_warnings_legacy_xtls_security() {
        // Go :2048-2049（大小写不敏感，与 Go strings.ToLower 一致）
        assert_eq!(
            rfw(r#"{"security":"xtls"}"#),
            vec![
                "The feature Legacy XTLS has been removed and migrated to \
                 xtls-rprx-vision with TLS or REALITY. Please update your config(s) \
                 according to release note and documentation."
                    .to_string()
            ]
        );
        assert_eq!(rfw(r#"{"security":"XTLS"}"#).len(), 1);
    }

    #[test]
    fn removed_warnings_xdns_domain() {
        // Go :1824-1827（finalmask tcp 链 xdns 的 settings.domain）
        let warns = rfw(
            r#"{"finalmask":{"tcp":[{"type":"xdns","settings":{"domain":"t.example.com"}}]}}"#,
        );
        assert_eq!(
            warns,
            vec![
                "The feature domain has been removed and migrated to domains(server) & \
                 resolvers(client). Please update your config(s) according to release \
                 note and documentation."
                    .to_string()
            ]
        );
        // xdns 无 domain（用 domains/resolvers 新形式）不触发
        assert!(rfw(r#"{"finalmask":{"tcp":[{"type":"xdns","settings":{"domains":["a.com"]}}]}}"#).is_empty());
    }

    #[test]
    fn removed_warnings_clean_config_is_empty() {
        // 常规 tcp/tls/ws 配置不触发任何警告
        assert!(rfw(r#"{"network":"tcp","security":"tls","tlsSettings":{"alpn":["h2"]}}"#).is_empty());
        assert!(rfw(r#"{"network":"ws","security":"reality"}"#).is_empty());
        assert!(rfw("{}").is_empty());
    }

    #[test]
    fn socket_options_parses_sockopt_json() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "mark": 255,
            "tcpFastOpen": true,
            "tcpKeepAliveInterval": 30,
            "tcpKeepAliveIdle": 60,
            "tcpMptcp": true,
            "v6only": true,
            "tcpCongestion": "bbr",
            "tproxy": true,
            "reusePort": true
        }));
        let o = s.socket_options();
        assert_eq!(o.mark, 255);
        assert!(o.tcp_fast_open);
        assert!(o.tcp_mptcp);
        assert_eq!(o.tcp_keepalive_interval, std::time::Duration::from_secs(30));
        assert_eq!(o.tcp_keepalive_idle, std::time::Duration::from_secs(60));
        assert!(o.ipv6_only);
        assert_eq!(o.tcp_congestion.as_deref(), Some("bbr"));
        assert!(o.tproxy);
        assert!(o.reuse_port);
    }
    #[test]
    fn socket_options_defaults_without_json() {
        let s = StreamSettings::tcp();
        assert_eq!(s.socket_options(), SocketOptions::default());
    }

    #[test]
    fn socket_options_tfo_accepts_numeric_one() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({ "tcpFastOpen": 1 }));
        assert!(s.socket_options().tcp_fast_open);
    }

    /// Happy Eyeballs 配置解析（bd 0ko，Go `SocketConfig.HappyEyeballs`）。
    #[test]
    fn socket_options_parses_happy_eyeballs() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "happyEyeballs": {
                "prioritizeIPv6": true,
                "tryDelayMs": 250,
                "interleave": 2,
                "maxConcurrentTry": 3
            }
        }));
        let he = s.socket_options().happy_eyeballs.expect("happyEyeballs parsed");
        assert!(he.prioritize_ipv6);
        assert_eq!(he.try_delay_ms, 250);
        assert_eq!(he.interleave, 2);
        assert_eq!(he.max_concurrent_try, 3);

        // 缺省字段取 Go UnmarshalJSON 缺省值（transport_internet.go:1021）。
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({ "happyEyeballs": {} }));
        let he = s.socket_options().happy_eyeballs.expect("happyEyeballs parsed");
        assert_eq!(
            he,
            HappyEyeballsConfig {
                prioritize_ipv6: false,
                interleave: 1,
                try_delay_ms: 0,
                max_concurrent_try: 4,
            }
        );

        // 无 happyEyeballs 字段 → None（默认关闭，对齐 Go TryDelayMs:0）。
        assert!(StreamSettings::tcp().socket_options().happy_eyeballs.is_none());
    }

    /// dialerProxy 解析（bd enk，Go SocketConfig.DialerProxy）。
    #[test]
    fn socket_options_parses_dialer_proxy() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({ "dialerProxy": "proxy-out" }));
        assert_eq!(s.socket_options().dialer_proxy, "proxy-out");
        // 缺省为空串。
        assert_eq!(StreamSettings::tcp().socket_options().dialer_proxy, "");
    }

    /// trustedXForwardedFor 解析（Go `SocketConfig.TrustedXForwardedFor`
    /// 字段 23，repeated string，JSON 字符串数组）。
    #[test]
    fn socket_options_parses_trusted_x_forwarded_for() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "trustedXForwardedFor": ["X-Real-IP", "CF-Connecting-IP"]
        }));
        assert_eq!(
            s.socket_options().trusted_x_forwarded_for,
            vec!["X-Real-IP".to_string(), "CF-Connecting-IP".to_string()]
        );
        // 缺省为空名单（默认永不采纳 XFF）。
        assert!(StreamSettings::tcp().socket_options().trusted_x_forwarded_for.is_empty());
    }

    /// 末端 5 字段解析（Go infra/conf/transport_sockopt.go:55-62 字段定义：
    /// tcpWindowClamp/tcpMaxSeg/penetrate/tcpUserTimeout 四标量 + customSockopt
    /// 列表 roundtrip；customSockopt 全 string 字段原样透传）。
    #[test]
    fn socket_options_parses_end_fields_and_custom_sockopt() {
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "tcpWindowClamp": 65536,
            "tcpMaxSeg": 1200,
            "tcpUserTimeout": 10000,
            "penetrate": true,
            "customSockopt": [
                { "system": "linux", "network": "tcp", "level": "6",
                  "opt": "5", "value": "1", "type": "int" },
                { "network": "udp", "opt": "123", "value": "hello", "type": "str" }
            ]
        }));
        let o = s.socket_options();
        assert_eq!(o.tcp_window_clamp, 65536);
        assert_eq!(o.tcp_max_seg, 1200);
        assert_eq!(o.tcp_user_timeout, 10000);
        assert!(o.penetrate);
        // customSockopt 列表逐条 roundtrip（Go CustomSockoptConfig 六字段）。
        assert_eq!(o.custom_sockopt.len(), 2);
        assert_eq!(o.custom_sockopt[0].system, "linux");
        assert_eq!(o.custom_sockopt[0].network, "tcp");
        assert_eq!(o.custom_sockopt[0].level, "6");
        assert_eq!(o.custom_sockopt[0].opt, "5");
        assert_eq!(o.custom_sockopt[0].value, "1");
        assert_eq!(o.custom_sockopt[0].r#type, "int");
        assert_eq!(o.custom_sockopt[1].network, "udp");
        assert_eq!(o.custom_sockopt[1].opt, "123");
        assert_eq!(o.custom_sockopt[1].value, "hello");
        assert_eq!(o.custom_sockopt[1].r#type, "str");

        // 缺省：无字段 → Default（三 TCP 选项 0 / penetrate false / 列表空）。
        let d = StreamSettings::tcp().socket_options();
        assert_eq!(d.tcp_window_clamp, 0);
        assert_eq!(d.tcp_max_seg, 0);
        assert_eq!(d.tcp_user_timeout, 0);
        assert!(!d.penetrate);
        assert!(d.custom_sockopt.is_empty());
    }

    /// domainStrategy/addressPortStrategy 解析（bd 5y8，Go
    /// transport_internet.go:1082-1142，大小写不敏感）。
    #[test]
    fn socket_options_parses_strategies() {
        use crate::sockopt::{AddressPortStrategy, DomainStrategy};
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "domainStrategy": "ForceIPv4v6",
            "addressPortStrategy": "TxtPortAndAddress"
        }));
        let opts = s.socket_options();
        assert_eq!(opts.domain_strategy, DomainStrategy::ForceIPv4v6);
        assert_eq!(opts.address_port_strategy, AddressPortStrategy::TxtPortAndAddress);

        // 大小写不敏感。
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({ "domainStrategy": "USEIP" }));
        assert_eq!(s.socket_options().domain_strategy, DomainStrategy::UseIP);

        // 未知值回退默认（Go conf 层硬报错，此层宽容 + warn）。
        let mut s = StreamSettings::tcp();
        s.sockopt_json = Some(serde_json::json!({
            "domainStrategy": "bogus",
            "addressPortStrategy": "bogus"
        }));
        let opts = s.socket_options();
        assert_eq!(opts.domain_strategy, DomainStrategy::AsIs);
        assert_eq!(opts.address_port_strategy, AddressPortStrategy::None);
    }

    #[test]
    fn register_and_get_transport_dialer() {
        let dialer: TransportDialFn = Arc::new(|_dest: &Destination, _sockopt: &SocketOptions, _s: &StreamSettings| {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::Other, "test")) })
        });
        // 注册（如果之前已注册同名，忽略 AlreadyExists）。
        let _ = register_transport_dialer("test-protocol-cache", dialer.clone());
        assert!(get_transport_dialer("test-protocol-cache").is_some());
    }

    #[test]
    fn duplicate_registration_returns_error() {
        let dialer: TransportDialFn = Arc::new(|_, _, _| Box::pin(async { unreachable!() }));
        let _ = register_transport_dialer("test-dup-protocol", dialer.clone());
        let result = register_transport_dialer("test-dup-protocol", dialer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn get_unregistered_returns_none() {
        assert!(get_transport_dialer("nonexistent-protocol").is_none());
    }

    #[tokio::test]
    async fn dial_transport_tcp_uses_system_dialer() {
        // TCP 协议走 system_dialer（应能连接本地 listener）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dest = Destination::tcp(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
        );
        let sockopt = SocketOptions::default();
        let result = dial_transport("tcp", &dest, &sockopt).await;
        assert!(result.is_ok());
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn dial_transport_unregistered_returns_not_found() {
        let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(0));
        let sockopt = SocketOptions::default();
        let result = dial_transport("unregistered-proto", &dest, &sockopt).await;
        match result {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::NotFound),
            other => { let _ = other; panic!("expected err"); }
        }
    }

    #[test]
    fn stream_settings_tcp_default() {
        let s = StreamSettings::from_json(None);
        assert_eq!(s.protocol, "tcp");
        assert!(!s.is_tls());
        assert!(s.transport_json.is_none());
    }

    #[test]
    fn stream_settings_parses_ws_tls() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"network":"ws","security":"tls","wsSettings":{"path":"/ray"},"tlsSettings":{"serverName":"x.com"}}"#
        ).unwrap();
        let s = StreamSettings::from_json(Some(&v));
        assert_eq!(s.protocol, "ws");
        assert!(s.is_tls());
        assert_eq!(s.transport_json.as_ref().unwrap().get("path").and_then(|p| p.as_str()), Some("/ray"));
        assert_eq!(s.security_json.as_ref().unwrap().get("serverName").and_then(|n| n.as_str()), Some("x.com"));
    }

    #[test]
    fn stream_settings_grpc_settings_key() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"network":"grpc","grpcSettings":{"serviceName":"gun"}}"#
        ).unwrap();
        let s = StreamSettings::from_json(Some(&v));
        assert_eq!(s.protocol, "grpc");
        assert_eq!(s.transport_json.as_ref().unwrap().get("serviceName").and_then(|n| n.as_str()), Some("gun"));
    }

    #[test]
    fn dial_with_settings_tcp_routes_to_system() {
        // 验证新 dial_with_settings 入口 TCP 路径与旧 dial_transport 等价。
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept_task = tokio::spawn(async move {
                let _ = listener.accept().await;
            });
            let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
            let sockopt = SocketOptions::default();
            let settings = StreamSettings::tcp();
            let result = dial_with_settings("tcp", &dest, &sockopt, &settings).await;
            assert!(result.is_ok());
            accept_task.await.unwrap();
        });
    }
}
