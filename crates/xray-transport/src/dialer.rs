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

use crate::sockopt::SocketOptions;

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
        let protocol = v.get("network").and_then(|n| n.as_str()).unwrap_or("tcp").to_string();
        let security = v.get("security").and_then(|s| s.as_str()).unwrap_or("").to_string();
        // 协议特定配置：尝试 `<protocol>Settings`（如 `wsSettings`/`grpcSettings`/`tcpSettings`）。
        // Go JSON 解析器约定 `network` 值与 settings 字段名对应（`tcp`→`tcpSettings`, `ws`→`wsSettings`, ...）。
        let transport_json = protocol_settings_key(&protocol)
            .and_then(|k| v.get(k).cloned());
        // 安全配置：`tlsSettings` 或 `realitySettings`。
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
