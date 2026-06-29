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
pub type TransportDialFn = Arc<
    dyn Fn(&Destination, &SocketOptions) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send>>
        + Send
        + Sync,
>;

/// Transport dialer 全局注册表。对应 Go `transportDialerCache`。
static TRANSPORT_DIALER_CACHE: OnceLock<RwLock<HashMap<String, TransportDialFn>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<String, TransportDialFn>> {
    TRANSPORT_DIALER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

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
pub async fn dial_transport(
    protocol: &str,
    destination: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // TCP 协议走 system dialer（含 sockopt）。
    if protocol == "tcp" || protocol == "raw" {
        return crate::system_dialer::dial_system(destination, sockopt).await;
    }
    // 其他协议查注册表。
    match get_transport_dialer(protocol) {
        Some(dialer_fn) => dialer_fn(destination, sockopt).await,
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{protocol} dialer not registered"),
        )),
    }
}

#[cfg(test)]
mod transport_cache_tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;
    use std::net::Ipv4Addr;

    #[test]
    fn register_and_get_transport_dialer() {
        let dialer: TransportDialFn = Arc::new(|_dest: &Destination, _sockopt: &SocketOptions| {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::Other, "test")) })
        });
        // 注册（如果之前已注册同名，忽略 AlreadyExists）。
        let _ = register_transport_dialer("test-protocol-cache", dialer.clone());
        assert!(get_transport_dialer("test-protocol-cache").is_some());
    }

    #[test]
    fn duplicate_registration_returns_error() {
        let dialer: TransportDialFn = Arc::new(|_, _| Box::pin(async { unreachable!() }));
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
}
