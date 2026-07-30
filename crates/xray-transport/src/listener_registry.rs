//! Transport listener 全局注册表 + 连接回调类型。
//!
//! 对应 Go `transport/internet/tcp_hub.go` 的 `transportListenerCache` +
//! `RegisterTransportListener` + `ConnHandler` + `ListenFunc` + `Listener` interface。
//!
//! 每个 transport 协议（tcp/tls/websocket/grpc/httpupgrade/splithttp/reality/kcp/hysteria）
//! 在启动时注册自己的 `TransportListenFn`。上层监听时按 `StreamSettings.protocol` 查找。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

use crate::connection::Connection;
use crate::dialer::StreamSettings;
use crate::sockopt::SocketOptions;

// ===== ConnHandler =====

/// 新连接回调。对应 Go `ConnHandler = func(stat.Connection)`。
///
/// 每当 listener accept 一个新连接后调用，把连接交给上层（proxyman inbound worker）。
/// 使用 `Arc<dyn Fn>` 而非 trait object，因为 Go 的 `ConnHandler` 是函数值。
pub type ConnHandler = Arc<dyn Fn(Box<dyn Connection>) + Send + Sync>;

// ===== TransportListener trait =====

/// Transport listener 抽象。对应 Go `internet.Listener` interface。
///
/// 仅要求 `close` + `local_addr`，与 Go 版本一致。
/// `accept` 由各协议内部实现（在 `TransportListenFn` 中 spawn accept loop）。
pub trait TransportListener: Send + Sync {
    /// 关闭监听器。
    fn close(&self) -> io::Result<()>;

    /// 监听器本地地址。
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

// ===== TransportListenFn =====

/// Transport 协议监听函数签名。对应 Go `ListenFunc`。
///
/// 每个协议注册一个此类型函数，接收地址 + 端口 + stream settings + 连接回调，
/// 返回 `Box<dyn TransportListener>`。
///
/// 调用方负责 spawn accept loop（在 `TransportListenFn` 实现内部）。
pub type TransportListenFn = Arc<
    dyn Fn(
            SocketAddr,          // bind address
            StreamSettings,       // protocol + security config (owned, avoids lifetime issues)
            SocketOptions,        // socket options (owned, avoids lifetime issues)
            ConnHandler,          // new-connection callback
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn TransportListener>>> + Send>>
        + Send
        + Sync,
>;

// ===== 全局注册表 =====

/// Transport listener 全局注册表。对应 Go `transportListenerCache`。
static TRANSPORT_LISTENER_CACHE: OnceLock<RwLock<std::collections::HashMap<String, TransportListenFn>>> =
    OnceLock::new();

fn cache() -> &'static RwLock<std::collections::HashMap<String, TransportListenFn>> {
    TRANSPORT_LISTENER_CACHE.get_or_init(|| RwLock::new(std::collections::HashMap::new()))
}

/// 注册 transport 协议监听函数。对应 Go `RegisterTransportListener`。
///
/// 同名协议重复注册返回 `AlreadyExists` 错误。
/// 协议名大小写敏感（Go 端用 lowercase）。
pub fn register_transport_listener(
    protocol: &str,
    listen_fn: TransportListenFn,
) -> io::Result<()> {
    let mut cache = cache().write();
    if cache.contains_key(protocol) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{protocol} listener already registered"),
        ));
    }
    cache.insert(protocol.to_string(), listen_fn);
    Ok(())
}

/// 按 protocol 名查找 transport listener。
///
/// 返回 `None` 表示该协议未注册。
#[must_use]
pub fn get_transport_listener(protocol: &str) -> Option<TransportListenFn> {
    cache().read().get(protocol).cloned()
}

// ===== ListenTCP 顶层入口 =====

/// 上层 transport 监听入口。对应 Go `transport/internet/tcp_hub.go::ListenTCP`。
///
/// 按 `settings.protocol` 查 transport listener 注册表，调用注册的 `TransportListenFn`。
/// `settings = None` 等价 TCP 裸连。
///
/// # 错误
///
/// - `InvalidInput`：address 是 domain（TCP 监听不支持 domain）
/// - `NotFound`：protocol 未注册
/// - listen_fn 内部错误透传
pub async fn listen_tcp(
    addr: SocketAddr,
    settings: StreamSettings,
    sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let protocol = &settings.protocol;
    match get_transport_listener(protocol) {
        Some(listen_fn) => listen_fn(addr, settings, sockopt, handler).await,
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{protocol} listener not registered"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_get_transport_listener() {
        let listen_fn: TransportListenFn = Arc::new(
            |_addr: SocketAddr, _s: StreamSettings, _so: SocketOptions, _h: ConnHandler| {
                Box::pin(async { Err(io::Error::new(io::ErrorKind::Other, "test")) })
            },
        );
        let _ = register_transport_listener("test-listener-protocol", listen_fn.clone());
        assert!(get_transport_listener("test-listener-protocol").is_some());
    }

    #[test]
    fn duplicate_registration_returns_error() {
        let listen_fn: TransportListenFn = Arc::new(|_, _, _, _| Box::pin(async { unreachable!() }));
        let _ = register_transport_listener("test-dup-listener", listen_fn.clone());
        let result = register_transport_listener("test-dup-listener", listen_fn);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn get_unregistered_returns_none() {
        assert!(get_transport_listener("nonexistent-listener").is_none());
    }

    #[tokio::test]
    async fn listen_tcp_unregistered_returns_not_found() {
        let handler: ConnHandler = Arc::new(|_| {});
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let settings = StreamSettings::tcp();
        let sockopt = SocketOptions::default();
        let result = listen_tcp(addr, settings, sockopt, handler).await;
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::NotFound));
    }
}
