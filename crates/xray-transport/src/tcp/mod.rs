//! # TCP transport
//!
//! 对应 Go `transport/internet/tcp/`。
pub mod hub;

/// 注册 TCP transport listener 到全局注册表。
///
/// 对应 Go `init() { RegisterTransportListener(protocolName, ListenTCP) }`。
/// 必须在使用 `listener_registry::listen_tcp("tcp", ...)` 之前调用。
/// 重复调用返回 `Err(io::Error(AlreadyExists))`。
pub fn register_tcp_transport() -> std::io::Result<()> {
    crate::listener_registry::register_transport_listener("tcp", hub::tcp_listen_fn())
}
