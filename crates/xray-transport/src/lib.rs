//! # xray-transport
//!
//! 传输层 IO 边界抽象。提供 `Link` / `Connection` / `Listener` / `Dialer` 核心
//! trait 及参考 TCP 实现，供下游 crate （Phase 4+ dispatcher/dns/router 等）
//! 引用类型边界。
//!
//! ## 本 crate 范围（ponytail 最小骨架）
//! - `link::Link` — inbound→outbound 字节流桥，组装 `Reader` + `Writer`
//! - `connection::Connection` trait + `TcpConnection` 参考实现
//! - `listener::Listener` trait + `TcpListenerConn` 参考实现
//! - `dialer::Dialer` trait（仅声明，无实现）
//! - `stat::CounterConnection` 字节计数包装器
//!
//! ## 未实现（留 stub）
//! `sockopt` / `tcp` / `udp` / `headers` / `finalmask` / `pipe` / `config` /
//! `filelocker` / `browser_dialer` / `tagged` / `memory_settings`
//! 这些模块依赖 Phase 4+ 未就绪的 `outbound.Manager` / `session.Outbound` /
//! `policy.BufferPolicyFromContext` / 平台特定 syscall，留待具体传输实现 crate 处理。
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\`。

pub mod bridge;
pub mod cnc;
pub mod connection;
pub mod dialer;
pub mod fallback;
pub mod link;
pub mod listener;
pub mod listener_registry;
pub mod retry;
pub mod splice;
pub mod stat;
pub mod system_dialer;
pub mod system_listener;

// 以下模块依赖 Phase 4+ 才会出现的 features（dns/outbound/policy 等），当前为 stub。
#[cfg(feature = "browser-dialer")]
pub mod browser_dialer;
pub mod config;
pub mod filelocker;
pub mod finalmask;
pub mod happy_eyeballs;
pub mod headers;
pub mod memory_settings;
pub mod pipe;
pub mod proxy_protocol;
pub mod sockopt;
pub mod tagged;
pub mod tcp;
pub mod udp;
// 顶层 re-export。
pub use bridge::{bridge_connections, bridge_connections_with_splice, copy_one_way};
pub use proxy_protocol::{build_proxy_header, read_proxy_protocol};
/// Re-exported so proxy crates can inspect negotiated TLS parameters (e.g.
/// `ServerConnection::protocol_version` for VLESS XRV outer-TLS1.3 gating)
/// without a direct `rustls` dependency.
pub use rustls;
/// TLS acceptor for inbound connections.
/// Re-exported so proxy crates don't need a direct `tokio-rustls` dependency.
pub use tokio_rustls::TlsAcceptor;
