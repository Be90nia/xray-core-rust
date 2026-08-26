//! 分发器应用服务（Go → Rust 翻译）
//!
//! 对应 Go 版本 `app/dispatcher/`。负责将入站连接按规则分发到出站处理器，
//! 含嗅探（sniff）逻辑、字节计数（stats）和 fake DNS 集成。
//!
//! ## 当前状态
//!
//! 业务核心（独立可测）：
//! - [`sniffer`] — `SniffResult` trait、`Sniffer` 编排框架、`CompositeSniffResult` 组合结果、
//!   `ProtocolSniffer` trait（具体协议解析器留 TODO）
//! - [`stats`] — `SizeStatWriter` / `SizeStatReader` 字节计数包装
//! - [`error`] — `DispatcherError` 错误类型
//!
//! IO 边界（trait + NotImplemented 占位）：
//! - [`default`] — `DefaultDispatcher`、`DispatchHandler`/`OutboundHandlerManager`/`RoutingRouter`
//!   trait。完整 `Dispatch`/`DispatchLink` 流程依赖 transport 全链路，主体留 TODO
//! - [`fakednssniffer`] — `FakeDnsEngine` trait、`FakeDnsSnifferFactory` 占位
//!
//! ## 关键决策（详见 docs/translation-conventions.md §10）
//!
//! 1. 不实现 `xray_features::routing::Router`：API 简化（`(dest, session) -> tag`），
//!    Go 的 `routing.Context` 含 source IP/user/protocol 等丰富字段。crate 内部定义
//!    独立 `RoutingContext` trait 保持语义
//! 2. 协议嗅探器（HTTP/TLS/BitTorrent/QUIC/UTP）全 trait + NotImplemented stub
//! 3. 不直接依赖 xray-app-dns / xray-app-router，避免循环依赖，trait 在本 crate 定义

pub mod config;
pub mod default;
pub mod error;
pub mod dnssniffer;
pub mod fakednssniffer;
pub mod endpoint_override;
pub mod sniffer;
pub mod stats;
pub mod udp_session;

pub use config::{Config, SessionConfig};
pub use default::{
    AccessContext, AccessLogEntry, AccessLogSink, CachedReader, DefaultDispatcher, DialBridge,
    DispatchHandler, DispatcherContext, OutboundHandlerManager, RoutingContext, RoutingRouter,
    SimpleOhm,
};
pub use error::DispatcherError;
pub use udp_session::UdpDispatchSession;
pub use fakednssniffer::{
    DnsThenOthersSniffResult, FakeDnsEngine, FakeDnsSniffResult, FakeDnsSnifferFactory,
};
pub use sniffer::{
    CompositeSniffResult, ProtocolSniffer, SniffError, SniffResult, Sniffer,
    SnifferResultComposite, SnifferIsProtoSubsetOf,
};
pub use stats::{SizeStatReader, SizeStatWriter, maybe_wrap_reader, maybe_wrap_writer};
