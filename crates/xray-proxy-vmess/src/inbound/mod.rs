//! VMess inbound 处理器。
//!
//! 对应 Go 版本 `proxy/vmess/inbound/inbound.go`。
//! - `server::serve_vmess`：完整 inbound 入口（accept → decode header → body chunk pump →
//!   dispatch）
//! - `handler::InboundHandler`：trait 注入式 handler（保留兼容，processor 默认 Noop）

pub mod handler;
pub mod server;

pub use handler::{InboundHandler, InboundProcessor, NoopInboundProcessor};
pub use server::serve_vmess;
