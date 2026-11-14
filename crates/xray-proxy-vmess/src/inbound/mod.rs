//! VMess inbound 处理器。
//!
//! 对应 Go 版本 `proxy/vmess/inbound/inbound.go`。
//! - `server::serve_vmess`：完整 inbound 入口（accept → decode header → body chunk pump →
//!   dispatch）

pub mod server;

pub(crate) mod chunk_stream;

pub use server::serve_vmess;
