//! VMess outbound 处理器。
//!
//! 对应 Go 版本 `proxy/vmess/outbound/outbound.go`。主入口 `Process` 依赖
//! `transport::Link` + `retry` + `signal` + `internet::Dialer` 全链路，留 trait + stub。

pub mod handler;

pub use handler::{NoopOutboundProcessor, OutboundHandler, OutboundProcessor};
