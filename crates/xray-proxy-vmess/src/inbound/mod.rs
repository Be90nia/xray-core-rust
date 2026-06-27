//! VMess inbound 处理器。
//!
//! 对应 Go 版本 `proxy/vmess/inbound/inbound.go`。
//! 主入口 `Process` 依赖 `transport::Link` + `dispatcher` + `buf.BufferedReader` 全链路，
//! 当前留 trait + stub。

pub mod handler;

pub use handler::{InboundHandler, InboundProcessor, NoopInboundProcessor};
