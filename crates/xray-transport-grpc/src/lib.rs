//! # xray-transport-grpc
//!
//! gRPC 传输协议——基于 HTTP/2 + protobuf framing 的双向 stream。
//! 对应 Go `transport/internet/grpc/`。
//!
//! ## 协议本质
//!
//! gRPC 走 HTTP/2 多路复用 stream，每个 TCP 连接可承载多个 gRPC stream，
//! Xray 利用此特性实现 multi_mode（每连接多 stream 提升吞吐）。底层
//! 用 google.golang.org/grpc 标准库的 Tun/TunMulti 服务，把 net.Conn 适配为
//! gRPC 双向 stream。
//!
//! ## 切片边界（P5-4 切片1）
//!
//! 仅实现配置层 + 服务名解析逻辑（纯字符串处理，独立可测）：
//! - [`config::Config`] — 8 字段配置 + `service_name`/`tun_stream_name`/
//!   `tun_multi_stream_name` 解析 + prost proto 双向转换
//! - [`config::path_escape`] — URL path percent-escape（对应 Go `url.PathEscape`）
//!
//! 切片2 待办：`dial`（依赖 tonic/h2 替代 google.golang.org/grpc）+
//! `hub`（grpc.Server）+ `encoding`（HunkConn/MultiHunkConn 适配 net.Conn）+
//! User-Agent 反射 hack（Rust 端改用 tonic interceptor）。

pub mod config;
pub mod error;
pub mod client;
pub mod server;

// 顶层 re-export。
pub use config::Config;
pub use error::{GrpcError, Result};
