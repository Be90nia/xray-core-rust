#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-transport-splithttp
//!
//! SplitHTTP 传输协议——基于 HTTP/2 多路复用的分包传输，Xray 最复杂的 transport。
//! 对应 Go `transport/internet/splithttp/`。
//!
//! ## 协议本质
//!
//! SplitHTTP 通过 HTTP POST 上传分包 + SSE/HTTP 下载流，绕过 CDN/中间设备对
//! WebSocket 的限制。支持 `packet-up` / `stream-up` / `stream-one` 三种模式，配合
//! `xmux` 多路复用、X-Padding 混淆、多种 Placement 策略（path/query/header/cookie/body）
//! 实现高度可配置性。
//!
//! ## 切片边界（P5-3 切片1）
//!
//! 实现配置层 + 所有 `GetNormalized*` 纯函数方法（默认值推断 + Placement 依赖判定）：
//! - [`config::Config`] — 28 字段配置 + `from_proto`/`to_proto` prost 双向
//! - [`config::RangeConfig`] / [`config::XmuxConfig`] — 范围采样 + 多路复用调优
//! - 7 种 `PLACEMENT_*` 常量
//! - `normalized_path`/`query`/`uplink_http_method`/`sc_*`/`uplink_chunk_size`/
//!   `session_*`/`seq_*`/`server_max_header_bytes` 等纯函数方法
//!
//! 切片2（已实现，依赖 `http::Request` / `XPadding` / 实际网络栈）：
//! `WriteResponseHeader`（`Config::write_response_header`）/
//! `ApplyMetaToRequest`（`Config::apply_meta_to_uri`）/
//! `FillStreamRequest`（`Config::build_stream_request_meta`）/
//! `FillPacketRequest`（`Config::build_packet_request_meta`）/
//! `ExtractMetaFromRequest`（`hub::meta::extract_meta`）+
//! 实际 HTTP 拨号（H1/H2 + H3）+ SSE 流 + upload_queue + xmux 连接池骨架。

// 数据面分配纪律（P0 护栏，见本 crate clippy.toml）：测试编译单元统一豁免，
// 断言扁平化属测试便利；生产代码禁令不受影响。
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod batched_upload;
pub mod browser_client;
pub mod client;
pub mod config;
pub mod connection;
pub mod dialer;
pub mod error;
pub mod h1_conn;
pub mod h3_client;
pub mod hub;
pub mod mux;
pub mod register;
pub mod transport;
pub mod upload_queue;
pub mod xpadding;

// 顶层 re-export。
pub use config::{Config, RangeConfig, XmuxConfig};
// Placement 常量顶层 re-export，方便下游直接 `use xray_transport_splithttp::PLACEMENT_PATH`。
pub use config::{
    PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH,
    PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER,
};
pub use error::{Result, SplitHttpError};
pub use register::{register_dialer, register_listener};
pub use upload_queue::{Packet, UploadQueue};
