#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! naive+https 出站（naiveproxy 客户端协议移植）。
//!
//! 机制：裸 Chrome 指纹 TLS（btls）+ HTTP/2 CONNECT + `Proxy-Authorization:
//! Basic` 鉴权 + 双向首 8 帧 padding（kVariant1）。Go Xray 无此协议——本
//! crate 为对 naiveproxy / sing-box naive inbound 的互操作实现。
//!
//! - `padding`：帧编解码 + padding 头生成（naiveproxy `NaivePaddingFramer` 移植）
//! - [`uri`]：`naive+https://` 分享链接与 settings JSON 解析
//! - `dial`：TCP → btls TLS → h2 CONNECT → padding 隧道
//! - `dispatcher`：`make_naive_dial_fn`（xray-core 接线）

mod dial;
mod dispatcher;
mod inbound;
mod padding;
pub mod uri;

pub use dial::{NaiveConn, PaddingReader, PaddingWriter, dial_naive};
pub use dispatcher::make_naive_dial_fn;
pub use inbound::{NaiveInboundConfig, NaiveInboundHandler};
pub use uri::{NaiveConfig, parse_naive_uri};
