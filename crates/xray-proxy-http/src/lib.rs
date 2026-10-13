#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-proxy-http
//!
//! HTTP 代理协议——RFC 7230 CONNECT 隧道 + 普通 HTTP 代理模式。
//! 对应 Go `proxy/http/`。
//!
//! ## 切片边界（P6-5 49t 切片1）
//!
//! 实现配置层 + 账户认证纯函数：
//! - [`config::Account`] — 账户 + `equals` 比较 + proto 双向
//! - [`config::ServerConfig`] — 服务端配置 + `has_account` 认证校验 + proto 双向
//! - [`config::ClientConfig`] — 客户端配置（上游服务器 + 自定义 header）+ proto 双向
//! - [`config::Header`] — 自定义 header
//!
//! 切片2 待办：`client.go`（HTTP CONNECT 请求构造 + Proxy-Authorization）+
//! `server.go`（HTTP 请求解析 + 认证 + CONNECT 隧道建立 + 透明代理）。

pub mod client;
pub mod config;
pub mod error;
pub mod server;

// 顶层 re-export。
pub use client::{HttpOutboundConfig, make_http_dial_fn, parse_http_config};
pub use config::{Account, ClientConfig, Header, ServerConfig};
pub use error::{HttpProxyError, Result};
pub use server::HttpServer;
