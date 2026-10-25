#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 断言便利）；spawn 走 xray_common::testing（L3
// 闸不豁免），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! Blackhole 代理协议
//!
//! 对应 Go 版本 [`proxy/blackhole`](https://github.com/XTLS/Xray-core/tree/main/proxy/blackhole)：
//! 一种出站处理器，静默吞掉整个连接的有效载荷，可选择向客户端回写一份预设响应。
//!
//! # 当前实现范围
//!
//! 完整翻译 Go 版本的响应配置（`ResponseConfig`：none / http / custom 自定义数据，
//! 对应 Go 01a034be）与 `Handler::new`。`Handler::process` 接受任意
//! [`xray_buf::io::Writer`]，写出预设响应。
//!
//! Go 版本 `Process` 还涉及 `transport.Link`/`internet.Dialer`/`session`/`signal` 的交互，
//! 这些类型在 Rust 端尚未实现（dev-plan "动态分层" 原则）。等 `xray-transport` 提供
//! 等价的 `Link` 与 `Dialer` 后，可在 `Handler` 之上加一层 adapter 对接 `OutboundHandler` trait.

pub mod dispatcher;
pub mod handler;
pub mod inbound;
// P1-7 插件化（五层强约束首个实证件）：BlackholePlugin + BlackholeLifecycle。
pub mod plugin;
pub mod response;

pub use dispatcher::{BlackholeHandler, make_blackhole_handler};
pub use handler::{BlackholeError, Handler};
pub use inbound::BlackholeInboundHandler;
pub use plugin::{BlackholeLifecycle, BlackholePlugin};
pub use response::{ResponseConfig, get_internal_response, proto_response};
pub use xray_proto::xray::proxy::blackhole::{Config, Response};
