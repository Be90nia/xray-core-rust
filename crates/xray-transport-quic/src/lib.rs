#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-transport-quic
//!
//! QUIC 传输协议——基于 quinn（rustls + ring）的双向 stream。
//! 对应 Go `transport/internet/quic/`。
//!
//! 本 crate 提供最小可用的 QUIC transport：
//! - [`transport::dial`] — 主动拨号：绑定本地 UDP socket → quinn connect → open_bi → duplex 桥接
//! - [`transport::listen`] — 监听：绑定 UDP socket → spawn accept loop → accept_bi → duplex 桥接
//! - [`register::register_dialer`] / [`register::register_listener`] — 注册到全局 transport
//!   注册表（协议名 `"quic"`）
//!
//! 配置仅消费 TLS 层（[`xray_tls::client_config`] / [`xray_tls::server_config`]），
//! quicSettings 的 KeepAlive / 拥塞控制等参数留 follow-up。

/// T3.2a 日志统一入口：域规范 target = `xray_frame::transport::quic`（热路径豁免清单见
/// reports/framework-audit-2026-10-24/T3.2a-log-transport-cli.md）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("transport::quic", vec![]));

pub mod config;
pub mod congestion_swappable;
pub mod register;
pub mod transport;
mod udp_gso;

pub use config::QuicConfig;
