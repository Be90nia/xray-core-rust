#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 断言便利）；spawn 走 xray_common::testing（L3
// 闸不豁免），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-proxy-dokodemo
//!
//! Dokodemo-door 入站代理——把所有连接重定向到固定目标地址，或跟随 iptables
//! REDIRECT 的原始目标地址（透明代理）。对应 Go `proxy/dokodemo/`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! - [`config::Config`] + `predefined_address`/`allows_network` + Network 枚举 + prost 双向
//! - [`server::DokodemoServer`] + `impl InboundHandler`（start/accept/close lifecycle）
//! - [`fakeudp::fake_udp`]：TPROXY 伪造源地址 UDP（Linux；非 Linux 返回错误）

pub mod config;
pub mod error;
pub mod fakeudp;
pub mod outbound;
pub mod plugin;
pub mod server;

// 顶层 re-export。
pub use config::{Config, Network, PredefinedAddress};
pub use error::{DokodemoError, Result};
pub use outbound::{DokodemoOutboundConfig, make_dokodemo_dial_fn};
pub use plugin::{DokodemoLifecycle, DokodemoPlugin};
pub use server::DokodemoServer;
