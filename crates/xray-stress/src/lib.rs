#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-stress：Xray-core-rust 压测 harness。
//!
//! 独立二进制，只消费现有 crate 公开 API（`xray-core::functions::start_full`、
//! hysteria QUIC loopback、`xray-common::runtime_guard`），不碰生产代码。

pub mod error;
pub mod quic_loop;
pub mod report;
pub mod sampler;
pub mod scenarios;
pub mod topology;
