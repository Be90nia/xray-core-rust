#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-cli
//!
//! Xray CLI 入口库。对应 Go `main/` 包。
//!
//! ## 切片边界（P7-3 切片1）
//!
//! - [`run`] — `xray run` 命令：配置查找 + 加载 + `-test`/`-dump` 模式
//! - [`version`] — `xray version` 命令：输出版本声明
//! - [`error`] — CLI 错误类型
//!
//! 实际实例启动（`Instance::new(config) + Start`）依赖 P7-2 切片2 的完整
//! `New(config)` 实现，当前返回 [`error::CliError::Unimplemented`]。
//!
//! 切片2 待办：完整 `run` 启动路径 + gRPC client 接入（API 命令真实调用）
//! + 信号处理（SIGINT/SIGTERM）。

pub mod alloc_stats;
pub mod commands;
pub mod distro;
pub mod error;
pub mod run;
pub mod version;

// 顶层 re-export。
pub use error::{CliError, Result};
