#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! 策略应用服务
//!
//! 对应 Go 版本 [`app/policy`](https://github.com/XTLS/Xray-core/tree/main/app/policy)，
//! 实现 `features/policy.Manager` trait：按用户 level 查找运行时策略。
//!
//! # 与 Go 版本的差异
//!
//! Rust 端 `xray-features::policy::Policy` 已整合 Go `features/policy.Session` 字段，
//! 故不需要 proto Policy ↔ features.Session 的转换层——这里直接把 proto 字段
//! 合并到默认 `features::Policy` 上（对应 Go `overrideWith`）。
//!
//! `SystemStats` 定义在 `xray-features::policy`，对应 Go `features/policy.SystemStats`，
//! `PolicyManager` trait 的 `for_system()` 返回该类型。

pub mod convert;
pub mod feature;
pub mod manager;

pub use convert::{SystemStats, policy_from_proto, system_stats_from_proto};
pub use feature::PolicyFeature;
pub use manager::{Manager, ManagerError};
pub use xray_proto::xray::app::policy::{
    Config, Policy as ProtoPolicy, Second, SystemPolicy as ProtoSystemPolicy,
};
