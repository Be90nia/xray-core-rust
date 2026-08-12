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
//! Go 的 `ForSystem()` 返回 `features/policy.System`，Rust 端未提供该类型，
//! 故本 crate 定义本地 [`SystemStats`] 表达同一概念。

pub mod convert;
pub mod feature;
pub mod manager;

pub use convert::{policy_from_proto, system_stats_from_proto, SystemStats};
pub use feature::PolicyFeature;
pub use manager::{Manager, ManagerError};
pub use xray_proto::xray::app::policy::{Config, Policy as ProtoPolicy, Second, SystemPolicy as ProtoSystemPolicy};
