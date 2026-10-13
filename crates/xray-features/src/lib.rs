#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-features
//!
//! Feature trait 定义 + 各功能域 trait 抽象（dns / routing / inbound /
//! outbound / policy / stats / extension），对应 Go `features/` 包。
//!
//! 所有 trait 都是 `Send + Sync`，约定 Xray 多线程运行时安全共享。

// async-trait 展开对每个脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

pub mod dns;
pub mod extension;
pub mod feature;
pub mod inbound;
pub mod outbound;
pub mod policy;
pub mod registry;
pub mod routing;
pub mod stats;

// 顶层 re-export：Feature trait + 全局工厂注册表。
pub use feature::{Feature, FeatureError, Result};
pub use registry::{FeatureFactory, create_feature, is_registered, register_feature};

pub mod deps;
pub use deps::{DepBag, OutboundTagSelector};
