//! # xray-features
//!
//! Feature trait 定义 + 各功能域 trait 抽象（dns / routing / inbound /
//! outbound / policy / stats / extension），对应 Go `features/` 包。
//!
//! 所有 trait 都是 `Send + Sync`，约定 Xray 多线程运行时安全共享。

pub mod dns;
pub mod routing;
pub mod inbound;
pub mod outbound;
pub mod policy;
pub mod stats;
pub mod extension;
pub mod feature;
pub mod registry;

// 顶层 re-export：Feature trait + 全局工厂注册表。
pub use feature::{Feature, FeatureError, Result};
pub use registry::{create_feature, is_registered, register_feature, FeatureFactory};

pub mod deps;
pub use deps::{DepBag, OutboundTagSelector};
