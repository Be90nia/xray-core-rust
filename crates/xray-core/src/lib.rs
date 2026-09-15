//! # xray-core
//!
//! Xray 核心实例与 Feature 注册中心，对应 Go `core/` 包。
//!
//! ## 切片边界（P7-2 切片1）
//!
//! 本 crate 实现 Feature 注册容器 + 生命周期管理 + 上下文传递 + 版本声明。
//! **不实现**：完整 `New(config)` 初始化路径、Go 反射式 DI resolution、
//! essential defaults 自动注入、`Dial`/`DialUDP` 网络分发——这些依赖各
//! `xray-app-*` 与 `xray-transport` 完成翻译，留待切片2。
//!
//! ## 与 Go 差异
//!
//! - **DI**：Go 用 `reflect.TypeOf(callback).NumIn()` 扫描回调参数注入 features。
//!   Rust 不自然，改用显式 `instance.get_feature::<T>()` API（编译期类型安全）。
//! - **Context**：Go 用 `context.Context` 携带 `*Instance`。Rust 用 [`tokio::task_local`]
//!   线程局部变量 + 显式 `Arc<Instance>` 参数双轨制。
//! - **Feature 标识**：Go 用占位指针 `Type() interface{}`。Rust 用 [`TypeId`](std::any::TypeId)。
//!
//! ## 快速上手
//!
//! ```no_run
//! use std::sync::Arc;
//! use xray_core::{Instance, Feature};
//! use xray_features::Feature as _;
//!
//! struct MyFeature;
//! impl Feature for MyFeature {}
//!
//! let mut instance = Instance::new();
//! instance.add_feature(Arc::new(MyFeature)).unwrap();
//! assert!(instance.has_feature::<MyFeature>());
//! instance.start().unwrap();
//! instance.close().unwrap();
//! ```

pub mod config;
pub mod grpc_server;
pub mod context;
pub mod functions;
pub mod instance;
pub mod outbound;
pub mod register;
pub mod router;
pub mod inbound;
pub mod wiring;
pub mod version;

// 顶层 re-export：常用类型直接从 crate 根访问。
pub use instance::Instance;
pub use version::{version, version_statement, VERSION_X, VERSION_Y, VERSION_Z};

// 从 xray-features re-export Feature trait，让下游无需直接依赖 xray-features
// 即可定义自己的 Feature 实现。
pub use xray_features::{Feature, FeatureError};

pub use functions::{start_from_built, start_full, start_instance, CoreFunctionError};
pub use register::register_all_features;
pub use register::register_all_transports;
