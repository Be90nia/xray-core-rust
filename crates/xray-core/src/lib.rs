#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 同 lint 的级别属性后者覆盖前者：warn 必须在前，test 豁免 allow 才能在测试目标生效
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
// 测试目标统一豁免（print 宏断言便利 + 测试计时夹具裸时钟不得改语义），生产禁令不受影响
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
//! - **DI**：Go 用 `reflect.TypeOf(callback).NumIn()` 扫描回调参数注入 features。 Rust
//!   不自然，改用显式 `instance.get_feature::<T>()` API（编译期类型安全）。
//! - **Context**：Go 用 `context.Context` 携带 `*Instance`。Rust 用 [`tokio::task_local`]
//!   线程局部变量 + 显式 `Arc<Instance>` 参数双轨制。
//! - **Feature 标识**：Go 用占位指针 `Type() interface{}`。Rust 用 [`TypeId`](std::any::TypeId)。
//!
//! ## 快速上手
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use xray_core::{Feature, Instance};
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

// T4.2 五阶段法 phase 1：协议臂构造函数（inbound/outbound match 臂抽取件）。
mod arm_builders;
// W1-1a：生产装配主路的构造器注册表（xray-frame PluginRegistry 承载 arm 构造器）。
pub(crate) mod arm_registry;
pub mod config;
pub mod context;
// W1-1b：Instance::start 启动编排桥（feature 门 `shutdown-coordinator`，默认开；
// 关=旧注册序循环）。与 shutdown_bridge 同门：框架编排路径的开/关。
#[cfg(feature = "shutdown-coordinator")]
mod feature_framework;
pub mod functions;
pub mod grpc_server;
pub mod inbound;
pub mod instance;
pub mod outbound;
pub mod register;
// T1.1：Instance::close 停机编排桥（feature 门 `shutdown-coordinator`，默认开；关=旧逆序循环）。
pub mod router;
#[cfg(feature = "shutdown-coordinator")]
mod shutdown_bridge;
// P3-2 对拍测试（cfg(test)）：旧解析面 vs 插件 build 管线逐字段相等。
#[cfg(test)]
mod tests_config_parity;
pub mod version;
pub mod wiring;

// 顶层 re-export：常用类型直接从 crate 根访问。
pub use functions::{CoreFunctionError, start_from_built, start_full, start_instance};
pub use instance::Instance;
pub use register::{register_all_features, register_all_transports};
pub use version::{VERSION_X, VERSION_Y, VERSION_Z, version, version_statement};
// 从 xray-features re-export Feature trait，让下游无需直接依赖 xray-features
// 即可定义自己的 Feature 实现。
pub use xray_features::{Feature, FeatureError};
