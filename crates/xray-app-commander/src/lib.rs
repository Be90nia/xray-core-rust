#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言 + 测试内裸 spawn 自管 runtime，bd g3cr 家规扩展；生产禁令不受影响）
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-commander：gRPC 命令注册中心。
//!
//! 对应 Go `app/commander/`：
//! - `commander.go` → [`commander::Commander`]（service 容器 + 配置载体）
//! - `service.go` → [`commander::Service`] trait + [`commander::ReflectionService`]
//! - `outbound.go` → [`outbound::OutboundListener`] / `outbound::OutboundHandler` trait stub（依赖
//!   transport 全链路）
//! - `config.proto` → [`commander::Config`] + [`commander::TypedMessageConfig`]
//!
//! ## IO 边界范围（与 P4-4 proxyman / P4-7 stats 一致）
//!
//! - **业务核心**：Service 元数据 + Commander 容器 + 配置载体，完全独立可测
//! - **gRPC server 注册留 trait**：[`commander::GrpcServerRegistrar`] trait 由 上层（`xray-core`
//!   main）注入实现（封装 tonic `ServerBuilder`）
//! - **Outbound listener / handler 留 trait stub**：依赖 `xray_transport::Link`
//!   + cnc 等价物，当前阶段仅定义 trait + [`outbound::StubOutboundHandler`] 占位
//! - **TypedMessage 解码由上层负责**：Go 用全局 `common.RegisterConfig` 注册表 +
//!   `rawConfig.GetInstance()`；Rust 端无副作用全局，上层显式创建 Service 实例 后通过
//!   [`commander::Commander::add_service`] 注册
//!
//! ## 关键决策
//!
//! 1. **不引入 tonic**：gRPC server 实例不在 Commander 中持有，由 registrar 实现持有（避免 P4
//!    阶段引入 tonic 生态）
//! 2. **Commander::start_with_registrar 不实际监听**：仅注册 service + 标记 running；TCP/Unix
//!    socket bind + outbound handler register + serve 循环 全部由上层 xray-core 注入完成
//! 3. **TypedMessage 不在 Commander 解码**：上层基于 [`commander::Config::service_configs`] 按
//!    type_url 路由到对应 factory 创建 Service
//! 4. **add_service 去重保护**：相同 type_url 拒绝重复注册（Go 不去重，加更严谨）

pub mod commander;
pub mod error;
pub mod grpc;
pub mod outbound;
pub mod server;
// Re-export 主要公共类型
pub use commander::{
    Commander, Config, DeclaredServiceMarker, GrpcServerRegistrar, HandlerServiceMarker,
    NoopRegistrar, ReflectionService, Service, TypedMessageConfig, api_services,
};
pub use error::CommanderError;
pub use grpc::{LoggerServiceImpl, OutboundRuntime};
pub use outbound::{CommanderConn, OutboundListener, OutboundRegistrar, StubOutboundHandler};
pub use server::{OutboundHandlerImpl, OutboundHandlerRegistry, OutboundListenerImpl};
// Re-export xray-features 的 OutboundHandler（统一 trait 入口）
pub use xray_features::outbound::OutboundHandler;
