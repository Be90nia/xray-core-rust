#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-log crate.
//!
//! 对应 Go `app/log/`：日志实例 + Handler 注册机制 + IP 掩码处理。
//!
//! ## IO 边界
//!
//! 以下通过 trait 注入实现，本 crate 不绑定具体日志后端：
//! - 实际写日志：[`instance::LogHandler`] trait（由 console/file 实现提供）
//! - Handler 工厂：[`instance::HandlerCreator`] trait + [`instance::HandlerCreatorRegistry`]
//! - gRPC server：[`command::LogServiceRegistrar`] trait
//!
//! ## 核心业务
//!
//! - [`mask::parse_mask_address`] + [`mask::mask_addresses`]：纯逻辑可独立测试
//! - [`instance::LogInstance`]：消息分发编排（access / dns / general）

pub mod command;
pub mod config;
pub mod error;
pub mod feature;
pub mod instance;
pub mod mask;

pub use command::{
    DefaultLogService, LogService, LogServiceDescriptor, LogServiceRegistrar,
    NoopLogServiceRegistrar,
};
pub use config::{LogConfig, LogFormat, LogType, SeverityLevel};
pub use error::{LogError, at_error, at_warning};
pub use feature::LogFeature;
pub use instance::{
    AccessMessage, AccessStatus, ConsoleHandler, ConsoleHandlerCreator, DnsLog, DnsStatus,
    FileHandler, FileHandlerCreator, GeneralMessage, HandlerCreator, HandlerCreatorOptions,
    HandlerCreatorRegistry, LogEntry, LogHandler, LogInstance, MaskingHandler, NoneHandlerCreator,
    register_default_creators,
};
pub use mask::{mask_addresses, parse_mask_address};
