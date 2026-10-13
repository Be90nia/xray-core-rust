#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! DNS 应用服务。
//!
//! 对应 Go `app/dns/`。业务核心（数据结构/缓存/hosts/fakedns）独立可测；
//! IO 边界（实际 DNS 查询、transport dial）留 trait + 工厂占位，等生态成熟。

pub mod cache_controller;
pub mod config;
pub mod dial;
pub mod dnscommon;
pub mod error;
pub mod fakedns;
pub mod hosts;
pub mod jsonconf;
pub mod nameserver;
pub mod server;

// 重导出顶层 API，便于上层直接 `use xray_app_dns::DnsService`。
pub use jsonconf::DnsAppConfig;
pub use server::{DnsService, DomainMatcherInfo, check_routes};
