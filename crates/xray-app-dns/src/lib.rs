//! DNS 应用服务。
//!
//! 对应 Go `app/dns/`。业务核心（数据结构/缓存/hosts/fakedns）独立可测；
//! IO 边界（实际 DNS 查询、transport dial）留 trait + 工厂占位，等生态成熟。

pub mod error;
pub mod config;
pub mod dnscommon;
pub mod hosts;
pub mod cache_controller;
pub mod fakedns;
pub mod nameserver;
pub mod server;
pub mod jsonconf;

// 重导出顶层 API，便于上层直接 `use xray_app_dns::DnsService`。
pub use jsonconf::DnsAppConfig;
pub use server::{DnsService, DomainMatcherInfo, check_routes};
