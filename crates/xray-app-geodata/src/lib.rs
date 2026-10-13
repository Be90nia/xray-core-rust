#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-geodata crate.
//!
//! 对应 Go `app/geodata/`：cron 调度的 GeoIP/GeoSite 文件下载 + 原子 swap 更新。
//!
//! ## IO 边界
//!
//! - HTTP 下载 + dispatcher dial：[`downloader::AssetDownloader`] trait
//! - GeoIP/Site reload：[`downloader::GeodataReloader`] trait
//! - cron 调度：[`instance::Scheduler`] trait
//!
//! ## 核心业务
//!
//! - [`swap`] 模块：纯文件系统操作（Stage/Swap/Tx/swap_all/clean），可在临时目录完整测试
//! - [`downloader::reload_with_update`]：download → swap → reload → commit/rollback 编排
//! - [`instance::GeodataInstance`]：start/execute/close 生命周期

pub mod config;
pub mod downloader;
pub mod error;
pub mod feature;
pub mod instance;
pub mod scheduler;
pub mod swap;
pub use config::{GeodataAsset, GeodataConfig};
pub use downloader::{
    AssetDownloader, DefaultAssetDownloader, GeodataReloader, NoopReloader, RealAssetDownloader,
    download_assets, reload_with_update,
};
pub use error::{GeodataError, at_error, at_warning};
pub use feature::GeodataFeature;
pub use instance::{GeodataInstance, NoopScheduler, ScheduleHandle, Scheduler};
pub use scheduler::CronScheduler;
