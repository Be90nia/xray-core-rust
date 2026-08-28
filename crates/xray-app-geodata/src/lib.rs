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
pub mod swap;
pub use config::{GeodataAsset, GeodataConfig};
pub use downloader::{
    download_assets, reload_with_update, AssetDownloader, DefaultAssetDownloader,
    GeodataReloader, NoopReloader,
};
pub use error::{at_error, at_warning, GeodataError};
pub use feature::GeodataFeature;
pub use instance::{
    GeodataInstance, NoopScheduler, ScheduleHandle, Scheduler,
};
