//! 版本应用服务
//!
//! 对应 Go 版本 [`app/version`](https://github.com/XTLS/Xray-core/tree/main/app/version)，
//! 提供基于点分十进制版本字符串的核心版本兼容性检查。
//!
//! # 作用
//!
//! Xray 配置可以指定 `min_version` / `max_version` 约束运行核心版本，
//! 防止在不兼容的核心版本上启动。
//!
//! # 用法
//!
//! ```
//! use xray_app_version::{Config, Version};
//!
//! let cfg = Config {
//!     core_version: "1.8.0".into(),
//!     min_version: "1.8.0".into(),
//!     max_version: String::new(),
//! };
//! let _v = Version::new(cfg).expect("version constraints satisfied");
//! ```

pub mod version;

pub use version::{Version, VersionError, compare_versions};
pub use xray_proto::xray::app::version::Config;
