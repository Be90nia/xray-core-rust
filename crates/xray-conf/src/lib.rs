//! # xray-conf
//!
//! Xray 配置文件解析，对应 Go `infra/conf` + `main/confloader`。
//!
//! 支持 JSON / YAML / TOML 三种格式的配置文件解析，提供格式自动识别与文件加载。
//!
//! ## 设计差异（vs Go）
//!
//! Go 用 `JSONConfigLoader` 注册制 + `json.RawMessage` 处理协议特定 settings。
//! Rust 利用 serde derive + [`serde_json::Value`] 占位，大幅简化代码：
//!
//! - **enum 替代注册制**：协议分发未来用 `#[serde(tag = "protocol", content = "settings")]`
//!   tagged enum，无需 `RegisterCreator` map。
//! - **serde derive 替代手写 UnmarshalJSON**：PortList 的 `number/string/array` 多态
//!   通过自定义 `Deserialize` impl 表达，集中在一处。
//! - **切片策略**：当前协议 settings 用 [`serde_json::Value`] 占位，
//!   待各 `xray-proxy-*` crate 完成后逐步替换为强类型字段。
//!
//! ## 快速上手
//!
//! ```
//! use xray_conf::{Config, Format, load_str};
//!
//! let json = r#"{ "inbounds": [{ "protocol": "vless", "port": 443, "tag": "in" }] }"#;
//! let cfg: Config = load_str(Format::Json, json).unwrap();
//! assert_eq!(cfg.inbound_count(), 1);
//! ```
pub mod built;
pub mod app_config;
pub mod common;
pub mod confloader;
pub mod config;
pub mod error;
pub mod init;
pub mod json;
pub mod serial;
pub mod lint;
pub mod toml_config;
pub mod vformat;
pub mod yaml;

// 顶层 re-export：常用类型与函数直接从 crate 根访问。
pub use common::{Address, Int32Range, Network, NetworkList, PortList, PortRange, StringList, User};
pub use config::{Config, InboundDetourConfig, MuxConfig, OutboundDetourConfig, SniffingConfig};
pub use built::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
pub use serial::{build_config, merge_config_from_files, merge_configs};
pub use confloader::{
    load_file, load_file_with_format, load_reader, load_str, load_str_auto_detect,
};
pub use error::{ConfError, Result};
pub use vformat::Format;
