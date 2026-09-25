//! 配置格式注册表与加载入口，对应 Go `core/config.go`。
//!
//! ## 切片边界（P7-2 切片1）
//!
//! Go 端用 `map[string]*ConfigFormat` 注册制承载 JSON/YAML/TOML/Protobuf 多格式
//! loader，因为这些 loader 分散在不同 init() 中通过 import 副作用注册。
//!
//! Rust 端 [`xray_conf::Format`] 枚举已直接覆盖 JSON/YAML/TOML；Protobuf 加载
//! 在切片1 暂不实现（依赖 prost-build 完整 `core.Config` proto 定义）。
//!
//! 本模块提供：
//!
//! - [`get_format_by_extension`] —— 扩展名到格式名识别（与 Go API 一致）。
//! - [`ConfigSource`] —— CLI 入口路径与格式元组（供 P7-3 CLI 使用）。
//! - [`load_config`] —— 从 [`ConfigSource`] 加载 [`xray_conf::Config`]。
//!
//! 切片2 会加入 Protobuf 格式 + `Config → Instance` 完整 Build 路径。

use std::path::Path;

use thiserror::Error;
use xray_conf::{Config, Format, load_file_with_format};

/// 配置来源：路径 + 格式。供 CLI/批量加载使用。对应 Go `core.ConfigSource`。
#[derive(Debug, Clone)]
pub struct ConfigSource {
    /// 文件路径或 `"stdin:"` 特殊标记。
    pub name: String,
    /// 配置格式（`"json"` / `"yaml"` / `"toml"`）。
    pub format: String,
}

/// 配置加载错误。
#[derive(Debug, Error)]
pub enum ConfigLoadError {
    /// 文件 IO 错误。
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// 配置解析错误（透传 [`xray_conf::ConfError`]）。
    #[error("config parse error: {0}")]
    Parse(#[from] xray_conf::ConfError),

    /// 不支持的格式。
    #[error("unsupported config format: {0}")]
    UnsupportedFormat(String),
}

/// 按文件扩展名识别配置格式。返回 `"json"`/`"yaml"`/`"toml"`/`""`。
///
/// 对应 Go `GetFormatByExtension`，大小写不敏感。
pub fn get_format_by_extension(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "json" | "jsonc" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        // protobuf 留切片2（依赖完整 core.Config proto + prost-build）。
        _ => "",
    }
}

/// 从文件路径提取扩展名。无扩展名返回空串。对应 Go `getExtension`。
fn extension_of(filename: &str) -> &str {
    match filename.rfind('.') {
        Some(idx) => &filename[idx + 1..],
        None => "",
    }
}

/// 根据文件路径推断格式名。对应 Go `GetFormat`。
pub fn get_format(filename: &str) -> &'static str {
    get_format_by_extension(extension_of(filename))
}

/// 把格式名映射到 [`xray_conf::Format`] 枚举。
pub fn format_from_name(name: &str) -> Option<Format> {
    match name.to_ascii_lowercase().as_str() {
        "json" => Some(Format::Json),
        "yaml" | "yml" => Some(Format::Yaml),
        "toml" => Some(Format::Toml),
        _ => None,
    }
}

/// 从 [`ConfigSource`] 加载 [`Config`]。
///
/// 切片1 仅支持本地文件路径加载（不支持 `"stdin:"` 特殊标记，留给 P7-3 CLI）。
pub fn load_config(source: &ConfigSource) -> Result<Config, ConfigLoadError> {
    let format = format_from_name(&source.format)
        .ok_or_else(|| ConfigLoadError::UnsupportedFormat(source.format.clone()))?;
    let path = Path::new(&source.name);
    load_file_with_format(path, format).map_err(ConfigLoadError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_recognition() {
        assert_eq!(get_format_by_extension("json"), "json");
        assert_eq!(get_format_by_extension("JSON"), "json");
        assert_eq!(get_format_by_extension("jsonc"), "json");
        assert_eq!(get_format_by_extension("yaml"), "yaml");
        assert_eq!(get_format_by_extension("YML"), "yaml");
        assert_eq!(get_format_by_extension("toml"), "toml");
        assert_eq!(get_format_by_extension("pb"), "");
        assert_eq!(get_format_by_extension("unknown"), "");
    }

    #[test]
    fn get_format_from_filename() {
        assert_eq!(get_format("/etc/xray/config.json"), "json");
        assert_eq!(get_format("config.yaml"), "yaml");
        assert_eq!(get_format("config.yml"), "yaml");
        assert_eq!(get_format("conf.toml"), "toml");
        assert_eq!(get_format("noext"), "");
    }

    #[test]
    fn format_from_name_roundtrip() {
        assert_eq!(format_from_name("json"), Some(Format::Json));
        assert_eq!(format_from_name("YAML"), Some(Format::Yaml));
        assert_eq!(format_from_name("yml"), Some(Format::Yaml));
        assert_eq!(format_from_name("toml"), Some(Format::Toml));
        assert_eq!(format_from_name("protobuf"), None);
    }

    #[test]
    fn load_unsupported_format_errors() {
        let src = ConfigSource { name: "x.pb".into(), format: "protobuf".into() };
        let err = load_config(&src).unwrap_err();
        assert!(matches!(err, ConfigLoadError::UnsupportedFormat(_)));
    }

    #[test]
    fn load_missing_file_errors() {
        let src = ConfigSource { name: "/nonexistent/x.json".into(), format: "json".into() };
        let err = load_config(&src).unwrap_err();
        // 实际是 ConfError::Io 包装。
        assert!(matches!(err, ConfigLoadError::Parse(_)));
    }
}
