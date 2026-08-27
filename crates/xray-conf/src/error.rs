//! 配置系统错误类型。
//!
//! 对应 Go `infra/conf` 中的 errors 包装，提供格式/位置感知的错误信息。

use thiserror::Error;

/// 配置处理错误。
#[derive(Error, Debug)]
pub enum ConfError {
    /// 读取文件/流失败。
    #[error("failed to read config: {0}")]
    Read(String),

    /// 解析失败并携带格式与行列位置（serde_json 的 SyntaxError 类）。
    #[error("failed to parse {format} config at line {line} column {column}: {message}")]
    Parse {
        format: &'static str,
        line: usize,
        column: usize,
        message: String,
    },

    /// 解析失败但无精确位置（yaml/toml 或顶层 IO 错误）。
    #[error("failed to parse {format} config: {message}")]
    ParseSimple {
        format: &'static str,
        message: String,
    },

    /// 配置语义非法（如 PortList 为空、协议未知）。
    #[error("invalid config: {0}")]
    Invalid(String),

    /// 不支持的配置格式（无法识别扩展名或魔数）。
    #[error("unsupported config format: {0}")]
    UnsupportedFormat(String),

    /// IO 错误自动转换（`?` 透传）。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 错误自动转换。位置信息通过 [`ConfError::with_position`] 提取。
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML 错误自动转换。
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// TOML 反序列化错误自动转换。
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    /// 使用了已废弃的配置（如全局 transport 字段）。`hint` 给出迁移指引。
    #[error("deprecated config: {feature}; migrate to {hint}")]
    Deprecated { feature: &'static str, hint: &'static str },

    /// 使用了已移除的配置（如顶层 `reverse` 字段）。对应 Go
    /// `common/errors.PrintRemovedFeatureError`，文案与 Go 对齐。
    #[error("The feature {feature} has been removed and migrated to {migrate}. Please update your config(s) according to release note and documentation.")]
    Removed { feature: &'static str, migrate: &'static str },

    /// Build 阶段序列化失败（极少触发，因字段已成功解析）。
    #[error("failed to build {what}: {message}")]
    Build { what: &'static str, message: String },
}

impl ConfError {
    /// 把 serde_json 错误升级为带位置信息的 Parse 错误。
    pub fn from_json(format: &'static str, err: serde_json::Error) -> Self {
        ConfError::Parse {
            format,
            line: err.line(),
            column: err.column(),
            message: err.to_string(),
        }
    }

    /// 包装为 ParseSimple（用于 yaml/toml）。
    pub fn simple(format: &'static str, err: impl std::fmt::Display) -> Self {
        ConfError::ParseSimple {
            format,
            message: err.to_string(),
        }
    }
}

/// crate 级 Result 别名。
pub type Result<T> = std::result::Result<T, ConfError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_format_and_position() {
        let err = ConfError::Parse {
            format: "json",
            line: 5,
            column: 10,
            message: "unexpected token".into(),
        };
        let s = err.to_string();
        assert!(s.contains("json") && s.contains("line 5") && s.contains("column 10"));
    }

    #[test]
    fn from_json_extracts_position() {
        let err = serde_json::from_str::<serde_json::Value>("{ bad }").unwrap_err();
        let wrapped = ConfError::from_json("json", err);
        match wrapped {
            ConfError::Parse { format, line, .. } => {
                assert_eq!(format, "json");
                assert!(line > 0);
            }
            _ => panic!("expected Parse variant"),
        }
    }
}
