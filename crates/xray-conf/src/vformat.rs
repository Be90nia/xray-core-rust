//! 配置格式识别与派发。
//!
//! 对应 Go `main/confloader` 中按扩展名/内容识别格式的逻辑。
//! 提供三种格式（JSON/YAML/TOML）的统一入口。

use std::{io::Read, path::Path};

use crate::{config::Config, error::Result};

/// 支持的配置文件格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
    Toml,
}

impl Format {
    /// 按文件扩展名识别（不区分大小写，接受带或不带前导 `.`）。
    ///
    /// ```
    /// use xray_conf::vformat::Format;
    /// assert_eq!(Format::from_extension("json"), Some(Format::Json));
    /// assert_eq!(Format::from_extension(".YAML"), Some(Format::Yaml));
    /// assert_eq!(Format::from_extension("unknown"), None);
    /// ```
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().trim_start_matches('.') {
            "json" | "jsonc" | "json5" => Some(Format::Json),
            "yaml" | "yml" => Some(Format::Yaml),
            "toml" => Some(Format::Toml),
            _ => None,
        }
    }

    /// 按路径扩展名识别。
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension().and_then(|e| e.to_str()).and_then(Self::from_extension)
    }

    /// 按内容首字节粗略识别（魔数探测）。
    ///
    /// 启发式规则：
    /// - `---` / `%YAML` 开头 → YAML 文档
    /// - `{` / `[` 开头 → JSON
    /// - 首行含 ` = ` 且非 `{` 开头 → TOML
    /// - 否则返回 `None`（调用方需指定格式或报错）
    pub fn detect(content: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(content).ok()?.trim_start();
        if s.starts_with("---") || s.starts_with('%') {
            return Some(Format::Yaml);
        }
        if s.starts_with('{') || s.starts_with('[') {
            return Some(Format::Json);
        }
        // TOML 启发：首行像 key = value
        if s.lines()
            .next()
            .map(|line| line.contains(" = ") && !line.starts_with('{'))
            .unwrap_or(false)
        {
            return Some(Format::Toml);
        }
        None
    }

    /// 格式名（小写字符串，用于错误信息）。
    pub const fn name(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Yaml => "yaml",
            Format::Toml => "toml",
        }
    }

    /// 按格式派发到对应解码器。
    pub fn decode<R: Read>(self, reader: R) -> Result<Config> {
        match self {
            Format::Json => crate::json::decode_json(reader),
            Format::Yaml => crate::yaml::decode_yaml(reader),
            Format::Toml => crate::toml_config::decode_toml(reader),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_recognition_case_insensitive() {
        assert_eq!(Format::from_extension("JSON"), Some(Format::Json));
        assert_eq!(Format::from_extension(".yaml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("TOML"), Some(Format::Toml));
        assert_eq!(Format::from_extension("yml"), Some(Format::Yaml));
        assert_eq!(Format::from_extension("jsonc"), Some(Format::Json));
        assert_eq!(Format::from_extension(""), None);
        assert_eq!(Format::from_extension("xml"), None);
    }

    #[test]
    fn detect_json_by_brace() {
        assert_eq!(Format::detect(b"{ \"a\": 1 }"), Some(Format::Json));
        assert_eq!(Format::detect(b"  [{\"x\":2}]"), Some(Format::Json));
    }

    #[test]
    fn detect_yaml_by_marker() {
        assert_eq!(Format::detect(b"---\ninbounds: []"), Some(Format::Yaml));
        assert_eq!(Format::detect(b"%YAML 1.2"), Some(Format::Yaml));
    }

    #[test]
    fn detect_toml_by_key_value() {
        assert_eq!(Format::detect(b"key = \"value\"\n"), Some(Format::Toml));
    }

    #[test]
    fn detect_unknown_returns_none() {
        assert_eq!(Format::detect(b"plain text"), None);
    }

    #[test]
    fn name_returns_lowercase() {
        assert_eq!(Format::Json.name(), "json");
        assert_eq!(Format::Yaml.name(), "yaml");
        assert_eq!(Format::Toml.name(), "toml");
    }

    #[test]
    fn decode_dispatches_correctly() {
        let json = b"{ \"inbounds\": [] }";
        let cfg = Format::Json.decode(json.as_ref()).unwrap();
        assert_eq!(cfg.inbound_count(), 0);

        let yaml = b"inbounds: []\n";
        let cfg = Format::Yaml.decode(yaml.as_ref()).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }
}
