//! 配置文件加载器。
//!
//! 对应 Go `main/confloader/*.go`。提供从文件路径、reader、字符串加载配置的高级 API，
//! 自动按扩展名识别格式。

use std::{fs::File, io::Read, path::Path};

use crate::{
    config::Config,
    error::{ConfError, Result},
    vformat::Format,
};

/// 从文件路径加载配置。
///
/// 按扩展名识别格式（`.json` / `.yaml` / `.yml` / `.toml`）。
/// 扩展名无法识别时返回 [`ConfError::UnsupportedFormat`]。
pub fn load_file(path: &Path) -> Result<Config> {
    let format = Format::from_path(path).ok_or_else(|| {
        ConfError::UnsupportedFormat(
            path.extension().and_then(|e| e.to_str()).unwrap_or("<no extension>").to_owned(),
        )
    })?;
    let file =
        File::open(path).map_err(|e| ConfError::Read(format!("open {}: {e}", path.display())))?;
    format.decode(file)
}

/// 用显式指定的格式从文件加载（忽略扩展名）。
pub fn load_file_with_format(path: &Path, format: Format) -> Result<Config> {
    let file =
        File::open(path).map_err(|e| ConfError::Read(format!("open {}: {e}", path.display())))?;
    format.decode(file)
}

/// 用指定格式从 reader 加载。
pub fn load_reader<R: Read>(format: Format, reader: R) -> Result<Config> {
    format.decode(reader)
}

/// 用指定格式从字符串加载（便捷方法，多用于测试）。
pub fn load_str(format: Format, s: &str) -> Result<Config> {
    format.decode(s.as_bytes())
}

/// 从字符串自动探测格式后加载。
///
/// 探测失败时返回 [`ConfError::UnsupportedFormat`]。
/// 优先用 [`load_file`] / [`load_str`]（已知格式场景），探测仅作兜底。
pub fn load_str_auto_detect(s: &str) -> Result<Config> {
    let format = Format::detect(s.as_bytes())
        .ok_or_else(|| ConfError::UnsupportedFormat("auto-detect failed".into()))?;
    format.decode(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let base = std::env::temp_dir().join("xray-conf-tests");
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let path = temp_dir().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_json_file_by_extension() {
        let path = write_temp(
            "conf_json_test.json",
            r#"{ "inbounds": [{ "protocol": "vless", "tag": "in" }] }"#,
        );
        let cfg = load_file(&path).unwrap();
        assert_eq!(cfg.inbound_count(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_yaml_file_by_extension() {
        let path = write_temp(
            "conf_yaml_test.yaml",
            "outbounds:\n  - protocol: freedom\n    tag: direct\n",
        );
        let cfg = load_file(&path).unwrap();
        assert_eq!(cfg.outbound_count(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_toml_file_by_extension() {
        let path = write_temp(
            "conf_toml_test.toml",
            r#"
[[outbounds]]
protocol = "freedom"
tag = "direct"
"#,
        );
        let cfg = load_file(&path).unwrap();
        assert_eq!(cfg.outbound_count(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_file_unknown_extension_errors() {
        let path = write_temp("conf_xml_test.xml", "<config/>");
        let err = load_file(&path).unwrap_err();
        assert!(matches!(err, ConfError::UnsupportedFormat(_)));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_with_explicit_format_ignores_extension() {
        let path = write_temp("conf_noext", r#"{ "inbounds": [] }"#);
        let cfg = load_file_with_format(&path, Format::Json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_str_dispatches_by_format() {
        let cfg = load_str(Format::Json, r#"{ "inbounds": [] }"#).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn auto_detect_json() {
        let cfg = load_str_auto_detect(r#"{ "inbounds": [] }"#).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn auto_detect_yaml_by_marker() {
        let cfg = load_str_auto_detect("---\ninbounds: []\n").unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }
}
