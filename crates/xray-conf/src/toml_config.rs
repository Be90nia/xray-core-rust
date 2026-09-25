//! TOML 配置解码器。
//!
//! 对应 Go `infra/conf/serial.DecodeTOMLConfig`。Go 路径：`toml → map → json → Config`。
//! Rust 等价：`toml::Value → serde_json::Value → Config`。
//!
//! 文件名 `toml_config` 而非 `toml`：避免与 `toml` crate 名冲突（`mod toml {}` 会让
//! `toml::from_str` 在模块内指向本地 mod 而非 crate）。

use std::io::Read;

use crate::{
    config::Config,
    error::{ConfError, Result},
};

/// 从 reader 解析 TOML 配置。
pub fn decode_toml(mut reader: impl Read) -> Result<Config> {
    // toml crate 的反序列化器要求字符串输入（不支持 from_reader）。
    let mut buf = String::new();
    reader.read_to_string(&mut buf).map_err(ConfError::Io)?;

    let toml_value: toml::Value = toml::from_str(&buf).map_err(|e| ConfError::simple("toml", e))?;

    let json_value: serde_json::Value = serde_json::to_value(&toml_value)
        .map_err(|e| ConfError::simple("toml", format!("convert toml→json: {e}")))?;

    serde_json::from_value(json_value).map_err(|e| ConfError::from_json("toml", e))
}

/// 从字符串切片解析 TOML 配置。
pub fn decode_toml_from_str(s: &str) -> Result<Config> {
    decode_toml(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_toml_inbound() {
        // TOML 表达 Xray 配置较冗长（[[inbounds]] 数组表），但能完整描述。
        let toml_src = r#"
[[inbounds]]
protocol = "vless"
tag = "vless-in"
listen = "0.0.0.0"
"#;
        let cfg = decode_toml_from_str(toml_src).unwrap();
        assert_eq!(cfg.inbound_count(), 1);
        assert_eq!(cfg.inbound_configs[0].tag, "vless-in");
        assert_eq!(cfg.inbound_configs[0].listen.as_ref().unwrap().as_str(), "0.0.0.0");
    }

    #[test]
    fn decode_toml_outbound() {
        let toml_src = r#"
[[outbounds]]
protocol = "freedom"
tag = "direct"
"#;
        let cfg = decode_toml_from_str(toml_src).unwrap();
        assert_eq!(cfg.outbound_count(), 1);
        assert_eq!(cfg.outbound_configs[0].protocol, "freedom");
    }

    #[test]
    fn toml_error_is_parse_simple() {
        let bad = "not = = valid";
        let err = decode_toml_from_str(bad).unwrap_err();
        match err {
            ConfError::ParseSimple { format, .. } => assert_eq!(format, "toml"),
            other => panic!("expected ParseSimple, got {other:?}"),
        }
    }
}
