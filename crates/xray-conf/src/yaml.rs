//! YAML 配置解码器。
//!
//! 对应 Go `infra/conf/serial.DecodeYAMLConfig`。Go 用 `ghodss/yaml.YAMLToJSON`
//! 把 YAML 转成 JSON 再走 JSON 路径。Rust 等价路径：
//! `serde_yaml::Value → serde_json::Value → Config`，
//! 保证所有 `Value` 字段统一为 `serde_json::Value`（与 JSON 解码器兼容）。

use std::io::Read;

use crate::{
    config::Config,
    error::{ConfError, Result},
};

/// 从 reader 解析 YAML 配置。
pub fn decode_yaml(reader: impl Read) -> Result<Config> {
    let yaml_value: serde_yaml::Value =
        serde_yaml::from_reader(reader).map_err(|e| ConfError::simple("yaml", e))?;

    let json_value: serde_json::Value = serde_json::to_value(&yaml_value)
        .map_err(|e| ConfError::simple("yaml", format!("convert yaml→json: {e}")))?;

    serde_json::from_value(json_value).map_err(|e| ConfError::from_json("yaml", e))
}

/// 从字符串切片解析 YAML 配置。
pub fn decode_yaml_from_str(s: &str) -> Result<Config> {
    decode_yaml(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML_CONFIG: &str = r#"
inbounds:
  - protocol: vless
    port: 443
    listen: "0.0.0.0"
    tag: vless-in
    sniffing:
      enabled: true
      destOverride:
        - http
        - tls
outbounds:
  - protocol: freedom
    tag: direct
routing:
  domainStrategy: IPIfNonMatch
"#;

    #[test]
    fn decode_yaml_config() {
        let cfg = decode_yaml_from_str(YAML_CONFIG).unwrap();
        assert_eq!(cfg.inbound_count(), 1);
        assert_eq!(cfg.outbound_count(), 1);
        let inbound = &cfg.inbound_configs[0];
        assert_eq!(inbound.protocol, "vless");
        assert_eq!(inbound.tag, "vless-in");
        assert!(inbound.sniffing.as_ref().unwrap().enabled);
        assert_eq!(cfg.outbound_configs[0].tag, "direct");
    }

    #[test]
    fn yaml_preserves_camel_case_keys() {
        // YAML 中 camelCase key 需要引号；不带引号会被解析成 snake_case 而丢字段。
        // 测试目的：确保 YAML → JSON 转换保留 camelCase key。
        let yaml = r##"
"fakeDns":
  ipPool: "198.18.0.0/15"
"##;
        let cfg = decode_yaml_from_str(yaml).unwrap();
        assert!(cfg.fake_dns.is_some(), "fakeDns key must map to fake_dns field");
    }

    #[test]
    fn yaml_error_is_parse_simple() {
        let bad = "  - bad: [unclosed";
        let err = decode_yaml_from_str(bad).unwrap_err();
        match err {
            ConfError::ParseSimple { format, .. } => assert_eq!(format, "yaml"),
            other => panic!("expected ParseSimple, got {other:?}"),
        }
    }
}
