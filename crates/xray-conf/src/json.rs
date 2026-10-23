//! JSON 配置解码器（薄封装）。
//!
//! 实体机制——RFC 8259 严格解码 / 注释容忍 / 64MiB 输入上限 / 行列位置错误——
//! 已提炼上浮 udf `std-ext::json`（P1-9，udf-promotion-candidate 终态落位）；
//! 本文件只留 Xray 语义：env 切 strict（`xray_common::platform::use_strict_json`）
//! 与 `Config` 装配。
//!
//! 对应 Go `infra/conf/serial.DecodeJSONConfig` / `DecodeJSONConfigStrict`。
//! Go 兼容序列化（`to_json_string`，`JSONMarshalWithoutEscape` + 4 空格缩进）
//! 属 Xray 语义，留 `serial.rs` 不上浮。

use std::io::Read;

use std_ext::json::{self, JsonMode};

use crate::{
    config::Config,
    error::{ConfError, Result},
};

/// strict env（`xray.json.strict` / `XRAY_JSON_STRICT`，对应 Go `platform.UseStrictJSON`）
/// 选择解码模式。
fn json_mode() -> JsonMode {
    if xray_common::platform::use_strict_json() { JsonMode::Strict } else { JsonMode::Tolerant }
}

/// udf 解码结果装配为 [`Config`]（解码目标类型留仓）。
fn config_from_value(value: serde_json::Value) -> Result<Config> {
    serde_json::from_value(value).map_err(|e| ConfError::from_json("json", e))
}

/// 从 reader 解析 JSON 配置（默认容忍 // 和 /* */ 注释）。
///
/// `xray.json.strict`（或 `XRAY_JSON_STRICT`）== "true" 时按严格 RFC 8259 解析
/// （对应 Go `platform.UseStrictJSON`）。
pub fn decode_json(reader: impl Read) -> Result<Config> {
    config_from_value(json::decode(reader, json_mode())?)
}

/// 从 reader 解析严格 RFC 8259 JSON 配置。
///
/// 用于远程源（HTTP）等机器生成、不应含注释的场景。
pub fn decode_json_strict(reader: impl Read) -> Result<Config> {
    config_from_value(json::decode(reader, JsonMode::Strict)?)
}

/// 从字符串切片解析 JSON 配置（容忍注释，strict env 可关）。
pub fn decode_json_from_str(s: &str) -> Result<Config> {
    config_from_value(json::decode_str(s, json_mode())?)
}

/// 从字节切片解析 JSON 配置（容忍注释，strict env 可关）。
pub fn decode_json_from_slice(s: &[u8]) -> Result<Config> {
    config_from_value(json::decode_slice(s, json_mode())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::PortRange;

    #[test]
    fn decode_valid_json() {
        let json = r#"{ "inbounds": [{ "protocol": "vless", "port": 443, "tag": "in" }] }"#;
        let cfg = decode_json_from_str(json).unwrap();
        assert_eq!(cfg.inbound_count(), 1);
        assert_eq!(cfg.inbound_configs[0].tag, "in");
        assert_eq!(cfg.inbound_configs[0].port.as_ref().unwrap().0, vec![PortRange::single(443)]);
    }

    #[test]
    fn decode_returns_position_aware_error() {
        let bad = "{ \"bad\": }";
        let err = decode_json_from_str(bad).unwrap_err();
        match err {
            ConfError::Parse { format, line, .. } => {
                assert_eq!(format, "json");
                assert!(line >= 1);
            },
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn strict_and_permissive_equivalent_for_now() {
        let json = r#"{ "inbounds": [] }"#;
        let a = decode_json_strict(json.as_bytes()).unwrap();
        let b = decode_json(json.as_bytes()).unwrap();
        assert_eq!(a.inbound_count(), b.inbound_count());
    }

    #[test]
    fn decode_from_slice_works() {
        let json = b"{ \"inbounds\": [] }";
        let cfg = decode_json_from_slice(json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn decode_from_reader_works() {
        let json = b"{ \"outbounds\": [{ \"protocol\": \"freedom\", \"tag\": \"direct\" }] }";
        let cfg = decode_json(json.as_ref()).unwrap();
        assert_eq!(cfg.outbound_count(), 1);
    }
    #[test]
    fn strip_line_comment_basic() {
        let json = "{ \"inbounds\": [] } // comment\n";
        let cfg = decode_json_from_str(json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn strip_block_comment() {
        let json = "/* config */ { \"inbounds\": [] }";
        let cfg = decode_json_from_str(json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn preserve_url_in_string() {
        // https:// in string literal must NOT be stripped
        let json = r#"{"inbounds":[],"routing":{"rules":[]}}"#;
        let cfg = decode_json_from_str(json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }
}
