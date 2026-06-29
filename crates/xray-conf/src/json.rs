//! JSON 配置解码器。
//!
//! 对应 Go `infra/conf/serial.DecodeJSONConfig` / `DecodeJSONConfigStrict`。
//!
//! Go 区分两个版本：`DecodeJSONConfig` 容忍 JSON5/JSONC 注释（via 自定义 reader），
//! `DecodeJSONConfigStrict` 严格 RFC 8259。Rust 的 `serde_json` 默认就是 strict，
//! 所以当前两个函数等价；保留独立函数以便将来引入 `json5` 支持注释时分叉实现。
//!
//! `serde_json::Error` 自带 `line()` / `column()`，不需要像 Go 那样手写 `findOffset`。

use std::io::Read;

use crate::config::Config;
use crate::error::{ConfError, Result};

/// 从 reader 解析 JSON 配置（容忍扩展，当前等价于 strict）。
pub fn decode_json(reader: impl Read) -> Result<Config> {
    serde_json::from_reader(reader).map_err(|e| ConfError::from_json("json", e))
}

/// 从 reader 解析严格 RFC 8259 JSON 配置。
///
/// 用于远程源（HTTP）等机器生成、不应含注释的场景。
pub fn decode_json_strict(reader: impl Read) -> Result<Config> {
    // 当前 serde_json 默认 strict；保留独立函数以备将来引入 json5 容忍注释时分叉。
    decode_json(reader)
}

/// 从字符串切片解析 JSON 配置。
pub fn decode_json_from_str(s: &str) -> Result<Config> {
    serde_json::from_str(s).map_err(|e| ConfError::from_json("json", e))
}

/// 从字节切片解析 JSON 配置。
pub fn decode_json_from_slice(s: &[u8]) -> Result<Config> {
    serde_json::from_slice(s).map_err(|e| ConfError::from_json("json", e))
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
        assert_eq!(
            cfg.inbound_configs[0].port.as_ref().unwrap().0,
            vec![PortRange::single(443)]
        );
    }

    #[test]
    fn decode_returns_position_aware_error() {
        let bad = "{ \"bad\": }";
        let err = decode_json_from_str(bad).unwrap_err();
        match err {
            ConfError::Parse { format, line, .. } => {
                assert_eq!(format, "json");
                assert!(line >= 1);
            }
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
}
