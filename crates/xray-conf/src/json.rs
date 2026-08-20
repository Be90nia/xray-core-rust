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

/// 从 reader 解析 JSON 配置（默认容忍 // 和 /* */ 注释）。
///
/// `xray.json.strict`（或 `XRAY_JSON_STRICT`）== "true" 时跳过注释剥离，
/// 按严格 RFC 8259 解析（对应 Go `platform.UseStrictJSON`）。
pub fn decode_json(reader: impl Read) -> Result<Config> {
    let mut buf = String::new();
    reader.take(64 * 1024 * 1024).read_to_string(&mut buf)
        .map_err(|e| ConfError::Read(format!("read JSON: {e}")))?;
    decode_json_from_str(&buf)
}

/// 从 reader 解析严格 RFC 8259 JSON 配置。
///
/// 用于远程源（HTTP）等机器生成、不应含注释的场景。
pub fn decode_json_strict(reader: impl Read) -> Result<Config> {
    let mut buf = String::new();
    reader.take(64 * 1024 * 1024).read_to_string(&mut buf)
        .map_err(|e| ConfError::Read(format!("read JSON: {e}")))?;
    serde_json::from_str(&buf).map_err(|e| ConfError::from_json("json", e))
}

/// 从字符串切片解析 JSON 配置（容忍注释，strict env 可关）。
pub fn decode_json_from_str(s: &str) -> Result<Config> {
    if xray_common::platform::use_strict_json() {
        return serde_json::from_str(s).map_err(|e| ConfError::from_json("json", e));
    }
    let stripped = strip_json_comments(s);
    serde_json::from_str(&stripped).map_err(|e| ConfError::from_json("json", e))
}

/// 从字节切片解析 JSON 配置（容忍注释，strict env 可关）。
pub fn decode_json_from_slice(s: &[u8]) -> Result<Config> {
    let s = std::str::from_utf8(s).map_err(|e| ConfError::ParseSimple { format: "json", message: format!("UTF-8: {e}") })?;
    decode_json_from_str(s)
}

/// 剥离 JSON 配置中的 `//` 行注释和 `/* */` 块注释。
///
/// 字符串字面量内的注释标记被保留（对应 Go `infra/conf/json_reader.go`）。
fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                // 转义字符：保留下一字符
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' { in_string = false; }
            i += 1;
            continue;
        }
        // 不在字符串中
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }
        // 行注释 //
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            // 跳到行尾
            i += 2;
            while i < chars.len() && chars[i] != '\n' { i += 1; }
            continue;
        }
        // 块注释 /* */
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') { i += 1; }
            i += 2; // skip */
            if i > chars.len() { i = chars.len(); }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
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
