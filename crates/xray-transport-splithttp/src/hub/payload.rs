//! Payload 提取 + base64/cookie/query 工具函数。
//!
//! 从 handler.rs 拆出，保持 handler.rs 在 250 LOC 以下。

use http::HeaderMap;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, StatusCode};

use crate::config::{PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER};
use crate::xpadding::{is_padding_valid, PADDING_METHOD_REPEAT_X};

use super::handler::HandlerContext;

/// 提取 packet-up payload（body / header / cookie / auto placement）。
pub(super) async fn extract_packet_payload(
    req: Request<Incoming>,
    ctx: &HandlerContext,
) -> Result<Vec<u8>, StatusCode> {
    let placement = ctx.config.normalized_uplink_data_placement();
    let key = &ctx.config.uplink_data_key;
    let (parts, body) = req.into_parts();
    let headers = &parts.headers;

    let mut payload = Vec::new();

    if placement == PLACEMENT_AUTO || placement == PLACEMENT_HEADER {
        payload.extend_from_slice(&extract_header_payload(headers, key));
    }
    if placement == PLACEMENT_AUTO || placement == PLACEMENT_COOKIE {
        payload.extend_from_slice(&extract_cookie_payload(headers, key));
    }
    if placement == PLACEMENT_AUTO || placement == PLACEMENT_BODY {
        let bytes = body
            .collect()
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .to_bytes();
        payload.extend_from_slice(&bytes);
    }

    Ok(payload)
}

/// 从 `{key}-{i}` header 序列提取并 base64 解码。
pub(super) fn extract_header_payload(headers: &HeaderMap, key: &str) -> Vec<u8> {
    let mut chunks = Vec::new();
    for i in 0.. {
        let name = format!("{key}-{i}");
        if let Some(val) = headers.get(name.as_str()) {
            if let Ok(s) = val.to_str() {
                chunks.push(s.to_string());
            }
        } else {
            break;
        }
    }
    let encoded = chunks.concat();
    if encoded.is_empty() {
        Vec::new()
    } else {
        base64url_decode(&encoded).unwrap_or_default()
    }
}

/// 从 `{key}_{i}` cookie 序列提取并 base64 解码。
pub(super) fn extract_cookie_payload(headers: &HeaderMap, key: &str) -> Vec<u8> {
    let mut chunks = Vec::new();
    for i in 0.. {
        let name = format!("{key}_{i}");
        let val = cookie_get(headers, &name);
        if val.is_empty() {
            break;
        }
        chunks.push(val);
    }
    let encoded = chunks.concat();
    if encoded.is_empty() {
        Vec::new()
    } else {
        base64url_decode(&encoded).unwrap_or_default()
    }
}

/// 校验 padding（简化版：检查 Referer header 的 x_padding query）。
pub(super) fn validate_padding(req: &Request<Incoming>, ctx: &HandlerContext) -> bool {
    // ponytail: 非强制 padding 校验。obfs_mode=true 时依赖完整 xpadding 模块，留后续。
    if ctx.config.x_padding_obfs_mode {
        return true;
    }
    let referer = match req.headers().get("Referer").and_then(|v| v.to_str().ok()) {
        Some(r) => r,
        None => return true,
    };
    let padding_val = extract_query_value(referer, "x_padding");
    if padding_val.is_empty() {
        return true;
    }
    let range = ctx.config.get_normalized_x_padding_bytes();
    is_padding_valid(&padding_val, range.from, range.to, PADDING_METHOD_REPEAT_X)
}

/// 从 URL query string 中提取指定 key 的 value。
pub(super) fn extract_query_value(url: &str, key: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&') {
        if let Some(eq) = pair.find('=') {
            if &pair[..eq] == key {
                return pair[eq + 1..].to_string();
            }
        }
    }
    String::new()
}

/// 从 Cookie header 中按 name 提取 value。
pub(super) fn cookie_get(headers: &HeaderMap, name: &str) -> String {
    for value in headers.get_all("cookie").iter() {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some(eq) = pair.find('=') {
                    if &pair[..eq] == name {
                        return pair[eq + 1..].to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// URL-safe base64 解码（无 padding）。对应 Go `base64.RawURLEncoding.DecodeString`。
pub(super) fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn char_val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let vals = [
            char_val(bytes[i]),
            char_val(bytes[i + 1]),
            char_val(bytes[i + 2]),
            char_val(bytes[i + 3]),
        ];
        if vals.iter().any(Option::is_none) {
            return Err(());
        }
        let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];
        out.push((v[0] << 2) | (v[1] >> 4));
        out.push((v[1] << 4) | (v[2] >> 2));
        out.push((v[2] << 6) | v[3]);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem >= 2 {
        let v0 = char_val(bytes[i]).ok_or(())?;
        let v1 = char_val(bytes[i + 1]).ok_or(())?;
        out.push((v0 << 2) | (v1 >> 4));
        if rem == 3 {
            let v2 = char_val(bytes[i + 2]).ok_or(())?;
            out.push((v1 << 4) | (v2 >> 2));
        }
    } else if rem == 1 {
        return Err(());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_decode_basic() {
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64url_decode("d29ybGQh").unwrap(), b"world!");
    }

    #[test]
    fn base64url_decode_empty() {
        assert_eq!(base64url_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64url_decode_all_0xff() {
        assert_eq!(base64url_decode("____").unwrap(), vec![0xffu8, 0xff, 0xff]);
    }

    #[test]
    fn base64url_decode_invalid_char_returns_err() {
        assert!(base64url_decode("abc!def").is_err());
    }

    #[test]
    fn base64url_decode_single_remaining_char_is_error() {
        assert!(base64url_decode("a").is_err());
    }

    #[test]
    fn extract_query_value_finds_key() {
        assert_eq!(
            extract_query_value("https://example.com/ws?x_padding=XXXX", "x_padding"),
            "XXXX"
        );
        assert_eq!(extract_query_value("https://e.com/ws?a=1&b=2", "b"), "2");
    }

    #[test]
    fn extract_query_value_missing_returns_empty() {
        assert_eq!(extract_query_value("https://example.com/ws", "x_padding"), "");
    }

    #[test]
    fn cookie_get_finds_value() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "foo=bar; token=abc; baz=qux".parse().unwrap());
        assert_eq!(cookie_get(&headers, "token"), "abc");
        assert_eq!(cookie_get(&headers, "foo"), "bar");
        assert_eq!(cookie_get(&headers, "missing"), "");
    }

    #[test]
    fn extract_header_payload_concatenates_chunks() {
        let mut headers = HeaderMap::new();
        headers.insert("payload-0", "aGVs".parse().unwrap());
        headers.insert("payload-1", "bG8".parse().unwrap());
        let result = extract_header_payload(&headers, "payload");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn extract_header_payload_empty_key_returns_empty() {
        let headers = HeaderMap::new();
        assert_eq!(extract_header_payload(&headers, "nonexistent"), Vec::<u8>::new());
    }
}
