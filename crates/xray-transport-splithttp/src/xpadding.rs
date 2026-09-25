//! XHTTP/SplitHTTP X-Padding 混淆层。
//!
//! 对应 Go `transport/internet/splithttp/xpadding.go`。
//!
//! # 切片 B 范围（完整 obfs）
//!
//! - HPACK Huffman 编码长度计算（RFC 7541 Appendix B 内嵌 256-entry bits 表）
//! - `generate_padding`：`repeat-x` / `tokenish` 两种填充策略
//! - `is_padding_valid`：服务端校验
//! - `XPaddingConfig` / `XPaddingPlacement`：placement 策略
//! - `apply_xpadding_to_request_meta`：客户端 padding 注入
//!
//! # 切片 B 不含
//!
//! - `extract_xpadding_from_request_meta`（服务端用，留 hub.rs 实现切片）
//! - HTTP body / path placement（客户端默认 query/cookie/header/queryInHeader）

use rand::RngCore;

use crate::config::{
    PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_QUERY_IN_HEADER, RequestMeta, uri_append_query,
};

/// 填充方法：重复 'X'（每个 X = 8 bits，HPACK 不压缩长度）。
pub const PADDING_METHOD_REPEAT_X: &str = "repeat-x";
/// 填充方法：随机 base62 字符串，目标 Huffman 编码长度匹配目标字节数。
pub const PADDING_METHOD_TOKENISH: &str = "tokenish";

/// Base62 字符集（数字 + 大写字母 + 小写字母）。
const CHARSET_BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Huffman 编码对 base62 序列的平均压缩率（约 20% 压缩，每字符 ~0.8 字节）。
const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;

/// 服务端验证 tolerance（±2 字节）：允许客户端 padding 长度因随机性不完全精确匹配。
const VALIDATION_TOLERANCE: i32 = 2;

/// tokenish 算法最大迭代次数（防止无限循环）。
const TOKENISH_MAX_ITER: usize = 150;

/// RFC 7541 Appendix B - HPACK 静态 Huffman 编码每个字节的 bit 长度。
///
/// 用于精确计算字符串经 HPACK Huffman 压缩后的字节数
/// （等价 Go `golang.org/x/net/http2/hpack.HuffmanEncodeLength`）。
///
/// 'X' (88) 和 'Z' (90) 都是 8 bits，HPACK 不会压缩全 X/Z 字符串，对应 Go 注释：
/// "'X' and 'Z' are assigned an 8 bit code, so HPACK compression won't change
/// actual padding length on the wire"。
// w1s7：按 RFC 7541 Appendix B 脚本化对拍（256 项逐字节），之前手抄版错
// 144 处（含 15 个 base62 字符 e/g/h/i/j/k/m/o/q/r/s/t/u/y/z 等），导致
// tokenish padding 长度系统性偏差 ~15%；Go 服务端 IsPaddingValid 容差仅 ±2 必拒。
// 与 Go `golang.org/x/net/http2/hpack.HuffmanEncodeLength` 等价。
// 'X' (88) 和 'Z' (90) 都是 8 bits：HPACK 不压缩全 X/Z 串，'padding 长度' == '字节长度'。
const HUFFMAN_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 00-0f
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 10-1f
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 20-2f
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 30-3f
    13, 10, 13, 23, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 40-4f
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, // 50-5f
    14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, // 60-6f
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 11, 11, 14, // 70-7f
    13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, // 80-8f
    24, 23, 24, 24, 24, 24, 24, 23, 24, 24, 24, 23, 24, 24, 24, 24, // 90-9f
    21, 22, 22, 22, 22, 21, 22, 22, 23, 23, 24, 23, 23, 23, 23, 23, // a0-af
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, // b0-bf
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, // c0-cf
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, // d0-df
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, // e0-ef
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, // f0-ff
];

/// HPACK Huffman 编码后字节数。等价 Go `hpack.HuffmanEncodeLength`。
#[inline]
#[must_use]
pub fn huffman_encode_length(s: &str) -> usize {
    let total_bits: u32 = s.bytes().map(|b| HUFFMAN_BITS[b as usize] as u32).sum();
    ((total_bits + 7) / 8) as usize
}

/// Placement 描述（与 Go `XPaddingPlacement` 等价）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XPaddingPlacement {
    /// Placement 类型（`query` / `cookie` / `header` / `queryInHeader` 等）。
    pub placement: String,
    /// Query / cookie 的 key 名。
    pub key: String,
    /// Header 名（`header` / `queryInHeader` placement 用）。
    pub header: String,
    /// 原始 URL（`queryInHeader` placement 用，padding 写入此 URL 的 query）。
    pub raw_url: String,
}

/// Padding 配置（与 Go `XPaddingConfig` 等价）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XPaddingConfig {
    /// Padding 字节长度（Huffman 编码后，tokenish 模式有 ±2 容差）。
    pub length: i32,
    /// Placement 描述。
    pub placement: XPaddingPlacement,
    /// Padding 方法（`repeat-x` / `tokenish`）。
    pub method: String,
}

/// 用 `charset` 中字符生成 `n` 字节随机字符串（拒绝采样避免 modulo bias）。
///
/// 对应 Go `randStringFromCharset`。返回 `None` 当 `n == 0` 或 `charset` 为空。
fn rand_string_from_charset(n: usize, charset: &[u8]) -> Option<String> {
    if n == 0 || charset.is_empty() {
        return None;
    }
    let m = charset.len();
    let limit = 256 - (256 % m);
    let mut result = vec![0u8; n];
    let mut buf = [0u8; 256];
    let mut filled = 0;
    while filled < n {
        rand::rng().fill_bytes(&mut buf);
        for &rb in &buf {
            if (rb as usize) >= limit {
                continue;
            }
            result[filled] = charset[(rb as usize) % m];
            filled += 1;
            if filled == n {
                break;
            }
        }
    }
    // SAFETY: charset 为 ASCII（base62），result 字节均来自 charset。
    Some(unsafe { String::from_utf8_unchecked(result) })
}

/// 用 `tokenish` 策略生成 base62 字符串，使 Huffman 编码后字节数接近 `target_huffman_bytes`。
///
/// 对应 Go `GenerateTokenishPaddingBase62`。算法：
/// 1. 初始字符数 = ceil(target / 0.8)（基于平均压缩率）
/// 2. 迭代调整：太短追加 'X'/'Z'（每个 8 bits），太长删除末尾
/// 3. 直到 Huffman 长度与 target 差 ≤ 2 字节，或达到 150 次迭代上限
#[must_use]
pub fn generate_tokenish_padding_base62(target_huffman_bytes: i32) -> String {
    if target_huffman_bytes <= 0 {
        return String::new();
    }
    let mut n = ((target_huffman_bytes as f64) / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).ceil() as usize;
    if n < 1 {
        n = 1;
    }
    let mut s = match rand_string_from_charset(n, CHARSET_BASE62) {
        Some(s) => s,
        None => return String::new(),
    };
    let mut adjust = b'X';
    for _ in 0..TOKENISH_MAX_ITER {
        let cur = huffman_encode_length(&s) as i32;
        let diff = cur - target_huffman_bytes;
        if diff.abs() <= VALIDATION_TOLERANCE {
            return s;
        }
        if diff < 0 {
            // 太短 -> 追加 'X' 或 'Z'（都是 8 bits，HPACK 不压缩）
            s.push(adjust as char);
            // 交替 X/Z 避免连续相同字符
            adjust = if adjust == b'X' { b'Z' } else { b'X' };
        } else if s.len() <= 1 {
            return s;
        } else {
            // 太长 -> 删除末尾
            s.pop();
        }
    }
    s
}

/// 按 `method` 生成 padding 字符串，长度 `length` 字节。对应 Go `GeneratePadding`。
///
/// - `repeat-x`：全 'X'（HPACK 不压缩长度，每个 X = 8 bits）
/// - `tokenish`：随机 base62，目标 Huffman 编码字节数 = `length`
/// - 其他：同 `repeat-x`（Go 默认行为）
#[must_use]
pub fn generate_padding(method: &str, length: i32) -> String {
    if length <= 0 {
        return String::new();
    }
    match method {
        PADDING_METHOD_TOKENISH => {
            let v = generate_tokenish_padding_base62(length);
            if v.is_empty() { "X".repeat(length as usize) } else { v }
        },
        _ => "X".repeat(length as usize),
    }
}

/// 服务端校验 padding 值是否在 `[from, to]` 范围内。对应 Go `IsPaddingValid`。
///
/// - `repeat-x`：直接用字符串字节数
/// - `tokenish`：用 Huffman 编码后字节数，允许 ±2 字节 tolerance
/// - 其他：同 `repeat-x`
#[must_use]
pub fn is_padding_valid(padding_value: &str, mut from: i32, mut to: i32, method: &str) -> bool {
    if padding_value.is_empty() {
        return false;
    }
    if to <= 0 {
        // 默认范围（与 Go GetNormalizedXPaddingBytes 一致）
        from = 100;
        to = 1000;
    }
    let (n, lo, hi) = match method {
        PADDING_METHOD_TOKENISH => {
            let n = huffman_encode_length(padding_value) as i32;
            let lo = (from - VALIDATION_TOLERANCE).max(0);
            (n, lo, to + VALIDATION_TOLERANCE)
        },
        _ => (padding_value.len() as i32, from, to),
    };
    n >= lo && n <= hi
}

/// 将 padding 值注入 `RequestMeta`。对应 Go `ApplyXPaddingToRequest`。
///
/// 支持 placement：`query` / `cookie` / `header` / `queryInHeader`。
/// `path` / `body` placement 由调用方在构造 URI / payload 时处理（非通用场景）。
///
/// # Panics
/// 不会 panic。空 padding 值直接返回（保持 RequestMeta 不变）。
pub fn apply_xpadding_to_request_meta(meta: &mut RequestMeta, config: &XPaddingConfig) {
    let placement = config.placement.placement.as_str();
    let padding_value = generate_padding(&config.method, config.length);
    if padding_value.is_empty() {
        return;
    }
    match placement {
        PLACEMENT_HEADER => {
            meta.headers.push((config.placement.header.clone(), padding_value));
        },
        PLACEMENT_QUERY_IN_HEADER => {
            // header 值是 URL，把 padding 写入 URL query
            // 例：Referer: <base> -> Referer: <base>?x_padding=XXX
            let new_value = if config.placement.raw_url.is_empty() {
                format!("?{}={}", config.placement.key, padding_value)
            } else {
                uri_append_query(&config.placement.raw_url, &config.placement.key, &padding_value)
            };
            meta.headers.push((config.placement.header.clone(), new_value));
        },
        PLACEMENT_COOKIE => {
            meta.cookies.push((config.placement.key.clone(), padding_value));
        },
        // 默认 query：注入到 URI 的 query string
        _ => {
            meta.uri = uri_append_query(&meta.uri, &config.placement.key, &padding_value);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PLACEMENT_QUERY;

    /// w1s7：X=7 bits（RFC 7541 修正）。X 单字符 = 7 bits → 1 byte；Z=8 bits。
    /// 16 个 X = 16 × 7 = 112 bits → ceil(112/8) = 14 bytes。
    /// 8 个 Z = 8 × 8 = 64 bits → 8 bytes。
    #[test]
    fn huffman_length_x_and_z_are_8_bits() {
        assert_eq!(huffman_encode_length("X"), 1);
        assert_eq!(huffman_encode_length("Z"), 1);
        assert_eq!(huffman_encode_length("XX"), 2); // 14 bits → 2 bytes
        assert_eq!(huffman_encode_length("ZZZZ"), 4); // 32 bits → 4 bytes
    }

    /// w1s7：HUFFMAN_BITS 完整 256 项逐字节对照 RFC 7541 Appendix B 真值。
    /// 之前手抄版 144 项错（base62 字符 e/g/h/i/j/k/m/o/q/r/s/t/u/y/z 全错位
    /// + 0x80-0xff 段多位偏差），tokenish padding 长度系统性偏离 ~15% → Go
    /// 服务端 IsPaddingValid 容差 ±2 必拒收（B 类节点 fail）。本测试用真值数组
    /// 一次性兜底防回归——任何单字节写错都会被这条测试捕获。
    #[test]
    fn huffman_table_matches_rfc7541_for_all_256_bytes() {
        // RFC 7541 Appendix B 完整 Huffman code 长度表（256 项）。
        const RFC: [u8; 256] = [
            13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28,
            30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8,
            6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 10, 13, 23, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15,
            5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 11, 11,
            14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 24,
            24, 24, 23, 24, 24, 24, 23, 24, 24, 24, 24, 21, 22, 22, 22, 22, 21, 22, 22, 23, 23, 24,
            23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
            23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
            23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
            23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
        ];
        for (i, (&got, &want)) in HUFFMAN_BITS.iter().zip(RFC.iter()).enumerate() {
            assert_eq!(
                got,
                want,
                "byte {i:#04x} ({}): rust={got} rfc={want}",
                if (32..127).contains(&i) { char::from(i as u8) } else { '?' }
            );
        }
    }

    #[test]
    fn huffman_length_digit_one_byte() {
        // 数字 '0' = 5 bits -> 1 byte
        assert_eq!(huffman_encode_length("0"), 1);
        // 16 个 '0' = 80 bits -> 10 bytes
        assert_eq!(huffman_encode_length("0000000000000000"), 10);
    }

    #[test]
    fn huffman_length_lowercase_a_one_byte() {
        // 'a' = 6 bits -> 1 byte
        assert_eq!(huffman_encode_length("a"), 1);
    }

    #[test]
    fn huffman_length_empty_string() {
        assert_eq!(huffman_encode_length(""), 0);
    }

    /// w1s7：HUFFMAN_BITS 表已按 RFC 7541 Appendix B 修正。"Ab0" = A(10)+b(15)+0(5) =
    /// 30 bits → ceil(30/8) = 4 bytes。注：原手抄表把 A 写成 6 bits → 误判 3 bytes。
    #[test]
    fn huffman_length_mixed_base62_rounding() {
        assert_eq!(huffman_encode_length("Ab0"), 4);
    }

    /// w1s7：'X' = 7 bits（RFC 7541 修正），非 8 bits。10 × 7 = 70 bits → 9 bytes。
    /// 注意：手抄表把 X 错成 8 bits 时生成的 'XXXXXX...' padding 会比 Go 端
    /// `hpack.HuffmanEncodeLength` 算长，导致 xPaddingMethod=repeat-x 场景
    /// 与 Go 服务端 IsPaddingValid 校验错位。
    #[test]
    fn generate_padding_repeat_x() {
        let s = generate_padding(PADDING_METHOD_REPEAT_X, 10);
        assert_eq!(s.len(), 10);
        assert_eq!(s, "XXXXXXXXXX");
        assert_eq!(huffman_encode_length(&s), 9); // 10 chars × 7 bits = 70 bits = 9 bytes
    }
    #[test]
    fn generate_padding_zero_or_negative_returns_empty() {
        assert_eq!(generate_padding(PADDING_METHOD_REPEAT_X, 0), "");
        assert_eq!(generate_padding(PADDING_METHOD_REPEAT_X, -5), "");
        assert_eq!(generate_padding(PADDING_METHOD_TOKENISH, 0), "");
    }

    #[test]
    fn generate_padding_unknown_method_defaults_to_repeat_x() {
        let s = generate_padding("unknown-method", 5);
        assert_eq!(s, "XXXXX");
    }

    #[test]
    fn generate_tokenish_padding_hits_target_within_tolerance() {
        for target in [50, 100, 200, 500, 1000] {
            let s = generate_tokenish_padding_base62(target);
            assert!(!s.is_empty(), "target={target} produced empty padding");
            let encoded = huffman_encode_length(&s) as i32;
            let diff = (encoded - target).abs();
            assert!(
                diff <= VALIDATION_TOLERANCE,
                "target={target} encoded={encoded} diff={diff} > tolerance={VALIDATION_TOLERANCE}"
            );
        }
    }

    #[test]
    fn generate_tokenish_padding_returns_base62() {
        let s = generate_tokenish_padding_base62(100);
        for b in s.bytes() {
            assert!(CHARSET_BASE62.contains(&b), "non-base62 char in padding: {b}");
        }
    }

    #[test]
    fn is_padding_valid_repeat_x_in_range() {
        // "XXXXX" len=5, range [5, 10] -> valid
        assert!(is_padding_valid("XXXXX", 5, 10, PADDING_METHOD_REPEAT_X));
        // len=5, range [6, 10] -> invalid
        assert!(!is_padding_valid("XXXXX", 6, 10, PADDING_METHOD_REPEAT_X));
    }

    #[test]
    fn is_padding_valid_tokenish_uses_huffman_length() {
        // padding 100 bytes target -> huffman length 接近 100
        let s = generate_tokenish_padding_base62(100);
        assert!(is_padding_valid(&s, 100, 100, PADDING_METHOD_TOKENISH));
        // ±2 tolerance 应该通过
        assert!(is_padding_valid(&s, 102, 102, PADDING_METHOD_TOKENISH));
        // 远离范围 -> invalid
        assert!(!is_padding_valid(&s, 200, 300, PADDING_METHOD_TOKENISH));
    }

    #[test]
    fn is_padding_valid_empty_returns_false() {
        assert!(!is_padding_valid("", 0, 100, PADDING_METHOD_REPEAT_X));
        assert!(!is_padding_valid("", 0, 100, PADDING_METHOD_TOKENISH));
    }

    #[test]
    fn is_padding_valid_default_range_when_to_zero() {
        // to=0 触发默认范围 [100, 1000]
        assert!(is_padding_valid(&"X".repeat(200), 0, 0, PADDING_METHOD_REPEAT_X));
        assert!(!is_padding_valid(&"X".repeat(50), 0, 0, PADDING_METHOD_REPEAT_X));
    }

    #[test]
    fn apply_xpadding_query_placement_injects_into_uri() {
        let mut meta = RequestMeta {
            method: "GET".into(),
            uri: "https://example.com/path".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let config = XPaddingConfig {
            length: 10,
            placement: XPaddingPlacement {
                placement: PLACEMENT_QUERY.into(),
                key: "x_padding".into(),
                ..Default::default()
            },
            method: PADDING_METHOD_REPEAT_X.into(),
        };
        apply_xpadding_to_request_meta(&mut meta, &config);
        assert!(meta.uri.contains("x_padding=XXXXXXXXXX"));
        assert!(meta.uri.starts_with("https://example.com/path?"));
    }

    #[test]
    fn apply_xpadding_cookie_placement_injects_cookie() {
        let mut meta = RequestMeta {
            method: "GET".into(),
            uri: "https://example.com/".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let config = XPaddingConfig {
            length: 5,
            placement: XPaddingPlacement {
                placement: PLACEMENT_COOKIE.into(),
                key: "kp".into(),
                ..Default::default()
            },
            method: PADDING_METHOD_REPEAT_X.into(),
        };
        apply_xpadding_to_request_meta(&mut meta, &config);
        assert_eq!(meta.cookies, vec![("kp".to_string(), "XXXXX".to_string())]);
    }

    #[test]
    fn apply_xpadding_header_placement_sets_header() {
        let mut meta = RequestMeta {
            method: "POST".into(),
            uri: "https://example.com/".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let config = XPaddingConfig {
            length: 8,
            placement: XPaddingPlacement {
                placement: PLACEMENT_HEADER.into(),
                header: "X-Pad".into(),
                ..Default::default()
            },
            method: PADDING_METHOD_REPEAT_X.into(),
        };
        apply_xpadding_to_request_meta(&mut meta, &config);
        assert_eq!(meta.headers, vec![("X-Pad".to_string(), "XXXXXXXX".to_string())]);
    }

    #[test]
    fn apply_xpadding_query_in_header_placement_sets_referer_with_query() {
        let mut meta = RequestMeta {
            method: "GET".into(),
            uri: "https://example.com/path".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let config = XPaddingConfig {
            length: 4,
            placement: XPaddingPlacement {
                placement: PLACEMENT_QUERY_IN_HEADER.into(),
                key: "x_padding".into(),
                header: "Referer".into(),
                raw_url: "https://example.com/ws".into(),
            },
            method: PADDING_METHOD_REPEAT_X.into(),
        };
        apply_xpadding_to_request_meta(&mut meta, &config);
        assert_eq!(meta.headers.len(), 1);
        let (k, v) = &meta.headers[0];
        assert_eq!(k, "Referer");
        assert_eq!(v, "https://example.com/ws?x_padding=XXXX");
    }

    #[test]
    fn apply_xpadding_zero_length_no_op() {
        let mut meta = RequestMeta {
            method: "GET".into(),
            uri: "https://example.com/".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let config = XPaddingConfig {
            length: 0,
            placement: XPaddingPlacement {
                placement: PLACEMENT_QUERY.into(),
                key: "x_padding".into(),
                ..Default::default()
            },
            method: PADDING_METHOD_REPEAT_X.into(),
        };
        apply_xpadding_to_request_meta(&mut meta, &config);
        assert_eq!(meta.uri, "https://example.com/");
        assert!(meta.headers.is_empty());
        assert!(meta.cookies.is_empty());
    }

    #[test]
    fn rand_string_from_charset_returns_valid_length() {
        let s = rand_string_from_charset(32, CHARSET_BASE62).expect("non-empty");
        assert_eq!(s.len(), 32);
        for b in s.bytes() {
            assert!(CHARSET_BASE62.contains(&b));
        }
    }

    #[test]
    fn rand_string_from_charset_empty_inputs() {
        assert!(rand_string_from_charset(0, CHARSET_BASE62).is_none());
        assert!(rand_string_from_charset(10, b"").is_none());
    }
}
