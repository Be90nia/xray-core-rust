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
// bd g90ft：整表按 **RFC 7541 Appendix B** 重生成（此前"手抄/脚本对拍"版有 131/256
// 处错值：X=7 应 8、A=10 应 6、0xb0-0xff 段全拍平成 23 等）。校验来源为**被测系统
// 之外**的两份独立实现——Go `x/net@v0.61.0 http2/hpack` huffmanCodeLen 与 Rust
// `h2 0.4.20` ENCODE_CODE_LENGTHS——逐项 diff 256/256 完全一致，且满足 Kraft
// 等式（见 tests::huffman_table_satisfies_kraft_equality）。旧测试内嵌的"RFC 真值"
// 与坏表同源同错（自证循环），已换成独立断言。
const HUFFMAN_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 00-0f
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 10-1f
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 20-2f
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 30-3f
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 40-4f
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, // 50-5f
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, // 60-6f
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, // 70-7f
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, // 80-8f
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, // 90-9f
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, // a0-af
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, // b0-bf
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, // c0-cf
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, // d0-df
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, // e0-ef
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, // f0-ff
];

/// HPACK Huffman 编码后字节数。等价 Go `hpack.HuffmanEncodeLength`。
#[inline]
#[must_use]
pub fn huffman_encode_length(s: &str) -> usize {
    let total_bits: u32 = s.bytes().map(|b| HUFFMAN_BITS[b as usize] as u32).sum();
    total_bits.div_ceil(8) as usize
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

    /// w1s7 → bd g90ft：X/Z 在 RFC 7541 Appendix B 里都是 **8 bit** 码 ⇒ HPACK 不压缩
    /// 全 X/Z 串（这正是 `repeat-x` 填充长度 == 字节长度的依据）。旧注释写成 7 bits 并
    /// 与错表自洽，已随整表重生成更正。
    #[test]
    fn huffman_length_x_and_z_are_8_bits() {
        assert_eq!(HUFFMAN_BITS[usize::from(b'X')], 8);
        assert_eq!(HUFFMAN_BITS[usize::from(b'Z')], 8);
        assert_eq!(huffman_encode_length("X"), 1);
        assert_eq!(huffman_encode_length("Z"), 1);
        // 16 个 X = 128 bits → 16 bytes（旧错表给 7 bits ⇒ 14 bytes，恰出 Go
        // IsPaddingValid 的 ±2 容差 ⇒ 生产上传被拒）。
        assert_eq!(huffman_encode_length(&"X".repeat(16)), 16);
        assert_eq!(huffman_encode_length(&"Z".repeat(16)), 16);
    }

    /// bd g90ft：**独立**校验（不内嵌第二份长度表——旧测试的真值数组抄自实现，
    /// 同源同错 ⇒ 永远绿）。
    ///
    /// Kraft 等式：Huffman 码集（256 字节 + EOS）的 `Σ 2^-len` 必须**恰好等于 1**。
    /// 该等式只依赖长度表本身与信息论，任何单字节错值都会破坏它（除非另一处恰好补偿，
    /// 概率极低），且不需要任何外部真值副本。整数化：所有 len ≤ 30 ⇒ 逐项算
    /// `2^(30-len)` 求和，应等于 `2^30`（EOS 的 len=30 贡献 1）。
    #[test]
    fn huffman_table_satisfies_kraft_equality() {
        const SCALE: u64 = 1 << 30;
        let sum: u64 = HUFFMAN_BITS.iter().map(|&l| 1u64 << (30 - u32::from(l))).sum();
        let with_eos = sum + 1; // EOS 码长 30 bits（RFC 7541 Appendix B 末项）
        assert_eq!(with_eos, SCALE, "Huffman 长度表不满足 Kraft 等式（码表被写错）");
    }

    /// bd g90ft：RFC 7541 §C.4 示例串的 Huffman 编码长度（附录 C 的三个请求/响应示例
    /// 给出的 hex 载荷字节数），作为与长度表**不同源**的权威对拍点。
    #[test]
    fn huffman_encode_length_matches_rfc7541_appendix_c() {
        // C.4.1 "www.example.com" → 12 字节（f1e3 c2e5 f23a 6ba0 ab90 f4ff）
        assert_eq!(huffman_encode_length("www.example.com"), 12);
        // C.4.2 cache-control: no-cache → "no-cache" 6 字节（a8eb 1064 9cbf）
        assert_eq!(huffman_encode_length("no-cache"), 6);
        // C.4.3 custom-key / custom-value → 8 / 9 字节
        assert_eq!(huffman_encode_length("custom-key"), 8);
        assert_eq!(huffman_encode_length("custom-value"), 9);
    }

    /// bd g90ft：base62 字母表的平均压缩率必须与代码里声明的
    /// `AVG_HUFFMAN_BYTES_PER_CHAR_BASE62` 一致（tokenish 目标长度估算的锚）。
    /// 错表（0xb0-0xff 段被拍平成 23、多个小写字母错位）会把均值拉偏。
    #[test]
    fn base62_average_huffman_ratio_matches_declared_constant() {
        let total_bits: u32 =
            CHARSET_BASE62.iter().map(|&c| u32::from(HUFFMAN_BITS[usize::from(c)])).sum();
        let avg = f64::from(total_bits) / CHARSET_BASE62.len() as f64 / 8.0;
        assert!(
            (avg - AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).abs() < 0.01,
            "base62 平均 {avg:.4} B/char 偏离声明常量 {AVG_HUFFMAN_BYTES_PER_CHAR_BASE62}"
        );
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

    /// bd g90ft：按 RFC 7541 Appendix B，`"Ab0"` = A(6)+b(6)+0(5) = 17 bits →
    /// ceil(17/8) = 3 bytes。（旧坏表把 A 写成 10 / b 写成 15 ⇒ 误判 4 bytes——
    /// 这是同一张错表自洽出的一族错误期望。）
    #[test]
    fn huffman_length_mixed_base62_rounding() {
        assert_eq!(HUFFMAN_BITS[usize::from(b'A')], 6);
        assert_eq!(HUFFMAN_BITS[usize::from(b'b')], 6);
        assert_eq!(huffman_encode_length("Ab0"), 3);
    }

    /// bd g90ft：`repeat-x` 的 'X' 是 **8 bit** 码 ⇒ padding 长度 == HPACK 编码长度
    /// （Go 注释原话是 "'X' and 'Z' are assigned an 8 bit code, so HPACK compression
    /// won't change actual padding length"）。旧测试按 7 bits 断言 9 bytes，与错表自洽。
    #[test]
    fn generate_padding_repeat_x() {
        let s = generate_padding(PADDING_METHOD_REPEAT_X, 10);
        assert_eq!(s.len(), 10);
        assert_eq!(s, "XXXXXXXXXX");
        assert_eq!(huffman_encode_length(&s), 10); // 10 chars × 8 bits = 80 bits = 10 bytes
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
        // bd b7vs1 附带：原实现用随机 `generate_tokenish_padding_base62(100)` 去断言
        // `[102,102]`（= 编码长度 ∈ [100,104]），而生成器只保证「编码长度与 target 差 ≤ 容差」
        // ⇒ 抽到 97/98/99 即失败（构造性 flaky）。改为确定性串：huffman 长度可算，
        // 且能区分「用 huffman 字节数」与「用原始字节数」。
        let s = "a".repeat(100); // 'a' 的 HPACK Huffman 码长 5 bit ⇒ 编码后 ~63B ≠ 100B
        let enc = huffman_encode_length(&s) as i32;
        assert!((enc - 100).abs() > VALIDATION_TOLERANCE, "样例须能区分两种口径: enc={enc}");

        // 精确命中编码长度 —— 通过
        assert!(is_padding_valid(&s, enc, enc, PADDING_METHOD_TOKENISH));
        // ±容差边界内 —— 通过
        assert!(is_padding_valid(
            &s,
            enc + VALIDATION_TOLERANCE,
            enc + VALIDATION_TOLERANCE,
            PADDING_METHOD_TOKENISH
        ));
        // 超出容差 —— 不通过
        assert!(!is_padding_valid(
            &s,
            enc + VALIDATION_TOLERANCE + 1,
            enc + VALIDATION_TOLERANCE + 1,
            PADDING_METHOD_TOKENISH
        ));
        // 按**原始字节数**（100）判定本该通过；tokenish 用 huffman 长度 ⇒ 必须不通过
        assert!(
            !is_padding_valid(&s, 100, 100, PADDING_METHOD_TOKENISH),
            "tokenish 须用 huffman 长度"
        );
        // 远离范围 —— 不通过
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
