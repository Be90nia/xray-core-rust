//! 加密层共享常量与纯协议格式编解码（无 IO 依赖）。
//!
//! 对应 Go `proxy/vless/encryption/common.go` 中可独立测试的部分：
//! - TLS 1.3 record header 编解码（5B：`[23,3,3,len_hi,len_lo]`，长度 17~16640）
//! - 2B BE 长度字段编解码（对应 Go `EncodeLength`/`DecodeLength`）
//! - padding 配置解析（完整实现 Go `ParsePadding`：`a-b-c.d-e-f` 三元组 + 约束校验）
//!
//! nonce 递增逻辑（小端，对齐 Go `IncreaseNonce`）见 [`super::aead`]。

use crate::error::{Result, VlessError};

/// TLS 1.3 Application Data record type byte (0x17 = 23)。
pub const TLS_RECORD_TYPE_APP_DATA: u8 = 23;

/// TLS 1.3 legacy_version 高字节 (0x03)。
pub const TLS_LEGACY_VERSION_HIGH: u8 = 3;

/// TLS 1.3 legacy_version 低字节 (0x03)。
pub const TLS_LEGACY_VERSION_LOW: u8 = 3;

/// TLS record header 总长度（5 字节：type + version_hi + version_lo + len_hi + len_lo）。
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// TLS record 载荷长度下限（对应 Go `DecodeHeader` 的 17）。
pub const TLS_PAYLOAD_MIN: u16 = 17;

/// TLS record 载荷长度上限（16384 + 256，RFC 8446 §5.2，对应 Go `16640`）。
pub const TLS_PAYLOAD_MAX: u16 = 16640;

/// 把 5 字节 TLS 1.3 record header 写入 `out`（对应 Go `EncodeHeader`）。
///
/// # Panics
/// `out.len() < 5` 时 panic（debug 断言）。
pub fn write_tls_record_header(out: &mut [u8], payload_len: u16) {
    assert!(out.len() >= TLS_RECORD_HEADER_LEN, "tls header buffer too short");
    out[0] = TLS_RECORD_TYPE_APP_DATA;
    out[1] = TLS_LEGACY_VERSION_HIGH;
    out[2] = TLS_LEGACY_VERSION_LOW;
    let bytes = payload_len.to_be_bytes();
    out[3] = bytes[0];
    out[4] = bytes[1];
}

/// 解码 5 字节 TLS 1.3 record header（对应 Go `DecodeHeader`）。
///
/// 校验 `[23,3,3]` 前缀 + 载荷长度在 `TLS_PAYLOAD_MIN..=TLS_PAYLOAD_MAX` 范围。
///
/// # Errors
/// 前缀错误或长度越界返回 [`VlessError::Other`]（消息格式对齐 Go `"invalid header: ..."`）。
pub fn decode_tls_record_header(header: &[u8; TLS_RECORD_HEADER_LEN]) -> Result<u16> {
    let len = u16::from_be_bytes([header[3], header[4]]);
    let prefix_ok = header[0] == TLS_RECORD_TYPE_APP_DATA
        && header[1] == TLS_LEGACY_VERSION_HIGH
        && header[2] == TLS_LEGACY_VERSION_LOW;
    let range_ok = (TLS_PAYLOAD_MIN..=TLS_PAYLOAD_MAX).contains(&len);
    if !prefix_ok || !range_ok {
        return Err(VlessError::Other(format!(
            "invalid header: {header:?}"
        )));
    }
    Ok(len)
}

/// 2B BE 长度编码（对应 Go `EncodeLength`）。
pub fn encode_length_be(out: &mut Vec<u8>, len: u16) {
    out.extend_from_slice(&len.to_be_bytes());
}

/// 从 `bytes` 解码 2B BE 长度，返回 (剩余字节, 长度)（对应 Go `DecodeLength`）。
///
/// # Errors
/// 字节不足 2 返回 [`VlessError::Other`]。
pub fn decode_length_be(bytes: &[u8]) -> Result<(&[u8], u16)> {
    if bytes.len() < 2 {
        return Err(VlessError::Other(
            "decode_length_be: buffer too short".into(),
        ));
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]);
    Ok((&bytes[2..], len))
}

/// padding 配置三元组：`(base, min, max)`，对应 Go `PaddingLens [3]int`。
pub type PaddingTriple = [u32; 3];

/// 解析 padding 配置字符串（对应 Go `ParsePadding`）。
///
/// 格式：`"a-b-c.d-e-f"`，以 `.` 分隔多个三元组，每个三元组用 `-` 分隔 3 个非负整数。
/// - 偶数 index（0,2,...）→ paddingLens
/// - 奇数 index（1,3,...）→ paddingGaps
///
/// 约束：
/// - 每个三元组必须有 3 个非空数字
/// - 第一个三元组必须 `base>=100 && min>=35 && max>=35`（Go 写作 `18+17`）
/// - 所有 lens 的 `max(min, max)` 之和 ≤ `18+65535 = 65553`
///
/// # Errors
/// 格式错误、数字解析失败、约束未满足 → [`VlessError::Other`]（消息对齐 Go）。
pub fn parse_padding(padding: &str) -> Result<(Vec<PaddingTriple>, Vec<PaddingTriple>)> {
    if padding.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    let mut max_len_total = 0u32;

    for (i, segment) in padding.split('.').enumerate() {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(VlessError::Other(format!(
                "invalid padding lenth/gap parameter: {segment}"
            )));
        }
        let parse_part = |s: &str| -> Result<u32> {
            s.parse::<u32>().map_err(|_| {
                VlessError::Other(format!("invalid padding number: {s}"))
            })
        };
        let y: PaddingTriple = [parse_part(parts[0])?, parse_part(parts[1])?, parse_part(parts[2])?];

        // 第一个三元组最小值约束（Go: y[0]<100 || y[1]<18+17 || y[2]<18+17）
        if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
            return Err(VlessError::Other(
                "first padding length must not be smaller than 35".into(),
            ));
        }

        if i % 2 == 0 {
            max_len_total += y[1].max(y[2]);
            lens.push(y);
        } else {
            gaps.push(y);
        }
    }

    if max_len_total > 18 + 65535 {
        return Err(VlessError::Other(
            "total padding length must not be larger than 65553".into(),
        ));
    }

    Ok((lens, gaps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_record_header_layout() {
        let mut buf = [0u8; 5];
        write_tls_record_header(&mut buf, 0x1234);
        assert_eq!(buf, [23, 3, 3, 0x12, 0x34]);
    }

    #[test]
    fn tls_record_header_max_len() {
        let mut buf = [0u8; 5];
        write_tls_record_header(&mut buf, u16::MAX);
        assert_eq!(buf, [23, 3, 3, 0xFF, 0xFF]);
    }

    #[test]
    fn decode_tls_record_header_valid() {
        let buf = [23, 3, 3, 0x01, 0x11]; // len = 0x0111 = 273
        assert_eq!(decode_tls_record_header(&buf).unwrap(), 273);
    }

    #[test]
    fn decode_tls_record_header_min_boundary() {
        let buf = [23, 3, 3, 0x00, 17]; // len = 17 (min)
        assert_eq!(decode_tls_record_header(&buf).unwrap(), 17);
    }

    #[test]
    fn decode_tls_record_header_max_boundary() {
        let buf = [23, 3, 3, 0x41, 0x00]; // len = 0x4100 = 16640 (max)
        assert_eq!(decode_tls_record_header(&buf).unwrap(), 16640);
    }

    #[test]
    fn decode_tls_record_header_bad_prefix() {
        let buf = [24, 3, 3, 0x01, 0x11]; // type != 23
        assert!(decode_tls_record_header(&buf).is_err());
    }

    #[test]
    fn decode_tls_record_header_too_short() {
        let buf = [23, 3, 3, 0x00, 16]; // len = 16 < 17
        assert!(decode_tls_record_header(&buf).is_err());
    }

    #[test]
    fn decode_tls_record_header_too_long() {
        let buf = [23, 3, 3, 0x41, 0x01]; // len = 16641 > 16640
        assert!(decode_tls_record_header(&buf).is_err());
    }

    #[test]
    fn encode_decode_length_be_round_trip() {
        let mut buf = Vec::new();
        encode_length_be(&mut buf, 0xABCD);
        assert_eq!(buf, vec![0xAB, 0xCD]);

        let (rest, len) = decode_length_be(&buf).unwrap();
        assert_eq!(len, 0xABCD);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_length_be_too_short_rejected() {
        let one_byte = [0u8; 1];
        let err = decode_length_be(&one_byte).unwrap_err();
        match err {
            VlessError::Other(msg) => assert!(msg.contains("too short")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn parse_padding_empty_returns_default() {
        let (lens, gaps) = parse_padding("").unwrap();
        assert!(lens.is_empty());
        assert!(gaps.is_empty());
    }

    #[test]
    fn parse_padding_single_triplet_to_lens() {
        // 单个三元组（i=0，偶数）→ lens[0]，gaps 为空
        let (lens, gaps) = parse_padding("100-200-300").unwrap();
        assert_eq!(lens, vec![[100, 200, 300]]);
        assert!(gaps.is_empty());
    }


    #[test]
    fn parse_padding_segment_extra_parts_ignored() {
        // Go 只取 parts[0..3]，多余 part 忽略（对应 Go `len(x) < 3` 检查只跳过不足，不限上限）
        let (lens, gaps) = parse_padding("100-200-300-150-250-350").unwrap();
        assert_eq!(lens, vec![[100, 200, 300]]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn parse_padding_multi_segments_split_by_dot() {
        // 正确多 segment 格式："a-b-c.d-e-f"
        // i=0（偶）→ lens，i=1（奇）→ gaps
        let (lens, gaps) = parse_padding("100-200-300.400-500-600").unwrap();
        assert_eq!(lens, vec![[100, 200, 300]]);
        assert_eq!(gaps, vec![[400, 500, 600]]);
    }

    #[test]
    fn parse_padding_first_triplet_min_35_enforced() {
        // 第一个三元组必须 base>=100 && min>=35 && max>=35
        assert!(parse_padding("99-200-300").is_err(), "base < 100 应拒绝");
        assert!(parse_padding("100-34-300").is_err(), "min < 35 应拒绝");
        assert!(parse_padding("100-200-34").is_err(), "max < 35 应拒绝");
    }

    #[test]
    fn parse_padding_too_few_parts_rejected() {
        assert!(parse_padding("100-200").is_err());
        assert!(parse_padding("100").is_err());
    }

    #[test]
    fn parse_padding_empty_part_rejected() {
        // "100--300" 中间空 part 应拒绝
        assert!(parse_padding("100--300").is_err());
        assert!(parse_padding("-200-300").is_err());
    }

    #[test]
    fn parse_padding_non_numeric_rejected() {
        assert!(parse_padding("abc-200-300").is_err());
        assert!(parse_padding("100-2xx-300").is_err());
    }

    #[test]
    fn parse_padding_total_length_overflow_rejected() {
        // 单 segment 的 max(y[1], y[2]) 不能超过 65553
        // 设 lens[0] = 100-65534-65534 → max_len_total=65534 ≤ 65553 通过
        let (lens, _) = parse_padding("100-65534-65534").unwrap();
        assert_eq!(lens[0], [100, 65534, 65534]);
        // 65555 > 65553 应拒绝
        assert!(parse_padding("100-65555-65555").is_err());
    }

    #[test]
    fn parse_padding_invalid_segment_rejected_with_message() {
        let err = parse_padding("100-200").unwrap_err();
        match err {
            VlessError::Other(msg) => assert!(msg.contains("invalid padding")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }
}
