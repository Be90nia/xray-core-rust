//! Mask 地址解析与 IP 掩码替换。
//!
//! 对应 Go `app/log/log.go` 的 `ParseMaskAddress` 与 `MaskedMsgWrapper.String`。

use std::sync::LazyLock;
use regex::Regex;

use crate::error::LogError;

/// 解析 mask 配置字符串。
///
/// 支持格式：
/// - `""` → 不掩码（mask4=32, mask6=128，原样输出）
/// - `"full"` → 全部掩码（mask4=0, mask6=0）
/// - `"half"` → mask4=16, mask6=32
/// - `"quarter"` → mask4=8, mask6=16
/// - `"16+64"` → mask4=16, mask6=64
/// - `"/16//64"` → mask4=16, mask6=64（前缀斜杠容忍）
///
/// mask4 必须 ∈ [0, 32] 且整除 8；mask6 必须 ∈ [0, 128]。
/// 返回 `(mask4, mask6)`，校验失败时返回完整掩码 (32, 128) + Err。
pub fn parse_mask_address(spec: &str) -> Result<(i32, i32), LogError> {
    let (m4, m6): (i32, i32) = match spec {
        "" => return Ok((32, 128)),
        "half" => (16, 32),
        "quarter" => (8, 16),
        "full" => (0, 0),
        _ => {
            let parts: Vec<&str> = spec.split('+').collect();
            if parts.is_empty() {
                return Ok((32, 128));
            }
            let mut local_m4: i32 = 0;
            let mut local_m6: i32 = 0;
            if let Some(first) = parts.first() {
                if !first.is_empty() {
                    let s = first.strip_prefix('/').unwrap_or(first);
                    local_m4 = s.parse().map_err(|_| {
                        LogError::InvalidMaskAddress(format!("invalid ipv4 mask: {spec}"))
                    })?;
                }
            }
            if parts.len() >= 2 {
                let s2 = parts[1];
                if !s2.is_empty() {
                    let s = s2.strip_prefix('/').unwrap_or(s2);
                    local_m6 = s.parse().map_err(|_| {
                        LogError::InvalidMaskAddress(format!("invalid ipv6 mask: {spec}"))
                    })?;
                }
            }
            (local_m4, local_m6)
        }
    };

    if m4 < 0 || m4 > 32 || m4 % 8 != 0 {
        return Err(LogError::InvalidIpv4Mask(m4));
    }
    if m6 < 0 || m6 > 128 {
        return Err(LogError::InvalidIpv6Mask(m6));
    }

    Ok((m4, m6))
}

static IPV4_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d{1,3}\.){3}\d{1,3}").unwrap());

static IPV6_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}){2,7}").unwrap());

/// 对输入字符串中的 IPv4 / IPv6 地址做掩码处理。
///
/// - `mask4 == 32`：IPv4 原样保留。
/// - `mask4 == 0`：IPv4 替换为 `[Masked IPv4]`。
/// - 其他：保留前 `mask4/8` 段，剩余替换为 `*`。
///
/// - `mask6 == 128`：IPv6 原样保留。
/// - `mask6 == 0`：IPv6 替换为 `Masked IPv6`。
/// - 其他：用 `CIDRMask(mask6, 128)` 计算，返回 `masked_ip/mask6`。
pub fn mask_addresses(input: &str, mask4: i32, mask6: i32) -> String {
    let after_v4 = IPV4_REGEX.replace_all(input, |caps: &regex::Captures| {
        let s = &caps[0];
        if mask4 == 32 {
            return s.to_string();
        }
        if mask4 == 0 {
            return "[Masked IPv4]".to_string();
        }
        let mut parts: Vec<String> = s.split('.').map(|x| x.to_string()).collect();
        let start = (mask4 / 8) as usize;
        for p in parts.iter_mut().skip(start) {
            *p = "*".to_string();
        }
        parts.join(".")
    });

    let after_v6 = IPV6_REGEX.replace_all(&after_v4, |caps: &regex::Captures| {
        let s = &caps[0];
        if mask6 == 128 {
            return s.to_string();
        }
        if mask6 == 0 {
            return "Masked IPv6".to_string();
        }
        // IPv6 应用掩码：解析为 Ipv6Addr，按 mask6 计算网络地址
        if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
            let octets = ip.octets();
            let masked = apply_ipv6_mask(&octets, mask6 as u32);
            let masked_ip = std::net::Ipv6Addr::from(masked);
            format!("{masked_ip}/{mask6}")
        } else {
            s.to_string()
        }
    });

    after_v6.into_owned()
}

/// 对 IPv6 8 字节 octets 按 mask6 bits 计算网络地址。
fn apply_ipv6_mask(octets: &[u8; 16], mask6: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let full_bytes = (mask6 / 8) as usize;
    let remainder_bits = mask6 % 8;

    for (i, b) in octets.iter().enumerate() {
        if i < full_bytes {
            out[i] = *b;
        } else if i == full_bytes && remainder_bits != 0 {
            let mask = (0xff_u8).checked_shl(8 - remainder_bits).unwrap_or(0);
            out[i] = *b & mask;
        } else {
            out[i] = 0;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_returns_full() {
        assert_eq!(parse_mask_address("").unwrap(), (32, 128));
    }

    #[test]
    fn parse_half() {
        assert_eq!(parse_mask_address("half").unwrap(), (16, 32));
    }

    #[test]
    fn parse_quarter() {
        assert_eq!(parse_mask_address("quarter").unwrap(), (8, 16));
    }

    #[test]
    fn parse_full() {
        assert_eq!(parse_mask_address("full").unwrap(), (0, 0));
    }

    #[test]
    fn parse_explicit_form() {
        assert_eq!(parse_mask_address("16+64").unwrap(), (16, 64));
    }

    #[test]
    fn parse_slash_prefixed() {
        // 前缀 / 容忍
        assert_eq!(parse_mask_address("/16+/96").unwrap(), (16, 96));
    }

    #[test]
    fn parse_invalid_v4_not_divisible() {
        assert!(parse_mask_address("7+64").is_err());
    }

    #[test]
    fn parse_invalid_v4_out_of_range() {
        assert!(parse_mask_address("40+64").is_err());
    }

    #[test]
    fn parse_invalid_v6_out_of_range() {
        assert!(parse_mask_address("16+200").is_err());
    }

    #[test]
    fn parse_negative_v4_rejected() {
        // "-8" 会被 split 解析为 i32 = -8，校验失败
        assert!(parse_mask_address("-8+64").is_err());
    }

    #[test]
    fn parse_only_v4() {
        // 只有 ipv4 mask，ipv6 默认 0
        assert_eq!(parse_mask_address("16").unwrap(), (16, 0));
    }

    #[test]
    fn mask_v4_full_keep() {
        let s = mask_addresses("from 192.168.1.1", 32, 128);
        assert!(s.contains("192.168.1.1"));
    }

    #[test]
    fn mask_v4_full_mask() {
        let s = mask_addresses("from 192.168.1.1", 0, 128);
        assert!(s.contains("[Masked IPv4]"));
        assert!(!s.contains("192.168.1.1"));
    }

    #[test]
    fn mask_v4_half() {
        let s = mask_addresses("from 192.168.1.1", 16, 128);
        assert!(s.contains("192.168.*.*"));
    }

    #[test]
    fn mask_v4_quarter() {
        let s = mask_addresses("from 192.168.1.1", 8, 128);
        assert!(s.contains("192.*.*.*"));
    }

    #[test]
    fn mask_v6_full_keep() {
        let s = mask_addresses("from 2001:db8::1", 32, 128);
        assert!(s.contains("2001:db8::1"));
    }

    #[test]
    fn mask_v6_full_mask() {
        let s = mask_addresses("from 2001:db8::1", 32, 0);
        assert!(s.contains("Masked IPv6"));
    }

    #[test]
    fn mask_v6_partial() {
        // 32 位前缀：保留 2001:db8:0:0:0:0:0:0/32
        let s = mask_addresses("from 2001:db8::1", 32, 32);
        assert!(s.contains("/32"));
        assert!(s.contains("2001:db8::"));
    }

    #[test]
    fn mask_v6_with_v4_combined() {
        let s = mask_addresses("192.168.1.1 and 2001:db8::1", 16, 32);
        assert!(s.contains("192.168.*.*"));
        assert!(s.contains("/32"));
    }

    #[test]
    fn mask_v6_invalid_kept_as_is() {
        // "abc:def" 不是合法 IPv6，应保留原样
        let s = mask_addresses("looks like abc:def", 32, 32);
        assert!(s.contains("abc:def"));
    }

    #[test]
    fn mask_no_ip_passthrough() {
        let s = mask_addresses("hello world no ip", 16, 32);
        assert_eq!(s, "hello world no ip");
    }

    #[test]
    fn ipv6_octet_mask_helper() {
        let octets: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let masked = apply_ipv6_mask(&octets, 32);
        // 前 4 字节保留，后面清零
        assert_eq!(&masked[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(&masked[4..], &[0u8; 12][..]);
    }
}
