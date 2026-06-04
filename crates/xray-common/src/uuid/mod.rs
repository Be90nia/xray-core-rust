//! UUID 生成与解析
//!
//! 自定义 UUID 类型，使用 `[u8; 16]` 存储，不依赖外部 uuid crate。
//! 对应 Go 版本 `common/uuid` 包。

use std::fmt;

use rand::RngCore;

/// 自定义 UUID 类型，基于 16 字节数组存储。
///
/// 对应 Go 版本的 `uuid.UUID`，支持 v4 随机生成和标准格式解析。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UUID([u8; 16]);

impl UUID {
    /// 生成随机 v4 UUID。
    ///
    /// 使用 `rand` crate 填充随机字节，并设置 v4 版本位和变体位。
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        // 设置版本号为 v4 (0100)
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        // 设置变体为 RFC 4122 (10xx)
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Self(bytes)
    }

    /// 从 16 字节数组创建 UUID。
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 返回内部字节切片。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// 消费自身，返回内部字节数组。
    #[must_use]
    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    /// 解析标准 UUID 字符串（xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx）。
    ///
    /// 支持带连字符和不带连字符的格式。
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let byte_str = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// 派生命令密钥。
    ///
    /// 当前使用 XOR 折叠作为占位实现。
    /// TODO: 替换为 MD5(UUID.String()) 以匹配 Go 版本行为。
    #[must_use]
    pub fn cmd_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        // XOR 折叠：每 4 字节块异或到前 4 字节位置，然后循环
        for i in 0..16 {
            key[i % 4] ^= self.0[i];
        }
        // 用 UUID 的后半部分再次混合
        for i in 0..16 {
            key[4 + (i % 4)] ^= self.0[i];
            key[8 + (i % 4)] ^= self.0[i].wrapping_mul(17);
            key[12 + (i % 4)] ^= self.0[i].wrapping_mul(31);
        }
        key
    }
}

impl fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl std::str::FromStr for UUID {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("invalid UUID string: {s}"))
    }
}

impl AsRef<[u8]> for UUID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_generates_valid_v4() {
        let uuid = UUID::new();
        let b = uuid.as_bytes();
        // 版本号应为 v4 (高 4 位 = 0x4)
        assert_eq!(b[6] & 0xF0, 0x40, "version bits should be 0x4x");
        // 变体应为 RFC 4122 (高 2 位 = 10)
        assert_eq!(b[8] & 0xC0, 0x80, "variant bits should be 10xx");
    }

    #[test]
    fn test_new_unique() {
        let a = UUID::new();
        let b = UUID::new();
        assert_ne!(a, b, "two random UUIDs should differ");
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let uuid = UUID::from_bytes(bytes);
        assert_eq!(*uuid.as_bytes(), bytes);
        assert_eq!(uuid.into_bytes(), bytes);
    }

    #[test]
    fn test_parse_with_hyphens() {
        let uuid = UUID::parse("01234567-89ab-cdef-fedc-ba9876543210").expect("parse should succeed");
        assert_eq!(uuid.as_bytes()[0], 0x01);
        assert_eq!(uuid.as_bytes()[15], 0x10);
    }

    #[test]
    fn test_parse_without_hyphens() {
        let uuid = UUID::parse("0123456789abcdeffedcba9876543210").expect("parse should succeed");
        assert_eq!(uuid.as_bytes()[0], 0x01);
        assert_eq!(uuid.as_bytes()[15], 0x10);
    }

    #[test]
    fn test_parse_invalid_length() {
        assert!(UUID::parse("01234567").is_none());
        assert!(UUID::parse("").is_none());
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!(UUID::parse("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_none());
    }

    #[test]
    fn test_display_format() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let uuid = UUID::from_bytes(bytes);
        assert_eq!(format!("{uuid}"), "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn test_from_str_valid() {
        let uuid: UUID = "01234567-89ab-cdef-fedc-ba9876543210".parse().expect("parse");
        assert_eq!(uuid.as_bytes()[0], 0x01);
    }

    #[test]
    fn test_from_str_invalid() {
        let result: Result<UUID, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_key_deterministic() {
        let uuid = UUID::new();
        let key1 = uuid.cmd_key();
        let key2 = uuid.cmd_key();
        assert_eq!(key1, key2, "cmd_key should be deterministic for same UUID");
    }

    #[test]
    fn test_cmd_key_different_for_different_uuids() {
        let a = UUID::new();
        let b = UUID::new();
        assert_ne!(a.cmd_key(), b.cmd_key());
    }

    #[test]
    fn test_clone() {
        let uuid = UUID::new();
        let cloned = uuid.clone();
        assert_eq!(uuid, cloned);
    }

    #[test]
    fn test_equality() {
        let bytes = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xFF, 0xEE,
        ];
        let a = UUID::from_bytes(bytes);
        let b = UUID::from_bytes(bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn test_as_ref() {
        let uuid = UUID::new();
        let slice: &[u8] = uuid.as_ref();
        assert_eq!(slice.len(), 16);
    }

    #[test]
    fn test_parse_display_roundtrip() {
        let original = UUID::new();
        let display = format!("{original}");
        let parsed = UUID::parse(&display).expect("roundtrip parse");
        assert_eq!(original, parsed);
    }
}
