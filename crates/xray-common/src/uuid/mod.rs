//! UUID 生成与解析
//!
//! 自定义 UUID 类型，使用 `[u8; 16]` 存储，不依赖外部 uuid crate。
//! 对应 Go 版本 `common/uuid` 包。

use std::fmt;

/// cmd_key KDF 盐。Go `common/protocol/id.go` 的 `NewID` 里内联的字符串常量。
const CMD_KEY_SALT: &[u8; 36] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// 自定义 UUID 类型，基于 16 字节数组存储。
///
/// 对应 Go 版本的 `uuid.UUID`，支持 v4 随机生成和标准格式解析。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UUID([u8; 16]);

// Debug 脱敏：UUID 即 VLESS/VMess 认证凭据，禁止经 derive(Debug) 进入
// tracing/panic 输出（安全审计红线：含密码/UUID 的 struct 不得 derive Debug）。
impl fmt::Debug for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UUID([REDACTED])")
    }
}

impl Default for UUID {
    /// 随机 v4 UUID，与 [`UUID::new`] 一致（对齐 Go `uuid.New` 随机语义）。
    fn default() -> Self {
        Self::new()
    }
}

impl UUID {
    /// 生成随机 v4 UUID。
    ///
    /// 直接委托 udf 基件 [`std_ext::id::RandomId`]（bd h4bl5 派生件 2 的底座——OS getrandom
    /// CSPRNG、失败 fail-closed、ver/var 位面在基件内装配），本仓不再有第二套 v4
    /// 生成器（audit ARCH-06），也不经装配层 `xray_frame::uuid`（bd vqvn1 NEW-01：
    /// 底层工具 crate 不得反向依赖装配层）。
    /// 失败 panic 对齐 Go `uuid.New` 的 `Must` 语义（CSPRNG 不可用 = 环境坏，
    /// 静默降级弱熵禁），本仓既有 `UUID::new` 签名（无 `Result`）保持不变。
    #[must_use]
    pub fn new() -> Self {
        let id = std_ext::id::RandomId::new()
            .expect("uuid: OS CSPRNG unavailable (fail-closed; Go uuid.New Must() parity)");
        Self(id.as_u128().to_be_bytes())
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

    /// 解析 UUID 字符串（Go `ParseString` 完整语义）。
    ///
    /// - 标准格式（32-36 字符，带/不带连字符）：直接解析。
    /// - 1-30 字节非 UUID 文本：`SHA1(零UUID || text)[:16]` 派生 UUIDv5 （VLESS/VMess 自定义用户 ID
    ///   路径，`uuid -i` 同源）。
    /// - 空或 >30 字节且非标准格式：`None`。
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if s.len() >= 32 && s.len() <= 36 && hex.len() == 32 {
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
            }
            return Some(Self(bytes));
        }
        // Go uuid.go:71-82：短文本 → SHA1(zero_uuid || text)[:16]，设 v5 version + RFC4122
        // variant。
        let text = s.as_bytes();
        if text.is_empty() || text.len() > 30 {
            return None;
        }
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update([0u8; 16]);
        h.update(text);
        let sum = h.finalize();
        let mut u: [u8; 16] = sum[..16].try_into().expect("sha1 sum >= 16");
        u[6] = (u[6] & 0x0f) | (5 << 4);
        u[8] = (u[8] & (0xff >> 2)) | (0x02 << 6);
        Some(Self(u))
    }

    /// 派生命令密钥（cmd_key）。
    ///
    /// 对应 Go `common/protocol/id.go` 的 `NewID`：
    /// `md5(uuid.Bytes() || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`。
    /// 与 VMess/VLESS protocol cmd_key 保持 1:1 与 Go 版互通。
    ///
    /// 注意：Go `common/uuid` 包里**没有** `CmdKey` 方法，公式只存在于
    /// `protocol.NewID`；此处是同一公式的唯一实现，禁用「md5(带横线字符串)」变体
    /// （bd gv7gk：那会让 `protocol::ID::cmd_key` 与 VMess 线上值不符）。
    #[must_use]
    pub fn cmd_key(&self) -> [u8; 16] {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(self.0);
        hasher.update(CMD_KEY_SALT);
        hasher.finalize().into()
    }
}

impl fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
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
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let uuid = UUID::from_bytes(bytes);
        assert_eq!(*uuid.as_bytes(), bytes);
        assert_eq!(uuid.into_bytes(), bytes);
    }

    #[test]
    fn test_parse_with_hyphens() {
        let uuid =
            UUID::parse("01234567-89ab-cdef-fedc-ba9876543210").expect("parse should succeed");
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
        // Go ParseString 语义：空串/31 字节非法；1-30 字节短文本派生 v5。
        assert!(UUID::parse("").is_none());
        assert!(UUID::parse("0123456789012345678901234567890").is_none()); // 31 字节
    }

    #[test]
    fn test_parse_short_text_derives_v5() {
        // 对拍 Go：uuid.ParseString("example") = feb54431-301b-52bb-a6dd-e1e93e81bb9e
        let u = UUID::parse("example").expect("short text derives v5");
        assert_eq!(u.to_string(), "feb54431-301b-52bb-a6dd-e1e93e81bb9e");
        // version = 5, variant = RFC4122
        assert_eq!(u.as_bytes()[6] >> 4, 5);
        assert_eq!(u.as_bytes()[8] >> 6, 0b10);
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!(UUID::parse("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_none());
    }

    #[test]
    fn test_display_format() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
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
        // "invalid" 是 7 字节短文本——Go 语义下派生 v5，不再是 Err。
        // 真正非法：>30 字节非标准格式。
        let result: Result<UUID, _> = "this-string-is-longer-than-30bytes!!".parse();
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
    fn test_cmd_key_matches_go_newid_formula() {
        // Go common/protocol/id.go NewID：
        // md5(uuid.Bytes() || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
        // 向量由 Go 公式独立复算：b831381d-6324-4d53-ad4f-8cda48b30811
        let uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = uuid.cmd_key();
        let expected: [u8; 16] = [
            0xb5, 0x0d, 0x91, 0x6a, 0xc0, 0xce, 0xc0, 0x67, 0x98, 0x1a, 0xf8, 0xe5, 0xf3, 0x8a,
            0x75, 0x8f,
        ];
        assert_eq!(key, expected, "cmd_key must match Go NewID(md5(bytes||salt))");
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
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xFF, 0xEE,
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
