//! UUIDv4 凭据 id 值面（bd h4bl5 派生件 2）。
//!
//! 四栏归属：
//!
//! - **udf 基件**：`std_ext::id::RandomId`（`random` feature 门后的凭据级 CSPRNG v4：OS `getrandom`
//!   直通、`ver=0100`/`var=10` 位面集中装配、连字形 `Display`/`FromStr` 面、数值面
//!   `as_u128`/`from_u128`）。基件是**透明载体**：`from_u128` 形状不校验、 `from_str` 不校验
//!   `ver`/`var`——位语义按 udf 契约归消费方。
//! - **派生方式**：**组合包装**（newtype 包住基件）+ 位面归一化/严格校验——
//!   正是上句「归消费方」的那一半：本件把 v4 形状提升为类型级不变量。
//! - **xray-frame 派生件**：本件 [`Uuid`]。
//! - **消费点**：`crates/xray-cli/src/commands/tool.rs`（`xray uuid` 无输入路径， Go
//!   `main/commands/all/uuid.go` 的随机 v4）。
//!
//! # 边界语义
//!
//! - **生成**：[`Uuid::new`] 委托基件 `RandomId::new`（失败 fail-closed，无弱熵 回退；early-boot
//!   阻塞语义同基件红线）。
//! - **归一化装配**：任意 `u128`/16 字节 ⇒ 强制 `ver=0100` + `var=10`，其余 122 位
//!   原样；**幂等**（已合规格的值过 [`Uuid::from_u128`] 不变）。
//! - **文本**：`8-4-4-4-12` 小写连字形（36 字节），出=基件 [`Display`](std::fmt::Display)
//!   （禁第二份实现）。
//! - **反向解析**：连字形大小写不敏感；**形状合格但 `ver`/`var` 不合 v4 ⇒ 拒绝**
//!   （[`UuidParseError::NotV4`]）——凭据面禁把 v5/v7 值静默当 v4 用（基件此处
//!   刻意不校验，故校验落本件）。

use std::{fmt, str::FromStr};

use std_ext::id::{IdParseError, RandomId};

/// `ver` 字段（u128 第 76..80 位，RFC 4122 §4.1.1 `0100`）。
const VERSION_MASK: u128 = 0xF << 76;
const VERSION_4: u128 = 0b0100 << 76;
/// `var` 字段（第 62..64 位，RFC 4122 §4.1.1 `10`）。
const VARIANT_MASK: u128 = 0b11 << 62;
const VARIANT_RFC4122: u128 = 0b10 << 62;

/// 位面归一化：强制 v4 版本位 + RFC 4122 变体位，其余 122 位原样。
const fn normalize(raw: u128) -> u128 {
    (raw & !(VERSION_MASK | VARIANT_MASK)) | VERSION_4 | VARIANT_RFC4122
}

/// RFC 4122 v4 唯一 id（凭据/令牌面）。
///
/// 形状由类型保证：任何构造路径出口的 `ver` 恒 `0100`、`var` 恒 `10`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(RandomId);

impl Uuid {
    /// 生成一枚随机 v4（OS CSPRNG 直通；失败 fail-closed，无弱熵回退）。
    ///
    /// # Errors
    ///
    /// OS CSPRNG 不可用（[`RngError`](std_ext::id::RngError) 直通）。
    pub fn new() -> Result<Self, std_ext::id::RngError> {
        RandomId::new().map(Self)
    }

    /// 自任意 128 位装配：**强制** v4 版本位 + 变体位（幂等）。
    #[must_use]
    pub const fn from_u128(raw: u128) -> Self {
        Self(RandomId::from_u128(normalize(raw)))
    }

    /// 自 16 字节（大端 RFC 布局）装配：同样强制位面。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self::from_u128(u128::from_be_bytes(bytes))
    }

    /// 数值面（持久化编码/位面诊断）。
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        self.0.as_u128()
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// 连字形解析错误（两态显式：形状/hex 由基件判，版本面由本件判）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UuidParseError {
    /// `8-4-4-4-12` 形状或 hex 位非法（基件 [`IdParseError`] 直通）。
    Shape(IdParseError),
    /// 形状合格但 `ver`/`var` 不是 RFC 4122 v4（如把 v5/v7 值当凭据用）。
    NotV4 {
        /// 实际版本 nibble。
        version: u8,
        /// 实际变体两位（`0b10` = RFC 4122）。
        variant: u8,
    },
}

impl fmt::Display for UuidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(err) => write!(f, "invalid uuid text: {err}"),
            Self::NotV4 { version, variant } => write!(
                f,
                "expected RFC 4122 v4 (ver=4, var=10), got ver={version} var={variant:02b}"
            ),
        }
    }
}

impl std::error::Error for UuidParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Shape(err) => Some(err),
            Self::NotV4 { .. } => None,
        }
    }
}

impl From<IdParseError> for UuidParseError {
    fn from(err: IdParseError) -> Self {
        Self::Shape(err)
    }
}

impl FromStr for Uuid {
    type Err = UuidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id: RandomId = s.parse()?;
        let raw = id.as_u128();
        let version = ((raw >> 76) & 0xF) as u8;
        let variant = ((raw >> 62) & 0b11) as u8;
        if version != 4 || variant != 0b10 {
            return Err(UuidParseError::NotV4 { version, variant });
        }
        Ok(Self(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 位面：`ver=0100`（u128 第 76..80 位）、`var=10`（第 62..64 位）。
    fn assert_v4_bits(u: Uuid) {
        let raw = u.as_u128();
        assert_eq!((raw >> 76) & 0xF, 4, "ver 必须 0100: {u}");
        assert_eq!((raw >> 62) & 0b11, 0b10, "var 必须 10: {u}");
    }

    #[test]
    fn generated_ids_are_rfc4122_v4() {
        // 体量采样：弱熵/位面写错在千枚上必现（单枚靠运气过）。
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let u = Uuid::new().expect("OS CSPRNG");
            assert_v4_bits(u);
            let s = u.to_string();
            assert_eq!(s.len(), 36, "连字形 8-4-4-4-12：{s}");
            assert_eq!(&s[14..15], "4", "文本第 14 位即版本 nibble：{s}");
            assert!(matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b'), "var nibble：{s}");
            assert_eq!(s, s.to_lowercase(), "输出必须小写：{s}");
            assert!(seen.insert(u), "v4 采样撞值 = 熵面异常");
        }
    }

    #[test]
    fn from_u128_forces_v4_and_variant_bits() {
        let all_ones = Uuid::from_u128(u128::MAX);
        assert_v4_bits(all_ones);
        let zero = Uuid::from_u128(0);
        assert_v4_bits(zero);
        assert_ne!(zero.as_u128(), 0, "var 位被强制置 10");
    }

    #[test]
    fn from_bytes_matches_from_u128() {
        let bytes = [0xABu8; 16];
        assert_eq!(Uuid::from_bytes(bytes), Uuid::from_u128(u128::from_be_bytes(bytes)));
        assert_v4_bits(Uuid::from_bytes(bytes));
    }

    #[test]
    fn normalization_is_idempotent() {
        let once = Uuid::from_u128(u128::MAX);
        let twice = Uuid::from_u128(once.as_u128());
        assert_eq!(once, twice);
    }

    #[test]
    fn text_roundtrip() {
        let u = Uuid::new().expect("OS CSPRNG");
        let s = u.to_string();
        assert_eq!(Uuid::from_str(&s).expect("parse own output"), u);
        assert_eq!(Uuid::from_str(&s.to_uppercase()).expect("大小写不敏感"), u);
    }

    #[test]
    fn parse_rejects_non_v4_shape() {
        // v7 连字形（ver=0111、var=10）：形状合格但不是凭据 v4，必须硬拒。
        // 注意不能用 `Uuid::from_u128` 造——本件的装配面**强制**归一化回 v4。
        let v7_text = "018f9c3e-7a2b-7c4d-8e5f-0123456789ab";
        let err = Uuid::from_str(v7_text).expect_err("v7 必须被拒");
        assert!(matches!(err, UuidParseError::NotV4 { version: 7, .. }), "错误类别显式：{err:?}");
    }

    #[test]
    fn parse_rejects_malformed() {
        let err = Uuid::from_str("not-a-uuid").expect_err("乱串必须失败");
        assert!(matches!(err, UuidParseError::Shape(_)), "错误类别显式：{err:?}");
    }
}
