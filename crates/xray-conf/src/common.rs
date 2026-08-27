//! 配置层基础类型：地址、端口、字符串列表。
//!
//! 这些类型对应 Go `infra/conf/common.go` 与 `infra/conf/xray.go` 中的 JSON 反序列化类型。
//! 关注点是「从配置文件解析」，运行时转换（→ `xray_common::net::Address`）留给后续 Build 阶段。

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;


// =========================================================================
// Address —— 配置层地址字符串
// =========================================================================

/// 配置层地址，保留原始字符串形式。
///
/// 对应 Go `infra/conf.Address`。支持 IP / Domain / Unix socket 路径。
/// 为什么不用 `xray_common::net::Address`：那是运行时枚举，不支持 Unix 路径
/// 且无字符串解析语义。conf 层先保留原始输入，Build 时再解析分类。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Address(pub String);

impl Address {
    /// 从任何字符串输入构造。
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// 取底层字符串切片。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 是否为绝对路径（Unix domain socket 候选）。
    pub fn is_unix_path(&self) -> bool {
        self.0.starts_with('/') || self.0.starts_with('@')
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for Address {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // JSON 中地址恒为字符串（如 "1.2.3.4" / "example.com"）。
        // "env:VAR" 前缀先展开（Go common.go:59-61）。
        let s = String::deserialize(d)?;
        Ok(Address(expand_env(&s).into_owned()))
    }
}

/// `env:VAR` 前缀展开：读环境变量 VAR（先原名后大写下划线形式），未设置为空串。
///
/// 对应 Go `Address.UnmarshalJSON` / `parseStringPort` 的 env: 处理
/// （common.go:59-61、132-134）+ `platform.NewEnvFlag` 的 Name/AltName 双查。
fn expand_env(s: &str) -> Cow<'_, str> {
    s.strip_prefix("env:").map_or_else(
        || Cow::Borrowed(s),
        |name| {
            Cow::Owned(
                xray_common::platform::env::EnvFlag::new(name)
                    .get_value()
                    .unwrap_or_default()
                    .to_owned(),
            )
        },
    )
}

// =========================================================================
// PortRange / PortList —— 端口范围与端口列表
// =========================================================================

/// 端口范围 [start, end] 闭区间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// 单端口构造（start == end）。
    pub fn single(port: u16) -> Self {
        Self { start: port, end: port }
    }

    /// 端口落在此范围内。
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// 端口列表，支持 Go 的多种 JSON 表示：
/// - `80`（单数字）
/// - `"80"`（单字符串）
/// - `"80,443,1000-2000"`（逗号分隔 + 范围）
/// - `[80, "443", "1000-2000"]`（混合数组）
///
/// 对应 Go `infra/conf.PortList`。字段名 `PortList` 在 Go 中也用于 JSON tag "port"。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PortList(pub Vec<PortRange>);

impl PortList {
    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 端口数（范围按两端闭区间计数）。
    pub fn port_count(&self) -> usize {
        self.0
            .iter()
            .map(|r| (r.end as usize).saturating_sub(r.start as usize) + 1)
            .sum()
    }

    /// 端口是否命中任一范围。
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

impl<'de> Deserialize<'de> for PortList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {

        // 支持 number / string / array 混合输入。
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u16),
            String(String),
            Array(Vec<Raw>),
        }

        fn push_one<E: serde::de::Error>(ranges: &mut Vec<PortRange>, raw: Raw) -> Result<(), E> {
            match raw {
                Raw::Number(n) => ranges.push(PortRange::single(n)),
                Raw::String(s) => {
                    for part in s.split(',') {
                        let part = part.trim();
                        if part.is_empty() {
                            continue;
                        }
                        // "env:VAR" 前缀展开（Go parseStringPort，common.go:132-134）。
                        let expanded = expand_env(part);
                        let part = expanded.as_ref();
                        if let Some((a, b)) = part.split_once('-') {
                            let start: u16 = a.trim().parse().map_err(|e| {
                                E::custom(format!("invalid port start {a:?}: {e}"))
                            })?;
                            let end: u16 = b.trim().parse().map_err(|e| {
                                E::custom(format!("invalid port end {b:?}: {e}"))
                            })?;
                            if start > end {
                                return Err(E::custom(format!(
                                    "port range start {start} > end {end}"
                                )));
                            }
                            ranges.push(PortRange { start, end });
                        } else {
                            let n: u16 = part.parse().map_err(|e| {
                                E::custom(format!("invalid port {part:?}: {e}"))
                            })?;
                            ranges.push(PortRange::single(n));
                        }
                    }
                }
                Raw::Array(items) => {
                    for item in items {
                        push_one::<E>(ranges, item)?;
                    }
                }
            }
            Ok(())
        }

        let raw = Raw::deserialize(d)?;
        let mut ranges = Vec::new();
        push_one::<D::Error>(&mut ranges, raw)?;
        Ok(PortList(ranges))
    }
}

// =========================================================================
// User —— 配置层用户
// =========================================================================

/// 配置层用户（邮箱 + 权限等级）。
///
/// 对应 Go `infra/conf.User`（common.go:277-287）。各协议 inbound 的用户
/// 列表项先解析为此类型，Build 阶段转为运行时 [`xray_common::protocol::User`]。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// 用户邮箱（统计/限速标识）。Go `EmailString`。
    #[serde(default)]
    pub email: String,
    /// 权限等级。Go `LevelByte byte`。
    #[serde(default)]
    pub level: u8,
}

impl User {
    /// 转为运行时协议用户。对应 Go `(*User).Build()`（common.go:282-287）。
    #[must_use]
    pub fn build(&self) -> xray_common::protocol::user::User {
        xray_common::protocol::user::User::new(self.email.clone()).with_level(u32::from(self.level))
    }
}

// =========================================================================
// Int32Range —— "1-2" 或 1 双形态整数区间
// =========================================================================

/// 整数区间，JSON 兼容 `"1-2"`（字符串）与 `1`（纯数字）两种形态。
///
/// 对应 Go `infra/conf.Int32Range`（common.go:289-338）。反序列化后
/// `from <= to` 恒成立（原始顺序保留在 `left`/`right`）；负数可作哨兵值，
/// 也支持负数区间 `"-114-514"` / `"-1919--810"`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Int32Range {
    /// 原始左值。
    pub left: i32,
    /// 原始右值。
    pub right: i32,
    /// 排序后下界（恒 `<= to`）。
    pub from: i32,
    /// 排序后上界（恒 `>= from`）。
    pub to: i32,
}

impl Int32Range {
    /// `from`/`to` 取 `left`/`right` 并保证 `from <= to`。
    /// 对应 Go `ensureOrder`（common.go:332-338）。
    fn ensure_order(&mut self) {
        self.from = self.left;
        self.to = self.right;
        if self.from > self.to {
            std::mem::swap(&mut self.from, &mut self.to);
        }
    }
}

impl fmt::Display for Int32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Go String()（common.go:304-310）：左右相等输出单值，否则 "left-right"。
        if self.left == self.right {
            write!(f, "{}", self.left)
        } else {
            write!(f, "{}-{}", self.left, self.right)
        }
    }
}

impl Serialize for Int32Range {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Go MarshalJSON（common.go:299-302）：序列化为区间字符串。
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Go UnmarshalJSON（common.go:312-330）：字符串（区间语法）优先，纯数字次之。
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Int(i32),
        }

        let mut range = match Raw::deserialize(d) {
            Ok(Raw::Str(s)) => {
                let (left, right) = parse_range_string(&s).map_err(D::Error::custom)?;
                Int32Range {
                    left,
                    right,
                    ..Default::default()
                }
            }
            Ok(Raw::Int(i)) => Int32Range {
                left: i,
                right: i,
                ..Default::default()
            },
            Err(_) => {
                return Err(D::Error::custom(
                    "Invalid integer range, expected either string of form \"1-2\" or plain integer.",
                ));
            }
        };
        range.ensure_order();
        Ok(range)
    }
}

/// 解析区间字符串，支持负数：`"114-514"` `"-114-514"` `"-1919--810"` `"114514"` `""`。
///
/// 对应 Go `ParseRangeString`（common.go:350-377）。单值返回 `(v, v)`，空串返回 `(0, 0)`。
pub fn parse_range_string(s: &str) -> Result<(i32, i32), String> {
    // 纯数字（含负数单值）："114" / "-1"。
    if let Ok(v) = s.parse::<i32>() {
        return Ok((v, v));
    }
    // 空串视为 0（Go common.go:357-359）。
    if s.is_empty() {
        return Ok((0, 0));
    }
    // 区间：负数前缀需从第二个 '-' 切分，否则取第一个 '-'。
    let parsed = if s.starts_with('-') {
        split_from_second_dash(s)
            .and_then(|(l, r)| Some((l.parse::<i32>().ok()?, r.parse::<i32>().ok()?)))
    } else {
        s.split_once('-')
            .and_then(|(l, r)| Some((l.parse::<i32>().ok()?, r.parse::<i32>().ok()?)))
    };
    parsed.ok_or_else(|| format!("invalid range string: {s}"))
}

/// 从第二个 '-' 切分：`"-114-514"` → `("-114", "514")`；`"-1919--810"` → `("-1919", "-810")`。
///
/// 对应 Go `splitFromSecondDash`（common.go:340-348）。不足三段时返回 `None`。
fn split_from_second_dash(s: &str) -> Option<(String, &str)> {
    let mut parts = s.splitn(3, '-');
    let p0 = parts.next()?;
    let p1 = parts.next()?;
    let p2 = parts.next()?;
    Some((format!("{p0}-{p1}"), p2))
}

// =========================================================================
// StringList —— 兼容 string | string[] 的字符串列表
// =========================================================================

/// 字符串列表，兼容 `string` 与 `string[]` 两种 JSON 表示。
///
/// 对应 Go `infra/conf.StringList`。当配置写 `"http"` 时返回单元素列表。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StringList(pub Vec<String>);

impl StringList {
    pub fn new(items: Vec<String>) -> Self {
        Self(items)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Single(String),
            Multi(Vec<String>),
        }

        match Raw::deserialize(d)? {
            Raw::Single(s) => Ok(StringList(vec![s])),
            Raw::Multi(v) => Ok(StringList(v)),
        }
    }
}

impl From<StringList> for Vec<String> {
    fn from(s: StringList) -> Vec<String> {
        s.0
    }
}

// =========================================================================
// Network / NetworkList —— 网络类型（tcp/udp/unix/raw）
// =========================================================================

/// 配置层网络类型。对应 Go `infra/conf.Network`。
///
/// 取值：`"tcp"` / `"udp"` / `"unix"` / `"raw"`。路由规则用此区分流量类型。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Udp,
    Unix,
    Raw,
}

impl Network {
    /// 返回 Go 端小写字符串表示（`"tcp"` / `"udp"` / `"unix"` / `"raw"`）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Unix => "unix",
            Self::Raw => "raw",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 网络列表，兼容 `string`（逗号分隔）与 `string[]` 两种 JSON 表示。
///
/// 对应 Go `infra/conf.NetworkList`。当配置写 `"tcp,udp"` 时解析为两元素列表。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetworkList(pub Vec<Network>);

impl NetworkList {
    pub fn new(items: Vec<Network>) -> Self {
        Self(items)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Network> {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for NetworkList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Single(String),
            Multi(Vec<String>),
        }

        let parse_one = |s: &str| -> Option<Network> {
            match s.trim().to_ascii_lowercase().as_str() {
                "tcp" => Some(Network::Tcp),
                "udp" => Some(Network::Udp),
                "unix" => Some(Network::Unix),
                "raw" => Some(Network::Raw),
                _ => None,
            }
        };

        match Raw::deserialize(d)? {
            Raw::Single(s) => {
                let items = s.split(',').filter_map(|p| parse_one(p)).collect();
                Ok(NetworkList(items))
            }
            Raw::Multi(v) => {
                let items = v.iter().filter_map(|s| parse_one(s)).collect();
                Ok(NetworkList(items))
            }
        }
    }
}

impl From<NetworkList> for Vec<String> {
    fn from(n: NetworkList) -> Vec<String> {
        n.0.iter().map(Network::as_str).map(str::to_string).collect()
    }
}

// =========================================================================
// 测试
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Address -----

    #[test]
    fn address_new_and_as_str() {
        let a = Address::new("example.com");
        assert_eq!(a.as_str(), "example.com");
    }

    #[test]
    fn address_unix_path_detection() {
        assert!(Address::from("/var/run/xray.sock").is_unix_path());
        assert!(Address::from("@abstract_socket").is_unix_path());
        assert!(!Address::from("1.2.3.4").is_unix_path());
        assert!(!Address::from("example.com").is_unix_path());
    }

    #[test]
    fn address_serde_roundtrip() {
        let json = r#""1.2.3.4""#;
        let a: Address = serde_json::from_str(json).unwrap();
        assert_eq!(a.as_str(), "1.2.3.4");
        let back = serde_json::to_string(&a).unwrap();
        assert_eq!(back, json);
    }

    // ----- PortList -----

    #[test]
    fn portlist_single_number() {
        let p: PortList = serde_json::from_str("80").unwrap();
        assert_eq!(p.0, vec![PortRange::single(80)]);
    }

    #[test]
    fn portlist_single_string() {
        let p: PortList = serde_json::from_str(r#""443""#).unwrap();
        assert_eq!(p.0, vec![PortRange::single(443)]);
    }

    #[test]
    fn portlist_comma_separated() {
        let p: PortList = serde_json::from_str(r#""80,443,8080""#).unwrap();
        assert_eq!(
            p.0,
            vec![
                PortRange::single(80),
                PortRange::single(443),
                PortRange::single(8080),
            ]
        );
    }

    #[test]
    fn portlist_range_string() {
        let p: PortList = serde_json::from_str(r#""1000-2000""#).unwrap();
        assert_eq!(p.0, vec![PortRange { start: 1000, end: 2000 }]);
        assert_eq!(p.port_count(), 1001);
        assert!(p.contains(1500));
        assert!(!p.contains(999));
        assert!(!p.contains(2001));
    }

    #[test]
    fn portlist_mixed_array() {
        let p: PortList = serde_json::from_str(r#"[80, "443", "1000-2000"]"#).unwrap();
        assert_eq!(p.0.len(), 3);
        assert_eq!(p.0[0], PortRange::single(80));
        assert_eq!(p.0[1], PortRange::single(443));
        assert_eq!(p.0[2], PortRange { start: 1000, end: 2000 });
    }

    #[test]
    fn portlist_invalid_range() {
        let r = serde_json::from_str::<PortList>(r#""100-50""#);
        assert!(r.is_err(), "start > end should fail");
    }

    #[test]
    fn portlist_empty_array_yields_empty() {
        // 空数组是合法的空 PortList 输入。
        let p: PortList = serde_json::from_str("[]").unwrap();
        assert!(p.is_empty());
    }

    // ----- StringList -----

    #[test]
    fn stringlist_single() {
        let s: StringList = serde_json::from_str(r#""http""#).unwrap();
        assert_eq!(s.0, vec!["http".to_owned()]);
    }

    #[test]
    fn stringlist_multi() {
        let s: StringList = serde_json::from_str(r#"["http", "tls"]"#).unwrap();
        assert_eq!(s.0, vec!["http".to_owned(), "tls".to_owned()]);
    }

    // ----- Network / NetworkList -----

    #[test]
    fn network_serde_lowercase() {
        let n: Network = serde_json::from_str(r#""udp""#).unwrap();
        assert_eq!(n, Network::Udp);
        assert_eq!(n.as_str(), "udp");
        let back = serde_json::to_string(&n).unwrap();
        assert_eq!(back, r#""udp""#);
    }

    #[test]
    fn networklist_comma_separated_string() {
        let n: NetworkList = serde_json::from_str(r#""tcp,udp""#).unwrap();
        assert_eq!(n.0, vec![Network::Tcp, Network::Udp]);
    }

    #[test]
    fn networklist_array() {
        let n: NetworkList = serde_json::from_str(r#"["tcp", "udp"]"#).unwrap();
        assert_eq!(n.0, vec![Network::Tcp, Network::Udp]);
    }

    #[test]
    fn networklist_into_vec_string() {
        let n: NetworkList = serde_json::from_str(r#""unix""#).unwrap();
        let v: Vec<String> = n.into();
        assert_eq!(v, vec!["unix".to_string()]);
    }

    // ----- User -----

    #[test]
    fn user_parse_and_build() {
        // Go TestUserParsing：未知字段（id）忽略，email/level 正常解析并 Build。
        let u: User = serde_json::from_str(
            r#"{ "id": "96edb838-6d68-42ef-a933-25f7ac3a9d09", "email": "love@example.com", "level": 1 }"#,
        )
        .unwrap();
        assert_eq!(u, User { email: "love@example.com".into(), level: 1 });
        let p = u.build();
        assert_eq!(p.email(), "love@example.com");
        assert_eq!(p.level(), 1);
    }

    #[test]
    fn user_defaults_and_level_overflow() {
        let u: User = serde_json::from_str("{}").unwrap();
        assert_eq!(u, User::default());
        assert_eq!(u.build().level(), 0);
        // Go LevelByte byte：256 溢出报错。
        assert!(serde_json::from_str::<User>(r#"{ "level": 256 }"#).is_err());
    }

    // ----- Int32Range -----

    #[test]
    fn int32range_from_int() {
        let r: Int32Range = serde_json::from_str("1").unwrap();
        assert_eq!(r, Int32Range { left: 1, right: 1, from: 1, to: 1 });
    }

    #[test]
    fn int32range_from_string_range() {
        let r: Int32Range = serde_json::from_str(r#""1-2""#).unwrap();
        assert_eq!(r, Int32Range { left: 1, right: 2, from: 1, to: 2 });
    }

    #[test]
    fn int32range_swaps_from_to_when_left_gt_right() {
        // Go 注释（common.go:291）：From > To 时交换，left/right 保留原值。
        let r: Int32Range = serde_json::from_str(r#""5-1""#).unwrap();
        assert_eq!(r, Int32Range { left: 5, right: 1, from: 1, to: 5 });
    }

    #[test]
    fn int32range_negative_sentinels() {
        let r: Int32Range = serde_json::from_str(r#""-1""#).unwrap();
        assert_eq!(r, Int32Range { left: -1, right: -1, from: -1, to: -1 });

        // Go splitFromSecondDash："-114-514" → ("-114", "514")
        let r: Int32Range = serde_json::from_str(r#""-114-514""#).unwrap();
        assert_eq!(r, Int32Range { left: -114, right: 514, from: -114, to: 514 });

        // "-1919--810" → ("-1919", "-810")；from(-1919) < to(-810) 不交换
        let r: Int32Range = serde_json::from_str(r#""-1919--810""#).unwrap();
        assert_eq!(r, Int32Range { left: -1919, right: -810, from: -1919, to: -810 });
    }

    #[test]
    fn int32range_empty_string_is_zero() {
        // Go ParseRangeString："" 返回 (0, 0)。
        let r: Int32Range = serde_json::from_str(r#""""#).unwrap();
        assert_eq!(r, Int32Range::default());
    }

    #[test]
    fn int32range_invalid_inputs() {
        for json in [r#""abc""#, "1.5", r#""1-""#, "true", r#""1-2-3""#] {
            assert!(
                serde_json::from_str::<Int32Range>(json).is_err(),
                "should reject {json}"
            );
        }
    }

    #[test]
    fn int32range_display_and_serialize() {
        // Go String()/MarshalJSON（common.go:299-310）。
        let single: Int32Range = serde_json::from_str("5").unwrap();
        assert_eq!(single.to_string(), "5");
        assert_eq!(serde_json::to_string(&single).unwrap(), r#""5""#);

        let range: Int32Range = serde_json::from_str(r#""1-2""#).unwrap();
        assert_eq!(range.to_string(), "1-2");
        assert_eq!(serde_json::to_string(&range).unwrap(), r#""1-2""#);
    }

    // ----- env: 展开（进程环境变量共享，测试间互斥） -----

    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn address_expands_env_prefix() {
        let _g = ENV_LOCK.lock();
        unsafe { std::env::set_var("XRAY_CONF_TEST_ADDR", "1.2.3.4") };
        let a: Address = serde_json::from_str(r#""env:XRAY_CONF_TEST_ADDR""#).unwrap();
        assert_eq!(a.as_str(), "1.2.3.4");
        unsafe { std::env::remove_var("XRAY_CONF_TEST_ADDR") };
    }

    #[test]
    fn address_env_unset_expands_to_empty() {
        let _g = ENV_LOCK.lock();
        // Go GetValue(default "")：未设置为空串。
        let a: Address = serde_json::from_str(r#""env:XRAY_CONF_TEST_UNSET""#).unwrap();
        assert_eq!(a.as_str(), "");
    }

    #[test]
    fn address_without_env_prefix_untouched() {
        let a: Address = serde_json::from_str(r#""env.example.com""#).unwrap();
        assert_eq!(a.as_str(), "env.example.com");
    }

    #[test]
    fn portlist_expands_env_port() {
        // Go TestEnvPort（common_test.go:148-159）等价。
        let _g = ENV_LOCK.lock();
        unsafe { std::env::set_var("XRAY_CONF_TEST_PORT", "1234") };
        let p: PortList = serde_json::from_str(r#""env:XRAY_CONF_TEST_PORT""#).unwrap();
        assert_eq!(p.0, vec![PortRange::single(1234)]);
        unsafe { std::env::remove_var("XRAY_CONF_TEST_PORT") };
    }

    #[test]
    fn portlist_expands_env_range() {
        let _g = ENV_LOCK.lock();
        unsafe { std::env::set_var("XRAY_CONF_TEST_PORTS", "1000-2000") };
        let p: PortList = serde_json::from_str(r#""env:XRAY_CONF_TEST_PORTS""#).unwrap();
        assert_eq!(p.0, vec![PortRange { start: 1000, end: 2000 }]);
        unsafe { std::env::remove_var("XRAY_CONF_TEST_PORTS") };
    }

    #[test]
    fn portlist_env_in_comma_list() {
        let _g = ENV_LOCK.lock();
        unsafe { std::env::set_var("XRAY_CONF_TEST_P1", "80") };
        let p: PortList = serde_json::from_str(r#""env:XRAY_CONF_TEST_P1,443""#).unwrap();
        assert_eq!(p.0, vec![PortRange::single(80), PortRange::single(443)]);
        unsafe { std::env::remove_var("XRAY_CONF_TEST_P1") };
    }

    #[test]
    fn env_alt_name_uppercase_lookup() {
        // Go NewEnvFlag 双查（platform.go:42-53）：原名失败后查大写下划线形式。
        let _g = ENV_LOCK.lock();
        unsafe { std::env::set_var("XRAY_CONF_TEST_ALT", "8080") };
        let p: PortList = serde_json::from_str(r#""env:xray.conf.test.alt""#).unwrap();
        assert_eq!(p.0, vec![PortRange::single(8080)]);
        unsafe { std::env::remove_var("XRAY_CONF_TEST_ALT") };
    }
}
