//! 配置层基础类型：地址、端口、字符串列表。
//!
//! 这些类型对应 Go `infra/conf/common.go` 与 `infra/conf/xray.go` 中的 JSON 反序列化类型。
//! 关注点是「从配置文件解析」，运行时转换（→ `xray_common::net::Address`）留给后续 Build 阶段。

use serde::{Deserialize, Deserializer, Serialize};
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
        String::deserialize(d).map(Address)
    }
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
}
