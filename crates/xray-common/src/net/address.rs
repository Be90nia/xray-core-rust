//! 网络地址类型定义
//!
//! 对应 Go 版本 `common/net/address.go`，定义 IPv4/IPv6/域名地址类型。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

/// 网络地址：IPv4、IPv6 或域名。
///
/// 对应 Go 版本的 `Address` 接口和 `IPOrDomain` 结构体。
/// 使用枚举实现零开销的类型安全。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Address {
    /// IPv4 地址
    IPv4(Ipv4Addr),
    /// IPv6 地址
    IPv6(Ipv6Addr),
    /// 域名地址
    Domain(String),
}

impl Address {
    /// 从 IPv4 地址创建。
    #[must_use]
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self::IPv4(addr)
    }

    /// 从 IPv6 地址创建。
    #[must_use]
    pub fn ipv6(addr: Ipv6Addr) -> Self {
        Self::IPv6(addr)
    }

    /// 从域名字符串创建。
    #[must_use]
    pub fn new_domain(domain: impl Into<String>) -> Self {
        Self::Domain(domain.into())
    }

    /// 从 4 字节原始数据创建 IPv4 地址。
    #[must_use]
    pub fn from_ipv4_bytes(b: [u8; 4]) -> Self {
        Self::IPv4(Ipv4Addr::from(b))
    }

    /// 从 16 字节原始数据创建 IPv6 地址。
    #[must_use]
    pub fn from_ipv6_bytes(b: [u8; 16]) -> Self {
        Self::IPv6(Ipv6Addr::from(b))
    }

    /// 是否为 IPv4 地址。
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::IPv4(_))
    }

    /// 是否为 IPv6 地址。
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::IPv6(_))
    }

    /// 是否为域名地址。
    #[must_use]
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(_))
    }

    /// 获取 IP 地址（IPv4 或 IPv6），域名返回 `None`。
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::IPv4(addr) => Some(IpAddr::from(*addr)),
            Self::IPv6(addr) => Some(IpAddr::from(*addr)),
            Self::Domain(_) => None,
        }
    }

    /// 获取域名字符串引用，IP 地址返回 `None`。
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(d) => Some(d),
            _ => None,
        }
    }

    /// 获取 IPv4 原始字节数组，非 IPv4 返回 `None`。
    #[must_use]
    pub fn ipv4_bytes(&self) -> Option<[u8; 4]> {
        match self {
            Self::IPv4(addr) => Some(addr.octets()),
            _ => None,
        }
    }

    /// 获取 IPv6 原始字节数组，非 IPv6 返回 `None`。
    #[must_use]
    pub fn ipv6_bytes(&self) -> Option<[u8; 16]> {
        match self {
            Self::IPv6(addr) => Some(addr.octets()),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IPv4(addr) => write!(f, "{addr}"),
            Self::IPv6(addr) => write!(f, "[{addr}]"),
            Self::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(addr: Ipv4Addr) -> Self {
        Self::IPv4(addr)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(addr: Ipv6Addr) -> Self {
        Self::IPv6(addr)
    }
}

impl From<IpAddr> for Address {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::IPv4(v4),
            IpAddr::V6(v6) => Self::IPv6(v6),
        }
    }
}

impl std::str::FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 尝试解析为 IPv4
        if let Ok(addr) = s.parse::<Ipv4Addr>() {
            return Ok(Self::IPv4(addr));
        }

        // 尝试解析为 IPv6（可能带方括号）
        let trimmed = s.trim_start_matches('[').trim_end_matches(']');
        if let Ok(addr) = trimmed.parse::<Ipv6Addr>() {
            return Ok(Self::IPv6(addr));
        }

        // 视为域名
        if s.is_empty() {
            return Err("address string is empty".to_string());
        }

        Ok(Self::Domain(s.to_string()))
    }
}

/// 用于 protobuf 序列化兼容的地址包装类型。
///
/// 对应 Go 版本的 `common/net.IPOrDomain` proto 消息。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IPOrDomain {
    address: Address,
}

impl IPOrDomain {
    /// 从 Address 创建。
    #[must_use]
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    /// 获取内部地址的引用。
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// 消费自身，返回内部 Address。
    #[must_use]
    pub fn into_address(self) -> Address {
        self.address
    }

    /// 如果内部是 IP 地址则返回，否则返回 `None`。
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        self.address.ip()
    }

    /// 如果内部是域名则返回，否则返回 `None`。
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        self.address.as_domain()
    }
}

impl From<Address> for IPOrDomain {
    fn from(address: Address) -> Self {
        Self::new(address)
    }
}

impl From<IPOrDomain> for Address {
    fn from(val: IPOrDomain) -> Self {
        val.into_address()
    }
}

impl std::fmt::Display for IPOrDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_constructor() {
        let addr = Address::ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert!(!addr.is_domain());
    }

    #[test]
    fn test_ipv6_constructor() {
        let addr = Address::ipv6(Ipv6Addr::LOCALHOST);
        assert!(!addr.is_ipv4());
        assert!(addr.is_ipv6());
        assert!(!addr.is_domain());
    }

    #[test]
    fn test_domain_constructor() {
        let addr = Address::new_domain("example.com");
        assert!(!addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert!(addr.is_domain());
    }

    #[test]
    fn test_from_ipv4_bytes() {
        let addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        assert!(addr.is_ipv4());
        assert_eq!(addr.ip(), Some(IpAddr::from([127, 0, 0, 1])));
    }

    #[test]
    fn test_from_ipv6_bytes() {
        let bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr = Address::from_ipv6_bytes(bytes);
        assert!(addr.is_ipv6());
        assert_eq!(addr.ip(), Some(IpAddr::from(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_ip_accessor_ipv4() {
        let addr = Address::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(addr.ip(), Some(IpAddr::from([1, 2, 3, 4])));
        assert_eq!(addr.as_domain(), None);
    }

    #[test]
    fn test_ip_accessor_ipv6() {
        let addr = Address::ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(addr.ip().is_some());
        assert_eq!(addr.as_domain(), None);
    }

    #[test]
    fn test_ip_accessor_domain() {
        let addr = Address::new_domain("example.com");
        assert_eq!(addr.ip(), None);
        assert_eq!(addr.as_domain(), Some("example.com"));
    }

    #[test]
    fn test_ipv4_bytes_accessor() {
        let addr = Address::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(addr.ipv4_bytes(), Some([10, 0, 0, 1]));
        assert_eq!(addr.ipv6_bytes(), None);
    }

    #[test]
    fn test_ipv6_bytes_accessor() {
        let addr = Address::ipv6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.ipv4_bytes(), None);
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(addr.ipv6_bytes(), Some(expected));
    }

    #[test]
    fn test_domain_bytes_accessors() {
        let addr = Address::new_domain("test.com");
        assert_eq!(addr.ipv4_bytes(), None);
        assert_eq!(addr.ipv6_bytes(), None);
    }

    #[test]
    fn test_display_ipv4() {
        let addr = Address::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(format!("{addr}"), "1.2.3.4");
    }

    #[test]
    fn test_display_ipv6() {
        let addr = Address::ipv6(Ipv6Addr::LOCALHOST);
        assert_eq!(format!("{addr}"), "[::1]");
    }

    #[test]
    fn test_display_domain() {
        let addr = Address::new_domain("example.com");
        assert_eq!(format!("{addr}"), "example.com");
    }

    #[test]
    fn test_from_ipv4addr() {
        let addr: Address = Ipv4Addr::new(127, 0, 0, 1).into();
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_from_ipv6addr() {
        let addr: Address = Ipv6Addr::LOCALHOST.into();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_from_ipaddr() {
        let addr: Address = IpAddr::from([192, 168, 0, 1]).into();
        assert!(addr.is_ipv4());

        let addr: Address = IpAddr::from(Ipv6Addr::LOCALHOST).into();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_from_str_ipv4() {
        let addr: Address = "192.168.1.1".parse().expect("parse should succeed");
        assert!(addr.is_ipv4());
        assert_eq!(format!("{addr}"), "192.168.1.1");
    }

    #[test]
    fn test_from_str_ipv6_bare() {
        let addr: Address = "::1".parse().expect("parse should succeed");
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_from_str_ipv6_bracketed() {
        let addr: Address = "[::1]".parse().expect("parse should succeed");
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_from_str_domain() {
        let addr: Address = "example.com".parse().expect("parse should succeed");
        assert!(addr.is_domain());
    }

    #[test]
    fn test_from_str_empty_fails() {
        let result: Result<Address, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_or_domain_new() {
        let addr = Address::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let iod = IPOrDomain::new(addr);
        assert!(iod.address().is_ipv4());
        assert_eq!(iod.as_ip(), Some(IpAddr::from([1, 2, 3, 4])));
        assert_eq!(iod.as_domain(), None);
    }

    #[test]
    fn test_ip_or_domain_domain() {
        let addr = Address::new_domain("test.com");
        let iod = IPOrDomain::new(addr);
        assert_eq!(iod.as_ip(), None);
        assert_eq!(iod.as_domain(), Some("test.com"));
    }

    #[test]
    fn test_ip_or_domain_into_address() {
        let addr = Address::new_domain("test.com");
        let iod = IPOrDomain::new(addr.clone());
        let recovered = iod.into_address();
        assert_eq!(recovered, addr);
    }

    #[test]
    fn test_ip_or_domain_from_conversions() {
        let addr = Address::ipv4(Ipv4Addr::LOCALHOST);
        let iod: IPOrDomain = addr.clone().into();
        assert_eq!(*iod.address(), addr);

        let back: Address = iod.into();
        assert_eq!(back, addr);
    }

    #[test]
    fn test_ip_or_domain_display() {
        let iod = IPOrDomain::new(Address::new_domain("example.com"));
        assert_eq!(format!("{iod}"), "example.com");
    }

    #[test]
    fn test_serde_roundtrip_ipv4() {
        let addr = Address::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let json = serde_json::to_string(&addr).expect("serialize");
        let deserialized: Address = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_domain() {
        let addr = Address::new_domain("example.com");
        let json = serde_json::to_string(&addr).expect("serialize");
        let deserialized: Address = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, deserialized);
    }

    #[test]
    fn test_equality() {
        let a1 = Address::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let a2 = Address::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let a3 = Address::ipv6(Ipv6Addr::LOCALHOST);
        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    #[test]
    fn test_clone() {
        let a1 = Address::new_domain("test.com");
        let a2 = a1.clone();
        assert_eq!(a1, a2);
    }
}
