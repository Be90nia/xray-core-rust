//! 网络目的地类型定义
//!
//! 对应 Go 版本 `common/net/destination.go`，定义 Destination 和 Endpoint 类型。

use serde::{Deserialize, Serialize};

use super::{address::Address, network::Network, port::Port};

/// 网络目的地 = 地址 + 端口 + 网络类型。
///
/// 对应 Go 版本的 `Destination` 结构体，完整描述一个网络连接目标。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Destination {
    address: Address,
    port: Port,
    network: Network,
}

impl Destination {
    /// 创建新的目的地。
    #[must_use]
    pub fn new(address: Address, port: Port, network: Network) -> Self {
        Self { address, port, network }
    }

    /// 创建 TCP 目的地。
    #[must_use]
    pub fn tcp(address: Address, port: Port) -> Self {
        Self::new(address, port, Network::TCP)
    }

    /// 创建 UDP 目的地。
    #[must_use]
    pub fn udp(address: Address, port: Port) -> Self {
        Self::new(address, port, Network::UDP)
    }

    /// 获取地址的引用。
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// 获取端口号。
    #[must_use]
    pub fn port(&self) -> Port {
        self.port
    }

    /// 获取网络类型。
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// 是否为 TCP 目的地。
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.network == Network::TCP
    }

    /// 是否为 UDP 目的地。
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.network == Network::UDP
    }

    /// 返回使用指定网络类型的新目的地。
    #[must_use]
    pub fn with_network(&self, network: Network) -> Self {
        Self { address: self.address.clone(), port: self.port, network }
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.network, self.address, self.port)
    }
}

/// 端点 = 地址 + 端口（无网络类型）。
///
/// 对应 Go 版本的 `Endpoint`，用于不需要区分 TCP/UDP 的场景。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    address: Address,
    port: Port,
}

impl Endpoint {
    /// 创建新的端点。
    #[must_use]
    pub fn new(address: Address, port: Port) -> Self {
        Self { address, port }
    }

    /// 获取地址的引用。
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// 获取端口号。
    #[must_use]
    pub fn port(&self) -> Port {
        self.port
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_destination_new() {
        let addr = Address::ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let dest = Destination::new(addr.clone(), Port::new(8080), Network::TCP);
        assert_eq!(dest.address(), &addr);
        assert_eq!(dest.port(), Port::new(8080));
        assert_eq!(dest.network(), Network::TCP);
    }

    #[test]
    fn test_destination_tcp() {
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(443));
        assert!(dest.is_tcp());
        assert!(!dest.is_udp());
        assert_eq!(dest.network(), Network::TCP);
    }

    #[test]
    fn test_destination_udp() {
        let dest = Destination::udp(Address::new_domain("dns.server"), Port::new(53));
        assert!(!dest.is_tcp());
        assert!(dest.is_udp());
        assert_eq!(dest.network(), Network::UDP);
    }

    #[test]
    fn test_destination_with_network() {
        let tcp_dest = Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(80));
        let udp_dest = tcp_dest.with_network(Network::UDP);
        assert_eq!(udp_dest.network(), Network::UDP);
        assert_eq!(udp_dest.address(), tcp_dest.address());
        assert_eq!(udp_dest.port(), tcp_dest.port());
    }

    #[test]
    fn test_destination_display_tcp() {
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(443));
        assert_eq!(format!("{dest}"), "tcp:example.com:443");
    }

    #[test]
    fn test_destination_display_udp_ipv4() {
        let dest = Destination::udp(Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)), Port::new(53));
        assert_eq!(format!("{dest}"), "udp:10.0.0.1:53");
    }

    #[test]
    fn test_destination_display_ipv6() {
        let dest = Destination::tcp(Address::ipv6(Ipv6Addr::LOCALHOST), Port::new(443));
        assert_eq!(format!("{dest}"), "tcp:[::1]:443");
    }

    #[test]
    fn test_endpoint_new() {
        let addr = Address::new_domain("example.com");
        let ep = Endpoint::new(addr.clone(), Port::new(80));
        assert_eq!(ep.address(), &addr);
        assert_eq!(ep.port(), Port::new(80));
    }

    #[test]
    fn test_endpoint_display_domain() {
        let ep = Endpoint::new(Address::new_domain("example.com"), Port::new(443));
        assert_eq!(format!("{ep}"), "example.com:443");
    }

    #[test]
    fn test_endpoint_display_ipv4() {
        let ep = Endpoint::new(Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)), Port::new(8080));
        assert_eq!(format!("{ep}"), "192.168.1.1:8080");
    }

    #[test]
    fn test_endpoint_display_ipv6() {
        let ep = Endpoint::new(Address::ipv6(Ipv6Addr::LOCALHOST), Port::new(443));
        assert_eq!(format!("{ep}"), "[::1]:443");
    }

    #[test]
    fn test_destination_equality() {
        let d1 = Destination::tcp(Address::new_domain("test.com"), Port::new(443));
        let d2 = Destination::tcp(Address::new_domain("test.com"), Port::new(443));
        let d3 = Destination::udp(Address::new_domain("test.com"), Port::new(443));
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_endpoint_equality() {
        let e1 = Endpoint::new(Address::new_domain("test.com"), Port::new(443));
        let e2 = Endpoint::new(Address::new_domain("test.com"), Port::new(443));
        let e3 = Endpoint::new(Address::new_domain("other.com"), Port::new(443));
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_serde_roundtrip_destination() {
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(443));
        let json = serde_json::to_string(&dest).expect("serialize");
        let deserialized: Destination = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dest, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_endpoint() {
        let ep = Endpoint::new(Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)), Port::new(8080));
        let json = serde_json::to_string(&ep).expect("serialize");
        let deserialized: Endpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ep, deserialized);
    }

    #[test]
    fn test_destination_clone() {
        let dest = Destination::tcp(Address::new_domain("test.com"), Port::new(443));
        let cloned = dest.clone();
        assert_eq!(dest, cloned);
    }
}
