//! 服务器规格类型
//!
//! 对应 Go 版本 `common/protocol/server_spec.go`，定义服务器规格和端点。

use serde::{Deserialize, Serialize};

use crate::net::address::Address;
use crate::net::destination::Destination;
use crate::net::port::Port;

/// 服务器规格，描述目标服务器及其可选邮箱。
///
/// 对应 Go 版本的 `ServerSpec`，使用 builder 模式构建。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerSpec {
    destination: Destination,
    email: Option<String>,
}

impl ServerSpec {
    /// 创建新的服务器规格。
    #[must_use]
    pub fn new(destination: Destination) -> Self {
        Self {
            destination,
            email: None,
        }
    }

    /// 设置邮箱，返回新的 ServerSpec。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// 获取目的地引用。
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// 获取邮箱引用。
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
}

/// 服务器端点，由地址和端口组成。
///
/// 对应 Go 版本的 `ServerEndpoint`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerEndpoint {
    address: Address,
    port: Port,
}

impl ServerEndpoint {
    /// 创建新的服务器端点。
    #[must_use]
    pub fn new(address: Address, port: Port) -> Self {
        Self { address, port }
    }

    /// 获取地址引用。
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// 获取端口。
    #[must_use]
    pub fn port(&self) -> Port {
        self.port
    }
}

impl std::fmt::Display for ServerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_destination() -> Destination {
        Destination::tcp(Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)), Port::new(443))
    }

    #[test]
    fn test_server_spec_new() {
        let dest = sample_destination();
        let spec = ServerSpec::new(dest.clone());
        assert_eq!(spec.destination(), &dest);
        assert_eq!(spec.email(), None);
    }

    #[test]
    fn test_server_spec_with_email() {
        let spec = ServerSpec::new(sample_destination()).with_email("admin@example.com");
        assert_eq!(spec.email(), Some("admin@example.com"));
    }

    #[test]
    fn test_server_spec_builder_chain() {
        let spec = ServerSpec::new(sample_destination()).with_email("user@test.com");
        assert!(spec.email().is_some());
        assert_eq!(spec.email().expect("email"), "user@test.com");
    }

    #[test]
    fn test_server_spec_equality() {
        let a = ServerSpec::new(sample_destination());
        let b = ServerSpec::new(sample_destination());
        assert_eq!(a, b);

        let c = ServerSpec::new(sample_destination()).with_email("diff@test.com");
        assert_ne!(a, c);
    }

    #[test]
    fn test_server_spec_clone() {
        let spec = ServerSpec::new(sample_destination()).with_email("test@test.com");
        let cloned = spec.clone();
        assert_eq!(spec, cloned);
    }

    #[test]
    fn test_server_endpoint_new() {
        let addr = Address::new_domain("example.com");
        let endpoint = ServerEndpoint::new(addr.clone(), Port::new(443));
        assert_eq!(endpoint.address(), &addr);
        assert_eq!(endpoint.port(), Port::new(443));
    }

    #[test]
    fn test_server_endpoint_display() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443));
        assert_eq!(format!("{endpoint}"), "example.com:443");
    }

    #[test]
    fn test_server_endpoint_display_ipv4() {
        let endpoint = ServerEndpoint::new(
            Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            Port::new(8080),
        );
        assert_eq!(format!("{endpoint}"), "10.0.0.1:8080");
    }

    #[test]
    fn test_server_endpoint_equality() {
        let a = ServerEndpoint::new(Address::new_domain("test.com"), Port::new(443));
        let b = ServerEndpoint::new(Address::new_domain("test.com"), Port::new(443));
        assert_eq!(a, b);
    }

    #[test]
    fn test_serde_roundtrip_server_spec() {
        let spec = ServerSpec::new(sample_destination()).with_email("test@test.com");
        let json = serde_json::to_string(&spec).expect("serialize");
        let deserialized: ServerSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_server_endpoint() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443));
        let json = serde_json::to_string(&endpoint).expect("serialize");
        let deserialized: ServerEndpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(endpoint, deserialized);
    }
}
