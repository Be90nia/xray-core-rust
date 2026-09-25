//! 服务器规格类型
//!
//! 对应 Go 版本 `common/protocol/server_spec.go` + `server_spec.proto`。
//! Go 消费方：vless/vmess/trojan/shadowsocks/socks/http/hysteria 的
//! client/outbound（`protocol.NewServerSpecFromPB(config.Server/Receiver/Vnext)`）。

use serde::{Deserialize, Serialize};

use crate::{
    net::{address::Address, destination::Destination, port::Port},
    protocol::user::{MemoryUser, User},
};

/// 服务器规格，描述目标服务器及其可选用户。
///
/// 对应 Go 版本的 `ServerSpec{Destination net.Destination; User *MemoryUser}`。
/// 运行时结构（含已解析账户），与 Go 一致不参与序列化。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerSpec {
    destination: Destination,
    user: Option<MemoryUser>,
}

impl ServerSpec {
    /// 创建新的服务器规格（无用户）。
    #[must_use]
    pub fn new(destination: Destination) -> Self {
        Self { destination, user: None }
    }

    /// 设置用户，返回新的 ServerSpec。
    ///
    /// 对应 Go 版本的 `NewServerSpec(dest, user)`。
    #[must_use]
    pub fn with_user(mut self, user: MemoryUser) -> Self {
        self.user = Some(user);
        self
    }

    /// 获取目的地引用。
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// 获取用户引用。
    #[must_use]
    pub fn user(&self) -> Option<&MemoryUser> {
        self.user.as_ref()
    }

    /// 从服务器端点（proto 形式）转换。
    ///
    /// 对应 Go 版本的 `NewServerSpecFromPB(spec *ServerEndpoint)`：
    /// 目的地固定为 TCP（`net.TCPDestination`）。
    /// 差异：Go 经 `User.ToMemoryUser()` 解析 typed account（依赖 proto
    /// 实例注册表）；Rust 侧 email/level 透传，账户解析属各 proxy crate
    /// 的消费方接入任务，此处置空。
    #[must_use]
    pub fn from_server_endpoint(endpoint: &ServerEndpoint) -> Self {
        let user = endpoint.user().map(|u| MemoryUser::new(u.email()).with_level(u.level()));
        Self { destination: Destination::tcp(endpoint.address().clone(), endpoint.port()), user }
    }
}

/// 服务器端点，由地址、端口和可选用户组成。
///
/// 对应 Go 版本 `server_spec.proto` 的 `ServerEndpoint` 消息：
/// `{ address IPOrDomain; port uint32; user User }`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerEndpoint {
    address: Address,
    port: Port,
    user: Option<User>,
}

impl ServerEndpoint {
    /// 创建新的服务器端点。
    #[must_use]
    pub fn new(address: Address, port: Port) -> Self {
        Self { address, port, user: None }
    }

    /// 设置用户（proto 形式），返回新的 ServerEndpoint。
    #[must_use]
    pub fn with_user(mut self, user: User) -> Self {
        self.user = Some(user);
        self
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

    /// 获取用户（proto 形式）引用。
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user.as_ref()
    }
}

impl std::fmt::Display for ServerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn sample_destination() -> Destination {
        Destination::tcp(Address::ipv4(Ipv4Addr::new(192, 168, 1, 1)), Port::new(443))
    }

    // ========== ServerSpec ==========

    #[test]
    fn test_server_spec_new() {
        let dest = sample_destination();
        let spec = ServerSpec::new(dest.clone());
        assert_eq!(spec.destination(), &dest);
        assert_eq!(spec.user(), None);
    }

    #[test]
    fn test_server_spec_with_user() {
        let spec = ServerSpec::new(sample_destination())
            .with_user(MemoryUser::new("admin@example.com").with_level(2));
        let user = spec.user().expect("user");
        assert_eq!(user.email(), "admin@example.com");
        assert_eq!(user.level(), 2);
    }

    #[test]
    fn test_server_spec_equality() {
        let a = ServerSpec::new(sample_destination());
        let b = ServerSpec::new(sample_destination());
        assert_eq!(a, b);

        let c = ServerSpec::new(sample_destination()).with_user(MemoryUser::new("diff@test.com"));
        assert_ne!(a, c);
    }

    #[test]
    fn test_server_spec_clone() {
        let spec = ServerSpec::new(sample_destination()).with_user(MemoryUser::new("u@test.com"));
        let cloned = spec.clone();
        assert_eq!(spec, cloned);
    }

    /// 对应 Go `NewServerSpecFromPB`：目的地固定 TCP，无用户时 user 为空。
    #[test]
    fn test_from_server_endpoint_without_user() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443));
        let spec = ServerSpec::from_server_endpoint(&endpoint);
        assert_eq!(
            spec.destination(),
            &Destination::tcp(Address::new_domain("example.com"), Port::new(443))
        );
        assert_eq!(spec.user(), None);
    }

    #[test]
    fn test_from_server_endpoint_with_user() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443))
            .with_user(User::new("alice@example.com").with_level(3));
        let spec = ServerSpec::from_server_endpoint(&endpoint);
        let user = spec.user().expect("user");
        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.level(), 3);
        assert!(user.account().is_none()); // 账户解析待消费方接入
    }

    // ========== ServerEndpoint ==========

    #[test]
    fn test_server_endpoint_new() {
        let addr = Address::new_domain("example.com");
        let endpoint = ServerEndpoint::new(addr.clone(), Port::new(443));
        assert_eq!(endpoint.address(), &addr);
        assert_eq!(endpoint.port(), Port::new(443));
        assert_eq!(endpoint.user(), None);
    }

    #[test]
    fn test_server_endpoint_with_user() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443))
            .with_user(User::new("bob@example.com"));
        assert_eq!(endpoint.user().expect("user").email(), "bob@example.com");
    }

    #[test]
    fn test_server_endpoint_display() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443));
        assert_eq!(format!("{endpoint}"), "example.com:443");
    }

    #[test]
    fn test_server_endpoint_display_ipv4() {
        let endpoint =
            ServerEndpoint::new(Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)), Port::new(8080));
        assert_eq!(format!("{endpoint}"), "10.0.0.1:8080");
    }

    #[test]
    fn test_server_endpoint_equality() {
        let a = ServerEndpoint::new(Address::new_domain("test.com"), Port::new(443));
        let b = ServerEndpoint::new(Address::new_domain("test.com"), Port::new(443));
        assert_eq!(a, b);

        let c = ServerEndpoint::new(Address::new_domain("test.com"), Port::new(443))
            .with_user(User::new("x@test.com"));
        assert_ne!(a, c);
    }

    #[test]
    fn test_serde_roundtrip_server_endpoint() {
        let endpoint = ServerEndpoint::new(Address::new_domain("example.com"), Port::new(443))
            .with_user(User::new("alice@example.com").with_level(1));
        let json = serde_json::to_string(&endpoint).expect("serialize");
        let deserialized: ServerEndpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(endpoint, deserialized);
    }
}
