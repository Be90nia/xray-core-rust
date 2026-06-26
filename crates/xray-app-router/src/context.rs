//! Routing context trait（对应 Go `features/routing.Context`）。
//!
//! Go 中 `routing.Context` 是一个接口，提供获取路由相关字段的方法集合
//! （目标 IP/域名/端口、源 IP/端口、用户、入站 tag、协议等）。
//!
//! 由于 `xray-features::routing` 当前的 `Router` trait 采用了简化的
//! `(destination, session) -> tag` 签名，无法承载 Go 版本丰富的上下文
//! 字段，本 crate 在内部定义独立的 `RoutingContext` trait 保持 Go 语义。
//!
//! 上层（如 dispatcher）接入时，提供 `RoutingData` 适配器即可。

use std::collections::HashMap;
use std::net::IpAddr;

use xray_common::net::network::Network;
use xray_common::net::port::Port;

/// 路由上下文，对应 Go `routing.Context`。
///
/// 所有方法同步、对象安全（dyn-compatible）。matcher 通过 `&dyn RoutingContext`
/// 访问上下文字段。
pub trait RoutingContext: Send + Sync {
    /// 目标 IP 列表（已解析）。可能为空（域名目标 + 未解析）。
    fn get_target_ips(&self) -> &[IpAddr];

    /// 目标域名（若目标用域名表达）。空字符串表示无域名。
    fn get_target_domain(&self) -> &str;

    /// 目标端口。
    fn get_target_port(&self) -> Port;

    /// 源 IP 列表。
    fn get_source_ips(&self) -> &[IpAddr];

    /// 源端口。
    fn get_source_port(&self) -> Port;

    /// 本地（入站侧）IP 列表。
    fn get_local_ips(&self) -> &[IpAddr];

    /// 本地端口。
    fn get_local_port(&self) -> Port;

    /// VLESS 路由端口（对应 Go `GetVlessRoute`）。
    fn get_vless_route(&self) -> Port;

    /// 网络类型（TCP/UDP/Unix）。
    fn get_network(&self) -> Network;

    /// 用户标识（邮箱等）。
    fn get_user(&self) -> &str;

    /// 属性映射（如 HTTP 头 `:path`）。
    fn get_attributes(&self) -> &HashMap<String, String>;

    /// 入站 tag。
    fn get_inbound_tag(&self) -> &str;

    /// 协议（如 "http/1.1"、"tls"）。
    fn get_protocol(&self) -> &str;

    /// 跳过 DNS 解析标志（用于路由循环保护）。
    fn get_skip_dns_resolve(&self) -> bool;
}

/// 持有所有路由上下文字段的 owned 数据结构。
///
/// 用于测试与上层适配（从 `xray_common::session::Session` 转换）。
/// 实现了 `RoutingContext` trait。
#[derive(Debug, Clone)]
pub struct RoutingData {
    /// 目标 IP 列表。
    pub target_ips: Vec<IpAddr>,
    /// 目标域名。
    pub target_domain: String,
    /// 目标端口。
    pub target_port: Port,
    /// 源 IP 列表。
    pub source_ips: Vec<IpAddr>,
    /// 源端口。
    pub source_port: Port,
    /// 本地 IP 列表。
    pub local_ips: Vec<IpAddr>,
    /// 本地端口。
    pub local_port: Port,
    /// VLESS 路由端口。
    pub vless_route: Port,
    /// 网络类型。
    pub network: Network,
    /// 用户标识。
    pub user: String,
    /// 属性映射。
    pub attributes: HashMap<String, String>,
    /// 入站 tag。
    pub inbound_tag: String,
    /// 协议。
    pub protocol: String,
    /// 跳过 DNS 解析标志。
    pub skip_dns_resolve: bool,
}

impl Default for RoutingData {
    fn default() -> Self {
        Self {
            target_ips: Vec::new(),
            target_domain: String::new(),
            target_port: Port::new(0),
            source_ips: Vec::new(),
            source_port: Port::new(0),
            local_ips: Vec::new(),
            local_port: Port::new(0),
            vless_route: Port::new(0),
            network: Network::TCP,
            user: String::new(),
            attributes: HashMap::new(),
            inbound_tag: String::new(),
            protocol: String::new(),
            skip_dns_resolve: false,
        }
    }
}

impl RoutingData {
    /// 创建空的 RoutingData。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// builder：设置目标域名。
    #[must_use]
    pub fn with_target_domain(mut self, domain: impl Into<String>) -> Self {
        self.target_domain = domain.into();
        self
    }

    /// builder：追加目标 IP。
    #[must_use]
    pub fn with_target_ip(mut self, ip: IpAddr) -> Self {
        self.target_ips.push(ip);
        self
    }

    /// builder：设置目标端口。
    #[must_use]
    pub fn with_target_port(mut self, port: Port) -> Self {
        self.target_port = port;
        self
    }

    /// builder：设置网络类型。
    #[must_use]
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// builder：设置源 IP。
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ips.push(ip);
        self
    }

    /// builder：设置源端口。
    #[must_use]
    pub fn with_source_port(mut self, port: Port) -> Self {
        self.source_port = port;
        self
    }

    /// builder：设置用户。
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// builder：设置入站 tag。
    #[must_use]
    pub fn with_inbound_tag(mut self, tag: impl Into<String>) -> Self {
        self.inbound_tag = tag.into();
        self
    }

    /// builder：设置协议。
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// builder：设置属性。
    #[must_use]
    pub fn with_attributes(mut self, attrs: HashMap<String, String>) -> Self {
        self.attributes = attrs;
        self
    }
}

impl RoutingContext for RoutingData {
    fn get_target_ips(&self) -> &[IpAddr] {
        &self.target_ips
    }
    fn get_target_domain(&self) -> &str {
        &self.target_domain
    }
    fn get_target_port(&self) -> Port {
        self.target_port
    }
    fn get_source_ips(&self) -> &[IpAddr] {
        &self.source_ips
    }
    fn get_source_port(&self) -> Port {
        self.source_port
    }
    fn get_local_ips(&self) -> &[IpAddr] {
        &self.local_ips
    }
    fn get_local_port(&self) -> Port {
        self.local_port
    }
    fn get_vless_route(&self) -> Port {
        self.vless_route
    }
    fn get_network(&self) -> Network {
        self.network
    }
    fn get_user(&self) -> &str {
        &self.user
    }
    fn get_attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }
    fn get_inbound_tag(&self) -> &str {
        &self.inbound_tag
    }
    fn get_protocol(&self) -> &str {
        &self.protocol
    }
    fn get_skip_dns_resolve(&self) -> bool {
        self.skip_dns_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_routing_data() {
        let d = RoutingData::default();
        assert!(d.get_target_ips().is_empty());
        assert!(d.get_target_domain().is_empty());
        assert!(d.get_source_ips().is_empty());
        assert_eq!(d.get_target_port(), Port::new(0));
        assert_eq!(d.get_network(), Network::TCP); // default() of enum is first variant
        assert!(!d.get_skip_dns_resolve());
    }

    #[test]
    fn test_builder_chain() {
        let d = RoutingData::new()
            .with_target_domain("example.com")
            .with_target_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .with_target_port(Port::new(443))
            .with_network(Network::UDP)
            .with_user("admin@example.com")
            .with_inbound_tag("in")
            .with_protocol("http/1.1");
        assert_eq!(d.get_target_domain(), "example.com");
        assert_eq!(d.get_target_ips().len(), 1);
        assert_eq!(d.get_target_port(), Port::new(443));
        assert_eq!(d.get_network(), Network::UDP);
        assert_eq!(d.get_user(), "admin@example.com");
        assert_eq!(d.get_inbound_tag(), "in");
        assert_eq!(d.get_protocol(), "http/1.1");
    }

    #[test]
    fn test_dyn_dispatch() {
        let d = RoutingData::new().with_target_domain("test.com");
        let ctx: &dyn RoutingContext = &d;
        assert_eq!(ctx.get_target_domain(), "test.com");
    }

    #[test]
    fn test_attributes_default_empty() {
        let d = RoutingData::default();
        assert!(d.get_attributes().is_empty());
    }

    #[test]
    fn test_with_attributes() {
        let mut attrs = HashMap::new();
        attrs.insert(":path".to_string(), "/test".to_string());
        let d = RoutingData::new().with_attributes(attrs);
        assert_eq!(d.get_attributes().get(":path"), Some(&"/test".to_string()));
    }
}
