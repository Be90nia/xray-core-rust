//! 会话管理与上下文
//!
//! 对应 Go 版本 `common/session` 包，定义会话 ID、入站/出站信息、
//! 内容类型和套接字选项等元数据。

use std::collections::HashMap;

use crate::net::destination::Destination;
use crate::net::network::Network;
use crate::uuid::UUID;

// ========== Session ID ==========

/// 会话 ID，基于 UUID。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ID(UUID);

impl ID {
    /// 生成新的随机会话 ID。
    pub fn new() -> Self {
        Self(UUID::new())
    }

    /// 从 UUID 创建会话 ID。
    pub fn from_uuid(uuid: UUID) -> Self {
        Self(uuid)
    }

    /// 获取内部 UUID 引用。
    pub fn as_uuid(&self) -> &UUID {
        &self.0
    }

    /// 消费自身，返回内部 UUID。
    pub fn into_uuid(self) -> UUID {
        self.0
    }
}

impl Default for ID {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ========== Inbound ==========

/// 入站处理器信息。
#[derive(Debug, Clone)]
pub struct Inbound {
    /// 入站处理器标签。
    pub tag: Option<String>,
    /// 入站网络类型。
    pub network: Option<Network>,
    /// 入站目标地址（对应 Go session.Destination）。
    pub destination: Option<Destination>,
}

impl Inbound {
    /// 创建新的入站信息。
    pub fn new() -> Self {
        Self {
            tag: None,
            network: None,
            destination: None,
        }
    }

    /// 设置标签（builder 模式）。
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// 设置网络类型（builder 模式）。
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// 设置目标地址（builder 模式）。
    pub fn with_destination(mut self, dest: Destination) -> Self {
        self.destination = Some(dest);
        self
    }
}

impl Default for Inbound {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Outbound ==========

/// 出站处理器信息。
#[derive(Debug, Clone)]
pub struct Outbound {
    /// 出站处理器标签。
    pub tag: Option<String>,
    /// 目的地覆盖（可选）。
    pub destination_override: Option<Destination>,
}

impl Outbound {
    /// 创建新的出站信息。
    pub fn new() -> Self {
        Self {
            tag: None,
            destination_override: None,
        }
    }

    /// 设置标签（builder 模式）。
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// 设置目的地覆盖（builder 模式）。
    pub fn with_destination_override(mut self, dest: Destination) -> Self {
        self.destination_override = Some(dest);
        self
    }
}

impl Default for Outbound {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Content ==========

/// 内容类型标识。
#[derive(Debug, Clone)]
pub struct Content {
    /// 内容类型字符串。
    pub content_type: Option<String>,
}

impl Content {
    /// 创建新的内容信息。
    pub fn new() -> Self {
        Self { content_type: None }
    }

    /// 设置内容类型（builder 模式）。
    pub fn with_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

impl Default for Content {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Sockopt ==========

/// 套接字选项。
#[derive(Debug, Clone)]
pub struct Sockopt {
    /// TCP 标记（用于路由）。
    pub mark: Option<u32>,
    /// TOS（服务类型）字段。
    pub tos: Option<u8>,
    /// TCP Fast Open。
    pub tcp_fast_open: bool,
    /// TCP Keep-Alive 间隔（秒）。
    pub tcp_keep_alive_interval: Option<u32>,
}

impl Sockopt {
    /// 创建新的套接字选项。
    pub fn new() -> Self {
        Self {
            mark: None,
            tos: None,
            tcp_fast_open: false,
            tcp_keep_alive_interval: None,
        }
    }

    /// 设置 TCP 标记（builder 模式）。
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// 设置 TOS（builder 模式）。
    pub fn with_tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// 设置 TCP Fast Open（builder 模式）。
    pub fn with_tcp_fast_open(mut self, fast_open: bool) -> Self {
        self.tcp_fast_open = fast_open;
        self
    }

    /// 设置 TCP Keep-Alive 间隔（builder 模式）。
    pub fn with_tcp_keep_alive_interval(mut self, interval: u32) -> Self {
        self.tcp_keep_alive_interval = Some(interval);
        self
    }
}

impl Default for Sockopt {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Session ==========

/// 会话上下文，携带入站/出站/内容/套接字选项等元数据。
#[derive(Debug, Clone)]
pub struct Session {
    /// 会话 ID。
    pub id: ID,
    /// 入站信息。
    pub inbound: Inbound,
    /// 出站信息。
    pub outbound: Outbound,
    /// 内容信息。
    pub content: Content,
    /// 套接字选项。
    pub sockopt: Sockopt,
    /// 任意属性映射。
    pub attributes: HashMap<String, String>,
}

impl Session {
    /// 创建新的会话。
    pub fn new() -> Self {
        Self {
            id: ID::new(),
            inbound: Inbound::new(),
            outbound: Outbound::new(),
            content: Content::new(),
            sockopt: Sockopt::new(),
            attributes: HashMap::new(),
        }
    }

    /// 设置入站信息（builder 模式）。
    pub fn with_inbound(mut self, inbound: Inbound) -> Self {
        self.inbound = inbound;
        self
    }

    /// 设置出站信息（builder 模式）。
    pub fn with_outbound(mut self, outbound: Outbound) -> Self {
        self.outbound = outbound;
        self
    }

    /// 设置内容信息（builder 模式）。
    pub fn with_content(mut self, content: Content) -> Self {
        self.content = content;
        self
    }

    /// 设置套接字选项（builder 模式）。
    pub fn with_sockopt(mut self, sockopt: Sockopt) -> Self {
        self.sockopt = sockopt;
        self
    }

    /// 设置属性。
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// 获取属性。
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// 获取入站目标地址（对应 Go session.Destination）。
    ///
    /// 优先返回 `outbound.destination_override`（如果设置了），
    /// 否则返回 `inbound.destination`。
    pub fn destination(&self) -> Option<&Destination> {
        self.outbound
            .destination_override
            .as_ref()
            .or(self.inbound.destination.as_ref())
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::address::Address;
    use crate::net::port::Port;
    use std::net::Ipv4Addr;

    // ---- ID 测试 ----

    #[test]
    fn test_id_new() {
        let id = ID::new();
        assert!(!id.as_uuid().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_id_unique() {
        let a = ID::new();
        let b = ID::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_id_from_uuid() {
        let uuid = UUID::new();
        let id = ID::from_uuid(uuid.clone());
        assert_eq!(id.as_uuid(), &uuid);
    }

    #[test]
    fn test_id_display() {
        let id = ID::new();
        let display = format!("{id}");
        assert!(!display.is_empty());
        assert!(display.contains('-'));
    }

    #[test]
    fn test_id_default() {
        let id = ID::default();
        assert!(!id.as_uuid().as_bytes().iter().all(|&b| b == 0));
    }

    // ---- Inbound 测试 ----

    #[test]
    fn test_inbound_new() {
        let inbound = Inbound::new();
        assert!(inbound.tag.is_none());
        assert!(inbound.network.is_none());
    }

    #[test]
    fn test_inbound_with_tag() {
        let inbound = Inbound::new().with_tag("http-in");
        assert_eq!(inbound.tag, Some("http-in".to_string()));
    }

    #[test]
    fn test_inbound_with_network() {
        let inbound = Inbound::new().with_network(Network::TCP);
        assert_eq!(inbound.network, Some(Network::TCP));
    }

    #[test]
    fn test_inbound_default() {
        let inbound = Inbound::default();
        assert!(inbound.tag.is_none());
    }

    // ---- Outbound 测试 ----

    #[test]
    fn test_outbound_new() {
        let outbound = Outbound::new();
        assert!(outbound.tag.is_none());
        assert!(outbound.destination_override.is_none());
    }

    #[test]
    fn test_outbound_with_tag() {
        let outbound = Outbound::new().with_tag("proxy-out");
        assert_eq!(outbound.tag, Some("proxy-out".to_string()));
    }

    #[test]
    fn test_outbound_with_destination_override() {
        let dest = Destination::tcp(
            Address::ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::new(8080),
        );
        let outbound = Outbound::new().with_destination_override(dest.clone());
        assert_eq!(outbound.destination_override, Some(dest));
    }

    #[test]
    fn test_outbound_default() {
        let outbound = Outbound::default();
        assert!(outbound.tag.is_none());
    }

    // ---- Content 测试 ----

    #[test]
    fn test_content_new() {
        let content = Content::new();
        assert!(content.content_type.is_none());
    }

    #[test]
    fn test_content_with_type() {
        let content = Content::new().with_type("application/json");
        assert_eq!(content.content_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_content_default() {
        let content = Content::default();
        assert!(content.content_type.is_none());
    }

    // ---- Sockopt 测试 ----

    #[test]
    fn test_sockopt_new() {
        let sockopt = Sockopt::new();
        assert!(sockopt.mark.is_none());
        assert!(sockopt.tos.is_none());
        assert!(!sockopt.tcp_fast_open);
        assert!(sockopt.tcp_keep_alive_interval.is_none());
    }

    #[test]
    fn test_sockopt_with_mark() {
        let sockopt = Sockopt::new().with_mark(123);
        assert_eq!(sockopt.mark, Some(123));
    }

    #[test]
    fn test_sockopt_with_tos() {
        let sockopt = Sockopt::new().with_tos(0x10);
        assert_eq!(sockopt.tos, Some(0x10));
    }

    #[test]
    fn test_sockopt_with_tcp_fast_open() {
        let sockopt = Sockopt::new().with_tcp_fast_open(true);
        assert!(sockopt.tcp_fast_open);
    }

    #[test]
    fn test_sockopt_with_tcp_keep_alive_interval() {
        let sockopt = Sockopt::new().with_tcp_keep_alive_interval(30);
        assert_eq!(sockopt.tcp_keep_alive_interval, Some(30));
    }

    #[test]
    fn test_sockopt_default() {
        let sockopt = Sockopt::default();
        assert!(!sockopt.tcp_fast_open);
    }

    // ---- Session 测试 ----

    #[test]
    fn test_session_new() {
        let session = Session::new();
        assert!(!session.id.as_uuid().as_bytes().iter().all(|&b| b == 0));
        assert!(session.inbound.tag.is_none());
        assert!(session.outbound.tag.is_none());
        assert!(session.attributes.is_empty());
    }

    #[test]
    fn test_session_with_inbound() {
        let inbound = Inbound::new().with_tag("test-in");
        let session = Session::new().with_inbound(inbound.clone());
        assert_eq!(session.inbound.tag, inbound.tag);
    }

    #[test]
    fn test_session_with_outbound() {
        let outbound = Outbound::new().with_tag("test-out");
        let session = Session::new().with_outbound(outbound.clone());
        assert_eq!(session.outbound.tag, outbound.tag);
    }

    #[test]
    fn test_session_with_content() {
        let content = Content::new().with_type("text/html");
        let session = Session::new().with_content(content.clone());
        assert_eq!(session.content.content_type, content.content_type);
    }

    #[test]
    fn test_session_with_sockopt() {
        let sockopt = Sockopt::new().with_mark(255);
        let session = Session::new().with_sockopt(sockopt.clone());
        assert_eq!(session.sockopt.mark, sockopt.mark);
    }

    #[test]
    fn test_session_attributes() {
        let mut session = Session::new();
        session.set_attribute("key1", "value1");
        session.set_attribute("key2", "value2");

        assert_eq!(session.get_attribute("key1"), Some("value1"));
        assert_eq!(session.get_attribute("key2"), Some("value2"));
        assert_eq!(session.get_attribute("nonexistent"), None);
    }

    #[test]
    fn test_session_set_attribute_overwrite() {
        let mut session = Session::new();
        session.set_attribute("key", "value1");
        session.set_attribute("key", "value2");
        assert_eq!(session.get_attribute("key"), Some("value2"));
    }

    #[test]
    fn test_session_default() {
        let session = Session::default();
        assert!(session.attributes.is_empty());
    }

    #[test]
    fn test_session_clone() {
        let mut session = Session::new();
        session.set_attribute("key", "value");
        let cloned = session.clone();
        assert_eq!(cloned.get_attribute("key"), Some("value"));
    }

    #[test]
    fn test_session_builder_chain() {
        let session = Session::new()
            .with_inbound(Inbound::new().with_tag("in"))
            .with_outbound(Outbound::new().with_tag("out"))
            .with_content(Content::new().with_type("json"))
            .with_sockopt(Sockopt::new().with_mark(100));

        assert_eq!(session.inbound.tag, Some("in".to_string()));
        assert_eq!(session.outbound.tag, Some("out".to_string()));
        assert_eq!(session.content.content_type, Some("json".to_string()));
        assert_eq!(session.sockopt.mark, Some(100));
    }
}
