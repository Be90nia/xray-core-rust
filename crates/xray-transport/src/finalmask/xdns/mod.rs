//! # xdns：DNS-over-UDP 隧道伪装（对应 Go `transport/internet/finalmask/xdns/`）
//!
//! 把 UDP 代理流量伪装成普通 DNS 查询/响应——payload 被 base32 编码到 query name 的
//! 前缀 label，目标域名作为后缀；服务端解析 query.name，解码 payload，按 clientID
//! 路由到上层。响应把 payload 编码到 answer（TXT / A / AAAA 三种 RR 类型）。
//!
//! 仅 UDP（不实现 Tcpmask）。
//!
//! ## 子模块
//!
//! - [`dns`]：DNS wire format 编解码（RFC1035）
//! - [`spec`]：domainSpec / parseResolver
//! - [`record_transport`]：payload ↔ RR answers 编码
//! - `client`：[`XdnsConnClient`] 实现 [`super::UdpIo`]
//! - `server`：[`XdnsConnServer`] 实现 [`super::UdpIo`]
//! - `base32`：RFC4648 base32（无 padding）

pub(crate) mod base32;
mod client;
mod dns;
pub(crate) mod record_transport;
mod server;
pub(crate) mod spec;

use std::{io, time::Duration};

pub use spec::DomainSpec;

use super::{UdpIo, Udpmask};

/// client.rs 中用到的常量（顶层暴露便于子模块共享）。
pub(crate) const POLL_LIMIT: usize = 16;
pub(crate) const MAX_POLL_DELAY: Duration = Duration::from_secs(10);
pub const UDP_SIZE: usize = super::UDP_SIZE;

/// xdns 配置（对应 Go `xdns/Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 服务端：用于响应的域名规范（形如 "t.example.com[:txt|a|aaaa]"）。
    pub domains: Vec<String>,
    /// 客户端：解析器规范（形如 "domain[:rrType]+udp://resolver:53"）。
    pub resolvers: Vec<String>,
}

impl Udpmask for Config {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let client = client::XdnsConnClient::new(raw, self.resolvers.clone())?;
        Ok(Box::new(client))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let server = server::XdnsConnServer::new(raw, self.domains.clone())?;
        Ok(Box::new(server))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_empty() {
        let cfg = Config::default();
        assert!(cfg.domains.is_empty());
        assert!(cfg.resolvers.is_empty());
    }

    #[test]
    fn config_clone_preserves_fields() {
        let cfg = Config {
            domains: vec!["t.example.com".into()],
            resolvers: vec!["t.example.com+udp://8.8.8.8:53".into()],
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.domains, cfg.domains);
        assert_eq!(cloned.resolvers, cfg.resolvers);
    }
}
