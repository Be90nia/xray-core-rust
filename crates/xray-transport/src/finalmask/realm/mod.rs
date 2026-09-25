//! # Realm NAT 穿透伪装（对应 Go `transport/internet/finalmask/realm/`）
//!
//! 基于 STUN 反射 + HTTP REST 信令 + UDP 打洞的 NAT 穿透方案。
//! 仅支持 UDP（无 TCP），实现 [`crate::finalmask::Udpmask`] trait。
//!
//! 子模块：
//! - [`punch`]：UDP 打洞包协议
//! - [`stun`]：STUN 客户端 + NAT 端口预测
//! - [`http`]：HTTP REST + SSE 客户端
//! - [`conn`]：RealmConnClient/Server + UdpIo 桥接

use std::io;

use crate::finalmask::{UdpIo, Udpmask};

pub mod conn;
pub mod http;
pub mod punch;
pub mod stun;

pub use conn::{RealmConfig, RealmConnClient, RealmConnServer};
pub use http::{
    Client, ConnectRequest, ConnectResponse, ErrorResponse, HeartbeatRequest, HeartbeatResponse,
    PunchEvent, RegisterResponse, StatusError,
};
pub use punch::{PunchMetadata, PunchPacket, PunchPacketType};
pub use stun::{
    addr_port_strings, build_binding_request, candidate_punch_addrs,
    expand_symmetric_nat_candidates, is_stun_message, parse_addr_ports,
    parse_stun_binding_response, predictable_port_group, resolve_stun_servers, unique_sorted_ports,
};

/// Realm 配置（对应 Go `realm.Config` protobuf）。
///
/// 字段对应 Go protobuf：
/// ```text
/// message Config {
///   string scheme = 1;
///   string host = 2;
///   string port = 3;
///   string token = 4;
///   string id = 5;
///   repeated string stun_servers = 6;
/// }
/// ```
///
/// Go 端另有 `tls_config` 字段，Rust 端用 `use_tls: bool` 简化——TLS 协商细节
/// 由 reqwest 默认 rustls connector 处理。
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub token: String,
    pub id: String,
    pub stun_servers: Vec<String>,
    pub use_tls: bool,
}

impl From<&Config> for RealmConfig {
    fn from(c: &Config) -> Self {
        RealmConfig {
            scheme: c.scheme.clone(),
            host: c.host.clone(),
            port: c.port.clone(),
            token: c.token.clone(),
            id: c.id.clone(),
            stun_servers: c.stun_servers.clone(),
            use_tls: c.use_tls,
        }
    }
}

impl Udpmask for Config {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let realm_cfg: RealmConfig = self.into();
        let conn = RealmConnClient::new(&realm_cfg, raw)?;
        Ok(Box::new(conn))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let realm_cfg: RealmConfig = self.into();
        let conn = RealmConnServer::new(&realm_cfg, raw)?;
        Ok(Box::new(conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_into_realm_config() {
        let c = Config {
            scheme: "https".into(),
            host: "example.com".into(),
            port: "443".into(),
            token: "tok".into(),
            id: "realm-x".into(),
            stun_servers: vec!["stun.l.google.com:19302".into()],
            use_tls: true,
        };
        let r: RealmConfig = (&c).into();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, "443");
        assert_eq!(r.token, "tok");
        assert_eq!(r.id, "realm-x");
        assert_eq!(r.stun_servers.len(), 1);
        assert!(r.use_tls);
    }

    #[test]
    fn config_default_into_empty_realm_config() {
        let c = Config::default();
        let r: RealmConfig = (&c).into();
        assert!(r.scheme.is_empty());
        assert!(!r.use_tls);
    }
}
