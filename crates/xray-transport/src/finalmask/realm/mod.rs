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
pub mod tls;

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
///   xray.transport.internet.tls.Config tls_config = 7;
/// }
/// ```
///
/// `tls` 为 [`tls::TlsConfig`] 结构化信令 TLS 配置（`tlsConfig` JSON →
/// `GetTLSConfig` 字段子集，见 `tls.rs` 对齐表）；`None` = 缺省，reqwest 默认
/// rustls 路径（旧 `use_tls:true` 行为，向后兼容）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub token: String,
    pub id: String,
    pub stun_servers: Vec<String>,
    pub tls: Option<tls::TlsConfig>,
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
            tls: c.tls.clone(),
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
            tls: Some(tls::TlsConfig { alpn: vec!["h2".into()], ..Default::default() }),
        };
        let r: RealmConfig = (&c).into();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, "443");
        assert_eq!(r.token, "tok");
        assert_eq!(r.id, "realm-x");
        assert_eq!(r.stun_servers.len(), 1);
        assert_eq!(r.tls.as_ref().map(|t| t.alpn.as_slice()), Some(&["h2".to_string()][..]));
    }

    #[test]
    fn config_default_into_empty_realm_config() {
        let c = Config::default();
        let r: RealmConfig = (&c).into();
        assert!(r.scheme.is_empty());
        assert!(r.tls.is_none());
    }
}
