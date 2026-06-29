//! # xray-proxy-socks
//!
//! SOCKS 代理协议——RFC 1928 (SOCKS5) / RFC 1929 (用户名密码认证) + SOCKS4/4a 兼容。
//! 对应 Go `proxy/socks/`。
//!
//! ## 切片边界（P6-5 49t 切片1）
//!
//! 实现配置层 + 协议常量 + SOCKS5 addr/UDP 包编解码（纯函数，独立可测）：
//! - [`config::Account`] / [`config::AuthType`] / [`config::ServerConfig`] / [`config::ClientConfig`] —
//!   配置 + `has_account` 认证校验 + prost 双向
//! - [`protocol`] — SOCKS5 协议常量（version/cmd/auth/status）+ `write/parse_address_port` +
//!   `encode/decode_udp_packet`
//!
//! 切片2 待办：完整 SOCKS4/5 握手（`ServerSession.handshake4/handshake5`）+
//! 客户端 `client.go` + 服务端 `server.go` + `temp_udp_listen.go`（临时 UDP 监听器）。

pub mod config;
pub mod error;
pub mod protocol;
pub mod client;
pub mod server;

// 顶层 re-export。
pub use config::{Account, AuthType, ClientConfig, ServerConfig};
pub use error::{Result, SocksError};
pub use protocol::{
    Host, SocksAddr,
    AUTH_NOT_REQUIRED, AUTH_NO_MATCHING_METHOD, AUTH_PASSWORD,
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    CMD_TCP_BIND, CMD_TCP_CONNECT, CMD_UDP_ASSOCIATE,
    SOCKS4_REQUEST_GRANTED, SOCKS4_REQUEST_REJECTED,
    SOCKS4_VERSION, SOCKS5_VERSION, STATUS_CMD_NOT_SUPPORT, STATUS_SUCCESS,
    decode_udp_packet, encode_udp_packet, parse_address_port, write_address_port,
};
