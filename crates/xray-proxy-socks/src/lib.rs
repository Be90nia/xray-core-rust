//! # xray-proxy-socks
//!
//! SOCKS 代理协议——RFC 1928 (SOCKS5) / RFC 1929 (用户名密码认证) + SOCKS4/4a 兼容。
//! 对应 Go `proxy/socks/`。
//!
//! ## 切片边界
//!
//! - 切片1（已完成）：配置层 + 协议常量 + SOCKS5 addr/UDP 包编解码
//! - 切片2（已完成）：SOCKS5 server handshake + `SocksServer`
//! - 切片3（本提交）：`SocksClient` outbound + dispatcher 接入（NoAuth/Password 都支持）

pub mod client;
pub mod config;
pub mod dispatcher;
pub mod error;
pub mod protocol;
pub mod server;

// 顶层 re-export。
pub use client::{ClientConfig, SocksClient};
pub use config::{Account, AuthType, ClientConfig as ProtoClientConfig, ServerConfig};
pub use dispatcher::make_dial_fn as make_socks_dial_fn;
pub use error::{Result, SocksError};
pub use protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_NO_MATCHING_METHOD, AUTH_NOT_REQUIRED, AUTH_PASSWORD,
    CMD_TCP_BIND, CMD_TCP_CONNECT, CMD_UDP_ASSOCIATE, Host, SOCKS4_REQUEST_GRANTED,
    SOCKS4_REQUEST_REJECTED, SOCKS4_VERSION, SOCKS5_VERSION, STATUS_CMD_NOT_SUPPORT,
    STATUS_SUCCESS, SocksAddr, decode_udp_packet, encode_udp_packet, parse_address_port,
    write_address_port,
};
pub use server::{SocksServer, socks_handshake, socks4_handshake, socks5_server_handshake};
