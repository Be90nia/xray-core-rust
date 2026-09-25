//! Trojan 代理协议（Go→Rust 翻译版）
//!
//! 对应 Go `proxy/trojan/`：
//! - `config.go`：`MemoryAccount` + `hex_sha224` + `Account`
//! - `protocol.go`：TCP/UDP 协议帧编解码
//! - `validator.go`：用户验证器（dashmap 实现）
//! - `client.go` / `server.go`：入站/出站处理器（切片2 待实现）
//!
//! # 协议常量
//!
//! 与 Go 端一致：`commandTCP=1` / `commandUDP=3` / `maxLength=8192` / `CRLF="\r\n"`。
//!
//! # 当前切片（切片1）
//!
//! 提供完整的协议帧编解码 + 用户验证 API（独立可测试）。
//! 真正的网络 IO（AsyncRead/AsyncWrite 包装、transport::Link 接入、fallbacks 处理）
//! 留给切片2。

pub mod client;
pub mod config;
pub mod dispatcher;
pub mod error;
pub mod fallback;
pub mod protocol;
pub mod server;
pub mod validator;

pub use client::TrojanClient;
pub use config::{
    ACCOUNT_TYPE_URL, Account, ClientConfig, HEX_KEY_LEN, MemoryAccount, ServerConfig, hex_sha224,
    hex_string, md5_key,
};
pub use dispatcher::{TrojanOutboundConfig, make_dial_fn as make_trojan_dial_fn};
pub use error::{Result, TrojanError};
pub use protocol::{
    COMMAND_TCP, COMMAND_UDP, CRLF, MAX_LENGTH, MD5_KEY_LEN, Network, V2_VERSION, addr_type,
    is_v1_hex_prefix, parse_request_header, parse_request_header_v2, parse_udp_packet,
    read_address_port, write_address_port, write_request_header, write_request_header_v2,
    write_udp_packet,
};
pub use server::{TrojanServer, serve_trojan, serve_trojan_conn, trojan_server_handshake};
pub use validator::{MemoryUser, Validator};
