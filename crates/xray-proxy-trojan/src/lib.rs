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
pub mod protocol;
pub mod server;
pub mod validator;

pub use config::{hex_sha224, hex_string, Account, MemoryAccount, HEX_KEY_LEN};
pub use error::{Result, TrojanError};
pub use protocol::{
    addr_type, parse_request_header, parse_udp_packet, read_address_port, write_address_port,
    write_request_header, write_udp_packet, Network, COMMAND_TCP, COMMAND_UDP, CRLF, MAX_LENGTH,
};
pub use validator::{MemoryUser, Validator};
pub use server::{TrojanServer, trojan_server_handshake};
pub use dispatcher::{make_dial_fn as make_trojan_dial_fn, TrojanOutboundConfig};
