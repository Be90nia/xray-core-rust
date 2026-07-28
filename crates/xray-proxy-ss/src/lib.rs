//! Shadowsocks 代理协议（Go→Rust 翻译版）
//!
//! 对应 Go `proxy/shadowsocks/`：
//! - `config.go`：Cipher trait + AEADCipher + NoneCipher + MemoryAccount
//! - `protocol.go`：TCP/UDP 会话与包编解码
//! - `validator.go`：用户验证器
//! - `client.go` / `server.go`：入站/出站处理器
//!
//! 协议常量与 Go 端一致。

pub mod client;
pub mod inbound;
pub mod outbound;
pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod stream;
pub mod validator;
pub mod ss2022;

pub use config::{AeadCipher, Cipher, CipherType, InnerAead, MemoryAccount};
pub use error::{Result, SsError};
pub use validator::Validator;
pub use inbound::SsInbound;
pub use outbound::SsOutbound;
pub use ss2022::{
    Client2022, CipherKind2022, InboundResult, MultiUserInbound, RelayDestination,
    RelayInbound, Ss2022Inbound, Ss2022Outbound, Ss2022OutboundConfig, Ss2022User,
    UdpOverTcpConfig, derive_session_subkey, psk_from_base64,
};

/// Shadowsocks 协议版本，对应 Go `protocol.Version`。
pub const VERSION: u8 = 1;

/// 行为种子的 HMAC key，对应 Go `[]byte("SSBSKDF")`。
pub const SSBSKDF: &[u8] = b"SSBSKDF";

/// HKDF 派生 subkey 的 info，对应 Go `[]byte("ss-subkey")`。
pub const SS_SUBKEY: &[u8] = b"ss-subkey";
