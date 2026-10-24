#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_macros,
        clippy::print_stdout,
        clippy::print_stderr
    )
)] // 测试目标统一豁免（脚手架 spawn/print 断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
pub mod config;
pub mod dispatcher;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod protocol;
pub mod server;
pub mod ss2022;
pub mod stream;
pub mod validator;

pub use config::{AeadCipher, Cipher, CipherType, InnerAead, MemoryAccount};
pub use dispatcher::{
    Ss2022DialParams, SsConnection, SsOutboundConfig, make_ss_dial_fn, parse_ss_config,
};
pub use error::{Result, SsError};
pub use inbound::SsInbound;
pub use outbound::SsOutbound;
pub use ss2022::{
    CipherKind2022, Client2022, InboundResult, MultiUserInbound, RelayDestination, RelayInbound,
    Ss2022Inbound, Ss2022Outbound, Ss2022OutboundConfig, Ss2022User, UdpOverTcpConfig,
    derive_session_subkey, psk_from_base64,
};
pub use validator::Validator;

/// Shadowsocks 协议版本，对应 Go `protocol.Version`。
pub const VERSION: u8 = 1;

/// 行为种子的 HMAC key，对应 Go `[]byte("SSBSKDF")`。
pub const SSBSKDF: &[u8] = b"SSBSKDF";

/// HKDF 派生 subkey 的 info，对应 Go `[]byte("ss-subkey")`。
pub const SS_SUBKEY: &[u8] = b"ss-subkey";
