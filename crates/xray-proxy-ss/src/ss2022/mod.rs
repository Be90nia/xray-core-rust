//! SS-2022 (SIP022) protocol module.
//!
//! 对应 Go `proxy/shadowsocks_2022/`（thin wrapper over sing-shadowsocks）。
//! Rust 端手写协议层（blake3 key 派生 + TCP header + chunk），复用 `SSStream`。

pub mod client;
pub mod key;

pub use client::Client2022;
pub use key::{psk_from_base64, CipherKind2022, derive_session_subkey};
