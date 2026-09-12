//! SS-2022 (SIP022) protocol module.
//!
//! 对应 Go `proxy/shadowsocks_2022/`（thin wrapper over sing-shadowsocks）。
//! Rust 端手写协议层（blake3 key 派生 + TCP header + chunk），复用 `SSStream`。

pub mod client;
pub mod inbound;
pub mod key;
pub mod outbound;
pub mod packet;
pub mod replay;

pub use client::Client2022;
pub use inbound::{
    InboundResult, MultiUserInbound, RelayDestination, RelayInbound, Ss2022Inbound, Ss2022User,
};
pub use key::{CipherKind2022, derive_psk, derive_session_subkey, psk_from_base64};
pub use outbound::{Ss2022Outbound, Ss2022OutboundConfig, UdpOverTcpConfig};
pub use packet::{ClientUdpSession2022, DecodedClientHeader, ServerUdpSession2022, SlidingWindow};
