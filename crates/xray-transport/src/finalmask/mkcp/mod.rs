//! # mkcp 伪装（3 种 mode）
//!
//! 对应 Go `transport/internet/finalmask/mkcp/`。
//!
//! ## Modes
//!
//! | Mode | 对应 Go 子包 | 说明 |
//! |------|-------------|------|
//! | [`original`] | `mkcp/original` | XOR 链 + FNV1a-32 轻量认证（无加密），Overhead=6 |
//! | [`aes128gcm`] | `mkcp/aes128gcm` | AES-128-GCM AEAD，Overhead=28（nonce 12 + tag 16） |
//! | [`header`] | `mkcp/header` | 协议头伪装（6 种：DNS/DTLS/SRTP/UTP/WECHAT/WIREGUARD） |
//!
//! 三种 mode 都实现 [`super::Udpmask`]，可被 [`super::UdpmaskManager`] 链式包装。

pub mod aes128gcm;
pub mod header;
pub mod original;
