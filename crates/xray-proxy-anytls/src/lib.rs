//! # xray-proxy-anytls
//!
//! AnyTLS 协议层 wrapper——基于 [anytls-rs](https://crates.io/crates/anytls) 0.3.6。
//!
//! ## 协议本质
//!
//! AnyTLS 是社区协议，把代理流量伪装成标准 TLS 连接，缓解 TLS-in-TLS 指纹检测。
//! 协议层结构：
//! 1. 客户端建立 TLS 连接到服务端
//! 2. 客户端在 stream 首帧发送 SOCKS5 格式目标地址
//! 3. 双向透传
//!
//! 见 [anytls-go protocol.md](https://github.com/anytls/anytls-go)。
//!
//! ## 切片边界（批次 A · 协议层 wrapper）
//!
//! - [`client::AnytlsClient`] + [`client::AnytlsConn`]——客户端 outbound，dial 后返回
//!   AsyncRead + AsyncWrite 的连接
//! - [`socks::SocksAddr`]——SOCKS5 ATYP+ADDR+PORT 编解码
//!
//! 未实现（留 dispatcher 接入后）：
//! - 接入 `xray-features::OutboundHandler` trait（现有 trait dial 返回 `()`，桥接层待切片3）
//! - server 端 inbound（待 dispatcher 接入后做）

pub mod client;
pub mod error;
pub mod server;
pub mod socks;

pub use client::{AnytlsClient, AnytlsConn, ClientConfig};
pub use error::{AnytlsError, Result};
pub use server::AnytlsMockServer;
pub use socks::SocksAddr;
