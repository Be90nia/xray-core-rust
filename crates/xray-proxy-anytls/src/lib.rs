#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
//! - [`client::AnytlsClient`] + [`client::AnytlsConn`]——客户端 outbound，dial 后返回 AsyncRead +
//!   AsyncWrite 的连接
//! - [`socks::SocksAddr`]——SOCKS5 ATYP+ADDR+PORT 编解码
//!
//! 未实现（留 dispatcher 接入后）：
//! - server 端 inbound（待 dispatcher 接入后做）

pub mod client;
pub mod dispatcher;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod server;
pub mod socks;

pub use client::{AnytlsClient, AnytlsConn, ClientConfig};
pub use dispatcher::{AnytlsConnection, make_dial_fn as make_anytls_dial_fn};
pub use error::{AnytlsError, Result};
pub use inbound::AnytlsInboundHandler;
pub use outbound::AnytlsOutboundHandler;
pub use server::AnytlsMockServer;
pub use socks::SocksAddr;
