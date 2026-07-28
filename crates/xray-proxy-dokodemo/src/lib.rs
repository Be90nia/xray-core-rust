//! # xray-proxy-dokodemo
//!
//! Dokodemo-door 入站代理——把所有连接重定向到固定目标地址，或跟随 iptables
//! REDIRECT 的原始目标地址（透明代理）。对应 Go `proxy/dokodemo/`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! - [`config::Config`] + `predefined_address`/`allows_network` + Network 枚举 + prost 双向
//! - [`server::DokodemoServer`] + `impl InboundHandler`（start/accept/close lifecycle）
//!
//! 切片3 待办：dispatch to outbound handler + `follow_redirect`（SO_ORIGINAL_DST）+
//! port_map 端口映射 + TCP/UDP 双栈 + Unix socket 支持。

pub mod config;
pub mod error;
pub mod server;
pub mod outbound;

// 顶层 re-export。
pub use config::{Config, Network, PredefinedAddress};
pub use error::{DokodemoError, Result};
pub use server::DokodemoServer;
pub use outbound::{DokodemoOutboundConfig, make_dokodemo_dial_fn};
