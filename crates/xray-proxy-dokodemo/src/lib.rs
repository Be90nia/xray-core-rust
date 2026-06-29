//! # xray-proxy-dokodemo
//!
//! Dokodemo-door 入站代理——把所有连接重定向到固定目标地址，或跟随 iptables
//! REDIRECT 的原始目标地址（透明代理）。对应 Go `proxy/dokodemo/`。
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 实现配置层 + `predefined_address`/`allows_network` 纯函数 + Network 枚举
//! + prost 双向转换。Handler/Process/fakeudp 留切片2（依赖 transport/session/
//! policy + Linux SO_ORIGINAL_DST syscall）。

pub mod config;
pub mod error;

// 顶层 re-export。
pub use config::{Config, Network, PredefinedAddress};
pub use error::{DokodemoError, Result};
