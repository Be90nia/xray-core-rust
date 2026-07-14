//! # xray-proxy-wireguard
//!
//! WireGuard 代理协议——把 WireGuard VPN 包装为 Xray 的 inbound/outbound 代理。
//! 对应 Go `proxy/wireguard/`。
//!
//! ## 协议本质
//!
//! Xray WireGuard 代理不是协议级代理（如 SOCKS/HTTP），而是把整个 WireGuard 设备
//! 嵌入 Xray：客户端通过 WireGuard 隧道转发流量，服务端解封装后路由。Go 端用
//! `boringtun`（Cloudflare userspace WireGuard）+ gVisor netstack 实现。
//!
//! ## 切片边界（P6-7 切片1）
//!
//! 实现独立可测的纯逻辑部分：
//! - [`config::DeviceConfig`] / [`config::PeerConfig`] / [`config::DomainStrategy`] —
//!   配置层 + 5 种 DNS 策略的 prefer/fallback 判定 + prost 双向转换
//! - [`wireguard::parse_endpoints`] — endpoint 字符串解析（纯 IP / CIDR + 双栈检测）
//! - [`wireguard::create_ipc_request`] — DeviceConfig → WireGuard IPC 请求字符串
//!
//! 切片2 待办：UDP socket driver loop（tokio task 路由 socket↔Tunnel）+
//! smoltcp netstack + InboundHandler/OutboundHandler 适配。
//! 切片1 已实现：[`tunnel::Tunnel`]——boringtun Tunn 包装，同步 encapsulate/decapsulate/update_timers。

pub mod config;
pub mod error;
pub mod tunnel;
pub mod wireguard;

// 顶层 re-export。
pub use config::{DeviceConfig, DomainStrategy, PeerConfig};
pub use error::{Result, WgError};
pub use tunnel::{Output as TunnelOutput, Tunnel};
pub use wireguard::{ParsedEndpoints, create_ipc_request, parse_endpoints, SERVER_LISTEN_PORT_PLACEHOLDER};
