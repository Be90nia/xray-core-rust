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
//! ## 切片边界（P6-7 切片2/3）
//!
//! 切片1：[`config`] / [`wireguard`] / [`tunnel`]（纯逻辑部分）已实现。
//!
//! 切片2/3（本模块集合）：
//! - [`driver`] — UDP driver task（UdpSocket + Tunnel + smoltcp pump）
//! - [`netstack`] — smoltcp userspace 网络栈（IP 包 ↔ TCP/UDP socket）
//! - [`peer`] — peer 会话管理（Tunnel + endpoint + 握手状态）
//! - [`outbound`] — [`WireguardOutboundHandler`] 实现 [`OutboundHandler`](xray_features::outbound::OutboundHandler)
//! - [`inbound`] — [`WireguardInboundHandler`] 实现 [`InboundHandler`](xray_features::inbound::InboundHandler)
//!
//! 当前限制：dispatcher 桥接（smoltcp socket ↔ Xray router）留待后续切片。
//! dial/start 能创建 socket 与 driver，但实际用户数据拷贝未接入。

pub mod config;
pub mod driver;
pub mod error;
pub mod inbound;
pub mod netstack;
pub mod outbound;
pub mod peer;
pub mod tunnel;
pub mod wireguard;

// 顶层 re-export。
pub use config::{DeviceConfig, DomainStrategy, PeerConfig};
pub use driver::WgDriver;
pub use error::{Result, WgError};
pub use inbound::WireguardInboundHandler;
pub use netstack::{VirtualDevice, WgNetStack};
pub use outbound::WireguardOutboundHandler;
pub use peer::{PeerSession, SharedPeer};
pub use tunnel::{Output as TunnelOutput, Tunnel};
pub use wireguard::{ParsedEndpoints, create_ipc_request, parse_endpoints, SERVER_LISTEN_PORT_PLACEHOLDER};
