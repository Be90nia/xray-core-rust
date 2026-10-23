#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
//! - [`outbound`] — [`WireguardOutboundHandler`]（driver/netstack lazy-init 容器； 生产 dial 走
//!   ``dispatcher::make_wireguard_dial_fn`）
//! - [`inbound`] — [`WireguardInboundHandler`] 实现
//!   [`InboundHandler`](xray_features::inbound::InboundHandler)
//!
//! 数据面已实装：TCP/UDP 双向经 smoltcp netstack ↔ dispatcher 桥接（`inbound` 收 +
//! `dispatcher::make_wireguard_dial_fn` 发）。端到端验收见
//! `tests/integration/wireguard_dataplane_test.rs`。

pub mod config;
pub mod dispatcher;
pub mod driver;
pub mod error;
pub mod inbound;
pub mod netstack;
pub mod outbound;
pub mod peer;
pub mod plugin;
pub mod tunnel;
pub mod users;
pub mod wireguard;

// 顶层 re-export。
pub use config::{DeviceConfig, PeerConfig};
pub use dispatcher::make_wireguard_dial_fn;
pub use driver::WgDriver;
pub use error::{Result, WgError};
pub use inbound::WireguardInboundHandler;
pub use netstack::{TcpAcceptEvent, VirtualDevice, WgNetStack};
pub use outbound::WireguardOutboundHandler;
pub use peer::{PeerSession, SharedPeer};
pub use plugin::{WireguardBuiltConfig, WireguardLifecycle, WireguardPlugin};
pub use tunnel::{Output as TunnelOutput, Tunnel};
pub use users::{WgUser, WgUserRegistry};
pub use wireguard::{
    ParsedEndpoints, SERVER_LISTEN_PORT_PLACEHOLDER, create_ipc_request, parse_endpoints,
};
