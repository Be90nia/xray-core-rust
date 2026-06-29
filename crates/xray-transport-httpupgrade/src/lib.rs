//! # xray-transport-httpupgrade
//!
//! HTTPUpgrade 传输协议——伪 WebSocket Upgrade 握手 + raw 字节流。
//! 对应 Go `transport/internet/httpupgrade/`。
//!
//! ## 协议本质
//!
//! HTTPUpgrade 是简化版 WebSocket：客户端发 HTTP/1.1 GET + `Connection: Upgrade` +
//! `Upgrade: websocket`，服务端回 `101 Switching Protocols`，之后连接字节流不再
//! 封装（无 WebSocket 帧头、无掩码）。本质是「HTTP 握手伪装 + 透明 TCP」组合，
//! 用于绕过 CDN/中间设备对 WebSocket 的支持。
//!
//! ## 切片边界（P5-6 切片1）
//!
//! 实现握手字节流的纯函数构造与解析，不涉及实际网络 IO：
//! - [`dialer::build_upgrade_request`] — 构造客户端 GET 请求
//! - [`dialer::parse_upgrade_response`] — 校验服务端 101 响应
//! - [`hub::parse_upgrade_request`] — 服务端解析 + 校验请求 + 提取 XFF
//! - [`hub::build_upgrade_response`] — 构造服务端 101 响应
//! - [`config::Config`] — 配置层 + 与 prost proto 双向转换
//!
//! 切片2 待办：实际 TCP/TLS 拨号（依赖 `xray-transport::Dialer` impl +
//! `xray-tls` uTLS）+ Listener `keepAccepting` 循环 + PROXY protocol 解析 +
//! `TcpmaskManager` 包装。

pub mod config;
pub mod connection;
pub mod dialer;
pub mod error;
pub mod hub;

// 顶层 re-export。
pub use config::Config;
pub use connection::HttpUpgradeConnection;
pub use dialer::{build_upgrade_request, parse_upgrade_response};
pub use error::{HttpUpgradeError, Result};
pub use hub::{UpgradeRequest, build_upgrade_response, parse_upgrade_request, parse_x_forwarded_for};
