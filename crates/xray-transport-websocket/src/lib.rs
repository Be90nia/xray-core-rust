//! # xray-transport-websocket
//!
//! WebSocket 传输协议——RFC 6455 标准 WebSocket 握手 + 帧编解码。
//! 对应 Go `transport/internet/websocket/`。
//!
//! ## 协议本质
//!
//! Xray 的 WebSocket 传输是标准 RFC 6455 实现：HTTP/1.1 Upgrade 握手 + 二进制
//! WebSocket 帧承载 payload。Go 端用 `gorilla/websocket` 处理帧编解码，Xray 只做
//! 连接包装（心跳 ping + X-Forwarded-For）。
//!
//! ## 切片边界（P5-5 切片1）
//!
//! 实现独立可测的纯逻辑部分：
//! - [`config::Config`] — 6 字段配置 + prost 双向转换
//! - [`handshake::compute_accept_key`] — RFC 6455 Sec-WebSocket-Accept 计算 (SHA-1+base64)
//! - [`handshake::Opcode`] — 帧 opcode 枚举 + 控制帧判定
//!
//! 切片2 待办：实际 TCP/TLS 拨号 + 帧编解码 (依赖 `tokio-tungstenite` 替代
//! `gorilla/websocket`) + Listener keepAccepting 循环 + heartbeat ping 后台任务 +
//! PROXY protocol 解析 + TcpmaskManager 包装。

pub mod config;
pub mod error;
pub mod handshake;
pub mod client;
pub mod server;

// 顶层 re-export。
pub use config::Config;
pub use error::{Result, WsError};
pub use handshake::{Opcode, WS_GUID, compute_accept_key, generate_client_key_for_testing};
