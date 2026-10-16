#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
//! ## 切片2 （P1-639）
//!
//! 接入 `tokio-tungstenite` 0.26 + rustls，实现真实拨号/监听 + early data (0-RTT)：
//! - [`client::dial`] — TCP→TLS→WS 握手，构造自定义 request (host/path/Sec-WebSocket-Protocol)
//! - [`server::WsListener`] — TCP listener + accept_hdr_async 拦截 host/path 校验 + early data 提取
//! - [`ws_bridge::WsConnection`] — WebSocketStream → AsyncRead/AsyncWrite + Connection 包装
//!
//! 不在本切片：TcpmaskManager / PROXY protocol 解析 / X-Forwarded-For / 多 path 路由。

pub mod client;
pub mod config;
pub mod error;
pub mod handshake;
pub mod pool;
pub mod register;
pub mod server;
pub mod ws_bridge;
// 顶层 re-export。
pub use config::Config;
pub use error::{Result, WsError};
pub use handshake::{Opcode, WS_GUID, compute_accept_key, generate_client_key_for_testing};
pub use pool::{PoolKey, PooledConn, WsConnectionPool, WsPoolConfig, global_pool, reconfigure_global_pool};
pub use register::{register_dialer, register_listener};
pub use server::{AcceptedConn, WsListener};
pub use ws_bridge::WsConnection;
