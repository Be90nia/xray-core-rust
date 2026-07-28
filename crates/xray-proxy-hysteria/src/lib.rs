//! # xray-proxy-hysteria
//!
//! Hysteria 协议处理器（inbound + outbound），对应 Go `proxy/hysteria/`。
//!
//! ## 协议本质
//!
//! Hysteria 是基于 QUIC + 自定义 HTTP/3 auth 的高速代理协议。Xray 中：
//! - outbound：客户端拨号到 hysteria server，TCP/UDP 经 QUIC stream/datagram 转发
//! - inbound：服务端接收 hysteria 客户端，解封装为 Xray 内部流量
//!
//! ## 架构层次
//!
//! 本 crate 是 **协议处理器**层，连接 [`xray_transport_hysteria`]（transport 算法层）
//! 和 [`xray_features`]（代理 trait）：
//!
//! ```text
//! xray-features::OutboundHandler
//!     ↓ (本 crate 实现)
//! xray-transport-hysteria::HysteriaClient (编排)
//!     ↓
//! xray-transport-hysteria::HysteriaTransport trait
//!     ↓ (本 crate 提供 QuinnHysteriaTransport 实现)
//! quinn / h3 / rustls
//! ```
//!
//! ## 切片边界（task hyv 切片1）
//!
//! - **切片1（本提交）**：crate 骨架 + 错误类型 + 配置层（HysteriaConfig from proto）
//! - **切片2（待办）**：QuinnHysteriaTransport 实现（依赖 5lb 切片1b 的 auth 调研）
//! - **切片3（待办）**：HysteriaOutbound impl xray_features::OutboundHandler（桥接层）

pub mod config;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod protocol;
pub mod dispatcher;

pub use config::{HysteriaConfig, HysteriaInboundConfig, HysteriaUser, MultiUserValidator};
pub use error::{HysteriaProxyError, Result};
pub use inbound::{HysteriaInboundHandler, StaticAuthValidator, TcpDispatcher};
pub use outbound::HysteriaOutboundHandler;
pub use protocol::{Defragger, UdpMessage};
pub use dispatcher::make_hysteria_dial_fn;
