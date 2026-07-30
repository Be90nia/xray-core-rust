//! `xray-transport-hysteria` — Hysteria 传输协议（Go `transport/internet/hysteria`）。
//!
//! # 当前实现范围
//!
//! 业务核心 1:1 翻译自 Go `transport/internet/hysteria/`，所有逻辑独立可测：
//!
//! - **Config**（[`config`]）：常量（HTTP/3 路径、frame type、padding 范围、`Status` 三态、
//!   context keys）+ padding 随机字符串生成器。
//! - **ProtoConfig**（[`proto_config`]）：包裹 prost 生成的 `Config`，提供
//!   `default_config()` + 字段访问器。
//! - **UdpHop**（[`udphop`]）：`UdpHopPacketConn` —— 多端口 UDP 跳跃连接，完整翻译
//!   Go `udphop/conn.go` 的 hop/recv 循环 + buf pool 复用。
//! - **Congestion / Pacer**（[`congestion::common`]）：token bucket pacer，BBR/Brutal 共用。
//! - **Congestion / Brutal**（[`congestion::brutal`]）：固定带宽发送器 + ACK 率滑动窗口统计。
//! - **Congestion / BBR**（[`congestion::bbr`]）：完整 BBR 算法翻译（bandwidth sampler +
//!   bbr sender 状态机 + windowed filter + ring buffer + packet number queue）。
//! - **Conn**（[`conn`]）：`InterConn`（QUIC stream 抽象） + `UdpSessionManager`
//!   （QUIC datagram 多路复用 UDP session）。
//!
//! # IO 边界（trait + stub）
//!
//! 以下依赖外部资源（QUIC、HTTP/3、TLS、UDP socket），留 trait + 默认 stub 实现，
//! 等上层接入 quinn / h3 / rustls：
//!
//! - **Dialer**（[`dialer`]）：`HysteriaDialerFactory` trait。Go `Dial` 依赖
//!   `http3.Transport.RoundTrip`（HTTP/3 auth 握手）+ `quic.Transport.DialEarly`
//!   （QUIC 连接）+ `internet.DialSystem`（UDP）+ `UdpmaskManager`。当前仅定义
//!   trait + 编排框架，实际 QUIC/HTTP3 留待上层注入。
//! - **Listener**（[`hub`]）：`HysteriaListenerFactory` trait。Go `Listen` 依赖
//!   `http3.Server.ServeQUICConn` + `quic.Transport.Listen` + masquerade HTTP handler
//!   （404/file/proxy/string 四种伪装）。当前仅定义 trait + 编排框架。
//!
//! # quinn 适配（5lb 切片1a）
//!
//! [`quinn_adapter`] 模块提供 quinn 0.11 → hysteria trait 的包装：
//! [`quinn_adapter::QuinnQuicConn`] / [`quinn_adapter::QuinnQuicStream`] 实现
//! [`conn::QuicConn`] / [`conn::QuicStream`]，让 hysteria interConn / UdpSessionManager
//! 直接复用 quinn QUIC 栈。不含 transport（dial+auth）和 congestion controller 适配。

pub mod congestion;
pub mod config;
pub mod conn;
pub mod context;
pub mod dialer;
pub mod error;
pub mod hub;
pub mod proto_config;
pub mod udphop;
pub mod quinn_adapter;
pub mod hysteria_transport;
pub use config::{
    AuthRequestPadding, AuthResponsePadding, CommonHeaderCCRX, CommonHeaderPadding,
    FrameTypeTCPRequest, MaxDatagramFrameSize, RequestHeaderAuth, ResponseHeaderUDPEnabled,
    Status, StatusAuthOK, URLHost, URLPath,
};
pub use conn::{InterConn, UdpSessionManager};
pub use context::{ContextWithDatagram, ContextWithValidator, DatagramFromContext};
pub use dialer::HysteriaDialerFactory;
pub use error::{HysteriaError, Result};
pub use hub::{HysteriaListenerFactory, MasqType};
pub use proto_config::{Config, default_config};
pub use udphop::UdpHopPacketConn;
pub mod register;

/// 协议名（对应 Go `const protocolName = "hysteria"`）。
pub const PROTOCOL_NAME: &str = "hysteria";

pub use register::register_listener;
