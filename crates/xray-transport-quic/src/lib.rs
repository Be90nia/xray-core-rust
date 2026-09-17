//! # xray-transport-quic
//!
//! QUIC 传输协议——基于 quinn（rustls + ring）的双向 stream。
//! 对应 Go `transport/internet/quic/`。
//!
//! 本 crate 提供最小可用的 QUIC transport：
//! - [`transport::dial`] — 主动拨号：绑定本地 UDP socket → quinn connect → open_bi → duplex 桥接
//! - [`transport::listen`] — 监听：绑定 UDP socket → spawn accept loop → accept_bi → duplex 桥接
//! - [`register::register_dialer`] / [`register::register_listener`] — 注册到全局 transport 注册表（协议名 `"quic"`）
//!
//! 配置仅消费 TLS 层（[`xray_tls::client_config`] / [`xray_tls::server_config`]），
//! quicSettings 的 KeepAlive / 拥塞控制等参数留 follow-up。

pub mod congestion_swappable;
pub mod config;
pub mod register;
pub mod transport;
mod udp_gso;

pub use config::QuicConfig;
