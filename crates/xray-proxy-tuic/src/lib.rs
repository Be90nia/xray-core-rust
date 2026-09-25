//! # xray-proxy-tuic
//!
//! TUIC v5 协议代理（TCP relay 切片1 + UDP relay 切片2）。
//!
//! ## 切片范围
//!
//! - 完整协议层（Address + Header + 4 命令：Authenticate/Connect/Dissociate/Heartbeat）
//! - TCP relay 客户端 + mock server，loopback 端到端测试通过
//! - UDP relay（quic 模式：每包 uni-stream；native 模式：QUIC DATAGRAM）， [`udp::TuicUdpAssoc`] +
//!   mock server UDP 转发
//! - HTTP/3 ALPN 伪装（握手 ALPN 同时 offer `h3` 与 `tuic`，官方伪装语义）
//! - quinn 内置 QUIC（已就绪）+ rustls（watfaq fork）
//!
//! ## 后续待办
//!
//! - UDP 分片重组（FRAG_TOTAL/FRAG_ID/SIZE）
//! - native 模式（QUIC DATAGRAM 传输 UDP 包）
//! - 自定义 congestion controller（BBR/Brutal）——s8ti 已落地：
//!   `congestion_control=hysteria_bbr/hysteria_brutal`（+`brutal_up_bps`）经 xray-transport-quic
//!   共享 HysteriaCCSlot 通道预装；quinn 内建三臂默认不变

pub mod client;
pub mod dispatcher;
pub mod error;
pub mod inbound;
pub mod pool;
pub mod protocol;
pub mod server;
pub mod udp;

pub use client::{CongestionControl, TuicClient, TuicConn, TuicConnectOptions, UdpRelayMode};
pub use dispatcher::{
    TuicConnection, make_dial_fn as make_tuic_dial_fn, make_dial_fn_lazy as make_tuic_dial_fn_lazy,
};
pub use error::{Result, TuicError};
pub use inbound::{TuicInboundConfig, TuicInboundHandler};
pub use pool::{MultiplexedConnection, PoolKey, QuinnConnectionPool, ReconnectingConnection};
pub use protocol::{Address, Command, FragmentAssembler, Packet, TOKEN_LEN, VERSION};
pub use server::TuicMockServer;
pub use udp::TuicUdpAssoc;
