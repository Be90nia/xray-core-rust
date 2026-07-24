//! # xray-proxy-tuic
//!
//! TUIC v5 协议代理（TCP relay 切片1 + UDP relay 切片2）。
//!
//! ## 切片范围
//!
//! - 完整协议层（Address + Header + 4 命令：Authenticate/Connect/Dissociate/Heartbeat）
//! - TCP relay 客户端 + mock server，loopback 端到端测试通过
//! - UDP relay（quic 模式：每包 bi-stream），[`udp::TuicUdpAssoc`] + mock server UDP 转发
//! - HTTP/3 ALPN 协商（`h3` 伪装已启用；real-h3 帧封装未实现）
//! - quinn 内置 QUIC（已就绪）+ rustls（watfaq fork）
//!
//! ## 后续待办
//!
//! - UDP 分片重组（FRAG_TOTAL/FRAG_ID/SIZE）
//! - native 模式（QUIC DATAGRAM 传输 UDP 包）
//! - 自定义 congestion controller（BBR/Brutal）
//! - real-h3 HTTP/3 帧封装传输层

pub mod client;
pub mod dispatcher;
pub mod error;
pub mod protocol;
pub mod server;
pub mod udp;

pub use client::{TuicClient, TuicConn};
pub use dispatcher::{make_dial_fn as make_tuic_dial_fn, TuicConnection};
pub use error::{Result, TuicError};
pub use protocol::{Address, Command, Packet, TOKEN_LEN, VERSION};
pub use server::TuicMockServer;
pub use udp::TuicUdpAssoc;
