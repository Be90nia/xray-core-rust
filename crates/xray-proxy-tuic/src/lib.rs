//! # xray-proxy-tuic
//!
//! TUIC v5 协议代理（TCP relay 切片1）。
//!
//! ## 切片范围
//!
//! - 完整协议层（Address + Header + 4 命令：Authenticate/Connect/Dissociate/Heartbeat）
//! - TCP relay 客户端 + mock server，loopback 端到端测试通过
//! - quinn 内置 QUIC（已就绪）+ rustls（watfaq fork）
//!
//! ## 切片2 待办
//!
//! - Packet 命令 + UDP relay（datagram 模式 + stream 模式）
//! - UDP 分片重组（FRAG_TOTAL/FRAG_ID/SIZE）
//! - 多 ALPN 协商（h3 伪装）
//! - 自定义 congestion controller（BBR/Brutal）

pub mod client;
pub mod dispatcher;
pub mod error;
pub mod protocol;
pub mod server;

pub use client::{TuicClient, TuicConn};
pub use dispatcher::{make_dial_fn as make_tuic_dial_fn, TuicConnection};
pub use error::{Result, TuicError};
pub use protocol::{Address, Command, TOKEN_LEN, VERSION};
pub use server::TuicMockServer;
