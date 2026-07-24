//! TUIC v5 协议层（VER + TYPE + 负载）。
//!
//! 切片1 范围：Address + Header + 4 个命令（Authenticate / Connect / Dissociate / Heartbeat）。
//! 切片2 范围：Packet 帧 + UDP relay（bi-stream 模式）。分片重组仍待后续。

pub mod address;
pub mod command;
pub mod packet;

pub use address::Address;
pub use command::{parse_header, Command, TOKEN_LEN, VERSION};
pub use packet::Packet;
