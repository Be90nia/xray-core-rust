//! TUIC v5 协议层（VER + TYPE + 负载）。
//!
//! 切片1 范围：Address + Header + 4 个命令（Authenticate / Connect / Dissociate / Heartbeat）。
//! 切片2 待办：Packet 命令 + UDP relay + 分片重组。

pub mod address;
pub mod command;

pub use address::Address;
pub use command::{parse_header, Command, TOKEN_LEN, VERSION};
