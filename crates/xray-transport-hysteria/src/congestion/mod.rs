//! Congestion control —— 拥塞控制子模块（对应 Go `congestion/`）。
//!
//! 含：
//! - [`types`]：共享类型（ByteCount / PacketNumber / MonoTime 等）
//! - [`pacer`]：`Pacer` token bucket pacer（BBR/Brutal 共用）
//! - [`brutal`]：BrutalSender 固定带宽发送器
//! - [`bbr`]：完整 BBR 算法（含 bandwidth sampler + bbr sender + 窗口工具）
//! - [`utils`]：UseBBR / UseBrutal 入口（QUIC conn 操作留 trait）

pub mod bbr;
pub mod brutal;
pub mod pacer;
pub mod types;
pub mod utils;

pub use brutal::BrutalSender;
pub use pacer::Pacer;
