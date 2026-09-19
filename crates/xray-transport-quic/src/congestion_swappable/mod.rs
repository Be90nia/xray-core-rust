//! Congestion control —— 可共享拥塞控制子模块（对应 Go `congestion/`）。
//!
//! s8ti 起自 xray-transport-hysteria 提炼为跨协议共享模块：hysteria 侧
//! `pub use … as congestion` 保路径，TUIC 消费同一 [`HysteriaCCSlot`] 通道。
//!
//! 含：
//! - [`types`]：共享类型（ByteCount / PacketNumber / MonoTime 等）
//! - [`pacer`]：`Pacer` token bucket pacer（BBR/Brutal 共用）
//! - [`brutal`]：BrutalSender 固定带宽发送器
//! - [`bbr`]：完整 BBR 算法（含 bandwidth sampler + bbr sender + 窗口工具）
//! - [`utils`]：UseBBR / UseBrutal 入口（QUIC conn 操作留 trait）
//! - [`quinn_bridge`]：quinn Controller 桥（HysteriaCCSlot + 预装工厂 + apply_*）
//! - [`error`]：模块本地错误类型（自 hysteria error 解耦）

pub mod bbr;
pub mod brutal;
pub mod error;
pub mod pacer;
pub mod quinn_bridge;
pub mod types;
pub mod utils;

pub use brutal::{parse_bandwidth_bps, BrutalSender};
pub use error::{CongestionError, Result};
pub use pacer::Pacer;
pub use quinn_bridge::{apply_bbr, apply_brutal, install_swappable_cc, HysteriaCCSlot};
