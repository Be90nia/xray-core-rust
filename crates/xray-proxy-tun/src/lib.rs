//! # xray-proxy-tun
//!
//! TUN 设备代理——网络层 3 接入，把原始 IP 包桥接到 Xray 的 TCP/UDP stream。
//! 对应 Go `proxy/tun/`。
//!
//! ## 协议本质
//!
//! TUN 不是传统代理协议，而是把 Xray 包装成虚拟网卡：OS 把所有发往 `xray0`（或
//! `utun10`/`wintun` 等）的 IP 包交给 Xray，Xray 用 gVisor netstack 解封装为 TCP/UDP
//! 连接，再走正常代理链路。适合无法安装代理客户端的设备（智能电视、路由器下游）。
//!
//! ## 切片边界（P6-6 切片1）
//!
//! 实现纯逻辑与抽象层：
//! - [`config::score`] — 网络接口评分（用于选择默认出口接口），对应 Go `score`
//! - [`config::StackOptions`] — netstack 配置
//! - [`config::Tun`] / [`config::Stack`] trait — 设备与协议栈抽象
//!
//! 切片2 待办：`InterfaceUpdater`（网络接口动态查找）+ 平台 TUN 设备实现
//!（Linux/Windows/macOS/FreeBSD/Android/iOS）+ gVisor/smoltcp netstack 集成 +
//! TCP/UDP/ICMP 包处理 + UDP fullcone NAT。

pub mod config;
pub mod device;
pub mod error;

// 顶层 re-export。
pub use config::{Stack, StackOptions, Tun, score};
pub use device::TunDevice;
pub use error::{Result, TunError};
