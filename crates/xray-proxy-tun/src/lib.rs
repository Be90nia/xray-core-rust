#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 断言便利）；spawn 走 xray_common::testing（L3
// 闸不豁免），生产禁令不受影响
// 713x6 时钟禁令配套：测试耗时断言/夹具用裸时钟读数属测试面（存量不动），
// 生产站点逐点 allow + 理由登记（台账见 reports/audit-2026-10-26/proxy-clock-sweep.md）
#![cfg_attr(test, allow(clippy::disallowed_methods))]
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
//! - 切片2 待办：`InterfaceUpdater`（网络接口动态查找）+ 平台 TUN 设备实现
//!   （Linux/Windows/macOS/FreeBSD/Android/iOS）+ gVisor netstack 集成
//!   + TCP/UDP/ICMP 包处理 + UDP fullcone NAT。

use std::sync::LazyLock;

use xray_frame::LogFacade;

pub mod config;
pub mod dns_verify;
pub mod error;
pub mod inbound;
pub mod netstack;
pub mod outbound;
pub mod plugin;
pub mod sysroute;
pub mod tun_fd;
pub mod wfp;
// TUN 设备实现按平台门控：windows/macos/linux/bsd 走 tun_rs 真实现，
// android/ios 走 stub（移动端由宿主 App 注入流量，见 device_stub.rs）。
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod device;
// stub 必须占用同一 `crate::device` 路径：inbound.rs 等下游
// `use crate::device::TunDevice` 无需平台分支。
#[cfg(any(target_os = "android", target_os = "ios"))]
#[path = "device_stub.rs"]
pub mod device;

/// tun 域日志门面（nn8os 2b 同型处置：裸 tracing 宏 → LogFacade——本项目工具链上
/// `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶三形态实测
/// 无效），迁移为唯一关红路径）。域 = "tun"，target `xray_frame::tun` +
/// mask_secrets。
///
/// crate 级单例（域 = 协议名，全 crate 一个 target）：tun 面站点分布在
/// inbound / sysroute 两处，分模块各建一份会重复泄漏 target 字符串且 target
/// 相同——crate 级单份即可。
pub(crate) static TUN_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("tun", vec![]));

// 顶层 re-export。
pub use config::{Stack, StackOptions, Tun, score};
pub use device::TunDevice;
pub use dns_verify::{DnsRoutingProbe, register_dns_probe, verify_dns_routing};
pub use error::{Result, TunError};
pub use inbound::TunInboundHandler;
pub use netstack::{TcpAcceptEvent, TunNetStack, UdpRecvEvent};
pub use outbound::make_tun_dial_fn;
pub use plugin::{TunLifecycle, TunPlugin};
