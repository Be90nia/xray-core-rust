#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
//! # xray-proxy-masque
//!
//! MASQUE proxy（RFC 9484 CONNECT-IP；Go `proxy/masque/` 直译形态，裁定基准
//! v26.11.9 @ 676eaf66）。
//!
//! ## 模块（规划 `docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §5 B4.3）
//!
//! - [`plugin`] — [`plugin::MasquePlugin`]（12 条通用契约 + 3 条 masque extra）
//! - [`server`] — 服务端：Basic 认证（常数时间比较）→ 地址分配 → 全路由通告 → 包路由（隧道间 512
//!   有界队列 / 本机 [`xray_frame::ipstack::PacketStack`]）→ dispatcher 桥（TCP `DispatchHandler` /
//!   UDP `UdpDispatchSession`）
//! - [`client`] — 客户端：CONNECT-IP 隧道 → 隧道内目标拨号（TCP/UDP；域名走 隧道内 DNS，Go
//!   `wireguard.Net.LookupContextHost` 语义）
//!
//! ## udf 判定（CLAUDE.md §3.5.5）
//!
//! 协议内容（认证/分配/路由），非机制；单消费方——留主仓薄适配。
//! 栈桥（server 内 smoltcp socket ↔ dispatcher 中继）与 wireguard inbound
//! 同构（wireguard `inbound.rs` 注释已预告第三消费方）；公共提炼归
//! `xray-app-dispatcher` 需其引入 smoltcp 依赖——依赖方向与批次范围归 PM
//! 裁决，本批件头登记（`udf-promotion-candidate` 不适用：含 dispatcher 语义）。

pub mod client;
pub mod dns;
pub mod plugin;
pub mod relay;
pub mod server;

/// B4 日志门面（规划 #21：target `xray_frame::proxy::masque`；secrets 空——
/// 用户密码不进本门面，掩码走装配期进程级表 + 日志面只记 email）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("proxy::masque", vec![]));

/// MASQUE 协议名（Go `protocolName`；inbound/outbound 装配键与
/// `AccessContext.inbound_name` 同值）。
pub const MASQUE_PROTOCOL: &str = "masque";
