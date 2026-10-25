#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 宏断言便利，bd g3cr 家规扩展）；spawn 走 xray_common::testing
// （L3 闸不豁免），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! 代理管理器应用服务
//!
//! 对应 Go `app/proxyman/`。管理入站/出站 handler 生命周期、用户操作 RPC、流量计数。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`config::SniffingRequest`] 与 [`config::build_sniffing_request`] — 嗅探配置解析
//! - [`inbound::AlwaysOnInboundHandler`] / [`outbound::OutboundHandlerEntry`] — handler 配置载体
//! - [`outbound::parse_random_ip`] — CIDR 子网随机 IP
//! - 流量计数器命名规则（[`stats::counter_name`]）
//! - gRPC 命令编排（[`command::InboundOperation`] / [`command::OutboundOperation`] /
//!   [`command::HandlerService`]）
//!
//! IO 边界（trait + NotImplemented 占位）：
//! - worker 创建（TCP/UDP/Unix listener）— 依赖 `xray_transport::Listener` + xray-mux
//! - `outbound::OutboundHandlerEntry` 的 `dispatch`/`dial` — 依赖 `transport.Link` + 代理 + mux +
//!   xudp + DNS
//! - UoT ([`outbound::OutboundHandlerEntry::get_uo_t_connection`]) — UDP over TCP 桥接
//! - gRPC server 注册 — 依赖 tonic + xray-app-commander
//! - TypedMessage 操作解码 — 由上层注入 [`command::OperationDecoder`] 实现

// async-trait 展开对 trait 脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

pub mod command;
pub mod config;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod stats;

pub use config::{SniffingRequest, build_sniffing_request};
pub use error::ProxymanError;
pub use inbound::{
    AlwaysOnInboundHandler, InboundHandler, PinFuture,
    worker::{DsWorker, InboundConn, ProxyInbound, TcpWorker, UdpSession, UdpWorker, Worker},
};
pub use outbound::{
    OutboundDialer, OutboundHandler, OutboundHandlerEntry, ProxyOutbound, UotVersion,
    parse_random_ip,
    uot::{UotClientConn, UotServerConn},
};
pub use stats::{Counter, HandlerKind, NoopStatsProvider, StatsProvider, TrafficDirection};
