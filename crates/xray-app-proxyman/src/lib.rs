//! 代理管理器应用服务
//!
//! 对应 Go `app/proxyman/`。管理入站/出站 handler 生命周期、用户操作 RPC、流量计数。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`config::SniffingRequest`] 与 [`config::build_sniffing_request`] — 嗅探配置解析
//! - [`inbound::InboundManager`] / [`outbound::OutboundManager`] — handler 注册表（HashMap + RwLock）
//! - [`inbound::AlwaysOnInboundHandler`] / [`outbound::OutboundHandlerEntry`] — handler 配置载体
//! - [`outbound::parse_random_ip`] — CIDR 子网随机 IP
//! - 流量计数器命名规则（[`stats::counter_name`]）
//! - gRPC 命令编排（[`command::InboundOperation`] / [`command::OutboundOperation`] /
//!   [`command::HandlerService`]）
//!
//! IO 边界（trait + NotImplemented 占位）：
//! - worker 创建（TCP/UDP/Unix listener）— 依赖 `xray_transport::Listener` + xray-mux
//! - `outbound::OutboundHandlerEntry` 的 `dispatch`/`dial` — 依赖 `transport.Link` + 代理 + mux + xudp + DNS
//! - UoT ([`outbound::OutboundHandlerEntry::get_uo_t_connection`]) — UDP over TCP 桥接
//! - gRPC server 注册 — 依赖 tonic + xray-app-commander
//! - TypedMessage 操作解码 — 由上层注入 [`command::OperationDecoder`] 实现

pub mod command;
pub mod config;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod stats;

pub use config::{SniffingRequest, build_sniffing_request};
pub use error::ProxymanError;
pub use inbound::{AlwaysOnInboundHandler, InboundHandler, InboundManager, PinFuture};
pub use inbound::worker::{ProxyInbound, InboundConn, Worker, TcpWorker, UdpWorker, DsWorker, UdpSession};
pub use outbound::{OutboundHandler, OutboundManager, OutboundHandlerEntry, OutboundDialer, ProxyOutbound, UotVersion, parse_random_ip};
pub use stats::{Counter, HandlerKind, NoopStatsProvider, StatsProvider, TrafficDirection};
