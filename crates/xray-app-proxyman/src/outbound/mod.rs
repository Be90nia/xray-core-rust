//! 出站代理管理
//!
//! 对应 Go `app/proxyman/outbound/`：handler 实体（[`handler`]）+ 拨号/UoT 桥接
//! （[`uot`]）+ 出站处理器契约（[`proxy_outbound`]）。
//!
//! ## 当前实现范围
//!
//! - [`OutboundHandler`] trait — Go `outbound.Handler` 完整语义
//! - [`handler::OutboundHandlerEntry`] — handler 配置载体（mux/xudp/UoT/计数器）
//! - [`parse_random_ip`] — CIDR 子网随机 IP
//!
//! 生产出站表**不在本 crate**：dispatcher 的 `SimpleOhm`（tag → `DispatchHandler`）
//! 是唯一生产注册表（代理链经 `dispatcher::OutboundHandlerManager` 查找）。
//! 本模块只提供 Go 语义的 handler 实体与契约，无本地 Manager。

pub mod handler;
pub mod proxy_outbound;
pub mod uot;

pub use handler::{OutboundHandlerEntry, UotVersion, parse_random_ip};
pub use proxy_outbound::{OutboundDialer, ProxyOutbound};

use crate::{error::ProxymanError, inbound::PinFuture};

/// 出站 handler trait（对应 Go `features/outbound.Handler`）
///
/// 与 `xray_features::outbound::OutboundHandler` 区别：本 trait 暴露
/// `sender_settings` proto 引用 + `proxy_type_url` 字符串，保持 Go 完整语义。
pub trait OutboundHandler: Send + Sync {
    /// 返回 handler tag
    fn tag(&self) -> &str;

    /// 启动 handler
    fn start(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// 关闭 handler
    fn close(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// SenderSettings 配置（对应 Go `SenderSettings() *serial.TypedMessage`，
    /// Rust 端返回 type_url 字符串标识 SenderConfig 是否存在）
    fn sender_type_url(&self) -> Option<&str>;

    /// ProxySettings 类型 URL
    fn proxy_type_url(&self) -> &str;

    /// 分发出站流量（对应 Go `Handler.Dispatch(ctx, link)`）。
    ///
    /// 将 `link` 中的出站数据通过此 handler 的代理处理器发送。
    /// 如果未配置代理处理器，返回 [`ProxymanError::Other`]。
    fn dispatch(
        &self,
        session: xray_common::session::Session,
        link: xray_transport::link::Link,
    ) -> PinFuture<Result<(), ProxymanError>>;

    /// 向目标地址拨号（对应 Go `Handler.Dial(ctx, dest)`）。
    ///
    /// 如果配置了代理链 tag，通过 chained handler 拨号；否则直接拨号。
    fn dial(
        &self,
        dest: &xray_common::net::destination::Destination,
    ) -> PinFuture<std::io::Result<Box<dyn xray_transport::connection::Connection>>>;
}
