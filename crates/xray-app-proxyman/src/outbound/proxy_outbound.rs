//! 出站代理处理 trait 与拨号器 trait。
//!
//! 对应 Go `proxy.Outbound` 和 `internet.Dialer` 接口。
//!
//! - [`ProxyOutbound`] — 代理出站处理（Go `proxy.Outbound.Process`）
//! - [`OutboundDialer`] — 拨号器接口（Go `internet.Dialer`），由 mux 和代理链使用

use std::{io, sync::Arc};

use async_trait::async_trait;
use xray_common::{net::destination::Destination, session::Session};
use xray_transport::{connection::Connection, link::Link};

use crate::error::ProxymanError;

/// 出站代理处理 trait（对应 Go `proxy.Outbound`）。
///
/// Go 原型：
/// ```text
/// type Outbound interface {
///     Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error
/// }
/// ```
#[async_trait]
pub trait ProxyOutbound: Send + Sync {
    /// 通过此代理处理出站连接。
    ///
    /// 对应 Go `proxy.Outbound.Process(ctx, link, dialer)`。
    ///
    /// # Errors
    /// - 代理处理失败时返回 [`ProxymanError`]
    async fn process(
        &self,
        session: &Session,
        link: Link,
        dialer: Arc<dyn OutboundDialer>,
    ) -> Result<(), ProxymanError>;
}

/// 拨号器接口（对应 Go `internet.Dialer`）。
///
/// 由 mux client manager 和代理链使用，用于建立出站连接。
#[async_trait]
pub trait OutboundDialer: Send + Sync {
    /// 向目标地址发起连接。
    ///
    /// # Errors
    /// - 连接失败时返回 `io::Error`
    async fn dial(&self, dest: &Destination) -> io::Result<Box<dyn Connection>>;
}
