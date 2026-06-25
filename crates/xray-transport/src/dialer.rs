//! 拨号器抽象：客户端 IO 边界。
//!
//! 对应 Go `transport/internet/dialer.go` 的 `Dialer` interface。
//!
//! **范围说明**：本模块仅定义 trait，不提供具体实现。Go 版本的 `Dialer`
//! 全局注册表（`transportDialerCache`）和 `redirect()` 机制依赖 Phase 4+
//! 未就绪的 `outbound.Manager` / `session.Outbound` / `pipe.New` / `dns.Client`，
//! 因此本会话只交付 trait 边界，让下游 crate 可引用类型；具体传输
//! （TCP/TLS/WebSocket/gRPC 等）在各协议 crate 内实现并通过下游显式构造
//! 注入。

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;

use xray_common::net::destination::Destination;

use crate::connection::Connection;

/// 客户端拨号器 trait。对应 Go `transport/internet/dialer.go::Dialer`。
///
/// Go 原型（有 3 个方法）：
/// ```text
/// type Dialer interface {
///     Dial(ctx context.Context, dest net.Destination) (stat.Connection, error)
///     DestIpAddress() net.IP
///     SetOutboundGateway(ctx context.Context, ob *session.Outbound)
/// }
/// ```
///
/// Rust 翻译取舍：
/// - `dial` 返回 `Box<dyn Connection>`（而非 Go 的 `stat.Connection`——那是
///   `net.Conn` 接口别名，统计包装通过 `CounterConnection` 装饰，不在 trait 级强制）
/// - `set_outbound_gateway` 依赖未实现的 `session.Outbound`，此处仅声明为
///   `&self` 可选项，下游实现可暂返回 `Ok(())` 或暂不实现直到 Phase 4+
///   Outbound 就绪。必要时后续拆成子 trait。
pub trait Dialer: Send + Sync {
    /// 向 `dest` 发起连接。返回的 Connection 对象以 trait object 形式交由上层多态使用。
    fn dial<'a>(
        &'a self,
        dest: &'a Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>>;

    /// 返回该拨号器将使用的出口 IP 地址（对应 Go `DestIpAddress()`）。
    /// Go 原型返回 `net.IP`，可能为 nil。Rust 翻译为 `Option<IpAddr>` 表达 nil 语义。
    fn dest_ip_address(&self) -> Option<IpAddr>;

    /// 配置出口网关（对应 Go `SetOutboundGateway`）。
    ///
    /// 当前为接口占位，下游实现可暂不实现（返回 `Ok(())`）——`session.Outbound`
    /// 类型在 Phase 4+ 才出现。后续在此 trait 升级为参数化的版本，或拆分为
    /// `GatewayAwareDialer` 子 trait。
    fn set_outbound_gateway(&self) -> io::Result<()> {
        // ponytail: 默认实现，等 Phase 4+ session.Outbound 就绪后细化
        Ok(())
    }
}
