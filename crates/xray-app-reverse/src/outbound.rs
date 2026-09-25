//! Portal outbound handler 集成。
//!
//! 对应 Go `portal.go` 的 `Outbound` struct（实现 `outbound.Handler.Dispatch`）+
//! `Portal.Start()` 调用 `ohm.AddHandler` / `Portal.Close()` 调用 `ohm.RemoveHandler`。
//!
//! - [`OutboundRegistrar`]：对应 Go `outbound.Manager.AddHandler/RemoveHandler`， 生产实现
//!   [`SimpleOhmRegistrar`]（包 xray-app-dispatcher 的 `SimpleOhm`）
//! - [`PortalOutbound`]：注册进 outbound manager 的 portal 出站 handler， `dispatch` = Go
//!   `Outbound.Dispatch` → `Portal.HandleConnection`

use std::sync::Arc;

use xray_app_dispatcher::{DispatchHandler, default::SimpleOhm};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_mux::{
    client::{ClientWorker, Link as MuxLink},
    session::ClientStrategy,
};
use xray_transport::link::Link as TransportLink;

use crate::{
    bridge::is_domain, error::ReverseError, picker::StaticMuxPicker, worker::PortalWorker,
};

/// Outbound handler 注册 trait。
///
/// 对应 Go `outbound.Manager.AddHandler / RemoveHandler`。
/// Portal 在 `start()` 时注册、`close()` 时注销。
pub trait OutboundRegistrar: Send + Sync {
    /// 注册 handler（tag 对应 Portal.tag）。
    fn add_handler(&self, tag: &str, handler: Arc<dyn DispatchHandler>)
    -> Result<(), ReverseError>;

    /// 按 tag 注销 handler。
    fn remove_handler(&self, tag: &str) -> Result<(), ReverseError>;
}

/// 生产注册器：`SimpleOhm`（xray-app-dispatcher）→ [`OutboundRegistrar`]。
pub struct SimpleOhmRegistrar(pub Arc<SimpleOhm>);

impl OutboundRegistrar for SimpleOhmRegistrar {
    fn add_handler(
        &self,
        tag: &str,
        handler: Arc<dyn DispatchHandler>,
    ) -> Result<(), ReverseError> {
        self.0.add(tag, handler);
        Ok(())
    }

    fn remove_handler(&self, tag: &str) -> Result<(), ReverseError> {
        if self.0.remove(tag) { Ok(()) } else { Err(ReverseError::OutboundMetadataMissing) }
    }
}

/// 测试用注册器：记录 `(tag, handler)` 列表。
pub struct StubOutboundRegistrar {
    handlers: parking_lot::Mutex<Vec<(String, Arc<dyn DispatchHandler>)>>,
}

impl StubOutboundRegistrar {
    #[must_use]
    pub fn new() -> Self {
        Self { handlers: parking_lot::Mutex::new(Vec::new()) }
    }

    pub fn count(&self) -> usize {
        self.handlers.lock().len()
    }

    pub fn tags(&self) -> Vec<String> {
        self.handlers.lock().iter().map(|(t, _)| t.clone()).collect()
    }
}

impl Default for StubOutboundRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundRegistrar for StubOutboundRegistrar {
    fn add_handler(
        &self,
        tag: &str,
        handler: Arc<dyn DispatchHandler>,
    ) -> Result<(), ReverseError> {
        self.handlers.lock().push((tag.to_string(), handler));
        Ok(())
    }

    fn remove_handler(&self, tag: &str) -> Result<(), ReverseError> {
        let mut handlers = self.handlers.lock();
        let before = handlers.len();
        handlers.retain(|(t, _)| t != tag);
        if handlers.len() == before {
            return Err(ReverseError::OutboundMetadataMissing);
        }
        Ok(())
    }
}

/// Portal outbound handler（对应 Go `portal.go` 的 `Outbound`，104-119 行）。
///
/// 持 picker + portal domain；`dispatch` 即 Go `Portal.HandleConnection`
/// （portal.go:67-101）：
/// - 目标域 == portal domain：本连接是 bridge 建来的反向 carrier—— `mux.NewClientWorker(link)` +
///   `NewPortalWorker` + `picker.AddWorker`
/// - 其余：picker 选 worker，dispatch 子会话到 carrier
pub struct PortalOutbound {
    tag: String,
    picker: Arc<StaticMuxPicker<Arc<PortalWorker>>>,
    domain: String,
}

impl PortalOutbound {
    #[must_use]
    pub fn new(
        tag: String,
        picker: Arc<StaticMuxPicker<Arc<PortalWorker>>>,
        domain: String,
    ) -> Self {
        Self { tag, picker, domain }
    }

    /// 对应 Go `Portal.HandleConnection`（portal.go:67-101）。
    ///
    /// `access`：入站 ctx（txno④，Go client.go:268-271 `IsReverseMuxFromContext`
    /// 时 `NewWriter(..., inbound)` 携带 inbound 的等价通道）——常规连接经
    /// carrier 下发 New 帧时把 `from`/`local` 作为 source/local 写出（二者均可
    /// 解析才携带，空值/缺省行为与改造前一致）。
    pub async fn handle_connection(
        &self,
        dest: &Destination,
        link: TransportLink,
        access: &xray_app_dispatcher::AccessContext,
    ) -> Result<(), ReverseError> {
        if is_domain(dest.address().as_domain(), &self.domain) {
            // 反向 carrier：在链路上起 mux client + portal worker
            let client = ClientWorker::new(
                MuxLink { reader: link.reader, writer: link.writer },
                ClientStrategy::default(),
            );
            let worker = PortalWorker::new(client.clone()).inspect_err(|e| {
                // Go Outbound.Dispatch 出错时 Interrupt(link)；此处 link 已并入
                // ClientWorker，close 等价拆除
                client.close();
            })?;
            self.picker.add_worker(worker);
            // Go portal.go:87-92：reader 为 pipe 时立即返回（carrier 会话由
            // ClientWorker 内部驱动，本函数无需等待）
            return Ok(());
        }

        // 常规连接：picker 选 worker 后 dispatch。
        // Go portal.go:96-99 的 UDP EndpointOverride（OriginalTarget ctx）无 Rust
        // 对应物（dispatch 签名无 OriginalTarget），不翻译。
        // Go ClientManager.Dispatch 仅对非 pipe reader 等待会话结束；Rust
        // ClientWorker::dispatch 统一等待 → spawn 等价。
        let worker = self.picker.pick_available()?;
        let d = dest.clone();
        let inbound = reverse_mux_inbound(access);
        tokio::spawn(async move {
            worker
                .client()
                .dispatch_with_source(
                    &d,
                    MuxLink { reader: link.reader, writer: link.writer },
                    None,
                    inbound,
                )
                .await;
        });
        Ok(())
    }
}

/// 入站 ctx → Reverse-mux (source, local)（txno④）。
///
/// `from`/`local` 均可解析为 `ip:port` 才返回 `Some`；任一缺失（空串、
/// 域名形态、解析失败）返回 `None`——New 帧退回无元数据形态（与改造前
/// 线格式兼容）。网络恒 TCP（portal 写侧承载的是入站 TCP 会话元数据；
/// Go inbound.Source 由 TCP conn RemoteAddr 构造，frame.go:88 同判）。
fn reverse_mux_inbound(
    access: &xray_app_dispatcher::AccessContext,
) -> Option<(Destination, Destination)> {
    let source = parse_ip_destination(access.from.as_str())?;
    let local = parse_ip_destination(access.local.as_str())?;
    Some((source, local))
}

/// `"ip:port"` → TCP [`Destination`]（Go net.TCPDestination(addr, port)）。
///
/// 域名形态/空串/解析失败 → `None`（New 帧退回无元数据形态）。
fn parse_ip_destination(s: &str) -> Option<Destination> {
    let addr: std::net::SocketAddr = s.parse().ok()?;
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::IPv4(v4),
        std::net::IpAddr::V6(v6) => Address::IPv6(v6),
    };
    Some(Destination::new(address, Port::new(addr.port()), Network::TCP))
}

impl DispatchHandler for PortalOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 对应 Go `Outbound.Dispatch`（portal.go:113-119）：HandleConnection；
    /// 出错 log + 拆链（Go Interrupt，此处已并入 handle_connection 错误路径）。
    fn dispatch(
        &self,
        dest: &Destination,
        link: TransportLink,
    ) -> xray_app_dispatcher::default::PinFuture<()> {
        let tag = self.tag.clone();
        let picker = Arc::clone(&self.picker);
        let domain = self.domain.clone();
        let dest = dest.clone();
        Box::pin(async move {
            let outbound = PortalOutbound { tag, picker, domain };
            if let Err(e) = outbound
                .handle_connection(&dest, link, &xray_app_dispatcher::AccessContext::default())
                .await
            {
                tracing::info!(
                    target: "xray_app_reverse",
                    error = %e,
                    "failed to process reverse connection"
                );
            }
        })
    }
}

impl std::fmt::Debug for PortalOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalOutbound")
            .field("tag", &self.tag)
            .field("domain", &self.domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_registrar_add_remove() {
        let reg = StubOutboundRegistrar::new();
        let h = Arc::new(PortalOutbound::new(
            "portal_out".into(),
            Arc::new(StaticMuxPicker::new()),
            "t.example.com".into(),
        )) as Arc<dyn DispatchHandler>;
        reg.add_handler("portal_out", h).unwrap();
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.tags(), vec!["portal_out".to_string()]);
        reg.remove_handler("portal_out").unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn stub_registrar_remove_missing_errors() {
        let reg = StubOutboundRegistrar::new();
        let err = reg.remove_handler("nope").unwrap_err();
        assert!(matches!(err, ReverseError::OutboundMetadataMissing));
    }

    #[test]
    fn stub_registrar_add_multiple() {
        let reg = StubOutboundRegistrar::new();
        let mk = |t: &str| {
            Arc::new(PortalOutbound::new(t.into(), Arc::new(StaticMuxPicker::new()), "d".into()))
                as Arc<dyn DispatchHandler>
        };
        reg.add_handler("a", mk("a")).unwrap();
        reg.add_handler("b", mk("b")).unwrap();
        assert_eq!(reg.count(), 2);
        reg.remove_handler("a").unwrap();
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn stub_registrar_default_is_empty() {
        let reg = StubOutboundRegistrar::default();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn portal_outbound_debug_format() {
        let h = PortalOutbound::new(
            "portal_out".into(),
            Arc::new(StaticMuxPicker::new()),
            "d.example.com".into(),
        );
        let s = format!("{h:?}");
        assert!(s.contains("PortalOutbound"));
        assert!(s.contains("portal_out"));
    }
}
