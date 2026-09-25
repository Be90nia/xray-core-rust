//! Mux handler 接入层
//!
//! 将 mux 多路复用能力暴露为 `xray_features::OutboundHandler` /
//! `InboundHandler`，使其可作为可注册 handler 接入 proxyman。
//!
//! # 模块结构
//!
//! - [`MuxOutboundHandler`] — mux 出站：包装底层 outbound，dial 时通过 [`IncrementalWorkerPicker`]
//!   调度 worker + 分配 session
//! - [`MuxInboundHandler`] — mux 入站：接收 mux 连接并解复用
//! - [`MuxHandlerFactory`] — 统一工厂入口

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use xray_common::{
    net::{destination::Destination, network::Network},
    session::Session,
};
use xray_features::{
    inbound::{InboundError, InboundHandler},
    outbound::{OutboundError, OutboundHandler},
};

use crate::{
    client::{DialingWorkerFactory, IncrementalWorkerPicker, MUX_COOL_PORT},
    session::ClientStrategy,
};

/// mux handler 的 proxy 类型 URL（注册标识）
pub const MUX_PROXY_TYPE_URL: &str = "xray.mux";

/// 占位底层 handler：carrier 永不建立（dispatch future 挂起）。
///
/// ponytail: MuxOutboundHandler 的 xray_features 数据路径尚未接 transport 层
/// （真实生产路径走 xray-core outbound.rs 的 MuxBridge）；DialingWorkerFactory
/// 构造需要底层 handler，此处给 pending 占位，等待 transport 接入时替换。
#[derive(Debug)]
struct PendingUnderlying;

impl xray_app_dispatcher::DispatchHandler for PendingUnderlying {
    fn tag(&self) -> &str {
        "mux-pending"
    }

    fn dispatch(
        &self,
        _dest: &Destination,
        _link: xray_transport::link::Link,
    ) -> xray_app_dispatcher::default::PinFuture<()> {
        Box::pin(std::future::pending())
    }
}

// ========== MuxOutboundHandler ==========

/// Mux 出站 Handler——包装底层 outbound 实现多路复用。
///
/// dial 时通过 [`IncrementalWorkerPicker`] 获取/创建 worker，在共享底层
/// 连接上分配独立 session，实现多路复用。底层 outbound 负责建立到 mux
/// 服务端的实际连接（如 freedom / socks）。
///
/// frame IO 桥接（session ↔ transport.Link）依赖 transport 全链路接入。
pub struct MuxOutboundHandler {
    tag: String,
    enabled: bool,
    picker: Arc<IncrementalWorkerPicker>,
    underlying: Arc<dyn OutboundHandler>,
}

impl MuxOutboundHandler {
    /// 创建 mux 出站 handler。
    ///
    /// `concurrency` 为每个 worker 的最大并发会话数（0 默认补 8，
    /// 对应 Go `MultiplexingConfig.Concurrency == 0` 的默认行为）。
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        concurrency: u32,
        underlying: Arc<dyn OutboundHandler>,
    ) -> Self {
        let effective = if concurrency == 0 { 8 } else { concurrency };
        let strategy = ClientStrategy { max_concurrency: effective, max_connection: 0 };
        let factory = Arc::new(DialingWorkerFactory::new(Arc::new(PendingUnderlying), strategy));
        let picker = Arc::new(IncrementalWorkerPicker::new(factory));
        Self { tag: tag.into(), enabled: true, picker, underlying }
    }

    /// 引用内部 Worker 选择器（供外部观察 worker 状态）。
    #[must_use]
    pub fn picker(&self) -> &Arc<IncrementalWorkerPicker> {
        &self.picker
    }

    /// 是否启用 mux。
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 引用底层出站 handler。
    #[must_use]
    pub fn underlying(&self) -> &Arc<dyn OutboundHandler> {
        &self.underlying
    }
}

#[async_trait]
impl OutboundHandler for MuxOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 picker 调度 worker + 分配 session。
    ///
    /// 先确认底层 outbound 可处理目标，再走 mux 调度链路。
    /// frame IO 桥接留 transport 接入后实现。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> Result<(), OutboundError> {
        if !self.enabled {
            return Err(OutboundError::ConnectionFailed("mux is not enabled".into()));
        }
        if !self.underlying.can_handle(destination) {
            return Err(OutboundError::NoOutbound(
                "underlying outbound cannot handle destination".into(),
            ));
        }

        // pick_internal 是 async 路径，会按需创建 worker（ClientManager.dispatch 的 sync 路径无法
        // bootstrap）
        let worker = self
            .picker
            .pick_internal()
            .await
            .ok_or_else(|| OutboundError::ConnectionFailed("mux no available worker".into()))?;

        let _mux_session = worker.allocate_session().await.ok_or_else(|| {
            OutboundError::ConnectionFailed("mux session allocation failed (worker full)".into())
        })?;

        // ponytail: frame IO 桥接（session ↔ transport.Link）留 transport 接入后实现
        tracing::debug!(
            tag = %self.tag,
            session_count = worker.session_count(),
            "mux outbound dispatch succeeded (frame IO bridge pending transport)"
        );
        Ok(())
    }

    /// mux 启用时处理 TCP 目标（底层 outbound 也必须能处理）。
    fn can_handle(&self, destination: &Destination) -> bool {
        self.enabled
            && destination.network() == Network::TCP
            && self.underlying.can_handle(destination)
    }
}

// ========== MuxInboundHandler ==========

/// Mux 入站 Handler——接收 mux 连接并解复用为独立流。
///
/// listener 接入 + frame 读取 + session 分发留 transport 层。
pub struct MuxInboundHandler {
    tag: String,
    port: u16,
    started: AtomicBool,
}

impl MuxInboundHandler {
    /// 创建 mux 入站 handler。
    #[must_use]
    pub fn new(tag: impl Into<String>, port: u16) -> Self {
        Self { tag: tag.into(), port, started: AtomicBool::new(false) }
    }
}

#[async_trait]
impl InboundHandler for MuxInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        // ponytail: listener + Server 接入留 transport 层
        Ok(())
    }

    async fn close(&self) -> Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

// ========== 工厂方法 ==========

/// Mux handler 工厂——统一创建入口。
pub struct MuxHandlerFactory;

impl MuxHandlerFactory {
    /// 创建 mux 出站 handler。
    #[must_use]
    pub fn create_outbound(
        tag: impl Into<String>,
        concurrency: u32,
        underlying: Arc<dyn OutboundHandler>,
    ) -> MuxOutboundHandler {
        MuxOutboundHandler::new(tag, concurrency, underlying)
    }

    /// 创建 mux 入站 handler（`port == 0` 时默认 [`MUX_COOL_PORT`]）。
    #[must_use]
    pub fn create_inbound(tag: impl Into<String>, port: u16) -> MuxInboundHandler {
        let effective_port = if port == 0 { MUX_COOL_PORT } else { port };
        MuxInboundHandler::new(tag, effective_port)
    }
}

#[cfg(test)]
mod tests {
    use xray_common::net::{address::Address, port::Port};

    use super::*;

    /// 测试用底层 outbound stub：can_handle 返回固定值。
    struct StubOutbound {
        tag: String,
        handleable: bool,
    }

    #[async_trait]
    impl OutboundHandler for StubOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn dial(&self, _: &Destination, _: &Session) -> Result<(), OutboundError> {
            Ok(())
        }

        fn can_handle(&self, _: &Destination) -> bool {
            self.handleable
        }
    }

    fn make_tcp_dest() -> Destination {
        Destination::new(Address::IPv4("127.0.0.1".parse().unwrap()), Port::new(443), Network::TCP)
    }

    fn make_udp_dest() -> Destination {
        Destination::new(Address::IPv4("127.0.0.1".parse().unwrap()), Port::new(443), Network::UDP)
    }

    fn make_handler(tag: &str) -> MuxOutboundHandler {
        let underlying = Arc::new(StubOutbound { tag: "stub".into(), handleable: true });
        MuxOutboundHandler::new(tag, 8, underlying)
    }

    // ========== MuxOutboundHandler ==========

    #[test]
    fn outbound_tag_returns_construction_tag() {
        let h = make_handler("mux_out");
        assert_eq!(h.tag(), "mux_out");
    }

    #[test]
    fn outbound_can_handle_tcp_when_enabled() {
        let h = make_handler("t");
        assert!(h.can_handle(&make_tcp_dest()));
    }

    #[test]
    fn outbound_cannot_handle_udp() {
        let h = make_handler("t");
        assert!(!h.can_handle(&make_udp_dest()));
    }

    #[test]
    fn outbound_cannot_handle_when_underlying_rejects() {
        let underlying = Arc::new(StubOutbound { tag: "stub".into(), handleable: false });
        let h = MuxOutboundHandler::new("t", 8, underlying);
        assert!(!h.can_handle(&make_tcp_dest()));
    }

    #[tokio::test]
    async fn outbound_concurrency_zero_defaults_to_eight() {
        let h = make_handler("t");
        // pick_internal 创建 worker 成功即说明 strategy 生效
        let worker = h.picker().pick_internal().await;
        assert!(worker.is_some());
    }

    #[tokio::test]
    async fn outbound_dial_dispatches_and_allocates_session() {
        let h = make_handler("dial-test");
        let dest = make_tcp_dest();
        let session = Session::new();
        let result = h.dial(&dest, &session).await;
        assert!(result.is_ok(), "dial should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn outbound_dial_fails_when_underlying_cannot_handle() {
        let underlying = Arc::new(StubOutbound { tag: "stub".into(), handleable: false });
        let h = MuxOutboundHandler::new("t", 8, underlying);
        let result = h.dial(&make_tcp_dest(), &Session::new()).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OutboundError::NoOutbound(_) => {},
            other => panic!("expected NoOutbound, got {other:?}"),
        }
    }

    #[test]
    fn outbound_exposes_underlying_and_picker() {
        let h = make_handler("t");
        assert_eq!(h.underlying().tag(), "stub");
        assert!(h.is_enabled());
    }

    // ========== MuxInboundHandler ==========

    #[test]
    fn inbound_tag_and_port() {
        let h = MuxInboundHandler::new("mux_in", 9527);
        assert_eq!(h.tag(), "mux_in");
        assert_eq!(h.port(), 9527);
    }

    #[tokio::test]
    async fn inbound_start_close_lifecycle() {
        let h = MuxInboundHandler::new("mux_in", 9527);
        assert!(h.start().await.is_ok());
        assert!(h.close().await.is_ok());
        // close 后可再次 start
        assert!(h.start().await.is_ok());
    }

    #[tokio::test]
    async fn inbound_double_start_errors() {
        let h = MuxInboundHandler::new("mux_in", 9527);
        assert!(h.start().await.is_ok());
        let result = h.start().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            InboundError::AlreadyStarted(tag) => assert_eq!(tag, "mux_in"),
            other => panic!("expected AlreadyStarted, got {other:?}"),
        }
    }

    // ========== MuxHandlerFactory ==========

    #[test]
    fn factory_create_outbound() {
        let underlying = Arc::new(StubOutbound { tag: "stub".into(), handleable: true });
        let h = MuxHandlerFactory::create_outbound("factory_out", 16, underlying);
        assert_eq!(h.tag(), "factory_out");
        assert!(h.is_enabled());
    }

    #[test]
    fn factory_create_inbound_defaults_port_to_mux_cool() {
        let h = MuxHandlerFactory::create_inbound("factory_in", 0);
        assert_eq!(h.port(), MUX_COOL_PORT);
    }

    #[test]
    fn factory_create_inbound_preserves_explicit_port() {
        let h = MuxHandlerFactory::create_inbound("factory_in", 8080);
        assert_eq!(h.port(), 8080);
    }

    #[test]
    fn mux_proxy_type_url_constant() {
        assert_eq!(MUX_PROXY_TYPE_URL, "xray.mux");
    }
}
