//! Portal outbound handler 集成（IO 边界 trait stub）。
//!
//! 对应 Go `portal.go` 的 `Outbound` struct（实现 `outbound.Handler`）+
//! `Portal.Start()` 调用 `ohm.AddHandler` / `Portal.Close()` 调用 `ohm.RemoveHandler`。
//!
//! ## Rust 化策略
//!
//! - **不引入 transport::Link**：dispatch 依赖 transport 全链路 + mux，当前阶段留
//!   trait 定义 + stub struct（与 `xray-app-commander/src/outbound.rs` 同模式）
//! - **OutboundRegistrar trait**：对应 Go `outbound.Manager.AddHandler/RemoveHandler`，
//!   上层 proxyman 注入实现
//! - **ReverseOutboundHandler trait**：对应 Go `Outbound` struct，tag/closed/start/close
//!   可独立测试；dispatch 方法留待 transport 就绪后补充

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::ReverseError;

/// Outbound handler 注册 trait。
///
/// 对应 Go `outbound.Manager.AddHandler / RemoveHandler`。
/// Portal 在 `start()` 时注册、`close()` 时注销。
pub trait OutboundRegistrar: Send + Sync {
    /// 注册 handler。
    fn add_handler(&self, handler: Arc<dyn ReverseOutboundHandler>) -> Result<(), ReverseError>;

    /// 按 tag 注销 handler。
    fn remove_handler(&self, tag: &str) -> Result<(), ReverseError>;
}

/// Reverse outbound handler 接口。
///
/// 对应 Go `portal.go` 的 `Outbound` struct（实现 `outbound.Handler`）。
/// `dispatch` 依赖 `transport::Link` + mux，当前阶段留 trait 定义，
/// 上层注入实现。
pub trait ReverseOutboundHandler: Send + Sync {
    /// handler 标识（与 Portal.tag 对应）。
    fn tag(&self) -> &str;

    /// 是否已关闭。
    fn closed(&self) -> bool;

    /// 启动 handler。
    fn start(&self) -> Result<(), ReverseError>;

    /// 关闭 handler。
    fn close(&self) -> Result<(), ReverseError>;
}

/// 默认 handler 占位（无实际 dispatch，仅记录状态）。
///
/// 用于测试编排流程。实际场景由上层注入实现。
pub struct StubOutboundHandler {
    tag: String,
    closed: AtomicBool,
}

impl StubOutboundHandler {
    #[must_use]
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            closed: AtomicBool::new(true),
        }
    }
}

impl ReverseOutboundHandler for StubOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), ReverseError> {
        self.closed.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn close(&self) -> Result<(), ReverseError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl std::fmt::Debug for StubOutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubOutboundHandler")
            .field("tag", &self.tag)
            .field("closed", &self.closed())
            .finish()
    }
}

/// 测试用 stub registrar。
pub struct StubOutboundRegistrar {
    handlers: parking_lot::Mutex<Vec<Arc<dyn ReverseOutboundHandler>>>,
}

impl StubOutboundRegistrar {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn count(&self) -> usize {
        self.handlers.lock().len()
    }
}

impl Default for StubOutboundRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundRegistrar for StubOutboundRegistrar {
    fn add_handler(&self, handler: Arc<dyn ReverseOutboundHandler>) -> Result<(), ReverseError> {
        self.handlers.lock().push(handler);
        Ok(())
    }

    fn remove_handler(&self, tag: &str) -> Result<(), ReverseError> {
        let mut handlers = self.handlers.lock();
        let before = handlers.len();
        handlers.retain(|h| h.tag() != tag);
        if handlers.len() == before {
            return Err(ReverseError::OutboundMetadataMissing);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_handler_tag() {
        let h = StubOutboundHandler::new("portal_out");
        assert_eq!(h.tag(), "portal_out");
    }

    #[test]
    fn stub_handler_initial_closed() {
        let h = StubOutboundHandler::new("portal_out");
        assert!(h.closed(), "stub 初始为 closed 状态");
    }

    #[test]
    fn stub_handler_start_open() {
        let h = StubOutboundHandler::new("portal_out");
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn stub_handler_close_close() {
        let h = StubOutboundHandler::new("portal_out");
        h.start().unwrap();
        h.close().unwrap();
        assert!(h.closed());
    }

    #[test]
    fn stub_handler_start_close_start() {
        let h = StubOutboundHandler::new("portal_out");
        h.start().unwrap();
        h.close().unwrap();
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn stub_handler_debug_format() {
        let h = StubOutboundHandler::new("portal_out");
        let s = format!("{h:?}");
        assert!(s.contains("StubOutboundHandler"));
        assert!(s.contains("portal_out"));
    }

    #[test]
    fn reverse_outbound_handler_trait_object_safe() {
        let h: Arc<dyn ReverseOutboundHandler> = Arc::new(StubOutboundHandler::new("portal_out"));
        assert_eq!(h.tag(), "portal_out");
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn stub_registrar_add_remove() {
        let reg = StubOutboundRegistrar::new();
        let h: Arc<dyn ReverseOutboundHandler> = Arc::new(StubOutboundHandler::new("portal_out"));
        reg.add_handler(h).unwrap();
        assert_eq!(reg.count(), 1);
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
        reg.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        reg.add_handler(Arc::new(StubOutboundHandler::new("b"))).unwrap();
        assert_eq!(reg.count(), 2);
        reg.remove_handler("a").unwrap();
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn stub_registrar_default_is_empty() {
        let reg = StubOutboundRegistrar::default();
        assert_eq!(reg.count(), 0);
    }
}
