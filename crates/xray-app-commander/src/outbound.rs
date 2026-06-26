//! Commander outbound 集成（IO 边界 trait stub）。
//!
//! 对应 Go `app/commander/outbound.go`：
//! - `OutboundListener`：net.Listener 实现，buffer chan 接受 Outbound 投递的连接
//! - `Outbound`：outbound.Handler 实现，dispatch Link → 创建 cnc.Connection → 投到 listener
//!
//! ## Rust 化策略
//!
//! - **不引入 transport::Link / cnc.Connection**：依赖 transport 全链路 +
//!   xray_buf 多缓冲 IO，当前阶段留 trait 定义 + stub struct
//! - **OutboundListener trait 含 sync API**：`accept` 返回 `Option<Conn>`（同步），
//!   因为 Go 的 net.Listener.Accept 也是阻塞 sync；Rust 端实际异步化由 trait
//!   实现决定（可包 `tokio::sync::mpsc::Receiver` + block_on）
//! - **Conn 类型留 type parameter stub**：避免引入 transport::Link，用 `Box<dyn AsyncRead + AsyncWrite + Send + Unpin>` 作为最简抽象；trait 不依赖具体 crate

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::CommanderError;

/// Commander 连接 IO 抽象（同时实现 tokio AsyncRead + AsyncWrite）。
///
/// 因 Rust trait object 不允许 `dyn AsyncRead + AsyncWrite`（两个 non-auto trait），
/// 用 supertrait + blanket impl 模式包装。
pub trait CommanderIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> CommanderIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Listener 接受的连接类型（IO 抽象，避免引入具体 transport 类型）。
///
/// 实际实现应满足 tokio AsyncRead + AsyncWrite + Unpin + Send。
pub type CommanderConn = Box<dyn CommanderIo>;

/// Outbound listener 接口。对应 Go `OutboundListener struct`（实现 net.Listener）。
///
/// 接受来自 [`OutboundHandler::dispatch`] 投递的连接。Commander 的 gRPC server
/// 在 outbound 模式下从此 listener accept 连接而非 TCP 监听。
///
/// **当前为 trait stub**：实际实现需要 transport::Link 全链路支持。
pub trait OutboundListener: Send + Sync {
    /// 接受下一条连接。返回 `None` 表示 listener 已关闭。
    ///
    /// 对应 Go `(*OutboundListener).Accept() (net.Conn, error)`。
    /// Rust 化：异步化（Go 是 sync 阻塞 + select done）。
    fn accept(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<CommanderConn>> + Send + '_>>;

    /// 关闭 listener，丢弃所有缓冲的连接。
    /// 对应 Go `(*OutboundListener).Close() error`。
    fn close(&self) -> Result<(), CommanderError>;

    /// 是否已关闭。
    fn closed(&self) -> bool;
}

/// Outbound handler 接口。对应 Go `Outbound struct`（实现 outbound.Handler）。
///
/// dispatch 接受 Link（reader + writer），包装为 cnc.Connection 后投递到
/// [`OutboundListener`]。
///
/// **当前为 trait stub**：实际实现依赖 `xray_transport::link::Link` + cnc 等价物。
pub trait OutboundHandler: Send + Sync {
    /// handler 标识（与 Commander.tag 对应）。
    /// 对应 Go `Outbound.Tag() string`。
    fn tag(&self) -> &str;

    /// 是否已关闭。对应 Go `Outbound.closed` 字段。
    fn closed(&self) -> bool;

    /// 启动 handler。对应 Go `Outbound.Start() error`。
    fn start(&self) -> Result<(), CommanderError>;

    /// 关闭 handler。对应 Go `Outbound.Close() error`。
    fn close(&self) -> Result<(), CommanderError>;

    // 注：Go 的 Dispatch(ctx, *transport.Link) 接口方法依赖 transport::Link，
    // 当前阶段（P4-6）transport 全链路未就绪，留待后续接入。
    // 上层 xray-core main 应实现此 trait 并提供 dispatch 实现。
}

/// Outbound handler 注册 trait。对应 Go `outbound.Manager.AddHandler`。
///
/// Commander 在 outbound 模式下需要把 [`OutboundHandler`] 注册到 outbound
/// manager，由 dispatcher 路由 API 流量到 commander。当前阶段 outbound
/// manager 由 P4-4 proxyman 实现，但跨 crate 调用依赖待定。
pub trait OutboundRegistrar: Send + Sync {
    /// 注册 handler。
    fn add_handler(&self, handler: Arc<dyn OutboundHandler>) -> Result<(), CommanderError>;

    /// 移除 handler。
    fn remove_handler(&self, tag: &str) -> Result<(), CommanderError>;
}

/// 默认 handler 占位（无 listener，仅记录状态）。
///
/// 实际场景由上层注入实现。此 struct 用于测试编排流程。
pub struct StubOutboundHandler {
    tag: String,
    closed: AtomicBool,
}

impl StubOutboundHandler {
    #[must_use]
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            closed: AtomicBool::new(true), // 初始未 start
        }
    }
}

impl OutboundHandler for StubOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), CommanderError> {
        self.closed.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn close(&self) -> Result<(), CommanderError> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_handler_tag() {
        let h = StubOutboundHandler::new("api");
        assert_eq!(h.tag(), "api");
    }

    #[test]
    fn stub_handler_initial_closed() {
        let h = StubOutboundHandler::new("api");
        assert!(h.closed(), "stub 初始为 closed 状态");
    }

    #[test]
    fn stub_handler_start_open() {
        let h = StubOutboundHandler::new("api");
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn stub_handler_close_close() {
        let h = StubOutboundHandler::new("api");
        h.start().unwrap();
        h.close().unwrap();
        assert!(h.closed());
    }

    #[test]
    fn stub_handler_start_close_start() {
        let h = StubOutboundHandler::new("api");
        h.start().unwrap();
        h.close().unwrap();
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn stub_handler_debug_format() {
        let h = StubOutboundHandler::new("api");
        let s = format!("{h:?}");
        assert!(s.contains("StubOutboundHandler"));
        assert!(s.contains("api"));
    }

    #[test]
    fn outbound_handler_trait_object_safe() {
        let h: Arc<dyn OutboundHandler> = Arc::new(StubOutboundHandler::new("api"));
        assert_eq!(h.tag(), "api");
        h.start().unwrap();
        assert!(!h.closed());
    }

    // --- OutboundRegistrar mock ---

    struct MockRegistrar {
        handlers: parking_lot::Mutex<Vec<Arc<dyn OutboundHandler>>>,
    }
    impl MockRegistrar {
        fn new() -> Self {
            Self {
                handlers: parking_lot::Mutex::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.handlers.lock().len()
        }
    }
    impl OutboundRegistrar for MockRegistrar {
        fn add_handler(&self, handler: Arc<dyn OutboundHandler>) -> Result<(), CommanderError> {
            self.handlers.lock().push(handler);
            Ok(())
        }
        fn remove_handler(&self, tag: &str) -> Result<(), CommanderError> {
            let mut handlers = self.handlers.lock();
            let before = handlers.len();
            handlers.retain(|h| h.tag() != tag);
            if handlers.len() == before {
                return Err(CommanderError::OutboundRegisterFailed(tag.into()));
            }
            Ok(())
        }
    }

    #[test]
    fn mock_registrar_add_remove() {
        let reg = MockRegistrar::new();
        let h: Arc<dyn OutboundHandler> = Arc::new(StubOutboundHandler::new("api"));
        reg.add_handler(h).unwrap();
        assert_eq!(reg.count(), 1);
        reg.remove_handler("api").unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn mock_registrar_remove_missing_errors() {
        let reg = MockRegistrar::new();
        let err = reg.remove_handler("nope").unwrap_err();
        assert!(matches!(err, CommanderError::OutboundRegisterFailed(_)));
    }

    // --- CommanderConn type alias ---

    #[test]
    fn commander_conn_is_type_alias() {
        // 仅验证 type alias 编译通过
        fn _accept_conn(_c: CommanderConn) {}
        // 实际构造需要 transport 实现，这里仅类型检查
    }
}
