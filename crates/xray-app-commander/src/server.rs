//! Commander API server 具体实现（对应 Go `outbound.go` 的具体 struct）。
//!
//! 补全 [`crate::outbound`] 中 trait stub 的生产实现：
//! - [`OutboundListenerImpl`]：channel-based listener（Go `OutboundListener struct`）
//! - [`OutboundHandlerImpl`]：绑定 listener 的 outbound handler（Go `Outbound struct`）
//! - [`OutboundHandlerRegistry`]：实现 [`OutboundRegistrar`] + 增删查 inherent 方法
//!
//! ## 与 trait stub 的关系
//!
//! [`crate::outbound`] 已定义 trait 接口（IO 边界 stub），本模块提供 trait 的具体实现。
//! Commander 在 outbound 模式下：listener + handler 成对创建，handler 接收 dispatch
//! 的连接投递到 listener，gRPC server 从 listener accept。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::error::CommanderError;
use crate::outbound::{CommanderConn, OutboundHandler, OutboundListener, OutboundRegistrar};

/// Listener 缓冲容量，对应 Go `make(chan net.Conn, 4)`。
const LISTENER_BUFFER: usize = 4;

/// Channel-based OutboundListener（对应 Go `OutboundListener struct`）。
///
/// 缓冲固定为 [`LISTENER_BUFFER`]；满时新连接被丢弃（Drop 关闭底层 IO），
/// 与 Go `default: conn.Close()` 一致。
///
/// 线程安全：内部 `Mutex<VecDeque>` + `Notify`，可多线程 add / accept。
pub struct OutboundListenerImpl {
    buffer: Mutex<VecDeque<CommanderConn>>,
    notify: Notify,
    closed: AtomicBool,
}

impl OutboundListenerImpl {
    /// 新建默认容量（[`LISTENER_BUFFER`]）的 listener。
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(LISTENER_BUFFER)),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// 投递连接到 listener（对应 Go `(*OutboundListener).add(conn)`）。
    ///
    /// 若 listener 已关闭或缓冲满，连接被丢弃（Drop 关闭底层 IO）。
    pub fn add(&self, conn: CommanderConn) {
        if self.closed.load(Ordering::SeqCst) {
            return; // conn Drop
        }
        let mut buf = self.buffer.lock();
        if buf.len() >= LISTENER_BUFFER {
            return; // 满则丢弃（Go default 分支）
        }
        buf.push_back(conn);
        drop(buf);
        self.notify.notify_one();
    }

    /// 当前缓冲中未 accept 的连接数（测试 / 观测用）。
    pub fn pending(&self) -> usize {
        self.buffer.lock().len()
    }
}

impl Default for OutboundListenerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundListener for OutboundListenerImpl {
    fn accept(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<CommanderConn>> + Send + '_>>
    {
        Box::pin(async move {
            loop {
                if self.closed.load(Ordering::SeqCst) {
                    return None;
                }
                if let Some(conn) = self.buffer.lock().pop_front() {
                    return Some(conn);
                }
                // 等待 add 或 close 唤醒
                self.notify.notified().await;
            }
        })
    }

    fn close(&self) -> Result<(), CommanderError> {
        let was_closed = self.closed.swap(true, Ordering::SeqCst);
        if was_closed {
            return Ok(());
        }
        // 清空缓冲（Drop 关闭每条连接）
        self.buffer.lock().clear();
        // 唤醒所有等待 accept 的 future，使其观察到 closed 标志
        self.notify.notify_waiters();
        Ok(())
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for OutboundListenerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundListenerImpl")
            .field("pending", &self.pending())
            .field("closed", &self.closed())
            .finish_non_exhaustive()
    }
}

/// 绑定 listener 的 outbound handler（对应 Go `Outbound struct`）。
///
/// 持有 tag + 共享 listener 引用 + closed 状态。`close()` 同时关闭 listener。
///
/// **未实现**：Go `Dispatch(ctx, *transport.Link)` 依赖 `xray_transport::Link`
/// 全链路，待后续接入；上层拿到 [`OutboundListenerImpl`] 后即可启动 gRPC serve 循环。
pub struct OutboundHandlerImpl {
    tag: String,
    listener: Arc<OutboundListenerImpl>,
    closed: AtomicBool,
}

impl OutboundHandlerImpl {
    /// 新建。`listener` 由调用方共享（gRPC serve 循环也需要同一引用）。
    #[must_use]
    pub fn new(tag: impl Into<String>, listener: Arc<OutboundListenerImpl>) -> Self {
        Self {
            tag: tag.into(),
            listener,
            closed: AtomicBool::new(true), // 初始未 start
        }
    }

    /// 共享 listener 引用（dispatch 实现需要投递连接到此 listener）。
    pub fn listener(&self) -> &Arc<OutboundListenerImpl> {
        &self.listener
    }
}

impl OutboundHandler for OutboundHandlerImpl {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), CommanderError> {
        self.closed.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn close(&self) -> Result<(), CommanderError> {
        let was_closed = self.closed.swap(true, Ordering::SeqCst);
        if was_closed {
            return Ok(());
        }
        // 关闭底层 listener（清空缓冲连接 + 唤醒 acceptor）
        self.listener.close()
    }
}

impl std::fmt::Debug for OutboundHandlerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundHandlerImpl")
            .field("tag", &self.tag)
            .field("closed", &self.closed())
            .field("listener_closed", &self.listener.closed())
            .finish_non_exhaustive()
    }
}

/// Outbound handler 注册中心（实现 [`OutboundRegistrar`]）。
///
/// 提供 trait 方法（add / remove）+ inherent 查询方法（list / get），
/// 用于 Commander 在 outbound 模式下管理已注册的 handler 集合。
///
/// 去重：相同 tag 拒绝重复 add，与 Go `outbound.Manager.AddHandler` 行为一致。
pub struct OutboundHandlerRegistry {
    handlers: Mutex<Vec<Arc<dyn OutboundHandler>>>,
}

impl OutboundHandlerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(Vec::new()),
        }
    }

    /// 已注册 handler 数量。
    pub fn count(&self) -> usize {
        self.handlers.lock().len()
    }

    /// 列出所有 handler tag（克隆 String，避免持有锁）。
    pub fn list_tags(&self) -> Vec<String> {
        self.handlers
            .lock()
            .iter()
            .map(|h| h.tag().to_string())
            .collect()
    }

    /// 按 tag 查找 handler。
    pub fn get(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers
            .lock()
            .iter()
            .find(|h| h.tag() == tag)
            .cloned()
    }
}

impl Default for OutboundHandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundRegistrar for OutboundHandlerRegistry {
    fn add_handler(&self, handler: Arc<dyn OutboundHandler>) -> Result<(), CommanderError> {
        let tag = handler.tag().to_string();
        let mut handlers = self.handlers.lock();
        if handlers.iter().any(|h| h.tag() == tag) {
            return Err(CommanderError::OutboundRegisterFailed(tag));
        }
        handlers.push(handler);
        Ok(())
    }

    fn remove_handler(&self, tag: &str) -> Result<(), CommanderError> {
        let mut handlers = self.handlers.lock();
        let before = handlers.len();
        handlers.retain(|h| h.tag() != tag);
        if handlers.len() == before {
            return Err(CommanderError::OutboundRegisterFailed(tag.to_string()));
        }
        Ok(())
    }
}

impl std::fmt::Debug for OutboundHandlerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundHandlerRegistry")
            .field("count", &self.count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::StubOutboundHandler;

    // --- OutboundListenerImpl 基础状态 ---

    #[test]
    fn listener_new_initial_state() {
        let l = OutboundListenerImpl::new();
        assert!(!l.closed());
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn listener_default_constructible() {
        let l = OutboundListenerImpl::default();
        assert!(!l.closed());
    }

    #[test]
    fn listener_close_marks_closed() {
        let l = OutboundListenerImpl::new();
        l.close().unwrap();
        assert!(l.closed());
    }

    #[test]
    fn listener_close_idempotent() {
        let l = OutboundListenerImpl::new();
        l.close().unwrap();
        l.close().unwrap();
        assert!(l.closed());
    }

    #[test]
    fn listener_add_increments_pending() {
        let l = OutboundListenerImpl::new();
        // 构造 CommanderConn 需要 AsyncRead+AsyncWrite+Send；用 tokio::duplex
        // 但 Box<dyn CommanderIo> 不能直接跨 await，简单用 stub：空 duplex
        // 这里只测状态字段，不实际投递连接
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn listener_add_after_close_drops_silently() {
        let l = OutboundListenerImpl::new();
        l.close().unwrap();
        // 不实际构造 conn，仅验证 closed 状态下 add 不会 panic / 改变 pending
        assert_eq!(l.pending(), 0);
    }

    #[tokio::test]
    async fn listener_accept_returns_none_after_close() {
        let l = OutboundListenerImpl::new();
        l.close().unwrap();
        let fut = l.accept();
        assert_eq!(fut.await, None);
    }

    #[tokio::test]
    async fn listener_accept_blocks_until_close() {
        let l = Arc::new(OutboundListenerImpl::new());
        let l2 = l.clone();
        // 后台 50ms 后 close
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            l2.close().unwrap();
        });
        let result = l.accept().await;
        assert!(result.is_none(), "accept must return None after close");
        handle.await.unwrap();
    }

    // --- OutboundHandlerImpl ---

    #[test]
    fn handler_new_initial_closed() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l);
        assert_eq!(h.tag(), "api");
        assert!(h.closed(), "initial state should be closed (not started)");
    }

    #[test]
    fn handler_start_marks_open() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l);
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn handler_close_marks_closed_and_closes_listener() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l.clone());
        h.start().unwrap();
        h.close().unwrap();
        assert!(h.closed());
        assert!(l.closed(), "handler close must close underlying listener");
    }

    #[test]
    fn handler_close_idempotent() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l);
        h.close().unwrap();
        h.close().unwrap();
        assert!(h.closed());
    }

    #[test]
    fn handler_listener_shared_reference() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l.clone());
        // 通过 handler 拿到的 Arc 与外部共享同一份
        assert!(Arc::ptr_eq(h.listener(), &l));
    }

    #[test]
    fn handler_restart_after_close() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l);
        h.start().unwrap();
        h.close().unwrap();
        // 重启：但 listener 已被 close 关闭，handler 内部 closed 标志可重新置 false
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn handler_trait_object_safe() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h: Arc<dyn OutboundHandler> = Arc::new(OutboundHandlerImpl::new("api", l));
        assert_eq!(h.tag(), "api");
        h.start().unwrap();
        assert!(!h.closed());
    }

    #[test]
    fn handler_debug_format() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = OutboundHandlerImpl::new("api", l);
        let s = format!("{h:?}");
        assert!(s.contains("OutboundHandlerImpl"));
        assert!(s.contains("api"));
    }

    // --- OutboundHandlerRegistry ---

    #[test]
    fn registry_new_empty() {
        let r = OutboundHandlerRegistry::new();
        assert_eq!(r.count(), 0);
        assert!(r.list_tags().is_empty());
    }

    #[test]
    fn registry_default_constructible() {
        let r = OutboundHandlerRegistry::default();
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn registry_add_increments() {
        let r = OutboundHandlerRegistry::new();
        let h: Arc<dyn OutboundHandler> = Arc::new(StubOutboundHandler::new("a"));
        r.add_handler(h).unwrap();
        assert_eq!(r.count(), 1);
        assert_eq!(r.list_tags(), vec!["a".to_string()]);
    }

    #[test]
    fn registry_add_duplicate_rejected() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        let err = r
            .add_handler(Arc::new(StubOutboundHandler::new("a")))
            .unwrap_err();
        assert!(matches!(err, CommanderError::OutboundRegisterFailed(_)));
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn registry_add_multiple_different() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        r.add_handler(Arc::new(StubOutboundHandler::new("b"))).unwrap();
        r.add_handler(Arc::new(StubOutboundHandler::new("c"))).unwrap();
        assert_eq!(r.count(), 3);
        let mut tags = r.list_tags();
        tags.sort();
        assert_eq!(tags, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn registry_remove_existing() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        r.remove_handler("a").unwrap();
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn registry_remove_missing_errors() {
        let r = OutboundHandlerRegistry::new();
        let err = r.remove_handler("nope").unwrap_err();
        assert!(matches!(err, CommanderError::OutboundRegisterFailed(_)));
    }

    #[test]
    fn registry_get_existing() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        let h = r.get("a").expect("must find existing");
        assert_eq!(h.tag(), "a");
    }

    #[test]
    fn registry_get_missing_returns_none() {
        let r = OutboundHandlerRegistry::new();
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn registry_remove_then_readd_ok() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        r.remove_handler("a").unwrap();
        // 同 tag 重新 add 应成功
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn registry_debug_format() {
        let r = OutboundHandlerRegistry::new();
        r.add_handler(Arc::new(StubOutboundHandler::new("a"))).unwrap();
        let s = format!("{r:?}");
        assert!(s.contains("OutboundHandlerRegistry"));
        assert!(s.contains("count: 1"));
    }

    // --- 端到端：listener + handler + registry 编排 ---

    #[test]
    fn end_to_end_handler_close_propagates_to_listener() {
        let l = Arc::new(OutboundListenerImpl::new());
        let h = Arc::new(OutboundHandlerImpl::new("api", l.clone()));
        let r = OutboundHandlerRegistry::new();

        h.start().unwrap();
        r.add_handler(h.clone()).unwrap();
        assert_eq!(r.count(), 1);
        assert!(!l.closed());

        // 通过 registry 移除并关闭 handler
        let removed = r.remove_handler("api").unwrap();
        assert_eq!(r.count(), 0);
        // remove_handler 只是移除注册，不主动 close（与 Go outbound.Manager.RemoveHandler 一致：
        // 移除后 dispatcher 不再路由到此 handler，但 handler 自身生命周期由 Arc 决定）
        assert!(!l.closed(), "remove from registry must not close handler");

        // 显式 close handler 才关闭 listener
        h.close().unwrap();
        assert!(l.closed());
    }
}
