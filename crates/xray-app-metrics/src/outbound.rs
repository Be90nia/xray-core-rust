//! xray-app-metrics 的 Outbound / OutboundListener。
//!
//! 对应 Go `app/metrics/outbound.go`：`OutboundListener` 实现 `net.Listener`，作为
//! metrics HTTP 流量进入的内部管道；`Outbound` 实现 `outbound.Handler`，把 dispatcher
//! 投递的 Link 包装为 Conn 后塞进 listener 的缓冲区，再被 HTTP server 接走。
//!
//! Rust 翻译保留纯业务：缓冲区容量管理、关闭状态、Conn 的 trait object 类型擦除。
//! IO 边界（transport::Link → Conn 的转换、http.Serve 的实际运行）由上层注入。

use std::any::Any;
use std::collections::VecDeque;

use parking_lot::{Condvar, Mutex};

use crate::error::{at_warning, MetricsError};

/// 内部 Conn 容器：用 `Box<dyn Any + Send>` 类型擦除，让 listener 不绑定具体连接类型。
///
/// 上层负责把 `transport::Link`（或等价的 IO 抽象）打包成 `Box<dyn Any + Send>`，
/// listener 只负责缓冲与生命周期管理，不解析内部结构。
pub type BoxedConn = Box<dyn Any + Send + 'static>;

/// 内部缓冲区容量，对应 Go 版 `make(chan net.Conn, 4)`。
const BUFFER_CAPACITY: usize = 4;

struct ListenerInner {
    queue: VecDeque<BoxedConn>,
    closed: bool,
}

/// OutboundListener：metrics HTTP 流量的内部 Conn 中转。
///
/// 对应 Go `OutboundListener` + `chan net.Conn` + `*done.Instance`。
/// - `add`：当缓冲区满或已关闭时丢弃连接（与 Go `select default` 一致）。
/// - `accept`：阻塞等待连接，关闭后返回 `ListenerClosed`。
/// - `close`：标记关闭，丢弃所有缓冲中的连接（调用方负责 close 内部 conn）。
pub struct OutboundListener {
    inner: Mutex<ListenerInner>,
    cv: Condvar,
}

impl OutboundListener {
    /// 创建空的 listener。
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ListenerInner {
                queue: VecDeque::with_capacity(BUFFER_CAPACITY),
                closed: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// 把一个 conn 加入缓冲区。
    ///
    /// 当 listener 已关闭或缓冲区已满时返回 false，调用方负责关闭/丢弃该 conn。
    pub fn try_add(&self, conn: BoxedConn) -> bool {
        let mut g = self.inner.lock();
        if g.closed {
            return false;
        }
        if g.queue.len() >= BUFFER_CAPACITY {
            return false;
        }
        g.queue.push_back(conn);
        self.cv.notify_one();
        true
    }

    /// 阻塞等待一个 conn（同步原语，与 Go `Accept` 阻塞语义一致）。
    ///
    /// 关闭后立即返回 `Err(ListenerClosed)`。已阻塞的 `accept` 调用会被唤醒。
    pub fn accept(&self) -> Result<BoxedConn, MetricsError> {
        let mut g = self.inner.lock();
        loop {
            if let Some(conn) = g.queue.pop_front() {
                return Ok(conn);
            }
            if g.closed {
                return Err(MetricsError::ListenerClosed);
            }
            self.cv.wait(&mut g);
        }
    }

    /// 标记 listener 关闭，丢弃所有缓冲中的 conn（调用方需要在 conn 上做清理）。
    pub fn close(&self) {
        let mut g = self.inner.lock();
        if g.closed {
            return;
        }
        g.closed = true;
        let dropped: Vec<BoxedConn> = g.queue.drain(..).collect();
        // 通知所有阻塞的 accept 唤醒
        self.cv.notify_all();
        // 在锁外 drop 连接（drop 可能触发副作用，避免持锁）
        drop(g);
        let count = dropped.len();
        drop(dropped);
        if count > 0 {
            at_warning(&MetricsError::ListenInvalid(format!(
                "outbound listener closed with {count} pending conn dropped"
            )));
        }
    }

    /// 是否已关闭。
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// 当前缓冲区长度（仅用于测试/观测）。
    pub fn pending_len(&self) -> usize {
        self.inner.lock().queue.len()
    }
}

impl Default for OutboundListener {
    fn default() -> Self {
        Self::new()
    }
}

/// Outbound：metrics HTTP 流量的 outbound.Handler。
///
/// 对应 Go `Outbound`：持有 tag + listener + 关闭状态（RwLock 保护）。
/// `dispatch` 把上层传入的 conn 投递到 listener；`close` 关闭 listener。
pub struct Outbound {
    tag: String,
    listener: OutboundListener,
    closed: Mutex<bool>,
}

impl Outbound {
    pub fn new(tag: impl Into<String>, listener: OutboundListener) -> Self {
        Self {
            tag: tag.into(),
            listener,
            closed: Mutex::new(false),
        }
    }

    /// Tag。
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 持有的 listener 引用。
    pub fn listener(&self) -> &OutboundListener {
        &self.listener
    }

    /// 把一个 conn 投递到 listener；关闭后丢弃并记录 warning。
    pub fn dispatch(&self, conn: BoxedConn) {
        if *self.closed.lock() {
            at_warning(&MetricsError::ListenerClosed);
            return;
        }
        if !self.listener.try_add(conn) {
            at_warning(&MetricsError::ListenInvalid(format!(
                "metrics outbound '{}': listener full or closed, conn dropped",
                self.tag
            )));
        }
    }

    /// Start：清除关闭标记（与 Go 版一致）。
    pub fn start(&self) {
        *self.closed.lock() = false;
    }

    /// Close：标记关闭并 close listener。
    pub fn close(&self) {
        let mut g = self.closed.lock();
        if *g {
            return;
        }
        *g = true;
        drop(g);
        self.listener.close();
    }

    /// 是否已关闭。
    pub fn is_closed(&self) -> bool {
        *self.closed.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn boxed(v: i32) -> BoxedConn {
        Box::new(v)
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn listener_is_send_sync() {
        assert_send_sync::<OutboundListener>();
    }

    #[test]
    fn outbound_is_send_sync() {
        assert_send_sync::<Outbound>();
    }

    #[test]
    fn new_listener_is_empty_and_open() {
        let l = OutboundListener::new();
        assert_eq!(l.pending_len(), 0);
        assert!(!l.is_closed());
    }

    #[test]
    fn add_increments_pending() {
        let l = OutboundListener::new();
        assert!(l.try_add(boxed(1)));
        assert!(l.try_add(boxed(2)));
        assert_eq!(l.pending_len(), 2);
    }

    #[test]
    fn add_beyond_capacity_returns_false() {
        let l = OutboundListener::new();
        for i in 0..BUFFER_CAPACITY {
            assert!(l.try_add(boxed(i as i32)), "add {i} should succeed");
        }
        assert!(!l.try_add(boxed(99)), "beyond capacity must reject");
        assert_eq!(l.pending_len(), BUFFER_CAPACITY);
    }

    #[test]
    fn add_after_close_returns_false() {
        let l = OutboundListener::new();
        l.close();
        assert!(!l.try_add(boxed(1)));
    }

    #[test]
    fn close_marks_closed_and_empties_queue() {
        let l = OutboundListener::new();
        l.try_add(boxed(1));
        l.try_add(boxed(2));
        l.close();
        assert!(l.is_closed());
        assert_eq!(l.pending_len(), 0);
    }

    #[test]
    fn close_twice_is_noop() {
        let l = OutboundListener::new();
        l.close();
        l.close();
        assert!(l.is_closed());
    }

    #[test]
    fn accept_pops_in_fifo_order() {
        let l = Arc::new(OutboundListener::new());
        l.try_add(boxed(10));
        l.try_add(boxed(20));

        let c1 = l.accept().expect("first accept");
        let c2 = l.accept().expect("second accept");
        assert_eq!(*c1.downcast_ref::<i32>().unwrap(), 10);
        assert_eq!(*c2.downcast_ref::<i32>().unwrap(), 20);
    }

    #[test]
    fn accept_after_close_returns_err() {
        let l = OutboundListener::new();
        l.close();
        let err = l.accept().unwrap_err();
        assert!(matches!(err, MetricsError::ListenerClosed));
    }

    #[test]
    fn accept_blocks_until_close_unblocks() {
        // 跨线程：启动 accept，等待其阻塞后 close，应唤醒并返回 Err
        let l = Arc::new(OutboundListener::new());
        let l2 = l.clone();
        let handle = std::thread::spawn(move || l2.accept());
        // 给 worker 时间进入等待
        std::thread::sleep(std::time::Duration::from_millis(50));
        l.close();
        let res = handle.join().expect("worker thread");
        assert!(res.is_err());
    }

    #[test]
    fn accept_blocks_until_add_unblocks() {
        let l = Arc::new(OutboundListener::new());
        let l2 = l.clone();
        let handle = std::thread::spawn(move || l2.accept());
        std::thread::sleep(std::time::Duration::from_millis(50));
        l.try_add(boxed(42));
        let conn = handle.join().expect("worker thread").expect("got conn");
        assert_eq!(*conn.downcast_ref::<i32>().unwrap(), 42);
    }

    #[test]
    fn outbound_dispatch_routes_to_listener() {
        let l = OutboundListener::new();
        let ob = Outbound::new("metrics", l);
        ob.dispatch(boxed(7));
        assert_eq!(ob.listener().pending_len(), 1);
    }

    #[test]
    fn outbound_dispatch_after_close_drops() {
        let l = OutboundListener::new();
        let ob = Outbound::new("metrics", l);
        ob.close();
        ob.dispatch(boxed(1));
        assert_eq!(ob.listener().pending_len(), 0);
    }

    #[test]
    fn outbound_close_propagates_to_listener() {
        let l = OutboundListener::new();
        let ob = Outbound::new("metrics", l);
        ob.close();
        assert!(ob.is_closed());
        assert!(ob.listener().is_closed());
    }

    #[test]
    fn outbound_start_clears_closed_flag() {
        let l = OutboundListener::new();
        let ob = Outbound::new("metrics", l);
        ob.close();
        ob.start();
        assert!(!ob.is_closed());
        // 注意：listener 已被 close，需上层重建（与 Go 行为一致）
    }

    #[test]
    fn outbound_tag_returns_construction_tag() {
        let l = OutboundListener::new();
        let ob = Outbound::new("pingpong", l);
        assert_eq!(ob.tag(), "pingpong");
    }

    #[test]
    fn outbound_close_twice_is_noop() {
        let l = OutboundListener::new();
        let ob = Outbound::new("metrics", l);
        ob.close();
        ob.close();
        assert!(ob.is_closed());
    }

    #[test]
    fn default_listener_equivalent_to_new() {
        let d = OutboundListener::default();
        assert_eq!(d.pending_len(), 0);
        assert!(!d.is_closed());
    }
}
