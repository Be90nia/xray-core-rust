//! Mux 客户端
//!
//! 对应 Go 版本 `common/mux/client.go`，实现 Mux 客户端的多路复用调度。
//!
//! # 核心组件
//!
//! - [`Link`]: 传输链路（读写两端）
//! - [`ClientManager`]: 顶层调度入口
//! - [`WorkerPicker`]: Worker 选择器 trait
//! - [`IncrementalWorkerPicker`]: 增量式选择器（LRU + 30s 清理）
//! - [`ClientWorker`]: 核心工作单元
//! - [`ClientWorkerFactory`]: Worker 工厂 trait
//! - [`DialingWorkerFactory`]: 拨号式 Worker 工厂

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{watch, Mutex};
use tokio::time::Duration;
use tracing::debug;
use xray_buf::io::{Reader, Writer};
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;

use crate::session::{ClientStrategy, Session, SessionManager};

// ========== 常量 ==========

/// Mux 协议识别地址
pub const MUX_COOL_ADDRESS: &str = "v1.mux.cool";

/// Mux 协议识别端口
pub const MUX_COOL_PORT: u16 = 9527;

/// 客户端心跳间隔
pub const CLIENT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(16);

/// 首包超时时间
pub const FIRST_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(100);

/// 最大调度重试次数
pub const MAX_DISPATCH_RETRY: usize = 16;

/// Worker 选择器清理间隔
pub const PICKER_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

// ========== Link 结构 ==========

/// 传输链路，包含读取端和写入端。
///
/// 对应 Go 版本 `transport.Link`。
pub struct Link {
    /// 读取端
    pub reader: Box<dyn Reader>,
    /// 写入端
    pub writer: Box<dyn Writer>,
}

// ========== WorkerPicker trait ==========

/// Worker 选择器 trait。
///
/// 对应 Go 版本 `WorkerPicker` 接口。
pub trait WorkerPicker: Send + Sync {
    /// 选择一个可用的 ClientWorker。
    fn pick_available(&self) -> Option<Arc<ClientWorker>>;
}

// ========== ClientWorkerFactory trait ==========

/// Worker 工厂 trait。
///
/// 对应 Go 版本 `ClientWorkerFactory` 接口。
#[async_trait::async_trait]
pub trait ClientWorkerFactory: Send + Sync {
    /// 创建一个新的 ClientWorker。
    async fn create(&self) -> Arc<ClientWorker>;
}

// ========== ClientManager ==========

/// 客户端管理器，顶层调度入口。
///
/// 对应 Go 版本 `ClientManager`。
pub struct ClientManager {
    /// 是否启用 mux
    pub enabled: bool,
    /// Worker 选择器
    picker: Box<dyn WorkerPicker>,
}

impl ClientManager {
    /// 创建新的客户端管理器。
    pub fn new(enabled: bool, picker: Box<dyn WorkerPicker>) -> Self {
        Self { enabled, picker }
    }

    /// 调度连接到 mux worker。
    ///
    /// 对应 Go 版本 `ClientManager.Dispatch`。
    /// 最多重试 `MAX_DISPATCH_RETRY` 次寻找可用 Worker。
    pub fn dispatch(&self) -> Result<Arc<ClientWorker>, ClientError> {
        if !self.enabled {
            return Err(ClientError::MuxDisabled);
        }

        for _ in 0..MAX_DISPATCH_RETRY {
            if let Some(worker) = self.picker.pick_available() {
                if !worker.is_full() {
                    return Ok(worker);
                }
            }
        }

        Err(ClientError::NoAvailableWorker)
    }
}

// ========== IncrementalWorkerPicker ==========

/// 增量式 Worker 选择器。
///
/// 对应 Go 版本 `IncrementalWorkerPicker`。
/// 维护 Worker 列表，优先使用已有可用 Worker，
/// 不可用时通过 Factory 创建新 Worker。
pub struct IncrementalWorkerPicker {
    factory: Arc<dyn ClientWorkerFactory>,
    workers: Mutex<Vec<Arc<ClientWorker>>>,
    cleanup_started: AtomicBool,
}

impl IncrementalWorkerPicker {
    /// 创建新的增量式 Worker 选择器。
    pub fn new(factory: Arc<dyn ClientWorkerFactory>) -> Self {
        Self {
            factory,
            workers: Mutex::new(Vec::new()),
            cleanup_started: AtomicBool::new(false),
        }
    }

    /// 内部选择逻辑：查找可用 Worker 或创建新 Worker。
    ///
    /// 对应 Go 版本 `pickInternal`。
    pub async fn pick_internal(&self) -> Option<Arc<ClientWorker>> {
        let mut workers = self.workers.lock().await;

        // 查找可用 Worker（非 Full、非 Closed）
        if let Some(idx) = Self::find_available(&workers) {
            let len = workers.len();
            if idx != len - 1 {
                workers.swap(idx, len - 1);
            }
            return Some(workers[len - 1].clone());
        }

        // 清理已关闭的 Worker
        workers.retain(|w| !w.is_closed());
        drop(workers);

        // 创建新 Worker
        let worker = self.factory.create().await;
        let mut workers = self.workers.lock().await;
        workers.push(worker.clone());

        // 首次创建 Worker 时标记清理已启动
        // 完整实现应使用 tokio::spawn 启动周期清理任务
        self.cleanup_started.store(true, Ordering::Relaxed);

        Some(worker)
    }

    /// 查找可用的 Worker 索引。
    fn find_available(workers: &[Arc<ClientWorker>]) -> Option<usize> {
        workers.iter().position(|w| !w.is_full() && !w.is_closed())
    }

    /// 清理已关闭的 Worker。
    pub async fn cleanup(&self) {
        let mut workers = self.workers.lock().await;
        let before = workers.len();
        workers.retain(|w| !w.is_closed());
        let removed = before - workers.len();
        if removed > 0 {
            debug!("cleaned up {} closed workers", removed);
        }
    }

    /// 获取 Worker 数量。
    pub async fn worker_count(&self) -> usize {
        self.workers.lock().await.len()
    }
}

impl WorkerPicker for IncrementalWorkerPicker {
    fn pick_available(&self) -> Option<Arc<ClientWorker>> {
        match self.workers.try_lock() {
            Ok(workers) => {
                if let Some(idx) = Self::find_available(&workers) {
                    return Some(workers[idx].clone());
                }
                None
            }
            Err(_) => None,
        }
    }
}

// ========== ClientWorker ==========

/// 客户端工作单元。
///
/// 对应 Go 版本 `ClientWorker`。
/// 管理 SessionManager、心跳定时器和策略。
pub struct ClientWorker {
    session_manager: Arc<SessionManager>,
    closed: AtomicBool,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
    strategy: ClientStrategy,
}

impl ClientWorker {
    /// 创建新的 ClientWorker。
    pub fn new(strategy: ClientStrategy) -> Self {
        let (done_tx, done_rx) = watch::channel(false);
        Self {
            session_manager: Arc::new(SessionManager::new()),
            closed: AtomicBool::new(false),
            done_tx,
            done_rx,
            strategy,
        }
    }

    /// 检查是否即将关闭（达到最大连接数）。
    #[must_use]
    pub fn is_closing(&self) -> bool {
        let max_conn = self.strategy.max_connection;
        max_conn > 0 && self.session_manager.count() >= max_conn as u16
    }

    /// 检查是否已满（达到并发或连接上限）。
    #[must_use]
    pub fn is_full(&self) -> bool {
        if self.is_closing() || self.is_closed() {
            return true;
        }
        let max_conc = self.strategy.max_concurrency;
        max_conc > 0 && self.session_manager.count() >= max_conc as u16
    }

    /// 检查是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// 关闭 Worker。
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.done_tx.send(true);
    }

    /// 分配新会话到此 Worker。
    pub async fn allocate_session(&self) -> Option<Arc<Session>> {
        if self.is_full() {
            return None;
        }
        self.session_manager.allocate(&self.strategy).await
    }

    /// 获取会话管理器引用。
    #[must_use]
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// 获取策略引用。
    #[must_use]
    pub fn strategy(&self) -> &ClientStrategy {
        &self.strategy
    }

    /// 获取关闭信号接收端。
    pub fn done_rx(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }

    /// 获取会话管理器计数。
    #[must_use]
    pub fn session_count(&self) -> u16 {
        self.session_manager.count()
    }

    /// 创建 mux 目标地址（v1.mux.cool:9527）。
    #[must_use]
    pub fn mux_destination() -> Destination {
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;
        Destination::new(
            Address::new_domain(MUX_COOL_ADDRESS),
            Port::new(MUX_COOL_PORT),
            Network::TCP,
        )
    }

    /// 启动 KeepAlive 定时发送任务。
    ///
    /// 对应 Go 版本 `ClientWorker.monitor` 中的 timer 逻辑。
    /// 客户端每 16 秒向所有活跃 session 发送 KeepAlive 帧。
    /// 同时检查空闲超时，关闭空闲超过 300 秒的 session。
    pub fn spawn_keepalive(
        &self,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn xray_buf::io::Writer>>>>,
    ) -> tokio::task::JoinHandle<()> {
        use crate::frame::FrameMetadata;
        use crate::session::SESSION_IDLE_TIMEOUT;
        use xray_buf::buffer::Buffer;
        use xray_buf::multi::MultiBuffer;
        use tracing::warn;

        let session_manager = Arc::clone(&self.session_manager);
        let mut done_rx = self.done_rx.clone();
        let lw = link_writer;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLIENT_KEEPALIVE_INTERVAL);
            loop {
                tokio::select! {
                    _ = done_rx.changed() => break,
                    _ = interval.tick() => {
                        // 向所有活跃 session 发送 KeepAlive 帧
                        let sessions = session_manager.active_sessions().await;
                        for session in &sessions {
                            if session.is_closed() { continue; }
                            let meta = FrameMetadata::keep_alive(session.id());
                            let mut vec = Vec::new();
                            if meta.write_to(&mut vec).is_err() { continue; }
                            let mb = MultiBuffer::from_buffer(Buffer::from_vec(vec));
                            let mut wg = lw.lock().await;
                            if let Some(ref mut writer) = *wg {
                                let _ = writer.write_multi_buffer(mb).await;
                            }
                        }
                        // 检查空闲超时
                        for session in sessions {
                            if session.is_closed() { continue; }
                            if session.is_idle_timeout(SESSION_IDLE_TIMEOUT).await {
                                warn!("client session {} idle timeout, closing", session.id());
                                session.close().await;
                            }
                        }
                    }
                }
            }
        })
    }
}

// ========== DialingWorkerFactory ==========

/// 拨号式 Worker 工厂。
///
/// 对应 Go 版本 `DialingWorkerFactory`。
pub struct DialingWorkerFactory {
    /// 策略
    pub strategy: ClientStrategy,
}

impl DialingWorkerFactory {
    /// 创建新的拨号式工厂。
    pub fn new(strategy: ClientStrategy) -> Self {
        Self { strategy }
    }
}

#[async_trait::async_trait]
impl ClientWorkerFactory for DialingWorkerFactory {
    async fn create(&self) -> Arc<ClientWorker> {
        Arc::new(ClientWorker::new(self.strategy.clone()))
    }
}

// ========== 错误类型 ==========

/// 客户端错误。
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    /// Mux 未启用
    #[error("mux is not enabled")]
    MuxDisabled,
    /// 无可用 Worker
    #[error("no available worker")]
    NoAvailableWorker,
    /// Worker 已满
    #[error("worker is full")]
    WorkerFull,
    /// 达到最大会话数
    #[error("max session reached")]
    MaxSessionReached,
}

// ========== 测试 ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_worker_new() {
        let worker = ClientWorker::new(ClientStrategy::default());
        assert!(!worker.is_closed());
        assert!(!worker.is_full());
        assert!(!worker.is_closing());
    }

    #[test]
    fn test_client_worker_close() {
        let worker = ClientWorker::new(ClientStrategy::default());
        worker.close();
        assert!(worker.is_closed());
    }

    #[test]
    fn test_client_worker_is_full_when_closed() {
        let worker = ClientWorker::new(ClientStrategy::default());
        worker.close();
        assert!(worker.is_full());
    }

    #[test]
    fn test_client_worker_is_closing_with_max_connection() {
        let strategy = ClientStrategy {
            max_concurrency: 0,
            max_connection: 1,
        };
        let worker = ClientWorker::new(strategy);
        assert!(!worker.is_closing()); // count=0 < max_connection=1
    }

    #[test]
    fn test_mux_cool_constants() {
        assert_eq!(MUX_COOL_ADDRESS, "v1.mux.cool");
        assert_eq!(MUX_COOL_PORT, 9527);
    }

    #[test]
    fn test_mux_destination() {
        let dest = ClientWorker::mux_destination();
        assert_eq!(dest.network(), Network::TCP);
    }

    #[test]
    fn test_client_manager_disabled() {
        struct NoopPicker;
        impl WorkerPicker for NoopPicker {
            fn pick_available(&self) -> Option<Arc<ClientWorker>> {
                None
            }
        }
        let mgr = ClientManager::new(false, Box::new(NoopPicker));
        assert!(mgr.dispatch().is_err());
    }

    #[test]
    fn test_dialing_worker_factory() {
        let strategy = ClientStrategy {
            max_concurrency: 10,
            max_connection: 5,
        };
        let factory = DialingWorkerFactory::new(strategy);
        assert_eq!(factory.strategy.max_concurrency, 10);
    }

    #[tokio::test]
    async fn test_incremental_picker_cleanup() {
        let strategy = ClientStrategy::default();
        let factory = Arc::new(DialingWorkerFactory::new(strategy));
        let picker = IncrementalWorkerPicker::new(factory);
        assert_eq!(picker.worker_count().await, 0);
        picker.cleanup().await;
    }

    #[tokio::test]
    async fn test_incremental_picker_pick_internal() {
        let strategy = ClientStrategy::default();
        let factory = Arc::new(DialingWorkerFactory::new(strategy));
        let picker = IncrementalWorkerPicker::new(factory);
        let worker = picker.pick_internal().await;
        assert!(worker.is_some());
        assert_eq!(picker.worker_count().await, 1);
    }

    #[test]
    fn test_client_error_display() {
        assert_eq!(
            format!("{}", ClientError::MuxDisabled),
            "mux is not enabled"
        );
        assert_eq!(
            format!("{}", ClientError::NoAvailableWorker),
            "no available worker"
        );
    }

    #[test]
    fn test_link_struct() {
        // Link 结构体的字段类型编译验证
        fn _assert_link_send(reader: Box<dyn Reader>, writer: Box<dyn Writer>) -> Link {
            Link { reader, writer }
        }
    }
}
