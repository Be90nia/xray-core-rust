//! Mux 会话管理
//!
//! 对应 Go 版本 `common/mux/session.go`，实现 Mux 多路复用的会话生命周期管理。
//!
//! # 核心组件
//!
//! - [`TransferType`]: 传输类型（流式/包式）
//! - [`Session`]: 单个 Mux 会话
//! - [`SessionManager`]: 会话管理器
//! - [`XUDP`]: UDP 会话扩展
//! - [`XUDPManager`]: UDP 会话管理器

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tracing::debug;

// ========== 传输类型 ==========

/// 传输类型。
///
/// 对应 Go 版本 `protocol.TransferType`，区分流式和包式传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransferType {
    /// 流式传输（TCP）。
    Stream = 0,
    /// 包式传输（UDP）。
    Packet = 1,
}

impl TransferType {
    /// 从字节值解析传输类型。
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Stream),
            1 => Some(Self::Packet),
            _ => None,
        }
    }

    /// 转换为字节值。
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

// ========== 客户端策略 ==========

/// 客户端策略。
///
/// 对应 Go 版本 `ClientStrategy`，控制会话分配的限制条件。
#[derive(Debug, Clone, Default)]
pub struct ClientStrategy {
    /// 最大并发会话数（0 表示无限制）。
    pub max_concurrency: u32,
    /// 最大连接数（0 表示无限制）。
    pub max_connection: u32,
}

// ========== XUDP 状态 ==========

/// XUDP 会话状态。
///
/// 对应 Go 版本的常量定义：`Initializing`, `Active`, `Expiring`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum XudpStatus {
    /// 初始化中。
    Initializing = 0,
    /// 活跃状态。
    Active = 1,
    /// 过期中（等待清理）。
    Expiring = 2,
}

// ========== 错误类型 ==========

/// 会话管理错误。
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum SessionError {
    /// 会话已关闭。
    #[error("session is closed")]
    SessionClosed,
    /// 会话管理器已关闭。
    #[error("session manager is closed")]
    ManagerClosed,
    /// 会话不存在。
    #[error("session not found: {0}")]
    SessionNotFound(u16),
    /// 达到最大并发限制。
    #[error("max concurrency limit reached: {0}")]
    MaxConcurrencyReached(u32),
    /// 达到最大连接限制。
    #[error("max connection limit reached: {0}")]
    MaxConnectionReached(u32),
}

// ========== 弱引用类型别名 ==========

type WeakSession = std::sync::Weak<Session>;

// ========== Session ==========

/// Mux 会话。
///
/// 对应 Go 版本 `Session`，表示 Mux 连接中的一个客户端连接。
pub struct Session {
    /// 会话 ID。
    id: u16,
    /// 传输类型。
    transfer_type: TransferType,
    /// 关闭标志（原子操作，用于无锁快速检查）。
    closed_flag: Arc<AtomicBool>,
    /// XUDP 扩展（可选）。
    xudp: Mutex<Option<XUDP>>,
}

impl Session {
    /// 创建新会话。
    pub(crate) fn new(id: u16, transfer_type: TransferType) -> Self {
        Self {
            id,
            transfer_type,
            closed_flag: Arc::new(AtomicBool::new(false)),
            xudp: Mutex::new(None),
        }
    }

    /// 获取会话 ID。
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// 获取传输类型。
    #[must_use]
    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }

    /// 检查会话是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed_flag.load(Ordering::Acquire)
    }

    /// 关闭会话。
    ///
    /// 返回 `true` 表示本次调用实际关闭了会话，`false` 表示会话已关闭。
    pub async fn close(&self) -> bool {
        if self.closed_flag.swap(true, Ordering::AcqRel) {
            return false;
        }

        // 处理 XUDP 特殊逻辑：Active 状态转为 Expiring，设置 60 秒过期
        let mut xudp_guard = self.xudp.lock().await;
        if let Some(ref mut xudp) = *xudp_guard {
            if xudp.status == XudpStatus::Active {
                xudp.status = XudpStatus::Expiring;
                xudp.expire = Instant::now() + Duration::from_secs(60);
                debug!("XUDP put: {:?}", xudp.global_id);
            }
        }

        true
    }

    /// 设置 XUDP 扩展。
    pub async fn set_xudp(&self, xudp: XUDP) {
        let mut guard = self.xudp.lock().await;
        *guard = Some(xudp);
    }

    /// 获取 XUDP 扩展。
    pub async fn xudp(&self) -> Option<XUDP> {
        let guard = self.xudp.lock().await;
        guard.clone()
    }

    /// 获取关闭标志的 Arc（用于等待关闭）。
    #[must_use]
    pub fn closed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed_flag)
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("transfer_type", &self.transfer_type)
            .field("closed", &self.is_closed())
            .finish()
    }
}

// ========== XUDP ==========

/// XUDP 会话扩展。
///
/// 对应 Go 版本 `XUDP`，用于 UDP 会话的源追踪和过期管理。
#[derive(Debug, Clone)]
pub struct XUDP {
    /// 全局 ID（8 字节）。
    pub global_id: [u8; 8],
    /// 状态。
    pub status: XudpStatus,
    /// 过期时间。
    pub expire: Instant,
    /// 关联的会话（弱引用避免循环引用）。
    mux: Option<WeakSession>,
}

impl XUDP {
    /// 创建新的 XUDP 扩展。
    #[must_use]
    pub fn new(global_id: [u8; 8]) -> Self {
        Self {
            global_id,
            status: XudpStatus::Initializing,
            expire: Instant::now(),
            mux: None,
        }
    }

    /// 设置关联会话。
    pub fn set_mux(&mut self, session: &Arc<Session>) {
        self.mux = Some(Arc::downgrade(session));
    }

    /// 中断关联会话。
    pub async fn interrupt(&self) {
        if let Some(ref weak) = self.mux {
            if let Some(session) = weak.upgrade() {
                session.close().await;
            }
        }
    }
}

// ========== SessionManager ==========

/// 会话管理器内部状态。
struct SessionManagerInner {
    /// 会话映射表。
    sessions: HashMap<u16, Arc<Session>>,
    /// 计数器（已分配的会话总数，包括已关闭的）。
    count: u16,
    /// 是否已关闭。
    closed: bool,
}

/// 会话管理器。
///
/// 对应 Go 版本 `SessionManager`，管理所有 Mux 会话的生命周期。
pub struct SessionManager {
    /// 内部状态（RwLock 保护）。
    inner: Arc<RwLock<SessionManagerInner>>,
    /// 计数器（原子操作，用于快速读取）。
    count: Arc<AtomicU16>,
    /// 关闭标志。
    closed_flag: Arc<AtomicBool>,
}

impl SessionManager {
    /// 创建新的会话管理器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SessionManagerInner {
                sessions: HashMap::with_capacity(16),
                count: 0,
                closed: false,
            })),
            count: Arc::new(AtomicU16::new(0)),
            closed_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 检查管理器是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed_flag.load(Ordering::Acquire)
    }

    /// 获取当前活跃会话数。
    pub async fn size(&self) -> usize {
        let inner = self.inner.read().await;
        inner.sessions.len()
    }

    /// 获取已分配的会话总数（包括已关闭的）。
    #[must_use]
    pub fn count(&self) -> u16 {
        self.count.load(Ordering::Acquire)
    }

    /// 分配新会话。
    ///
    /// 根据 `strategy` 的限制条件分配新会话，返回 `None` 表示无法分配。
    pub async fn allocate(&self, strategy: &ClientStrategy) -> Option<Arc<Session>> {
        let mut inner = self.inner.write().await;

        if inner.closed {
            return None;
        }

        let max_concurrency = strategy.max_concurrency as usize;
        if max_concurrency > 0 && inner.sessions.len() >= max_concurrency {
            return None;
        }

        let max_connection = strategy.max_connection as u16;
        if max_connection > 0 && inner.count >= max_connection {
            return None;
        }

        inner.count += 1;
        self.count.store(inner.count, Ordering::Release);

        let session = Arc::new(Session::new(inner.count, TransferType::Stream));
        inner.sessions.insert(session.id, Arc::clone(&session));
        Some(session)
    }

    /// 添加已存在的会话。
    ///
    /// 返回 `true` 表示添加成功，`false` 表示管理器已关闭。
    pub async fn add(&self, session: Arc<Session>) -> bool {
        let mut inner = self.inner.write().await;

        if inner.closed {
            return false;
        }

        inner.count = inner.count.saturating_add(1);
        self.count.store(inner.count, Ordering::Release);
        inner.sessions.insert(session.id(), session);
        true
    }

    /// 移除会话。
    pub async fn remove(&self, id: u16) {
        let mut inner = self.inner.write().await;
        if !inner.closed {
            inner.sessions.remove(&id);
        }
    }

    /// 获取会话。
    pub async fn get(&self, id: u16) -> Option<Arc<Session>> {
        let inner = self.inner.read().await;
        if inner.closed {
            return None;
        }
        inner.sessions.get(&id).cloned()
    }

    /// 检查是否可以关闭（无会话且空闲）。
    pub async fn close_if_no_session_and_idle(
        &self,
        check_size: usize,
        check_count: u16,
    ) -> bool {
        let mut inner = self.inner.write().await;

        if inner.closed {
            return true;
        }

        if !inner.sessions.is_empty() || check_size != 0 || check_count != inner.count {
            return false;
        }

        inner.closed = true;
        self.closed_flag.store(true, Ordering::Release);
        inner.sessions.clear();
        true
    }

    /// 关闭管理器及所有会话。
    pub async fn close(&self) {
        let mut inner = self.inner.write().await;

        if inner.closed {
            return;
        }

        inner.closed = true;
        self.closed_flag.store(true, Ordering::Release);

        // 关闭所有会话
        for session in inner.sessions.values() {
            session.close().await;
        }

        inner.sessions.clear();
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("count", &self.count.load(Ordering::Acquire))
            .field("closed", &self.is_closed())
            .finish()
    }
}

// ========== XUDPManager ==========

/// XUDP 管理器。
///
/// 对应 Go 版本的 `XUDPManager` 全局变量，管理所有 XUDP 会话扩展。
pub struct XUDPManager {
    /// 条目映射表。
    entries: Arc<Mutex<HashMap<[u8; 8], XUDP>>>,
    /// 清理任务句柄。
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl XUDPManager {
    /// 创建新的 XUDP 管理器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            cleanup_handle: None,
        }
    }

    /// 启动清理任务。
    ///
    /// 每 60 秒清理一次过期的 XUDP 条目。
    pub fn start_cleanup(&mut self) {
        let entries = Arc::clone(&self.entries);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut entries_guard = entries.lock().await;
                let expired: Vec<[u8; 8]> = entries_guard
                    .iter()
                    .filter(|(_, x)| x.status == XudpStatus::Expiring && now >= x.expire)
                    .map(|(id, _)| {
                        debug!("XUDP del: {:?}", id);
                        *id
                    })
                    .collect();
                for id in expired {
                    if let Some(xudp) = entries_guard.remove(&id) {
                        tokio::spawn(async move {
                            xudp.interrupt().await;
                        });
                    }
                }
            }
        });
        self.cleanup_handle = Some(handle);
    }

    /// 注册 XUDP 条目。
    pub async fn register(&self, xudp: XUDP) {
        let mut entries = self.entries.lock().await;
        entries.insert(xudp.global_id, xudp);
    }

    /// 注销 XUDP 条目。
    pub async fn unregister(&self, global_id: &[u8; 8]) {
        let mut entries = self.entries.lock().await;
        entries.remove(global_id);
    }

    /// 获取 XUDP 条目。
    pub async fn get(&self, global_id: &[u8; 8]) -> Option<XUDP> {
        let entries = self.entries.lock().await;
        entries.get(global_id).cloned()
    }

    /// 手动清理过期条目。
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let expired: Vec<[u8; 8]> = entries
            .iter()
            .filter(|(_, x)| x.status == XudpStatus::Expiring && now >= x.expire)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            entries.remove(&id);
        }
    }

    /// 获取条目数量。
    pub async fn len(&self) -> usize {
        let entries = self.entries.lock().await;
        entries.len()
    }

    /// 检查是否为空。
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

impl Default for XUDPManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XUDPManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

impl std::fmt::Debug for XUDPManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XUDPManager")
            .field("entries", &"<locked>")
            .finish()
    }
}
