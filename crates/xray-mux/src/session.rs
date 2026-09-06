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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// 默认会话空闲超时时间（300 秒）。
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

use tokio::sync::{watch, Mutex, RwLock};
use tracing::debug;
use xray_buf::reader::BufferedReader;
use xray_buf::writer::BufferedWriter;

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

// ========== SessionManager 共享状态 ==========

/// 会话管理器内部状态（RwLock 保护）。
struct SessionManagerInner {
    /// 会话映射表。
    sessions: HashMap<u16, Arc<Session>>,
    /// 计数器（已分配的会话总数，包括已关闭的）。
    count: u16,
    /// 是否已关闭。
    closed: bool,
}

/// 会话管理器共享状态。
///
/// 将 SessionManager 的核心状态提取为共享结构，
/// 使 Session 可以持有弱引用并在关闭时回调 parent。
pub(crate) struct SessionManagerShared {
    /// 内部状态（RwLock 保护）。
    inner: RwLock<SessionManagerInner>,
    /// 计数器（原子操作，用于快速读取）。
    count: AtomicU16,
    /// 关闭标志。
    closed_flag: AtomicBool,
}

// ========== 弱引用类型别名 ==========

type WeakSession = Weak<Session>;

// ========== Session ==========

/// Mux 会话。
///
/// 对应 Go 版本 `Session`，表示 Mux 连接中的一个客户端连接。
///
/// # 生命周期
///
/// 1. 由 `SessionManager::allocate` 创建
/// 2. 可通过 `set_input`/`set_output` 绑定 I/O
/// 3. 关闭时触发 `done` 信号，自动从管理器移除
/// 4. 若有 XUDP 扩展，关闭后进入 Expiring 状态等待清理
pub struct Session {
    /// 会话 ID。
    id: u16,
    /// 传输类型。
    transfer_type: TransferType,
    /// 关闭标志（原子操作，用于无锁快速检查）。
    closed_flag: Arc<AtomicBool>,
    /// 关闭信号发送端（发送 true 表示已关闭）。
    done_tx: watch::Sender<bool>,
    /// 关闭信号接收端（可克隆分发给等待者）。
    done_rx: watch::Receiver<bool>,
    /// 输入读取器（BufferedReader 支持中断）。
    input: Mutex<Option<BufferedReader>>,
    /// 输出写入器（BufferedWriter 支持刷新/关闭）。
    output: Mutex<Option<BufferedWriter>>,
    /// 父管理器的弱引用（关闭时回调移除）。
    parent: Weak<SessionManagerShared>,
    /// XUDP 扩展（可选）。
    xudp: Mutex<Option<XUDP>>,
    /// 上行字节数（客户端→服务端方向）。
    uplink_bytes: AtomicU64,
    /// 下行字节数（服务端→客户端方向）。
    downlink_bytes: AtomicU64,
    /// 最后活跃时间（收到数据或发送数据时更新）。
    last_active: Mutex<Instant>,
}

impl Session {
    /// 创建新会话。
    ///
    /// 对应 Go 版本 `Session` 的初始化。
    /// 通过 `SessionManager::allocate` 调用，不应直接构造。
    pub(crate) fn new(id: u16, transfer_type: TransferType) -> Self {
        let (done_tx, done_rx) = watch::channel(false);
        Self {
            id,
            transfer_type,
            closed_flag: Arc::new(AtomicBool::new(false)),
            done_tx,
            done_rx,
            input: Mutex::new(None),
            output: Mutex::new(None),
            parent: Weak::new(),
            xudp: Mutex::new(None),
            uplink_bytes: AtomicU64::new(0),
            downlink_bytes: AtomicU64::new(0),
            last_active: Mutex::new(Instant::now()),
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

    /// 获取关闭标志的 Arc（用于外部等待）。
    #[must_use]
    pub fn closed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed_flag)
    }

    /// 获取 done 信号接收端的克隆（用于等待关闭）。
    ///
    /// 对应 Go 版本通过 `done.Wait()` 等待会话关闭。
    pub fn done_receiver(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }

    /// 设置父管理器弱引用。
    pub(crate) fn set_parent(&mut self, parent: Weak<SessionManagerShared>) {
        self.parent = parent;
    }

    /// 设置输入读取器。
    ///
    /// 对应 Go 版本 `Session.input` 的赋值。
    pub async fn set_input(&self, reader: BufferedReader) {
        let mut guard = self.input.lock().await;
        *guard = Some(reader);
    }

    /// 设置输出写入器。
    ///
    /// 对应 Go 版本 `Session.output` 的赋值。
    pub async fn set_output(&self, writer: BufferedWriter) {
        let mut guard = self.output.lock().await;
        *guard = Some(writer);
    }

    /// 获取输入读取器的互斥锁守护。
    ///
    /// 用于需要直接操作 BufferedReader 的场景（如 read_multi_buffer）。
    pub async fn input(&self) -> tokio::sync::MutexGuard<'_, Option<BufferedReader>> {
        self.input.lock().await
    }

    /// 获取输出写入器的互斥锁守护。
    ///
    /// 用于需要直接操作 BufferedWriter 的场景（如 write_multi_buffer）。
    pub async fn output(&self) -> tokio::sync::MutexGuard<'_, Option<BufferedWriter>> {
        self.output.lock().await
    }

    /// 关闭会话。
    ///
    /// 对应 Go 版本 `Session.Close(locked bool)`。
    ///
    /// # 逻辑
    ///
    /// 1. 设置关闭标志，发送 done 信号
    /// 2. 若无 XUDP：中断 input，关闭 output
    /// 3. 若有 XUDP 且状态为 Active：转为 Expiring，设置 60 秒过期
    /// 4. 从父管理器移除自身
    ///
    /// 返回 `true` 表示本次调用实际关闭了会话，`false` 表示会话已关闭。
    pub async fn close(&self) -> bool {
        if self.closed_flag.swap(true, Ordering::AcqRel) {
            return false;
        }

        // 发送 done 信号
        let _ = self.done_tx.send(true);

        let mut xudp_guard = self.xudp.lock().await;

        if xudp_guard.is_none() {
            // 无 XUDP：中断输入，关闭输出
            drop(xudp_guard);

            if let Some(ref mut reader) = *self.input.lock().await {
                reader.interrupt();
                reader.close();
            }
            if let Some(ref mut writer) = *self.output.lock().await {
                let _ = writer.flush().await;
            }
        } else {
            // 有 XUDP：Active 状态转为 Expiring，设置 60 秒过期
            if let Some(ref mut xudp) = *xudp_guard {
                if xudp.status == XudpStatus::Active {
                    xudp.status = XudpStatus::Expiring;
                    xudp.expire = Instant::now() + Duration::from_secs(60);
                    debug!("XUDP put: {:?}", xudp.global_id);
                }
            }
        }

        // 从父管理器移除
        if let Some(shared) = self.parent.upgrade() {
            let mut inner = shared.inner.write().await;
            if !inner.closed {
                inner.sessions.remove(&self.id);
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

    // ========== 流量统计 ==========

    /// 增加上行字节数。
    pub fn add_uplink_bytes(&self, n: u64) {
        self.uplink_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// 增加下行字节数。
    pub fn add_downlink_bytes(&self, n: u64) {
        self.downlink_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// 获取上行字节数。
    #[must_use]
    pub fn uplink_bytes(&self) -> u64 {
        self.uplink_bytes.load(Ordering::Relaxed)
    }

    /// 获取下行字节数。
    #[must_use]
    pub fn downlink_bytes(&self) -> u64 {
        self.downlink_bytes.load(Ordering::Relaxed)
    }

    // ========== 空闲超时 ==========

    /// 更新最后活跃时间为当前时刻。
    pub async fn touch_active(&self) {
        let mut guard = self.last_active.lock().await;
        *guard = Instant::now();
    }

    /// 检查会话是否已空闲超时。
    ///
    /// 返回 `true` 表示自上次活跃以来已超过 `timeout` 时长。
    pub async fn is_idle_timeout(&self, timeout: Duration) -> bool {
        let guard = self.last_active.lock().await;
        guard.elapsed() > timeout
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

    /// 中断关联会话的输入，关闭输出。
    ///
    /// 对应 Go 版本 `XUDP.Interrupt()`，调用 mux.input.Interrupt()
    /// 和 mux.output.Close()。
    pub async fn interrupt(&self) {
        if let Some(ref weak) = self.mux {
            if let Some(session) = weak.upgrade() {
                // 中断输入
                if let Some(ref mut reader) = *session.input.lock().await {
                    reader.interrupt();
                }
                // 关闭输出
                if let Some(ref mut writer) = *session.output.lock().await {
                    let _ = writer.flush().await;
                }
            }
        }
    }
}

// ========== SessionManager ==========

/// 会话管理器。
///
/// 对应 Go 版本 `SessionManager`，管理所有 Mux 会话的生命周期。
///
/// # 线程安全
///
/// - `shared.inner` 通过 RwLock 保护会话映射表
/// - `shared.count` 和 `shared.closed_flag` 使用原子操作实现无锁快速读取
/// - Session 关闭时通过弱引用回调自动从管理器移除
pub struct SessionManager {
    /// 共享状态（Arc 允许 Session 持有弱引用）。
    shared: Arc<SessionManagerShared>,
}

impl SessionManager {
    /// 创建新的会话管理器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(SessionManagerShared {
                inner: RwLock::new(SessionManagerInner {
                    sessions: HashMap::with_capacity(16),
                    count: 0,
                    closed: false,
                }),
                count: AtomicU16::new(0),
                closed_flag: AtomicBool::new(false),
            }),
        }
    }

    /// 检查管理器是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed_flag.load(Ordering::Acquire)
    }

    /// 获取当前活跃会话数。
    pub async fn size(&self) -> usize {
        let inner = self.shared.inner.read().await;
        inner.sessions.len()
    }

    /// 获取已分配的会话总数（包括已关闭的）。
    #[must_use]
    pub fn count(&self) -> u16 {
        self.shared.count.load(Ordering::Acquire)
    }

    /// 分配新会话。
    ///
    /// 对应 Go 版本 `SessionManager.Allocate(ClientStrategy)`。
    ///
    /// 根据 `strategy` 的限制条件分配新会话：
    /// - 若管理器已关闭，返回 `None`
    /// - 若当前并发数超过 `max_concurrency`，返回 `None`
    /// - 若累计连接数超过 `max_connection`，返回 `None`
    ///
    /// 新会话自动添加到管理器，ID 递增分配。
    pub async fn allocate(&self, strategy: &ClientStrategy) -> Option<Arc<Session>> {
        let mut inner = self.shared.inner.write().await;

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

        inner.count = inner.count.saturating_add(1);
        self.shared.count.store(inner.count, Ordering::Release);

        let mut session = Session::new(inner.count, TransferType::Stream);
        session.set_parent(Arc::downgrade(&self.shared));
        let session = Arc::new(session);
        inner.sessions.insert(session.id, Arc::clone(&session));
        Some(session)
    }

    /// 添加已存在的会话并设置父管理器弱引用。
    ///
    /// 对应 Go 版本 `SessionManager.Add(*Session)`。
    ///
    /// 接收未共享的 `Session`，Arc 包装在本方法内完成：父引用必须在首次
    /// clone 前设置——若入参已是共享 Arc，`Arc::get_mut` 恒失败导致 parent
    /// 缺失，会话关闭时无法从管理器摘除（条目泄漏，size 永不归零，
    /// monitor 空闲判定 `CloseIfNoSessionAndIdle` 永不满足 → worker 不回收）。
    ///
    /// 返回 `Some(Arc<Session>)` 表示添加成功（新会话的唯一强引用交还调用方），
    /// `None` 表示管理器已关闭。

    pub async fn add(&self, mut session: Session) -> Option<Arc<Session>> {
        let mut inner = self.shared.inner.write().await;

        if inner.closed {
            return None;
        }

        inner.count = inner.count.saturating_add(1);
        self.shared.count.store(inner.count, Ordering::Release);

        session.set_parent(Arc::downgrade(&self.shared));
        let session = Arc::new(session);
        inner.sessions.insert(session.id(), Arc::clone(&session));
        Some(session)
    }

    /// 移除会话。
    ///
    /// 对应 Go 版本 `SessionManager.Remove(locked bool, id uint16)`。
    ///
    /// 若管理器已关闭则忽略。
    pub async fn remove(&self, id: u16) {
        let mut inner = self.shared.inner.write().await;
        if !inner.closed {
            inner.sessions.remove(&id);
        }
    }

    /// 获取会话。
    ///
    /// 对应 Go 版本 `SessionManager.Get(id uint16)`。
    ///
    /// 若管理器已关闭或会话不存在，返回 `None`。
    pub async fn get(&self, id: u16) -> Option<Arc<Session>> {
        let inner = self.shared.inner.read().await;
        if inner.closed {
            return None;
        }
        inner.sessions.get(&id).cloned()
    }

    /// 检查是否可以关闭（无会话且空闲）。
    ///
    /// 对应 Go 版本 `SessionManager.CloseIfNoSessionAndIdle`。
    ///
    /// 当满足以下所有条件时关闭管理器：
    /// - 无活跃会话
    /// - `check_size` 为 0（外部确认无待处理数据）
    /// - `check_count` 等于内部 count（外部确认无待处理连接）
    pub async fn close_if_no_session_and_idle(
        &self,
        check_size: usize,
        check_count: u16,
    ) -> bool {
        let mut inner = self.shared.inner.write().await;

        if inner.closed {
            return true;
        }

        if !inner.sessions.is_empty() || check_size != 0 || check_count != inner.count {
            return false;
        }

        inner.closed = true;
        self.shared.closed_flag.store(true, Ordering::Release);
        inner.sessions.clear();
        true
    }

    /// 关闭管理器及所有会话。
    pub async fn close(&self) {
        let sessions: Vec<Arc<Session>> = {
            let mut inner = self.shared.inner.write().await;

            if inner.closed {
                return;
            }

            inner.closed = true;
            self.shared.closed_flag.store(true, Ordering::Release);

            inner.sessions.values().cloned().collect()
        };

        // 在锁外关闭所有会话（避免与 Session::close 的 parent.remove 死锁）
        for session in sessions {
            session.close().await;
        }

        // 清理映射表
        let mut inner = self.shared.inner.write().await;
        inner.sessions.clear();
    }

    /// 获取所有活跃会话的克隆列表。
    ///
    /// 用于 KeepAlive 广播和空闲超时检查。
    pub async fn active_sessions(&self) -> Vec<Arc<Session>> {
        let inner = self.shared.inner.read().await;
        inner.sessions.values().cloned().collect()
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
            .field("count", &self.shared.count.load(Ordering::Acquire))
            .field("closed", &self.is_closed())
            .finish()
    }
}

// ========== XUDPManager ==========

/// XUDP 管理器。
///
/// 对应 Go 版本的 `XUDPManager` 全局变量，管理所有 XUDP 会话扩展。
///
/// # 并发模型
/// 内部 `entries` 用 `parking_lot::RwLock` 替代 `tokio::sync::Mutex`：
/// 实际数据访问（`get`/`len`/`register`/`unregister`/`cleanup`）均为非阻塞
/// 同步操作，无 `.await` 持锁点；在 multi_thread runtime 下亦不会因 `await`
/// 切换线程而出现锁迁移或阻塞清理任务。对应 Go `XUDPManager` 仅 `sync.Mutex`
/// 保护 map 的语义。
pub struct XUDPManager {
    /// 条目映射表。
    entries: Arc<parking_lot::RwLock<HashMap<[u8; 8], XUDP>>>,
    /// 清理任务句柄。
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl XUDPManager {
    /// 创建新的 XUDP 管理器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(parking_lot::RwLock::new(HashMap::new())),
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
                // 写锁仅在清理窗口内持锁；xudp.interrupt() 在 spawn 中独立运行，
                // 不再在持锁状态下跨 .await，避免 multi_thread runtime 下的锁迁移。
                let expired: Vec<(XUDP, [u8; 8])> = {
                    let mut guard = entries.write();
                    let mut out = Vec::new();
                    let ids: Vec<[u8; 8]> = guard
                        .iter()
                        .filter(|(_, x)| x.status == XudpStatus::Expiring && now >= x.expire)
                        .map(|(id, _)| {
                            debug!("XUDP del: {:?}", id);
                            *id
                        })
                        .collect();
                    for id in ids {
                        if let Some(x) = guard.remove(&id) {
                            out.push((x, id));
                        }
                    }
                    out
                };
                for (xudp, _id) in expired {
                    tokio::spawn(async move {
                        xudp.interrupt().await;
                    });
                }
            }
        });
        self.cleanup_handle = Some(handle);
    }

    /// 注册 XUDP 条目。
    pub async fn register(&self, xudp: XUDP) {
        // 同步锁，无 .await 持锁点；方法签名仍 async 以兼容调用方。
        self.entries.write().insert(xudp.global_id, xudp);
    }

    /// 注销 XUDP 条目。
    pub async fn unregister(&self, global_id: &[u8; 8]) {
        self.entries.write().remove(global_id);
    }

    /// 获取 XUDP 条目。
    pub async fn get(&self, global_id: &[u8; 8]) -> Option<XUDP> {
        self.entries.read().get(global_id).cloned()
    }

    /// 手动清理过期条目。
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut guard = self.entries.write();
        let expired: Vec<[u8; 8]> = guard
            .iter()
            .filter(|(_, x)| x.status == XudpStatus::Expiring && now >= x.expire)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            guard.remove(&id);
        }
    }

    /// 获取条目数量。
    pub async fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// 检查是否为空。
    pub async fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use xray_buf::io::{new_reader, new_writer};

    // ========== TransferType 测试 ==========

    #[test]
    fn test_transfer_type_from_byte() {
        assert_eq!(TransferType::from_byte(0), Some(TransferType::Stream));
        assert_eq!(TransferType::from_byte(1), Some(TransferType::Packet));
        assert_eq!(TransferType::from_byte(2), None);
    }

    #[test]
    fn test_transfer_type_to_byte() {
        assert_eq!(TransferType::Stream.to_byte(), 0);
        assert_eq!(TransferType::Packet.to_byte(), 1);
    }

    // ========== Session 基础测试 ==========

    #[tokio::test]
    async fn test_session_new_and_close() {
        let session = Session::new(1, TransferType::Stream);
        assert_eq!(session.id(), 1);
        assert_eq!(session.transfer_type(), TransferType::Stream);
        assert!(!session.is_closed());

        let closed = session.close().await;
        assert!(closed);
        assert!(session.is_closed());

        // 重复关闭返回 false
        let closed_again = session.close().await;
        assert!(!closed_again);
    }

    #[tokio::test]
    async fn test_session_done_signal() {
        let session = Session::new(2, TransferType::Packet);
        let rx = session.done_receiver();

        // 初始值为 false
        assert_eq!(*rx.borrow(), false);

        // 关闭后发送 done 信号
        session.close().await;
        assert_eq!(*rx.borrow(), true);
    }

    #[tokio::test]
    async fn test_session_input_output() {
        let session = Session::new(3, TransferType::Stream);

        // 初始无 input/output
        let input_guard = session.input().await;
        assert!(input_guard.is_none());
        drop(input_guard);

        let output_guard = session.output().await;
        assert!(output_guard.is_none());
        drop(output_guard);

        // 设置 input/output
        let cursor = Cursor::new(b"hello".to_vec());
        let reader = BufferedReader::new(new_reader(cursor));
        session.set_input(reader).await;

        let buffer: Vec<u8> = Vec::new();
        let writer = BufferedWriter::new(Box::new(new_writer(buffer)));
        session.set_output(writer).await;

        // 确认已设置
        let input_guard = session.input().await;
        assert!(input_guard.is_some());
        drop(input_guard);

        let output_guard = session.output().await;
        assert!(output_guard.is_some());
    }

    #[tokio::test]
    async fn test_session_close_interrupts_input() {
        let session = Session::new(4, TransferType::Stream);

        let cursor = Cursor::new(b"test data".to_vec());
        let reader = BufferedReader::new(new_reader(cursor));
        session.set_input(reader).await;

        // 关闭后输入应被中断
        session.close().await;

        let input_guard = session.input().await;
        if let Some(ref reader) = *input_guard {
            assert!(reader.is_interrupted());
        }
    }

    // ========== SessionManager 测试 ==========

    #[tokio::test]
    async fn test_session_manager_new() {
        let manager = SessionManager::new();
        assert!(!manager.is_closed());
        assert_eq!(manager.count(), 0);
        assert_eq!(manager.size().await, 0);
    }

    #[tokio::test]
    async fn test_session_manager_allocate() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        let session = manager.allocate(&strategy).await;
        assert!(session.is_some());

        let s = session.unwrap();
        assert_eq!(s.id(), 1);
        assert_eq!(manager.count(), 1);
        assert_eq!(manager.size().await, 1);

        // 分配第二个
        let session2 = manager.allocate(&strategy).await;
        assert!(session2.is_some());
        assert_eq!(session2.unwrap().id(), 2);
        assert_eq!(manager.count(), 2);
        assert_eq!(manager.size().await, 2);
    }

    #[tokio::test]
    async fn test_session_manager_allocate_max_concurrency() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy {
            max_concurrency: 2,
            max_connection: 0,
        };

        let s1 = manager.allocate(&strategy).await;
        assert!(s1.is_some());
        let s2 = manager.allocate(&strategy).await;
        assert!(s2.is_some());
        let s3 = manager.allocate(&strategy).await;
        assert!(s3.is_none()); // 超过 max_concurrency
    }

    #[tokio::test]
    async fn test_session_manager_allocate_max_connection() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy {
            max_concurrency: 0,
            max_connection: 3,
        };

        for _ in 0..3 {
            let s = manager.allocate(&strategy).await;
            assert!(s.is_some());
        }
        // 超过 max_connection
        let s4 = manager.allocate(&strategy).await;
        assert!(s4.is_none());
    }

    #[tokio::test]
    async fn test_session_manager_get_and_remove() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        let session = manager.allocate(&strategy).await.unwrap();
        let id = session.id();

        // Get
        let fetched = manager.get(id).await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id(), id);

        // 获取不存在 ID
        let missing = manager.get(999).await;
        assert!(missing.is_none());

        // Remove
        manager.remove(id).await;
        assert_eq!(manager.size().await, 0);
        let after_remove = manager.get(id).await;
        assert!(after_remove.is_none());
    }

    #[tokio::test]
    async fn test_session_manager_close() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        let s1 = manager.allocate(&strategy).await.unwrap();
        let s2 = manager.allocate(&strategy).await.unwrap();

        manager.close().await;
        assert!(manager.is_closed());
        assert_eq!(manager.size().await, 0);
        assert!(s1.is_closed());
        assert!(s2.is_closed());

        // 关闭后 allocate 返回 None
        let s3 = manager.allocate(&strategy).await;
        assert!(s3.is_none());
    }

    #[tokio::test]
    async fn test_session_manager_close_if_no_session_and_idle() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        // 分配然后关闭会话（触发自动移除）
        let s = manager.allocate(&strategy).await.unwrap();
        let count = manager.count();
        s.close().await;

        // 会话已从管理器移除
        assert_eq!(manager.size().await, 0);
        assert_eq!(manager.count(), count);

        // 满足空闲条件可关闭
        let result = manager
            .close_if_no_session_and_idle(0, count)
            .await;
        assert!(result);
        assert!(manager.is_closed());
    }

    #[tokio::test]
    async fn test_session_manager_close_if_no_session_not_idle() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        let _s = manager.allocate(&strategy).await.unwrap();

        // 有活跃会话，不应关闭
        let result = manager
            .close_if_no_session_and_idle(0, 0)
            .await;
        assert!(!result);
        assert!(!manager.is_closed());
    }

    // ========== XUDP 测试 ==========

    #[test]
    fn test_xudp_new() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let xudp = XUDP::new(id);
        assert_eq!(xudp.global_id, id);
        assert_eq!(xudp.status, XudpStatus::Initializing);
    }

    #[tokio::test]
    async fn test_session_xudp_expiring_on_close() {
        let session = Arc::new(Session::new(10, TransferType::Packet));
        let mut xudp = XUDP::new([0xAA; 8]);
        xudp.status = XudpStatus::Active;
        xudp.set_mux(&session);
        session.set_xudp(xudp).await;

        // 关闭时 Active → Expiring
        session.close().await;

        let xudp = session.xudp().await;
        assert!(xudp.is_some());
        let xudp = xudp.unwrap();
        assert_eq!(xudp.status, XudpStatus::Expiring);
    }

    // ========== XUDPManager 测试 ==========

    #[tokio::test]
    async fn test_xudp_manager_register_and_get() {
        let manager = XUDPManager::new();
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let xudp = XUDP::new(id);
        manager.register(xudp).await;

        assert_eq!(manager.len().await, 1);
        assert!(!manager.is_empty().await);

        let fetched = manager.get(&id).await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().global_id, id);
    }

    #[tokio::test]
    async fn test_xudp_manager_unregister() {
        let manager = XUDPManager::new();
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let xudp = XUDP::new(id);
        manager.register(xudp).await;
        manager.unregister(&id).await;

        assert_eq!(manager.len().await, 0);
        assert!(manager.is_empty().await);
    }

    #[tokio::test]
    async fn test_xudp_manager_cleanup_expired() {
        let manager = XUDPManager::new();

        // 注册一个已过期的 Expiring 条目
        let mut xudp1 = XUDP::new([1u8; 8]);
        xudp1.status = XudpStatus::Expiring;
        xudp1.expire = Instant::now() - Duration::from_secs(1); // 已过期
        manager.register(xudp1).await;

        // 注册一个未过期的 Expiring 条目
        let mut xudp2 = XUDP::new([2u8; 8]);
        xudp2.status = XudpStatus::Expiring;
        xudp2.expire = Instant::now() + Duration::from_secs(60); // 未过期
        manager.register(xudp2).await;

        // 注册一个 Active 条目（不会被清理）
        let mut xudp3 = XUDP::new([3u8; 8]);
        xudp3.status = XudpStatus::Active;
        manager.register(xudp3).await;

        manager.cleanup().await;

        // 只有已过期的 Expiring 条目被清理
        assert_eq!(manager.len().await, 2);
        assert!(manager.get(&[1u8; 8]).await.is_none());
        assert!(manager.get(&[2u8; 8]).await.is_some());
        assert!(manager.get(&[3u8; 8]).await.is_some());
    }

    // ========== Session.Close 自动从管理器移除 ==========

    #[tokio::test]
    async fn test_session_close_removes_from_manager() {
        let manager = SessionManager::new();
        let strategy = ClientStrategy::default();

        let session = manager.allocate(&strategy).await.unwrap();
        assert_eq!(manager.size().await, 1);

        // 关闭会话时自动从管理器移除
        session.close().await;
        assert_eq!(manager.size().await, 0);
        assert!(manager.get(session.id()).await.is_none());
    }

    /// add() 路径的 parent 接线回归：经 add() 入册的会话关闭后必须从管理器
    /// 摘除（旧实现入参为共享 Arc，`Arc::get_mut` 恒失败 → parent 缺失 →
    /// 条目泄漏，size 永不归零）。
    #[tokio::test]
    async fn test_session_manager_add_close_removes_entry() {
        let manager = SessionManager::new();
        let session = manager
            .add(Session::new(7, TransferType::Stream))
            .await
            .expect("add on open manager");
        assert_eq!(manager.size().await, 1);

        session.close().await;
        assert_eq!(manager.size().await, 0, "entry must be removed on close");
        assert!(manager.get(7).await.is_none());

        // 已关闭的管理器 add 返回 None
        manager.close().await;
        assert!(
            manager
                .add(Session::new(8, TransferType::Stream))
                .await
                .is_none()
        );
    }

    // ========== Debug 格式化测试 ==========

    #[test]
    fn test_session_debug_format() {
        let session = Session::new(42, TransferType::Stream);
        let debug_str = format!("{session:?}");
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("Stream"));
        assert!(debug_str.contains("closed: false"));
    }

    #[test]
    fn test_session_manager_debug_format() {
        let manager = SessionManager::new();
        let debug_str = format!("{manager:?}");
        assert!(debug_str.contains("count: 0"));
        assert!(debug_str.contains("closed: false"));
    }

    #[test]
    fn test_xudp_status_values() {
        assert_eq!(XudpStatus::Initializing as u8, 0);
        assert_eq!(XudpStatus::Active as u8, 1);
        assert_eq!(XudpStatus::Expiring as u8, 2);
    }

    #[test]
    fn test_session_error_display() {
        assert_eq!(
            format!("{}", SessionError::SessionClosed),
            "session is closed"
        );
        assert_eq!(
            format!("{}", SessionError::ManagerClosed),
            "session manager is closed"
        );
        assert_eq!(
            format!("{}", SessionError::SessionNotFound(42)),
            "session not found: 42"
        );
    }

    // ========== 流量统计测试 ==========

    #[test]
    fn test_session_traffic_stats_initial() {
        let session = Session::new(1, TransferType::Stream);
        assert_eq!(session.uplink_bytes(), 0);
        assert_eq!(session.downlink_bytes(), 0);
    }

    #[test]
    fn test_session_traffic_stats_increment() {
        let session = Session::new(1, TransferType::Stream);
        session.add_uplink_bytes(100);
        session.add_downlink_bytes(200);
        assert_eq!(session.uplink_bytes(), 100);
        assert_eq!(session.downlink_bytes(), 200);
        session.add_uplink_bytes(50);
        session.add_downlink_bytes(150);
        assert_eq!(session.uplink_bytes(), 150);
        assert_eq!(session.downlink_bytes(), 350);
    }

    // ========== 空闲超时测试 ==========

    #[tokio::test]
    async fn test_session_not_idle_initially() {
        let session = Session::new(1, TransferType::Stream);
        assert!(!session.is_idle_timeout(SESSION_IDLE_TIMEOUT).await);
    }

    #[tokio::test]
    async fn test_session_touch_active_updates_time() {
        let session = Session::new(1, TransferType::Stream);
        // 先等一小段时间
        tokio::time::sleep(Duration::from_millis(10)).await;
        // touch_active 应重置活跃时间
        session.touch_active().await;
        assert!(!session.is_idle_timeout(Duration::from_millis(1)).await);
    }

    #[tokio::test]
    async fn test_session_idle_timeout_constant() {
        assert_eq!(SESSION_IDLE_TIMEOUT, Duration::from_secs(300));
    }

    // ========== multi_thread runtime 锁迁移回归 ==========

    /// 模拟 vmess_over_mux_tcp_e2e 风格的并发场景：多 worker 线程同时
    /// register/get/unregister。`parking_lot::RwLock` 的 .read()/.write()
    /// 为同步短持锁，避免 multi_thread 下 `tokio::sync::Mutex` 的锁迁移。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_xudp_manager_concurrent_multi_thread_no_deadlock() {
        let manager = Arc::new(XUDPManager::new());
        let mut handles = Vec::new();
        for w in 0u8..8 {
            let m = Arc::clone(&manager);
            handles.push(tokio::spawn(async move {
                for i in 0u8..50 {
                    let id = [w, i, 0, 0, 0, 0, 0, 0];
                    m.register(XUDP::new(id)).await;
                    let _ = m.get(&id).await;
                    m.unregister(&id).await;
                }
            }));
        }
        for h in handles {
            h.await.expect("worker join");
        }
        assert_eq!(manager.len().await, 0);
    }
}
