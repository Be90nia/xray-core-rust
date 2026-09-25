//! Statistics interfaces.
//!
//! 对应 Go `features/stats/stats.go`：
//! - [`Counter`] / [`OnlineMap`] / [`Channel`] 三大接口
//! - [`Manager`] 注册表接口（含 `*OnlineMap*` / `*Channel*` 12 个方法）
//! - [`NoopManager`] 空实现
//! - [`get_or_register_counter`] / [`get_or_register_online_map`] / [`get_or_register_channel`]
//!   工具函数
//! - [`subscribe_runnable_channel`] / [`unsubscribe_closable_channel`] 工具函数
//!
//! ## 与 Go 的语义对齐
//!
//! - `Counter::add` 返回**旧值**（Go `atomic.AddInt64` 返回新值，但 `Counter.Add` interface
//!   注释明确 "returns the previous value"）
//! - `Counter::set` 返回**旧值**（Go `atomic.SwapInt64`）
//! - `Manager::register_*` 在重名时返回 [`ManagerError::AlreadyRegistered`]， 对齐 Go 的
//!   `errors.New("... already registered.")`
//!
//! ## 异步
//!
//! 全 sync API：`Channel::publish` 内部 spawn 异步 task 转发消息，
//! `Manager` 用 `RwLock<HashMap>` 互斥。这与 Go 模型等价
//! （Go 的 sync.RWMutex + buffered chan + goroutine broadcast）。

use std::sync::Arc;

use thiserror::Error;

use crate::Feature;

/// Feature type identifier for Stats.
///
/// 对应 Go `stats.ManagerType()` 返回的接口类型指针。
pub const FEATURE_STATS: &str = "stats";

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

/// Statistics counter interface.
///
/// 对应 Go `features/stats.Counter`。原子操作，线程安全。
/// - [`value`](Counter::value) → 当前值
/// - [`set`](Counter::set) → 设新值，返回旧值
/// - [`add`](Counter::add) → 加 delta，返回旧值
pub trait Counter: Send + Sync {
    /// 当前值。对应 Go `Counter.Value() int64`。
    fn value(&self) -> i64;

    /// 设新值返回旧值。对应 Go `Counter.Set(int64) int64`（用 `atomic.SwapInt64`）。
    fn set(&self, value: i64) -> i64;

    /// 加 delta 返回旧值。对应 Go `Counter.Add(int64) int64`（注释明确 "previous value"）。
    fn add(&self, delta: i64) -> i64;
}

// ---------------------------------------------------------------------------
// OnlineMap
// ---------------------------------------------------------------------------

/// 在线 IP 引用计数映射接口。
///
/// 对应 Go `features/stats.OnlineMap`：
/// - `add_ip` 增加引用计数，新 IP 时插入并 `count += 1`
/// - `remove_ip` 减少引用计数，归零时删除并 `count -= 1`
/// - `for_each` 在锁内回调，禁止回调内再调用 `add_ip` / `remove_ip`（死锁）
pub trait OnlineMap: Send + Sync {
    /// 唯一 IP 数。对应 Go `OnlineMap.Count() int`。
    fn count(&self) -> usize;

    /// 增加引用计数。对应 Go `OnlineMap.AddIP(string)`。
    fn add_ip(&self, ip: &str);

    /// 减少引用计数。对应 Go `OnlineMap.RemoveIP(string)`。
    fn remove_ip(&self, ip: &str);

    /// 遍历 `(ip, last_seen Unix 秒)`。回调返回 `false` 停止。
    /// 对应 Go `OnlineMap.ForEach(func(string, int64) bool)`。
    ///
    /// **死锁警告**：回调内禁止调用同一 `OnlineMap` 的 `add_ip` / `remove_ip`。
    fn for_each(&self, f: &mut dyn FnMut(&str, i64) -> bool);
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// 通道消息类型（type-erased）。
///
/// Go 用 `interface{}`，Rust 等价为 `Arc<dyn Any + Send + Sync>`。
/// `Arc` 让多订阅者广播时 clone 廉价。
pub type ChannelMessage = Arc<dyn std::any::Any + Send + Sync>;

/// 订阅句柄。对应 Go `chan interface{}` 的拥有端。
///
/// 由 [`Channel::subscribe`] 创建，`Drop` 时自动从订阅列表移除
/// （等价于 Go `UnsubscribeClosableChannel` 主动调用）。
pub struct ChannelSubscriber {
    /// 内部 mpsc Receiver。
    pub(crate) receiver: tokio::sync::mpsc::Receiver<ChannelMessage>,
    /// 订阅 ID（由 Channel 分配，用于 unsubscribe 查找）。
    pub(crate) id: u64,
}

impl ChannelSubscriber {
    /// 构造新订阅句柄（由 Channel 实现内部调用）。
    ///
    /// 调用方通常通过 [`Channel::subscribe`] 获取，而非直接构造。
    #[must_use]
    pub fn new(receiver: tokio::sync::mpsc::Receiver<ChannelMessage>, id: u64) -> Self {
        Self { receiver, id }
    }

    /// 接收下一条消息。对应 Go `<-subscriber`。
    ///
    /// 返回 `None` 表示通道关闭或被 drop。
    pub async fn recv(&mut self) -> Option<ChannelMessage> {
        self.receiver.recv().await
    }

    /// 尝试 downcast 接收并返回 `T: Clone + Send + Sync + 'static`。
    pub async fn recv_as<T>(&mut self) -> Option<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        let msg = self.recv().await?;
        msg.downcast_ref::<T>().cloned()
    }

    /// 订阅 ID（调试 / unsubscribe 用）。
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// 统计通道接口。
///
/// 对应 Go `features/stats.Channel`：发布订阅模型。
/// - [`publish`](Channel::publish) 同步入队，内部异步 task 转发到所有订阅者
/// - [`subscribe`](Channel::subscribe) / [`unsubscribe`](Channel::unsubscribe) 管理订阅
/// - [`start`](Channel::start) / [`close`](Channel::close) 控制 broadcast task 生命周期
pub trait Channel: Send + Sync {
    /// 发布消息。对应 Go `Channel.Publish(context.Context, interface{})`。
    ///
    /// 同步返回：消息入队即返回，实际广播由后台 task 完成。
    fn publish(&self, msg: ChannelMessage);

    /// 当前订阅者数量。对应 Go `len(c.Subscribers())`。
    fn subscribers(&self) -> usize;

    /// 订阅。对应 Go `Channel.Subscribe() (chan interface{}, error)`。
    fn subscribe(&self) -> Result<ChannelSubscriber, ChannelError>;

    /// 取消订阅。对应 Go `Channel.Unsubscribe(chan interface{}) error`。
    fn unsubscribe(&self, sub: &ChannelSubscriber) -> Result<(), ChannelError>;

    /// 是否运行中。对应 Go `Channel.Running() bool`。
    fn running(&self) -> bool;

    /// 启动 broadcast task。对应 Go `Channel.Start() error`。
    fn start(&self) -> Result<(), ChannelError>;

    /// 关闭 broadcast task。对应 Go `Channel.Close() error`。
    fn close(&self) -> Result<(), ChannelError>;
}

/// Channel 操作错误。对应 Go 隐式 `errors.New("...")` 的具体化。
#[derive(Debug, Error)]
pub enum ChannelError {
    /// 订阅者数已达上限。对应 Go `"Number of subscribers has reached limit"`。
    #[error("subscribers reached limit ({limit})")]
    SubscribersLimitReached { limit: usize },

    /// 通道已关闭，操作不允许。
    #[error("channel closed")]
    Closed,

    /// 通道未启动。
    #[error("channel not started")]
    NotStarted,

    /// 给定订阅 ID 不存在。
    #[error("subscriber {0} not found")]
    SubscriberNotFound(u64),
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// 统计管理器接口。
///
/// 对应 Go `features/stats.Manager`：管理 counters / onlineMaps / channels
/// 三类资源。所有 `visit_*` 方法在锁内回调，**禁止回调内调用 `register_*` /
/// `unregister_*`（死锁）**。
pub trait Manager: Send + Sync {
    // Counter
    /// 注册新 counter。重名返回 [`ManagerError::AlreadyRegistered`]。
    fn register_counter(&self, name: &str) -> Result<Arc<dyn Counter>, ManagerError>;

    /// 注销 counter。不存在时静默返回（对齐 Go）。
    fn unregister_counter(&self, name: &str);

    /// 获取 counter。不存在返回 `None`。
    fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>>;

    /// 遍历所有 counter。回调返回 `false` 停止。
    fn visit_counters(&self, f: &mut dyn FnMut(&str, &dyn Counter) -> bool);

    // OnlineMap
    /// 注册新 OnlineMap。重名返回 [`ManagerError::AlreadyRegistered`]。
    fn register_online_map(&self, name: &str) -> Result<Arc<dyn OnlineMap>, ManagerError>;

    /// 注销 OnlineMap。不存在时静默返回。
    fn unregister_online_map(&self, name: &str);

    /// 获取 OnlineMap。不存在返回 `None`。
    fn get_online_map(&self, name: &str) -> Option<Arc<dyn OnlineMap>>;

    /// 遍历所有 OnlineMap。回调返回 `false` 停止。
    fn visit_online_maps(&self, f: &mut dyn FnMut(&str, &dyn OnlineMap) -> bool);

    // Channel
    /// 注册新 Channel。重名返回 [`ManagerError::AlreadyRegistered`]。
    fn register_channel(&self, name: &str) -> Result<Arc<dyn Channel>, ManagerError>;

    /// 注销 Channel。不存在时静默返回。
    fn unregister_channel(&self, name: &str);

    /// 获取 Channel。不存在返回 `None`。
    fn get_channel(&self, name: &str) -> Option<Arc<dyn Channel>>;

    /// 获取所有 `Count() > 0` 的 OnlineMap 名。
    /// 对应 Go `Manager.GetAllOnlineUsers() []string`。
    fn get_all_online_users(&self) -> Vec<String>;
}

/// Manager 操作错误。
#[derive(Debug, Error)]
pub enum ManagerError {
    /// 资源名已注册。对应 Go `"Counter X already registered."` 等。
    #[error("{kind} `{name}` already registered")]
    AlreadyRegistered { kind: &'static str, name: String },

    /// 操作未实现。对应 Go NoopManager 的 `errors.New("not implemented")`。
    #[error("not implemented")]
    NotImplemented,
}

// ---------------------------------------------------------------------------
// Helper free functions
// ---------------------------------------------------------------------------

/// 获取或注册 counter。对应 Go `GetOrRegisterCounter(m, name)`。
///
/// 已存在则返回现有的；否则注册新的。
pub fn get_or_register_counter(
    m: &dyn Manager,
    name: &str,
) -> Result<Arc<dyn Counter>, ManagerError> {
    if let Some(c) = m.get_counter(name) {
        return Ok(c);
    }
    m.register_counter(name)
}

/// 获取或注册 OnlineMap。对应 Go `GetOrRegisterOnlineMap(m, name)`。
pub fn get_or_register_online_map(
    m: &dyn Manager,
    name: &str,
) -> Result<Arc<dyn OnlineMap>, ManagerError> {
    if let Some(om) = m.get_online_map(name) {
        return Ok(om);
    }
    m.register_online_map(name)
}

/// 获取或注册 Channel。对应 Go `GetOrRegisterChannel(m, name)`。
pub fn get_or_register_channel(
    m: &dyn Manager,
    name: &str,
) -> Result<Arc<dyn Channel>, ManagerError> {
    if let Some(c) = m.get_channel(name) {
        return Ok(c);
    }
    m.register_channel(name)
}

/// 订阅 Runnable Channel（首个订阅者触发 `start`）。
/// 对应 Go `SubscribeRunnableChannel(c)`。
pub fn subscribe_runnable_channel(c: &dyn Channel) -> Result<ChannelSubscriber, ChannelError> {
    if c.subscribers() == 0 {
        c.start()?;
    }
    c.subscribe()
}

/// 取消订阅 Closable Channel（无订阅者时触发 `close`）。
/// 对应 Go `UnsubscribeClosableChannel(c, sub)`。
pub fn unsubscribe_closable_channel(
    c: &dyn Channel,
    sub: &ChannelSubscriber,
) -> Result<(), ChannelError> {
    c.unsubscribe(sub)?;
    if c.subscribers() == 0 {
        c.close()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NoopManager
// ---------------------------------------------------------------------------

/// Manager 空实现。对应 Go `NoopManager`。
///
/// 所有 `register_*` 返回 [`ManagerError::NotImplemented`]，
/// 所有 `unregister_*` / `get_*` 返回空，所有 `visit_*` 空遍历。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopManager;

impl Manager for NoopManager {
    fn register_counter(&self, _name: &str) -> Result<Arc<dyn Counter>, ManagerError> {
        Err(ManagerError::NotImplemented)
    }

    fn unregister_counter(&self, _name: &str) {}

    fn get_counter(&self, _name: &str) -> Option<Arc<dyn Counter>> {
        None
    }

    fn visit_counters(&self, _f: &mut dyn FnMut(&str, &dyn Counter) -> bool) {}

    fn register_online_map(&self, _name: &str) -> Result<Arc<dyn OnlineMap>, ManagerError> {
        Err(ManagerError::NotImplemented)
    }

    fn unregister_online_map(&self, _name: &str) {}

    fn get_online_map(&self, _name: &str) -> Option<Arc<dyn OnlineMap>> {
        None
    }

    fn visit_online_maps(&self, _f: &mut dyn FnMut(&str, &dyn OnlineMap) -> bool) {}

    fn register_channel(&self, _name: &str) -> Result<Arc<dyn Channel>, ManagerError> {
        Err(ManagerError::NotImplemented)
    }

    fn unregister_channel(&self, _name: &str) {}

    fn get_channel(&self, _name: &str) -> Option<Arc<dyn Channel>> {
        None
    }

    fn get_all_online_users(&self) -> Vec<String> {
        Vec::new()
    }
}

/// 默认 Stats Feature 实现（essentialFeatures fallback）。
///
/// 当配置中没有指定 stats app 时，Instance 使用此空实现占位。
/// 内部委托 NoopManager，所有 register/get 操作返回空。
pub struct DefaultStatsFeature {
    manager: NoopManager,
}

impl DefaultStatsFeature {
    pub fn new() -> Self {
        Self { manager: NoopManager }
    }
}

impl Feature for DefaultStatsFeature {
    fn feature_name(&self) -> &'static str {
        "default_stats"
    }
}

impl Manager for DefaultStatsFeature {
    fn register_counter(&self, name: &str) -> Result<Arc<dyn Counter>, ManagerError> {
        self.manager.register_counter(name)
    }

    fn unregister_counter(&self, name: &str) {
        self.manager.unregister_counter(name)
    }

    fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>> {
        self.manager.get_counter(name)
    }

    fn visit_counters(&self, f: &mut dyn FnMut(&str, &dyn Counter) -> bool) {
        self.manager.visit_counters(f)
    }

    fn register_online_map(&self, name: &str) -> Result<Arc<dyn OnlineMap>, ManagerError> {
        self.manager.register_online_map(name)
    }

    fn unregister_online_map(&self, name: &str) {
        self.manager.unregister_online_map(name)
    }

    fn get_online_map(&self, name: &str) -> Option<Arc<dyn OnlineMap>> {
        self.manager.get_online_map(name)
    }

    fn visit_online_maps(&self, f: &mut dyn FnMut(&str, &dyn OnlineMap) -> bool) {
        self.manager.visit_online_maps(f)
    }

    fn register_channel(&self, name: &str) -> Result<Arc<dyn Channel>, ManagerError> {
        self.manager.register_channel(name)
    }

    fn unregister_channel(&self, name: &str) {
        self.manager.unregister_channel(name)
    }

    fn get_channel(&self, name: &str) -> Option<Arc<dyn Channel>> {
        self.manager.get_channel(name)
    }

    fn get_all_online_users(&self) -> Vec<String> {
        self.manager.get_all_online_users()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_stats_constant() {
        assert_eq!(FEATURE_STATS, "stats");
    }

    // ----- NoopManager -----

    #[test]
    fn noop_register_counter_returns_not_implemented() {
        let m = NoopManager;
        let err = match m.register_counter("x") {
            Err(ManagerError::NotImplemented) => "ok",
            Err(e) => panic!("expected NotImplemented, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert_eq!(err, "ok");
    }

    #[test]
    fn noop_register_online_map_returns_not_implemented() {
        let m = NoopManager;
        match m.register_online_map("u") {
            Err(ManagerError::NotImplemented) => (),
            Err(e) => panic!("expected NotImplemented, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn noop_register_channel_returns_not_implemented() {
        let m = NoopManager;
        match m.register_channel("c") {
            Err(ManagerError::NotImplemented) => (),
            Err(e) => panic!("expected NotImplemented, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn noop_unregister_silent_no_op() {
        let m = NoopManager;
        m.unregister_counter("a");
        m.unregister_online_map("b");
        m.unregister_channel("c");
    }

    #[test]
    fn noop_get_returns_none() {
        let m = NoopManager;
        assert!(m.get_counter("a").is_none());
        assert!(m.get_online_map("b").is_none());
        assert!(m.get_channel("c").is_none());
    }

    #[test]
    fn noop_visit_no_invocation() {
        let m = NoopManager;
        let mut counter_called = 0;
        let mut online_called = 0;
        m.visit_counters(&mut |_, _| {
            counter_called += 1;
            true
        });
        m.visit_online_maps(&mut |_, _| {
            online_called += 1;
            true
        });
        assert_eq!(counter_called, 0);
        assert_eq!(online_called, 0);
    }

    #[test]
    fn noop_get_all_online_users_empty() {
        let m = NoopManager;
        assert!(m.get_all_online_users().is_empty());
    }

    #[test]
    fn noop_default_constructible() {
        let _m = NoopManager::default();
    }

    // ----- Error display -----

    #[test]
    fn channel_error_display() {
        let e = ChannelError::SubscribersLimitReached { limit: 10 };
        assert_eq!(e.to_string(), "subscribers reached limit (10)");
        let e = ChannelError::Closed;
        assert_eq!(e.to_string(), "channel closed");
        let e = ChannelError::NotStarted;
        assert_eq!(e.to_string(), "channel not started");
        let e = ChannelError::SubscriberNotFound(42);
        assert_eq!(e.to_string(), "subscriber 42 not found");
    }

    #[test]
    fn manager_error_display() {
        let e = ManagerError::AlreadyRegistered { kind: "Counter", name: "x".into() };
        assert_eq!(e.to_string(), "Counter `x` already registered");
        let e = ManagerError::NotImplemented;
        assert_eq!(e.to_string(), "not implemented");
    }

    // ----- get_or_register_* with NoopManager (validation only, real impl in app-stats) -----

    #[test]
    fn get_or_register_counter_returns_err_when_noop() {
        let m = NoopManager;
        // get 返回 None → 走 register 路径 → NotImplemented
        let res = get_or_register_counter(&m, "c");
        assert!(matches!(res, Err(ManagerError::NotImplemented)));
    }

    #[test]
    fn get_or_register_online_map_returns_err_when_noop() {
        let m = NoopManager;
        let res = get_or_register_online_map(&m, "u");
        assert!(matches!(res, Err(ManagerError::NotImplemented)));
    }

    #[test]
    fn get_or_register_channel_returns_err_when_noop() {
        let m = NoopManager;
        let res = get_or_register_channel(&m, "ch");
        assert!(matches!(res, Err(ManagerError::NotImplemented)));
    }
}
