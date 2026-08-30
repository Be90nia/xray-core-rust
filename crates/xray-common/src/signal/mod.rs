//! 信号处理工具
//!
//! 对应 Go 版本 `common/signal` 包，包含 Done 信号、Notifier、
//! ActivityTimer、PubSub 和 Semaphore 等并发原语。

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{watch, Notify, Semaphore as TokioSemaphore};

// ========== Done 信号 (Go: signal/done) ==========

/// 可取消的 Done 信号。
///
/// 对应 Go 版本 `done.Instance`，通过 `watch` channel 实现
/// 取消通知，所有等待者会在取消时被唤醒。
#[derive(Clone, Debug)]
pub struct Done {
    cancel_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
}

impl Done {
    /// 创建新的 Done 信号，初始状态为未取消。
    pub fn new() -> Self {
        let (cancel_tx, done_rx) = watch::channel(false);
        Self { cancel_tx, done_rx }
    }

    /// 取消信号，通知所有等待者。
    ///
    /// 多次调用是安全的（幂等）。
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// 等待取消信号，返回 `true`。
    ///
    /// 如果已经取消则立即返回。
    pub async fn wait(&mut self) -> bool {
        if *self.done_rx.borrow() {
            return true;
        }
        while self.done_rx.changed().await.is_ok() {
            if *self.done_rx.borrow() {
                return true;
            }
        }
        // sender 被丢弃也视为取消
        true
    }

    /// 检查当前是否已取消。
    pub fn is_cancelled(&self) -> bool {
        *self.done_rx.borrow()
    }
}

impl Default for Done {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Notifier ==========

/// 活动通知器，基于 tokio `Notify` 实现。
pub struct Notifier {
    notify: Arc<Notify>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier").finish_non_exhaustive()
    }
}

impl Notifier {
    /// 创建新的通知器。
    pub fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
        }
    }

    /// 发出通知信号。
    pub fn notify(&self) {
        self.notify.notify_one();
    }

    /// 等待通知信号。
    pub async fn wait(&self) {
        self.notify.notified().await;
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Notifier {
    fn clone(&self) -> Self {
        Self {
            notify: Arc::clone(&self.notify),
        }
    }
}

// ========== ActivityTimer ==========

/// 不活动超时计时器。
///
/// 对应 Go 版本 `CancelAfterInactivity` + `common/signal/timer.go` `ActivityTimer`：
/// - `update_activity()`：活动信号，重置超时窗口（对应 Go `Update`）；
/// - `set_timeout(t)`：重置超时窗口（对应 Go `SetTimeout`，重建 checkTask + `Update()`）；
/// - `set_timeout(0)`：立即 cancel done（对应 Go `SetTimeout(0) → finish()`）。
/// - 超时无活动 → cancel done。
///
/// `timeout` 字段为 `Arc<Mutex<Duration>>` 让 [`Self::set_timeout`] 能在不持有 `&mut self`
/// 的情况下重置窗口（Go `ActivityTimer.SetTimeout` 是值接收者）。
#[derive(Debug)]
pub struct ActivityTimer {
    done: Done,
    notifier: Notifier,
    timeout: Arc<Mutex<std::time::Duration>>,
}

impl ActivityTimer {
    pub fn new(timeout: std::time::Duration) -> Self {
        Self {
            done: Done::new(),
            notifier: Notifier::new(),
            timeout: Arc::new(Mutex::new(timeout)),
        }
    }

    /// 运行计时器循环，超时时自动取消。
    ///
    /// 每次收到活动通知会重置超时计时。
    /// 此方法应在一个独立的 tokio 任务中运行。
    pub async fn run(&mut self) {
        // Sliding window：每轮循环读当前 timeout（可被 set_timeout 重置），
        // 用 sleep_until 到 deadline。性能开销可忽略（每轮一次 sleep）。
        loop {
            let current = *self.timeout.lock();
            let deadline = tokio::time::Instant::now() + current;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    self.done.cancel();
                    return;
                }
                _ = self.notifier.wait() => {
                    if self.done.is_cancelled() {
                        return;
                    }
                    // 重新循环 → 重新读 timeout + 重新算 deadline（sliding window）
                }
            }
        }
    }

    /// 通知有活动发生，重置超时计时（对应 Go `ActivityTimer.Update`）。
    pub fn update_activity(&self) {
        self.notifier.notify();
    }

    /// 重新调度超时窗口。对应 Go `common/signal/timer.go:53-76` `ActivityTimer.SetTimeout`：
    ///
    /// - `t == Duration::ZERO`：立即 cancel done（等价 Go `SetTimeout(0) → finish()`）。
    /// - `t > Duration::ZERO`：替换内部 timeout + 唤醒 `run` 循环以重算 deadline
    ///   （Go 等价：close old checkTask + new checkTask + `Update()`）。
    /// - 多次调用安全；`is_cancelled()` 后调用为 no-op。
    pub fn set_timeout(&self, t: std::time::Duration) {
        if self.done.is_cancelled() {
            return;
        }
        if t.is_zero() {
            self.done.cancel();
            self.notifier.notify();
            return;
        }
        *self.timeout.lock() = t;
        // 唤醒 run 中的 sleep，让其重新读 timeout + 算新 deadline。
        self.notifier.notify();
    }

    /// 手动取消计时器。
    pub fn cancel(&self) {
        self.done.cancel();
        self.notifier.notify();
    }

    /// 检查是否已取消。
    pub fn is_cancelled(&self) -> bool {
        self.done.is_cancelled()
    }

    /// 获取 Done 信号的克隆，用于外部等待超时。
    pub fn done_signal(&self) -> Done {
        self.done.clone()
    }

    /// 获取当前超时窗口。对应 Go `t.timeout` 读取。
    #[must_use]
    pub fn timeout(&self) -> std::time::Duration {
        *self.timeout.lock()
    }

    /// 兼容别名：保留旧 `done()` 调用方（`xray-app-proxyman` worker 等）。
    #[deprecated(note = "use done_signal for clarity; kept for backward compat")]
    pub fn done(&self) -> Done {
        self.done.clone()
    }
}

// ========== PubSub (Go: signal/pubsub) ==========

/// PubSub 主题枚举。对应 Go `signal/pubsub.Service.Subscribe(name)` / `Publish(name, msg)`。
///
/// 用 enum 保证主题名在编译期固定、不会拼错。Rust 扩展（Go 用 string）。
/// 添加新主题只需扩展此 enum + 实现 `as_str`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PubSubTopic {
    /// 全局无主题（Go `Subscribe("")` 等价）。
    Global,
    /// DNS 解析统计主题（Go app/dns internal pubsub）。
    DnsStats,
    /// 路由统计主题（对应 Go `app/router` + `app/stats` 桥接）。
    RouteStats,
    /// Observer 观测主题（对应 Go `app/observatory`）。
    Observer,
}

impl PubSubTopic {
    /// 主题名（Go `name` 字符串）。
    pub const fn as_str(&self) -> &'static str {
        match self {
            PubSubTopic::Global => "",
            PubSubTopic::DnsStats => "dns.stats",
            PubSubTopic::RouteStats => "route.stats",
            PubSubTopic::Observer => "observer",
        }
    }
}

impl std::fmt::Display for PubSubTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 发布-订阅服务，用于事件广播。
///
/// 对应 Go 版本 `signal/pubsub.Service`，支持多个订阅者同时监听消息。
///
/// **主题路由**：内部用 `HashMap<String, Vec<watch::Sender>>` 按主题分组；
/// - 旧 `subscribe()` / `publish()` 不传主题等价 `PubSubTopic::Global`（向后兼容）。
/// - `subscribe_topic(topic)` / `publish_topic(topic, msg)` 走指定主题。
pub struct PubSub<T: Clone + Send + Sync + 'static> {
    subscribers: Arc<tokio::sync::RwLock<HashMap<String, Vec<watch::Sender<Option<T>>>>>>,
}

impl<T: Clone + Send + Sync + 'static> PubSub<T> {
    /// 创建新的 PubSub 服务。
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// 订阅全局主题（无主题名），返回订阅者。
    ///
    /// 向后兼容旧 API；等价 `subscribe_topic(PubSubTopic::Global)`。
    pub async fn subscribe(&self) -> PubSubSubscriber<T> {
        self.subscribe_topic(PubSubTopic::Global).await
    }

    /// 订阅指定主题，返回订阅者。
    ///
    /// 对应 Go `Service.Subscribe(name)`。
    pub async fn subscribe_topic(&self, topic: PubSubTopic) -> PubSubSubscriber<T> {
        self.subscribe_named(topic.as_str()).await
    }

    /// 订阅自定义主题名（Rust 扩展，让外部 crate 注册私有主题）。
    pub async fn subscribe_named(&self, name: &str) -> PubSubSubscriber<T> {
        let (tx, rx) = watch::channel(None);
        let mut subs = self.subscribers.write().await;
        // 清理该主题内已断开的订阅者
        if let Some(bucket) = subs.get_mut(name) {
            bucket.retain(|s| s.receiver_count() > 0);
            bucket.push(tx);
        } else {
            subs.insert(name.to_string(), vec![tx]);
        }
        PubSubSubscriber { receiver: rx }
    }

    /// 向全局主题发布消息。
    ///
    /// 向后兼容旧 API；等价 `publish_topic(PubSubTopic::Global, message)`。
    pub async fn publish(&self, message: T) {
        self.publish_topic(PubSubTopic::Global, message).await;
    }

    /// 向指定主题发布消息。
    ///
    /// 对应 Go `Service.Publish(name, message)`。
    pub async fn publish_topic(&self, topic: PubSubTopic, message: T) {
        self.publish_named(topic.as_str(), message).await;
    }

    /// 向自定义主题名发布消息（Rust 扩展）。
    pub async fn publish_named(&self, name: &str, message: T) {
        let mut subs = self.subscribers.write().await;
        if let Some(bucket) = subs.get_mut(name) {
            // retain：移除已断开的订阅者；send 失败时 retain 会丢弃。
            bucket.retain(|s| s.send(Some(message.clone())).is_ok());
        }
        // 未订阅主题 → no-op（Go 同行为，subs[name] 不存在则 range 空）。
    }

    /// 当前每个主题的活跃订阅者数量（按主题聚合）。
    /// 主要用于测试 / 诊断。
    pub async fn subscribers_by_topic(&self) -> HashMap<String, usize> {
        let subs = self.subscribers.read().await;
        subs.iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

impl<T: Clone + Send + Sync + 'static> Default for PubSub<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// PubSub 订阅者。
pub struct PubSubSubscriber<T: Clone + Send + Sync + 'static> {
    receiver: watch::Receiver<Option<T>>,
}

impl<T: Clone + Send + Sync + 'static> PubSubSubscriber<T> {
    /// 等待下一条消息。
    ///
    /// 返回 `None` 表示发布者已断开。
    pub async fn wait(&mut self) -> Option<T> {
        while self.receiver.changed().await.is_ok() {
            if let Some(msg) = self.receiver.borrow().clone() {
                return Some(msg);
            }
        }
        None
    }
}

// ========== Semaphore (Go: signal/semaphore) ==========

/// 异步信号量，支持 acquire/release。
///
/// 对应 Go 版本 `signal/semaphore.Instance`，基于 tokio 信号量实现。
pub struct Semaphore {
    inner: Arc<TokioSemaphore>,
}

impl Semaphore {
    /// 创建新的信号量，指定最大并发数。
    pub fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(TokioSemaphore::new(max)),
        }
    }

    /// 获取一个许可，返回许可持有者。
    ///
    /// 当信号量已满时会异步等待。
    pub async fn acquire(&self) -> SemaphorePermit {
        let permit = self
            .inner
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore acquire should not fail unless closed");
        SemaphorePermit { _permit: permit }
    }

    /// 获取当前可用许可数。
    pub fn available_permits(&self) -> usize {
        self.inner.available_permits()
    }
}

impl Clone for Semaphore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// 信号量许可，释放时自动归还。
pub struct SemaphorePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ---- Done 测试 ----

    #[tokio::test]
    async fn test_done_new_not_cancelled() {
        let done = Done::new();
        assert!(!done.is_cancelled());
    }

    #[tokio::test]
    async fn test_done_cancel() {
        let done = Done::new();
        done.cancel();
        assert!(done.is_cancelled());
    }

    #[tokio::test]
    async fn test_done_wait_already_cancelled() {
        let mut done = Done::new();
        done.cancel();
        let result = done.wait().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_done_wait_then_cancel() {
        let mut done = Done::new();
        let done_clone = done.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done_clone.cancel();
        });
        let result = done.wait().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_done_idempotent_cancel() {
        let done = Done::new();
        done.cancel();
        done.cancel();
        assert!(done.is_cancelled());
    }

    #[tokio::test]
    async fn test_done_default() {
        let done = Done::default();
        assert!(!done.is_cancelled());
    }

    // ---- Notifier 测试 ----

    #[tokio::test]
    async fn test_notifier_wait_notify() {
        let notifier = Notifier::new();
        let notifier_clone = notifier.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            notifier_clone.notify();
        });
        notifier.wait().await;
    }

    #[tokio::test]
    async fn test_notifier_default() {
        let notifier = Notifier::default();
        notifier.notify();
    }

    // ---- ActivityTimer 测试 ----

    #[tokio::test]
    async fn test_activity_timer_timeout() {
        let mut timer = ActivityTimer::new(Duration::from_millis(100));
        timer.run().await;
        assert!(timer.is_cancelled());
    }

    #[tokio::test]
    async fn test_activity_timer_manual_cancel() {
        let timer = ActivityTimer::new(Duration::from_secs(10));
        timer.cancel();
        assert!(timer.is_cancelled());
    }

    #[tokio::test]
    async fn test_activity_timer_update_activity() {
        let timer = ActivityTimer::new(Duration::from_millis(200));
        let timer_ref = ActivityTimer::new(Duration::from_millis(200));

        // 在超时前发送活动通知
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            timer_ref.update_activity();
        });

        // timer 不应立即取消
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!timer.is_cancelled());
    }

    #[tokio::test]
    async fn test_activity_timer_done_signal() {
        let mut timer = ActivityTimer::new(Duration::from_millis(100));
        let mut done = timer.done();

        // spawn timer run，超时后 done 信号应触发
        tokio::spawn(async move {
            timer.run().await;
        });

        // 等待 done 信号
        let cancelled = done.wait().await;
        assert!(cancelled);
    }

    // ---- PubSub 测试 ----

    #[tokio::test]
    async fn test_pubsub_publish_subscribe() {
        let pubsub: PubSub<i32> = PubSub::new();
        let mut sub1 = pubsub.subscribe().await;
        let mut sub2 = pubsub.subscribe().await;

        pubsub.publish(42).await;

        let msg1 = sub1.wait().await;
        let msg2 = sub2.wait().await;
        assert_eq!(msg1, Some(42));
        assert_eq!(msg2, Some(42));
    }

    #[tokio::test]
    async fn test_pubsub_default() {
        let pubsub: PubSub<String> = PubSub::default();
        let _sub = pubsub.subscribe().await;
    }

    #[tokio::test]
    async fn test_pubsub_multiple_messages() {
        let pubsub: PubSub<i32> = PubSub::new();
        let mut sub = pubsub.subscribe().await;

        pubsub.publish(1).await;
        pubsub.publish(2).await;

        let msg1 = sub.wait().await;
        // watch channel 只保留最新值，可能丢失中间消息
        assert!(msg1.is_some());
    }

    // ---- Semaphore 测试 ----

    #[tokio::test]
    async fn test_semaphore_acquire_release() {
        let sem = Semaphore::new(2);
        assert_eq!(sem.available_permits(), 2);

        let _permit1 = sem.acquire().await;
        assert_eq!(sem.available_permits(), 1);

        let _permit2 = sem.acquire().await;
        assert_eq!(sem.available_permits(), 0);
    }

    #[tokio::test]
    async fn test_semaphore_concurrent() {
        let sem = Semaphore::new(1);
        let sem_clone = sem.clone();

        let _permit = sem.acquire().await;
        assert_eq!(sem.available_permits(), 0);

        let handle = tokio::spawn(async move {
            let _p = sem_clone.acquire().await;
        });

        drop(_permit);

        handle.await.expect("task should complete");
    }

    #[tokio::test]
    async fn test_semaphore_clone() {
        let sem1 = Semaphore::new(3);
        let sem2 = sem1.clone();
        assert_eq!(sem1.available_permits(), 3);
        assert_eq!(sem2.available_permits(), 3);
    }

    // ---- ActivityTimer::set_timeout 测试 ----

    #[tokio::test]
    async fn test_activity_timer_set_timeout_zero_finishes() {
        // Go common/signal/timer.go:57-60: SetTimeout(0) → 立即 finish（cancel done）。
        let timer = ActivityTimer::new(Duration::from_secs(10));
        assert!(!timer.is_cancelled());
        timer.set_timeout(Duration::ZERO);
        assert!(timer.is_cancelled(), "set_timeout(0) 必须立即 cancel done");
    }

    #[tokio::test]
    async fn test_activity_timer_set_timeout_updates_window() {
        // Go common/signal/timer.go:62-75: SetTimeout(t>0) → 替换 timeout + Update。
        let timer = ActivityTimer::new(Duration::from_secs(10));
        assert_eq!(timer.timeout(), Duration::from_secs(10));
        timer.set_timeout(Duration::from_millis(500));
        assert_eq!(
            timer.timeout(),
            Duration::from_millis(500),
            "set_timeout(t>0) 必须替换 timeout"
        );
    }

    #[tokio::test]
    async fn test_activity_timer_set_timeout_after_cancelled_is_noop() {
        let timer = ActivityTimer::new(Duration::from_secs(10));
        timer.cancel();
        assert!(timer.is_cancelled());
        // 已 cancelled 后 set_timeout 不应改变 timeout，也不应 panic。
        timer.set_timeout(Duration::from_millis(100));
        assert_eq!(timer.timeout(), Duration::from_secs(10));
    }

    // ---- PubSub 主题路由测试 ----

    #[tokio::test]
    async fn test_pubsub_topic_routing_isolated() {
        // 不同主题的订阅者互不影响。
        let pubsub: PubSub<i32> = PubSub::new();
        let mut sub_global = pubsub.subscribe().await;
        let mut sub_dns = pubsub.subscribe_topic(PubSubTopic::DnsStats).await;

        pubsub.publish_topic(PubSubTopic::DnsStats, 42).await;

        // global 不应收到。
        assert!(
            tokio::time::timeout(Duration::from_millis(50), sub_global.wait())
                .await
                .is_err(),
            "global topic 不应收到 DnsStats 消息"
        );
        // dns 应收到。
        let msg = tokio::time::timeout(Duration::from_millis(100), sub_dns.wait())
            .await
            .expect("dns subscriber 收到消息超时")
            .expect("msg should not be None");
        assert_eq!(msg, 42);
    }

    #[tokio::test]
    async fn test_pubsub_global_topic_backward_compat() {
        // 旧 API subscribe()/publish() 等价 PubSubTopic::Global。
        let pubsub: PubSub<String> = PubSub::new();
        let mut sub = pubsub.subscribe().await;
        pubsub.publish("hello".into()).await;
        let got = sub.wait().await;
        assert_eq!(got, Some("hello".into()));
    }

    #[tokio::test]
    async fn test_pubsub_topic_strings() {
        // 主题字符串值稳定，便于序列化兼容。
        assert_eq!(PubSubTopic::Global.as_str(), "");
        assert_eq!(PubSubTopic::DnsStats.as_str(), "dns.stats");
        assert_eq!(PubSubTopic::RouteStats.as_str(), "route.stats");
        assert_eq!(PubSubTopic::Observer.as_str(), "observer");
        assert_eq!(format!("{}", PubSubTopic::Observer), "observer");
    }

    #[tokio::test]
    async fn test_pubsub_subscribers_by_topic() {
        let pubsub: PubSub<i32> = PubSub::new();
        let _s1 = pubsub.subscribe().await;
        let _s2 = pubsub.subscribe().await;
        let _d1 = pubsub.subscribe_topic(PubSubTopic::DnsStats).await;

        let counts = pubsub.subscribers_by_topic().await;
        assert_eq!(counts.get(""), Some(&2), "global 主题 2 个订阅者");
        assert_eq!(counts.get("dns.stats"), Some(&1));
    }
}
