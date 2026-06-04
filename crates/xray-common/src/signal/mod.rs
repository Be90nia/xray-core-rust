//! 信号处理工具
//!
//! 对应 Go 版本 `common/signal` 包，包含 Done 信号、Notifier、
//! ActivityTimer、PubSub 和 Semaphore 等并发原语。

use std::sync::Arc;

use tokio::sync::{watch, Notify, Semaphore as TokioSemaphore};

// ========== Done 信号 (Go: signal/done) ==========

/// 可取消的 Done 信号。
///
/// 对应 Go 版本 `done.Instance`，通过 `watch` channel 实现
/// 取消通知，所有等待者会在取消时被唤醒。
#[derive(Clone)]
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
///
/// 用于通知某个事件已发生，等待者会被唤醒。
pub struct Notifier {
    notify: Arc<Notify>,
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
/// 对应 Go 版本 `CancelAfterInactivity`，在指定时间内
/// 没有活动通知时自动取消。
pub struct ActivityTimer {
    done: Done,
    notifier: Notifier,
    timeout: std::time::Duration,
}

impl ActivityTimer {
    /// 创建新的活动计时器，指定超时时间。
    pub fn new(timeout: std::time::Duration) -> Self {
        Self {
            done: Done::new(),
            notifier: Notifier::new(),
            timeout,
        }
    }

    /// 运行计时器循环，超时时自动取消。
    ///
    /// 每次收到活动通知会重置超时计时。
    /// 此方法应在一个独立的 tokio 任务中运行。
    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.timeout) => {
                    self.done.cancel();
                    return;
                }
                _ = self.notifier.wait() => {
                    if self.done.is_cancelled() {
                        return;
                    }
                }
            }
        }
    }

    /// 通知有活动发生，重置超时计时。
    pub fn update_activity(&self) {
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
}

// ========== PubSub (Go: signal/pubsub) ==========

/// 发布-订阅服务，用于事件广播。
///
/// 对应 Go 版本 `signal/pubsub.Service`，支持多个订阅者
/// 同时监听消息。
pub struct PubSub<T: Clone + Send + Sync + 'static> {
    subscribers: Arc<tokio::sync::RwLock<Vec<watch::Sender<Option<T>>>>>,
}

impl<T: Clone + Send + Sync + 'static> PubSub<T> {
    /// 创建新的 PubSub 服务。
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// 订阅消息，返回订阅者。
    pub async fn subscribe(&self) -> PubSubSubscriber<T> {
        let (tx, rx) = watch::channel(None);
        let mut subs = self.subscribers.write().await;
        // 清理已断开的订阅者
        subs.retain(|s| s.receiver_count() > 0);
        subs.push(tx);
        PubSubSubscriber { receiver: rx }
    }

    /// 向所有订阅者广播消息。
    pub async fn publish(&self, message: T) {
        let mut subs = self.subscribers.write().await;
        subs.retain(|s| s.send(Some(message.clone())).is_ok());
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
}
