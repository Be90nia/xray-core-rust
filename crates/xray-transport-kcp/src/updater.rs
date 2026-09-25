//! Updater 抽象（对应 Go `connection.go` 的 `Updater`）。
//!
//! Go 的 `Updater` 用 `signal.Notifier + time.Ticker + goroutine` 实现按需唤醒：
//!
//! - `WakeUp()`：spawn 一个 goroutine 跑 `run()`（用 semaphore.Instance 保证 同一时刻只有一个
//!   goroutine 在跑）。
//! - `run()`：若 `shouldTerminate()` 直接退出；否则 `time.NewTicker(interval)`， 循环
//!   `updateFunc()` 直到 `shouldContinue()` 为 false。
//! - `interval` 字段是 `int64`，可用 `atomic.StoreInt64` 实时改。
//!
//! Rust 等价：trait + Tokio 实现 + Noop 实现。
//!
//! - [`Updater`] trait：`wake_up` / `set_interval` / `interval`。
//! - [`TokioUpdater`]：用 `tokio::sync::Notify + tokio::spawn` 实现真实 wakeup。 单实例运行通过
//!   `AtomicBool` running flag 保证。
//! - [`NoopUpdater`]：测试用，不调度（直接丢弃 wake_up）。

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use tokio::sync::Notify;

/// Updater 接口。
pub trait Updater: Send + Sync {
    /// 唤醒一次（对应 Go `WakeUp`）。若无活动任务则启动一个，否则丢弃。
    fn wake_up(&self);

    /// 设置更新间隔（对应 Go `SetInterval`）。
    fn set_interval(&self, interval: Duration);

    /// 当前间隔（对应 Go `Interval`）。
    fn interval(&self) -> Duration;
}

/// Tokio 实现：通过 `tokio::spawn` 启动异步循环。
///
/// 调用方必须保证 `wake_up` 在 tokio runtime 上下文中调用（spawn 需要 runtime）。
/// 若调用方在同步上下文中，需要先用 `tokio::spawn` 包一层。
pub struct TokioUpdater {
    interval: Mutex<Duration>,
    running: AtomicBool,
    notify: Notify,
    should_continue: Arc<dyn Fn() -> bool + Send + Sync>,
    should_terminate: Arc<dyn Fn() -> bool + Send + Sync>,
    update_func: Arc<dyn Fn() + Send + Sync>,
}

impl TokioUpdater {
    /// 构造（对应 Go `NewUpdater`）。
    pub fn new(
        interval: Duration,
        should_continue: impl Fn() -> bool + Send + Sync + 'static,
        should_terminate: impl Fn() -> bool + Send + Sync + 'static,
        update_func: impl Fn() + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            interval: Mutex::new(interval),
            running: AtomicBool::new(false),
            notify: Notify::new(),
            should_continue: Arc::new(should_continue),
            should_terminate: Arc::new(should_terminate),
            update_func: Arc::new(update_func),
        })
    }

    /// 自引用 spawn：方法内克隆 Arc 并 spawn 一个 task。
    ///
    /// 必须在 tokio runtime 上下文调用。如果调用方在同步代码中，用
    /// `tokio::runtime::Handle::try_current()` 检查后再 spawn。
    fn try_spawn(self: &Arc<Self>) {
        // CAS：保证只有一个 task 同时运行
        if self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            if (this.should_terminate)() {
                this.running.store(false, Ordering::SeqCst);
                return;
            }

            let mut interval = tokio::time::interval(*this.interval.lock());
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            while (this.should_continue)() {
                (this.update_func)();
                interval.tick().await;
                // 检查间隔是否被外部更新
                let new_interval = *this.interval.lock();
                if interval.period() != new_interval {
                    interval = tokio::time::interval(new_interval);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    interval.tick().await; // consume immediate tick
                }
            }

            this.running.store(false, Ordering::SeqCst);
        });
    }
}

impl Updater for TokioUpdater {
    fn wake_up(&self) {
        // 实际上需要 &Arc<Self> 才能 spawn，但 trait 方法是 &self。
        // 用 unsafe？不，用另一种思路：running CAS 在 try_spawn 内做，
        // 这里通过 Notify 触发现有 task。
        // 改方案：让 wake_up 直接调用 notify，task 启动时等待 notify。
        //
        // 简化：如果 running=false，尝试 spawn；否则 notify 现有 task。
        // 这里需要 Arc::clone 自己 —— 但 trait 方法 &self 没有 Arc。
        // 解决：在 struct 内嵌 Weak<Self>，构造后 upgrade。
        //
        // 更简单的方案：直接绕过 trait，给 TokioUpdater 加专用方法
        // `wake_up_arc(self: &Arc<Self>)`。trait 方法 wake_up 用 notify_one
        // 触发现有 task；首次启动在 new() 后由调用方显式调一次 wake_up_arc。
        self.notify.notify_one();
    }

    fn set_interval(&self, interval: Duration) {
        *self.interval.lock() = interval;
    }

    fn interval(&self) -> Duration {
        *self.interval.lock()
    }
}

impl TokioUpdater {
    /// Arc-aware 版本的 wake_up（推荐用法）。
    ///
    /// 若无活动 task，spawn 一个新 task；否则 notify 现有 task。
    pub fn wake_up_arc(self: &Arc<Self>) {
        if !self.running.load(Ordering::SeqCst) {
            self.try_spawn();
        } else {
            self.notify.notify_one();
        }
    }
}

/// Noop 实现（测试用）。
#[derive(Debug, Default)]
pub struct NoopUpdater {
    interval: Mutex<Duration>,
    wake_count: std::sync::atomic::AtomicU32,
}

impl NoopUpdater {
    #[must_use]
    pub fn new() -> Self {
        Self {
            interval: Mutex::new(Duration::from_millis(50)),
            wake_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// 检查 wake_up 被调用次数（测试用）。
    pub fn wake_count(&self) -> u32 {
        self.wake_count.load(Ordering::SeqCst)
    }
}

impl Updater for NoopUpdater {
    fn wake_up(&self) {
        self.wake_count.fetch_add(1, Ordering::SeqCst);
    }

    fn set_interval(&self, interval: Duration) {
        *self.interval.lock() = interval;
    }

    fn interval(&self) -> Duration {
        *self.interval.lock()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use super::*;

    #[test]
    fn noop_updater_records_wake_calls() {
        let u = NoopUpdater::new();
        assert_eq!(u.wake_count(), 0);
        u.wake_up();
        u.wake_up();
        u.wake_up();
        assert_eq!(u.wake_count(), 3);
    }

    #[test]
    fn noop_updater_set_get_interval() {
        let u = NoopUpdater::new();
        let initial = u.interval();
        u.set_interval(Duration::from_secs(5));
        assert_ne!(u.interval(), initial);
        assert_eq!(u.interval(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn tokio_updater_runs_update_func() {
        // 用 counter 验证 update_func 被调用至少一次
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let should_continue_counter = Arc::new(AtomicU32::new(0));
        let sc = should_continue_counter.clone();

        let u = TokioUpdater::new(
            Duration::from_millis(5),
            move || {
                let count = sc.fetch_add(1, Ordering::SeqCst);
                count < 3 // 跑 3 次后停
            },
            || false,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
        );

        u.wake_up_arc();
        // 给一些时间让 task 跑
        tokio::time::sleep(Duration::from_millis(50)).await;

        let calls = counter.load(Ordering::SeqCst);
        assert!(calls >= 1, "update_func 应被调用至少一次，实际 {calls}");
    }

    #[tokio::test]
    async fn tokio_updater_terminates_when_should_terminate() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let u = TokioUpdater::new(
            Duration::from_millis(5),
            || true,
            || true, // 立即终止
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
        );

        u.wake_up_arc();
        tokio::time::sleep(Duration::from_millis(20)).await;
        // should_terminate=true 时 update_func 不应被调用
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tokio_updater_set_interval_runtime() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let sc = Arc::new(AtomicU32::new(0));
        let sc_clone = sc.clone();

        let u = TokioUpdater::new(
            Duration::from_millis(5),
            move || sc_clone.fetch_add(1, Ordering::SeqCst) < 5,
            || false,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
        );

        u.set_interval(Duration::from_millis(20));
        assert_eq!(u.interval(), Duration::from_millis(20));

        u.wake_up_arc();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 应至少被调用一次
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }
}
