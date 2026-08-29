//! 不活动超时计时器（带可变 timeout + terminate 回调）。
//!
//! 对应 Go `common/signal/timer.go` 的 `ActivityTimer` + `CancelAfterInactivity`：
//! - `update()`：活动信号，重置超时窗口（Go `Update`，buffered chan cap=1 合并语义）
//! - `set_timeout(0)`：立即 finish（Go `SetTimeout(0)` → `finish()` → `onTimeout()` 一次）
//! - `set_timeout(t)`：替换超时窗口并重置（Go `SetTimeout` 重建 checkTask + `Update()`）
//! - 超时无活动 → finish：`on_timeout` 恰好执行一次
//!
//! 复用 `xray_common::signal::ActivityTimer` 的障碍：其 `timeout` 字段不可变且
//! `run(&mut self)` 独占，无 `set_timeout`/terminate 回调；本 crate 的 BridgeWorker
//! 依赖 `SetTimeout(0)`（立即终止）与 `SetTimeout(24h)`（drain 窗口）语义。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::Notify;

struct Inner {
    updated: Notify,
    timeout: RwLock<Duration>,
    finished: AtomicBool,
    stop_tx: tokio::sync::watch::Sender<bool>,
    on_timeout: Box<dyn Fn() + Send + Sync>,
}

/// 不活动超时计时器。构造即启动后台 run 循环。
///
/// 对应 Go `signal.CancelAfterInactivity(ctx, cancel, timeout)`。
pub struct InactivityTimer {
    inner: Arc<Inner>,
}

impl InactivityTimer {
    /// 创建并启动计时器，超时（或 [`Self::set_timeout`] 传零）时执行 `on_timeout` 一次。
    pub fn new(timeout: Duration, on_timeout: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let inner = Arc::new(Inner {
            updated: Notify::new(),
            timeout: RwLock::new(timeout),
            finished: AtomicBool::new(false),
            stop_tx,
            on_timeout: Box::new(on_timeout),
        });

        let run_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            // sliding window：deadline = 最近一次 update + 当前 timeout
            loop {
                let timeout = *run_inner.timeout.read();
                tokio::select! {
                    _ = tokio::time::sleep(timeout) => {
                        finish(&run_inner);
                        break;
                    }
                    _ = run_inner.updated.notified() => {
                        if run_inner.finished.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    _ = stop_rx.changed() => break,
                }
            }
        });

        Arc::new(Self { inner })
    }

    /// 活动信号：重置超时窗口（多次合并为一次，同 Go buffered chan(1)）。
    pub fn update(&self) {
        self.inner.updated.notify_one();
    }

    /// 替换超时窗口；`0` 立即 finish（执行 `on_timeout` 并停止）。
    ///
    /// 对应 Go `ActivityTimer.SetTimeout`。
    pub fn set_timeout(&self, timeout: Duration) {
        if timeout.is_zero() {
            finish(&self.inner);
            return;
        }
        if self.inner.finished.load(Ordering::Acquire) {
            return;
        }
        *self.inner.timeout.write() = timeout;
        self.update();
    }

    /// 是否已 finish（`on_timeout` 已执行或即将执行）。
    pub fn is_finished(&self) -> bool {
        self.inner.finished.load(Ordering::Acquire)
    }
}

fn finish(inner: &Inner) {
    if !inner.finished.swap(true, Ordering::AcqRel) {
        (inner.on_timeout)();
    }
    let _ = inner.stop_tx.send(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn timeout_fires_on_timeout_once() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let t = InactivityTimer::new(Duration::from_millis(100), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(t.is_finished());
    }

    #[tokio::test]
    async fn update_prevents_timeout() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let t = InactivityTimer::new(Duration::from_millis(150), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            t.update();
        }
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert!(!t.is_finished());
    }

    #[tokio::test]
    async fn set_timeout_zero_finishes_immediately() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let t = InactivityTimer::new(Duration::from_secs(3600), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        t.set_timeout(Duration::ZERO);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(t.is_finished());
    }

    #[tokio::test]
    async fn set_timeout_extends_window() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let t = InactivityTimer::new(Duration::from_millis(100), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        // 100ms 窗口即将到期前延长到 1s：不应触发
        tokio::time::sleep(Duration::from_millis(60)).await;
        t.set_timeout(Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn finish_is_idempotent() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let t = InactivityTimer::new(Duration::from_secs(3600), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        t.set_timeout(Duration::ZERO);
        t.set_timeout(Duration::ZERO); // 二次 finish 不重复执行
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }
}
