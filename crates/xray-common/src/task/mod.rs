//! 异步任务管理
//!
//! 对应 Go 版本 `common/task` 包，提供周期性任务执行器。

use std::sync::Arc;
use std::time::Duration;

use crate::errors::Error;

/// 周期性任务执行器。
///
/// 对应 Go 版本 `task.Periodic`，按固定间隔重复执行任务回调。
pub struct Periodic {
    interval: Duration,
    running: Arc<std::sync::Mutex<bool>>,
}

impl Periodic {
    /// 创建新的周期性任务，指定执行间隔。
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            running: Arc::new(std::sync::Mutex::new(false)),
        }
    }

    /// 启动周期性任务，传入任务回调函数。
    ///
    /// 任务会在独立 tokio 任务中按间隔重复执行，直到调用 `stop()`。
    /// 如果回调返回错误，任务会停止运行。
    ///
    /// # Errors
    ///
    /// 任务已在运行时返回错误。
    pub async fn start<F>(&self, task: F) -> Result<(), Error>
    where
        F: Fn() -> Result<(), Error> + Send + Sync + 'static,
    {
        {
            let mut running = self.running.lock().map_err(|_| Error::new("running lock poisoned"))?;
            if *running {
                return Err(Error::new("periodic task is already running"));
            }
            *running = true;
        }

        let interval = self.interval;
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            loop {
                {
                    let r = match running.lock() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if !*r {
                        break;
                    }
                }

                match task() {
                    Ok(()) => {}
                    Err(_) => {
                        if let Ok(mut r) = running.lock() {
                            *r = false;
                        }
                        break;
                    }
                }

                tokio::time::sleep(interval).await;
            }
        });

        Ok(())
    }

    /// 停止周期性任务。锁中毒时静默忽略。
    pub fn stop(&self) {
        if let Ok(mut running) = self.running.lock() {
            *running = false;
        }
    }

    /// 检查任务是否正在运行。锁中毒时返回 `false`。
    pub fn is_running(&self) -> bool {
        self.running.lock().map_or(false, |r| *r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_periodic_new() {
        let periodic = Periodic::new(Duration::from_millis(100));
        assert!(!periodic.is_running());
    }

    #[tokio::test]
    async fn test_periodic_start_stop() {
        let periodic = Periodic::new(Duration::from_millis(50));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        periodic
            .start(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect("start should succeed");

        assert!(periodic.is_running());

        // 等待几次执行
        tokio::time::sleep(Duration::from_millis(200)).await;
        periodic.stop();
        assert!(!periodic.is_running());

        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 2, "should have executed at least 2 times, got {count}");
    }

    #[tokio::test]
    async fn test_periodic_start_already_running() {
        let periodic = Periodic::new(Duration::from_millis(100));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        periodic
            .start(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect("first start should succeed");

        // 第二次启动应返回错误
        let counter2 = Arc::new(AtomicUsize::new(0));
        let counter2_clone = counter2.clone();
        let result = periodic.start(move || {
            counter2_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }).await;

        assert!(result.is_err());
        periodic.stop();
    }

    #[tokio::test]
    async fn test_periodic_task_error_stops() {
        let periodic = Periodic::new(Duration::from_millis(50));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        periodic
            .start(move || {
                let c = counter_clone.fetch_add(1, Ordering::SeqCst);
                if c >= 2 {
                    return Err(Error::new("task error"));
                }
                Ok(())
            })
            .await
            .expect("start should succeed");

        // 等待任务因错误停止
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!periodic.is_running());
    }

    #[tokio::test]
    async fn test_periodic_stop_idempotent() {
        let periodic = Periodic::new(Duration::from_millis(100));
        periodic.stop();
        periodic.stop();
        assert!(!periodic.is_running());
    }
}
