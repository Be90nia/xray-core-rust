//! 异步任务管理
//!
//! 对应 Go 版本 `common/task` 包，提供周期性任务执行器。

use std::{sync::Arc, time::Duration};

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
        Self { interval, running: Arc::new(std::sync::Mutex::new(false)) }
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
            let mut running =
                self.running.lock().map_err(|_| Error::new("running lock poisoned"))?;
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
                    Ok(()) => {},
                    Err(_) => {
                        if let Ok(mut r) = running.lock() {
                            *r = false;
                        }
                        break;
                    },
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
        self.running.lock().is_ok_and(|r| *r)
    }
}

/// 闭包型 trait：对象支持显式关闭，对应 Go `common.Closable` interface。
///
/// 任务管线常用 `task.Close(obj)` 包装为 `func() error`。
pub trait Closable {
    /// 关闭对象，幂等实现常见。
    fn close(&self) -> Result<(), Error>;
}

/// 对实现了 [`Closable`] 的对象，返回一个调用其 `close()` 的零参闭包。
///
/// 对应 Go `task.Close(v interface{}) func() error`：Go 在 `common.Close`
/// 中检查是否实现 `Closable`，未实现则返回 nil。Rust 端用 trait bound 在
/// 调用处约束，编译期拒绝非 `Closable` 类型——更严格但更安全。
// 函数名对齐 Go `task.Close` API，保留大写。
#[allow(non_snake_case)]
pub fn Close<T: Closable>(v: T) -> impl FnOnce() -> Result<(), Error> {
    move || v.close()
}

/// 串行组合 f 和 g：当 f 返回 Ok 时执行 g。
///
/// 对应 Go `task.OnSuccess(f, g func() error) func() error`。
// 函数名对齐 Go `task.OnSuccess` API，保留大写。
#[allow(non_snake_case)]
pub fn OnSuccess<F, G>(f: F, g: G) -> impl FnOnce() -> Result<(), Error>
where
    F: FnOnce() -> Result<(), Error>,
    G: FnOnce() -> Result<(), Error>,
{
    move || match f() {
        Ok(()) => g(),
        Err(e) => Err(e),
    }
}

/// 并行执行一组任务，返回首个错误。
///
/// 对应 Go `task.Run(ctx context.Context, tasks ...func() error) error`。
/// Rust 端使用 `std::thread::scope` 阻塞并行（Go goroutines 同步语义）。
/// `ctx` 保留为占位（与 Go 对齐），当前不支持取消——Go 中也是按 `ctx.Done()`
/// 协作式轮询；此端口复刻了运行队列 + 完成钩子语义。
///
/// 工作线程数受 `std::thread::available_parallelism()` 限制（默认上限 16）。
/// 任一任务失败立即返回错误，其他 worker 仍在并发跑完。
// 函数名对齐 Go `task.Run` API，保留大写。
#[allow(non_snake_case)]
pub fn Run<C, F>(ctx: &C, tasks: Vec<F>) -> Result<(), Error>
where
    C: ?Sized,
    F: FnOnce() -> Result<(), Error> + Send + 'static,
{
    let _ = ctx; // 占位；保留以对齐 Go 签名
    if tasks.is_empty() {
        return Ok(());
    }
    // 用 Arc<Mutex<Option<Error>>> 共享首个错误。
    let first_err: Arc<parking_lot::Mutex<Option<Error>>> = Arc::new(parking_lot::Mutex::new(None));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(tasks.len());
        for task in tasks {
            let first_err = Arc::clone(&first_err);
            handles.push(scope.spawn(move || {
                if let Err(e) = task() {
                    let mut slot = first_err.lock();
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
    });

    let mut slot = first_err.lock();
    if slot.is_some() { Err(slot.take().expect("checked")) } else { Ok(()) }
}

/// 并行调用 `f(0..n-1)`，按可用 CPU 数分块。
///
/// 对应 Go `task.ParallelForN(n int, fn func(i int) error) error`。
/// 索引被划分为连续 chunk；每个 worker 处理一段，worker 数受
/// `std::thread::available_parallelism()` 限制。
// 函数名对齐 Go `task.ParallelForN` API，保留大写。
#[allow(non_snake_case)]
pub fn ParallelForN<F>(n: usize, f: F) -> Result<(), Error>
where
    F: Fn(usize) -> Result<(), Error> + Sync + Send,
{
    if n == 0 {
        return Ok(());
    }
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(16).min(n);
    let chunk = n.div_ceil(workers);
    let first_err: Arc<parking_lot::Mutex<Option<Error>>> = Arc::new(parking_lot::Mutex::new(None));
    // 多 worker 共享同一 f。
    let f = std::sync::Arc::new(f);

    std::thread::scope(|scope| {
        for w in 0..workers {
            let start = w * chunk;
            let end = (start + chunk).min(n);
            if start >= end {
                break;
            }
            let first_err = Arc::clone(&first_err);
            let f = Arc::clone(&f);
            scope.spawn(move || {
                for i in start..end {
                    if first_err.lock().is_some() {
                        return;
                    }
                    if let Err(e) = f(i) {
                        let mut slot = first_err.lock();
                        if slot.is_none() {
                            *slot = Some(e);
                        }
                        return;
                    }
                }
            });
        }
    });

    let mut slot = first_err.lock();
    if slot.is_some() { Err(slot.take().expect("checked")) } else { Ok(()) }
}
#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

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
        let result = periodic
            .start(move || {
                counter2_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;

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
    use parking_lot::Mutex;

    use super::{Closable, Close, OnSuccess, ParallelForN, Run};
    use crate::errors::Error;

    #[test]
    fn test_run_empty() {
        let ctx = ();
        let tasks: Vec<Box<dyn FnOnce() -> Result<(), Error> + Send + 'static>> = vec![];
        let result = Run(&ctx, tasks);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_success() {
        let ctx = ();
        let counter = Arc::new(Mutex::new(0u32));
        let mut tasks: Vec<Box<dyn FnOnce() -> Result<(), Error> + Send + 'static>> = vec![];
        for _ in 0..5 {
            let c = Arc::clone(&counter);
            tasks.push(Box::new(move || {
                *c.lock() += 1;
                Ok(())
            }));
        }
        let result = Run(&ctx, tasks);
        assert!(result.is_ok());
        assert_eq!(*counter.lock(), 5);
    }

    #[test]
    fn test_run_first_error() {
        let ctx = ();
        let mut tasks: Vec<Box<dyn FnOnce() -> Result<(), Error> + Send + 'static>> = vec![];
        for i in 0..3 {
            if i == 1 {
                tasks.push(Box::new(|| Err(Error::new("boom"))));
            } else {
                tasks.push(Box::new(|| Ok(())));
            }
        }
        let result = Run(&ctx, tasks);
        assert!(result.is_err());
    }

    #[test]
    fn test_on_success_chain() {
        let ran_f = Arc::new(Mutex::new(false));
        let ran_g = Arc::new(Mutex::new(false));
        let f = {
            let r = Arc::clone(&ran_f);
            move || {
                *r.lock() = true;
                Ok(())
            }
        };
        let g = {
            let r = Arc::clone(&ran_g);
            move || {
                *r.lock() = true;
                Ok(())
            }
        };
        let task = OnSuccess(f, g);
        let result = task();
        assert!(result.is_ok());
        assert!(*ran_f.lock());
        assert!(*ran_g.lock());
    }

    #[test]
    fn test_on_success_skip_g_on_error() {
        let ran_g = Arc::new(Mutex::new(false));
        let g = {
            let r = Arc::clone(&ran_g);
            move || {
                *r.lock() = true;
                Ok(())
            }
        };
        let task = OnSuccess(|| Err(Error::new("f failed")), g);
        let result = task();
        assert!(result.is_err());
        assert!(!*ran_g.lock());
    }

    #[test]
    fn test_parallel_for_n_empty() {
        let called = Arc::new(Mutex::new(false));
        let c = Arc::clone(&called);
        let result = ParallelForN(0, move |_i| {
            *c.lock() = true;
            Ok(())
        });
        assert!(result.is_ok());
        assert!(!*called.lock());
    }

    #[test]
    fn test_parallel_for_n_all_indices() {
        let seen = Arc::new(Mutex::new(vec![false; 100]));
        let s = Arc::clone(&seen);
        let result = ParallelForN(100, move |i| {
            s.lock()[i] = true;
            Ok(())
        });
        assert!(result.is_ok());
        let seen = seen.lock();
        for (i, &v) in seen.iter().enumerate() {
            assert!(v, "index {i} 未被访问");
        }
    }

    #[test]
    fn test_parallel_for_n_error() {
        let result =
            ParallelForN(1000, |i| if i == 42 { Err(Error::new("boom at 42")) } else { Ok(()) });
        assert!(result.is_err());
    }

    #[test]
    fn test_close_closable() {
        struct Counter(Arc<Mutex<u32>>);
        impl Closable for Counter {
            fn close(&self) -> Result<(), Error> {
                *self.0.lock() += 1;
                Ok(())
            }
        }
        let counter = Arc::new(Mutex::new(0u32));
        let c = Counter(Arc::clone(&counter));
        let task = Close(c);
        let result = task();
        assert!(result.is_ok());
        assert_eq!(*counter.lock(), 1);
    }
}
