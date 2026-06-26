//! Scheduler trait + GeodataInstance 编排。
//!
//! 对应 Go `app/geodata/geodata.go` 的 `Instance` + cron 调度。

use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::GeodataConfig;
use crate::downloader::{AssetDownloader, GeodataReloader, reload_with_update};
use crate::error::{at_error, at_warning, GeodataError};

/// Scheduler trait：把 cron 表达式 + 回调注册到调度器，返回可取消的 handle。
///
/// 对应 Go `cron.Cron` + `tasker.AddFunc`。具体 cron 解析由上层实现。
pub trait Scheduler: Send + Sync {
    /// 注册一个 cron 调度的回调。
    fn schedule(
        &self,
        cron_expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<ScheduleHandle, GeodataError>;
}

/// 调度句柄：可 cancel 一个已注册的任务。
pub struct ScheduleHandle {
    cancel: Box<dyn FnOnce() + Send>,
}

impl ScheduleHandle {
    pub fn new(cancel: impl FnOnce() + Send + 'static) -> Self {
        Self {
            cancel: Box::new(cancel),
        }
    }

    /// 取消调度。
    pub fn cancel(self) {
        (self.cancel)();
    }
}

/// Noop scheduler：测试用，不实际调度。
pub struct NoopScheduler;
impl Scheduler for NoopScheduler {
    fn schedule(
        &self,
        _cron: &str,
        _cb: Box<dyn Fn() + Send + Sync>,
    ) -> Result<ScheduleHandle, GeodataError> {
        Ok(ScheduleHandle::new(|| {}))
    }
}

/// GeodataInstance：geodata crate 的主编排类。
///
/// 持有 config + downloader + reloader，编排：
///   - `start()`：通过 scheduler 注册 cron 调度
///   - `execute()`：手动触发一次 reload（cron 调度的回调内会调用此方法）
///   - `close()`：取消调度
pub struct GeodataInstance {
    config: GeodataConfig,
    state: Mutex<InstanceState>,
}

struct InstanceState {
    running: bool,
    handle: Option<ScheduleHandle>,
}

impl GeodataInstance {
    pub fn new(config: GeodataConfig) -> Self {
        Self {
            config,
            state: Mutex::new(InstanceState {
                running: false,
                handle: None,
            }),
        }
    }

    pub fn config(&self) -> &GeodataConfig {
        &self.config
    }

    pub fn is_running(&self) -> bool {
        self.state.lock().running
    }

    /// Start：通过 scheduler 注册 cron 调度。
    ///
    /// 若 config.cron 为空，则不调度（与 Go 版 `if config.Cron == ""` 一致）。
    pub fn start(
        &self,
        scheduler: &dyn Scheduler,
    ) -> Result<(), GeodataError> {
        let mut g = self.state.lock();
        if g.running {
            return Err(GeodataError::AlreadyRunning);
        }

        if !self.config.cron.is_empty() {
            let handle = scheduler.schedule(&self.config.cron, Box::new(|| {}))?;
            g.handle = Some(handle);
        }
        g.running = true;
        Ok(())
    }

    /// Close：取消调度。
    pub fn close(&self) -> Result<(), GeodataError> {
        let mut g = self.state.lock();
        if !g.running {
            return Err(GeodataError::NotRunning);
        }
        if let Some(h) = g.handle.take() {
            h.cancel();
        }
        g.running = false;
        Ok(())
    }

    /// 执行一次 reload（含 download + swap）。
    ///
    /// 对应 Go `Instance.execute` + `reloadWithUpdate`。
    pub fn execute<D: AssetDownloader, R: GeodataReloader>(
        &self,
        downloader: &D,
        reloader: &R,
    ) -> Result<(), GeodataError> {
        if self.config.assets.is_empty() {
            // 无 asset：仅 reload
            return reloader.reload();
        }
        reload_with_update(downloader, reloader, &self.config.assets).map_err(|e| {
            at_error(&e);
            e
        })
    }

    /// 仅 reload（不下载，与 Go `reload()` 等价）。
    pub fn reload_only<R: GeodataReloader>(&self, reloader: &R) -> Result<(), GeodataError> {
        reloader.reload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting_scheduler() -> (Arc<CountingScheduler>, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let s = Arc::new(CountingScheduler {
            counter: counter.clone(),
        });
        (s, counter)
    }

    struct CountingScheduler {
        counter: Arc<AtomicUsize>,
    }

    impl Scheduler for CountingScheduler {
        fn schedule(
            &self,
            _cron: &str,
            _cb: Box<dyn Fn() + Send + Sync>,
        ) -> Result<ScheduleHandle, GeodataError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(ScheduleHandle::new(|| {}))
        }
    }

    #[test]
    fn instance_with_empty_cron_does_not_schedule() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        let (s, c) = counting_scheduler();
        inst.start(&*s).unwrap();
        assert!(inst.is_running());
        assert_eq!(c.load(Ordering::SeqCst), 0);
        inst.close().unwrap();
    }

    #[test]
    fn instance_with_cron_schedules_once() {
        let cfg = GeodataConfig {
            cron: "0 0 * * *".into(),
            ..Default::default()
        };
        let inst = GeodataInstance::new(cfg);
        let (s, c) = counting_scheduler();
        inst.start(&*s).unwrap();
        assert_eq!(c.load(Ordering::SeqCst), 1);
        inst.close().unwrap();
    }

    #[test]
    fn instance_start_twice_errors() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        let (s, _) = counting_scheduler();
        inst.start(&*s).unwrap();
        let err = inst.start(&*s).unwrap_err();
        assert!(matches!(err, GeodataError::AlreadyRunning));
        inst.close().unwrap();
    }

    #[test]
    fn instance_close_without_start_errors() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        let err = inst.close().unwrap_err();
        assert!(matches!(err, GeodataError::NotRunning));
    }

    #[test]
    fn instance_close_after_start_succeeds() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        let (s, _) = counting_scheduler();
        inst.start(&*s).unwrap();
        inst.close().unwrap();
        assert!(!inst.is_running());
    }

    #[test]
    fn instance_restart_after_close() {
        let cfg = GeodataConfig {
            cron: "*".into(),
            ..Default::default()
        };
        let inst = GeodataInstance::new(cfg);
        let (s, _) = counting_scheduler();
        inst.start(&*s).unwrap();
        inst.close().unwrap();
        inst.start(&*s).unwrap();
        assert!(inst.is_running());
        inst.close().unwrap();
    }

    #[test]
    fn noop_scheduler_returns_handle() {
        let s = NoopScheduler;
        let h = s.schedule("*", Box::new(|| {})).unwrap();
        h.cancel(); // no panic
    }

    struct RecordingDownloader {
        dir: std::path::PathBuf,
    }
    impl AssetDownloader for RecordingDownloader {
        fn download_to(
            &self,
            _url: &str,
            temp: &std::path::Path,
        ) -> Result<(), GeodataError> {
            std::fs::write(temp, b"x").unwrap();
            Ok(())
        }
        fn resolve_target(&self, file: &str) -> Result<std::path::PathBuf, GeodataError> {
            Ok(self.dir.join(file))
        }
    }

    #[test]
    fn execute_with_empty_assets_calls_only_reload() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        struct CountingReloader(Mutex<u32>);
        impl GeodataReloader for CountingReloader {
            fn reload(&self) -> Result<(), GeodataError> {
                *self.0.lock() += 1;
                Ok(())
            }
        }
        let r = CountingReloader(Mutex::new(0));
        inst.execute(&RecordingDownloader { dir: std::env::temp_dir() }, &r).unwrap();
        assert_eq!(*r.0.lock(), 1);
    }

    #[test]
    fn reload_only_invokes_reloader() {
        let cfg = GeodataConfig::default();
        let inst = GeodataInstance::new(cfg);
        struct Once;
        impl GeodataReloader for Once {
            fn reload(&self) -> Result<(), GeodataError> {
                Ok(())
            }
        }
        inst.reload_only(&Once).unwrap();
    }

    #[test]
    fn schedule_handle_cancel_does_not_panic() {
        let called = Arc::new(AtomicUsize::new(0));
        let c = called.clone();
        let h = ScheduleHandle::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        h.cancel();
        assert_eq!(called.load(Ordering::SeqCst), 1);
    }
}
