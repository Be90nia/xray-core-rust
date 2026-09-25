//! GeodataFeature —— 将 xray-app-geodata 接入 Feature 系统。
//!
//! 对应 Go `app/geodata/geodata.go` 的 `Instance`（实现 `features.Feature`）。
//! 解决 bd issue Xray-core-rust-gpc：之前 `register.rs` 把 geodata 注册为
//! `SimpleFeature` no-op，`GeodataInstance` 从不实例化，cron 自动下载 + swap
//! reload 全是死代码。
//!
//! 本模块把 `GeodataInstance` 包成 `Feature`，在 `start()` 中：
//! 1. 构造执行闭包（捕获 downloader + reloader Arc 句柄）
//! 2. 通过 `Scheduler` 注册 cron 回调
//! 3. 回调真正调用 `execute()` —— 不是占位的 `|| {}`
//!
//! `close()` 取消调度 handle。

use std::sync::Arc;

use xray_features::{Feature, FeatureError};

use crate::{
    config::GeodataConfig,
    downloader::{AssetDownloader, GeodataReloader},
    instance::{GeodataInstance, Scheduler},
};

/// Geodata app Feature 实现。
///
/// 持有 `Arc<GeodataInstance>` + scheduler/downloader/reloader 三个 trait object。
/// `start()` 把真正的 `execute()` 闭包传给 `GeodataInstance::start_with_callback`，
/// 不再用 `|| {}` 占位。
pub struct GeodataFeature {
    instance: Arc<GeodataInstance>,
    scheduler: Arc<dyn Scheduler>,
    downloader: Arc<dyn AssetDownloader>,
    reloader: Arc<dyn GeodataReloader>,
}

impl GeodataFeature {
    /// 从配置 + 注入的 scheduler/downloader/reloader 构造。
    pub fn new(
        config: GeodataConfig,
        scheduler: Arc<dyn Scheduler>,
        downloader: Arc<dyn AssetDownloader>,
        reloader: Arc<dyn GeodataReloader>,
    ) -> Self {
        Self { instance: Arc::new(GeodataInstance::new(config)), scheduler, downloader, reloader }
    }

    /// 暴露内部 instance（测试与探针用）。
    pub fn instance(&self) -> &Arc<GeodataInstance> {
        &self.instance
    }
}

impl Feature for GeodataFeature {
    fn feature_name(&self) -> &'static str {
        "geodata"
    }

    fn start(&self) -> xray_features::Result<()> {
        // 闭包捕获 Arc clone；`GeodataInstance::execute` 错误仅记录（与 Go
        // `errors.LogInfo` + `errors.LogError` 等价，不向上传播到 cron tick）。
        let instance = Arc::clone(&self.instance);
        let downloader = Arc::clone(&self.downloader);
        let reloader = Arc::clone(&self.reloader);
        let callback = Box::new(move || {
            let _ = instance.execute(downloader.as_ref(), reloader.as_ref());
        });
        self.instance
            .start_with_callback(self.scheduler.as_ref(), callback)
            .map_err(|e| FeatureError::StartFailed { name: "geodata", message: e.to_string() })
    }

    fn close(&self) -> xray_features::Result<()> {
        self.instance
            .close()
            .map_err(|e| FeatureError::CloseFailed { name: "geodata", message: e.to_string() })
    }
}

fn _assert_send_sync<T: Send + Sync>() {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    use super::*;
    use crate::{
        downloader::{AssetDownloader, GeodataReloader},
        error::GeodataError,
        instance::{ScheduleHandle, Scheduler},
    };

    /// 捕获最近注册的 cron 回调（仅保留最后一次），允许测试触发。
    pub struct CallbackCapturingScheduler {
        captured: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        schedule_calls: AtomicUsize,
    }

    impl CallbackCapturingScheduler {
        pub fn new() -> Arc<Self> {
            Arc::new(Self { captured: Mutex::new(None), schedule_calls: AtomicUsize::new(0) })
        }
    }

    impl Scheduler for CallbackCapturingScheduler {
        fn schedule(
            &self,
            _cron: &str,
            callback: Box<dyn Fn() + Send + Sync>,
        ) -> std::result::Result<ScheduleHandle, GeodataError> {
            self.schedule_calls.fetch_add(1, Ordering::SeqCst);
            *self.captured.lock() = Some(callback);
            Ok(ScheduleHandle::new(|| {}))
        }
    }

    /// 测试用 downloader：成功但不写真实文件。
    pub struct DummyDownloader;
    impl AssetDownloader for DummyDownloader {
        fn download_to(
            &self,
            _url: &str,
            _temp: &std::path::Path,
        ) -> std::result::Result<(), GeodataError> {
            Ok(())
        }

        fn resolve_target(
            &self,
            file: &str,
        ) -> std::result::Result<std::path::PathBuf, GeodataError> {
            Ok(std::env::temp_dir().join(file))
        }
    }

    /// 计数 reloader。
    pub struct CountingReloader(pub Arc<AtomicUsize>);
    impl GeodataReloader for CountingReloader {
        fn reload(&self) -> std::result::Result<(), GeodataError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn feature_name_is_geodata() {
        let scheduler: Arc<CallbackCapturingScheduler> = CallbackCapturingScheduler::new();
        let downloader: Arc<dyn AssetDownloader> = Arc::new(DummyDownloader);
        let reloader: Arc<dyn GeodataReloader> =
            Arc::new(CountingReloader(Arc::new(AtomicUsize::new(0))));
        let feature = GeodataFeature::new(
            GeodataConfig::default(),
            scheduler as Arc<dyn Scheduler>,
            downloader,
            reloader,
        );
        assert_eq!(feature.feature_name(), "geodata");
    }

    #[test]
    fn start_with_empty_cron_does_not_register_callback() {
        let scheduler: Arc<CallbackCapturingScheduler> = CallbackCapturingScheduler::new();
        let downloader: Arc<dyn AssetDownloader> = Arc::new(DummyDownloader);
        let reloader: Arc<dyn GeodataReloader> =
            Arc::new(CountingReloader(Arc::new(AtomicUsize::new(0))));
        let feature = GeodataFeature::new(
            GeodataConfig::default(),
            scheduler.clone() as Arc<dyn Scheduler>,
            downloader,
            reloader,
        );
        feature.start().expect("start should succeed");
        assert_eq!(
            scheduler.schedule_calls.load(Ordering::SeqCst),
            0,
            "empty cron must not schedule (matches Go `if config.Cron == \"\"`)"
        );
        assert!(
            scheduler.captured.lock().is_none(),
            "no callback should be registered for empty cron"
        );
        feature.close().expect("close should succeed");
    }

    /// bd issue Xray-core-rust-gpc 验收测试：cron 非空时，scheduler
    /// 收到的回调**不是空 closure**——它真正调用 `execute()`，进而调用
    /// `reloader.reload()`。
    #[test]
    fn start_with_cron_registers_execute_callback() {
        let scheduler: Arc<CallbackCapturingScheduler> = CallbackCapturingScheduler::new();
        let downloader: Arc<dyn AssetDownloader> = Arc::new(DummyDownloader);
        let reload_count = Arc::new(AtomicUsize::new(0));
        let reloader: Arc<dyn GeodataReloader> =
            Arc::new(CountingReloader(Arc::clone(&reload_count)));

        let feature = GeodataFeature::new(
            GeodataConfig { cron: "* * * * *".into(), ..Default::default() },
            scheduler.clone() as Arc<dyn Scheduler>,
            downloader,
            reloader,
        );
        feature.start().expect("start should succeed");

        // cron 非空 → schedule 调用 1 次
        assert_eq!(
            scheduler.schedule_calls.load(Ordering::SeqCst),
            1,
            "cron set must trigger one schedule() call"
        );

        // 闭包类型 `Box<dyn Fn() + Send + Sync>` 不能直接调用 by-value，
        // 但 Option::take 后是 owned Box<dyn Fn>——可直接调用。
        let cb = scheduler.captured.lock().take();
        assert!(cb.is_some(), "callback must be captured (was `|| {{}}` before fix)");
        cb.unwrap()();

        assert_eq!(
            reload_count.load(Ordering::SeqCst),
            1,
            "registered callback must invoke execute() which calls reloader.reload()"
        );

        feature.close().expect("close should succeed");
    }

    #[test]
    fn feature_is_send_sync() {
        _assert_send_sync::<GeodataFeature>();
    }
}
