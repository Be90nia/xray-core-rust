//! LogFeature —— 将 Log app 接入 Feature 系统。
//!
//! 对应 Go `app/log/log.go` 中 `Instance` 作为 `features.Feature` 的角色。
//! 在 `start()` 中注册默认 handler creators 并创建 LogInstance。

use std::sync::Arc;

use xray_features::{Feature, FeatureError, Result};

use crate::{
    command::DefaultLogService,
    config::LogConfig,
    instance::{HandlerCreatorRegistry, LogInstance, register_default_creators},
};

/// Log app Feature 实现。
///
/// 持有 LogInstance + HandlerCreatorRegistry，在 start() 中：
/// 1. 注册 None/Console/File handler creators
/// 2. 创建 LogInstance 并启动
pub struct LogFeature {
    instance: Arc<LogInstance>,
    registry: Arc<HandlerCreatorRegistry>,
}

impl LogFeature {
    /// 从配置创建 LogFeature。
    pub fn new(config: LogConfig) -> Result<Self> {
        let registry = Arc::new(HandlerCreatorRegistry::new());
        let instance = Arc::new(
            LogInstance::new(config)
                .map_err(|e| FeatureError::StartFailed { name: "log", message: e.to_string() })?,
        );
        Ok(Self { instance, registry })
    }

    /// 获取 LogInstance 引用。
    pub fn instance(&self) -> &Arc<LogInstance> {
        &self.instance
    }

    /// 获取 HandlerCreatorRegistry 引用。
    pub fn registry(&self) -> &Arc<HandlerCreatorRegistry> {
        &self.registry
    }

    /// 获取 DefaultLogService（用于 gRPC 注册）。
    pub fn log_service(&self) -> Arc<DefaultLogService> {
        Arc::new(DefaultLogService::new(self.instance.clone(), self.registry.clone()))
    }
}

impl Feature for LogFeature {
    fn feature_name(&self) -> &'static str {
        "log"
    }

    fn start(&self) -> Result<()> {
        register_default_creators(&self.registry)
            .map_err(|e| FeatureError::StartFailed { name: "log", message: e.to_string() })?;
        self.instance
            .start(&self.registry)
            .map_err(|e| FeatureError::StartFailed { name: "log", message: e.to_string() })
    }

    fn close(&self) -> Result<()> {
        self.instance.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{command::LogService, config::LogType, instance::HandlerCreatorOptions};

    #[test]
    fn log_feature_start_registers_creators_and_starts_instance() {
        let cfg = LogConfig::default();
        let feature = LogFeature::new(cfg).unwrap();
        assert!(feature.start().is_ok());
        assert!(feature.instance.is_active());
        // Verify creators work by creating handlers
        let opts = HandlerCreatorOptions::default();
        let console = feature.registry.create(LogType::Console, &opts).unwrap();
        assert!(console.is_some());
        let file = feature.registry.create(LogType::File, &opts);
        // File without path should error
        assert!(file.is_err());
    }

    #[test]
    fn log_feature_close_stops_instance() {
        let cfg = LogConfig::default();
        let feature = LogFeature::new(cfg).unwrap();
        feature.start().unwrap();
        assert!(feature.close().is_ok());
        assert!(!feature.instance.is_active());
    }
    #[test]
    fn log_feature_log_service_returns_service() {
        let cfg = LogConfig::default();
        let feature = LogFeature::new(cfg).unwrap();
        let svc = feature.log_service();
        // restart_logger works even before start (restart re-creates handlers)
        assert!(svc.restart_logger().is_ok());
    }

    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn log_feature_is_send_sync() {
        _assert_send_sync::<LogFeature>();
        _assert_send_sync::<Arc<LogFeature>>();
    }
}
