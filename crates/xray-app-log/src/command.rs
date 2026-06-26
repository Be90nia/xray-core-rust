//! xray-app-log command gRPC 服务编排 trait。
//!
//! 对应 Go `app/log/command/command.go`：仅暴露 `RestartLogger` 一个 RPC。
//! 不引入 tonic，gRPC server 由上层注入 `LogServiceRegistrar` 实现。

use std::sync::Arc;

use crate::error::LogError;
use crate::instance::{HandlerCreatorRegistry, LogInstance};

/// Log 服务 trait：暴露 restart RPC。
///
/// 对应 Go `LoggerServer.RestartLogger`。
pub trait LogService: Send + Sync {
    fn restart_logger(&self) -> Result<(), LogError>;
}

/// gRPC server 注册 trait（与 commander/proxyman/stats 同模式）。
pub trait LogServiceRegistrar: Send + Sync {
    fn register_log_service(&self, service: Arc<dyn LogService>) -> Result<(), LogError>;
}

/// Noop registrar：测试用。
pub struct NoopLogServiceRegistrar;
impl LogServiceRegistrar for NoopLogServiceRegistrar {
    fn register_log_service(&self, _service: Arc<dyn LogService>) -> Result<(), LogError> {
        Ok(())
    }
}

/// 默认实现：持有一个 LogInstance + HandlerCreatorRegistry 引用，
/// 调用 instance.restart() 完成重启。
pub struct DefaultLogService {
    instance: Arc<LogInstance>,
    registry: Arc<HandlerCreatorRegistry>,
}

impl DefaultLogService {
    pub fn new(instance: Arc<LogInstance>, registry: Arc<HandlerCreatorRegistry>) -> Self {
        Self { instance, registry }
    }
}

impl LogService for DefaultLogService {
    fn restart_logger(&self) -> Result<(), LogError> {
        self.instance.restart(&self.registry)
    }
}

/// 服务描述元数据（用于上层 gRPC 注册）。
pub struct LogServiceDescriptor;

impl LogServiceDescriptor {
    /// 服务名（与 Go `LoggerService_ServiceDesc.ServiceName` 一致）。
    pub const SERVICE_NAME: &'static str = "xray.app.log.command.LoggerService";

    /// 兼容旧名（v2ray.core 兼容服务名）。
    pub const LEGACY_SERVICE_NAME: &'static str = "v2ray.core.app.log.command.LoggerService";

    /// type_url（与 commander 的 Service trait 模式一致）。
    pub const TYPE_URL: &'static str = "xray.app.log.command.Config";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogConfig;

    struct FailingInstance {
        fail: bool,
    }
    impl LogService for FailingInstance {
        fn restart_logger(&self) -> Result<(), LogError> {
            if self.fail {
                Err(LogError::NotActive)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn descriptor_constants() {
        assert_eq!(LogServiceDescriptor::SERVICE_NAME, "xray.app.log.command.LoggerService");
        assert_eq!(
            LogServiceDescriptor::LEGACY_SERVICE_NAME,
            "v2ray.core.app.log.command.LoggerService"
        );
        assert!(!LogServiceDescriptor::TYPE_URL.contains("LoggerService"));
        assert!(LogServiceDescriptor::TYPE_URL.ends_with("Config"));
    }

    #[test]
    fn noop_registrar_always_ok() {
        let r = NoopLogServiceRegistrar;
        let inst: Arc<dyn LogService> = Arc::new(FailingInstance { fail: false });
        assert!(r.register_log_service(inst).is_ok());
    }

    #[test]
    fn default_service_restart_invokes_instance() {
        let cfg = LogConfig::default();
        let inst = Arc::new(LogInstance::new(cfg).unwrap());
        let reg = Arc::new(HandlerCreatorRegistry::new());
        reg.register(crate::config::LogType::Console, Arc::new(crate::instance::NoneHandlerCreator))
            .unwrap();
        reg.register(crate::config::LogType::None, Arc::new(crate::instance::NoneHandlerCreator))
            .unwrap();
        let svc = DefaultLogService::new(inst.clone(), reg);
        svc.restart_logger().unwrap();
        assert!(inst.is_active());
    }

    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn types_are_send_sync() {
        _assert_send_sync::<DefaultLogService>();
        _assert_send_sync::<NoopLogServiceRegistrar>();
        _assert_send_sync::<Arc<dyn LogService>>();
        _assert_send_sync::<Arc<dyn LogServiceRegistrar>>();
    }
}
