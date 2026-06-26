//! Observatory command gRPC 编排 trait。
//!
//! 对应 Go `app/observatory/command/command.go`：仅暴露 `GetOutboundStatus` RPC。

use std::sync::Arc;

use crate::config::ObservationResult;
use crate::error::ObservatoryError;

/// ObservationProvider trait：暴露当前观测快照。
///
/// 对应 Go `extension.Observatory.GetObservation(ctx)`。
pub trait ObservationProvider: Send + Sync {
    fn get_observation(&self) -> Result<ObservationResult, ObservatoryError>;
}

/// gRPC server 注册 trait（与 commander/proxyman/stats/log 同模式）。
pub trait ObservatoryServiceRegistrar: Send + Sync {
    fn register_observatory_service(
        &self,
        service: Arc<dyn ObservatoryService>,
    ) -> Result<(), ObservatoryError>;
}

/// ObservatoryService trait：暴露 GetOutboundStatus RPC。
pub trait ObservatoryService: Send + Sync {
    fn get_outbound_status(&self) -> Result<ObservationResult, ObservatoryError>;
}

/// Noop registrar：测试用。
pub struct NoopObservatoryServiceRegistrar;
impl ObservatoryServiceRegistrar for NoopObservatoryServiceRegistrar {
    fn register_observatory_service(
        &self,
        _service: Arc<dyn ObservatoryService>,
    ) -> Result<(), ObservatoryError> {
        Ok(())
    }
}

/// 默认实现：包装 ObservationProvider，调用 provider.get_observation。
pub struct DefaultObservatoryService {
    provider: Arc<dyn ObservationProvider>,
}

impl DefaultObservatoryService {
    pub fn new(provider: Arc<dyn ObservationProvider>) -> Self {
        Self { provider }
    }
}

impl ObservatoryService for DefaultObservatoryService {
    fn get_outbound_status(&self) -> Result<ObservationResult, ObservatoryError> {
        self.provider.get_observation()
    }
}

/// 服务描述元数据。
pub struct ObservatoryServiceDescriptor;

impl ObservatoryServiceDescriptor {
    pub const SERVICE_NAME: &'static str = "xray.core.app.observatory.ObservatoryService";

    pub const LEGACY_SERVICE_NAME: &'static str = "v2ray.core.app.observatory.ObservatoryService";

    pub const TYPE_URL: &'static str = "xray.core.app.observatory.command.Config";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundStatus;

    struct FixedProvider {
        result: ObservationResult,
        fail: bool,
    }

    impl ObservationProvider for FixedProvider {
        fn get_observation(&self) -> Result<ObservationResult, ObservatoryError> {
            if self.fail {
                Err(ObservatoryError::NoObservation)
            } else {
                Ok(self.result.clone())
            }
        }
    }

    #[test]
    fn descriptor_constants() {
        assert!(ObservatoryServiceDescriptor::SERVICE_NAME.contains("ObservatoryService"));
        assert_eq!(
            ObservatoryServiceDescriptor::LEGACY_SERVICE_NAME,
            "v2ray.core.app.observatory.ObservatoryService"
        );
        assert!(ObservatoryServiceDescriptor::TYPE_URL.ends_with("Config"));
    }

    #[test]
    fn noop_registrar_always_ok() {
        let r = NoopObservatoryServiceRegistrar;
        let svc: Arc<dyn ObservatoryService> = Arc::new(DefaultObservatoryService::new(
            Arc::new(FixedProvider {
                result: ObservationResult::default(),
                fail: false,
            }),
        ));
        assert!(r.register_observatory_service(svc).is_ok());
    }

    #[test]
    fn default_service_returns_provider_result() {
        let provider = Arc::new(FixedProvider {
            result: ObservationResult {
                status: vec![OutboundStatus {
                    outbound_tag: "x".into(),
                    alive: true,
                    delay: 10,
                    ..Default::default()
                }],
            },
            fail: false,
        });
        let svc = DefaultObservatoryService::new(provider);
        let r = svc.get_outbound_status().unwrap();
        assert_eq!(r.status.len(), 1);
        assert_eq!(r.status[0].outbound_tag, "x");
    }

    #[test]
    fn default_service_propagates_provider_error() {
        let provider = Arc::new(FixedProvider {
            result: ObservationResult::default(),
            fail: true,
        });
        let svc = DefaultObservatoryService::new(provider);
        let err = svc.get_outbound_status().unwrap_err();
        assert!(matches!(err, ObservatoryError::NoObservation));
    }
}
