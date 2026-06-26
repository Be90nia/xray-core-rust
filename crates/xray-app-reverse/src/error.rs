//! xray-app-reverse 错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReverseError {
    #[error("bridge tag is empty")]
    BridgeTagEmpty,

    #[error("bridge domain is empty")]
    BridgeDomainEmpty,

    #[error("portal tag is empty")]
    PortalTagEmpty,

    #[error("portal domain is empty")]
    PortalDomainEmpty,

    #[error("no mux worker available")]
    NoWorkerAvailable,

    #[error("empty worker list")]
    EmptyWorkerList,

    #[error("client worker stopped")]
    WorkerStopped,

    #[error("already disposed")]
    AlreadyDisposed,

    #[error("unable to dispatch control connection")]
    DispatchControlFailed,

    #[error("outbound metadata not found")]
    OutboundMetadataMissing,

    #[error("failed to create mux client worker: {0}")]
    CreateClientWorker(String),

    #[error("failed to create portal worker: {0}")]
    CreatePortalWorker(String),

    #[error("failed to create bridge worker: {0}")]
    CreateBridgeWorker(String),

    #[error("bridge monitor failed: {0}")]
    MonitorFailed(String),

    #[error("portal dispatch failed: {0}")]
    PortalDispatchFailed(String),

    #[error("invalid control state: {0}")]
    InvalidControlState(i32),

    #[error("proto marshal/unmarshal failed: {0}")]
    ProtoError(String),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub fn at_warning(err: &ReverseError) {
    tracing::warn!(target: "xray_app_reverse", "{err}");
}

pub fn at_error(err: &ReverseError) {
    tracing::error!(target: "xray_app_reverse", "{err}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_bridge_tag_empty() {
        assert!(format!("{}", ReverseError::BridgeTagEmpty).contains("bridge tag"));
    }

    #[test]
    fn display_portal_domain_empty() {
        assert!(format!("{}", ReverseError::PortalDomainEmpty).contains("portal domain"));
    }

    #[test]
    fn display_no_worker() {
        assert!(format!("{}", ReverseError::NoWorkerAvailable).contains("worker"));
    }

    #[test]
    fn display_create_client_failed() {
        let e = ReverseError::CreateClientWorker("conn refused".into());
        assert!(format!("{e}").contains("conn refused"));
    }

    #[test]
    fn display_proto_error() {
        let e = ReverseError::ProtoError("decode fail".into());
        assert!(format!("{e}").contains("decode fail"));
    }

    #[test]
    fn display_invalid_control_state() {
        let e = ReverseError::InvalidControlState(99);
        assert!(format!("{e}").contains("99"));
    }

    #[test]
    fn at_warning_no_panic() {
        at_warning(&ReverseError::WorkerStopped);
    }

    #[test]
    fn at_error_no_panic() {
        at_error(&ReverseError::EmptyWorkerList);
    }
}
