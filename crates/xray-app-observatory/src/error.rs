//! xray-app-observatory 错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObservatoryError {
    #[error("no observation available")]
    NoObservation,

    #[error("outbound manager does not implement HandlerSelector")]
    NotHandlerSelector,

    #[error("probe failed for outbound {outbound}: {reason}")]
    ProbeFailed { outbound: String, reason: String },

    #[error("select outbounds failed: {0}")]
    SelectFailed(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("invalid probe url: {0}")]
    InvalidProbeUrl(String),

    #[error("invalid http method: {0}")]
    InvalidHttpMethod(String),

    #[error("observer already started")]
    AlreadyStarted,

    #[error("observer not started")]
    NotStarted,

    #[error("underlying connection error: {0}")]
    UnderlyingConnectionError(String),

    #[error("failed to produce report")]
    FailedToProduceReport,

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub fn at_warning(err: &ObservatoryError) {
    tracing::warn!(target: "xray_app_observatory", "{err}");
}

pub fn at_error(err: &ObservatoryError) {
    tracing::error!(target: "xray_app_observatory", "{err}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_no_observation() {
        let e = ObservatoryError::NoObservation;
        assert!(format!("{e}").contains("observation"));
    }

    #[test]
    fn display_probe_failed() {
        let e = ObservatoryError::ProbeFailed {
            outbound: "out".into(),
            reason: "timeout".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("out"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn display_invalid_probe_url() {
        let e = ObservatoryError::InvalidProbeUrl("bad".into());
        assert!(format!("{e}").contains("bad"));
    }

    #[test]
    fn display_already_started() {
        let e = ObservatoryError::AlreadyStarted;
        assert!(format!("{e}").contains("already"));
    }

    #[test]
    fn display_underlying_conn() {
        let e = ObservatoryError::UnderlyingConnectionError("refused".into());
        assert!(format!("{e}").contains("refused"));
    }

    #[test]
    fn display_failed_to_produce_report() {
        let e = ObservatoryError::FailedToProduceReport;
        assert!(format!("{e}").contains("report"));
    }

    #[test]
    fn at_warning_no_panic() {
        at_warning(&ObservatoryError::NoObservation);
    }
}
