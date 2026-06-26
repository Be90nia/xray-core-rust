//! xray-app-log 错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("invalid log type: {0}")]
    InvalidLogType(i32),

    #[error("invalid severity: {0}")]
    InvalidSeverity(i32),

    #[error("invalid mask address spec: {0}")]
    InvalidMaskAddress(String),

    #[error("ipv4 mask must be divisible by 8 and between 0-32, got {0}")]
    InvalidIpv4Mask(i32),

    #[error("ipv6 mask must be between 0-128, got {0}")]
    InvalidIpv6Mask(i32),

    #[error("handler creator already registered for log type {0:?}")]
    DuplicateHandlerCreator(crate::config::LogType),

    #[error("no handler creator registered for log type {0:?}")]
    NoHandlerCreator(crate::config::LogType),

    #[error("handler creation failed: {0}")]
    HandlerCreate(String),

    #[error("logger not active")]
    NotActive,

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub fn at_warning(err: &LogError) {
    tracing::warn!(target: "xray_app_log", "{err}");
}

pub fn at_error(err: &LogError) {
    tracing::error!(target: "xray_app_log", "{err}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogType;

    #[test]
    fn display_invalid_log_type() {
        let e = LogError::InvalidLogType(99);
        assert!(format!("{e}").contains("99"));
    }

    #[test]
    fn display_invalid_severity() {
        let e = LogError::InvalidSeverity(42);
        assert!(format!("{e}").contains("42"));
    }

    #[test]
    fn display_invalid_mask_address() {
        let e = LogError::InvalidMaskAddress("foo".into());
        assert!(format!("{e}").contains("foo"));
    }

    #[test]
    fn display_invalid_ipv4_mask() {
        let e = LogError::InvalidIpv4Mask(7);
        assert!(format!("{e}").contains("7"));
    }

    #[test]
    fn display_invalid_ipv6_mask() {
        let e = LogError::InvalidIpv6Mask(200);
        assert!(format!("{e}").contains("200"));
    }

    #[test]
    fn display_duplicate_handler_creator() {
        let e = LogError::DuplicateHandlerCreator(LogType::Console);
        let s = format!("{e}");
        assert!(s.contains("Console"));
    }

    #[test]
    fn display_no_handler_creator() {
        let e = LogError::NoHandlerCreator(LogType::File);
        let s = format!("{e}");
        assert!(s.contains("File"));
    }

    #[test]
    fn display_handler_create() {
        let e = LogError::HandlerCreate("permission denied".into());
        assert!(format!("{e}").contains("permission denied"));
    }

    #[test]
    fn display_not_active() {
        let e = LogError::NotActive;
        assert_eq!(format!("{e}"), "logger not active");
    }

    #[test]
    fn at_warning_and_error_no_panic() {
        at_warning(&LogError::NotActive);
        at_error(&LogError::NotActive);
    }
}
