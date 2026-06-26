//! xray-app-geodata 错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeodataError {
    #[error("invalid geodata cron expression: {0}")]
    InvalidCron(String),

    #[error("missing dispatcher for geodata downloader")]
    MissingDispatcher,

    #[error("missing outbound tag for geodata downloader")]
    MissingOutbound,

    #[error("tagged dialer not initialized")]
    TaggedDialerMissing,

    #[error("download failed for {url}: {reason}")]
    DownloadFailed { url: String, reason: String },

    #[error("unexpected HTTP status code: {0}")]
    UnexpectedStatus(u16),

    #[error("empty response body from {0}")]
    EmptyResponse(String),

    #[error("redirected to non-https URL: {0}")]
    InsecureRedirect(String),

    #[error("too many redirects (>=10)")]
    TooManyRedirects,

    #[error("connection idle timeout")]
    IdleTimeout,

    #[error("asset file path invalid: {0}")]
    InvalidFilePath(String),

    #[error("temp file create failed for {target}: {reason}")]
    TempFileCreate { target: String, reason: String },

    #[error("backup file create failed for {target}: {reason}")]
    BackupFileCreate { target: String, reason: String },

    #[error("file rename failed from {from} to {to}: {reason}")]
    RenameFailed { from: String, to: String, reason: String },

    #[error("file remove failed for {path}: {reason}")]
    RemoveFailed { path: String, reason: String },

    #[error("file mkdir failed for {path}: {reason}")]
    MkdirFailed { path: String, reason: String },

    #[error("reload failed: {0}")]
    ReloadFailed(String),

    #[error("schedule failed: {0}")]
    ScheduleFailed(String),

    #[error("instance already running")]
    AlreadyRunning,

    #[error("instance not running")]
    NotRunning,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub fn at_warning(err: &GeodataError) {
    tracing::warn!(target: "xray_app_geodata", "{err}");
}

pub fn at_error(err: &GeodataError) {
    tracing::error!(target: "xray_app_geodata", "{err}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_cron() {
        let e = GeodataError::InvalidCron("xxx".into());
        assert!(format!("{e}").contains("xxx"));
    }

    #[test]
    fn display_download_failed() {
        let e = GeodataError::DownloadFailed {
            url: "http://x".into(),
            reason: "timeout".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("http://x"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn display_unexpected_status() {
        let e = GeodataError::UnexpectedStatus(500);
        assert!(format!("{e}").contains("500"));
    }

    #[test]
    fn display_empty_response() {
        let e = GeodataError::EmptyResponse("http://y".into());
        assert!(format!("{e}").contains("http://y"));
    }

    #[test]
    fn display_insecure_redirect() {
        let e = GeodataError::InsecureRedirect("http://insecure".into());
        assert!(format!("{e}").contains("http://insecure"));
    }

    #[test]
    fn display_too_many_redirects() {
        let e = GeodataError::TooManyRedirects;
        assert!(format!("{e}").contains("redirect"));
    }

    #[test]
    fn display_idle_timeout() {
        let e = GeodataError::IdleTimeout;
        assert!(format!("{e}").contains("idle"));
    }

    #[test]
    fn display_invalid_file_path() {
        let e = GeodataError::InvalidFilePath("bad/path".into());
        assert!(format!("{e}").contains("bad/path"));
    }

    #[test]
    fn display_temp_file_create() {
        let e = GeodataError::TempFileCreate {
            target: "x".into(),
            reason: "denied".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("x"));
        assert!(s.contains("denied"));
    }

    #[test]
    fn display_rename_failed() {
        let e = GeodataError::RenameFailed {
            from: "a".into(),
            to: "b".into(),
            reason: "cross-device".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("a"));
        assert!(s.contains("b"));
    }

    #[test]
    fn display_remove_failed() {
        let e = GeodataError::RemoveFailed {
            path: "p".into(),
            reason: "busy".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("p"));
    }

    #[test]
    fn display_already_running() {
        let e = GeodataError::AlreadyRunning;
        assert!(format!("{e}").contains("already"));
    }

    #[test]
    fn display_not_running() {
        let e = GeodataError::NotRunning;
        assert!(format!("{e}").contains("not running"));
    }

    #[test]
    fn io_error_wraps() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e: GeodataError = inner.into();
        assert!(format!("{e}").contains("missing"));
    }

    #[test]
    fn at_warning_and_error_no_panic() {
        at_warning(&GeodataError::NotRunning);
        at_error(&GeodataError::AlreadyRunning);
    }
}
