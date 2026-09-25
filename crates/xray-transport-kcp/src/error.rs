//! KCP 错误类型（对应 Go `ErrIOTimeout` / `ErrClosedListener` / `ErrClosedConnection`）。

use std::io;

use thiserror::Error;

/// KCP crate 的统一错误类型。
#[derive(Debug, Error)]
pub enum KcpError {
    /// 读/写超时（对应 Go `ErrIOTimeout`）。
    #[error("Read/Write timeout")]
    IoTimeout,

    /// 监听器已关闭（对应 Go `ErrClosedListener`）。
    #[error("Listener closed")]
    ClosedListener,

    /// 连接已关闭（对应 Go `ErrClosedConnection`）。
    #[error("Connection closed")]
    ClosedConnection,

    /// 底层 IO 错误。
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Segment 解析失败。
    #[error("invalid segment bytes")]
    InvalidSegment,
}

impl KcpError {
    /// 与 Go 一致：超时返回 true。
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::IoTimeout)
    }
}

/// crate 内统一 Result 别名。
pub type Result<T> = std::result::Result<T, KcpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_match_go() {
        assert_eq!(KcpError::IoTimeout.to_string(), "Read/Write timeout");
        assert_eq!(KcpError::ClosedListener.to_string(), "Listener closed");
        assert_eq!(KcpError::ClosedConnection.to_string(), "Connection closed");
    }

    #[test]
    fn is_timeout_predicate() {
        assert!(KcpError::IoTimeout.is_timeout());
        assert!(!KcpError::ClosedConnection.is_timeout());

        let io_err = KcpError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        assert!(!io_err.is_timeout());
    }

    #[test]
    fn from_io_error_conversion() {
        let err: KcpError = io::Error::new(io::ErrorKind::Other, "x").into();
        assert!(matches!(err, KcpError::Io(_)));
    }
}
