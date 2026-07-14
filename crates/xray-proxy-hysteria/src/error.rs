//! Hysteria 代理错误类型。

use thiserror::Error;

/// Hysteria 代理处理器错误。
#[derive(Debug, Error)]
pub enum HysteriaProxyError {
    /// 配置无效（地址缺失、ALPN 错误等）。
    #[error("invalid hysteria config: {0}")]
    InvalidConfig(String),

    /// QUIC 拨号失败。
    #[error("quic dial failed: {0}")]
    DialFailed(String),

    /// Hysteria auth 握手失败（HTTP/3 POST /auth 失败）。
    #[error("hysteria auth failed: {0}")]
    AuthFailed(String),

    /// 传输层错误（来自 xray-transport-hysteria）。
    #[error("transport error: {0}")]
    Transport(#[from] xray_transport_hysteria::HysteriaError),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Hysteria 代理 Result 别名。
pub type Result<T> = std::result::Result<T, HysteriaProxyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = HysteriaProxyError::InvalidConfig("missing server address".into());
        assert!(format!("{e}").contains("missing server address"));
        assert!(format!("{e}").contains("invalid hysteria config"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: HysteriaProxyError = io_err.into();
        assert!(matches!(err, HysteriaProxyError::Io(_)));
    }
}
