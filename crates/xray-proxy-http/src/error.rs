//! HTTP 代理错误类型。

use thiserror::Error;

/// HTTP 代理错误。
#[derive(Debug, Error)]
pub enum HttpProxyError {
    /// 客户端：HTTP CONNECT 请求构造或解析失败。
    #[error("http connect failed: {0}")]
    ConnectFailed(String),

    /// 服务端：HTTP 请求解析失败（非合法 HTTP/1.1 请求行/header）。
    #[error("invalid http request: {0}")]
    InvalidRequest(String),

    /// 认证失败（用户名/密码不匹配，或缺少 Proxy-Authorization header）。
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// 配置无效。
    #[error("invalid http proxy config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// HTTP 代理操作 Result 别名。
pub type Result<T> = std::result::Result<T, HttpProxyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = HttpProxyError::AuthFailed("bad password".into());
        assert!(format!("{e}").contains("bad password"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: HttpProxyError = io_err.into();
        assert!(matches!(err, HttpProxyError::Io(_)));
    }
}
