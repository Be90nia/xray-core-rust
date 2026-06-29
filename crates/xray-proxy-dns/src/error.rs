//! DNS 代理错误类型。

use thiserror::Error;

/// DNS 代理错误。
#[derive(Debug, Error)]
pub enum DnsProxyError {
    /// DNS 查询解析失败（非合法 DNS over UDP/TCP 格式）。
    #[error("dns query parse failed: {0}")]
    QueryParseFailed(String),

    /// DNS 响应构造失败。
    #[error("dns response build failed: {0}")]
    ResponseBuildFailed(String),

    /// 上游 DNS 服务器转发失败。
    #[error("upstream forward failed: {0}")]
    UpstreamForwardFailed(String),

    /// 配置无效（如 rule 的 q_type 重复、domain 规则格式错误）。
    #[error("invalid dns proxy config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// DNS 代理操作 Result 别名。
pub type Result<T> = std::result::Result<T, DnsProxyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = DnsProxyError::QueryParseFailed("truncated".into());
        assert!(format!("{e}").contains("truncated"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: DnsProxyError = io_err.into();
        assert!(matches!(err, DnsProxyError::Io(_)));
    }
}
