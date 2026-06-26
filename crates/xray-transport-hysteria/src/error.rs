//! Hysteria 错误类型。

use std::io;

use thiserror::Error;

/// Hysteria crate 的统一错误类型。
#[derive(Debug, Error)]
pub enum HysteriaError {
    /// TLS 配置缺失（对应 Go `"tls config is nil"`）。
    #[error("tls config is nil")]
    MissingTlsConfig,

    /// 验证器缺失（对应 Go `"validator is nil"`）。
    #[error("validator is nil")]
    MissingValidator,

    /// 地址是域名（QUIC 必须用 IP）。
    #[error("address is domain")]
    AddressIsDomain,

    /// 未知的 masquerade 类型（对应 Go `"unknown masq type"`）。
    #[error("unknown masq type: {0}")]
    UnknownMasqType(String),

    /// 鉴权失败（HTTP 状态码非 233）。
    #[error("auth failed code {0}")]
    AuthFailed(u16),

    /// 不支持的拥塞控制类型。
    #[error("unsupported congestion type: {0}")]
    UnsupportedCongestionType(String),

    /// 不支持的 BBR profile。
    #[error("unsupported BBR profile: {0}")]
    UnsupportedBbrProfile(String),

    /// 连接已关闭。
    #[error("connection closed")]
    ConnectionClosed,

    /// UDP hop 参数非法。
    #[error("invalid udphop parameters: {0}")]
    InvalidUdpHop(String),

    /// 底层 IO 错误。
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// crate 内统一 Result 别名。
pub type Result<T> = std::result::Result<T, HysteriaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_match_go() {
        assert_eq!(HysteriaError::MissingTlsConfig.to_string(), "tls config is nil");
        assert_eq!(HysteriaError::MissingValidator.to_string(), "validator is nil");
        assert_eq!(HysteriaError::AddressIsDomain.to_string(), "address is domain");
        assert_eq!(
            HysteriaError::UnknownMasqType("foo".into()).to_string(),
            "unknown masq type: foo"
        );
        assert_eq!(HysteriaError::AuthFailed(403).to_string(), "auth failed code 403");
        assert_eq!(
            HysteriaError::UnsupportedCongestionType("cubic".into()).to_string(),
            "unsupported congestion type: cubic"
        );
        assert_eq!(
            HysteriaError::UnsupportedBbrProfile("weird".into()).to_string(),
            "unsupported BBR profile: weird"
        );
        assert_eq!(HysteriaError::ConnectionClosed.to_string(), "connection closed");
    }

    #[test]
    fn from_io_error_conversion() {
        let err: HysteriaError =
            io::Error::new(io::ErrorKind::UnexpectedEof, "eof").into();
        assert!(matches!(err, HysteriaError::Io(_)));
    }

    #[test]
    fn invalid_udphop_message_contains_detail() {
        let e = HysteriaError::InvalidUdpHop("hopIntervalMin < 5s".into());
        assert!(e.to_string().contains("hopIntervalMin < 5s"));
    }
}
