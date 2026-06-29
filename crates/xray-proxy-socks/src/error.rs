//! SOCKS 代理错误类型。

use thiserror::Error;

/// SOCKS 代理错误。
#[derive(Debug, Error)]
pub enum SocksError {
    /// SOCKS4/5 握手失败（版本不支持、命令非法、方法不匹配）。
    #[error("socks handshake failed: {0}")]
    HandshakeFailed(String),

    /// SOCKS5 认证失败（用户名/密码不匹配，或方法协商无匹配）。
    #[error("socks auth failed: {0}")]
    AuthFailed(String),

    /// SOCKS5 帧/地址解析失败（非法 addr type、长度不足、fragmentation）。
    #[error("invalid socks frame: {0}")]
    InvalidFrame(String),

    /// UDP 包编解码失败。
    #[error("socks udp packet error: {0}")]
    UdpPacketError(String),

    /// 配置无效。
    #[error("invalid socks config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// SOCKS 操作 Result 别名。
pub type Result<T> = std::result::Result<T, SocksError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = SocksError::HandshakeFailed("unsupported version".into());
        assert!(format!("{e}").contains("unsupported version"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: SocksError = io_err.into();
        assert!(matches!(err, SocksError::Io(_)));
    }
}
