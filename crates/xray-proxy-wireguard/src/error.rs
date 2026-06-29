//! WireGuard 代理错误类型。

use thiserror::Error;

/// WireGuard 代理错误。
#[derive(Debug, Error)]
pub enum WgError {
    /// endpoint 字符串格式非法（不是 IP 也不是 CIDR）。
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    /// interface 地址子网掩码不是 /32 (IPv4) 或 /128 (IPv6)。
    #[error("interface address subnet must be /32 for IPv4 or /128 for IPv6, got: {0}")]
    InvalidSubnetMask(String),

    /// 内部 TUN 设备初始化失败。
    #[error("tun init failed: {0}")]
    TunInitFailed(String),

    /// WireGuard 协议握手失败。
    #[error("wireguard handshake failed: {0}")]
    HandshakeFailed(String),

    /// 配置无效（如 secret_key 缺失、peers 为空）。
    #[error("invalid wireguard config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// WireGuard 操作 Result 别名。
pub type Result<T> = std::result::Result<T, WgError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = WgError::InvalidEndpoint("not-an-ip".into());
        assert!(format!("{e}").contains("not-an-ip"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: WgError = io_err.into();
        assert!(matches!(err, WgError::Io(_)));
    }
}
