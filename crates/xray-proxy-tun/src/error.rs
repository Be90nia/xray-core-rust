//! TUN 代理错误类型。

use thiserror::Error;

/// TUN 代理错误。
#[derive(Debug, Error)]
pub enum TunError {
    /// TUN 设备创建失败（平台特定：Linux /dev/net/tun、Windows wintun.dll、macOS utun）。
    #[error("tun device create failed: {0}")]
    DeviceCreateFailed(String),

    /// 找不到 TUN 设备（名称/索引不匹配）。
    #[error("tun device not found: {0}")]
    DeviceNotFound(String),

    /// 网络接口更新失败（`InterfaceUpdater` 无法找到有效接口）。
    #[error("interface update failed: {0}")]
    InterfaceUpdateFailed(String),

    /// 网络栈初始化失败。
    #[error("netstack init failed: {0}")]
    StackInitFailed(String),

    /// TCP socket 监听失败（端口被占用 / 状态非法）。
    #[error("tcp listen failed: {0}")]
    TcpListenFailed(String),

    /// UDP socket 绑定失败。
    #[error("udp bind failed: {0}")]
    UdpBindFailed(String),

    /// ICMP socket 绑定失败。
    #[error("icmp bind failed: {0}")]
    IcmpBindFailed(String),

    /// 配置无效。
    #[error("invalid tun config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// TUN 操作 Result 别名。
pub type Result<T> = std::result::Result<T, TunError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = TunError::DeviceCreateFailed("permission denied".into());
        assert!(format!("{e}").contains("permission denied"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: TunError = io_err.into();
        assert!(matches!(err, TunError::Io(_)));
    }
}
