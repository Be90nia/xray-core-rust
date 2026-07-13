//! AnyTLS 协议错误类型。

use thiserror::Error;

/// AnyTLS 协议层错误。
#[derive(Debug, Error)]
pub enum AnytlsError {
    /// 底层 IO 错误（TLS 握手、socket 读写等）。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS 错误。
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    /// SOCKS5 地址格式错误（编码或解码）。
    #[error("invalid socks5 address: {0}")]
    InvalidSocksAddr(String),

    /// 服务端拒绝（cmdAlert）或协议错误。
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// AnyTLS 协议层 Result 别名。
pub type Result<T> = std::result::Result<T, AnytlsError>;
