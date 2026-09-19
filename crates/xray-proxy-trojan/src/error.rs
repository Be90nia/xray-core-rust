//! Trojan 协议错误类型，对应 Go `proxy/trojan/` 内 `errors.New(...)` 调用点。

use thiserror::Error;

/// Trojan 协议错误。
#[derive(Debug, Error)]
pub enum TrojanError {
    #[error("failed to read user hash: {0}")]
    ReadUserHash(String),

    #[error("failed to read crlf: {0}")]
    ReadCrlf(String),

    #[error("failed to read command: {0}")]
    ReadCommand(String),

    #[error("failed to read address and port: {0}")]
    ReadAddressPort(String),

    #[error("failed to read payload length: {0}")]
    ReadPayloadLength(String),

    #[error("oversize payload: {0} > {1}")]
    OversizePayload(usize, usize),

    #[error("failed to read payload: {0}")]
    ReadPayload(String),

    #[error("failed to write request header: {0}")]
    WriteHeader(String),

    #[error("failed to write address: {0}")]
    WriteAddress(String),

    #[error("user not found")]
    UserNotFound,

    #[error("user {0} already exists")]
    UserAlreadyExists(String),

    #[error("user {0} not found")]
    UserNotFoundByEmail(String),

    #[error("email must not be empty")]
    EmptyEmail,

    #[error("user account is not valid")]
    InvalidUserAccount,

    #[error("invalid remote address")]
    InvalidRemoteAddress,

    #[error("insufficient data: need {0}, have {1}")]
    InsufficientData(usize, usize),

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for TrojanError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Trojan Result 别名。
pub type Result<T> = std::result::Result<T, TrojanError>;
