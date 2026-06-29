//! Shadowsocks 错误类型，对应 Go `errors.New(...)` 调用点。

use thiserror::Error;

/// Shadowsocks 协议错误。
#[derive(Debug, Error)]
pub enum SsError {
    #[error("unsupported cipher")]
    UnsupportedCipher,

    #[error("failed to get cipher: {0}")]
    GetCipher(String),

    #[error("unsupported cipher type value: {0}")]
    InvalidCipherType(i32),

    #[error("failed to read 50 bytes: {0}")]
    ReadInitial(String),

    #[error("failed to match an user")]
    UserNotFound,

    #[error("failed iv check")]
    IvNotUnique,

    #[error("unexpected validator error: {0}")]
    Validator(String),

    #[error("failed to initialize decoding stream: {0}")]
    InitDecode(String),

    #[error("failed to write iv")]
    WriteIv,

    #[error("failed to write header: {0}")]
    WriteHeader(String),

    #[error("failed to write address: {0}")]
    WriteAddress(String),

    #[error("failed to read address: {0}")]
    ReadAddress(String),

    #[error("failed to encrypt udp payload: {0}")]
    EncryptUdp(String),

    #[error("failed to decrypt udp payload: {0}")]
    DecryptUdp(String),

    #[error("insufficient data: {0}")]
    InsufficientData(usize),

    #[error("invalid remote address")]
    InvalidRemoteAddress,

    #[error("the cipher is not support single-port multi-user")]
    NoMultiUserForStreamCipher,

    #[error("email must not be empty")]
    EmptyEmail,

    #[error("user {0} not found")]
    UserNotFoundByEmail(String),

    #[error("expected MemoryAccount returned from validator")]
    NotMemoryAccount,

    #[error("user account is not valid")]
    InvalidUserAccount,

    #[error("aes-gcm init: {0}")]
    AesGcmInit(String),

    #[error("chacha20poly1305 init: {0}")]
    ChaChaInit(String),

    #[error("aead seal failed: {0}")]
    AeadSeal(String),

    #[error("aead open failed: {0}")]
    AeadOpen(String),

    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for SsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Shadowsocks Result 别名。

impl From<xray_crypto::aead::CryptoError> for SsError {
    fn from(e: xray_crypto::aead::CryptoError) -> Self {
        Self::AesGcmInit(e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, SsError>;
