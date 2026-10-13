//! 压测 harness 强类型错误面（thiserror）。
//!
//! 取代原 anyhow 裸字符串上下文：每个失败点归入可判别变体，
//! 排障按 variant 分流而非 message 前缀。harness 只消费生产 crate
//! 公开 API，不回写其错误类型。

/// harness 统一 Result 别名。
pub type Result<T, E = StressError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum StressError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("pem base64 decode: {0}")]
    PemBase64(#[from] base64::DecodeError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("scenario: {0}")]
    Scenario(String),

    #[error("self-signed cert: {0}")]
    Cert(String),

    #[error("private key der: {0}")]
    KeyDer(String),

    #[error("rustls config: {0}")]
    Rustls(String),

    #[error("engine start: {0}")]
    Start(String),

    #[error("probe roundtrip: {0}")]
    Probe(String),

    #[error("{name} link probe timeout (60s)")]
    ProbeTimeout {
        /// 场景显示名（PROTOCOL_SCENARIOS 表项，如 "s5-vmess-ws"）。
        name: String,
    },
}
