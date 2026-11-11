//! MASQUE 错误分类（规划 §4.3 `MasqueError`；ClauseId::ErrorClassifiedNoPanicEscape）。
//!
//! 分类面 = Go 拒绝/失败语义的 Rust 归类：
//! - [`MasqueError::Auth`] ← 401（Go `proxy/masque/server.go:271-282` Basic 认证失败）
//! - [`MasqueError::Rejected`] ← 405/400/503 等握手拒绝（Go `connectip/request.go:61-96`）
//! - [`MasqueError::Protocol`] ← 胶囊/帧解析失败（Go `connectip/capsule.go` + `errCapsuleLimit`
//!   族）
//! - [`MasqueError::Io`] ← 底层 IO（h2 流 / 连接错误透传）
//! - [`MasqueError::Mtu`] ← 包超 MTU（Go `connectip/conn.go:63` maxCapsulePacketSize）

use http::StatusCode;

/// MASQUE 错误分类面。
#[derive(Debug, thiserror::Error)]
pub enum MasqueError {
    /// 认证失败（HTTP Basic；对端拒绝或凭据缺失）。
    #[error("masque: authentication failed")]
    Auth,
    /// 协议违规（胶囊解析失败 / 非法帧 / 上限超限）。
    #[error("masque: protocol violation: {0}")]
    Protocol(String),
    /// 底层 IO 错误（h2 流 / 连接 / TLS 透传）。
    #[error("masque: io error: {0}")]
    Io(#[from] std::io::Error),
    /// 包超 MTU（DATAGRAM 包 > [`crate::capsule::MAX_CAPSULE_PAYLOAD`]）。
    #[error(
        "masque: packet exceeds capsule packet size limit ({})",
        crate::capsule::MAX_CAPSULE_PAYLOAD
    )]
    Mtu,
    /// 对端显式拒绝（HTTP 状态码；405/400/401/503 等，Go `hub.go:357-365`）。
    #[error("masque: request rejected: {0}")]
    Rejected(StatusCode),
}

/// MASQUE 结果别名（错误类型带缺省参数，精确错误时可显式覆盖 `E`）。
pub type Result<T, E = MasqueError> = std::result::Result<T, E>;
