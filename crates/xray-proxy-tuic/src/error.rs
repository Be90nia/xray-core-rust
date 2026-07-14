//! TUIC 错误类型。

use std::io;

use thiserror::Error;

/// TUIC 协议/传输错误。
#[derive(Debug, Error)]
pub enum TuicError {
    /// 协议版本不匹配（期望 0x05）。
    #[error("invalid protocol version: expected 0x05, got {0:#04x}")]
    InvalidVersion(u8),

    /// 未知命令类型码。
    #[error("unknown command type: {0:#04x}")]
    UnknownCommandType(u8),

    /// 地址编码错误（未知 ATYP 或长度不足）。
    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),

    /// 字节流过早结束。
    #[error("unexpected end of stream: {0}")]
    UnexpectedEof(&'static str),

    /// quinn 错误。
    #[error("quinn error: {0}")]
    Quinn(#[from] quinn::ConnectionError),

    /// quinn 写错误。
    #[error("quinn write error: {0}")]
    QuinnWrite(#[from] quinn::WriteError),

    /// quinn 读错误。
    #[error("quinn read error: {0}")]
    QuinnRead(#[from] quinn::ReadError),

    /// rustls 错误。
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// TLS keying material exporter 失败。
    #[error("tls keying material export failed")]
    KeyingMaterialExport,

    /// io 错误。
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// TUIC Result 别名。
pub type Result<T> = std::result::Result<T, TuicError>;
