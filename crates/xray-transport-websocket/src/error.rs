//! WebSocket 传输错误类型。

use thiserror::Error;

/// WebSocket 传输协议错误。
#[derive(Debug, Error)]
pub enum WsError {
    /// 客户端：握手失败（HTTP 升级响应不是 101，或 Sec-WebSocket-Accept 不匹配）。
    #[error("websocket handshake failed: {0}")]
    HandshakeFailed(String),

    /// 服务端：请求不是合法的 WebSocket 升级请求。
    #[error("invalid upgrade request: {reason}")]
    InvalidUpgradeRequest { reason: String },

    /// 帧 opcode 非法（不在 0..=0xF 范围，或控制帧带 fragmentation）。
    #[error("invalid frame opcode: {0:#x}")]
    InvalidOpcode(u8),

    /// 帧过长（payload length > 2^64-1 或超出内部限制）。
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u64),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// WebSocket 操作 Result 别名。
pub type Result<T> = std::result::Result<T, WsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = WsError::HandshakeFailed("unexpected status 200".into());
        assert!(format!("{e}").contains("200"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: WsError = io_err.into();
        assert!(matches!(err, WsError::Io(_)));
    }

    #[test]
    fn invalid_opcode_display_hex() {
        let e = WsError::InvalidOpcode(0xff);
        assert!(format!("{e}").contains("0xff"));
    }
}
