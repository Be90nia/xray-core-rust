//! HTTPUpgrade 错误类型，覆盖客户端（dialer）与服务端（hub）所有错误路径。

use thiserror::Error;

/// HTTPUpgrade 协议错误。
#[derive(Debug, Error)]
pub enum HttpUpgradeError {
    /// 客户端：服务端响应不是 `101 Switching Protocols`，或缺少必需的
    /// `Upgrade: websocket` / `Connection: upgrade` header。
    #[error("unrecognized reply from server: status={status}, upgrade={upgrade:?}, connection={connection:?}")]
    UnrecognizedReply {
        status: String,
        upgrade: String,
        connection: String,
    },

    /// 服务端：请求缺少必需的 `Upgrade: websocket` / `Connection: upgrade` header。
    #[error("unrecognized request: connection={connection:?}, upgrade={upgrade:?}")]
    UnrecognizedRequest { connection: String, upgrade: String },

    /// 服务端：Host header 与配置不匹配。
    #[error("bad host: {host:?}")]
    BadHost { host: String },

    /// 服务端：Path 与配置不匹配。
    #[error("bad path: {path:?}")]
    BadPath { path: String },

    /// 握手请求/响应字节解析失败（HTTP/1.1 格式不合法）。
    #[error("invalid http/1.1 format: {0}")]
    InvalidHttpFormat(String),

    /// IO 错误（读写底层连接）。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// HTTPUpgrade 操作 Result 别名。
pub type Result<T> = std::result::Result<T, HttpUpgradeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_diagnostic() {
        let e = HttpUpgradeError::UnrecognizedReply {
            status: "200 OK".into(),
            upgrade: "".into(),
            connection: "".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("200 OK"));
        assert!(s.contains("unrecognized"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: HttpUpgradeError = io_err.into();
        assert!(matches!(err, HttpUpgradeError::Io(_)));
    }
}
