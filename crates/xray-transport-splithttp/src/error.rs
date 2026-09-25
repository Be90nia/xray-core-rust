//! SplitHTTP 传输错误类型。

use thiserror::Error;

/// SplitHTTP 传输协议错误。
#[derive(Debug, Error)]
pub enum SplitHttpError {
    /// 客户端：HTTP 拨号或 SSE 下载流失败。
    #[error("splithttp dial failed: {0}")]
    DialFailed(String),

    /// 服务端：HTTP 服务监听失败。
    #[error("splithttp listen failed: {0}")]
    ListenFailed(String),

    /// Range 配置无效（from > to 或超出合法范围）。
    #[error("invalid range: from={from} to={to}")]
    InvalidRange { from: i32, to: i32 },

    /// Placement 值不合法（非 Placement* 常量之一）。
    #[error("invalid placement: {0}")]
    InvalidPlacement(String),

    /// 配置无效。
    #[error("invalid splithttp config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// upload_queue: 队列已关闭（push 在 close 后调用）。
    #[error("upload queue closed")]
    QueueClosed,

    /// upload_queue: reorder 堆超过 max_packets 上限，连接被强制拆除。
    #[error("packet queue too large: max={max}, current={current}")]
    PacketQueueTooLarge { max: usize, current: usize },

    /// hyper HTTP 错误（连接、协议、IO）。
    #[error("splithttp hyper error: {0}")]
    Hyper(String),

    /// HTTP 状态码非 200（包上传/下载流收到错误响应）。
    #[error("splithttp bad status: {0}")]
    BadStatus(u16),

    /// 无效 URL 构造。
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// 无效 HTTP header value/name（来自 `http::header::InvalidName` /
    /// [`http::header::InvalidHeaderValue`]）。
    #[error("invalid http header: {0}")]
    InvalidHeader(String),
}

/// SplitHTTP 操作 Result 别名。
pub type Result<T> = std::result::Result<T, SplitHttpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = SplitHttpError::InvalidRange { from: 100, to: 50 };
        assert!(format!("{e}").contains("from=100"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: SplitHttpError = io_err.into();
        assert!(matches!(err, SplitHttpError::Io(_)));
    }
}
