//! gRPC 传输错误类型。

use thiserror::Error;

/// gRPC 传输协议错误。
#[derive(Debug, Error)]
pub enum GrpcError {
    /// 客户端：gRPC 拨号或 Tun/TunMulti stream 创建失败。
    #[error("grpc dial failed: {0}")]
    DialFailed(String),

    /// 服务端：gRPC 服务注册或 Serve 失败。
    #[error("grpc listen failed: {0}")]
    ListenFailed(String),

    /// 配置无效（如 service_name 含非法字符）。
    #[error("invalid grpc config: {0}")]
    InvalidConfig(String),

    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 解压失败（如 gzip 解压错误或不支持的压缩算法）。
    #[error("grpc decompression failed: {0}")]
    Decompression(String),
}

/// gRPC 操作 Result 别名。
pub type Result<T> = std::result::Result<T, GrpcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = GrpcError::DialFailed("connection refused".into());
        assert!(format!("{e}").contains("connection refused"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err: GrpcError = io_err.into();
        assert!(matches!(err, GrpcError::Io(_)));
    }
}
