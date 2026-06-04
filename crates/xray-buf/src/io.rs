//! IO 抽象层
//!
//! 对应 Go 版本 `common/buf` 的 io.go，定义异步 Reader/Writer trait、
//! 错误类型和工厂函数。所有 IO 操作均为异步，基于 tokio AsyncRead/AsyncWrite。

use crate::multi::MultiBuffer;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

// ========== 错误类型 ==========

/// IO 错误类型
///
/// 对应 Go 的 io.EOF 和各类 IO 错误分类。
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// 读取失败
    #[error("read error: {0}")]
    ReadError(String),

    /// 写入失败
    #[error("write error: {0}")]
    WriteError(String),

    /// 超时
    #[error("timeout")]
    TimeoutError,

    /// 中断（用于 BufferedReader 的中断信号）
    #[error("interrupted")]
    Interrupted,
}

/// 判断是否为读取错误
#[inline]
pub fn is_read_error(err: &Error) -> bool {
    matches!(err, Error::ReadError(_))
}

/// 判断是否为写入错误
#[inline]
pub fn is_write_error(err: &Error) -> bool {
    matches!(err, Error::WriteError(_))
}

/// 将 std::io::Error 转换为本模块的 Error，自动分类读写
pub fn classify_io_error(err: std::io::Error, is_read: bool) -> Error {
    if err.kind() == std::io::ErrorKind::TimedOut {
        return Error::TimeoutError;
    }
    if err.kind() == std::io::ErrorKind::Interrupted {
        return Error::Interrupted;
    }
    if is_read {
        Error::ReadError(err.to_string())
    } else {
        Error::WriteError(err.to_string())
    }
}

// ========== Result 类型 ==========

/// IO 操作结果类型
pub type Result<T> = std::result::Result<T, Error>;

// ========== Reader trait ==========

/// 异步多缓冲区读取接口
///
/// 对应 Go 的 `buf.Reader` 接口，读取返回 `MultiBuffer`。
/// 使用 `Pin<Box<dyn Future>>` 返回类型以支持动态分发。
pub trait Reader: Send {
    /// 异步读取数据，返回 MultiBuffer
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>>;
}

// ========== Writer trait ==========

/// 异步多缓冲区写入接口
///
/// 对应 Go 的 `buf.Writer` 接口，接受 `MultiBuffer` 写入。
/// 使用 `Pin<Box<dyn Future>>` 返回类型以支持动态分发。
pub trait Writer: Send {
    /// 异步写入 MultiBuffer
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

// ========== Box<dyn> 实现 ==========

impl Reader for Box<dyn Reader> {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        (**self).read_multi_buffer()
    }
}

impl Writer for Box<dyn Writer> {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).write_multi_buffer(mb)
    }
}

// ========== TimeoutReader trait ==========

/// 带超时的异步多缓冲区读取接口
///
/// 对应 Go 的 `buf.TimeoutReader` 接口。
pub trait TimeoutReader: Send {
    /// 带超时异步读取数据，返回 MultiBuffer
    fn read_multi_buffer_timeout(
        &mut self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>>;
}

// ========== 工厂函数 ==========

/// 将 tokio AsyncRead 包装为 Reader
///
/// 对应 Go 的 `buf.NewReader(io.Reader)`，使用 SingleReader 实现。
pub fn new_reader(r: impl AsyncRead + Unpin + Send + 'static) -> Box<dyn Reader> {
    Box::new(crate::reader::SingleReader::new(r))
}

/// 将 tokio AsyncRead 包装为 UDP 包语义的 Reader
///
/// 对应 Go 的 `buf.NewPacketReader(io.Reader)`，使用 PacketReader 实现。
pub fn new_packet_reader(r: impl AsyncRead + Unpin + Send + 'static) -> Box<dyn Reader> {
    Box::new(crate::reader::PacketReader::new(r))
}

/// 将 tokio AsyncWrite 包装为 Writer
///
/// 对应 Go 的 `buf.NewWriter(io.Writer)`，使用 SequentialWriter 实现。
pub fn new_writer(w: impl AsyncWrite + Unpin + Send + 'static) -> Box<dyn Writer> {
    Box::new(crate::writer::SequentialWriter::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_variants() {
        let read_err = Error::ReadError("connection reset".to_string());
        let write_err = Error::WriteError("broken pipe".to_string());
        let timeout_err = Error::TimeoutError;
        let interrupted_err = Error::Interrupted;

        assert!(is_read_error(&read_err));
        assert!(!is_read_error(&write_err));
        assert!(is_write_error(&write_err));
        assert!(!is_write_error(&read_err));
        assert!(!is_read_error(&timeout_err));
        assert!(!is_write_error(&interrupted_err));
    }

    #[test]
    fn test_classify_io_error_read() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err = classify_io_error(io_err, true);
        assert!(is_read_error(&err));
    }

    #[test]
    fn test_classify_io_error_write() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let err = classify_io_error(io_err, false);
        assert!(is_write_error(&err));
    }

    #[test]
    fn test_classify_io_error_timeout() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let err = classify_io_error(io_err, true);
        assert!(matches!(err, Error::TimeoutError));
    }

    #[test]
    fn test_classify_io_error_interrupted() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        let err = classify_io_error(io_err, false);
        assert!(matches!(err, Error::Interrupted));
    }

    #[test]
    fn test_error_display() {
        let err = Error::ReadError("test error".to_string());
        assert_eq!(format!("{err}"), "read error: test error");
        let err = Error::TimeoutError;
        assert_eq!(format!("{err}"), "timeout");
    }

    #[tokio::test]
    async fn test_new_reader() {
        use std::io::Cursor;
        let cursor = Cursor::new(b"hello".to_vec());
        let mut reader = new_reader(cursor);
        let mb = reader.read_multi_buffer().await.expect("read should succeed");
        assert!(!mb.is_empty());
    }

    #[tokio::test]
    async fn test_new_writer() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);
        let mb = MultiBuffer::from_buffer(crate::buffer::Buffer::from_vec(b"hello".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write should succeed");
    }

    #[tokio::test]
    async fn test_new_packet_reader() {
        use std::io::Cursor;
        let cursor = Cursor::new(b"packet data".to_vec());
        let mut reader = new_packet_reader(cursor);
        let mb = reader.read_multi_buffer().await.expect("read should succeed");
        assert!(!mb.is_empty());
    }
}
