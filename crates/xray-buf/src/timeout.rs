//! 超时包装器
//!
//! 对应 Go 版本 `common/buf/timeout.go`，为 Reader 和 Writer 提供超时包装。
//! 使用 `tokio::select!` 实现超时机制。

use std::{future::Future, pin::Pin, time::Duration};

use crate::{
    io::{Error, Reader, Result, TimeoutReader, Writer},
    multi::MultiBuffer,
};

// ========== TimeoutReaderWrapper ==========

/// 带超时的 Reader 包装器
///
/// 对应 Go 的 `TimeoutReader`，为底层 Reader 添加超时机制。
/// 使用 `tokio::select!` 在读取和超时定时器之间竞争。
pub struct TimeoutReaderWrapper<R> {
    reader: R,
}

impl<R> TimeoutReaderWrapper<R> {
    /// 创建新的超时读取包装器
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// 获取底层 Reader 的可变引用
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// 消费包装器，返回底层 Reader
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: Reader> TimeoutReader for TimeoutReaderWrapper<R> {
    fn read_multi_buffer_timeout(
        &mut self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            tokio::select! {
                result = self.reader.read_multi_buffer() => result,
                _ = tokio::time::sleep(timeout) => {
                    tracing::trace!(timeout_ms = timeout.as_millis(), "TimeoutReader 超时");
                    Err(Error::TimeoutError)
                }
            }
        })
    }
}

// ========== TimeoutWriterWrapper ==========

/// 带超时的 Writer 包装器
///
/// 为底层 Writer 添加超时机制（Go 版本无对应，但为对称性而提供）。
pub struct TimeoutWriterWrapper<W> {
    writer: W,
}

impl<W> TimeoutWriterWrapper<W> {
    /// 创建新的超时写入包装器
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// 获取底层 Writer 的可变引用
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// 消费包装器，返回底层 Writer
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Writer + Send> TimeoutWriterWrapper<W> {
    /// 带超时写入 MultiBuffer
    ///
    /// 使用 `tokio::select!` 在写入和超时定时器之间竞争。
    pub async fn write_multi_buffer_timeout(
        &mut self,
        mb: MultiBuffer,
        timeout: Duration,
    ) -> Result<()> {
        tokio::select! {
            result = self.writer.write_multi_buffer(mb) => result,
            _ = tokio::time::sleep(timeout) => {
                tracing::trace!(timeout_ms = timeout.as_millis(), "TimeoutWriter 超时");
                Err(Error::TimeoutError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{
        buffer::Buffer,
        io::{new_reader, new_writer},
    };

    #[tokio::test]
    async fn test_timeout_reader_success() {
        let cursor = Cursor::new(b"hello".to_vec());
        let reader = new_reader(cursor);
        let mut wrapper = TimeoutReaderWrapper::new(reader);

        let mb = wrapper
            .read_multi_buffer_timeout(Duration::from_secs(5))
            .await
            .expect("timeout read failed");
        assert!(!mb.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_reader_empty_eof() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let reader = new_reader(cursor);
        let mut wrapper = TimeoutReaderWrapper::new(reader);

        let mb = wrapper
            .read_multi_buffer_timeout(Duration::from_secs(5))
            .await
            .expect("timeout read failed");
        assert!(mb.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_writer_success() {
        let buffer: Vec<u8> = Vec::new();
        let writer = new_writer(buffer);
        let mut wrapper = TimeoutWriterWrapper::new(writer);

        let mb = MultiBuffer::from_buffer(Buffer::from_vec(b"hello".to_vec()));
        wrapper
            .write_multi_buffer_timeout(mb, Duration::from_secs(5))
            .await
            .expect("timeout write failed");
    }

    #[tokio::test]
    async fn test_timeout_reader_timeout_error() {
        struct SlowReader;

        impl Reader for SlowReader {
            fn read_multi_buffer(
                &mut self,
            ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_secs(100)).await;
                    Ok(MultiBuffer::new())
                })
            }
        }

        let mut wrapper = TimeoutReaderWrapper::new(SlowReader);

        let result = wrapper.read_multi_buffer_timeout(Duration::from_millis(50)).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::TimeoutError));
    }

    #[tokio::test]
    async fn test_timeout_reader_get_mut() {
        let cursor = Cursor::new(b"hello".to_vec());
        let reader = new_reader(cursor);
        let mut wrapper = TimeoutReaderWrapper::new(reader);
        let _inner = wrapper.get_mut();
    }

    #[tokio::test]
    async fn test_timeout_reader_into_inner() {
        let cursor = Cursor::new(b"hello".to_vec());
        let reader = new_reader(cursor);
        let wrapper = TimeoutReaderWrapper::new(reader);
        let _inner = wrapper.into_inner();
    }

    #[tokio::test]
    async fn test_timeout_writer_get_mut() {
        let buffer: Vec<u8> = Vec::new();
        let writer = new_writer(buffer);
        let mut wrapper = TimeoutWriterWrapper::new(writer);
        let _inner = wrapper.get_mut();
    }

    #[tokio::test]
    async fn test_timeout_writer_into_inner() {
        let buffer: Vec<u8> = Vec::new();
        let writer = new_writer(buffer);
        let wrapper = TimeoutWriterWrapper::new(writer);
        let _inner = wrapper.into_inner();
    }
}
