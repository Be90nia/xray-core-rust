//! Buffer 读取器实现
//!
//! 对应 Go 版本 `common/buf/reader.go`，提供 SingleReader、PacketReader 和 BufferedReader。

use crate::buffer::Buffer;
use crate::io::{self, Reader, Result, Writer};
use crate::multi::MultiBuffer;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

// ========== SingleReader ==========

/// 单缓冲区读取器
///
/// 对应 Go 的 `SingleReader`，将 tokio AsyncRead 包装为 Reader trait。
/// 每次读取填充一个 Buffer（最多 8KB），返回包含单个 Buffer 的 MultiBuffer。
pub struct SingleReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
}

impl SingleReader {
    /// 创建新的 SingleReader
    pub fn new(r: impl AsyncRead + Unpin + Send + 'static) -> Self {
        Self {
            inner: Box::new(r),
        }
    }
}

impl Reader for SingleReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            let mut buf = Buffer::new();
            let writable = buf.writable_bytes();
            match self.inner.read(writable).await {
                Ok(0) => {
                    buf.release();
                    Ok(MultiBuffer::new())
                }
                Ok(n) => {
                    buf.advance_write(n);
                    tracing::trace!(bytes = n, "SingleReader 读取");
                    Ok(MultiBuffer::from_buffer(buf))
                }
                Err(e) => {
                    buf.release();
                    Err(io::classify_io_error(e, true))
                }
            }
        })
    }
}

// ========== PacketReader ==========

/// UDP 包语义读取器
///
/// 对应 Go 的 `PacketReader`，模拟 UDP 数据包读取行为。
/// 读取时跳过空数据包（最多重试 64 次），确保返回非空数据。
pub struct PacketReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
}

impl PacketReader {
    /// 创建新的 PacketReader
    pub fn new(r: impl AsyncRead + Unpin + Send + 'static) -> Self {
        Self {
            inner: Box::new(r),
        }
    }
}

impl Reader for PacketReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            const MAX_RETRIES: usize = 64;

            for _ in 0..MAX_RETRIES {
                let mut buf = Buffer::new();
                let writable = buf.writable_bytes();
                match self.inner.read(writable).await {
                    Ok(0) => {
                        buf.release();
                        return Ok(MultiBuffer::new());
                    }
                    Ok(n) => {
                        if n == 0 {
                            buf.release();
                            continue;
                        }
                        buf.advance_write(n);
                        tracing::trace!(bytes = n, "PacketReader 读取");
                        return Ok(MultiBuffer::from_buffer(buf));
                    }
                    Err(e) => {
                        buf.release();
                        return Err(io::classify_io_error(e, true));
                    }
                }
            }

            Ok(MultiBuffer::new())
        })
    }
}

// ========== BufferedReader ==========

/// 带内部缓存的读取器
///
/// 对应 Go 的 `BufferedReader`，在 Reader 之上添加内部 MultiBuffer 缓存。
/// 支持预读、限制读取、中断信号等操作。
pub struct BufferedReader {
    reader: Box<dyn Reader>,
    buffer: MultiBuffer,
    interrupted: Arc<AtomicBool>,
}

impl BufferedReader {
    /// 创建新的 BufferedReader
    pub fn new(reader: Box<dyn Reader>) -> Self {
        Self {
            reader,
            buffer: MultiBuffer::new(),
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 从内部缓存读取数据到 dst
    ///
    /// 优先从缓存读取，缓存不足时从底层 Reader 补充。
    pub async fn read(&mut self, dst: &mut [u8]) -> usize {
        if dst.is_empty() {
            return 0;
        }

        if !self.buffer.is_empty() {
            return self.buffer.read_to(dst);
        }

        match self.reader.read_multi_buffer().await {
            Ok(mb) => {
                if mb.is_empty() {
                    return 0;
                }
                self.buffer.merge(mb);
                self.buffer.read_to(dst)
            }
            Err(_) => 0,
        }
    }

    /// 读取 MultiBuffer（内部实现）
    ///
    /// 优先返回缓存数据，缓存为空时从底层 Reader 读取。
    async fn read_multi_buffer_impl(&mut self) -> Result<MultiBuffer> {
        if self.interrupted.load(Ordering::Relaxed) {
            return Err(io::Error::Interrupted);
        }

        if !self.buffer.is_empty() {
            let len = self.buffer.len();
            let result = self.buffer.split_bytes(len);
            return Ok(result);
        }

        self.reader.read_multi_buffer().await
    }

    /// 读取最多 size 字节
    ///
    /// 对应 Go 的 `BufferedReader.ReadAtMost`。
    pub async fn read_at_most(&mut self, size: usize) -> Result<MultiBuffer> {
        if self.interrupted.load(Ordering::Relaxed) {
            return Err(io::Error::Interrupted);
        }

        if size == 0 {
            return Ok(MultiBuffer::new());
        }

        if !self.buffer.is_empty() {
            let result = self.buffer.split_bytes(size);
            return Ok(result);
        }

        let mut mb = self.reader.read_multi_buffer().await?;
        if mb.len() <= size {
            return Ok(mb);
        }

        let result = mb.split_bytes(size);
        self.buffer.merge(mb);
        Ok(result)
    }

    /// 将缓存数据写入 Writer
    ///
    /// 对应 Go 的 `BufferedReader.WriteTo`。
    pub async fn write_to(&mut self, writer: &mut dyn Writer) -> Result<()> {
        if !self.buffer.is_empty() {
            let len = self.buffer.len();
            let mb = self.buffer.split_bytes(len);
            writer.write_multi_buffer(mb).await?;
        }
        Ok(())
    }

    /// 发送中断信号
    ///
    /// 设置中断标志，后续读取操作将返回 Interrupted 错误。
    pub fn interrupt(&mut self) {
        self.interrupted.store(true, Ordering::Relaxed);
    }

    /// 关闭读取器，释放内部缓存
    pub fn close(&mut self) {
        self.buffer.release();
    }

    /// 检查是否已中断
    pub fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }
}

impl Reader for BufferedReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move { self.read_multi_buffer_impl().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::new_reader;
    use std::io::Cursor;

    fn make_cursor_reader(data: &[u8]) -> Box<dyn Reader> {
        new_reader(Cursor::new(data.to_vec()))
    }

    #[tokio::test]
    async fn test_single_reader_basic() {
        let cursor = Cursor::new(b"hello world".to_vec());
        let mut reader = SingleReader::new(cursor);
        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(!mb.is_empty());
        assert_eq!(mb.to_vec(), b"hello world");
    }

    #[tokio::test]
    async fn test_single_reader_empty() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut reader = SingleReader::new(cursor);
        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(mb.is_empty());
    }

    #[tokio::test]
    async fn test_single_reader_large() {
        let data = vec![0xABu8; 20000];
        let cursor = Cursor::new(data.clone());
        let mut reader = SingleReader::new(cursor);

        let mut total = MultiBuffer::new();
        loop {
            let mb = reader.read_multi_buffer().await.expect("read failed");
            if mb.is_empty() {
                break;
            }
            total.merge(mb);
        }
        assert_eq!(total.len(), 20000);
        assert_eq!(total.to_vec(), data);
    }

    #[tokio::test]
    async fn test_packet_reader_basic() {
        let cursor = Cursor::new(b"packet data".to_vec());
        let mut reader = PacketReader::new(cursor);
        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(!mb.is_empty());
        assert_eq!(mb.to_vec(), b"packet data");
    }

    #[tokio::test]
    async fn test_packet_reader_empty() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut reader = PacketReader::new(cursor);
        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(mb.is_empty());
    }

    #[tokio::test]
    async fn test_buffered_reader_basic() {
        let inner = make_cursor_reader(b"hello world");
        let mut reader = BufferedReader::new(inner);

        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(!mb.is_empty());
        assert_eq!(mb.to_vec(), b"hello world");
    }

    #[tokio::test]
    async fn test_buffered_reader_read() {
        let inner = make_cursor_reader(b"hello world");
        let mut reader = BufferedReader::new(inner);

        let mut dst = [0u8; 5];
        let n = reader.read(&mut dst).await;
        assert_eq!(n, 5);
        assert_eq!(&dst, b"hello");
    }

    #[tokio::test]
    async fn test_buffered_reader_read_at_most() {
        let inner = make_cursor_reader(b"hello world");
        let mut reader = BufferedReader::new(inner);

        let mb = reader.read_at_most(5).await.expect("read failed");
        assert_eq!(mb.len(), 5);
        assert_eq!(mb.to_vec(), b"hello");
    }

    #[tokio::test]
    async fn test_buffered_reader_read_at_most_zero() {
        let inner = make_cursor_reader(b"hello");
        let mut reader = BufferedReader::new(inner);

        let mb = reader.read_at_most(0).await.expect("read failed");
        assert!(mb.is_empty());
    }

    #[tokio::test]
    async fn test_buffered_reader_interrupt() {
        let inner = make_cursor_reader(b"hello");
        let mut reader = BufferedReader::new(inner);

        reader.interrupt();
        let result = reader.read_multi_buffer().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), io::Error::Interrupted));
    }

    #[tokio::test]
    async fn test_buffered_reader_close() {
        let inner = make_cursor_reader(b"hello");
        let mut reader = BufferedReader::new(inner);

        let _ = reader.read_multi_buffer().await;
        reader.close();
    }

    #[tokio::test]
    async fn test_buffered_reader_is_interrupted() {
        let inner = make_cursor_reader(b"hello");
        let mut reader = BufferedReader::new(inner);
        assert!(!reader.is_interrupted());
        reader.interrupt();
        assert!(reader.is_interrupted());
    }

    #[tokio::test]
    async fn test_buffered_reader_read_at_most_excess() {
        let inner = make_cursor_reader(b"hello world");
        let mut reader = BufferedReader::new(inner);

        let mb = reader.read_at_most(5).await.expect("read failed");
        assert_eq!(mb.to_vec(), b"hello");

        let mb2 = reader.read_at_most(6).await.expect("read failed");
        assert_eq!(mb2.to_vec(), b" world");
    }

    #[tokio::test]
    async fn test_buffered_reader_write_to() {
        let inner = make_cursor_reader(b"hello");
        let mut reader = BufferedReader::new(inner);

        let mb = reader.read_multi_buffer().await.expect("read failed");
        reader.buffer.merge(mb);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = crate::io::new_writer(buffer);
        reader.write_to(&mut writer).await.expect("write failed");
    }
}
