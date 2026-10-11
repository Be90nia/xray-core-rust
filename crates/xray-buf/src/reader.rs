//! Buffer 读取器实现
//!
//! 对应 Go 版本 `common/buf/reader.go`，提供 SingleReader、PacketReader 和 BufferedReader。

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    buffer::Buffer,
    io::{self, Reader, Result, Writer},
    multi::MultiBuffer,
};

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
        Self { inner: Box::new(r) }
    }
}

impl Reader for SingleReader {
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<MultiBuffer>> {
        let mut buf = Buffer::new();
        let n = {
            let mut rb = ReadBuf::new(buf.writable_bytes());
            match Pin::new(&mut *self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                Poll::Ready(Err(e)) => {
                    buf.release();
                    return Poll::Ready(Err(io::classify_io_error(e, true)));
                },
                Poll::Pending => {
                    // rb 借用随块尾结束（NLL），块尾 buf 先释放回池再返回
                    buf.release();
                    return Poll::Pending;
                },
            }
        };
        if n == 0 {
            buf.release();
            return Poll::Ready(Ok(MultiBuffer::new()));
        }
        buf.advance_write(n);
        tracing::trace!(bytes = n, "SingleReader 读取");
        Poll::Ready(Ok(MultiBuffer::from_buffer(buf)))
    }
}

// ========== PacketReader ==========

/// UDP 包语义读取器
///
/// 对应 Go 的 `PacketReader`，模拟 UDP 数据包读取行为。
/// 读到 0 字节按 EOF 约定返回空 MultiBuffer。
pub struct PacketReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
}

impl PacketReader {
    /// 创建新的 PacketReader
    pub fn new(r: impl AsyncRead + Unpin + Send + 'static) -> Self {
        Self { inner: Box::new(r) }
    }
}

impl Reader for PacketReader {
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<MultiBuffer>> {
        let mut buf = Buffer::new();
        let n = {
            let mut rb = ReadBuf::new(buf.writable_bytes());
            match Pin::new(&mut *self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                Poll::Ready(Err(e)) => {
                    buf.release();
                    return Poll::Ready(Err(io::classify_io_error(e, true)));
                },
                Poll::Pending => {
                    buf.release();
                    return Poll::Pending;
                },
            }
        };
        if n == 0 {
            buf.release();
            return Poll::Ready(Ok(MultiBuffer::new()));
        }
        buf.advance_write(n);
        tracing::trace!(bytes = n, "PacketReader 读取");
        Poll::Ready(Ok(MultiBuffer::from_buffer(buf)))
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
        Self { reader, buffer: MultiBuffer::new(), interrupted: Arc::new(AtomicBool::new(false)) }
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
            },
            Err(_) => 0,
        }
    }

    /// [`BufferedReader::read`] 的 poll 形态（poll 状态机驱动用，行为一致）。
    pub fn poll_read(&mut self, dst: &mut [u8], cx: &mut Context<'_>) -> Poll<usize> {
        if dst.is_empty() {
            return Poll::Ready(0);
        }

        if !self.buffer.is_empty() {
            return Poll::Ready(self.buffer.read_to(dst));
        }

        match self.reader.poll_read_multi_buffer(cx) {
            Poll::Ready(Ok(mb)) => {
                if mb.is_empty() {
                    return Poll::Ready(0);
                }
                self.buffer.merge(mb);
                Poll::Ready(self.buffer.read_to(dst))
            },
            Poll::Ready(Err(_)) => Poll::Ready(0),
            Poll::Pending => Poll::Pending,
        }
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
            crate::io::write_mb(writer, mb).await?;
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
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<MultiBuffer>> {
        if self.interrupted.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::Interrupted));
        }

        if !self.buffer.is_empty() {
            let len = self.buffer.len();
            return Poll::Ready(Ok(self.buffer.split_bytes(len)));
        }

        self.reader.poll_read_multi_buffer(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::io::new_reader;

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
