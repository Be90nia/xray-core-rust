//! Buffer 写入器实现
//!
//! 对应 Go 版本 `common/buf/writer.go`，提供 SequentialWriter、BufferedWriter 和 Discard。

use std::{
    future::{Future, poll_fn},
    io::IoSlice,
    pin::Pin,
};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    buffer::Buffer,
    io::{self, Result, Writer},
    multi::MultiBuffer,
};

// ========== SequentialWriter ==========

/// 顺序写入器
///
/// 对应 Go 的 `SequentialWriter`，将 MultiBuffer 中的各 Buffer 顺序写入
/// 底层 tokio AsyncWrite。
pub struct SequentialWriter {
    inner: Box<dyn AsyncWrite + Unpin + Send>,
}

impl SequentialWriter {
    /// 创建新的 SequentialWriter
    pub fn new(w: impl AsyncWrite + Unpin + Send + 'static) -> Self {
        Self { inner: Box::new(w) }
    }

    /// 消费写入器，返回底层 AsyncWrite
    pub fn into_inner(self) -> Box<dyn AsyncWrite + Unpin + Send> {
        self.inner
    }
}

impl Writer for SequentialWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let buffers = mb.into_buffers();
            // 底层支持 vectored（裸 TCP sendmsg 等）时聚合一次写出；
            // TLS 包装层等默认 is_write_vectored()==false 自动退回逐块顺序写。
            let res = if self.inner.is_write_vectored() {
                write_vectored_all(&mut self.inner, &buffers).await
            } else {
                write_sequential(&mut self.inner, &buffers).await
            };
            for mut buf in buffers {
                buf.release();
            }
            res
        })
    }
}

/// 逐块顺序写（原 [`SequentialWriter`] 行为）。
async fn write_sequential<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    buffers: &[Buffer],
) -> Result<()> {
    for buf in buffers {
        let data = buf.bytes();
        if data.is_empty() {
            continue;
        }
        w.write_all(data).await.map_err(|e| io::classify_io_error(e, false))?;
    }
    Ok(())
}

/// vectored 聚合写：把全部非空块收集为 iovec，尽量单次 `poll_write_vectored`
/// 写出；部分写（返回值小于总量）时从断点继续。N×8KB 块从 N 次 syscall
/// 收敛到 ~1 次。
async fn write_vectored_all<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    buffers: &[Buffer],
) -> Result<()> {
    let mut slices: Vec<IoSlice<'_>> = buffers
        .iter()
        .map(|b| IoSlice::new(b.bytes()))
        // ponytail: Vec.remove(0) 前进——块数 ≤8，O(n²) 无关紧要
        .filter(|s| !s.is_empty())
        .collect();
    while !slices.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *w).poll_write_vectored(cx, &slices))
            .await
            .map_err(|e| io::classify_io_error(e, false))?;
        if n == 0 {
            return Err(io::classify_io_error(
                std::io::Error::new(std::io::ErrorKind::WriteZero, "write_vectored returned 0"),
                false,
            ));
        }
        let mut rem = n;
        while rem > 0 && !slices.is_empty() {
            let len = slices[0].len();
            if len <= rem {
                rem -= len;
                slices.remove(0);
            } else {
                slices[0].advance(rem);
                rem = 0;
            }
        }
    }
    Ok(())
}

// ========== BufferedWriter ==========

/// 带内部缓存的写入器
///
/// 对应 Go 的 `BufferedWriter`，在 Writer 之上添加内部 Buffer 缓存。
/// 支持缓冲模式切换和延迟刷新。
pub struct BufferedWriter {
    writer: Box<dyn Writer>,
    buffer: Option<Buffer>,
    buffered: bool,
    flush_next: bool,
}

impl BufferedWriter {
    /// 创建新的 BufferedWriter
    ///
    /// 默认为缓冲模式（buffered = true）。
    pub fn new(writer: Box<dyn Writer>) -> Self {
        Self { writer, buffer: None, buffered: true, flush_next: false }
    }

    /// 写入单个 Buffer
    ///
    /// 在缓冲模式下，尝试将数据追加到内部缓冲区；空间不足时先刷新再缓冲。
    /// 在非缓冲模式下，直接写入底层 Writer。
    pub async fn write_buffer(&mut self, mut buf: Buffer) -> Result<()> {
        if !self.buffered {
            let mb = MultiBuffer::from_buffer(buf);
            return self.writer.write_multi_buffer(mb).await;
        }

        if self.flush_next {
            self.flush().await?;
            self.flush_next = false;
        }

        if let Some(ref mut inner) = self.buffer {
            if inner.free() >= buf.len() {
                inner.write_from(buf.bytes());
                buf.release();
                return Ok(());
            }
            self.flush().await?;
        }

        if buf.len() <= buf.capacity() / 2 {
            self.buffer = Some(buf);
        } else {
            let mb = MultiBuffer::from_buffer(buf);
            self.writer.write_multi_buffer(mb).await?;
        }

        Ok(())
    }

    /// 写入 MultiBuffer
    pub async fn write_multi_buffer_impl(&mut self, mb: MultiBuffer) -> Result<()> {
        for buf in mb.into_buffers() {
            self.write_buffer(buf).await?;
        }
        Ok(())
    }

    /// 设置缓冲模式
    ///
    /// buffered = true 时启用内部缓冲，false 时直接写入底层。
    pub fn set_buffered(&mut self, buffered: bool) {
        self.buffered = buffered;
    }

    /// 设置下次写入前先刷新
    ///
    /// 对应 Go 的 `BufferedWriter.SetFlushNext`。
    pub fn set_flush_next(&mut self) {
        self.flush_next = true;
    }

    /// 刷新内部缓冲区到底层 Writer
    ///
    /// 将内部 Buffer 的数据写入底层 Writer 并释放 Buffer。
    pub async fn flush(&mut self) -> Result<()> {
        if let Some(mut buf) = self.buffer.take() {
            if !buf.is_empty() {
                let mb = MultiBuffer::from_buffer(buf);
                self.writer.write_multi_buffer(mb).await?;
            } else {
                buf.release();
            }
        }
        Ok(())
    }

    /// 检查是否为缓冲模式
    pub fn is_buffered(&self) -> bool {
        self.buffered
    }
}

impl Writer for BufferedWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { self.write_multi_buffer_impl(mb).await })
    }
}

// ========== Discard ==========

/// 丢弃所有数据的 Writer
///
/// 对应 Go 的 `Discard`，实现 Writer trait，丢弃所有写入的 MultiBuffer 数据
/// 并释放缓冲区。
pub struct Discard;

/// 丢弃所有数据的常量实例
pub const DISCARD: Discard = Discard;

impl Writer for Discard {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let mut mb = mb;
            mb.release();
            Ok(())
        })
    }
}

/// 丢弃原始字节数据的写入器
///
/// 对应 Go 的 `DiscardBytes`，用于原始字节写入场景。
pub struct DiscardBytes;

impl DiscardBytes {
    /// 写入并丢弃数据
    pub async fn write(&mut self, data: &[u8]) -> std::result::Result<usize, std::io::Error> {
        Ok(data.len())
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use super::*;

    #[tokio::test]
    async fn test_sequential_writer_basic() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = SequentialWriter::new(buffer);

        let buf = Buffer::from_vec(b"hello".to_vec());
        let mb = MultiBuffer::from_buffer(buf);
        writer.write_multi_buffer(mb).await.expect("write failed");

        let buf2 = Buffer::from_vec(b" world".to_vec());
        let mb2 = MultiBuffer::from_buffer(buf2);
        writer.write_multi_buffer(mb2).await.expect("write failed");
    }

    #[tokio::test]
    async fn test_sequential_writer_multi_buffer() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = SequentialWriter::new(buffer);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"hello".to_vec()));
        mb.push(Buffer::from_vec(b" world".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");
    }

    #[tokio::test]
    async fn test_buffered_writer_direct_mode() {
        let buffer: Vec<u8> = Vec::new();
        let seq_writer = SequentialWriter::new(buffer);
        let mut writer = BufferedWriter::new(Box::new(seq_writer));

        writer.set_buffered(false);
        assert!(!writer.is_buffered());

        let buf = Buffer::from_vec(b"hello".to_vec());
        writer.write_buffer(buf).await.expect("write failed");

        writer.flush().await.expect("flush failed");
    }

    #[tokio::test]
    async fn test_buffered_writer_buffered_mode() {
        let buffer: Vec<u8> = Vec::new();
        let seq_writer = SequentialWriter::new(buffer);
        let mut writer = BufferedWriter::new(Box::new(seq_writer));

        assert!(writer.is_buffered());

        let buf = Buffer::from_vec(b"hello".to_vec());
        writer.write_buffer(buf).await.expect("write failed");

        writer.flush().await.expect("flush failed");
    }

    #[tokio::test]
    async fn test_buffered_writer_set_flush_next() {
        let buffer: Vec<u8> = Vec::new();
        let seq_writer = SequentialWriter::new(buffer);
        let mut writer = BufferedWriter::new(Box::new(seq_writer));

        let buf1 = Buffer::from_vec(b"hello".to_vec());
        writer.write_buffer(buf1).await.expect("write failed");

        writer.set_flush_next();

        let buf2 = Buffer::from_vec(b" world".to_vec());
        writer.write_buffer(buf2).await.expect("write failed");

        writer.flush().await.expect("flush failed");
    }

    #[tokio::test]
    async fn test_discard() {
        let mut discard = Discard;
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(b"hello".to_vec()));
        discard.write_multi_buffer(mb).await.expect("discard failed");
    }

    #[tokio::test]
    async fn test_discard_const() {
        let mut d = DISCARD;
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(b"data".to_vec()));
        d.write_multi_buffer(mb).await.expect("discard failed");
    }

    #[tokio::test]
    async fn test_discard_bytes() {
        let mut discard = DiscardBytes;
        let n = discard.write(b"hello").await.expect("write failed");
        assert_eq!(n, 5);
    }

    #[tokio::test]
    async fn test_buffered_writer_large_data() {
        let buffer: Vec<u8> = Vec::new();
        let seq_writer = SequentialWriter::new(buffer);
        let mut writer = BufferedWriter::new(Box::new(seq_writer));

        let data = vec![0xABu8; 20000];
        let buf = Buffer::from_vec(data.clone());
        writer.write_buffer(buf).await.expect("write failed");

        writer.flush().await.expect("flush failed");
    }

    #[tokio::test]
    async fn test_sequential_writer_empty_buffer() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = SequentialWriter::new(buffer);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::new());
        writer.write_multi_buffer(mb).await.expect("write failed");
    }

    /// `is_write_vectored()==true` 的 mock：记录聚合结果与调用次数，
    /// 可配置每次最多消费的字节数（模拟部分写）。
    struct VectoredMock {
        data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        chunk: Option<usize>,
        vectored_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl VectoredMock {
        fn new(chunk: Option<usize>) -> (Self, Self) {
            let data = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let writer_mock = Self {
                data: std::sync::Arc::clone(&data),
                chunk,
                vectored_calls: std::sync::Arc::clone(&calls),
            };
            let probe = Self { data, chunk, vectored_calls: calls };
            (writer_mock, probe)
        }
    }

    impl AsyncWrite for VectoredMock {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.data.lock().expect("unpoisoned").extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.vectored_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let total: usize = bufs.iter().map(|s| s.len()).sum();
            let n = self.chunk.map_or(total, |c| c.min(total));
            let mut rem = n;
            for s in bufs {
                if rem == 0 {
                    break;
                }
                let take = rem.min(s.len());
                self.data.lock().expect("unpoisoned").extend_from_slice(&s[..take]);
                rem -= take;
            }
            Poll::Ready(Ok(n))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_sequential_writer_vectored_single_call() {
        let (mock, probe) = VectoredMock::new(None);
        let mut writer = SequentialWriter::new(mock);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"aaa".to_vec()));
        mb.push(Buffer::from_vec(b"bbb".to_vec()));
        mb.push(Buffer::from_vec(b"cc".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");

        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(
            *probe.data.lock().expect("unpoisoned"),
            b"aaabbbcc".as_slice(),
            "聚合写必须保序拼接全部块"
        );
        assert_eq!(probe.vectored_calls.load(Relaxed), 1, "3 块应单次 poll_write_vectored 写出");
    }

    #[tokio::test]
    async fn test_sequential_writer_vectored_partial_writes() {
        // 每次 writev 只消费 4 字节 → 9 字节需要 3 次（4+4+1）
        let (mock, probe) = VectoredMock::new(Some(4));
        let mut writer = SequentialWriter::new(mock);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"aaa".to_vec()));
        mb.push(Buffer::from_vec(b"bbb".to_vec()));
        mb.push(Buffer::from_vec(b"ccc".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");

        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(
            *probe.data.lock().expect("unpoisoned"),
            b"aaabbbccc".as_slice(),
            "部分写必须从断点续写且保序"
        );
        assert_eq!(probe.vectored_calls.load(Relaxed), 3);
    }
}
