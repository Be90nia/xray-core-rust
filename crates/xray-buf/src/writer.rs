//! Buffer 写入器实现
//!
//! 对应 Go 版本 `common/buf/writer.go`，提供 SequentialWriter、BufferedWriter 和 Discard。

use std::{
    future::{Future, poll_fn},
    io::IoSlice,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::AsyncWrite;

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
    fn poll_write_multi_buffer(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        // 无跨 poll 状态字段：进度持久化在 mb（整块写完即摘除回池，半块
        // 游标推进放回队首），每次 poll 重建 iovec/顺序游标。
        if self.inner.is_write_vectored() {
            self.poll_write_vectored(cx, mb)
        } else {
            self.poll_write_sequential(cx, mb)
        }
    }

    /// 排空 + 半关闭底层 AsyncWrite（poll_shutdown：TLS 层=flush sendable_tls
    /// 后发 close_notify；裸 TCP=FIN）。bd VISIONMAC：bridge 收尾必须走这里，
    /// 默认 no-op 会让 TLS BufWriter 语义滞留的尾巴随 drop 蒸发。
    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(poll_fn(|cx| Pin::new(&mut *self.inner).poll_shutdown(cx)))
    }
}

impl SequentialWriter {
    /// vectored 聚合写：剩余块收集为 iovec 尽量单次 `poll_write_vectored`
    /// 写出；部分写从断点续传（N×8KB 块收敛 ~1 次 syscall）。
    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        loop {
            // 沿途释放队首空块
            release_empty_front(mb);
            if mb.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let slices: Vec<IoSlice<'_>> =
                mb.iter().map(|b| IoSlice::new(b.bytes())).filter(|s| !s.is_empty()).collect();
            let mut write = std::pin::pin!(poll_fn(
                |cx| Pin::new(&mut *self.inner).poll_write_vectored(cx, &slices)
            ));
            let n = match write.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::classify_io_error(e, false))),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::classify_io_error(
                    std::io::Error::new(std::io::ErrorKind::WriteZero, "write_vectored returned 0"),
                    false,
                )));
            }
            consume_front_bytes(mb, n);
        }
    }

    /// 逐块顺序写（非 vectored 底层，TLS 包装等）。
    fn poll_write_sequential(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        loop {
            release_empty_front(mb);
            if mb.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let mut write = std::pin::pin!(poll_fn(|cx| {
                let data = mb.iter().next().map_or(&[][..], |b| b.bytes());
                Pin::new(&mut *self.inner).poll_write(cx, data)
            }));
            let n = match write.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::classify_io_error(e, false))),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                // AsyncWrite 协议：非空 buf 的 Ok(0) = 写入器无法再接受数据
                return Poll::Ready(Err(io::classify_io_error(
                    std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0"),
                    false,
                )));
            }
            consume_front_bytes(mb, n);
        }
    }
}

/// 释放 mb 队首连续空块（回池）。
fn release_empty_front(mb: &mut MultiBuffer) {
    while let Some(mut front) = mb.split_first() {
        if front.bytes().is_empty() {
            front.release();
        } else {
            mb.push_front(front);
            break;
        }
    }
}

/// 从队首消费 n 字节：整块写完摘除回池，半块游标推进放回队首。
fn consume_front_bytes(mb: &mut MultiBuffer, mut n: usize) {
    while n > 0 {
        match mb.split_first() {
            Some(mut front) => {
                let len = front.len();
                if len == 0 {
                    front.release();
                    continue;
                }
                if len <= n {
                    n -= len;
                    front.release();
                } else {
                    front.advance(n);
                    mb.push_front(front);
                    n = 0;
                }
            },
            None => break,
        }
    }
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
    /// poll 写路径的在途 flush 批：Pending 期间暂存内部缓存，Ready 后清空
    /// （poll 状态机跨 poll 的唯一自带状态；async 路径不经此字段）。
    flushing: Option<MultiBuffer>,
}

impl BufferedWriter {
    /// 创建新的 BufferedWriter
    ///
    /// 默认为缓冲模式（buffered = true）。
    pub fn new(writer: Box<dyn Writer>) -> Self {
        Self { writer, buffer: None, buffered: true, flush_next: false, flushing: None }
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

    /// 直接整批写入底层 Writer（绕过内部缓冲的二次拆分）。
    ///
    /// 先 flush 既有内部缓冲（保持字节先后序），再把 `mb` 作为**单次**底层
    /// 写入交付。对帧协议写入方这是原子性边界：多路复用共享写端时，一次
    /// 调用的全部 Buffer 落在共享锁同一临界区内，中途不会插入其他写者的
    /// 帧（`write_multi_buffer_impl` 会按 Buffer 逐个 write_buffer，帧头与
    /// 载荷可被并发写者的完整帧插隔——mux carrier 帧错位根因，bd txhn）。
    pub async fn write_multi_buffer_direct(&mut self, mb: MultiBuffer) -> Result<()> {
        self.flush().await?;
        self.writer.write_multi_buffer(mb).await
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
        std::future::poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// [`BufferedWriter::flush`] 的 poll 形态（poll 状态机驱动用）。
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        // 先驱动在途 flush 批
        if let Some(flight) = self.flushing.as_mut() {
            ready!(self.writer.poll_write_multi_buffer(cx, flight))?;
            self.flushing = None;
        }
        if let Some(mut buf) = self.buffer.take() {
            if !buf.is_empty() {
                let mut mb = MultiBuffer::with_capacity(1);
                mb.push(buf);
                ready!(self.writer.poll_write_multi_buffer(cx, &mut mb))?;
            } else {
                buf.release();
            }
        }
        Poll::Ready(Ok(()))
    }

    /// [`BufferedWriter::write_multi_buffer_direct`] 的 poll 形态
    /// （MuxWriter 等 poll 状态机驱动用）：先排空内部缓存（保序），
    /// 再把 `mb` 整批直写底层。
    pub fn poll_write_multi_buffer_direct(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        ready!(self.poll_flush(cx))?;
        self.writer.poll_write_multi_buffer(cx, mb)
    }

    /// 检查是否为缓冲模式
    pub fn is_buffered(&self) -> bool {
        self.buffered
    }
}

impl Writer for BufferedWriter {
    fn poll_write_multi_buffer(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        if !self.buffered {
            // 直通模式：等价 write_buffer 非缓冲分支——不进内部缓存，整批转交
            return self.poll_write_multi_buffer_direct(cx, mb);
        }
        loop {
            // 在途 flush 优先驱动
            if let Some(flight) = self.flushing.as_mut() {
                ready!(self.writer.poll_write_multi_buffer(cx, flight))?;
                self.flushing = None;
            }

            let Some(mut buf) = mb.split_first() else { return Poll::Ready(Ok(())) };
            let buf_len = buf.len();

            // flush_next：先刷新既有缓存再缓冲新块（SetFlushNext 语义）
            if self.flush_next {
                self.stage_flush();
                self.flush_next = false;
                if self.flushing.is_some() {
                    mb.push_front(buf);
                    continue; // 回循环顶先驱动 flush，再回来处理本块
                }
            }

            // 吸收进缓存 / 缓存不足先冲刷 / 大块直写（write_buffer 语义）
            let cache_fits = match self.buffer.as_mut() {
                Some(inner) if inner.free() >= buf_len => true,
                Some(_) => {
                    self.stage_flush();
                    if self.flushing.is_some() {
                        mb.push_front(buf);
                        continue;
                    }
                    false
                },
                None => false,
            };

            if cache_fits {
                let inner = self.buffer.as_mut().expect("cache_fits 已确认存在");
                inner.write_from(buf.bytes());
                buf.release();
            } else if buf_len <= buf.capacity() / 2 {
                self.buffer = Some(buf);
            } else {
                let mut one = MultiBuffer::with_capacity(1);
                one.push(buf);
                ready!(self.writer.poll_write_multi_buffer(cx, &mut one))?;
            }
        }
    }

    fn shutdown(&self) {
        // 转发内层（pipe.Writer 覆写为实际 close → 读端 EOF）。默认 no-op 会让
        // 包裹 pipe 的会话写端永不通知 EOF（Go common.Close(s.output) 无对应）。
        // 不排空内部缓冲——需要保序的调用方先 flush 再 shutdown。
        self.writer.shutdown()
    }
}

impl BufferedWriter {
    /// 把内部缓存移入在途 flush 批（若非空）。仅 poll 路径使用。
    fn stage_flush(&mut self) {
        if self.flushing.is_none() {
            if let Some(mut buf) = self.buffer.take() {
                if !buf.is_empty() {
                    let mut mb = MultiBuffer::with_capacity(1);
                    mb.push(buf);
                    self.flushing = Some(mb);
                } else {
                    buf.release();
                }
            }
        }
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
    fn poll_write_multi_buffer(
        &mut self,
        _cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        // 同步丢弃：整批就地释放（回池），恒 Ready
        mb.release();
        Poll::Ready(Ok(()))
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
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.data.lock().expect("unpoisoned").extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
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
