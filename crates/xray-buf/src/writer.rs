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

    /// 写裸字节（非 vectored sink 的聚合交付口）：单次 `write_all`。
    ///
    /// 与 [`write_sequential`] 逐块写等价，区别是调用方自持字节缓冲
    /// （可常驻复用），本层不再包装 [`Buffer`]——聚合写不需要块语义。
    async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.inner.write_all(data).await.map_err(|e| io::classify_io_error(e, false))
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

    /// 排空 + 半关闭底层 AsyncWrite（poll_shutdown：TLS 层=flush sendable_tls
    /// 后发 close_notify；裸 TCP=FIN）。bd VISIONMAC：bridge 收尾必须走这里，
    /// 默认 no-op 会让 TLS BufWriter 语义滞留的尾巴随 drop 蒸发。
    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(poll_fn(|cx| Pin::new(&mut *self.inner).poll_shutdown(cx)))
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

    fn shutdown(&self) {
        // 转发内层（pipe.Writer 覆写为实际 close → 读端 EOF）。默认 no-op 会让
        // 包裹 pipe 的会话写端永不通知 EOF（Go common.Close(s.output) 无对应）。
        // 不排空内部缓冲——需要保序的调用方先 flush 再 shutdown。
        self.writer.shutdown()
    }
}

// ========== CoalescingWriter ==========

/// 聚合写常驻缓冲上限：单批字节超过此值时按块分次写出（字节序不变）。
///
/// 常规下行批 = readv 聚合读 8×8KB = 64KB（`readv.rs` MAX_READV=8 ×
/// DEFAULT_SIZE），远低于上限——上限只兜住异常大批，避免常驻缓冲无界增长。
const MAX_COALESCE: usize = 256 * 1024;

/// 整批聚合写入器（F2 服务端 TLS 写聚合）。
///
/// 底层不支持 vectored（TLS 层 `is_write_vectored()==false`）时，把一次
/// [`Writer::write_multi_buffer`] 的全部缓冲拼接为**单次** `write_all` 交付：
/// 8×8KB → 1×64KB，TLS 层产出 4×16KB record 而非 8×8KB，消除逐 record 的
/// 加密/排队/系统调用固定开销（harness btls 142→228 MB/s）。聚合边界 =
/// 单次 write_multi_buffer 调用：不跨调用积压、零交互延迟增量；单缓冲与
/// vectored-capable sink（裸 TCP sendmsg）直通内层，零拷贝零行为变化。
///
/// 拼接目标 = **常驻缓冲**（`buf` 字段，跨批复用 clear+extend）：不每批
/// 新鲜分配 Vec、不走 `Buffer::from_vec`（Frozen 永不回池），下行每字节
/// 零新增堆分配。批内字节超上限（256KB）时按块分次写出（字节序不变）；
/// 单块本身超限时直写该块（不拷贝）。
///
/// 仅服务端 flow=""（非 vision）装配启用——vision 帧写批边界语义保持原样。
pub struct CoalescingWriter {
    inner: SequentialWriter,
    /// 构造时快照 sink 能力：vectored-capable（裸 TCP）直通内层 iovec 聚合。
    vectored: bool,
    /// 常驻聚合缓冲：跨批复用（clear + extend），容量按批高水位增长。
    buf: Vec<u8>,
}

impl CoalescingWriter {
    /// 创建新的 CoalescingWriter
    pub fn new(w: impl AsyncWrite + Unpin + Send + 'static) -> Self {
        let vectored = w.is_write_vectored();
        Self { inner: SequentialWriter::new(w), vectored, buf: Vec::new() }
    }
}

impl Writer for CoalescingWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let buffers = mb.into_buffers();
            if self.vectored || buffers.len() <= 1 {
                return self.inner.write_multi_buffer(MultiBuffer::from_buffers(buffers)).await;
            }
            // 聚合路径：拼进常驻缓冲（clear + extend），零新鲜分配。
            for mut buf in buffers {
                if buf.len() > MAX_COALESCE {
                    // 单块超限：直写该块（不拷贝、不撑常驻缓冲），先前已聚合的
                    // 部分先刷出，保证字节序。
                    if !self.buf.is_empty() {
                        self.inner.write_bytes(&self.buf).await?;
                        self.buf.clear();
                    }
                    self.inner.write_bytes(buf.bytes()).await?;
                    buf.release();
                    continue;
                }
                if self.buf.len() + buf.len() > MAX_COALESCE {
                    // 常驻缓冲放不下这一块：先刷出已有部分（字节序不变）。
                    self.inner.write_bytes(&self.buf).await?;
                    self.buf.clear();
                }
                self.buf.extend_from_slice(buf.bytes());
                buf.release();
            }
            if !self.buf.is_empty() {
                self.inner.write_bytes(&self.buf).await?;
                self.buf.clear();
            }
            Ok(())
        })
    }

    fn shutdown(&self) {
        // 转发内层（同 BufferedWriter：pipe.Writer 覆写 EOF 通知不被吞）。
        self.inner.shutdown()
    }

    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        // bd VISIONMAC：桥收尾必须排空 TLS 层滞留尾巴，转发 poll_shutdown。
        self.inner.shutdown_flush()
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
        data: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
        chunk: Option<usize>,
        vectored_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl VectoredMock {
        fn new(chunk: Option<usize>) -> (Self, Self) {
            let data = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
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
            self.data.lock().extend_from_slice(buf);
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
                self.data.lock().extend_from_slice(&s[..take]);
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
        assert_eq!(*probe.data.lock(), b"aaabbbcc".as_slice(), "聚合写必须保序拼接全部块");
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
        assert_eq!(*probe.data.lock(), b"aaabbbccc".as_slice(), "部分写必须从断点续写且保序");
        assert_eq!(probe.vectored_calls.load(Relaxed), 3);
    }

    /// F2 CoalescingWriter 测试用非 vectored sink（TLS 层形态）：记录单次
    /// poll_write 调用数与全部落盘字节。
    struct NonVectoredMock {
        data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        write_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        shutdown_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl NonVectoredMock {
        fn new() -> (Self, Self) {
            fn counters() -> (
                std::sync::Arc<std::sync::atomic::AtomicUsize>,
                std::sync::Arc<std::sync::atomic::AtomicUsize>,
            ) {
                Default::default()
            }
            let (write_calls, shutdown_calls) = counters();
            let data: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
            (
                Self {
                    data: data.clone(),
                    write_calls: write_calls.clone(),
                    shutdown_calls: shutdown_calls.clone(),
                },
                Self { data, write_calls, shutdown_calls },
            )
        }
    }

    impl AsyncWrite for NonVectoredMock {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.write_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.data.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn is_write_vectored(&self) -> bool {
            false
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.shutdown_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_coalescing_writer_non_vectored_single_write() {
        // F2：非 vectored sink 上 3 块必须拼成**单次** write_all（8×8KB →
        // 1×64KB → TLS 层 4×16KB record，替代 8×8KB record）。
        let (mock, probe) = NonVectoredMock::new();
        let mut writer = CoalescingWriter::new(mock);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"aaa".to_vec()));
        mb.push(Buffer::from_vec(b"bbb".to_vec()));
        mb.push(Buffer::from_vec(b"cc".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");

        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(*probe.data.lock().unwrap(), b"aaabbbcc".as_slice(), "聚合写必须保序拼接全部块");
        assert_eq!(probe.write_calls.load(Relaxed), 1, "3 块应拼成单次 write_all");
    }

    #[tokio::test]
    async fn test_coalescing_writer_single_buffer_passthrough() {
        // 单缓冲直通：同样一次 write_all，不引入拷贝路径行为差异。
        let (mock, probe) = NonVectoredMock::new();
        let mut writer = CoalescingWriter::new(mock);

        let mb = MultiBuffer::from_buffer(Buffer::from_vec(b"hello".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");

        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(*probe.data.lock().unwrap(), b"hello".as_slice());
        assert_eq!(probe.write_calls.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn test_coalescing_writer_shutdown_flush_reaches_sink() {
        // bd VISIONMAC：桥收尾排空必须穿透包装层到达 sink（poll_shutdown）。
        let (mock, probe) = NonVectoredMock::new();
        let mut writer = CoalescingWriter::new(mock);

        let mb = MultiBuffer::from_buffer(Buffer::from_vec(b"tail".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");
        writer.shutdown_flush().await.expect("shutdown failed");

        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(*probe.data.lock().unwrap(), b"tail".as_slice(), "收尾前数据必须已落盘");
        assert_eq!(probe.shutdown_calls.load(Relaxed), 1, "shutdown_flush 必须转发到 sink");
    }
    /// F2 分配回归（bd ledtg）：第二批不得新分配常驻缓冲——容量不变即证明
    /// 复用（原先每批 `Vec::with_capacity` + `Buffer::from_vec` 新鲜分配）。
    #[tokio::test]
    async fn test_coalescing_writer_reuses_resident_buffer() {
        let (mock, probe) = NonVectoredMock::new();
        let mut writer = CoalescingWriter::new(mock);

        let batch = |tag: &[u8]| -> MultiBuffer {
            let mut mb = MultiBuffer::new();
            mb.push(Buffer::from_vec(tag.to_vec()));
            mb.push(Buffer::from_vec(b"second".to_vec()));
            mb.push(Buffer::from_vec(b"third".to_vec()));
            mb
        };

        writer.write_multi_buffer(batch(b"first")).await.expect("write failed");
        let cap_after_first = writer.buf.capacity();
        assert!(cap_after_first > 0, "首批必须撑起常驻缓冲");

        writer.write_multi_buffer(batch(b"again")).await.expect("write failed");
        assert_eq!(
            writer.buf.capacity(),
            cap_after_first,
            "第二批不得新分配常驻缓冲（容量应保持高水位）"
        );

        assert_eq!(
            *probe.data.lock().unwrap(),
            b"firstsecondthirdagainsecondthird".as_slice(),
            "跨批字节序必须保序"
        );
    }

    /// 超大批降级：单块超上限时直写、批内总量超上限时分块写出，字节序不变。
    #[tokio::test]
    async fn test_coalescing_writer_large_batch_order_preserved() {
        let (mock, probe) = NonVectoredMock::new();
        let mut writer = CoalescingWriter::new(mock);

        // 单块 300KB > MAX_COALESCE(256KB) → 直写不拷贝。
        let big = vec![0xABu8; 300 * 1024];
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"head".to_vec()));
        mb.push(Buffer::from_vec(big.clone()));
        mb.push(Buffer::from_vec(b"tail".to_vec()));
        writer.write_multi_buffer(mb).await.expect("write failed");

        let data = probe.data.lock().unwrap().clone();
        assert!(data.starts_with(b"head"), "批首字节必须在最前");
        assert!(data.ends_with(b"tail"), "批尾字节必须在最后");
        assert_eq!(data.len(), 4 + big.len() + 4, "字节数必须守恒");
        assert!(data[4..4 + big.len()].iter().all(|&b| b == 0xAB), "大块内容必须原样");
    }
}
