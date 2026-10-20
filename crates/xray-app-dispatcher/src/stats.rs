//! 字节计数包装 Writer/Reader
//!
//! 对应 Go `app/dispatcher/stats.go`。`SizeStatWriter` 在每次写入时累加计数，
//! `SizeStatReader` 在每次读取时累加计数，用于统计用户上下行流量。
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use xray_buf::{
    io::{Reader, Result as IoResult, Writer},
    multi::MultiBuffer,
};
use xray_features::stats::Counter;

/// 字节计数 Writer 包装
///
/// 对应 Go `SizeStatWriter struct { Counter stats.Counter; Writer buf.Writer }`。
/// 将每次 `write_multi_buffer` 的字节数累加到 Counter，再转发给内部 Writer。
pub struct SizeStatWriter {
    /// 流量计数器（通常是 `Arc<dyn Counter>`）
    pub counter: Arc<dyn Counter>,
    /// 被包装的 Writer
    pub writer: Box<dyn Writer>,
}

impl SizeStatWriter {
    /// 用 counter 和 writer 构造。
    #[must_use]
    pub fn new(counter: Arc<dyn Counter>, writer: Box<dyn Writer>) -> Self {
        Self { counter, writer }
    }
}

impl Writer for SizeStatWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            let n = i64::try_from(mb.len()).unwrap_or(i64::MAX);
            self.counter.add(n);
            self.writer.write_multi_buffer(mb).await
        })
    }

    /// bd d881⑤：poll 形态转发——默认实现把 `mb` 搬进一次性 future，管道满
    /// Pending 即丢数据（调用方重试变空手写入）。就地转发内层 poll；计数在
    /// Ready 落一次（Pending 期间数据留在 `mb`，重复 poll 不重复计数）。
    fn poll_write_multi_buffer(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<IoResult<()>> {
        let n = mb.len();
        match self.writer.poll_write_multi_buffer(cx, mb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.counter.add(i64::try_from(n).unwrap_or(i64::MAX));
                Poll::Ready(result)
            },
        }
    }

    /// 关闭底层 writer（对应 Go `(*SizeStatWriter).Interrupt/Close` 委托内层）。
    ///
    /// bd g35：UDP443 reject 等链路中断路径经 stats 包装时，shutdown 必须穿透，
    /// 否则下游 reader 收不到 EOF。
    fn shutdown(&self) {
        self.writer.shutdown();
    }

    /// 排空 + 半关闭穿透（bd VISIONMAC：隧道写半收尾必须穿透 stats 包装）。
    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        self.writer.shutdown_flush()
    }
}

impl SizeStatWriter {
    /// 关闭包装的 writer。对应 Go `(*SizeStatWriter).Close()`。
    ///
    /// Rust 端 Writer trait 无 close 方法，marker — 实际 close 由 Drop 或具体 Writer 处理。
    pub fn close(&mut self) -> IoResult<()> {
        Ok(())
    }
}

/// 字节计数 Reader 包装
///
/// 对称于 SizeStatWriter。在每次 `read_multi_buffer` 时累加字节数到 Counter。
/// 用于 downlink 方向：从 outbound reader 读取的字节 = 下行流量。
pub struct SizeStatReader {
    /// 流量计数器
    pub counter: Arc<dyn Counter>,
    /// 被包装的 Reader
    pub reader: Box<dyn Reader>,
}

impl SizeStatReader {
    /// 用 counter 和 reader 构造。
    #[must_use]
    pub fn new(counter: Arc<dyn Counter>, reader: Box<dyn Reader>) -> Self {
        Self { counter, reader }
    }
}

impl Reader for SizeStatReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = IoResult<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            let mb = self.reader.read_multi_buffer().await?;
            let n = i64::try_from(mb.len()).unwrap_or(i64::MAX);
            self.counter.add(n);
            Ok(mb)
        })
    }

    /// bd d881⑤：poll 形态转发（waker 注册/数据保留语义由内层承担）；
    /// 成功读到才计数（与 async 路径一致）。
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<MultiBuffer>> {
        match self.reader.poll_read_multi_buffer(cx) {
            Poll::Ready(Ok(mb)) => {
                let n = i64::try_from(mb.len()).unwrap_or(i64::MAX);
                self.counter.add(n);
                Poll::Ready(Ok(mb))
            },
            other => other,
        }
    }
}

/// 如果 counter 存在，用 SizeStatWriter 包装 writer；否则原样返回。
pub fn maybe_wrap_writer(
    counter: Option<Arc<dyn Counter>>,
    writer: Box<dyn Writer>,
) -> Box<dyn Writer> {
    match counter {
        Some(c) => Box::new(SizeStatWriter::new(c, writer)),
        None => writer,
    }
}

/// 如果 counter 存在，用 SizeStatReader 包装 reader；否则原样返回。
pub fn maybe_wrap_reader(
    counter: Option<Arc<dyn Counter>>,
    reader: Box<dyn Reader>,
) -> Box<dyn Reader> {
    match counter {
        Some(c) => Box::new(SizeStatReader::new(c, reader)),
        None => reader,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    use xray_buf::multi::MultiBuffer;

    use super::*;

    /// 测试用 Counter（实现 xray_features::stats::Counter）
    #[derive(Debug, Default)]
    struct TestCounter {
        value: AtomicI64,
    }

    impl Counter for TestCounter {
        fn value(&self) -> i64 {
            self.value.load(Ordering::SeqCst)
        }

        fn add(&self, delta: i64) -> i64 {
            // 对齐 Go 语义：返回旧值（features::stats::Counter trait 修正后）
            self.value.fetch_add(delta, Ordering::SeqCst)
        }

        fn set(&self, value: i64) -> i64 {
            // 对齐 Go 语义：返回旧值
            self.value.swap(value, Ordering::SeqCst)
        }
    }

    /// 测试用 Writer，仅记录被调用的 MultiBuffer 长度
    #[derive(Debug, Default)]
    struct CollectingWriter;

    impl Writer for CollectingWriter {
        fn write_multi_buffer(
            &mut self,
            mb: MultiBuffer,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>>
        {
            let _n = mb.len();
            Box::pin(async move {
                // 只记长度，丢弃 mb
                drop(mb);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn write_calls_counter_and_writer() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter);
        let mut sw = SizeStatWriter::new(counter.clone(), writer);

        let mb = MultiBuffer::default();
        sw.write_multi_buffer(mb).await.expect("write ok");

        // mb 长度为 0，counter 应等于 0
        assert_eq!(counter.value(), 0);
    }

    #[tokio::test]
    async fn close_returns_ok() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter);
        let mut sw = SizeStatWriter::new(counter, writer);
        sw.close().expect("close ok");
    }

    #[test]
    fn constructor_stores_fields() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter);
        let sw = SizeStatWriter::new(counter.clone(), writer);
        assert_eq!(sw.counter.value(), 0);
    }

    // --- SizeStatReader ---

    /// 测试用 Reader，返回固定大小的 MultiBuffer
    struct FixedReader {
        data: Vec<Vec<u8>>,
        idx: usize,
    }

    impl FixedReader {
        fn new(data: Vec<Vec<u8>>) -> Self {
            Self { data, idx: 0 }
        }
    }

    impl Reader for FixedReader {
        fn read_multi_buffer(
            &mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<MultiBuffer>> + Send + '_>>
        {
            let mb = if self.idx < self.data.len() {
                let mut buf = MultiBuffer::new();
                buf.merge_bytes(&self.data[self.idx]);
                self.idx += 1;
                buf
            } else {
                MultiBuffer::default()
            };
            Box::pin(async move { Ok(mb) })
        }
    }

    #[tokio::test]
    async fn reader_counts_bytes() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let reader = Box::new(FixedReader::new(vec![b"hello".to_vec(), b"world".to_vec()]));
        let mut sr = SizeStatReader::new(counter.clone(), reader);

        let mb1 = sr.read_multi_buffer().await.unwrap();
        assert_eq!(mb1.len(), 5);
        let mb2 = sr.read_multi_buffer().await.unwrap();
        assert_eq!(mb2.len(), 5);
        assert_eq!(counter.value(), 10);
    }

    #[test]
    fn maybe_wrap_writer_with_counter() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter);
        let wrapped = maybe_wrap_writer(Some(counter), writer);
        // 验证包装后可正常使用（类型正确）
        let _ = wrapped;
    }

    #[test]
    fn maybe_wrap_writer_without_counter() {
        let writer = Box::new(CollectingWriter);
        let wrapped = maybe_wrap_writer(None::<Arc<dyn Counter>>, writer);
        let _ = wrapped;
    }

    #[test]
    fn maybe_wrap_reader_with_counter() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let reader = Box::new(FixedReader::new(vec![]));
        let wrapped = maybe_wrap_reader(Some(counter), reader);
        let _ = wrapped;
    }

    #[test]
    fn maybe_wrap_reader_without_counter() {
        let reader = Box::new(FixedReader::new(vec![]));
        let wrapped = maybe_wrap_reader(None::<Arc<dyn Counter>>, reader);
        let _ = wrapped;
    }

    #[tokio::test]
    async fn size_stat_writer_shutdown_propagates_to_inner() {
        // reject 路径（bd g35）依赖 shutdown 穿透 stats 包装关闭下行
        let (r, w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = maybe_wrap_writer(Some(counter), Box::new(w));

        writer.shutdown();

        let mut reader = Box::new(r) as Box<dyn xray_buf::io::Reader>;
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(2), reader.read_multi_buffer())
                .await
                .expect("shutdown not propagated: read hangs");
        assert!(
            matches!(res, Err(xray_buf::io::Error::Eof)),
            "shutdown must propagate through SizeStatWriter, got: {res:?}"
        );
    }

    // --- bd d881⑤：poll 形态转发 ---

    /// waker 计数器：判定内层 poll 是否真的拿到 cx（注册了唤醒）。
    struct WakeCounter(AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<WakeCounter>, std::task::Waker) {
        let wc = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wc.clone());
        (wc, waker)
    }

    /// 第一次 poll Pending（模拟注册 waker + 稍后唤醒），第二次 Ready 消费 mb。
    struct PendingOnceWriter {
        polls: AtomicUsize,
    }

    impl Writer for PendingOnceWriter {
        fn write_multi_buffer(
            &mut self,
            _mb: MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(())))
        }

        fn poll_write_multi_buffer(
            &mut self,
            cx: &mut Context<'_>,
            mb: &mut MultiBuffer,
        ) -> Poll<IoResult<()>> {
            if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            std::mem::take(mb).release();
            Poll::Ready(Ok(()))
        }
    }

    /// 默认实现会把 `mb` 搬进一次性 future（Pending 后 mb 变空）——本测试锚定
    /// SizeStatWriter 覆写必须就地转发：Pending 保留数据、注册 waker、不计数。
    #[test]
    fn size_stat_writer_poll_forward_keeps_mb_and_counts_once() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let mut sw = SizeStatWriter::new(
            counter.clone(),
            Box::new(PendingOnceWriter { polls: AtomicUsize::new(0) }),
        );
        let (wc, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"hello");
        assert!(matches!(sw.poll_write_multi_buffer(&mut cx, &mut mb), Poll::Pending));
        assert_eq!(wc.0.load(Ordering::SeqCst), 1, "Pending 时必须注册 waker（转发内层 poll）");
        assert_eq!(mb.len(), 5, "Pending 后数据必须留在 mb（默认实现会丢弃）");
        assert_eq!(counter.value(), 0, "Pending 不得计数");

        assert!(matches!(sw.poll_write_multi_buffer(&mut cx, &mut mb), Poll::Ready(Ok(()))));
        assert_eq!(counter.value(), 5, "Ready 计数恰一次");
        assert!(mb.is_empty());
    }

    /// 同款锚定读端：Pending 不计数、waker 注册；Ready 计数恰一次。
    struct PendingOnceReader {
        polls: AtomicUsize,
        payload: Vec<u8>,
    }

    impl Reader for PendingOnceReader {
        fn read_multi_buffer(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = IoResult<MultiBuffer>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(MultiBuffer::default())))
        }

        fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<MultiBuffer>> {
            if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&self.payload);
            Poll::Ready(Ok(mb))
        }
    }

    #[test]
    fn size_stat_reader_poll_forward_counts_on_ready() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let mut sr = SizeStatReader::new(
            counter.clone(),
            Box::new(PendingOnceReader { polls: AtomicUsize::new(0), payload: b"abcd".to_vec() }),
        );
        let (wc, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(sr.poll_read_multi_buffer(&mut cx), Poll::Pending));
        assert_eq!(wc.0.load(Ordering::SeqCst), 1);
        assert_eq!(counter.value(), 0, "Pending 不得计数");

        match sr.poll_read_multi_buffer(&mut cx) {
            Poll::Ready(Ok(mb)) => assert_eq!(mb.len(), 4),
            other => panic!("expected data, got {other:?}"),
        }
        assert_eq!(counter.value(), 4);
    }

    /// bd d881⑤ e2e：计数开启 + 真实 pipe 满管道——修复前默认 poll 实现把
    /// mb 搬进一次性 future，Pending 丢数据（重试变空手写入假成功）。修复后
    /// 全部字节必达 + 双向计数恰等总量。
    #[tokio::test]
    async fn size_stat_wrapped_pipe_delivers_all_bytes_when_full() {
        let (pr, pw) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption {
            limit: 4096,
            ..Default::default()
        });
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let mut writer = maybe_wrap_writer(Some(counter.clone()), Box::new(pw));
        let mut reader = maybe_wrap_reader(Some(counter.clone()), Box::new(pr));

        let payload: Vec<u8> = (0..64 * 1024).map(|i| i as u8).collect();
        let w_task = tokio::spawn(async move {
            // 8KB 分块：第 2 块起管道已满（>4KB limit），必须走 Pending 等待路径。
            for chunk in payload.chunks(8 * 1024) {
                let mut mb = MultiBuffer::new();
                mb.merge_bytes(chunk);
                writer.write_multi_buffer(mb).await.unwrap();
            }
            writer.shutdown();
        });
        let r_task = tokio::spawn(async move {
            let mut got = 0usize;
            loop {
                match reader.read_multi_buffer().await {
                    Ok(mb) => got += mb.len(),
                    Err(xray_buf::io::Error::Eof) => break,
                    Err(e) => panic!("read error: {e:?}"),
                }
            }
            got
        });

        let (w_res, r_res) = tokio::join!(
            tokio::time::timeout(std::time::Duration::from_secs(10), w_task),
            tokio::time::timeout(std::time::Duration::from_secs(10), r_task),
        );
        w_res.expect("满管道写未在 10s 内完成（疑似丢唤醒挂死）").expect("writer task failed");
        let got =
            r_res.expect("满管道读未在 10s 内完成（疑似丢唤醒挂死）").expect("reader task failed");
        assert_eq!(got, 64 * 1024, "满管道下全部字节必达");
        assert_eq!(counter.value(), 2 * 64 * 1024, "读写双向各计一次总量");
    }
}
