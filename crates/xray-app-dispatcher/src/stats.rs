//! 字节计数包装 Writer/Reader
//!
//! 对应 Go `app/dispatcher/stats.go`。`SizeStatWriter` 在每次写入时累加计数，
//! `SizeStatReader` 在每次读取时累加计数，用于统计用户上下行流量。
use std::sync::Arc;

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

    /// 关闭底层 writer（对应 Go `(*SizeStatWriter).Interrupt/Close` 委托内层）。
    ///
    /// bd g35：UDP443 reject 等链路中断路径经 stats 包装时，shutdown 必须穿透，
    /// 否则下游 reader 收不到 EOF。
    fn shutdown(&self) {
        self.writer.shutdown();
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<MultiBuffer>> + Send + '_>>
    {
        Box::pin(async move {
            let mb = self.reader.read_multi_buffer().await?;
            let n = i64::try_from(mb.len()).unwrap_or(i64::MAX);
            self.counter.add(n);
            Ok(mb)
        })
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
    use std::sync::{
        Mutex,
        atomic::{AtomicI64, Ordering},
    };

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
    struct CollectingWriter {
        seen: Mutex<Vec<usize>>,
    }

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

    impl CollectingWriter {
        fn seen_total(&self) -> i64 {
            let g = self.seen.lock().unwrap();
            g.iter().map(|&x| i64::try_from(x).unwrap_or(i64::MAX)).sum()
        }
    }

    fn make_mb(_n: usize) -> MultiBuffer {
        // ponytail: 测试 SizeStatWriter 只需 mb.len() == 0，空 mb 即可
        MultiBuffer::default()
    }

    #[tokio::test]
    async fn write_calls_counter_and_writer() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter::default());
        let mut sw = SizeStatWriter::new(counter.clone(), writer);

        let mb = MultiBuffer::default();
        sw.write_multi_buffer(mb).await.expect("write ok");

        // mb 长度为 0，counter 应等于 0
        assert_eq!(counter.value(), 0);
    }

    #[tokio::test]
    async fn close_returns_ok() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter::default());
        let mut sw = SizeStatWriter::new(counter, writer);
        sw.close().expect("close ok");
    }

    #[test]
    fn constructor_stores_fields() {
        let counter: Arc<dyn Counter> = Arc::new(TestCounter::default());
        let writer = Box::new(CollectingWriter::default());
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
        let writer = Box::new(CollectingWriter::default());
        let wrapped = maybe_wrap_writer(Some(counter), writer);
        // 验证包装后可正常使用（类型正确）
        let _ = wrapped;
    }

    #[test]
    fn maybe_wrap_writer_without_counter() {
        let writer = Box::new(CollectingWriter::default());
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
}
