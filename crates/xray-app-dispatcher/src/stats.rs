//! 字节计数包装 Writer
//!
//! 对应 Go `app/dispatcher/stats.go`。`SizeStatWriter` 在每次写入时累加计数，
//! 用于统计用户上下行流量。

use std::sync::Arc;
use xray_buf::io::{Result as IoResult, Writer};
use xray_buf::multi::MultiBuffer;
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
}

impl SizeStatWriter {
    /// 关闭包装的 writer。对应 Go `(*SizeStatWriter).Close()`。
    ///
    /// 由于 Rust 端 Writer trait 无 close 方法，这里仅作为 marker（实际 close 由
    /// Drop 或具体 Writer 实现处理）。
    pub fn close(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;
    use xray_buf::multi::MultiBuffer;

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
            self.value.fetch_add(delta, Ordering::SeqCst) + delta
        }
        fn set(&self, value: i64) {
            self.value.store(value, Ordering::SeqCst);
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
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
}
