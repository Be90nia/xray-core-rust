//! SegmentWriter（对应 Go `output.go`）。
//!
//! SegmentWriter 是 Connection 的输出端：把 segment 序列化后写到下层（UDP socket）。
//!
//! - [`SimpleSegmentWriter`]：buffered 单 segment 写，对应 Go 同名 struct。
//! - [`RetryableWriter`]：5 次 100ms 间隔重试包装，对应 Go 同名 struct。

use std::{io, sync::Arc, time::Duration};

use parking_lot::Mutex;

use crate::segment::Segment;

/// Segment 写入器接口（对应 Go `SegmentWriter interface`）。
pub trait SegmentWriter: Send + Sync {
    /// 写出一个 segment。失败返回 io::Error。
    fn write_segment(&self, seg: &dyn Segment) -> io::Result<()>;
}

/// 简单 segment 写入器：每次写一个 segment，序列化后调底层 writer。
///
/// 对应 Go `SimpleSegmentWriter`，但底层 writer 用 trait 注入而非 `io.Writer`，
/// 测试时可注入 `CollectWriter` 收集字节验证。
pub struct SimpleSegmentWriter<W: UnderlyingWriter> {
    inner: Mutex<Inner<W>>,
}

struct Inner<W: UnderlyingWriter> {
    writer: W,
}

/// 底层字节写入器接口（注入到 `SimpleSegmentWriter`）。
///
/// 与 `tokio::io::AsyncWrite` 不同：KCP 输出循环是同步驱动（`Updater` 触发
/// `flush`），所以这里是同步 `io::Write`。上层在异步环境中可包装
/// `tokio::io::AsyncWrite` 为阻塞调用（如 `block_in_place`）。
pub trait UnderlyingWriter: Send + Sync {
    /// 写入字节切片，返回写入字节数或错误。
    fn write_all(&self, buf: &[u8]) -> io::Result<()>;
}

impl<W: UnderlyingWriter> SimpleSegmentWriter<W> {
    /// 构造（对应 Go `NewSegmentWriter`）。
    pub fn new(writer: W) -> Self {
        Self { inner: Mutex::new(Inner { writer }) }
    }

    /// 借用底层 writer（用于 Close / 状态查询）。
    pub fn with_writer<R>(&self, f: impl FnOnce(&W) -> R) -> R {
        let inner = self.inner.lock();
        f(&inner.writer)
    }
}

impl<W: UnderlyingWriter> SegmentWriter for SimpleSegmentWriter<W> {
    fn write_segment(&self, seg: &dyn Segment) -> io::Result<()> {
        let mut buf = vec![0u8; seg.byte_size()];
        seg.serialize(&mut buf);
        let inner = self.inner.lock();
        inner.writer.write_all(&buf)
    }
}

/// 重试写入器（对应 Go `RetryableWriter`）。
///
/// 包装另一个 SegmentWriter，写入失败时按固定间隔重试 N 次（默认 5 次 100ms）。
///
/// 注意：Go 版本用 `retry.Timed(5, 100).On(...)`，是异步阻塞重试。Rust 端的
/// SegmentWriter 接口是同步的，因此重试是同步 sleep —— 必须在 `block_in_place`
/// 或独立线程中调用，不能直接在 async task 中阻塞。
pub struct RetryableWriter {
    inner: Arc<dyn SegmentWriter>,
    retries: u32,
    interval: Duration,
}

impl RetryableWriter {
    /// 构造（对应 Go `NewRetryableWriter`，默认 5 次 100ms）。
    pub fn new(inner: Arc<dyn SegmentWriter>) -> Self {
        Self { inner, retries: 5, interval: Duration::from_millis(100) }
    }

    /// 自定义重试参数。
    pub fn with_retries(inner: Arc<dyn SegmentWriter>, retries: u32, interval: Duration) -> Self {
        Self { inner, retries, interval }
    }
}

impl SegmentWriter for RetryableWriter {
    fn write_segment(&self, seg: &dyn Segment) -> io::Result<()> {
        let mut last_err: Option<io::Error> = None;
        for _ in 0..=self.retries {
            match self.inner.write_segment(seg) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(self.interval);
                },
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("retry exhausted")))
    }
}

// ============== CollectWriter (test helper) =

#[cfg(test)]
#[derive(Debug, Default)]
struct CollectWriter {
    chunks: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl UnderlyingWriter for std::sync::Arc<CollectWriter> {
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.chunks.lock().unwrap().push(buf.to_vec());
        Ok(())
    }
}

#[cfg(test)]
impl CollectWriter {
    fn collected(&self) -> Vec<u8> {
        let chunks = self.chunks.lock().unwrap();
        let mut out = Vec::new();
        for c in chunks.iter() {
            out.extend_from_slice(c);
        }
        out
    }

    fn call_count(&self) -> usize {
        self.chunks.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{CmdOnlySegment, Command, Segment};

    fn make_seg() -> CmdOnlySegment {
        let mut s = CmdOnlySegment::new();
        s.conv = 42;
        s.cmd = Command::Ping;
        s.peer_rto = 1234;
        s
    }

    #[test]
    fn simple_writer_serializes_segment_to_underlying() {
        let collect: std::sync::Arc<CollectWriter> = std::sync::Arc::new(CollectWriter::default());
        let writer = SimpleSegmentWriter::new(collect.clone());
        let seg = make_seg();
        writer.write_segment(&seg).expect("write ok");

        let bytes = collect.collected();
        assert_eq!(bytes.len(), seg.byte_size());
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 42);
        assert_eq!(bytes[2], Command::Ping as u8);
    }

    #[test]
    fn retryable_writer_succeeds_first_try() {
        let collect: std::sync::Arc<CollectWriter> = std::sync::Arc::new(CollectWriter::default());
        let inner: Arc<dyn SegmentWriter> = Arc::new(SimpleSegmentWriter::new(collect.clone()));
        let retry = RetryableWriter::new(inner);
        let seg = make_seg();
        retry.write_segment(&seg).expect("ok");
        assert_eq!(collect.call_count(), 1);
    }

    #[test]
    fn retryable_writer_retries_on_failure() {
        let fail_writer = AlwaysFail;
        let inner: Arc<dyn SegmentWriter> = Arc::new(SimpleSegmentWriter::new(fail_writer));
        // 用 2 次重试 1ms 间隔减少测试时间
        let retry = RetryableWriter::with_retries(inner, 2, Duration::from_millis(1));
        let seg = make_seg();
        let result = retry.write_segment(&seg);
        assert!(result.is_err(), "应失败");
    }

    #[test]
    fn retryable_writer_recovers_after_failures() {
        let intermittent = IntermittentWriter::new(2); // 前 2 次失败，第 3 次成功
        let inner: Arc<dyn SegmentWriter> = Arc::new(SimpleSegmentWriter::new(intermittent));
        let retry = RetryableWriter::with_retries(inner, 5, Duration::from_millis(1));
        let seg = make_seg();
        retry.write_segment(&seg).expect("第 3 次应成功");
    }

    #[derive(Debug, Clone, Copy)]
    struct AlwaysFail;

    impl UnderlyingWriter for AlwaysFail {
        fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
            Err(io::Error::other("always fail"))
        }
    }

    #[derive(Debug)]
    struct IntermittentWriter {
        fails_left: std::sync::Mutex<u32>,
    }

    impl IntermittentWriter {
        fn new(initial_fails: u32) -> Self {
            Self { fails_left: std::sync::Mutex::new(initial_fails) }
        }
    }

    impl UnderlyingWriter for IntermittentWriter {
        fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
            let mut fl = self.fails_left.lock().unwrap();
            if *fl > 0 {
                *fl -= 1;
                return Err(io::Error::other("transient fail"));
            }
            Ok(())
        }
    }
}
