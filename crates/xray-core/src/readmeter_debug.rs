//! [DEBUG-8sum-rm] 临时读侧计量（bd 8sum 第二轮 instrumentation，交付后整体删除）。
//!
//! 量化 REALITY 服务端 TLS 流的 `poll_read` 块大小与唤醒节奏：
//! - 每次 poll_read 的结果分类：Pending（TLS 无数据）/ Ready(0)（EOF）/ Ready(n)
//! - Ready(n) 的字节数直方图 + 相邻两次 Ready 的间隔统计
//! - 周期性（每 2s）与 Drop 时经 tracing::warn 汇总输出（warning 级即可见）
//!
//! 启用：env `XRAY_DEBUG_READMETER=1`（未设时计数旁路，仅剩一个布尔分支）。
//! 输出行样例：
//! `[readmeter] t=4.0s reads=12 pend=2000 tot=524288 max_n=8192 gaps{avg=310.2 max=322.5ms} hist{8k=12}`

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 直方图桶上界（字节）：64 / 256 / 1K / 2K / 4K / 8K / 16K / >16K。
const BUCKET_EDGES: [usize; 8] = [64, 256, 1024, 2048, 4096, 8192, 16384, usize::MAX];

#[derive(Default)]
struct State {
    total_bytes: u64,
    ready_reads: u64,
    pending_polls: u64,
    zero_reads: u64,
    max_n: u64,
    sum_gap_us: u64,
    max_gap_us: u64,
    hist: [u64; 8],
    last_ready: Option<Instant>,
}

impl State {
    fn record_ready(&mut self, n: usize, now: Instant) {
        self.total_bytes += n as u64;
        self.ready_reads += 1;
        self.max_n = self.max_n.max(n as u64);
        for (i, edge) in BUCKET_EDGES.iter().enumerate() {
            if n <= *edge {
                self.hist[i] += 1;
                break;
            }
        }
        if let Some(prev) = self.last_ready {
            let gap = now.duration_since(prev).as_micros() as u64;
            self.sum_gap_us += gap;
            self.max_gap_us = self.max_gap_us.max(gap);
        }
        self.last_ready = Some(now);
    }

    fn snapshot_line(&self, elapsed: Duration) -> String {
        let gaps = if self.ready_reads > 1 {
            format!(
                " gaps{{avg={:.1} max={:.1}ms}}",
                self.sum_gap_us as f64 / 1000.0 / (self.ready_reads - 1) as f64,
                self.max_gap_us as f64 / 1000.0
            )
        } else {
            String::new()
        };
        let hist = BUCKET_EDGES
            .iter()
            .zip(self.hist.iter())
            .filter(|(_, c)| **c > 0)
            .map(|(e, c)| {
                if *e == usize::MAX {
                    format!(">16k={c}")
                } else {
                    format!("{e}={c}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "t={:.1}s reads={} pend={} eof={} tot={}B max_n={}{} hist{{{}}}",
            elapsed.as_secs_f64(),
            self.ready_reads,
            self.pending_polls,
            self.zero_reads,
            self.total_bytes,
            self.max_n,
            gaps,
            hist
        )
    }
}

struct Shared {
    enabled: bool,
    streams: AtomicU64,
    st: Mutex<State>,
    created: Instant,
}

impl Shared {
    fn dump(&self, final_dump: bool) {
        if !self.enabled {
            return;
        }
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        let line = st.snapshot_line(self.created.elapsed());
        let ready = st.ready_reads;
        // 周期 dump 后清空增量窗口（FINAL 保留累计值）。
        if !final_dump {
            *st = State::default();
        }
        drop(st);
        tracing::warn!(
            target: "readmeter",
            "[DEBUG-8sum-rm]{} [ready_total={ready}] {line}",
            if final_dump { " FINAL" } else { "" },
        );
    }
}

pub struct ReadMeterStream<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S> ReadMeterStream<S> {
    fn new(inner: S, enabled: bool) -> Self {
        let shared = Arc::new(Shared {
            enabled,
            streams: AtomicU64::new(1),
            st: Mutex::new(State::default()),
            created: Instant::now(),
        });
        if enabled {
            let dumper = Arc::downgrade(&shared);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(2));
                tick.tick().await; // 首个 tick 立即返回，跳过
                loop {
                    tick.tick().await;
                    match dumper.upgrade() {
                        Some(s) => s.dump(false),
                        None => break, // 最后一个流已 drop，dumper 退出
                    }
                }
            });
        }
        Self { inner, shared }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadMeterStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.shared.enabled {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let before_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before_len;
                let mut st = self.shared.st.lock().unwrap_or_else(|e| e.into_inner());
                if n == 0 {
                    st.zero_reads += 1;
                } else {
                    st.record_ready(n, Instant::now());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                let mut st = self.shared.st.lock().unwrap_or_else(|e| e.into_inner());
                st.pending_polls += 1;
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadMeterStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for ReadMeterStream<S> {
    fn drop(&mut self) {
        let left = self.shared.streams.fetch_sub(1, Ordering::Relaxed);
        if left == 1 {
            self.shared.dump(true);
        }
    }
}

/// env 门控包装：未设 `XRAY_DEBUG_READMETER` 时计数旁路（单布尔分支，透明传递）。
pub fn wrap_readmeter<S>(s: S) -> ReadMeterStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let enabled = std::env::var_os("XRAY_DEBUG_READMETER").is_some();
    ReadMeterStream::new(s, enabled)
}
