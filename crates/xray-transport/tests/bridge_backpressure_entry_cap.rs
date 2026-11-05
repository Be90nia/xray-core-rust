//! bd n580i：bridge 背压闸「按**条目**计」口径的行为钉桩。
//!
//! `bridge_link_with_stream_full` 的两向背压闸是 bounded mpsc，容量按
//! **条目**（MultiBuffer 个数）计：每方向 `PIPE_BUF_CAP` = 64 条。单条的字节数
//! 由**生产侧**决定（下行 readv 腿顶格 = 8 块 × 64KiB = 512KiB），故单方向
//! 在途上界 = 64 条 × 512KiB = **32MiB**——**不是** 512KiB（512KiB 是 Go 每连接
//! pipe 的字节软限，与本闸的条目闸不同量纲）。
//!
//! 本测试从**行为**侧钉住条目语义（纯注释会被后续改动悄悄改漂，正是本票的成因）：
//! 写侧永久阻塞时，读侧最多产出 `64（mpsc 缓冲）+ 1（writer 持有）+ 1（send
//! 阻塞）` = 65..66 条；把单条放大到 64KiB 后累计字节远超 512KiB ⇒ 闸不是字节闸。
//!
//! 复现：
//! ```text
//! cargo test -p xray-transport --test bridge_backpressure_entry_cap
//! ```

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_buf::{io::Reader, multi::MultiBuffer};
use xray_features::policy::TimeoutPolicy;
use xray_transport::{bridge::bridge_link_with_stream_full, connection::Connection, link::Link};

/// 单条 MultiBuffer 的字节数（64KiB = readv 升窗后的一块；亦即 readv 腿的顶格量级）。
const ENTRY_BYTES: usize = 64 * 1024;

/// 闸的**条目**容量（= `bridge_link_with_stream_full` 内的 `PIPE_BUF_CAP`）。
/// 此处复制一份供断言：改实现容量须同步改本值，否则本测试变红（正是要的效果）。
const PIPE_BUF_CAP: usize = 64;

/// 计数读腿：每轮交一条 [`ENTRY_BYTES`] 的 MultiBuffer，统计被拉起次数。
struct CountingReader {
    calls: Arc<AtomicUsize>,
}

impl Reader for CountingReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&vec![0u8; ENTRY_BYTES]);
            Ok(mb)
        })
    }
}

/// 写侧永久阻塞的连接（模拟对端不读）：`up_writer` 卡在 write ⇒ 上行 mpsc
/// 只可能靠**条目数**封顶，字节数封不住。
struct StalledConn {
    waker: Mutex<Option<std::task::Waker>>,
}

impl AsyncRead for StalledConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        *self.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for StalledConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        *self.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl Connection for StalledConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

#[tokio::test]
async fn backpressure_gate_counts_entries_not_bytes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let link = Link::new(
        Box::new(CountingReader { calls: Arc::clone(&calls) }) as Box<dyn Reader>,
        xray_buf::io::new_writer(tokio::io::sink()),
    );
    let policy = TimeoutPolicy::default();

    let handle = xray_common::testing::spawn("bridge-backpressure-gate", async move {
        let _ =
            bridge_link_with_stream_full(link, StalledConn { waker: Mutex::new(None) }, &policy)
                .await;
    });

    // 等闸封顶：条目数涨到 PIPE_BUF_CAP+1 即说明 mpsc 已满、reader 正卡在 send。
    // （不靠「两次采样相等」判稳定——慢 CI 上采样间隙可能恰好无进展而误判。）
    // 用轮次计数代替 Instant::now（后者在本 crate clippy 禁用清单上）。
    let mut rounds = 0u32;
    while calls.load(Ordering::SeqCst) < PIPE_BUF_CAP + 1 {
        assert!(
            rounds < 500,
            "10s 内未攒够 {} 条（实测 {}），背压闸未按预期封顶",
            PIPE_BUF_CAP + 1,
            calls.load(Ordering::SeqCst)
        );
        rounds += 1;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // 再静置一段，让封顶后的额外产出（若有）全部显现。
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let produced = calls.load(Ordering::SeqCst);
    assert!(
        (PIPE_BUF_CAP + 1..=PIPE_BUF_CAP + 2).contains(&produced),
        "闸按条目计：mpsc 缓冲 {PIPE_BUF_CAP} 条 + writer 持有 1 条 + send 阻塞 1 条 \
         ⇒ 读侧应产出 {}..{} 条，实测 {produced}",
        PIPE_BUF_CAP + 1,
        PIPE_BUF_CAP + 2,
    );
    // 单条 64KiB ⇒ 累计字节远超 512KiB ⇒ 闸绝不是 512KiB 的字节闸。
    assert!(
        produced * ENTRY_BYTES > 512 * 1024,
        "累计在途字节 {} 应远超 512KiB（闸按条目不按字节）",
        produced * ENTRY_BYTES,
    );

    handle.abort();
}
