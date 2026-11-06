//! bd n580i 条目口径钉桩 + u440m 字节闸收口：`bridge_link_with_stream_full`
//! 两向背压 = **条目闸 64 条**（`PIPE_BUF_CAP`）**+ 字节闸 2MiB/方向**
//! （`BRIDGE_BYTE_GATE_PER_DIRECTION_BYTES`，1KiB 许可粒度，许可随条目 drop
//! 归还）。
//!
//! n580i 当年的口径「64 条 × 512KiB = 32MiB、闸按条目不按字节」已被 u440m
//! 取代：32MiB 在途远超 xray_buf 池驻留 8MiB ⇒ 归还全丢 ⇒ 池命中率 0%
//! （sim-bridge-bytegate.md v3）。单条 64KiB（readv 腿一块）时字节闸先封顶：
//! 2048 许可 ÷ 64 许可/条 = 32 条在途，读侧拉取停在 `32（闸内）+ 1（手上一条
//! 待许可）` = **33 条**——写侧永久阻塞时拉取数钉在 33，改任一闸值即红。
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

/// 字节闸下 64KiB 条目的封顶拉取数 = `2MiB/64KiB`（闸内 32 条）`+ 1`（手上一条
/// 待许可）。此处**有意复制硬编码**而非从实现常量推导：改任一闸值/条目口径
/// 须同步改本值，否则本测试变红（正是要的效果；实现侧另有 memory_budget
/// 交叉断言与 bridge.rs 单测钉同一数字）。
const EXPECTED_PRODUCED: usize = 33;

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
async fn backpressure_byte_gate_caps_entries_at_budget() {
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

    // 等闸封顶：拉取数涨到 EXPECTED_PRODUCED 即说明字节闸已满、reader 正卡在
    // acquire。 （不靠「两次采样相等」判稳定——慢 CI 上采样间隙可能恰好无进展
    // 而误判。）用轮次计数代替 Instant::now（后者在本 crate clippy 禁用清单上）。
    let mut rounds = 0u32;
    while calls.load(Ordering::SeqCst) < EXPECTED_PRODUCED {
        assert!(
            rounds < 500,
            "10s 内未攒够 {} 条（实测 {}），字节闸未按预期封顶",
            EXPECTED_PRODUCED,
            calls.load(Ordering::SeqCst)
        );
        rounds += 1;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // 再静置一段，让封顶后的额外产出（若有）全部显现。
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let produced = calls.load(Ordering::SeqCst);
    assert_eq!(
        produced, EXPECTED_PRODUCED,
        "字节闸按字节记账：32×64KiB = 2MiB 占满许可 + 手上一条 ⇒ 读侧拉取应钉在 \
         {EXPECTED_PRODUCED} 条，实测 {produced}（条目闸口径下会是 65..66 ⇒ 红）"
    );
    // 在途字节 = 32×64KiB = 2MiB = 每方向预算（条目闸口径下应是 4MiB+ ⇒ 红）。
    assert_eq!(
        (produced - 1) * ENTRY_BYTES,
        2 * 1024 * 1024,
        "闸内条目字节账必须恰为每方向预算 2MiB"
    );

    handle.abort();
}
