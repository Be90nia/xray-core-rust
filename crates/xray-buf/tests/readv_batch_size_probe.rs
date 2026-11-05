//! 内存审计探针（2026-11-04 audit4-memory）：readv 聚合读的**单条目字节上界**实测。
//!
//! 为什么需要这条：`crates/xray-transport/src/bridge.rs` 的桥接 mpsc 背压闸
//! （`PIPE_BUF_CAP = 64`）按**条目数**计容量，不按字节。于是「桥接缓冲上界」 =
//! 64 × 单条目最大字节。单条目 = 一次 `read_multi_buffer()` 的 MultiBuffer：
//! - 基础形态：1-8 buffer × 8 KiB（注释声称的 512 KiB 口径）；
//! - readv 升窗后（`READ_BLOCK_MAX = 64 KiB`，连续 2 轮顶格满载触发）： 8 × 64 KiB = **512 KiB**。
//!
//! 本探针在真实 TCP 上跑稳态大吞吐，量出单条目实际能到多大（前若干轮 8 KiB 起步，
//! 升窗后应看到 ≥ 64 KiB 甚至 512 KiB 的条目）。
//!
//! 断言只压「条目字节 > 8 KiB 基线」这一条（升窗生效）；绝对峰值打印取证，不做
//! 脆断言（升窗依赖调度节奏，CI 机器慢时轮次组成会变）。

use tokio::io::AsyncWriteExt;
use xray_buf::io::{Reader, new_readv_reader_whole};

/// 稳态写入量：够触发升窗并跑出多个满载轮。
const PAYLOAD_MB: usize = 8;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::disallowed_methods, reason = "审计探针：模拟对端写入端，非生产任务托管面")]
async fn readv_multi_buffer_item_size_grows_past_base_block() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let writer = tokio::spawn(async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.set_nodelay(true).unwrap();
        let chunk = vec![0x5Au8; 64 * 1024];
        for _ in 0..(PAYLOAD_MB * 16) {
            if s.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = s.shutdown().await;
    });

    let (sock, _) = listener.accept().await.unwrap();
    sock.set_nodelay(true).unwrap();
    let mut reader = new_readv_reader_whole(sock);

    let mut total = 0usize;
    let mut max_item = 0usize;
    let mut items_over_base = 0usize;
    let mut items = 0usize;
    while let Ok(mb) = reader.read_multi_buffer().await {
        if mb.is_empty() {
            break;
        }
        let n = mb.len();
        items += 1;
        total += n;
        max_item = max_item.max(n);
        if n > 8 * 1024 {
            items_over_base += 1;
        }
        drop(mb);
        if total >= PAYLOAD_MB * 1024 * 1024 {
            break;
        }
    }
    let _ = writer.await;

    #[allow(clippy::print_stdout)]
    {
        println!(
            "readv probe: total={total} B, items={items}, max_item={max_item} B, \
             items_over_8KiB={items_over_base}"
        );
        println!(
            "bridge mpsc worst case (PIPE_BUF_CAP=64 items) = {} B = {:.1} MiB",
            64 * max_item,
            64.0 * max_item as f64 / (1024.0 * 1024.0)
        );
    }

    assert!(total > 0, "必须读到数据");
    assert_eq!(total, PAYLOAD_MB * 1024 * 1024, "字节守恒（探针自身正确性）");
    assert!(
        max_item > 8 * 1024,
        "稳态大吞吐下 readv 必须聚合出 > 基础块(8 KiB) 的条目，实测 max_item={max_item}"
    );
    assert!(
        max_item <= 8 * 64 * 1024,
        "单条目不得超过 MAX_READV(8) × READ_BLOCK_MAX(64 KiB)，实测 {max_item}"
    );
}
