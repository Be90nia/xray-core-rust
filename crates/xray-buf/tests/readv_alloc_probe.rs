//! 只读探针：ReadVReader 读路径的**实际分配率**（allocs / bytes per MB）。
//!
//! 目的：把 `alloc_site::BUF_READ` 站点在 loopback 全栈实测里观测到的
//! 「cli 侧 2.5 MB 分配 / MB 传输」落到具体机制上——是分层池不回收
//! （每读新鲜分配），还是池命中（稳态近零）。判据只看分配字节数，不看绝对时间。
//!
//! 复现：
//! ```text
//! cargo test -p xray-buf --test readv_alloc_probe -- --ignored --nocapture
//! ```
//!
//! 口径：`PROBE_RUN=1` 时服务端灌 `TOTAL` 字节，客户端只做「读一批 → 立刻 drop」，
//! 与桥下行（读→写→drop）同形；前 `WARMUP` 字节不计，避免把池预热算进稳态。

// 探针本体：灌流任务与墙钟计时就是测量手段（非生产站点），逐点登记豁免。
#![allow(
    clippy::disallowed_methods,
    reason = "只读探针：tokio::spawn 承载灌流对端、Instant::now 是测量锚点本身"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

use xray_buf::{io::Reader as _, readv::ReadVReader};

/// 计数分配器：只统计次数与字节，直通系统分配器。
struct Counting;

static ALLOC_N: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static COUNTING: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) == 1 {
            ALLOC_N.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) == 1 {
            ALLOC_N.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const TOTAL: usize = 64 << 20; // 64 MiB
const WARMUP: usize = 4 << 20; // 前 4 MiB 只预热池

#[tokio::test(flavor = "current_thread")]
#[ignore = "只读探针：人工判读分配率，不参与 CI 门"]
async fn readv_reader_steady_state_allocs_per_mb() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let sender = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.set_nodelay(true).expect("nodelay");
        let chunk = vec![0x5Au8; 64 << 10];
        let mut sent = 0usize;
        while sent < TOTAL {
            s.write_all(&chunk).await.expect("write");
            sent += chunk.len();
        }
        s.shutdown().await.expect("shutdown");
    });

    let (sock, _peer) = listener.accept().await.expect("accept");
    let (rd, _wr) = sock.into_split();
    let mut reader = ReadVReader::new(rd);

    let mut recv = 0usize;
    let mut warm = WARMUP;
    let (mut n_at, mut b_at) = (0u64, 0u64);
    let t0 = Instant::now();

    loop {
        COUNTING.store(1, Ordering::Relaxed);
        let mb = reader.read_multi_buffer().await.expect("read");
        COUNTING.store(0, Ordering::Relaxed);
        if mb.is_empty() {
            break;
        }
        let len = mb.len();
        drop(mb); // 与桥写路径同形：写完即释放 → 缓冲回池
        recv += len;
        if warm > 0 {
            warm = warm.saturating_sub(len);
            // 预热期同样采样，但从基线里扣除。
            n_at = ALLOC_N.load(Ordering::Relaxed);
            b_at = ALLOC_BYTES.load(Ordering::Relaxed);
        }
    }

    let elapsed = t0.elapsed();
    let (n_end, b_end) = (ALLOC_N.load(Ordering::Relaxed), ALLOC_BYTES.load(Ordering::Relaxed));
    let steady_bytes = recv.saturating_sub(WARMUP);
    let d_n = n_end.saturating_sub(n_at);
    let d_b = b_end.saturating_sub(b_at);
    let mb_xfer = steady_bytes as f64 / (1u64 << 20) as f64;

    println!(
        "[PROBE] readv steady_state: xfer={:.1} MiB allocs={} alloc_bytes={} \
         => {:.3} allocs/MiB, {:.3} MB-alloc/MB-xfer, {:.1} MB/s",
        mb_xfer,
        d_n,
        d_b,
        d_n as f64 / mb_xfer,
        d_b as f64 / (steady_bytes.max(1) as f64),
        (recv as f64 / (1u64 << 20) as f64) / elapsed.as_secs_f64()
    );

    // 数据面守恒：读满待灌字节（唯一硬断言，不随池实现漂移）。
    assert_eq!(recv, TOTAL, "读侧必须收到全部灌入字节");
    sender.await.expect("sender");
}

/// 对照组：`SingleReader`（非 readv 连接的桥下行读腿，`bridge.rs:410` 分支）
/// 在同样「读一批 → 立即 drop」形态下的稳态分配率。
#[tokio::test(flavor = "current_thread")]
#[ignore = "只读探针：人工判读分配率，不参与 CI 门"]
async fn single_reader_steady_state_allocs_per_mb() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let sender = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.set_nodelay(true).expect("nodelay");
        let chunk = vec![0x5Au8; 64 << 10];
        let mut sent = 0usize;
        while sent < TOTAL {
            s.write_all(&chunk).await.expect("write");
            sent += chunk.len();
        }
        s.shutdown().await.expect("shutdown");
    });

    let (sock, _peer) = listener.accept().await.expect("accept");
    let (rd, _wr) = sock.into_split();
    let mut reader: Box<dyn xray_buf::io::Reader> =
        Box::new(xray_buf::reader::SingleReader::new(rd));

    let mut recv = 0usize;
    let mut warm = WARMUP;
    let (mut n_at, mut b_at) = (0u64, 0u64);
    let t0 = Instant::now();

    loop {
        COUNTING.store(1, Ordering::Relaxed);
        let mb = reader.read_multi_buffer().await.expect("read");
        COUNTING.store(0, Ordering::Relaxed);
        if mb.is_empty() {
            break;
        }
        let len = mb.len();
        drop(mb);
        recv += len;
        if warm > 0 {
            warm = warm.saturating_sub(len);
            n_at = ALLOC_N.load(Ordering::Relaxed);
            b_at = ALLOC_BYTES.load(Ordering::Relaxed);
        }
    }

    let elapsed = t0.elapsed();
    let (n_end, b_end) = (ALLOC_N.load(Ordering::Relaxed), ALLOC_BYTES.load(Ordering::Relaxed));
    let steady_bytes = recv.saturating_sub(WARMUP);
    let d_n = n_end.saturating_sub(n_at);
    let d_b = b_end.saturating_sub(b_at);
    let mb_xfer = steady_bytes as f64 / (1u64 << 20) as f64;

    println!(
        "[PROBE] single steady_state: xfer={:.1} MiB allocs={} alloc_bytes={} \
         => {:.3} allocs/MiB, {:.3} MB-alloc/MB-xfer, {:.1} MB/s",
        mb_xfer,
        d_n,
        d_b,
        d_n as f64 / mb_xfer,
        d_b as f64 / (steady_bytes.max(1) as f64),
        (recv as f64 / (1u64 << 20) as f64) / elapsed.as_secs_f64()
    );

    assert_eq!(recv, TOTAL, "读侧必须收到全部灌入字节");
    sender.await.expect("sender");
}
