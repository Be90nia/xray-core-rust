//! FxScope「完成条目滞留」最小复现（只读复核资产，不进产品代码）。
//!
//! 复现目标：udf `FxScope` 的任务**已完成**、`in_flight()==0`，但其 `JoinSet`
//! 条目仍占据分配器存活字节，直到调用方显式 `try_reap()` 或 scope 停机/drop。
//!
//! 口径：`skeleton_infra::memgov::CountingAllocator::live_bytes()`（udf 自带计数
//! 分配器，与 xray-cli 的 `XRAY_ALLOC_STATS` 同一读数语义）。

use std::sync::atomic::{AtomicUsize, Ordering};

use skeleton_infra::fx::FxScope;
use skeleton_infra::memgov::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

static DONE: AtomicUsize = AtomicUsize::new(0);

fn live() -> usize {
    CountingAllocator::live_bytes()
}

/// 等所有任务跑完（只看任务体自己的计数，不 join → 条目必须留在 JoinSet 里）。
async fn wait_done(n: usize) {
    while DONE.load(Ordering::Acquire) < n {
        tokio::task::yield_now().await;
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // (标签, 模式, 任务数)：0=tiny，1=堆 Vec 4KiB（完成即释放），2=future 内联 4KiB
    let cases = [
        ("tiny", 0u8, 2_000usize),
        ("tiny", 0, 20_000),
        ("vec4k", 1, 20_000),
        ("inline4k", 2, 2_000),
    ];

    println!(
        "case,n,retained_B_per_entry,retained_allocs_per_entry,after_reap_B_per_entry,in_flight_after_done,reaped"
    );
    for (label, mode, n) in cases {
        DONE.store(0, Ordering::Release);
        let scope = FxScope::new();

        // 预热：让分配器/运行时先付一次性开销，避免算进 per-entry。
        let warm = 200;
        for _ in 0..warm {
            let _ = scope.spawn_tracked(async { DONE.fetch_add(1, Ordering::AcqRel); }).unwrap();
        }
        wait_done(warm).await;
        let _ = scope.try_reap();

        let base = live();
        let base_allocs = CountingAllocator::live_allocs();
        for _ in 0..n {
            match mode {
                0 => {
                    let _ = scope
                        .spawn_tracked(async {
                            DONE.fetch_add(1, Ordering::AcqRel);
                        })
                        .unwrap();
                }
                1 => {
                    let _ = scope
                        .spawn_tracked(async {
                            let v = vec![7u8; 4096];
                            std::hint::black_box(&v);
                            DONE.fetch_add(1, Ordering::AcqRel);
                        })
                        .unwrap();
                }
                _ => {
                    let _ = scope
                        .spawn_tracked(async {
                            let mut buf = [0u8; 4096];
                            std::hint::black_box(&mut buf);
                            DONE.fetch_add(1, Ordering::AcqRel);
                        })
                        .unwrap();
                }
            }
        }
        wait_done(warm + n).await;
        // 任务体全部跑完仍不 join：此刻「已完成条目」全留在生命周期集里。
        let after_complete = live();
        let inflight = scope.in_flight();
        let retained = (after_complete as i64 - base as i64) / n as i64;
        let retained_allocs =
            (CountingAllocator::live_allocs() as i64 - base_allocs as i64) as f64 / n as f64;

        let reaped = scope.try_reap().len();
        let after_reap_live = live();
        let after_reap = (after_reap_live as i64 - base as i64) / n as i64;

        println!(
            "{label},{n},{retained},{retained_allocs:.2},{after_reap},{inflight},{reaped}"
        );
    }
}
