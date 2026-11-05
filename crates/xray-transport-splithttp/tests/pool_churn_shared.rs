//! bd kw2si 复审：**进程级共享块池**的分配 churn 体检（只测不改码）。
//!
//! # 被测对象
//!
//! 生产共享池 `shared_pool(64 KiB)`（`crates/xray-transport-splithttp/src/pool_stream.rs`）：
//!
//! ```text
//! ObjectPool::with_reset(
//!     max      = pool_max_blocks(64 KiB) = POOL_BYTE_BUDGET(2 MiB) / 64 KiB = 32 块
//!     idle_cap = 同上 = 32 块
//!     factory  = || vec![0u8; 64 KiB]        （每次新构造 = 一次 64 KiB 分配）
//!     reset    = 容量归一到 64 KiB
//!     phase    = OnReturn
//! )
//! ```
//!
//! `pool_stream` 模块是 `pub(crate)`，集成测试（`tests/` = 外部 crate）够不到生产单例，
//! 故本文件用**同参复刻**（同一个 udf `ObjectPool` 类型 + 同一组构造参数）作测量仪器：
//! udf 池的全部记账语义由 `max`/`idle_cap`/factory/reset/phase 决定，与实例身份无关，
//! 故复刻件的 metrics 与生产单例逐项同义（生产侧唯一差异 = 全进程共享同一实例，
//! 复刻件每档独立新建以保证读数隔离）。
//!
//! 关键语义（udf `ObjectPool`）：
//!
//! - `max` = **池宇宙**（idle + 正常借出）硬上界，且**按分片均分**：`share(max, 8, idx) = 4` ⇒
//!   全进程最多 **32 块**存活于池内（= 2 MiB，与 `POOL_BYTE_BUDGET` 口径一致）。
//! - `idle_cap` 同为 32 ⇒ 全进程最多缓存 32 块（每片 4）。
//! - 借出四路径（`objpool.rs::pop_or_build`）：① 命中 idle（`reused++`）→ ② 宇宙扩容
//!   （`constructed++`，进入宇宙）→ ③ **宇宙已满 ⇒ 降级直构**（`constructed++` 且
//!   `degraded++`，该块**不入宇宙**，归还即释放）→ ④ 同 ③。
//! - `dropped_overflow` 只在**宇宙内**块归还时无处安放（每片 idle 已满且无片可迁）才 +1； 由于
//!   `idle_cap == max`（每片 idle 上限 = 宇宙上限），归还必落在原属片 ⇒ 该计数恒 0。
//!
//! # 判据
//!
//! 设进程内**同时在飞的块数** = I（= 并发流数 × 每流在飞块数）：
//!
//! - I ≤ 32 ⇒ 每轮 `reused += I`，`constructed` 不再增长 ⇒ 池完全吸收，无 churn。
//! - I > 32 ⇒ 每轮 `reused += 32`、`degraded += I-32`、`constructed += I-32` ⇒ **超出 32
//!   的在飞块每次借出都是一次全新 64 KiB 分配**（churn）。
//!
//! 即：churn 的触发条件是**进程内在飞块总数 > 32**，不是"流数 > 32"。
//!
//! # 跑法
//!
//! ```text
//! cargo test -p xray-transport-splithttp --test pool_churn_shared -- --nocapture
//! ```

// 测量面需真并发（每条"流"一个 OS 线程 + barrier 同步）⇒ 豁免线程禁令：
// 托管面（FxScope/PluginContext）在集成测试 binary 里不可达，且本测量要求
// 阻塞线程 + 确定性 barrier（异步任务调度会引入时序竞争，破坏可复现性）。
#![allow(
    clippy::disallowed_methods,
    reason = "测试：并发测量面用 OS 线程 + barrier 做确定性同步（托管面在测试 binary 不可达）"
)]

use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use skeleton_infra::{ObjectPool, ObjectPoolTuning, Owned, ResetPhase};

/// 生产 chunk 大小（`pool_stream.rs::UPLINK_CHUNK` = `hub::handler::DUPLEX_BUF` = 64 KiB）。
const CHUNK: usize = 64 * 1024;

/// 生产池宇宙块数：`POOL_BYTE_BUDGET`(2 MiB) / 64 KiB = 32（`pool_stream.rs::pool_max_blocks`）。
const UNIVERSE_BLOCKS: usize = 32;

/// 测量轮数（每轮 = 一次"全部流同时借出再全部归还"）。
const ROUNDS: usize = 8;

/// 生产共享池的同参复刻（见文件头「被测对象」）。
fn shared_pool_replica() -> Arc<ObjectPool<Vec<u8>>> {
    Arc::new(ObjectPool::with_reset(
        UNIVERSE_BLOCKS,
        UNIVERSE_BLOCKS,
        move || vec![0u8; CHUNK],
        move |buf: &mut Vec<u8>| {
            // 容量归一（生产 reset 钩子同款：只比较 len，命中即零成本）。
            if buf.len() != CHUNK {
                buf.clear();
                buf.resize(CHUNK, 0);
            }
        },
        ResetPhase::OnReturn,
    ))
}

/// 一档测量的读数（udf `ObjectPoolMetrics` 逐项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reading {
    constructed: u64,
    reused: u64,
    degraded: u64,
    dropped_overflow: u64,
    idle_blocks: usize,
    borrowed_blocks: usize,
}

impl Reading {
    fn of(pool: &ObjectPool<Vec<u8>>) -> Self {
        let m = pool.metrics();
        Self {
            constructed: m.constructed,
            reused: m.reused,
            degraded: m.degraded,
            dropped_overflow: m.core.dropped_overflow,
            idle_blocks: m.core.idle,
            borrowed_blocks: m.core.borrowed,
        }
    }

    /// 常驻块字节（idle 槽 × chunk）。
    fn idle_bytes(&self) -> usize {
        self.idle_blocks * CHUNK
    }
}

/// 驱动 `threads` 条并发流，每流同时持有 `depth` 块 64 KiB，共 `ROUNDS` 轮。
///
/// 确定性：两段 barrier 把每轮切成「全部借出」与「全部归还」两个相位 ⇒
/// 每轮峰值在飞块数**恰为** `threads * depth`（与线程调度无关）。
fn sweep(threads: usize, depth: usize) -> Reading {
    let pool = shared_pool_replica();
    let acquired = Arc::new(Barrier::new(threads));
    let released = Arc::new(Barrier::new(threads));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let pool = Arc::clone(&pool);
        let acquired = Arc::clone(&acquired);
        let released = Arc::clone(&released);
        handles.push(thread::spawn(move || {
            for _ in 0..ROUNDS {
                let mut held = Vec::with_capacity(depth);
                for _ in 0..depth {
                    let mut block = pool.acquire_owned();
                    // 触一次写（生产路径同样写入载荷），确保块真的被用过。
                    block[0] = 1;
                    held.push(block);
                }
                // 相位 1：全体同时持有 ⇒ 峰值在飞 = threads * depth。
                acquired.wait();
                // 相位 2：全体归还（`Owned` drop ⇒ 归还池）。
                drop(held);
                released.wait();
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread must not panic");
    }
    Reading::of(&pool)
}

/// 期望读数（由 udf 池语义推导，见文件头「判据」）。
fn expected(in_flight: usize) -> Reading {
    let universe = in_flight.min(UNIVERSE_BLOCKS);
    let overflow = in_flight.saturating_sub(UNIVERSE_BLOCKS);
    // 第 1 轮：idle 空 ⇒ 全部走构造路径（扩容 + 降级）。
    let constructed = in_flight as u64 + (ROUNDS as u64 - 1) * overflow as u64;
    let reused = (ROUNDS as u64 - 1) * universe as u64;
    Reading {
        constructed,
        reused,
        degraded: (ROUNDS as u64) * overflow as u64,
        dropped_overflow: 0,
        idle_blocks: universe,
        borrowed_blocks: 0,
    }
}

/// 改前（kw2si 之前）设计的同参复刻：**每流一份池** + `idle_cap` 随在飞峰值自适应。
///
/// 依据 `git show c9a04ec0^:crates/xray-transport-splithttp/src/pool_stream.rs`：
/// 每实例 `ObjectPool::with_reset(pool_max_blocks(chunk)=32, 1, ...)`（`idle_cap` 起 1），
/// 且 `take_block` 在观察到 `core.borrowed` 创新高时 `resize(max=32, idle_cap=峰值)`。
///
/// ⇒ 改前单流的池宇宙仍是 **32 块**（`max` 恒 32），但**每流各有一份** ⇒ N 流共 N×32 块宇宙。
/// 这正是「省了内存、多了分配」的可能来源：改前单流可独占 32 块，改后全进程只有 32 块。
fn legacy_per_stream_pool() -> Arc<ObjectPool<Vec<u8>>> {
    Arc::new(ObjectPool::with_reset(
        UNIVERSE_BLOCKS,
        1, // 改前 idle_cap 起 1（构造期）
        move || vec![0u8; CHUNK],
        move |buf: &mut Vec<u8>| {
            if buf.len() != CHUNK {
                buf.clear();
                buf.resize(CHUNK, 0);
            }
        },
        ResetPhase::OnReturn,
    ))
}

/// 改前设计的复刻借还（含自适应 `resize`），逐字照搬改前 `take_block` 语义。
fn legacy_take_block(pool: &Arc<ObjectPool<Vec<u8>>>, peak: &AtomicUsize) -> Owned<Vec<u8>> {
    let handle = pool.acquire_owned();
    let core = pool.metrics().core;
    if core.borrowed > peak.load(Ordering::Relaxed) {
        peak.store(core.borrowed, Ordering::Relaxed);
        let idle_cap = core.borrowed.min(core.max);
        let _ = pool.resize(ObjectPoolTuning { max: core.max, idle_cap });
    }
    handle
}

/// 改前设计下的同形测量：N 条流各持 depth 块（每流一份池 ⇒ 每流独立宇宙 32 块）。
fn sweep_legacy(threads: usize, depth: usize) -> (Reading, usize) {
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        handles.push(thread::spawn(move || {
            let pool = legacy_per_stream_pool();
            let peak = AtomicUsize::new(0);
            for _ in 0..ROUNDS {
                let mut held = Vec::with_capacity(depth);
                for _ in 0..depth {
                    let mut block = legacy_take_block(&pool, &peak);
                    block[0] = 1;
                    held.push(block);
                }
                drop(held);
            }
            Reading::of(&pool)
        }));
    }
    let mut agg = Reading {
        constructed: 0,
        reused: 0,
        degraded: 0,
        dropped_overflow: 0,
        idle_blocks: 0,
        borrowed_blocks: 0,
    };
    for h in handles {
        let r = h.join().expect("worker thread must not panic");
        agg.constructed += r.constructed;
        agg.reused += r.reused;
        agg.degraded += r.degraded;
        agg.dropped_overflow += r.dropped_overflow;
        agg.idle_blocks += r.idle_blocks;
        agg.borrowed_blocks += r.borrowed_blocks;
    }
    (agg, threads * UNIVERSE_BLOCKS)
}

#[test]
fn replica_tuning_matches_production_shared_pool() {
    let pool = shared_pool_replica();
    let m = pool.metrics();
    // `max` = 32 块（2 MiB / 64 KiB），`idle_cap` 同值 ⇒ 每片（8 片）4 块。
    assert_eq!(m.core.max, UNIVERSE_BLOCKS);
    assert_eq!(m.core.max * CHUNK, 2 * 1024 * 1024, "池宇宙字节 = POOL_BYTE_BUDGET 口径");
    assert_eq!(m.core.idle, 0);
    assert_eq!(m.degraded, 0);
}

/// 主表：N 条并发流（每流在飞 1 块），N ∈ {1, 8, 32, 64, 128}。
#[test]
fn concurrent_streams_churn_appears_above_32_in_flight_blocks() {
    let mut rows = Vec::new();
    for streams in [1usize, 8, 32, 64, 128] {
        let r = sweep(streams, 1);
        let want = expected(streams);
        assert_eq!(
            r, want,
            "N={streams}: 读数与推导不符（constructed/reused/degraded/dropped_overflow/idle/borrowed）"
        );
        rows.push((streams, 1, r));
    }
    print_table("N 条并发流（每流在飞 1 块）", &rows);
}

/// 副表：固定 8 条流，加大每流在飞块数 ⇒ 进程内在飞块数 I = 8 * depth。
///
/// 这一档说明 churn 的触发量是**进程内在飞块总数**（含 h2 发送缓冲排队深度），
/// 与"流数"无一一对应。
#[test]
fn in_flight_depth_drives_churn_not_stream_count() {
    let mut rows = Vec::new();
    for depth in [1usize, 2, 4, 8, 16] {
        let in_flight = 8 * depth;
        let r = sweep(8, depth);
        let want = expected(in_flight);
        assert_eq!(r, want, "depth={depth} (I={in_flight}): 读数与推导不符");
        rows.push((8, depth, r));
    }
    print_table("8 条流 × 每流在飞 depth 块", &rows);
}

/// A/B：**改前（每流一份池 + 自适应 idle_cap）vs 改后（进程级共享池）** 的 churn 对比。
///
/// 回答票面核心问题「kw2si 是不是拿内存换了 CPU」：
/// - 改前：N 流各一份 32 块宇宙 ⇒ 每流可独占 32 块 ⇒ **单流在飞 ≤ 32 时零 churn**；
/// - 改后：全进程一份 32 块宇宙 ⇒ **进程内在飞 > 32 时开始降级直构**。
///
/// ⇒ churn 是 kw2si **引入的**（改前同形负载下不产生），代价换的是常驻内存 N×2 MiB → 2 MiB。
#[test]
fn shared_pool_introduces_churn_above_process_wide_32_in_flight_blocks() {
    // 每流各 1 块（最常见的稳态形态：一条流同一时刻在飞的块数很小）。
    for streams in [1usize, 8, 32, 64, 128] {
        let (legacy, legacy_universe) = sweep_legacy(streams, 1);
        let shared = sweep(streams, 1);
        println!(
            "streams={streams:>4} | 改前(每流一份): universe={legacy_universe:>4} 块 \
             constructed={:<5} degraded={:<5} idle={} B | 改后(共享): universe={} 块 \
             constructed={:<5} degraded={:<5} idle={} B",
            legacy.constructed,
            legacy.degraded,
            legacy.idle_bytes(),
            UNIVERSE_BLOCKS,
            shared.constructed,
            shared.degraded,
            shared.idle_bytes(),
        );
        // 改前：每流峰值仅 1 块 ⇒ 每流宇宙 32 块远够 ⇒ 零降级、零丢弃。
        assert_eq!(legacy.degraded, 0, "改前设计在每流 1 块时不得降级");
        assert_eq!(legacy.dropped_overflow, 0, "改前设计在每流 1 块时不得丢弃");
        // 改前常驻 = N × 1 块（idle_cap 自适应到该流峰值 1）⇒ N × 64 KiB。
        assert_eq!(legacy.idle_blocks, streams, "改前每流 idle 应为该流峰值 1 块");
        // 改后：streams ≤ 32 ⇒ 零降级；streams > 32 ⇒ 降级 = (streams-32) × ROUNDS。
        let want_degraded = streams.saturating_sub(UNIVERSE_BLOCKS) as u64 * ROUNDS as u64;
        assert_eq!(
            shared.degraded, want_degraded,
            "streams={streams}: 改后降级次数应为 (N-32)×ROUNDS"
        );
    }
    // 关键断言：N=64 时改前零 churn、改后有 churn ⇒ churn 是 kw2si 引入的。
    let (legacy64, _) = sweep_legacy(64, 1);
    let shared64 = sweep(64, 1);
    assert_eq!(legacy64.degraded, 0, "改前 64 流零降级");
    assert!(shared64.degraded > 0, "改后 64 流必降级 ⇒ churn 由 kw2si 引入");
    assert!(
        shared64.idle_bytes() < legacy64.idle_bytes(),
        "改后常驻必须小于改前（省内存的收益确已兑现）"
    );
}

fn print_table(title: &str, rows: &[(usize, usize, Reading)]) {
    #[allow(clippy::print_stdout)]
    {
        println!("\n=== {title} ===");
        println!(
            "{:>6} {:>6} {:>10} {:>10} {:>9} {:>9} {:>12} {:>12} {:>10}",
            "threads",
            "depth",
            "in_flight",
            "constructed",
            "reused",
            "degraded",
            "dropped_ovf",
            "idle_bytes",
            "new_alloc/round"
        );
        for &(threads, depth, r) in rows {
            let in_flight = threads * depth;
            println!(
                "{threads:>6} {depth:>6} {in_flight:>10} {:>10} {:>10} {:>9} {:>9} {:>12} {:>10}",
                r.constructed,
                r.reused,
                r.degraded,
                r.dropped_overflow,
                r.idle_bytes(),
                r.constructed / ROUNDS as u64,
            );
        }
    }
}
