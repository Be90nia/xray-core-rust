//! 多线程争用基准（bd f516k 验收①）：**分片记账的热路径代价**。
//!
//! 对照组 = 「记账加入前」的形态复刻：同一套「thread_local TLS 缓存 → 8 分片
//! `Mutex<Vec<BytesMut>>` 轮询选片 → 超量丢弃」的结构，**零字节记账**。
//! 实验组 = 真实 `alloc`/`release`（分片锁内一字节加法 + 比较、TLS thread_local
//! 配额计数）。两者结构逐项对齐，唯一差异就是记账本身 ⇒ 差值即记账开销。
//!
//! 判据（PM 口径 2026-11-04 二修）：real / control ≤ **1.15** 视为无回归。**只在
//! release 档判定**（绝对耗时断言只在 release 口径压——debug 逐元素路径差一个量级，
//! 见仓内 rust-testing 规则）；debug 档照跑、只打印不判。
//!
//! **阈值 1.15 的依据（不是放水，是匹配实测噪声）**：PM 三轮复测（2026-11-04，本机
//! release）显示同轮内相邻采样波动 ±6 ns（control 60–70 ns），比值在 0.99–1.10 间随
//! 负载漂移；1.05 会让 CI runner 间歇性红（flaky test 比没有测试更糟——真回归会被当
//! 成噪声忽略）。真实回归的形态是 ≥1.5×（把记账放回全局原子 → 跨核乒乓；或每 op 取
//! 一次全局锁），那种回归不可能藏在 1.15 以内 ⇒ 1.15 仍有判别力。
//! 采样形态：10 轮 × 每轮 3 子样取中位（A/B 交错），再对轮中位取比值
//! （median-of-medians），对冲机器漂移。
//!
//! 跑法：`cargo test --release -p xray-buf --test shard_accounting_bench -- --nocapture`

use std::{sync::Barrier, thread, time::Instant};

use xray_buf::alloc::{alloc, release};

const THREADS: usize = 8;
const CYCLES_PER_THREAD: usize = 3_000;
const TIER: usize = 8192;
const RUNS: usize = 10;
const SUB_REPS: usize = 3;

/// 每周期块数：单块「alloc→release」回环会被 TLS LIFO 全量吸收（8 KiB 层 TLS 留
/// 8 块 ⇒ 全部线程本地命中，分片锁零争用，测不出记账代价）。批式借还（借 32 块
/// 再整批归还）让 75% 的 op 走分片锁 ⇒ 8 线程真实争用，与生产「连接级缓冲成批
/// 借还」同形态。
const BATCH: usize = 32;

/// 真实路径（含分片记账 + TLS thread_local 配额）。
fn real_op() {
    let mut bufs = Vec::with_capacity(BATCH);
    for _ in 0..BATCH {
        bufs.push(alloc(TIER));
    }
    for buf in bufs {
        release(buf);
    }
}

/// 对照池：记账加入前的形态复刻。**逐行对齐真实路径的全部既有开销**——层选择
/// （`select_tier` 同款扫描）、TLS thread_local 读写、轮询选片的共享原子、惰性
/// 收缩的时戳检查（`fetch_max`，8 线程下本就是争用点）——**唯一差异是记账本身**
/// （分片锁内一字节加法 + 比较、TLS 字节配额计数）。否则差值会把这些既有开销
/// 误算成"记账回归"。
mod control {
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use bytes::BytesMut;
    use parking_lot::Mutex;

    const SHARD_COUNT: usize = 8;
    const TLS_MAX: usize = 8;
    const SHARD_MAX: usize = 64;
    const SIZE: usize = 8192;
    const TIER_SIZES: [usize; 5] = [2048, 8192, 32768, 65536, 131072];

    static SHARD_INDEX: AtomicUsize = AtomicUsize::new(0);
    static LAST_SWEEP_MS: AtomicU64 = AtomicU64::new(0);
    static POOL: [Mutex<Vec<BytesMut>>; SHARD_COUNT] = [
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
    ];

    thread_local! {
        static TLS: RefCell<[Vec<BytesMut>; 5]> = const {
            RefCell::new([Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()])
        };
    }

    fn select_tier(size: usize) -> Option<usize> {
        TIER_SIZES.iter().position(|&tier_size| tier_size >= size)
    }

    fn now_ms() -> u64 {
        // 基准对照面的取时（与真实路径同款时戳检查），测量本身，逐点豁免。
        #[allow(clippy::disallowed_methods, reason = "对照面 sweep 时戳检查，测量本身")]
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        d.map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
    }

    pub fn alloc_block() -> BytesMut {
        let Some(tier) = select_tier(SIZE) else {
            return BytesMut::with_capacity(SIZE);
        };
        let from_tls = TLS.with(|cache| {
            let mut cache = cache.borrow_mut();
            if !cache[tier].is_empty() {
                let mut buf = cache[tier].pop().expect("已检查 len > 0");
                buf.clear();
                Some(buf)
            } else {
                None
            }
        });
        if let Some(buf) = from_tls {
            return buf;
        }
        let idx = SHARD_INDEX.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
        let mut shard = POOL[idx].lock();
        if let Some(mut buf) = shard.pop() {
            buf.clear();
            return buf;
        }
        drop(shard);
        BytesMut::with_capacity(TIER_SIZES[tier])
    }

    pub fn release_block(mut buf: BytesMut) {
        let capacity = buf.capacity();
        let Some(tier) = select_tier(capacity) else { return };
        if capacity != TIER_SIZES[tier] {
            return;
        }
        buf.clear();
        let mut buf = Some(buf);
        TLS.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache[tier].len() < TLS_MAX {
                cache[tier].push(buf.take().expect("buf 只被 take 一次"));
            }
        });
        let Some(buf) = buf else { return };
        let idx = SHARD_INDEX.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
        let mut shard = POOL[idx].lock();
        let _ = LAST_SWEEP_MS.fetch_max(now_ms(), Ordering::Relaxed);
        if shard.len() < SHARD_MAX {
            shard.push(buf);
        }
    }
}

fn control_op() {
    let mut bufs = Vec::with_capacity(BATCH);
    for _ in 0..BATCH {
        bufs.push(control::alloc_block());
    }
    for buf in bufs {
        control::release_block(buf);
    }
}

/// N 线程同起同收测一组：返回每次「alloc + release」对的纳秒数。
fn measure(name: &str, op: fn()) -> f64 {
    let start = Barrier::new(THREADS + 1);
    let end = Barrier::new(THREADS + 1);
    thread::scope(|s| {
        for _ in 0..THREADS {
            let start = &start;
            let end = &end;
            s.spawn(move || {
                start.wait();
                for _ in 0..CYCLES_PER_THREAD {
                    op();
                }
                end.wait();
            });
        }
        start.wait();
        // 取证型计时（[BENCH] 输出行是测量本身）：换注入钟即失去意义，逐点豁免。
        #[allow(
            clippy::disallowed_methods,
            reason = "基准墙钟测量面（本文件唯一站点）：计时是测量本身，注入钟无意义"
        )]
        let t0 = Instant::now();
        end.wait();
        let pairs = (THREADS * CYCLES_PER_THREAD * BATCH) as f64;
        let per_op = t0.elapsed().as_nanos() as f64 / pairs;
        println!(
            "  [{name}] {THREADS} 线程 × {CYCLES_PER_THREAD} 周期 × {BATCH} 块 = {per_op:.1} ns/pair"
        );
        per_op
    })
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("ns 计时无 NaN"));
    xs[xs.len() / 2]
}

#[test]
fn multithread_alloc_release_accounting_overhead() {
    // 预热：池填充 + tracing callsite 缓存 + 分页，避免首轮冷启动污染中位数。
    for _ in 0..2_000 {
        real_op();
        control_op();
    }

    let mut control_ns = Vec::new();
    let mut real_ns = Vec::new();
    for round in 0..RUNS {
        // 每轮 3 个子样内取中位（A/B 交错对冲机器漂移），轮与轮再取中位
        // ⇒ median-of-medians，压单轮噪声（同轮相邻采样实测漂 ±6 ns）。
        let mut control_sub = Vec::new();
        let mut real_sub = Vec::new();
        for _ in 0..SUB_REPS {
            control_sub.push(measure(&format!("r{round} control 无记账"), control_op));
            real_sub.push(measure(&format!("r{round} real 分片记账 "), real_op));
        }
        control_ns.push(median(control_sub));
        real_ns.push(median(real_sub));
    }

    let control_med = median(control_ns);
    let real_med = median(real_ns);
    let ratio = real_med / control_med;
    let delta_per_block = (real_med - control_med) / (BATCH as f64);
    println!(
        "[BENCH] control 中位 = {control_med:.0} ns/pair, real 中位 = {real_med:.0} ns/pair, \
         记账开销比 = {ratio:.3}x, 绝对增量 = {delta_per_block:+.2} ns/块"
    );

    if !cfg!(debug_assertions) {
        // 阈值 1.15 的依据：PM 三轮复测（2026-11-04，本机 release）显示
        //   同轮内相邻采样波动 ±6ns（control 60–70ns），比值在 0.99–1.10 间随负载漂移；
        //   1.05 会让 CI runner 间歇性红。真实回归的形态是 ≥1.5×
        //   （例：把记账放回全局原子 → 跨核乒乓；或每 op 取一次全局锁），
        //   那种回归不可能藏在 1.15 以内 ⇒ 1.15 仍有判别力。
        assert!(
            ratio <= 1.15,
            "分片记账热路径回归：real/control = {ratio:.3} > 1.15，\
             control={control_med:.1}ns real={real_med:.1}ns（绝对增量 \
             {delta_per_block:+.2} ns/块、{:+.1} ns/pair）",
            real_med - control_med
        );
    }
}
