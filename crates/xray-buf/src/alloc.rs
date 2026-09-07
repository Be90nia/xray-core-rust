//! 分层缓冲池分配器
//!
//! 使用 TLS 缓存 + 分片 Mutex 全局池的两级分配策略，
//! 对应 Go 版本 `common/bytespool` 的 sync.Pool 分层设计。
//!
//! # 分层策略
//! - Tier 0: 2KB   (2048 bytes)
//! - Tier 1: 8KB   (8192 bytes) — 默认缓冲区大小
//! - Tier 2: 32KB  (32768 bytes)
//! - Tier 3: 128KB (131072 bytes)

use bytes::BytesMut;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// 默认缓冲区大小 (8KB)，对应 Go 的 `buf.Size`。
pub const DEFAULT_SIZE: usize = 8192;

/// 缓冲区分层大小
const TIER_SIZES: [usize; 4] = [2048, 8192, 32768, 131072];

/// TLS 每层最大缓存数量
const TLS_MAX_PER_TIER: usize = 8;

/// 全局池分片数量
const SHARD_COUNT: usize = 8;

/// 全局池每分片每层上限：超出直接丢弃，防高水位无限堆积。
/// 8 分片 × 64 块：tier0 上限 1MB、tier3 上限 64MB。
const SHARD_MAX_PER_TIER: usize = 64;

/// 惰性收缩间隔（近似 Go sync.Pool 被 GC 周期性清池的节奏）。
const SWEEP_INTERVAL_MS: u64 = 60_000;

/// 上次惰性收缩时间（unix ms）。`fetch_max` 天然去重并发清扫。
static LAST_SWEEP_MS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// 全局池分片：每个分片包含4个层的 Vec<BytesMut>
struct Shard {
    tiers: [Vec<BytesMut>; 4],
}

impl Shard {
    const fn new() -> Self {
        Self {
            tiers: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        }
    }
}

impl Shard {
    /// 高水位回落收缩：距上次清扫超过 [`SWEEP_INTERVAL_MS`] 时，每层释放一半回系统。
    ///
    /// 近似 Go sync.Pool 被 GC 周期性清池的语义；减半而非全清，活动流量下不抖动。
    /// `now` 由调用方传入（生产 `now_ms()`，测试可注入）。
    fn maybe_sweep(&mut self, now: u64) {
        let last = LAST_SWEEP_MS.fetch_max(now, Ordering::Relaxed);
        if now.saturating_sub(last) < SWEEP_INTERVAL_MS {
            return;
        }
        for tier in &mut self.tiers {
            let keep = tier.len() / 2;
            tier.truncate(keep);
        }
    }
}

/// 全局分片池
static SHARDS: [Mutex<Shard>; SHARD_COUNT] = [
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
    Mutex::new(Shard::new()),
];

/// 分片轮询计数器
static SHARD_INDEX: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// TLS 缓存：每层维护一个 Vec<BytesMut>，最多 TLS_MAX_PER_TIER 个
    static TLS_CACHE: RefCell<[Vec<BytesMut>; 4]> = RefCell::new([
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ]);
}

/// 根据请求大小选择合适的分层索引。
/// 返回满足 `TIER_SIZES[tier] >= size` 的最小分层索引，
/// 如果请求超过最大分层则返回 `None`。
#[inline]
fn select_tier(size: usize) -> Option<usize> {
    for (i, &tier_size) in TIER_SIZES.iter().enumerate() {
        if tier_size >= size {
            return Some(i);
        }
    }
    None
}

/// 选择下一个分片索引（轮询策略）
#[inline]
fn next_shard() -> usize {
    SHARD_INDEX.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT
}

/// 从池中分配一个 `BytesMut`。
///
/// 分配优先级：TLS 缓存 → 全局分片 → 新分配。
/// 如果请求大小超过最大分层(128KB)，直接新分配而不走池。
pub fn alloc(size: usize) -> BytesMut {
    if let Some(tier) = select_tier(size) {
        let tier_size = TIER_SIZES[tier];

        // 1. 尝试 TLS 缓存
        let from_tls = TLS_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache[tier].len() > 0 {
                let mut buf = cache[tier].pop().expect("已检查 len > 0");
                buf.clear();
                tracing::trace!(tier, tier_size, "缓冲池 TLS 命中");
                Some(buf)
            } else {
                None
            }
        });
        if let Some(buf) = from_tls {
            return buf;
        }

        // 2. 尝试全局分片
        let shard_idx = next_shard();
        let mut shard = SHARDS[shard_idx].lock();
        if shard.tiers[tier].len() > 0 {
            let mut buf = shard.tiers[tier].pop().expect("已检查 len > 0");
            buf.clear();
            tracing::trace!(tier, tier_size, shard = shard_idx, "缓冲池分片命中");
            return buf;
        }
        drop(shard);

        // 3. 新分配
        tracing::trace!(tier, tier_size, "缓冲池分配新块");
        BytesMut::with_capacity(tier_size)
    } else {
        // 超大请求，直接分配
        tracing::trace!(size, "超大请求直接分配");
        BytesMut::with_capacity(size)
    }
}

/// 将 `BytesMut` 归还到池中。
///
/// 归还优先级：TLS 缓存 → 全局分片 → 丢弃。
/// 缓冲区在归还前会被清零（清除数据并重置长度）。
pub fn release(mut buf: BytesMut) {
    let capacity = buf.capacity();
    if let Some(tier) = select_tier(capacity) {
        buf.clear();

        // 1. 尝试 TLS 缓存
        let mut buf = Some(buf);
        TLS_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache[tier].len() < TLS_MAX_PER_TIER {
                cache[tier].push(buf.take().expect("buf 只被 take 一次"));
            }
        });
        if buf.is_none() {
            return;
        }
        let buf = buf.expect("is_none 已处理");

        // 2. 尝试全局分片（每分片每层上限 [`SHARD_MAX_PER_TIER`]，超出丢弃；
        // 拿锁顺带机会式惰性收缩，近似 Go sync.Pool 的 GC 清池）
        let shard_idx = next_shard();
        let mut shard = SHARDS[shard_idx].lock();
        shard.maybe_sweep(now_ms());
        if shard.tiers[tier].len() < SHARD_MAX_PER_TIER {
            shard.tiers[tier].push(buf);
            tracing::trace!(tier, shard = shard_idx, "缓冲池归还到分片");
        }
        // 超上限：buf drop 归还系统——高水位由 sweep 周期回落
    }
    // 容量不匹配任何分层或超出，直接丢弃
}

/// 清除所有 TLS 缓存和全局分片。
///
/// 主要用于测试清理，确保池状态干净。
pub fn clear() {
    // 清除 TLS
    TLS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        for tier in &mut *cache {
            tier.clear();
        }
    });

    // 清除全局分片
    for shard_mutex in &SHARDS {
        let mut shard = shard_mutex.lock();
        for tier in &mut shard.tiers {
            tier.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 串行化触碰全局池 static 的测试（clear/release 均是进程级共享状态）。
    static POOL_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_select_tier() {
        assert_eq!(select_tier(100), Some(0));
        assert_eq!(select_tier(2048), Some(0));
        assert_eq!(select_tier(2049), Some(1));
        assert_eq!(select_tier(8192), Some(1));
        assert_eq!(select_tier(10000), Some(2));
        assert_eq!(select_tier(32768), Some(2));
        assert_eq!(select_tier(50000), Some(3));
        assert_eq!(select_tier(131072), Some(3));
        assert_eq!(select_tier(200000), None);
    }

    #[test]
    fn test_alloc_default_size() {
        let buf = alloc(DEFAULT_SIZE);
        assert!(buf.capacity() >= DEFAULT_SIZE);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_alloc_small() {
        let buf = alloc(64);
        assert!(buf.capacity() >= 2048);
    }

    #[test]
    fn test_alloc_huge() {
        let buf = alloc(256 * 1024);
        assert!(buf.capacity() >= 256 * 1024);
    }

    #[test]
    fn test_release_and_reuse() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        let buf = alloc(DEFAULT_SIZE);
        let cap = buf.capacity();
        release(buf);

        let buf2 = alloc(DEFAULT_SIZE);
        assert_eq!(buf2.capacity(), cap);
        release(buf2);
        clear();
    }

    #[test]
    fn test_tls_cache_limit() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        for _ in 0..TLS_MAX_PER_TIER {
            release(alloc(DEFAULT_SIZE));
        }
        release(alloc(DEFAULT_SIZE));
        clear();
    }

    #[test]
    fn test_clear_empties_pools() {
        let _g = POOL_TEST_LOCK.lock();
        for _ in 0..5 {
            release(alloc(DEFAULT_SIZE));
        }
        clear();
        let buf = alloc(DEFAULT_SIZE);
        assert!(buf.capacity() >= DEFAULT_SIZE);
        release(buf);
    }

    #[test]
    fn test_default_size_constant() {
        assert_eq!(DEFAULT_SIZE, 8192);
    }

    #[test]
    fn test_multi_tier_operations() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        release(alloc(1024));
        release(alloc(4096));
        release(alloc(16384));
        release(alloc(65536));
        clear();
    }

    /// 全局池总池化块数（tier0）。
    fn shard_tier0_total() -> usize {
        SHARDS.iter().map(|s| s.lock().tiers[0].len()).sum()
    }

    #[test]
    fn test_shard_release_cap() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        // 冻结 sweep（last=MAX-1 时 now-last 饱和为 0），否则真实墙钟会在塞池中途
        // 触发减半，破坏钳制断言
        LAST_SWEEP_MS.store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);
        // 归还数远超全局容量上限（TLS 吸收 TLS_MAX_PER_TIER 个后余量进分片）
        let total = SHARD_MAX_PER_TIER * SHARD_COUNT + TLS_MAX_PER_TIER + 50;
        let bufs: Vec<_> = (0..total).map(|_| alloc(1024)).collect();
        for b in bufs {
            release(b);
        }
        assert_eq!(
            shard_tier0_total(),
            SHARD_MAX_PER_TIER * SHARD_COUNT,
            "全局池必须钳制在 分片数×每分片上限"
        );
        clear();
    }

    #[test]
    fn test_maybe_sweep_halves_tiers() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        LAST_SWEEP_MS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut shard = Shard::new();
        for _ in 0..10 {
            shard.tiers[2].push(BytesMut::with_capacity(TIER_SIZES[2]));
        }
        shard.maybe_sweep(SWEEP_INTERVAL_MS); // now - last(0) >= 间隔 → 触发
        assert_eq!(shard.tiers[2].len(), 5, "sweep 必须把每层减半");
        // 间隔内不重复触发：last 已被更新为 SWEEP_INTERVAL_MS
        for _ in 0..5 {
            shard.tiers[2].push(BytesMut::with_capacity(TIER_SIZES[2]));
        }
        shard.maybe_sweep(SWEEP_INTERVAL_MS * 2 - 1);
        assert_eq!(shard.tiers[2].len(), 10, "间隔未到不得收缩");
        LAST_SWEEP_MS.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}
