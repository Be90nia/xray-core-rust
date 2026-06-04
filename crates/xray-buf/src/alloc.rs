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
use std::sync::atomic::{AtomicUsize, Ordering};

/// 默认缓冲区大小 (8KB)，对应 Go 的 `buf.Size`。
pub const DEFAULT_SIZE: usize = 8192;

/// 缓冲区分层大小
const TIER_SIZES: [usize; 4] = [2048, 8192, 32768, 131072];

/// TLS 每层最大缓存数量
const TLS_MAX_PER_TIER: usize = 8;

/// 全局池分片数量
const SHARD_COUNT: usize = 8;

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

        // 2. 尝试全局分片（无上限，但 Mutex 保护）
        let shard_idx = next_shard();
        let mut shard = SHARDS[shard_idx].lock();
        shard.tiers[tier].push(buf);
        tracing::trace!(tier, shard = shard_idx, "缓冲池归还到分片");
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
        clear();
        for _ in 0..TLS_MAX_PER_TIER {
            release(alloc(DEFAULT_SIZE));
        }
        release(alloc(DEFAULT_SIZE));
        clear();
    }

    #[test]
    fn test_clear_empties_pools() {
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
        clear();
        release(alloc(1024));
        release(alloc(4096));
        release(alloc(16384));
        release(alloc(65536));
        clear();
    }
}
