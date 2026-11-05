//! 分层缓冲池分配器
//!
//! 使用 TLS 缓存 + 分片 Mutex 全局池的两级分配策略，
//! 对应 Go 版本 `common/bytespool` 的 sync.Pool 分层设计。
//!
//! # 分层策略
//! - Tier 0: 2KB   (2048 bytes)
//! - Tier 1: 8KB   (8192 bytes) — 默认缓冲区大小
//! - Tier 2: 32KB  (32768 bytes)
//! - Tier 3: 64KB  (65536 bytes) — k16um：消除「要 64KB 拿 128KB」的 2x 档位错配
//! - Tier 4: 128KB (131072 bytes)

use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use bytes::BytesMut;
use parking_lot::Mutex;

/// 默认缓冲区大小 (8KB)，对应 Go 的 `buf.Size`。
pub const DEFAULT_SIZE: usize = 8192;

/// 缓冲区分层大小
pub const TIER_SIZES: [usize; 5] = [2048, 8192, 32768, 65536, 131072];

/// TLS 每层最大缓存数量
pub const TLS_MAX_PER_TIER: usize = 8;

/// 全局池分片数量
pub const SHARD_COUNT: usize = 8;

/// 全局池每分片每层上限：超出直接丢弃，防高水位无限堆积。
/// 8 分片 × 64 块：tier0 上限 1MB、tier3 上限 32MB、tier4 上限 64MB。
/// **总字节仍由 [`POOL_BYTE_BUDGET`] 统收**（跨层跨分片的合计上界，8 MB）。
pub const SHARD_MAX_PER_TIER: usize = 64;

/// 惰性收缩间隔（近似 Go sync.Pool 被 GC 周期性清池的节奏）。
const SWEEP_INTERVAL_MS: u64 = 60_000;

/// 池**常驻总字节**预算（bd f516k）：按件上限（[`SHARD_MAX_PER_TIER`] × 8 分片，
/// 再叠加各线程 TLS 缓存）理论可达 ~116 MB，与 256 MB 小机场的 96 MB xray 预算
/// 无关（`reports/audit-2026-11-04/MEMORY-BUDGET-256MB.md` §1）。本常量把 TLS 缓存
/// 与全部分片的字节总和钉死，**超限归还即丢弃**（块归还系统，不累积）。
/// 实测稳态 0.3–0.7 MB，远低于本上界 ⇒ 热路径复用率不受影响。
pub const POOL_BYTE_BUDGET: usize = 8 * 1024 * 1024;

/// 每分片字节预算 = [`POOL_BYTE_BUDGET`] / [`SHARD_COUNT`]（静态均分，8 MiB / 8 = 1 MiB）。
///
/// **为什么记账放在分片内、不在全局**（别改回全局原子——审计裁定过的形态，bd f516k）：
/// 全局单一原子会让所有线程的借还打同一条 cache line ⇒ 跨核乒乓；且 CAS 形态的
/// `fetch_update` 是重试循环，不是单条指令。分片计数住在 `Shard` 里，借还本来就取
/// 该分片的锁 ⇒ 记账是**锁内一拍普通加减**，零共享写、零 CAS、零额外同步。
/// 上界仍硬：各分片 ≤ 1 MiB ⇒ 合计 ≤ [`POOL_BYTE_BUDGET`]（静态均分只会更保守）。
/// 代价：单分片偏热时可能先撞自己的 1 MiB 而别的分片有空余（轻微利用率损失），
/// 稳态总量 0.3–0.7 MB ⇒ 远达不到。全局合计只按需读侧求和（不进热路径）。
pub const SHARD_BYTE_BUDGET: usize = POOL_BYTE_BUDGET / SHARD_COUNT;

/// TLS 缓存单线程字节预算（thread_local 计数，无原子）：128 KiB/线程。超限的归还
/// 不进 TLS（还会继续试分片）；全局影响 = 每线程至多占 [`TLS_BYTE_BUDGET`]。
pub const TLS_BYTE_BUDGET: usize = 128 * 1024;

/// 因字节上界而丢弃的归还款（可观测：上界拒绝不得静默）。**只挂在丢弃分支**
/// （罕见路径），成功路径零触碰；`clear()` 不归零（单向事实计数，归零会让并行
/// 测试里别的线程读数凭空消失）。
static DROPPED_OVER_BUDGET: AtomicU64 = AtomicU64::new(0);

/// 上次惰性收缩时间（unix ms）。`fetch_max` 天然去重并发清扫。
static LAST_SWEEP_MS: AtomicU64 = AtomicU64::new(0);

// 数据面零时钟纪律的唯一登记点：池惰性清扫时戳锚（SWEEP_INTERVAL_MS 周期去重），
// 非时限语义；本 crate 零 skeleton 依赖（接 udf Clock = 新增依赖，红线），故留裸取时。
#[allow(
    clippy::disallowed_methods,
    reason = "池惰性清扫时戳锚（非时限语义）：xray-buf 零 skeleton 依赖纪律，接 udf Clock 需新增依赖（红线）；唯一登记点，无第二处"
)]
#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// 全局池分片：每个分片包含 5 个层的 Vec<BytesMut>，外加本分片**常驻字节记账**
/// （借还都在本分片锁内 ⇒ 普通加减，见 [`SHARD_BYTE_BUDGET`] 的 why 注释）。
struct Shard {
    tiers: [Vec<BytesMut>; 5],
    /// 本分片池内块的字节合计（只统计经 `release` 入池的标准容量块）。
    bytes: usize,
}

impl Shard {
    const fn new() -> Self {
        Self { tiers: [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()], bytes: 0 }
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
        for (i, tier) in self.tiers.iter_mut().enumerate() {
            let keep = tier.len() / 2;
            // 收缩回系统：销掉被裁掉块的字节额度（分片记账必须跟真实驻留同步，
            // 否则上界会被幽灵字节永久占满）。饱和不减穿：`maybe_sweep` 的单元测试
            // 直接往分片塞块（绕过记账），少记只会「少留几块」，不 wrap（否则永久拒收）。
            self.bytes = self.bytes.saturating_sub((tier.len() - keep) * TIER_SIZES[i]);
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
    static TLS_CACHE: RefCell<[Vec<BytesMut>; 5]> = const {
        RefCell::new([Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()])
    };
    /// 本线程 TLS 缓存的字节合计（配额见 [`TLS_BYTE_BUDGET`]）：thread_local 计数
    /// ⇒ 读写都是线程私有，无原子、无共享。
    static TLS_CACHE_BYTES: Cell<usize> = const { Cell::new(0) };
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
            if !cache[tier].is_empty() {
                let mut buf = cache[tier].pop().expect("已检查 len > 0");
                buf.clear();
                TLS_CACHE_BYTES.set(TLS_CACHE_BYTES.get().saturating_sub(tier_size));
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
        if !shard.tiers[tier].is_empty() {
            let mut buf = shard.tiers[tier].pop().expect("已检查 len > 0");
            buf.clear();
            // 命中销账：本分片锁内一拍普通减法（零跨线程原子，见 SHARD_BYTE_BUDGET）。
            shard.bytes = shard.bytes.saturating_sub(tier_size);
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
/// 归还前仅重置逻辑长度（[`BytesMut::clear`] 置 `len = 0`），**不清除字节内容**——
/// 旧数据留在块内，直到被下一持有者覆写。跨持有者不泄漏的保证不在清零，而在
/// `Buffer` 的视图纪律：读视图恒限 `[start, end)` 游标区间；`[end, cap)` 未提交区
/// 只经 `MaybeUninit` 只写视图（`writable_bytes` / `seal_window` tag /
/// `ReadBuf::uninit` 系统调用写）暴露。全仓调用点核查与 A7/A0 回归锁定见
/// `tests/pooled_logical_len.rs`。
///
/// 确需清零的池（如 udf `ObjectPool` 的明文块）**只许清「已写入区」**（`[..len]`），
/// 禁整块清零：64 KiB 整块清零审计实测 190.8µs/次（bd hdugl，debug 档；release 2.1µs），
/// 而只清 16 KiB 已写区仅 300ns —— 清零成本必须与写入量同阶，不能被借还开销（~100-300ns）反超。
pub fn release(mut buf: BytesMut) {
    let capacity = buf.capacity();
    if let Some(tier) = select_tier(capacity) {
        // 只回收「容量恰等于层大小」的块：`alloc(tier)` 的调用方按
        // TIER_SIZES[tier] 使用返回块，任意小容量真池块（Buffer::with_capacity /
        // from_bytes / Frozen 写时 COW 转正）入池会让下游拿到不足额 buffer
        // （2026-10-20 实测：8KB 层混入 3KB 块，读窗口缩水）。
        // 非标准容量直接丢弃 → 归还系统。
        if capacity != TIER_SIZES[tier] {
            tracing::trace!(capacity, tier, tier_size = TIER_SIZES[tier], "缓冲池丢弃非标准容量块");
            return;
        }
        buf.clear();

        // 1. 尝试 TLS 缓存（单线程字节配额，thread_local 计数 ⇒ 无原子）
        let mut buf = Some(buf);
        TLS_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache[tier].len() < TLS_MAX_PER_TIER
                && TLS_CACHE_BYTES.get() + capacity <= TLS_BYTE_BUDGET
            {
                TLS_CACHE_BYTES.set(TLS_CACHE_BYTES.get() + capacity);
                cache[tier].push(buf.take().expect("buf 只被 take 一次"));
            }
        });
        if buf.is_none() {
            return;
        }
        let buf = buf.expect("is_none 已处理");

        // 2. 尝试全局分片（每分片每层上限 [`SHARD_MAX_PER_TIER`] + 每分片字节预算
        // [`SHARD_BYTE_BUDGET`]，超出丢弃；拿锁顺带机会式惰性收缩，近似 Go
        // sync.Pool 的 GC 清池）
        let shard_idx = next_shard();
        let mut shard = SHARDS[shard_idx].lock();
        shard.maybe_sweep(now_ms());
        // 字节裁决 = 本分片锁内一拍加法 + 比较（零跨线程原子，见 SHARD_BYTE_BUDGET）；
        // 拒收只发生在丢弃分支（罕见路径），成功路径零全局触碰。
        if shard.tiers[tier].len() < SHARD_MAX_PER_TIER
            && shard.bytes + capacity <= SHARD_BYTE_BUDGET
        {
            shard.tiers[tier].push(buf);
            shard.bytes += capacity;
            tracing::trace!(tier, shard = shard_idx, "缓冲池归还到分片");
        } else {
            DROPPED_OVER_BUDGET.fetch_add(1, Ordering::Relaxed);
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

    // 记账归零：分片与本线程 TLS 缓存已空。他线程 TLS 缓存不在此清理 ⇒ 这是
    // 测试/收尾口径（生产不调 clear）。
    // `DROPPED_OVER_BUDGET` **不归零**：它是单向观测面（丢了多少块是事实），且并行
    // 测试会各调 `clear()`——归零会让别的线程的读数凭空消失（实测踩过：断言偶发 0）。
    for shard_mutex in &SHARDS {
        shard_mutex.lock().bytes = 0;
    }
    TLS_CACHE_BYTES.with(|b| b.set(0));
}

/// 池状态快照（bd a7snv 池可观测性：上界够不够在生产可读）。
///
/// **读侧逐分片求和**（8 分片 ≤ O(8) 逐片取锁，非热路径、零分配）——诊断/巡检
/// 面专用，**禁进借还热路径**（热路径的分片字节记账见 [`SHARD_BYTE_BUDGET`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// 全局分片常驻字节合计（`Σ shard.bytes`——只统计经 `release` 入池的标准
    /// 容量块；TLS 缓存不计入，见 [`PoolStats::tls_bytes`]）。
    pub resident_bytes: u64,
    /// 全局分片常驻块数合计。
    pub resident_blocks: u64,
    /// **本线程** TLS 缓存字节（thread_local 各线程私有；其他线程的 TLS 不在
    /// 本读数——进程级 TLS 合计 = 各线程自报求和，无全局账本）。
    pub tls_bytes: u64,
    /// 因字节/块数上界被丢弃的归还款（进程累计，单向事实计数，`clear()` 不
    /// 归零——增量对账请取两次快照做差）。
    pub dropped_over_budget: u64,
}

/// 池状态快照（诊断读口）：调用即取各分片锁求和 + 读本线程 TLS 计数。
pub fn stats() -> PoolStats {
    let mut resident_bytes = 0u64;
    let mut resident_blocks = 0u64;
    for shard_mutex in &SHARDS {
        let shard = shard_mutex.lock();
        resident_bytes += shard.bytes as u64;
        resident_blocks += shard.tiers.iter().map(Vec::len).sum::<usize>() as u64;
    }
    PoolStats {
        resident_bytes,
        resident_blocks,
        tls_bytes: TLS_CACHE_BYTES.get() as u64,
        dropped_over_budget: DROPPED_OVER_BUDGET.load(Ordering::Relaxed),
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
        // k16um：64KB 精确档（原 50000/131072 都落 128KB 层）
        assert_eq!(select_tier(32769), Some(3));
        assert_eq!(select_tier(65536), Some(3));
        assert_eq!(select_tier(50000), Some(3));
        assert_eq!(select_tier(65537), Some(4));
        assert_eq!(select_tier(131072), Some(4));
        assert_eq!(select_tier(200000), None);
    }

    /// k16um 验收判据①：`alloc(64KB)` 拿到精确 64KB 层块（不再向上吃 128KB），
    /// 且**归还后同块复用**。
    ///
    /// 池的真实语义（判据成立的前提）：归还进**本线程** TLS 层缓存（LIFO，
    /// ≤8 块/层/线程），下一次同线程 `alloc` **先弹 TLS** ⇒ 同块必然复用；
    /// 跨线程/分片路径不保证身份（Go `sync.Pool` 同样无身份保证）。
    ///
    /// 必须走 `release()` 归还池：直接 `drop()` 只把块还给**堆分配器**，下次
    /// `alloc` 是新鲜分配——地址是否相同纯属分配器 free-list 的巧合，并行负载
    /// 下必漂（2026-11-03 workspace 门禁红点实证：本地绿、并行红）。
    #[test]
    fn alloc_64k_request_lands_exact_tier() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        let first = alloc(64 * 1024);
        assert_eq!(first.capacity(), 64 * 1024, "64KB 请求必须落精确 64KB 层（A2 错配修复）");
        let addr = first.as_ptr() as usize;
        release(first);

        // 归还后同线程再取：TLS 层缓存先弹 ⇒ 同块复用（无新鲜分配）。
        let second = alloc(64 * 1024);
        assert_eq!(second.capacity(), 64 * 1024);
        assert_eq!(second.as_ptr() as usize, addr, "64KB 层块必须可归还复用");
        release(second);

        // 连续取块（跨过 TLS 8 块上限 ⇒ 走分片 / 新鲜分配路径）：容量恒为 64KB；
        // 任何一次拿到 131072 即为「64KB 请求被重新路由到 128KB 层」的回归。
        for _ in 0..32 {
            let b = alloc(64 * 1024);
            assert_eq!(b.capacity(), 64 * 1024, "64KB 请求在任何取块路径上都必须精确 64KB");
            release(b);
        }
        clear();
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
        let total = shard_tier0_total();
        assert!(
            total <= SHARD_MAX_PER_TIER * SHARD_COUNT,
            "全局池必须不超过分片数×每分片上限(实测{total}, 含并发污染)"
        );
        clear();
    }

    /// 池只回收「容量恰等于层大小」的块。
    ///
    /// 不足额块（Buffer::with_capacity / from_bytes / Frozen 写时 COW 转正的
    /// 任意容量 BytesMut）一旦入池，`alloc(tier)` 的调用方会拿到比层大小小的
    /// buffer（2026-10-20 实测：8KB 层混入 KB 级块，读窗口缩水）。修复=release
    /// 侧按 capacity == TIER_SIZES[tier] 过滤，本测试钉住该不变量。
    #[test]
    fn release_discards_off_size_blocks() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        let off = BytesMut::with_capacity(3000);
        assert!(off.capacity() < DEFAULT_SIZE, "前置：3000 落在 tier1 区间但不是标准容量");
        release(off);
        let got = alloc(DEFAULT_SIZE);
        assert_eq!(got.capacity(), DEFAULT_SIZE, "不足额块不得入池（否则下游读窗口缩水）");
        release(got);
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

    /// 总字节上界（bd f516k，分片记账形态）：每分片常驻 ≤ [`SHARD_BYTE_BUDGET`]
    /// （合计 ⇒ [`POOL_BYTE_BUDGET`]），超限归还**被丢弃且计数可见**（禁静默累积）。
    /// **反向自检锚点**：删掉 `release` 里的 `shard.bytes + capacity <= SHARD_BYTE_BUDGET`
    /// 闸，本断言必红（驻留会越过每分片 1 MB）。
    ///
    /// 并发纪律：本 crate 的 `buffer` 模块测试也碰全局池（各自 `clear()`，不持本锁），
    /// 故断言只用「只会被外部行为**减小**」的读数 + `DROPPED_OVER_BUDGET` 的**增量**
    /// （该计数在 `clear()` 后不归零）——避免外部 `clear()` 把读数抹成 0 的偶发红。
    #[test]
    fn release_over_byte_budget_drops_and_counts() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        // 冻结 sweep（真实墙钟可能在塞池中途把驻留减半，破坏上界读数）
        LAST_SWEEP_MS.store(u64::MAX - 1, Ordering::Relaxed);
        let dropped_before = DROPPED_OVER_BUDGET.load(Ordering::Relaxed);

        // 64 KiB × 200 = 12.8 MB > 预算（按件上限 8 分片 × 64 块 = 32 MB 装得下，
        // 故只有字节上界能拒收 ⇒ 本用例钉的是字节面）。
        let bufs: Vec<_> = (0..200).map(|_| alloc(TIER_SIZES[3])).collect();
        for b in bufs {
            release(b);
        }

        let mut shard_bytes_total = 0usize;
        for (i, shard_mutex) in SHARDS.iter().enumerate() {
            let bytes = shard_mutex.lock().bytes;
            assert!(
                bytes <= SHARD_BYTE_BUDGET,
                "分片 {i} 常驻 {bytes} 字节超每分片预算 {SHARD_BYTE_BUDGET}"
            );
            shard_bytes_total += bytes;
        }
        assert!(
            shard_bytes_total <= POOL_BYTE_BUDGET,
            "分片合计 {shard_bytes_total} 字节超总预算 {POOL_BYTE_BUDGET}"
        );
        assert!(
            DROPPED_OVER_BUDGET.load(Ordering::Relaxed) > dropped_before,
            "超上界的归还必须留痕（禁静默丢弃）"
        );

        // 上界生效后热路径照常复用（不因拒收打崩）。
        let again = alloc(TIER_SIZES[3]);
        assert_eq!(again.capacity(), TIER_SIZES[3], "上界生效后仍须拿到足额块");
        release(again);
    }

    /// TLS 缓存的**单线程字节配额**（bd f516k）：TLS 层最多留住
    /// `TLS_BYTE_BUDGET / 层大小` 块，超限归还跳过 TLS 直进分片（不丢弃）。
    /// **反向自检锚点**：删掉 `release` TLS 臂的 `TLS_CACHE_BYTES + capacity <=
    /// TLS_BYTE_BUDGET` 条件，本断言必红（TLS 会留满 TLS_MAX_PER_TIER 块）。
    #[test]
    fn release_tls_byte_quota_skips_tls_over_budget() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        let dropped_before = DROPPED_OVER_BUDGET.load(Ordering::Relaxed);
        // 128 KiB 预算 / 64 KiB 层 = 至多 2 块进 TLS（件上限 8 不再是有效边界）。
        for _ in 0..TLS_MAX_PER_TIER {
            release(alloc(TIER_SIZES[3]));
        }
        let tls_bytes = TLS_CACHE_BYTES.get();
        assert!(
            tls_bytes <= TLS_BYTE_BUDGET,
            "TLS 常驻 {tls_bytes} 字节超单线程预算 {TLS_BYTE_BUDGET}"
        );
        // 超配额的块不得静默消失：分片预算未满 ⇒ 全部收下，丢弃计数必须为零
        // （单向计数不受并行 clear() 影响，读增量口径）。
        assert_eq!(
            DROPPED_OVER_BUDGET.load(Ordering::Relaxed),
            dropped_before,
            "TLS 拒收的块必须落到分片，不得丢弃"
        );
    }

    // ── 池可观测性（bd a7snv）：stats() 读数与归还状态配平 ────────────────

    /// TLS 收满预算后余量落分片：`stats()` 的 `tls_bytes`（本线程精确）与
    /// `resident_bytes`（全局下界——分片会被并行测试归还污染，只断言增量下界）
    /// 各归其位；`dropped_over_budget` 走增量口径（`clear()` 不归零）。
    #[test]
    fn stats_reports_tls_and_resident_ledger() {
        let _g = POOL_TEST_LOCK.lock();
        clear();
        // 冻结 sweep（同 `test_shard_release_cap`：真实墙钟中途减半会破坏读数）
        LAST_SWEEP_MS.store(u64::MAX - 1, Ordering::Relaxed);
        let resident_before = stats().resident_bytes;

        // 3 块 64 KiB：TLS 预算 128 KiB 收前 2 块，第 3 块落分片（远低于分片
        // 字节预算 ⇒ 零丢弃）。
        let bufs: Vec<_> = (0..3).map(|_| alloc(TIER_SIZES[3])).collect();
        for b in bufs {
            release(b);
        }

        let s = stats();
        assert_eq!(s.tls_bytes, 2 * TIER_SIZES[3] as u64, "本线程 TLS 收 2 块（128 KiB 预算内）");
        assert!(
            s.resident_bytes >= resident_before + TIER_SIZES[3] as u64,
            "第 3 块必须落分片（resident {} ≥ {} + 64 KiB）",
            s.resident_bytes,
            resident_before
        );
        assert!(s.resident_blocks >= 1, "分片常驻块数随归还增长");
        assert_eq!(
            s.dropped_over_budget,
            DROPPED_OVER_BUDGET.load(Ordering::Relaxed),
            "stats 的 dropped 读数与丢弃计数同源"
        );

        clear();
        assert_eq!(stats().resident_bytes, 0, "clear 后分片常驻归零");
        assert_eq!(stats().resident_blocks, 0, "clear 后分片块数归零");
    }
}
