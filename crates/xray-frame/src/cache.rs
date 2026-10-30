//! serveStale 缓存（过期保留读 + 后台刷新 single-flight 闸）。
//!
//! 四栏归属（bd h4bl5）：
//!
//! - **udf 基件**：`std_ext::cache::SyncTtlCache`（并发面，`&self` 共享； 单线程 `&mut self` 的
//!   `LruCache`/`TtlCache` 不作基件——缓存面多线程共享）。
//! - **派生方式**：**组合包装**——基件之上叠一层 serveStale 语义： 值的形状带
//!   `fresh_until`（新鲜截止时刻），读路径三态 （新鲜 / 过期但仍在 stale 窗口 /
//!   超出窗口即未命中），并附**同 key 刷新许可** （single-flight 闸）。
//! - **xray-frame 派生件**：本件 [`ServeStaleCache`]。
//! - **消费点**：`crates/xray-app-dns/src/{cache_controller.rs,nameserver/cached.rs}` ——DNS
//!   serveStale 的**窗口口径**（[`stale_window`]）与**同 fqdn 刷新许可**
//!   （[`RefreshGate`]）由本件单源给出。DNS 答案本体仍留 `CacheController.ips` （Go
//!   对拍面：per-family 过期 + cleanup/shrink + pubsub 广播不换）。
//!
//! # 边界语义（精确规则）
//!
//! - **新鲜**：`now < fresh_until` ⇒ [`ServeStaleRead::Fresh`]，直接返回值。
//! - **过期但仍在 stale 窗口**：`now >= fresh_until` 且 `now <= fresh_until + stale_window` ⇒
//!   [`ServeStaleRead::Stale`]： **仍返回旧值**（不因过期而丢数据），并**尝试获取该 key
//!   的刷新许可**； 拿到许可者（[`RefreshPermit`]）负责去刷新，没拿到的直接用旧值。
//! - **超出 stale 窗口**：`now > fresh_until + stale_window` ⇒ **未命中**
//!   （[`ServeStaleRead::Miss`]），条目同时被物理摘除（不再占容量）。
//! - **stale 窗口 = `None`** ⇒ 过期值**无限期保留**（至容量淘汰）：对应 “serveStale
//!   但不设过期上限”的语义。
//! - **刷新许可**：同一 key 同时最多一个持有者；许可随持有者释放（[`RefreshPermit`] drop 即释放）⇒
//!   后到的读只拿旧值，不重复触发上游。
//! - **物理保留**：基件 TTL = `fresh_until + stale_window - now`（超窗口者不入缓存）。
//! - **无上限窗口的保留**：TTL 取「距 `fresh_until` 的剩余时间」与一年的较大者 （基件 TTL 恒 >
//!   0，禁零值）。

use std::{
    collections::HashSet,
    hash::Hash,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use skeleton::clock::Clock;
use std_ext::cache::SyncTtlCache;

/// 无上限 stale 窗口时的物理保留下限（一年）。
const UNBOUNDED_RETENTION: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// 值形状：业务值 + 新鲜截止时刻（`fresh_until`）。
///
/// `fresh_until` 与基件自身的 TTL 是**两件事**：基件 TTL 决定物理保留
/// （含 stale 窗口），`fresh_until` 决定**新鲜 vs 过期**的判定面。
#[derive(Debug, Clone)]
pub struct StaleValue<V> {
    /// 业务值。
    pub value: V,
    /// 新鲜截止时刻：`now < fresh_until` ⇒ 新鲜。
    pub fresh_until: Instant,
}

/// 读路径结果。
#[derive(Debug)]
pub enum ServeStaleRead<V> {
    /// 命中且新鲜（`now < fresh_until`）。
    Fresh(V),
    /// 已过期但仍在 stale 窗口内：**旧值照返**；
    /// `permit` 为 `Some` 时本调用方取得该 key 的刷新许可（负责去刷新）。
    Stale {
        /// 过期但仍可服务的旧值。
        value: V,
        /// 同 key 刷新许可：`Some` = 本调用方应去刷新；`None` = 他人已在刷新。
        permit: Option<RefreshPermit>,
    },
    /// 未命中：无条目，或已超出 stale 窗口。
    Miss,
}

/// 同 key 刷新许可（single-flight 闸）。
///
/// 持有者负责刷新；许可随持有者 drop 而释放（[`RefreshPermit::release`] 可提前释放）。
/// 释放动作对键类型擦除（闭包），故本类型与键类型无关、可跨模块传递。
pub struct RefreshPermit {
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl RefreshPermit {
    /// 提前释放许可（等价于 drop，但语义显式）。
    pub fn release(self) {}
}

impl Drop for RefreshPermit {
    fn drop(&mut self) {
        // 释放动作恰执行一次：`release` 已 take 过则此处为 None。
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

impl std::fmt::Debug for RefreshPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshPermit").finish_non_exhaustive()
    }
}

/// 同 key 刷新许可闸（single-flight 的**可独立复用**部分）。
///
/// [`ServeStaleCache`] 内嵌一份；只借「同 key 同时至多一个刷新者」语义、答案
/// 本体自己管的调用方（DNS 缓存的 serveStale pull 去重）也可直接持一份——不
/// 必为了许可去背一个缓存。
///
/// 锁毒化按 `PoisonError::into_inner` 恢复：闸状态是「可重入的集合」，一次
/// panic 不破坏其不变量。
pub struct RefreshGate<K> {
    refreshing: Arc<Mutex<HashSet<K>>>,
}

impl<K> Default for RefreshGate<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> RefreshGate<K> {
    /// 空闸。
    #[must_use]
    pub fn new() -> Self {
        Self { refreshing: Arc::new(Mutex::new(HashSet::new())) }
    }
}

impl<K> std::fmt::Debug for RefreshGate<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshGate").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> RefreshGate<K> {
    /// 尝试获取该 key 的刷新许可：已在刷新中 ⇒ `None`。
    ///
    /// 许可持有者负责刷新；许可随持有者 drop（或 [`RefreshPermit::release`]）释放。
    #[must_use]
    pub fn try_begin(&self, key: &K) -> Option<RefreshPermit> {
        let mut refreshing = self.refreshing.lock().unwrap_or_else(PoisonError::into_inner);
        if refreshing.contains(key) {
            return None;
        }
        refreshing.insert(key.clone());
        let refreshing = Arc::clone(&self.refreshing);
        let key = key.clone();
        Some(RefreshPermit {
            release: Some(Box::new(move || {
                let mut refreshing = refreshing.lock().unwrap_or_else(PoisonError::into_inner);
                refreshing.remove(&key);
            })),
        })
    }
}

/// serveStale 窗口（统一口径，DNS 等消费方共用）：
///
/// - `serve_stale == false` ⇒ `Some(Duration::ZERO)`：过期即失效（不服务旧值）；
/// - `serve_stale == true && grace == None` ⇒ `None`：过期值无限期可服务；
/// - `serve_stale == true && grace == Some(d)` ⇒ `Some(d)`：过期后 `d` 内仍可服务。
#[must_use]
pub const fn stale_window(serve_stale: bool, grace: Option<Duration>) -> Option<Duration> {
    match (serve_stale, grace) {
        (false, _) => Some(Duration::ZERO),
        (true, grace) => grace,
    }
}

/// 并发面：内部复用 [`SyncTtlCache`]（`&self` 共享），刷新许可走 [`RefreshGate`]
/// （同 key 至多一个刷新者，许可随持有者释放）。
pub struct ServeStaleCache<K, V> {
    inner: SyncTtlCache<K, StaleValue<V>>,
    clock: Arc<dyn Clock>,
    stale_window: Option<Duration>,
    gate: RefreshGate<K>,
}

impl<K, V> ServeStaleCache<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// 构造。
    ///
    /// - `clock`：新鲜/过期判定与物理保留的时间源（与基件同一时钟面）。
    /// - `capacity`：基件容量上限（`> 0`；由基件 fail-fast 校验）。
    /// - `stale_window`：`Some(d)` ⇒ 过期后 `d` 内仍可服务旧值； `None` ⇒
    ///   过期值无限期保留（至容量淘汰）。
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, capacity: usize, stale_window: Option<Duration>) -> Self {
        Self {
            inner: SyncTtlCache::new(Arc::clone(&clock), capacity),
            clock,
            stale_window,
            gate: RefreshGate::new(),
        }
    }

    /// 写入一条记录，新鲜截止时刻为 `fresh_until`。
    ///
    /// 返回是否入缓存：已超出 stale 窗口者**不入**（无保留价值）。
    pub fn insert_at(&self, key: K, value: V, fresh_until: Instant) -> bool {
        let now = self.clock.now_instant();
        let ttl = match self.stale_window {
            Some(window) => match fresh_until.checked_add(window) {
                Some(end) => end.saturating_duration_since(now),
                None => Duration::ZERO,
            },
            // 无上限窗口：保留至容量淘汰（TTL 至少一年，恒 > 0）。
            None => fresh_until.saturating_duration_since(now).max(UNBOUNDED_RETENTION),
        };
        if ttl.is_zero() {
            return false;
        }
        self.inner.insert(key, StaleValue { value, fresh_until }, ttl);
        true
    }

    /// 读路径（新鲜 / 过期保留 / 未命中）。
    pub fn get(&self, key: &K) -> ServeStaleRead<V> {
        let Some(entry) = self.inner.get(key) else {
            return ServeStaleRead::Miss;
        };
        let now = self.clock.now_instant();
        if now < entry.fresh_until {
            return ServeStaleRead::Fresh(entry.value.clone());
        }
        if let Some(window) = self.stale_window {
            let within = fresh_until_plus(entry.fresh_until, window).is_some_and(|end| now <= end);
            if !within {
                // 超出 stale 窗口 ⇒ 未命中（并摘除条目：不再占容量）。
                let _ = self.inner.remove(key);
                return ServeStaleRead::Miss;
            }
        }
        let permit = self.try_begin_refresh(key);
        ServeStaleRead::Stale { value: entry.value.clone(), permit }
    }

    /// 尝试获取该 key 的刷新许可：已在刷新中 ⇒ `None`。
    ///
    /// 许可持有者负责刷新；许可随持有者 drop 而释放。
    #[must_use]
    pub fn try_begin_refresh(&self, key: &K) -> Option<RefreshPermit> {
        self.gate.try_begin(key)
    }

    /// 摘除一条记录（物理面）。
    pub fn remove(&self, key: &K) -> bool {
        self.inner.remove(key).is_some()
    }

    /// 当前条数（物理面，含过期未淘汰者）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 是否为空（物理面）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// stale 窗口（`None` = 无上限）。
    #[must_use]
    pub fn stale_window(&self) -> Option<Duration> {
        self.stale_window
    }
}

/// `fresh_until + window`（溢出即 `None`）。
fn fresh_until_plus(fresh_until: Instant, window: Duration) -> Option<Instant> {
    fresh_until.checked_add(window)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;

    use skeleton::clock::MockClock;

    use super::*;

    fn cache(clock: Arc<MockClock>, window: Option<Duration>) -> ServeStaleCache<String, u32> {
        ServeStaleCache::new(clock, 16, window)
    }

    #[test]
    fn fresh_hit_returns_value_directly() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), Some(Duration::from_secs(30)));
        let now = clock.now_instant();
        assert!(c.insert_at("a".to_string(), 7, now + Duration::from_secs(10)));
        match c.get(&"a".to_string()) {
            ServeStaleRead::Fresh(v) => assert_eq!(v, 7),
            _ => panic!("fresh hit expected"),
        }
    }

    #[test]
    fn expired_within_window_returns_old_value_and_marks_stale() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), Some(Duration::from_secs(30)));
        let now = clock.now_instant();
        assert!(c.insert_at("a".to_string(), 7, now));
        clock.advance(Duration::from_secs(5));
        match c.get(&"a".to_string()) {
            ServeStaleRead::Stale { value, permit } => {
                assert_eq!(value, 7, "过期但窗口内必须仍返回旧值");
                assert!(permit.is_some(), "首个读者应拿到刷新许可");
            },
            _ => panic!("stale hit expected"),
        }
    }

    #[test]
    fn beyond_stale_window_is_miss() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), Some(Duration::from_secs(30)));
        let now = clock.now_instant();
        assert!(c.insert_at("a".to_string(), 7, now));
        clock.advance(Duration::from_secs(31));
        match c.get(&"a".to_string()) {
            ServeStaleRead::Miss => {},
            _ => panic!("miss expected beyond stale window"),
        }
        assert!(c.is_empty(), "超出窗口者应被物理摘除");
    }

    #[test]
    fn insert_beyond_window_is_rejected() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), Some(Duration::from_secs(30)));
        let now = clock.now_instant();
        assert!(!c.insert_at("a".to_string(), 7, now - Duration::from_secs(60)));
        assert!(c.is_empty());
    }

    #[test]
    fn unlimited_window_keeps_expired_value() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), None);
        let now = clock.now_instant();
        assert!(c.insert_at("a".to_string(), 7, now));
        clock.advance(Duration::from_secs(3600));
        match c.get(&"a".to_string()) {
            ServeStaleRead::Stale { value, .. } => assert_eq!(value, 7),
            _ => panic!("unlimited window must keep expired value"),
        }
    }

    #[test]
    fn concurrent_same_key_refresh_triggers_single_upstream() {
        let clock = Arc::new(MockClock::new());
        let c = cache(clock.clone(), Some(Duration::from_secs(30)));
        let now = clock.now_instant();
        assert!(c.insert_at("a".to_string(), 7, now));
        clock.advance(Duration::from_secs(5));

        let barrier = Arc::new(Barrier::new(8));
        let upstream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let holders: Vec<Option<RefreshPermit>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let upstream_calls = Arc::clone(&upstream_calls);
                    let c = &c;
                    scope.spawn(move || {
                        barrier.wait();
                        match c.get(&"a".to_string()) {
                            ServeStaleRead::Stale { permit, .. } => {
                                if permit.is_some() {
                                    upstream_calls
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    permit
                                } else {
                                    None
                                }
                            },
                            _ => None,
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("thread join")).collect()
        });
        assert_eq!(
            upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "同 key 只应触发一次上游"
        );
        assert_eq!(holders.iter().filter(|p| p.is_some()).count(), 1, "只有一个读者拿到刷新许可");
        drop(holders);
        // 许可释放后，下一个读者可再取许可（不泄漏）。
        match c.get(&"a".to_string()) {
            ServeStaleRead::Stale { permit, .. } => {
                assert!(permit.is_some(), "许可释放后应可再获取")
            },
            _ => panic!("stale hit expected"),
        }
    }

    #[test]
    fn refresh_gate_is_single_flight_and_releases() {
        let gate: RefreshGate<String> = RefreshGate::new();
        let key = "k".to_string();
        let first = gate.try_begin(&key).expect("首个持有者拿到许可");
        assert!(gate.try_begin(&key).is_none(), "同 key 在飞时不给第二个许可");
        assert!(gate.try_begin(&"other".to_string()).is_some(), "不同 key 互不阻塞");
        first.release();
        assert!(gate.try_begin(&key).is_some(), "释放后可再取");
    }

    #[test]
    fn stale_window_rule_is_shared() {
        // 不启用 serveStale ⇒ 零宽限窗（过期即失效）。
        assert_eq!(stale_window(false, None), Some(Duration::ZERO));
        assert_eq!(stale_window(false, Some(Duration::from_secs(60))), Some(Duration::ZERO));
        // 启用且未给宽限 ⇒ 无上限。
        assert_eq!(stale_window(true, None), None);
        // 启用且给宽限 ⇒ 该宽限。
        assert_eq!(
            stale_window(true, Some(Duration::from_secs(60))),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn zero_window_stores_nothing() {
        // 零宽限窗 = 不缓存：`insert_at` 的物理 TTL 恒 0 ⇒ fail-visible 拒绝，
        // 而不是插一条「立刻未命中」的僵尸（Go `collectExpiredKeys` 同口径：
        // 无保留价值者不入）。
        let clock = Arc::new(MockClock::new());
        let c = ServeStaleCache::new(clock.clone(), 16, stale_window(false, None));
        let now = clock.now_instant();
        assert!(!c.insert_at("a".to_string(), 7, now), "零窗口不保留任何条目");
        assert!(c.is_empty());
        assert!(matches!(c.get(&"a".to_string()), ServeStaleRead::Miss));
    }
}
