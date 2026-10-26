//! 防重放过滤器
//!
//! 对应 Go 版本 `common/antireplay` 包，提供基于双池时间窗的重放检测。

use std::{
    collections::HashSet,
    hash::Hash,
    time::{Duration, Instant},
};

use skeleton::clock::{Clock, SystemClock};

/// 防重放过滤器 trait。
///
/// `check` 返回 `true` 表示新值（未见过），`false` 表示重放（已见过）。
pub trait ReplayFilter<T>: Send + Sync {
    /// 检查值是否为新值。返回 true 表示新值，false 表示重放。
    fn check(&mut self, value: &T) -> bool;
}

/// Go `antireplay.ReplayFilter` 同构实现（`common/antireplay/mapfilter.go:9-45`）。
///
/// 双池时间换代：间隔 `interval` 秒后 poolB ← poolA（旧一代），poolA 清空
/// （新一代）；判重查两池，因此任意值在 `[interval, 2*interval)` 秒内必被拒，
/// 超过 `2*interval` 秒后可复用。池无容量上限——旧条目不会被新连接挤出。
pub struct MapFilter<T: Hash + Eq + Clone + Send + Sync, C: Clock = SystemClock> {
    pool_a: HashSet<T>,
    pool_b: HashSet<T>,
    interval: Duration,
    last_clean: Instant,
    /// 时间源契约（bd bf92）：生产 `SystemClock`（std 直通，行为零变化）；
    /// 测试注入 `MockClock` 得确定性换代时间线。泛型静态分发——`check` 是
    /// vmess authID 反重放热路径（逐连接逐次取时），禁动态分发开销。
    clock: C,
}

impl<T: Hash + Eq + Clone + Send + Sync> MapFilter<T, SystemClock> {
    /// 创建过滤器，`interval_secs` 为换代间隔秒数（Go `NewMapFilter(interval)`）。
    ///
    /// 豁免理由：缺省路径的 `Instant::now()` 就是 `SystemClock::now_instant()` 的
    /// std 直通（同值同语义，见 `with_clock` 注入面），调换只会多一层泛型实例化；
    /// 热路径取时已全部走 `clock` 端口，测试期由 `MockClock` 冻结。
    #[allow(clippy::disallowed_methods)]
    #[must_use]
    pub fn new(interval_secs: u64) -> Self {
        Self {
            pool_a: HashSet::new(),
            pool_b: HashSet::new(),
            interval: Duration::from_secs(interval_secs),
            last_clean: Instant::now(),
            clock: SystemClock,
        }
    }
}

impl<T: Hash + Eq + Clone + Send + Sync, C: Clock> MapFilter<T, C> {
    /// 指定时间源构造（测试注入 `MockClock`）。
    #[must_use]
    pub fn with_clock(interval_secs: u64, clock: C) -> Self {
        Self {
            pool_a: HashSet::new(),
            pool_b: HashSet::new(),
            interval: Duration::from_secs(interval_secs),
            last_clean: clock.now_instant(),
            clock,
        }
    }
}

impl<T: Hash + Eq + Clone + Send + Sync, C: Clock> ReplayFilter<T> for MapFilter<T, C> {
    fn check(&mut self, value: &T) -> bool {
        let now = self.clock.now_instant();
        if now.duration_since(self.last_clean) >= self.interval {
            self.pool_b = std::mem::take(&mut self.pool_a);
            self.last_clean = now;
        }

        let fresh = !self.pool_a.contains(value) && !self.pool_b.contains(value);
        if fresh {
            self.pool_a.insert(value.clone());
        }
        fresh
    }
}

impl<T: Hash + Eq + Clone + Send + Sync> Default for MapFilter<T, SystemClock> {
    /// 默认 120 秒——vmess authID 反重放的生产值（Go authid.go:71 `NewMapFilter(120)`）。
    fn default() -> Self {
        Self::new(120)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filter() {
        let filter: MapFilter<String> = MapFilter::new(120);
        assert!(filter.pool_a.is_empty());
        assert!(filter.pool_b.is_empty());
    }

    #[test]
    fn test_default_filter_is_120s() {
        let filter: MapFilter<u32> = MapFilter::default();
        assert_eq!(filter.interval, Duration::from_secs(120));
    }

    #[test]
    fn test_check_new_value() {
        let mut filter: MapFilter<&str> = MapFilter::new(120);
        assert!(filter.check(&"hello"));
    }

    #[test]
    fn test_check_replay() {
        let mut filter: MapFilter<&str> = MapFilter::new(120);
        assert!(filter.check(&"hello"));
        assert!(!filter.check(&"hello")); // 重放
    }

    #[test]
    fn test_multiple_values() {
        let mut filter: MapFilter<u32> = MapFilter::new(120);
        assert!(filter.check(&1));
        assert!(filter.check(&2));
        assert!(filter.check(&3));
        assert!(!filter.check(&1)); // 重放
        assert!(!filter.check(&2)); // 重放
        assert!(filter.check(&4)); // 新值
    }

    /// 票 j46g：双池无容量上限——大量新值不挤出旧条目（Go 语义；
    /// 旧实现的 `LruCache(120)` 会在 120 条新连接后放行重放）。
    #[test]
    fn no_capacity_eviction_within_interval() {
        let mut filter: MapFilter<u32> = MapFilter::new(120);
        assert!(filter.check(&0));
        for i in 1..=200u32 {
            assert!(filter.check(&i), "value {i} must pass as new");
        }
        assert!(!filter.check(&0), "first value must stay rejected after 200 new values");
    }

    /// 换代语义（`interval=0` 每次 check 都换代，确定性验证）：旧一代条目
    /// 挪入 poolB 再拒一次，随后被彻底遗忘——超过 `2*interval` 后可复用。
    #[test]
    fn pools_rotate_after_interval() {
        let mut filter: MapFilter<u32> = MapFilter::new(0);
        assert!(filter.check(&1));
        assert!(!filter.check(&1), "previous generation sits in poolB");
        assert!(filter.check(&1), "forgotten after both pools rotated past it");
    }

    /// bd bf92：换代节奏跟随注入钟（MockClock 确定性时间线，零 sleep）。
    /// 真实钟下 `last_clean` 锚真实 Instant，无法呈现「恰好 59_999ms 不换代 /
    /// +1ms 换代」——注入即被证明；`with_clock` 缺省路径（`new`）行为零变化
    /// （SystemClock = `Instant::now()` std 直通，上方既有测试全体守护）。
    #[test]
    fn rotation_follows_injected_clock() {
        use skeleton::clock::MockClock;
        let mut filter = MapFilter::with_clock(60, MockClock::new());
        assert!(filter.check(&1));
        filter.clock.advance(Duration::from_millis(59_999));
        assert!(filter.check(&2), "未到换代间隔：新值照过");
        assert!(!filter.check(&1), "未换代：旧代 poolA 命中");
        filter.clock.advance(Duration::from_millis(1)); // 累计 60s → 换代
        assert!(!filter.check(&1), "换代后 1 落 poolB 仍拒");
        assert!(!filter.check(&2), "换代后 2 落 poolB 仍拒");
        filter.clock.advance(Duration::from_secs(60)); // 第二次换代 → 可复用
        assert!(filter.check(&1), "超过 2×interval 可复用");
    }
}
