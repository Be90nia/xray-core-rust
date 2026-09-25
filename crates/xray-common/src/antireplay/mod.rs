//! 防重放过滤器
//!
//! 对应 Go 版本 `common/antireplay` 包，提供基于双池时间窗的重放检测。

use std::{
    collections::HashSet,
    hash::Hash,
    time::{Duration, Instant},
};

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
pub struct MapFilter<T: Hash + Eq + Clone + Send + Sync> {
    pool_a: HashSet<T>,
    pool_b: HashSet<T>,
    interval: Duration,
    last_clean: Instant,
}

impl<T: Hash + Eq + Clone + Send + Sync> MapFilter<T> {
    /// 创建过滤器，`interval_secs` 为换代间隔秒数（Go `NewMapFilter(interval)`）。
    #[must_use]
    pub fn new(interval_secs: u64) -> Self {
        Self {
            pool_a: HashSet::new(),
            pool_b: HashSet::new(),
            interval: Duration::from_secs(interval_secs),
            last_clean: Instant::now(),
        }
    }
}

impl<T: Hash + Eq + Clone + Send + Sync> ReplayFilter<T> for MapFilter<T> {
    fn check(&mut self, value: &T) -> bool {
        let now = Instant::now();
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

impl<T: Hash + Eq + Clone + Send + Sync> Default for MapFilter<T> {
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
}
