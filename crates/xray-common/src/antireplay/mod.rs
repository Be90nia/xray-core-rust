//! 防重放过滤器
//!
//! 对应 Go 版本 `common/antireplay` 包，提供基于 HashSet 的重放检测。

use std::collections::HashSet;
use std::hash::Hash;

/// 防重放过滤器 trait。
///
/// `check` 返回 `true` 表示新值（未见过），`false` 表示重放（已见过）。
pub trait ReplayFilter<T>: Send + Sync {
    /// 检查值是否为新值。返回 true 表示新值，false 表示重放。
    fn check(&mut self, value: &T) -> bool;
}

/// 基于 HashSet 的防重放过滤器。
pub struct MapFilter<T: Hash + Eq + Clone + Send + Sync> {
    seen: HashSet<T>,
}

impl<T: Hash + Eq + Clone + Send + Sync> MapFilter<T> {
    /// 创建新的空过滤器。
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }
}

impl<T: Hash + Eq + Clone + Send + Sync> ReplayFilter<T> for MapFilter<T> {
    fn check(&mut self, value: &T) -> bool {
        self.seen.insert(value.clone())
    }
}

impl<T: Hash + Eq + Clone + Send + Sync> Default for MapFilter<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filter() {
        let filter: MapFilter<String> = MapFilter::new();
        assert!(filter.seen.is_empty());
    }

    #[test]
    fn test_default_filter() {
        let filter: MapFilter<u32> = MapFilter::default();
        assert!(filter.seen.is_empty());
    }

    #[test]
    fn test_check_new_value() {
        let mut filter: MapFilter<&str> = MapFilter::new();
        assert!(filter.check(&"hello"));
    }

    #[test]
    fn test_check_replay() {
        let mut filter: MapFilter<&str> = MapFilter::new();
        assert!(filter.check(&"hello"));
        assert!(!filter.check(&"hello")); // 重放
    }

    #[test]
    fn test_multiple_values() {
        let mut filter: MapFilter<u32> = MapFilter::new();
        assert!(filter.check(&1));
        assert!(filter.check(&2));
        assert!(filter.check(&3));
        assert!(!filter.check(&1)); // 重放
        assert!(!filter.check(&2)); // 重放
        assert!(filter.check(&4));  // 新值
    }

    #[test]
    fn test_with_string() {
        let mut filter: MapFilter<String> = MapFilter::new();
        let s1 = "packet1".to_string();
        let s2 = "packet2".to_string();
        assert!(filter.check(&s1));
        assert!(filter.check(&s2));
        assert!(!filter.check(&s1));
    }
}
