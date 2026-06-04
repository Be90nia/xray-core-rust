//! Statistics manager trait for tracking counters.
//!
//! Corresponds to Go's `features/stats` package.

use async_trait::async_trait;
use std::sync::Arc;

/// Feature type identifier for Stats.
pub const FEATURE_STATS: &str = "stats";

/// Statistics counter.
///
/// Corresponds to Go's `features/stats.Counter`.
pub trait Counter: Send + Sync {
    /// Get the current counter value.
    fn value(&self) -> i64;

    /// Add a delta to the counter and return the new total.
    fn add(&self, delta: i64) -> i64;

    /// Set the counter to a specific value.
    fn set(&self, value: i64);
}

/// Statistics manager trait.
///
/// Corresponds to Go's `features/stats.Manager`.
#[async_trait]
pub trait StatsManager: Send + Sync {
    /// Register a new counter with the given name.
    ///
    /// If a counter with the same name already exists, returns the existing one.
    fn register_counter(&self, name: &str) -> Arc<dyn Counter>;

    /// Get a counter by name.
    fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>>;

    /// Unregister a counter by name.
    fn unregister_counter(&self, name: &str);
}

/// A simple atomic counter implementation.
pub struct AtomicCounter {
    inner: std::sync::atomic::AtomicI64,
}

impl AtomicCounter {
    /// Create a new atomic counter initialized to zero.
    pub fn new() -> Self {
        Self {
            inner: std::sync::atomic::AtomicI64::new(0),
        }
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl Counter for AtomicCounter {
    fn value(&self) -> i64 {
        self.inner.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn add(&self, delta: i64) -> i64 {
        self.inner.fetch_add(delta, std::sync::atomic::Ordering::SeqCst) + delta
    }

    fn set(&self, value: i64) {
        self.inner.store(value, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_stats_constant() {
        assert_eq!(FEATURE_STATS, "stats");
    }

    #[test]
    fn test_atomic_counter_new() {
        let counter = AtomicCounter::new();
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn test_atomic_counter_add() {
        let counter = AtomicCounter::new();
        assert_eq!(counter.add(10), 10);
        assert_eq!(counter.value(), 10);
        assert_eq!(counter.add(5), 15);
        assert_eq!(counter.value(), 15);
    }

    #[test]
    fn test_atomic_counter_set() {
        let counter = AtomicCounter::new();
        counter.set(42);
        assert_eq!(counter.value(), 42);
    }

    #[test]
    fn test_atomic_counter_negative() {
        let counter = AtomicCounter::new();
        counter.add(100);
        assert_eq!(counter.add(-30), 70);
        assert_eq!(counter.value(), 70);
    }

    #[test]
    fn test_atomic_counter_default() {
        let counter = AtomicCounter::default();
        assert_eq!(counter.value(), 0);
    }

    /// Mock stats manager for testing the trait is object-safe.
    struct MockStatsManager {
        counters: std::sync::Mutex<std::collections::HashMap<String, Arc<AtomicCounter>>>,
    }

    impl MockStatsManager {
        fn new() -> Self {
            Self {
                counters: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StatsManager for MockStatsManager {
        fn register_counter(&self, name: &str) -> Arc<dyn Counter> {
            let mut counters = self.counters.lock().unwrap();
            counters
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(AtomicCounter::new()))
                .clone()
        }

        fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>> {
            let counters = self.counters.lock().unwrap();
            counters.get(name).map(|c| c.clone() as Arc<dyn Counter>)
        }

        fn unregister_counter(&self, name: &str) {
            let mut counters = self.counters.lock().unwrap();
            counters.remove(name);
        }
    }

    #[test]
    fn test_mock_stats_manager_register() {
        let manager = MockStatsManager::new();
        let counter = manager.register_counter("uplink");
        counter.add(100);
        assert_eq!(counter.value(), 100);
    }

    #[test]
    fn test_mock_stats_manager_get() {
        let manager = MockStatsManager::new();
        manager.register_counter("downlink");
        let counter = manager.get_counter("downlink");
        assert!(counter.is_some());

        let missing = manager.get_counter("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_mock_stats_manager_unregister() {
        let manager = MockStatsManager::new();
        manager.register_counter("temp");
        assert!(manager.get_counter("temp").is_some());
        manager.unregister_counter("temp");
        assert!(manager.get_counter("temp").is_none());
    }
}
