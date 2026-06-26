//! Counter 实现。
//!
//! 对应 Go `app/stats/counter.go`：
//! - `Counter struct { value int64 }`
//! - `Value() int64` → `atomic.LoadInt64`
//! - `Set(int64) int64` → `atomic.SwapInt64`（返回旧值）
//! - `Add(int64) int64` → `atomic.AddInt64`（Go 注释明确返回 previous value）
//!
//! Rust 端用 [`std::sync::atomic::AtomicI64`] 直接对应。
//! 实现 [`xray_features::stats::Counter`] trait。

use std::sync::atomic::{AtomicI64, Ordering};
use xray_features::stats::Counter as CounterTrait;

/// 原子计数器实现。
///
/// 对应 Go `app/stats.Counter`。线程安全，零初始化为 0。
#[derive(Debug)]
pub struct Counter {
    value: AtomicI64,
}

impl Counter {
    /// 新建零值计数器。对应 Go `new(Counter)`。
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: AtomicI64::new(0),
        }
    }

    /// 从指定初值新建（测试 / 重启用）。
    #[must_use]
    pub fn with_initial(value: i64) -> Self {
        Self {
            value: AtomicI64::new(value),
        }
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterTrait for Counter {
    fn value(&self) -> i64 {
        self.value.load(Ordering::SeqCst)
    }

    fn set(&self, new_value: i64) -> i64 {
        // Go: atomic.SwapInt64(&c.value, newValue)
        self.value.swap(new_value, Ordering::SeqCst)
    }

    fn add(&self, delta: i64) -> i64 {
        // Go 注释明确 "returns the previous value"，但实际 atomic.AddInt64 返回新值。
        // features::stats::Counter trait 注释要求 previous value。
        // 实现：fetch_add 返回旧值，符合 trait 语义。
        self.value.fetch_add(delta, Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;


    #[test]
    fn new_starts_at_zero() {
        let c = Counter::new();
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn default_starts_at_zero() {
        let c = Counter::default();
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn with_initial_value() {
        let c = Counter::with_initial(42);
        assert_eq!(c.value(), 42);
    }

    #[test]
    fn add_returns_previous() {
        let c = Counter::with_initial(10);
        let prev = c.add(5);
        assert_eq!(prev, 10, "add must return previous value");
        assert_eq!(c.value(), 15);
    }

    #[test]
    fn add_negative_returns_previous() {
        let c = Counter::with_initial(100);
        let prev = c.add(-30);
        assert_eq!(prev, 100);
        assert_eq!(c.value(), 70);
    }

    #[test]
    fn add_zero_returns_previous() {
        let c = Counter::with_initial(7);
        let prev = c.add(0);
        assert_eq!(prev, 7);
        assert_eq!(c.value(), 7);
    }

    #[test]
    fn set_returns_previous() {
        let c = Counter::with_initial(11);
        let prev = c.set(99);
        assert_eq!(prev, 11, "set must return previous value");
        assert_eq!(c.value(), 99);
    }

    #[test]
    fn set_zero_clears() {
        let c = Counter::with_initial(123);
        let prev = c.set(0);
        assert_eq!(prev, 123);
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn add_accumulates() {
        let c = Counter::new();
        assert_eq!(c.add(1), 0);
        assert_eq!(c.add(2), 1);
        assert_eq!(c.add(3), 3);
        assert_eq!(c.value(), 6);
    }

    #[test]
    fn add_concurrent_safe() {
        // 并发 add 不丢数据（验证 SeqCst 顺序）
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(Counter::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c2 = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c2.add(1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.value(), 8000, "all increments must be counted");
    }

    #[test]
    fn implements_features_trait() {
        // 验证可作为 Arc<dyn xray_features::stats::Counter> 使用
        let c: Arc<dyn CounterTrait> = Arc::new(Counter::with_initial(5));
        assert_eq!(c.value(), 5);
        assert_eq!(c.add(3), 5);
        assert_eq!(c.value(), 8);
        assert_eq!(c.set(0), 8);
        assert_eq!(c.value(), 0);
    }
}
