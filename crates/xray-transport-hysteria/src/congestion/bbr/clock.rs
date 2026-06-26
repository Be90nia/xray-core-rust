//! Clock trait + DefaultClock（对应 Go `congestion/bbr/clock.go`）。
//!
//! ponytail: 用纳秒级 u64 单调时钟（对应 Go `monotime.Time`）。

use std::time::Instant;

use super::super::types::MonoTime;

/// Clock 抽象（对应 Go `Clock interface`）。
pub trait Clock: Send + Sync {
    /// 当前单调时间（纳秒）。
    fn now(&self) -> MonoTime;
}

/// DefaultClock：基于 `Instant` 的单调时钟（对应 Go `DefaultClock`）。
#[derive(Debug, Default, Copy, Clone)]
pub struct DefaultClock {
    /// 启动基准。`now()` 返回 `Instant::now() - base` 的纳秒数。
    base: Option<Instant>,
}

impl DefaultClock {
    /// 构造。延迟初始化 base，第一次 `now()` 调用时确定。
    #[must_use]
    pub const fn new() -> Self {
        Self { base: None }
    }

    /// 已知 base 的构造（测试用）。
    #[must_use]
    pub fn with_base(base: Instant) -> Self {
        Self { base: Some(base) }
    }
}

impl Clock for DefaultClock {
    fn now(&self) -> MonoTime {
        // ponytail: 用全局 Instant 比较返回纳秒。base 在首次调用时锁定。
        // 因 Clock trait 是 &self，无法缓存 base，所以用静态 OnceCell 作基准。
        use std::sync::OnceLock;
        static GLOBAL_BASE: OnceLock<Instant> = OnceLock::new();
        let base = self.base.unwrap_or_else(|| {
            *GLOBAL_BASE.get_or_init(Instant::now)
        });
        Instant::now().saturating_duration_since(base).as_nanos() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn default_clock_returns_monotonic_increasing() {
        let clock = DefaultClock::new();
        let t1 = clock.now();
        sleep(Duration::from_millis(5));
        let t2 = clock.now();
        assert!(t2 > t1, "t2={} should be > t1={}", t2, t1);
    }

    #[test]
    fn default_clock_with_explicit_base() {
        let base = Instant::now();
        sleep(Duration::from_millis(10));
        let clock = DefaultClock::with_base(base);
        let t = clock.now();
        // 至少 10ms = 10_000_000 ns
        assert!(t >= 10_000_000, "got {t}");
    }

    #[test]
    fn default_clock_monotonic_within_same_call() {
        let clock = DefaultClock::new();
        let t1 = clock.now();
        let t2 = clock.now();
        // 同一进程内连续调用应该单调非减
        assert!(t2 >= t1);
    }
}
