//! 对端延迟统计
//!
//! 对应 Go 版本 `common/peer` 包，提供延迟度量和加权移动平均。

use std::sync::Mutex;

/// 延迟度量 trait。
///
/// 对应 Go `peer.Latency` 接口。
pub trait Latency: Send + Sync {
    /// 返回当前延迟值（纳秒）。
    fn value(&self) -> u64;
}

/// 具有连接延迟和握手延迟的对端。
///
/// 对应 Go `peer.HasLatency` 接口。
pub trait HasLatency: Send + Sync {
    /// 连接延迟。
    fn connection_latency(&self) -> &dyn Latency;
    /// 握手延迟。
    fn handshake_latency(&self) -> &dyn Latency;
}

/// 加权移动平均延迟。
///
/// 对应 Go `peer.AverageLatency`。
/// 更新公式：`new = (old + sample * 2) / 3`，新样本权重 2/3。
pub struct AverageLatency {
    inner: Mutex<AverageLatencyInner>,
}

struct AverageLatencyInner {
    value: u64,
}

impl AverageLatency {
    /// 创建零初始值的平均延迟。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(AverageLatencyInner { value: 0 }),
        }
    }

    /// 用初始值创建平均延迟。
    #[must_use]
    pub fn with_value(value: u64) -> Self {
        Self {
            inner: Mutex::new(AverageLatencyInner { value }),
        }
    }

    /// 用新采样值更新延迟（加权移动平均）。
    ///
    /// 公式：`(old + sample * 2) / 3`。
    /// 锁中毒时静默忽略更新（与 Go 版本行为一致：Mutex 不可能中毒）。
    pub fn update(&self, new_value: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.value = (inner.value + new_value * 2) / 3;
        }
    }
}

impl Latency for AverageLatency {
    fn value(&self) -> u64 {
        self.inner
            .lock()
            .map_or(0, |inner| inner.value)
    }
}

impl Default for AverageLatency {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_starts_at_zero() {
        let latency = AverageLatency::new();
        assert_eq!(latency.value(), 0);
    }

    #[test]
    fn test_with_value() {
        let latency = AverageLatency::with_value(100);
        assert_eq!(latency.value(), 100);
    }

    #[test]
    fn test_update_weighted_average() {
        let latency = AverageLatency::with_value(30);
        // (30 + 60 * 2) / 3 = 150 / 3 = 50
        latency.update(60);
        assert_eq!(latency.value(), 50);
    }

    #[test]
    fn test_update_converges_to_sample() {
        let latency = AverageLatency::new();
        // 连续更新同一值，应收敛到该值
        for _ in 0..20 {
            latency.update(100);
        }
        // 加权平均会趋近 100 但不完全等于
        let v = latency.value();
        assert!(v > 90, "should converge toward 100, got {v}");
    }

    #[test]
    fn test_default_is_new() {
        let latency = AverageLatency::default();
        assert_eq!(latency.value(), 0);
    }

    #[test]
    fn test_latency_trait_object() {
        let latency: Box<dyn Latency> = Box::new(AverageLatency::with_value(42));
        assert_eq!(latency.value(), 42);
    }
}
