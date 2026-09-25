//! HealthPingRtts：环形缓冲 + statistics 计算（all/fail/avg/deviation/max/min）。
//!
//! 对应 Go `app/observatory/burst/healthping_result.go`。
//! 所有时间值是 i64 纳秒（与 Go time.Duration 兼容）。
//! 时间戳 now_unix_nanos 用 i64 表示（足够 ~292 年）。

use crate::burst::{RTT_FAILED, RTT_UNTESTED};

/// 单次 ping 记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingRtt {
    /// 测量时间（Unix 纳秒）。
    pub time: i64,
    /// RTT 值（纳秒），可能是哨兵值（RTT_FAILED/RTT_UNTESTED）。
    pub value: i64,
}

/// HealthPing 统计结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthPingStats {
    pub all: i64,
    pub fail: i64,
    pub deviation: i64,
    pub average: i64,
    pub max: i64,
    pub min: i64,
}

/// HealthPingRtts：固定容量的环形缓冲，存储最近 N 次 ping 结果。
///
/// 对应 Go `HealthPingRTTS`。
pub struct HealthPingRtts {
    cap: usize,
    validity_nanos: i64,
    rtts: Vec<PingRtt>,
    idx: usize, // 下一个写入位置；初始时全为 RTT_UNTESTED
    initialized: bool,
}

impl HealthPingRtts {
    /// 创建容量为 `cap`、RTT 有效期为 `validity_nanos` 的缓冲。
    pub fn new(cap: usize, validity_nanos: i64) -> Self {
        Self { cap, validity_nanos, rtts: Vec::with_capacity(cap), idx: 0, initialized: false }
    }

    /// 当前容量。
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// 写入一个 RTT 测量值。
    ///
    /// 对应 Go `Put`：环形缓冲覆盖最旧值。
    pub fn put(&mut self, value: i64, now_unix_nanos: i64) {
        if !self.initialized {
            self.rtts.clear();
            self.rtts.resize(self.cap, PingRtt { time: 0, value: RTT_UNTESTED });
            self.idx = 0;
            self.initialized = true;
        }
        self.rtts[self.idx] = PingRtt { time: now_unix_nanos, value };
        self.idx = (self.idx + 1) % self.cap;
    }

    /// 最新写入的样本值（环形缓冲 idx 前一位）。
    ///
    /// 未写入过任何样本 → `None`。
    pub fn latest(&self) -> Option<i64> {
        if !self.initialized {
            return None;
        }
        let last = (self.idx + self.cap - 1) % self.cap;
        Some(self.rtts[last].value)
    }

    /// 计算当前 statistics。
    ///
    /// 对应 Go `getStatistics`：跳过 untested + 过期项，统计 fail/avg/max/min/deviation。
    /// - `now_unix_nanos` 当前时间，用于判断过期
    /// - 若无有效项，stats.min = 0
    /// - 若有效项 < 2，deviation = average / 2（与 Go 一致）
    #[allow(clippy::field_reassign_with_default)] // 逐字段重置对齐 Go resetStats 表意
    pub fn statistics(&self, now_unix_nanos: i64) -> HealthPingStats {
        let mut stats = HealthPingStats::default();
        stats.max = 0;
        stats.min = RTT_FAILED;

        let mut sum: i64 = 0;
        let mut cnt: i64 = 0;
        let mut valid_rtts: Vec<i64> = Vec::new();

        for rtt in &self.rtts {
            if !self.initialized {
                // 未初始化时所有值是 RTT_UNTESTED
                continue;
            }
            // 跳过 untested
            if rtt.value == RTT_UNTESTED {
                continue;
            }
            // 跳过过期
            if now_unix_nanos - rtt.time > self.validity_nanos {
                continue;
            }
            // failed 计入 fail
            if rtt.value == RTT_FAILED {
                stats.fail += 1;
                continue;
            }
            // 正常有效值
            cnt += 1;
            sum = sum.saturating_add(rtt.value);
            valid_rtts.push(rtt.value);
            if stats.max < rtt.value {
                stats.max = rtt.value;
            }
            if stats.min > rtt.value {
                stats.min = rtt.value;
            }
        }

        stats.all = cnt + stats.fail;
        if cnt == 0 {
            stats.min = 0;
            return stats;
        }

        stats.average = sum / cnt;

        let std: f64 = if cnt < 2 {
            // 1 round tested: deviation = average / 2
            stats.average as f64 / 2.0
        } else {
            let mut variance: f64 = 0.0;
            for v in &valid_rtts {
                let diff = *v as f64 - stats.average as f64;
                variance += diff * diff;
            }
            (variance / cnt as f64).sqrt()
        };
        stats.deviation = std as i64;

        stats
    }

    /// 清空所有 RTT（重置为未初始化状态）。
    pub fn clear(&mut self) {
        self.rtts.clear();
        self.idx = 0;
        self.initialized = false;
    }

    /// 当前样本数（含 failed）。
    pub fn len(&self) -> usize {
        if self.initialized { self.cap } else { 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: i64 = 1_000_000_000; // 1s in nanos

    fn make_buf(cap: usize, validity_nanos: i64) -> HealthPingRtts {
        HealthPingRtts::new(cap, validity_nanos)
    }

    #[test]
    fn new_buf_is_empty() {
        let b = make_buf(5, 60_000_000_000);
        assert!(b.is_empty());
        assert_eq!(b.capacity(), 5);
    }

    #[test]
    fn put_one_makes_non_empty() {
        let mut b = make_buf(5, 60_000_000_000);
        b.put(VALID, 1000);
        assert!(!b.is_empty());
        assert_eq!(b.len(), 5); // cap
    }

    #[test]
    fn statistics_empty_returns_zeros() {
        let b = make_buf(5, 60_000_000_000);
        let s = b.statistics(2000);
        assert_eq!(s.all, 0);
        assert_eq!(s.fail, 0);
        assert_eq!(s.min, 0);
        assert_eq!(s.max, 0);
    }

    #[test]
    fn statistics_counts_untested_as_skip() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(VALID, 1000); // 1 valid; 2 untested
        let s = b.statistics(2000);
        assert_eq!(s.all, 1);
        assert_eq!(s.fail, 0);
        assert_eq!(s.average, VALID);
        assert_eq!(s.min, VALID);
        assert_eq!(s.max, VALID);
    }

    #[test]
    fn statistics_counts_failed_separately() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(VALID, 1000);
        b.put(RTT_FAILED, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.all, 2); // 1 valid + 1 fail
        assert_eq!(s.fail, 1);
        assert_eq!(s.average, VALID);
    }

    #[test]
    fn statistics_average_of_multiple() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(100, 1000);
        b.put(200, 1100);
        b.put(300, 1200);
        let s = b.statistics(2000);
        assert_eq!(s.all, 3);
        assert_eq!(s.average, (100 + 200 + 300) / 3);
        assert_eq!(s.min, 100);
        assert_eq!(s.max, 300);
    }

    #[test]
    fn statistics_skips_expired() {
        let mut b = make_buf(3, 1_000); // 1us validity
        b.put(100, 1000);
        b.put(200, 1100);
        b.put(300, 1200);
        // now 远超 validity：1000 应过期
        let s = b.statistics(10_000_000);
        // 1000 的过期（10000-1000=9000 > 1000），1100 过期，1200 过期
        assert_eq!(s.all, 0);
    }

    #[test]
    fn statistics_keeps_unexpired() {
        let mut b = make_buf(3, 1_000_000); // 1ms validity
        b.put(100, 1000);
        b.put(200, 1100);
        b.put(300, 1200);
        let s = b.statistics(1500); // 500 < 1_000_000
        assert_eq!(s.all, 3);
    }

    #[test]
    fn statistics_deviation_single_sample_half_of_avg() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(100, 1000);
        let s = b.statistics(2000);
        assert_eq!(s.deviation, 50); // 100/2
    }

    #[test]
    fn statistics_deviation_multiple_samples() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(100, 1000);
        b.put(200, 1100);
        b.put(300, 1200);
        let s = b.statistics(2000);
        // variance = ((100-200)^2 + 0 + (300-200)^2) / 3 = 20000/3 ≈ 6666.67
        // std ≈ 81.6
        assert!(s.deviation > 70 && s.deviation < 100);
    }

    #[test]
    fn ring_buffer_overwrites_oldest() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(10, 1000);
        b.put(20, 1100);
        b.put(30, 1200);
        b.put(40, 1300); // overwrite first (10)
        let s = b.statistics(2000);
        // 应该有 20, 30, 40 三个值
        assert_eq!(s.all, 3);
        assert_eq!(s.min, 20);
        assert_eq!(s.max, 40);
        assert_eq!(s.average, (20 + 30 + 40) / 3);
    }

    #[test]
    fn clear_resets_state() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(10, 1000);
        b.put(20, 1100);
        assert!(!b.is_empty());
        b.clear();
        assert!(b.is_empty());
        let s = b.statistics(2000);
        assert_eq!(s.all, 0);
    }

    #[test]
    fn put_after_clear_reinitializes() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(10, 1000);
        b.clear();
        b.put(20, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.all, 1);
        assert_eq!(s.average, 20);
    }

    #[test]
    fn failed_does_not_set_min() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(VALID, 1000);
        b.put(RTT_FAILED, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.fail, 1);
        assert_eq!(s.min, VALID);
    }

    #[test]
    fn failed_does_not_set_max() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(VALID, 1000);
        b.put(RTT_FAILED, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.max, VALID);
    }

    #[test]
    fn only_failed_returns_min_zero() {
        let mut b = make_buf(3, 60_000_000_000);
        b.put(RTT_FAILED, 1000);
        b.put(RTT_FAILED, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.all, 2);
        assert_eq!(s.fail, 2);
        assert_eq!(s.average, 0);
        assert_eq!(s.min, 0);
    }

    #[test]
    fn capacity_one_works() {
        let mut b = make_buf(1, 60_000_000_000);
        b.put(100, 1000);
        let s = b.statistics(2000);
        assert_eq!(s.all, 1);
        assert_eq!(s.average, 100);
        b.put(200, 1100);
        let s = b.statistics(2000);
        assert_eq!(s.average, 200);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // 存量清零批次：assertions_on_constants
    fn is_valid_rtt_helper() {
        assert!(50_i64 != RTT_UNTESTED && 50_i64 != RTT_FAILED);
        assert!(RTT_UNTESTED == RTT_UNTESTED);
        assert!(RTT_FAILED == RTT_FAILED);
    }

    #[test]
    fn len_returns_cap_after_init() {
        let mut b = make_buf(5, 60_000_000_000);
        assert_eq!(b.len(), 0);
        b.put(1, 1);
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn ping_rtt_eq() {
        let r1 = PingRtt { time: 1, value: 2 };
        let r2 = r1;
        assert_eq!(r1, r2);
    }
}
