//! Burst observer 子模块：HealthPingSettings + RTT 环形缓冲 + statistics。
//!
//! 对应 Go `app/observatory/burst/`：
//! - `burst.rs` RTT 哨兵常量
//! - `healthping_result.go` HealthPingRTTS / HealthPingStats / 统计算法
//! - `healthping.go` HealthPingSettings 校验

pub mod burst_observer;
pub mod healthping_settings;
pub mod healthping_stats;

pub use burst_observer::BurstObserver;
pub use healthping_settings::{HealthPingConfig, HealthPingSettings};
pub use healthping_stats::{HealthPingRtts, HealthPingStats, PingRtt};

/// RTT 哨兵值：探测失败（对应 Go `rttFailed = math.MaxInt64 - 0`）。
pub const RTT_FAILED: i64 = i64::MAX - 0;

/// RTT 哨兵值：未测试（对应 Go `rttUntested = math.MaxInt64 - 1`）。
pub const RTT_UNTESTED: i64 = i64::MAX - 1;

/// RTT 哨兵值：不符合资格（对应 Go `rttUnqualified = math.MaxInt64 - 2`）。
pub const RTT_UNQUALIFIED: i64 = i64::MAX - 2;

/// 判断 RTT 是否是有效（非哨兵）值。
pub fn is_valid_rtt(rtt: i64) -> bool {
    rtt != RTT_FAILED && rtt != RTT_UNTESTED && rtt != RTT_UNQUALIFIED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_values_distinct() {
        assert_ne!(RTT_FAILED, RTT_UNTESTED);
        assert_ne!(RTT_UNTESTED, RTT_UNQUALIFIED);
        assert_ne!(RTT_FAILED, RTT_UNQUALIFIED);
    }

    #[test]
    fn rtt_failed_is_max() {
        assert_eq!(RTT_FAILED, i64::MAX);
    }

    #[test]
    fn rtt_untested_one_below_max() {
        assert_eq!(RTT_UNTESTED, i64::MAX - 1);
    }

    #[test]
    fn rtt_unqualified_two_below_max() {
        assert_eq!(RTT_UNQUALIFIED, i64::MAX - 2);
    }

    #[test]
    fn is_valid_rtt_for_normal_value() {
        assert!(is_valid_rtt(50));
        assert!(is_valid_rtt(0));
        assert!(is_valid_rtt(1_000_000));
    }

    #[test]
    fn is_valid_rtt_for_sentinels() {
        assert!(!is_valid_rtt(RTT_FAILED));
        assert!(!is_valid_rtt(RTT_UNTESTED));
        assert!(!is_valid_rtt(RTT_UNQUALIFIED));
    }
}
