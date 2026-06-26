//! RTT 估算（对应 Go `connection.go` 的 `RoundTripInfo`）。
//!
//! 实现 RFC 6298 SRTT/RTTVAR/RTO 算法，与 Go 字节级语义一致：
//!
//! - 首次：SRTT := RTT, RTTVAR := RTT/2
//! - 后续：RTTVAR := (3·RTTVAR + |SRTT−RTT|) / 4，SRTT := (7·SRTT + RTT) / 8
//! - SRTT 不低于 min_rtt（构造时传入，对应 Go `config.Tti`）
//! - RTO := SRTT + 4·RTTVAR（min_rtt < 4·RTTVAR 时）否则 SRTT + RTTVAR
//! - RTO 上限 10000ms
//! - 最终 RTO := RTO · 5 / 4（Go 中的乘 1.25 系数）

use parking_lot::RwLock;

/// RTT 估算器（线程安全）。
///
/// 对应 Go `RoundTripInfo struct { sync.RWMutex; ... }`。
/// Rust 端用 `RwLock` 替代 `sync.RWMutex`（parking_lot 版本，不返回 Result）。
#[derive(Debug)]
pub struct RoundTripInfo {
    inner: RwLock<RoundTripState>,
}

#[derive(Debug, Clone, Copy)]
struct RoundTripState {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: u32,
}

impl RoundTripInfo {
    /// 构造（对应 Go `&RoundTripInfo{ rto: 100, minRtt: config.Tti }`）。
    #[must_use]
    pub fn new(min_rtt: u32) -> Self {
        Self {
            inner: RwLock::new(RoundTripState {
                variation: 0,
                srtt: 0,
                rto: 100,
                min_rtt,
                updated_timestamp: 0,
            }),
        }
    }

    /// 对端 RTO 同步（对应 Go `UpdatePeerRTO`）。
    ///
    /// 仅在距上次更新 ≥ 3000ms 时接受新值（防 RTO 抖动）。
    pub fn update_peer_rto(&self, rto: u32, current: u32) {
        let mut state = self.inner.write();
        if current.wrapping_sub(state.updated_timestamp) < 3000 {
            return;
        }
        state.updated_timestamp = current;
        state.rto = rto;
    }

    /// 根据 RTT 样本更新估算（对应 Go `Update`）。
    ///
    /// `current` 是当前 elapsed 毫秒数（由 Connection 维护的 `Elapsed()`）。
    pub fn update(&self, rtt: u32, current: u32) {
        // Go: if rtt > 0x7FFFFFFF { return }
        if rtt > 0x7FFF_FFFF {
            return;
        }
        let mut state = self.inner.write();

        if state.srtt == 0 {
            state.srtt = rtt;
            state.variation = rtt / 2;
        } else {
            // delta := |srtt - rtt|（u32 wrap-safe）
            let delta = if state.srtt > rtt {
                state.srtt - rtt
            } else {
                rtt - state.srtt
            };
            state.variation = (3 * state.variation + delta) / 4;
            state.srtt = (7 * state.srtt + rtt) / 8;
            if state.srtt < state.min_rtt {
                state.srtt = state.min_rtt;
            }
        }

        let rto = if state.min_rtt < 4 * state.variation {
            state.srtt + 4 * state.variation
        } else {
            state.srtt + state.variation
        };

        let rto = if rto > 10000 { 10000 } else { rto };
        state.rto = rto * 5 / 4;
        state.updated_timestamp = current;
    }

    /// 当前 RTO（对应 Go `Timeout()`）。
    #[must_use]
    pub fn timeout(&self) -> u32 {
        self.inner.read().rto
    }

    /// SRTT（对应 Go `SmoothedTime()`）。
    #[must_use]
    pub fn smoothed_time(&self) -> u32 {
        self.inner.read().srtt
    }
}

impl Default for RoundTripInfo {
    fn default() -> Self {
        Self::new(50)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_has_rto_100() {
        let rtt = RoundTripInfo::new(50);
        assert_eq!(rtt.timeout(), 100);
        assert_eq!(rtt.smoothed_time(), 0);
    }

    #[test]
    fn first_sample_sets_srtt_and_half_variation() {
        let rtt = RoundTripInfo::new(50);
        rtt.update(200, 1000);
        assert_eq!(rtt.smoothed_time(), 200);
        // RTO := SRTT + 4·RTTVAR（min_rtt=50 < 4·100=400 → 是这个分支）
        // = 200 + 400 = 600 → 不超 10000 → ×5/4 = 750
        assert_eq!(rtt.timeout(), 750);
    }

    #[test]
    fn subsequent_samples_blend_via_rfc6298() {
        let rtt = RoundTripInfo::new(50);
        rtt.update(100, 1000);
        // SRTT=100, RTTVAR=50, RTO = 100 + 4·50 = 300 → ×5/4 = 375
        assert_eq!(rtt.smoothed_time(), 100);
        assert_eq!(rtt.timeout(), 375);

        rtt.update(120, 2000);
        // delta = |100 - 120| = 20
        // RTTVAR = (3·50 + 20)/4 = 170/4 = 42
        // SRTT = (7·100 + 120)/8 = 820/8 = 102
        // min_rtt=50 < 4·42=168 → RTO = 102 + 4·42 = 270 → ×5/4 = 337
        assert_eq!(rtt.smoothed_time(), 102);
        assert_eq!(rtt.timeout(), 337);
    }

    #[test]
    fn srtt_not_clamped_on_first_sample() {
        // Go 中 srtt 钳制只在 else 分支（非首次），首次直接赋 rtt
        let rtt = RoundTripInfo::new(50);
        rtt.update(10, 1000);
        assert_eq!(rtt.smoothed_time(), 10);
    }

    #[test]
    fn rto_capped_at_10000() {
        let rtt = RoundTripInfo::new(50);
        // 极大 RTT 样本触发的 RTO 计算会被夹到 10000
        rtt.update(9000, 1000);
        // SRTT=9000, RTTVAR=4500
        // min_rtt=50 < 4·4500=18000 → RTO = 9000 + 4·4500 = 27000 → 夹到 10000 → ×5/4 = 12500
        // 但 10000 是夹完后的，×5/4 = 12500（注意 Go 是先夹再乘）
        // Go 代码：
        //   if rto > 10000 { rto = 10000 }
        //   info.rto = rto * 5 / 4
        // 所以最终 12500
        assert_eq!(rtt.timeout(), 12500);
    }

    #[test]
    fn rtt_over_int_max_ignored() {
        let rtt = RoundTripInfo::new(50);
        let before = rtt.timeout();
        rtt.update(0x8000_0000, 1000); // > 0x7FFF_FFFF，应被忽略
        assert_eq!(rtt.timeout(), before);
    }

    #[test]
    fn update_peer_rto_first_call_throttled_within_3s_of_epoch() {
        // 初始 updatedTimestamp=0；current=1000 时 1000-0=1000 < 3000 → 被忽略
        let rtt = RoundTripInfo::new(50);
        rtt.update_peer_rto(500, 1000);
        assert_eq!(rtt.timeout(), 100); // 仍为初始 100
    }

    #[test]
    fn update_peer_rto_accepted_after_3s() {
        let rtt = RoundTripInfo::new(50);
        rtt.update_peer_rto(500, 5000); // 5000-0=5000 ≥ 3000 → 接受
        assert_eq!(rtt.timeout(), 500);

        rtt.update_peer_rto(800, 7000); // 7000-5000=2000 < 3000 → 拒绝
        assert_eq!(rtt.timeout(), 500);

        rtt.update_peer_rto(800, 8500); // 8500-5000=3500 ≥ 3000 → 接受
        assert_eq!(rtt.timeout(), 800);
    }

    #[test]
    fn update_peer_rto_wrap_safe() {
        let rtt = RoundTripInfo::new(50);
        // 让 updated_timestamp 接近 u32::MAX
        rtt.update_peer_rto(700, 4_000_000_000);
        assert_eq!(rtt.timeout(), 700);

        // 跨 wrap：current=10 表示 wrap 后
        rtt.update_peer_rto(900, 10);
        // wrapping_sub(10, 4_000_000_000) 应 ≥ 3000（已过 ~296M ms）
        assert_eq!(rtt.timeout(), 900);
    }
}
