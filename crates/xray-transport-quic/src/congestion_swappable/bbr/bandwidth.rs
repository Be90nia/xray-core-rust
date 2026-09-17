//! Bandwidth 类型（对应 Go `congestion/bbr/bandwidth.go`）。

use std::time::Duration;

use super::super::types::ByteCount;

/// "无穷大" 带宽（对应 Go `infBandwidth = Bandwidth(math.MaxUint64)`）。
pub const INF_BANDWIDTH: Bandwidth = Bandwidth(u64::MAX);

/// 带宽类型（对应 Go `type Bandwidth uint64`）。
///
/// 内部存储：每秒比特数（bits/s），与 Go 一致。
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bandwidth(pub u64);

impl Bandwidth {
    /// 1 bit/s（对应 Go `BitsPerSecond Bandwidth = 1`）。
    pub const BITS_PER_SECOND: Self = Self(1);
    /// 1 byte/s = 8 bits/s（对应 Go `BytesPerSecond = 8 * BitsPerSecond`）。
    pub const BYTES_PER_SECOND: Self = Self(8);

    /// 从字节数 + 时间 delta 计算带宽（对应 Go `BandwidthFromDelta`）。
    ///
    /// 返回 bits/s。公式：`bytes * sec / delta * BytesPerSecond`。
    #[must_use]
    pub fn from_delta(bytes: ByteCount, delta: Duration) -> Self {
        if delta.is_zero() {
            return INF_BANDWIDTH;
        }
        // ponytail: 用 u128 中间运算避免溢出。
        let bytes_u = bytes.max(0) as u64;
        let ns = delta.as_nanos() as u128;
        let sec_equiv = (bytes_u as u128 * 1_000_000_000) / ns;
        // bits/s = bytes/s * 8
        let bps = sec_equiv * (Self::BYTES_PER_SECOND.0 as u128);
        if bps > u64::MAX as u128 { INF_BANDWIDTH } else { Self(bps as u64) }
    }

    /// 原始值（bits/s）。
    #[must_use]
    pub fn bits_per_second(&self) -> u64 {
        self.0
    }

    /// 转 bytes/s（向下取整）。
    #[must_use]
    pub fn bytes_per_second(&self) -> u64 {
        self.0 / 8
    }
}

impl std::ops::Mul<u64> for Bandwidth {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self(self.0.saturating_mul(rhs))
    }
}

impl std::ops::Div<u64> for Bandwidth {
    type Output = Self;

    fn div(self, rhs: u64) -> Self {
        if rhs == 0 { INF_BANDWIDTH } else { Self(self.0 / rhs) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inf_bandwidth_is_max() {
        assert_eq!(INF_BANDWIDTH.0, u64::MAX);
    }

    #[test]
    fn units_match_go() {
        assert_eq!(Bandwidth::BITS_PER_SECOND.0, 1);
        assert_eq!(Bandwidth::BYTES_PER_SECOND.0, 8);
    }

    #[test]
    fn from_delta_basic() {
        // 1000 bytes in 1 sec → 8000 bits/s
        let bw = Bandwidth::from_delta(1000, Duration::from_secs(1));
        assert_eq!(bw.0, 8000);
    }

    #[test]
    fn from_delta_zero_returns_inf() {
        let bw = Bandwidth::from_delta(1000, Duration::ZERO);
        assert_eq!(bw, INF_BANDWIDTH);
    }

    #[test]
    fn from_delta_high_precision() {
        // 1500 bytes in 100ms → 15_000 bytes/s → 120_000 bits/s
        let bw = Bandwidth::from_delta(1500, Duration::from_millis(100));
        assert_eq!(bw.0, 120_000);
    }

    #[test]
    fn bytes_per_second_conversion() {
        let bw = Bandwidth(16_000); // 16_000 bits/s
        assert_eq!(bw.bytes_per_second(), 2000); // 2000 bytes/s
        assert_eq!(bw.bits_per_second(), 16_000);
    }

    #[test]
    fn mul_saturates() {
        let big = Bandwidth(u64::MAX - 1);
        let prod = big * 10;
        assert_eq!(prod.0, u64::MAX);
    }

    #[test]
    fn div_by_zero_returns_inf() {
        let bw = Bandwidth(1000);
        assert_eq!(bw / 0, INF_BANDWIDTH);
    }

    #[test]
    fn ordering() {
        assert!(Bandwidth(100) < Bandwidth(200));
        assert!(Bandwidth(200) > Bandwidth(100));
        assert_eq!(Bandwidth(100).cmp(&Bandwidth(100)), std::cmp::Ordering::Equal);
    }
}
