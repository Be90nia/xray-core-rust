//! 协议时间戳类型
//!
//! 对应 Go 版本 `common/protocol/time.go`。
//! Go 基准注：`Timestamp`/`NowTime`/`NewTimestampGenerator` 在 Go v26.6.1
//! 代码库中除自身测试外无其他消费方，属兼容性 API，此处按接口面对齐移植。

use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};

/// 协议时间戳（Unix 秒）。
///
/// 对应 Go 版本的 `type Timestamp int64`。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// 当前系统时间。
    ///
    /// 对应 Go 版本的 `NowTime()`。
    #[must_use]
    pub fn now() -> Self {
        now_time()
    }

    /// 时间戳的 Unix 秒值。
    #[must_use]
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl From<i64> for Timestamp {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 当前系统时间（Unix 秒）。
///
/// 对应 Go 版本的 `NowTime()`。
#[must_use]
pub fn now_time() -> Timestamp {
    Timestamp(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0))
}

/// 时间戳生成器。
///
/// 对应 Go 版本的 `type TimestampGenerator func() Timestamp`。
pub type TimestampGenerator = Box<dyn Fn() -> Timestamp + Send + Sync>;

/// 创建基于 `base`、抖动范围为 `[-delta, delta]` 的时间戳生成器。
///
/// 对应 Go 版本的 `NewTimestampGenerator(base, delta)`：
/// 内部等价于 `dice.Roll(delta*2) - delta`，即 `[0, 2*delta)` 均匀分布再平移。
/// `delta <= 0` 时恒返回 `base`。
#[must_use]
pub fn new_timestamp_generator(base: Timestamp, delta: i64) -> TimestampGenerator {
    let base = base.0;
    if delta <= 0 {
        Box::new(move || Timestamp(base))
    } else {
        Box::new(move || {
            let range_in_delta = rand::rng().random_range(0..delta * 2) - delta;
            Timestamp(base + range_in_delta)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_time_near_system_clock() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64;
        let ts = now_time().as_i64();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64;
        assert!(ts >= before && ts <= after, "now_time {ts} outside [{before},{after}]");
    }

    /// 镜像 Go `time_test.go TestGenerateRandomInt64InRange`：
    /// 100 次采样全部落在 `[base-delta, base+delta]`。
    #[test]
    fn test_generate_random_int64_in_range() {
        let base = now_time().as_i64();
        let delta = 100_i64;
        let generator = new_timestamp_generator(Timestamp(base), delta);

        for _ in 0..100 {
            let val = generator().as_i64();
            assert!(
                val <= base + delta && val >= base - delta,
                "{val} not between {} and {}",
                base - delta,
                base + delta
            );
        }
    }

    #[test]
    fn test_generator_zero_delta_is_constant() {
        let generator = new_timestamp_generator(Timestamp(1_000), 0);
        for _ in 0..10 {
            assert_eq!(generator().as_i64(), 1_000);
        }
    }

    #[test]
    fn test_timestamp_traits() {
        let a = Timestamp::from(42);
        assert_eq!(a.as_i64(), 42);
        assert_eq!(a.to_string(), "42");
        assert_eq!(Timestamp::default(), Timestamp(0));
        assert!(Timestamp(1) > Timestamp(0));
        // serde roundtrip
        let json = serde_json::to_string(&a).expect("serialize");
        assert_eq!(serde_json::from_str::<Timestamp>(&json).expect("deserialize"), a);
    }
}
