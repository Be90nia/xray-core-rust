//! 确定性骰子随机选择工具
//!
//! 对应 Go 版本 `common/dice` 包，提供可设置种子的确定性随机数生成器。
//! 使用 xorshift64 算法实现，保证相同种子产生相同序列。

use rand::Rng;

/// 确定性骰子，基于 xorshift64 算法。
///
/// 可通过种子值进行确定性重现，也可使用随机种子。
pub struct DeterministicDice {
    next: u64,
}

impl DeterministicDice {
    /// 使用随机种子创建骰子。
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let seed = rng.random::<u64>();
        Self::with_seed(seed)
    }

    /// 使用指定种子创建骰子。
    ///
    /// 种子为 0 时自动替换为 1（xorshift 不允许 0 状态）。
    pub fn with_seed(seed: u64) -> Self {
        Self { next: if seed == 0 { 1 } else { seed } }
    }

    /// 生成下一个随机 u64 值。
    pub fn roll(&mut self) -> u64 {
        // xorshift64 算法
        let mut x = self.next;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.next = x;
        x
    }

    /// 生成 [0, n) 范围内的随机 i64 值。
    ///
    /// n 必须大于 0，否则返回 0。
    pub fn roll_int63n(&mut self, n: i64) -> i64 {
        if n <= 0 {
            return 0;
        }
        let val = self.roll();
        // 取高 63 位确保非负，然后对 n 取模
        ((val >> 1) as i64) % n
    }

    /// 生成随机 u16 值。
    pub fn roll_uint16(&mut self) -> u16 {
        (self.roll() & 0xFFFF) as u16
    }

    /// 生成随机 u64 值。
    pub fn roll_uint64(&mut self) -> u64 {
        self.roll()
    }
}

impl Default for DeterministicDice {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成 [0, n) 范围内的随机 i64。
///
/// 对应 Go `dice.RollInt63n(n int64) int64`（n 为 0 或 1 时短路返回 0）。
/// 使用全局线程本地 RNG（与 Go `math/rand` 全局默认源对齐）。
pub fn roll_int63n(n: i64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let mut rng = rand::rng();
    rng.random_range(0..n)
}

/// 生成 [0, n) 范围内的随机整数。
///
/// 对应 Go `dice.Roll(n int) int`（n 为 0 或 1 时短路返回 0）。
pub fn roll(n: i64) -> i64 {
    roll_int63n(n)
}

/// 使用固定种子生成 [0, n) 范围内的随机整数。
///
/// 对应 Go `dice.RollDeterministic(n int, seed int64) int`。
pub fn roll_deterministic(n: i64, seed: u64) -> i64 {
    if n <= 1 {
        return 0;
    }
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    rng.random_range(0..n)
}

/// 生成随机 u16 值。
///
/// 对应 Go `dice.RollUint16() uint16`。
pub fn roll_uint16() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(0..=u16::MAX as i64) as u16
}

/// 生成随机 u64 值。
///
/// 对应 Go `dice.RollUint64() uint64`。
pub fn roll_uint64() -> u64 {
    let mut rng = rand::rng();
    rng.random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_seed() {
        let mut dice1 = DeterministicDice::with_seed(42);
        let mut dice2 = DeterministicDice::with_seed(42);
        for _ in 0..10 {
            assert_eq!(dice1.roll(), dice2.roll());
        }
    }

    #[test]
    fn test_different_seeds() {
        let mut dice1 = DeterministicDice::with_seed(1);
        let mut dice2 = DeterministicDice::with_seed(2);
        let v1 = dice1.roll();
        let v2 = dice2.roll();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_zero_seed_normalized() {
        let mut dice = DeterministicDice::with_seed(0);
        // 不应 panic，种子 0 被规范化为 1
        let val = dice.roll();
        assert_ne!(val, 0);
    }

    #[test]
    fn test_roll_int63n_range() {
        let mut dice = DeterministicDice::with_seed(123);
        for _ in 0..100 {
            let val = dice.roll_int63n(10);
            assert!((0..10).contains(&val));
        }
    }

    #[test]
    fn test_roll_int63n_zero_n() {
        let mut dice = DeterministicDice::with_seed(123);
        assert_eq!(dice.roll_int63n(0), 0);
        assert_eq!(dice.roll_int63n(-1), 0);
    }

    #[test]
    fn test_roll_uint16_range() {
        let mut dice = DeterministicDice::with_seed(456);
        for _ in 0..100 {
            // 返回值恒为 u16（<= u16::MAX 恒真），仅验证可调用。
            let _: u16 = dice.roll_uint16();
        }
    }

    #[test]
    fn test_roll_uint64() {
        let mut dice = DeterministicDice::with_seed(789);
        let val = dice.roll_uint64();
        assert_ne!(val, 0); // 种子非零时首次 roll 不应为 0
    }

    #[test]
    fn test_default() {
        let _dice = DeterministicDice::default();
    }

    #[test]
    fn test_roll_zero() {
        // n=0 或 n=1 时按 Go 语义返回 0。
        assert_eq!(roll(0), 0);
    }

    #[test]
    fn test_roll_one() {
        // n=1 时按 Go 语义返回 0（rand.Intn(1) == 0，但显式短路避免依赖）。
        assert_eq!(roll(1), 0);
    }

    #[test]
    fn test_roll_range() {
        for _ in 0..200 {
            let v = roll(10);
            assert!((0..10).contains(&v), "roll(10) out of range: {v}");
        }
    }

    #[test]
    fn test_roll_int63n_zero() {
        assert_eq!(roll_int63n(0), 0);
        assert_eq!(roll_int63n(1), 0);
    }
    #[test]
    fn test_free_roll_int63n_range() {
        for _ in 0..200 {
            let v = roll_int63n(100);
            assert!((0..100).contains(&v), "roll_int63n(100) out of range: {v}");
        }
    }

    #[test]
    fn test_roll_deterministic_range() {
        for _ in 0..200 {
            let v = roll_deterministic(7, 12345);
            assert!((0..7).contains(&v), "roll_deterministic out of range: {v}");
        }
    }

    #[test]
    fn test_roll_deterministic_one() {
        // n=1 短路返回 0。
        assert_eq!(roll_deterministic(1, 42), 0);
        assert_eq!(roll_deterministic(0, 42), 0);
    }

    #[test]
    fn test_roll_deterministic_zero_n_zero_seed() {
        // seed=0 在 Go 是合法的（rand.NewSource(0) 有效）。
        let v = roll_deterministic(100, 0);
        assert!((0..100).contains(&v));
    }

    #[test]
    fn test_free_roll_uint16_range() {
        for _ in 0..200 {
            // 返回值恒为 u16（<= u16::MAX 恒真），仅验证可调用。
            let _: u16 = roll_uint16();
        }
    }

    #[test]
    fn test_roll_uint64_range() {
        // 不验证具体值，只保证函数可调用且返回 u64。
        let _: u64 = roll_uint64();
    }
}
