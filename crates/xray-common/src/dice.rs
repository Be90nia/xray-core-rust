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
        Self {
            next: if seed == 0 { 1 } else { seed },
        }
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
            let val = dice.roll_uint16();
            assert!(val <= u16::MAX);
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
}
