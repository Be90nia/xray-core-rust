#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! Cryptographic utilities for Xray-core.
//!
//! Provides random number generation functions ported from
//! Go's `common/crypto/crypto.go`, including bounded random
//! integers and bounded random byte filling.

pub mod aead;
pub mod auth_reader;
pub mod auth_writer;
pub mod authenticator;
pub mod chunk;
pub mod cryption_io;
pub mod key_cache;

use rand::Rng;

/// Error type for random number generation failures.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum RandomError {
    /// The RNG source failed to produce random bytes.
    #[error("RNG failed: {0}")]
    RngFailed(String),
}

/// Generates a cryptographically secure random `i64` in
/// the half-open range `[from, to)`.
///
/// When `from == to`, returns `from`. When `from > to`,
/// the bounds are swapped automatically (matching Go
/// behavior).
///
/// # Examples
///
/// ```
/// use xray_crypto::rand_between;
///
/// let val = rand_between(0, 100);
/// assert!(val >= 0 && val < 100);
/// ```
#[must_use]
pub fn rand_between(from: i64, to: i64) -> i64 {
    if from == to {
        return from;
    }
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };
    let mut rng = rand::rng();
    rng.random_range(lo..hi)
}

/// Fills the provided byte buffer with cryptographically
/// secure random bytes in the closed range `[from, to]`.
///
/// When `from > to`, the bounds are swapped automatically
/// (matching Go behavior). When `to - from == 255` (full
/// u8 range), the raw random bytes are used directly
/// without remapping for efficiency.
///
/// # Examples
///
/// ```
/// use xray_crypto::rand_bytes_between;
///
/// let mut buf = [0u8; 32];
/// rand_bytes_between(&mut buf, 10, 20);
/// for &b in &buf {
///     assert!(b >= 10 && b <= 20);
/// }
/// ```
pub fn rand_bytes_between(buf: &mut [u8], from: u8, to: u8) {
    let mut rng = rand::rng();
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };

    // Full u8 range — no remapping needed
    if hi.wrapping_sub(lo) == 255 {
        rng.fill(buf);
        return;
    }

    // P0-3（bd 6vqk）：rejection sampling（Menezes HAC §5.4.4，Go v26.9.9 同款）。
    // 此前 `lo + b % range` 有 modulo bias（b 均匀 [0,255]，range 不整除 256 时
    // 低位值概率偏高）。limit = 256 - 256%range 为最大完整倍数区——拒样重抽，
    // 重抽概率 <50%（range≥128 时为 0）。closed range 语义与 wire 均不变。
    let range = u16::from(hi - lo) + 1;
    let limit = 256u16 - (256 % range);
    for byte in buf.iter_mut() {
        loop {
            let mut sample = [0u8; 1];
            rng.fill(&mut sample);
            if u16::from(sample[0]) < limit {
                *byte = lo + (u16::from(sample[0]) % range) as u8;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_between_same_bounds_returns_value() {
        assert_eq!(rand_between(42, 42), 42);
        assert_eq!(rand_between(0, 0), 0);
        assert_eq!(rand_between(-7, -7), -7);
    }

    #[test]
    fn rand_between_result_in_range() {
        for _ in 0..1000 {
            let val = rand_between(10, 20);
            assert!((10..20).contains(&val), "rand_between(10, 20) = {val}, not in [10, 20)");
        }
    }

    #[test]
    fn rand_between_swapped_bounds() {
        for _ in 0..1000 {
            let val = rand_between(20, 10);
            assert!((10..20).contains(&val), "rand_between(20, 10) = {val}, not in [10, 20)");
        }
    }

    #[test]
    fn rand_between_negative_range() {
        for _ in 0..1000 {
            let val = rand_between(-100, -10);
            assert!(
                (-100..-10).contains(&val),
                "rand_between(-100, -10) = {val}, not in [-100, -10)"
            );
        }
    }

    #[test]
    fn rand_between_cross_zero_range() {
        for _ in 0..1000 {
            let val = rand_between(-50, 50);
            assert!((-50..50).contains(&val), "rand_between(-50, 50) = {val}, not in [-50, 50)");
        }
    }

    #[test]
    fn rand_between_full_i64_range() {
        // Edge case: near i64 boundaries
        let val = rand_between(i64::MIN, i64::MIN + 10);
        assert!((i64::MIN..i64::MIN + 10).contains(&val), "rand_between(MIN, MIN+10) = {val}");
    }

    #[test]
    fn rand_bytes_between_all_in_range() {
        let mut buf = [0u8; 256];
        rand_bytes_between(&mut buf, 10, 20);
        for &b in &buf {
            assert!((10..=20).contains(&b), "byte {b} not in [10, 20]");
        }
    }

    #[test]
    fn rand_bytes_between_swapped_bounds() {
        let mut buf = [0u8; 128];
        rand_bytes_between(&mut buf, 20, 10);
        for &b in &buf {
            assert!((10..=20).contains(&b), "byte {b} not in [10, 20]");
        }
    }

    #[test]
    fn rand_bytes_between_full_range_no_remap() {
        // When to - from == 255, raw bytes used directly
        let mut buf = [0u8; 1024];
        rand_bytes_between(&mut buf, 0, 255);
        // Just verify it doesn't panic and fills the buffer
        // (all u8 values are valid for full range)
        assert!(!buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn rand_bytes_between_single_value_range() {
        let mut buf = [0u8; 64];
        rand_bytes_between(&mut buf, 42, 42);
        for &b in &buf {
            assert_eq!(b, 42, "byte should always be 42");
        }
    }

    #[test]
    fn rand_bytes_between_empty_buffer() {
        let mut buf: [u8; 0] = [];
        // Should not panic on empty buffer
        rand_bytes_between(&mut buf, 0, 255);
    }

    #[test]
    fn rand_bytes_between_distribution() {
        // Statistical test: with enough samples, each value
        // in a small range should appear at least once
        let mut buf = [0u8; 10000];
        rand_bytes_between(&mut buf, 0, 4);
        let mut seen = [false; 5];
        for &b in &buf {
            seen[b as usize] = true;
        }
        for (i, &s) in seen.iter().enumerate() {
            assert!(s, "value {i} never appeared in 10000 samples");
        }
    }

    /// P0-3（bd 6vqk）：modulo bias 回归——range=200（256%200=56 旧实现偏差
    /// 区）下各值频次须均匀（±10%）。旧 `b % 200` 实现 [0,55] 概率是 [56,199]
    /// 的 2 倍，必挂此断言。
    #[test]
    fn rand_bytes_between_no_modulo_bias() {
        let range = 200usize;
        let mut freq = vec![0usize; range];
        let mut buf = [0u8; 200_000];
        rand_bytes_between(&mut buf, 0, 199);
        for &b in &buf {
            freq[b as usize] += 1;
        }
        let expect = buf.len() / range;
        for (v, &f) in freq.iter().enumerate() {
            let dev = f.abs_diff(expect);
            assert!(
                dev * 10 <= expect,
                "value {v} freq {f} deviates >10% from uniform {expect} (modulo bias?)"
            );
        }
    }
}
