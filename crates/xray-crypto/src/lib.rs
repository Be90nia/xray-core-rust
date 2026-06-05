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
    rng.fill(buf);

    let (lo, hi) = if from > to { (to, from) } else { (from, to) };

    // Full u8 range — no remapping needed
    if hi.wrapping_sub(lo) == 255 {
        return;
    }

    let range = hi - lo + 1;
    for byte in buf.iter_mut() {
        *byte = lo + *byte % range;
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
            assert!(
                (10..20).contains(&val),
                "rand_between(10, 20) = {val}, not in [10, 20)"
            );
        }
    }

    #[test]
    fn rand_between_swapped_bounds() {
        for _ in 0..1000 {
            let val = rand_between(20, 10);
            assert!(
                (10..20).contains(&val),
                "rand_between(20, 10) = {val}, not in [10, 20)"
            );
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
            assert!(
                (-50..50).contains(&val),
                "rand_between(-50, 50) = {val}, not in [-50, 50)"
            );
        }
    }

    #[test]
    fn rand_between_full_i64_range() {
        // Edge case: near i64 boundaries
        let val = rand_between(i64::MIN, i64::MIN + 10);
        assert!(
            (i64::MIN..i64::MIN + 10).contains(&val),
            "rand_between(MIN, MIN+10) = {val}"
        );
    }

    #[test]
    fn rand_bytes_between_all_in_range() {
        let mut buf = [0u8; 256];
        rand_bytes_between(&mut buf, 10, 20);
        for &b in &buf {
            assert!(
                (10..=20).contains(&b),
                "byte {b} not in [10, 20]"
            );
        }
    }

    #[test]
    fn rand_bytes_between_swapped_bounds() {
        let mut buf = [0u8; 128];
        rand_bytes_between(&mut buf, 20, 10);
        for &b in &buf {
            assert!(
                (10..=20).contains(&b),
                "byte {b} not in [10, 20]"
            );
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
}
