//! 通用重试策略，对应 Go `common/retry/retry.go`。
//!
//! Go `ExponentialBackoff` 名为指数实为线性：第 n 次失败后延迟 `n * base`
//! （0, d, 2d, 3d...），首次立即执行。成功立即返回；连续相同错误去重累积。

use std::future::Future;
use std::time::Duration;

/// 全部重试失败后的聚合错误（对应 Go `ErrRetryFailed` + accumulated errors）。
#[derive(Debug)]
pub struct RetryError<E> {
    /// 连续去重后的失败列表。
    pub errors: Vec<E>,
}

impl<E: std::fmt::Display> std::fmt::Display for RetryError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "all retry attempts failed")?;
        for e in &self.errors {
            write!(f, " | {e}")?;
        }
        Ok(())
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for RetryError<E> {}

/// 指数退避重试（对应 Go `retry.ExponentialBackoff(attempts, delay).On(f)`）。
///
/// - 首次立即执行；第 n 次失败（n 从 0 计）后延迟 `n * base_delay_ms` 再重试。
/// - 共执行 `attempts` 次；末次失败后不再延迟直接返回聚合错误
///   （Go 版末次失败后多 sleep 一次属实现浪费，不复制）。
/// - 连续相同的错误消息只累积一条（Go `On()` 同款去重）。
///
/// # Errors
/// 全部尝试失败时返回 [`RetryError`]，含去重后的错误列表。
pub async fn exponential_backoff<T, E, F, Fut>(
    attempts: u32,
    base_delay_ms: u64,
    mut f: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut errors: Vec<E> = Vec::new();
    for attempt in 0..attempts {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                let dup = errors.last().is_some_and(|last| last.to_string() == e.to_string());
                if !dup {
                    errors.push(e);
                }
                if attempt + 1 < attempts {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt) * base_delay_ms))
                        .await;
                }
            }
        }
    }
    Err(RetryError { errors })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn succeeds_first_attempt_without_retry() {
        let mut calls = 0;
        let v = exponential_backoff(5, 100, || {
            calls += 1;
            std::future::ready(Ok::<u32, String>(42))
        })
        .await
        .unwrap();
        assert_eq!((v, calls), (42, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn fails_after_exact_attempts_with_dedup() {
        let mut calls = 0;
        let err = exponential_backoff(5, 100, || {
            calls += 1;
            std::future::ready(Err::<u32, _>("boom".to_string()))
        })
        .await
        .unwrap_err();
        assert_eq!(calls, 5);
        assert_eq!(err.errors.len(), 1, "连续相同错误去重为一条");
        let msg = err.to_string();
        assert!(msg.contains("all retry attempts failed"), "{msg}");
        assert!(msg.contains("boom"), "{msg}");
    }

    #[tokio::test(start_paused = true)]
    async fn succeeds_on_third_attempt() {
        let mut calls = 0;
        let v = exponential_backoff(5, 100, || {
            calls += 1;
            if calls < 3 {
                std::future::ready(Err::<u32, _>("fail".to_string()))
            } else {
                std::future::ready(Ok(calls))
            }
        })
        .await
        .unwrap();
        assert_eq!((v, calls), (3, 3));
    }

    #[tokio::test(start_paused = true)]
    async fn delays_linear_first_immediate() {
        // Go 语义：尝试间延迟 0, d, 2d, 3d（线性，非 ×2）；首次不延迟。
        let mut stamps: Vec<tokio::time::Instant> = Vec::new();
        let _ = exponential_backoff(5, 100, || {
            stamps.push(tokio::time::Instant::now());
            std::future::ready(Err::<u32, _>("x".to_string()))
        })
        .await;
        assert_eq!(stamps.len(), 5);
        assert_eq!(stamps[1] - stamps[0], Duration::from_millis(0));
        assert_eq!(stamps[2] - stamps[1], Duration::from_millis(100));
        assert_eq!(stamps[3] - stamps[2], Duration::from_millis(200));
        assert_eq!(stamps[4] - stamps[3], Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn distinct_consecutive_errors_accumulate() {
        let mut n = 0;
        let err = exponential_backoff(3, 1, || {
            n += 1;
            std::future::ready(Err::<u32, _>(format!("e{n}")))
        })
        .await
        .unwrap_err();
        assert_eq!(err.errors, vec!["e1".to_string(), "e2".to_string(), "e3".to_string()]);
    }

    #[tokio::test]
    async fn zero_attempts_returns_immediately() {
        let mut calls = 0;
        let err = exponential_backoff(0, 100, || {
            calls += 1;
            std::future::ready(Err::<u32, _>("x".to_string()))
        })
        .await
        .unwrap_err();
        assert_eq!(calls, 0);
        assert!(err.errors.is_empty());
    }
}
