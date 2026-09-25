//! 重试策略和执行逻辑
//!
//! 对应 Go 版本 `common/retry` 包，提供可配置的重试策略。

use std::{future::Future, time::Duration};

/// 重试策略 trait，定义如何计算下次重试间隔。
pub trait Strategy: Send + Sync {
    /// 根据当前重试次数计算下次间隔。
    fn next_interval(&self, attempt: u32) -> Duration;
}

/// 固定间隔重试策略。
pub struct Timed {
    /// 重试间隔。
    pub interval: Duration,
    /// 最大重试次数（0 表示无限制）。
    pub max_attempts: u32,
}

impl Strategy for Timed {
    fn next_interval(&self, _attempt: u32) -> Duration {
        self.interval
    }
}

/// 指数退避重试策略。
pub struct ExponentialBackoff {
    /// 初始间隔。
    pub initial: Duration,
    /// 乘数因子。
    pub multiplier: f64,
    /// 最大间隔上限。
    pub max_interval: Duration,
}

impl Strategy for ExponentialBackoff {
    fn next_interval(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.powi(attempt as i32);
        let interval_micros = self.initial.as_micros() as f64 * factor;
        let capped = interval_micros.min(self.max_interval.as_micros() as f64);
        Duration::from_micros(capped as u64)
    }
}

/// 使用指定策略执行异步重试。
///
/// 如果 `f` 返回 `Err`，则按策略等待后重试，直到成功。
/// 调用方应在闭包中自行跟踪重试次数并决定何时放弃。
pub async fn retry<F, Fut, T, E>(strategy: &dyn Strategy, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut attempt: u32 = 0;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                let interval = strategy.next_interval(attempt);
                attempt += 1;
                if interval.is_zero() {
                    return Err(e);
                }
                tokio::time::sleep(interval).await;
            },
        }
    }
}

/// 带最大重试次数的异步重试。
///
/// 总尝试次数为 `max_attempts`（含首次），超过后返回最后一次错误。
pub async fn retry_timed<F, Fut, T, E>(
    interval: Duration,
    max_attempts: u32,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last_err = None;
    for _ in 0..max_attempts {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                last_err = Some(e);
                if !interval.is_zero() {
                    tokio::time::sleep(interval).await;
                }
            },
        }
    }
    Err(last_err.expect("max_attempts > 0 guarantees at least one error"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timed_strategy() {
        let strategy = Timed { interval: Duration::from_millis(100), max_attempts: 3 };
        assert_eq!(strategy.next_interval(0), Duration::from_millis(100));
        assert_eq!(strategy.next_interval(5), Duration::from_millis(100));
    }

    #[test]
    fn test_exponential_backoff() {
        let strategy = ExponentialBackoff {
            initial: Duration::from_millis(100),
            multiplier: 2.0,
            max_interval: Duration::from_secs(10),
        };
        assert_eq!(strategy.next_interval(0), Duration::from_micros(100_000));
        assert_eq!(strategy.next_interval(1), Duration::from_micros(200_000));
        assert_eq!(strategy.next_interval(2), Duration::from_micros(400_000));
    }

    #[test]
    fn test_exponential_backoff_capped() {
        let strategy = ExponentialBackoff {
            initial: Duration::from_millis(100),
            multiplier: 10.0,
            max_interval: Duration::from_secs(1),
        };
        let interval = strategy.next_interval(10);
        assert!(interval <= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_retry_success_immediately() {
        let strategy = Timed { interval: Duration::from_millis(10), max_attempts: 3 };
        let result = retry(&strategy, || async { Ok::<i32, &str>(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_retry_timed_success() {
        let mut count = 0u32;
        let result = retry_timed(Duration::from_millis(1), 3, || {
            count += 1;
            async move { if count < 3 { Err("not yet") } else { Ok(99) } }
        })
        .await;
        assert_eq!(result, Ok(99));
    }

    #[tokio::test]
    async fn test_retry_timed_exhausted() {
        let result = retry_timed::<_, _, i32, &str>(Duration::from_millis(1), 2, || async {
            Err("always fail")
        })
        .await;
        assert_eq!(result, Err("always fail"));
    }
}
