//! 通用重试策略，对应 Go `common/retry/retry.go`。
//!
//! Go `ExponentialBackoff` 名为指数实为线性：第 n 次失败后延迟 `n * base`
//! （0, d, 2d, 3d...），首次立即执行。成功立即返回；连续相同错误去重累积。
//!
//! 机制归属（bd cm2es，CLAUDE.md §3.5）：重试环（次数闸/裁决序/退避饱和/取消
//! 安全）消费 udf `std_ext::retry::retry_if_async` + `RetryPolicy`。
//!
//! 两处 Go 特有内容留本仓做派生薄壳：
//!
//! - 失败列表：udf `RetryError` 只回灌末次错误，Go `On()` 聚合去重全列表。
//!
//! - 首次零延迟：udf 自 attempt=1 起算，比 Go 多一档 base，睡前减回。

use std::{future::Future, time::Duration};

use std_ext::retry::{AsyncSleeper, RetryPolicy, retry_if_async};

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

/// Go 形异步睡眠口：udf 传入的 `d` 是政策退避值 `base * attempts`（attempt 自 1 起）。
///
/// Go 首次失败后延迟为零，故睡 `d - base` 还原 0, d, 2d 序列（逐次相等由
/// `delay_sequence_matches_go_table` 钉住）。
struct GoSleeper {
    base: Duration,
}

impl AsyncSleeper for GoSleeper {
    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(d.saturating_sub(self.base))
    }
}

/// 指数退避重试（对应 Go `retry.ExponentialBackoff(attempts, delay).On(f)`）。
///
/// - 首次立即执行；第 n 次失败（n 从 0 计）后延迟 `n * base_delay_ms` 再重试。
/// - 共执行 `attempts` 次；末次失败后不再延迟直接返回聚合错误 （Go 版末次失败后多 sleep
///   一次属实现浪费，不复制）。
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
    if attempts == 0 {
        return Err(RetryError { errors: Vec::new() });
    }
    let base = Duration::from_millis(base_delay_ms);
    // udf 政策构造期拒绝零 base：Go 零退避（base=0）改用 1ns base + max_delay=0
    // 截平表达，退避值恒零，语义不变。
    let policy = if base.is_zero() {
        RetryPolicy::new(attempts, Duration::from_nanos(1), Duration::ZERO)
    } else {
        RetryPolicy::new(attempts, base, Duration::MAX)
    }
    // 恒等抖动源=关 jitter：Go 退避确定性，时序须与改前逐次相等。
    .with_jitter(|d| d);

    // op 闭包侧边收集去重列表（&Mutex 是 Copy，可随每次调用的 future 借出，
    // 无需 Arc/分配）。udf 侧错误类型取 `()`——末次错误已进列表，不再回灌。
    let errors: parking_lot::Mutex<Vec<E>> = parking_lot::Mutex::new(Vec::new());
    let sink = &errors;
    let outcome = retry_if_async(
        &policy,
        |_attempt| {
            let fut = f();
            async move {
                match fut.await {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        let mut acc = sink.lock();
                        let dup = acc.last().is_some_and(|last| last.to_string() == e.to_string());
                        if !dup {
                            acc.push(e);
                        }
                        Err(())
                    },
                }
            }
        },
        GoSleeper { base },
        |_| true,
    )
    .await;

    match outcome {
        Ok(v) => Ok(v),
        Err(_) => Err(RetryError { errors: std::mem::take(&mut *errors.lock()) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 契约：`exponential_backoff(n, d, f)` 恰好调用 `f` n 次（Go
    /// `retry.ExponentialBackoff(5, 100)` 的调用次数语义）。平台无关，
    /// 是「拨号重试 5 次」的**唯一严格真源**——不要用 TCP accept 次数代理
    /// （macOS 上 accept 与 close 有竞态，实测 5 次尝试可能只出现 4 次 accept）。
    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_attempts_exactly_n_times() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let r = exponential_backoff(5, 100, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), &'static str>("boom")
        })
        .await;
        assert!(r.is_err(), "全失败必须返回错误");
        assert_eq!(calls.load(Ordering::SeqCst), 5, "必须恰好尝试 5 次");
    }

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

    /// 契约：完整退避序列等于 Go `ExponentialBackoff`——第 k 次失败后睡 `k * base`，
    /// 末次失败后不睡。机制改由 udf 政策驱动后此表是等价性真源（逐次相等，非近似）。
    #[tokio::test(start_paused = true)]
    async fn delay_sequence_matches_go_table() {
        for (attempts, base) in [(1u32, 100u64), (3, 200), (5, 1), (5, 100)] {
            let mut stamps: Vec<tokio::time::Instant> = Vec::new();
            let _ = exponential_backoff(attempts, base, || {
                stamps.push(tokio::time::Instant::now());
                std::future::ready(Err::<u32, _>("x".to_string()))
            })
            .await;
            let got: Vec<Duration> = stamps.windows(2).map(|w| w[1] - w[0]).collect();
            let want: Vec<Duration> = (0..attempts)
                .filter(|k| k + 1 < attempts)
                .map(|k| Duration::from_millis(u64::from(k) * base))
                .collect();
            assert_eq!(got, want, "attempts={attempts} base={base}");
        }
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

    /// 契约：失败列表 = Go `On()` 累积语义——只对**连续**相同错误去重，被不同错误
    /// 隔开的同错各自留一条（去重窗口是前一条，不是全历史）。
    #[tokio::test(start_paused = true)]
    async fn consecutive_dedup_keeps_full_list() {
        let mut n = 0;
        let err = exponential_backoff(4, 1, || {
            n += 1;
            let msg = match n {
                3 => "b",
                _ => "a",
            };
            std::future::ready(Err::<u32, _>(msg.to_string()))
        })
        .await
        .unwrap_err();
        assert_eq!(err.errors, vec!["a".to_string(), "b".to_string(), "a".to_string()]);
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
