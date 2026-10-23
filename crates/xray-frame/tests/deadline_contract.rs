//! P1-4 deadline 件契约验收（任务书五例 + 默认档/guard 接线冒烟）：
//! ①期限内 Ok ②真超时 Err(Elapsed)（10ms 真钟，断言不放宽）
//! ③外部取消传播（经 FxScope 的 cancel 面）④虚拟时钟零真实等待（<100ms）
//! ⑤构造零值 fail-fast panic（catch_unwind 断言）。

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use skeleton::clock::{Clock, SystemClock};
use skeleton_infra::fx::cancel_pair;
use tokio::time::error::Elapsed;
use xray_frame::deadline::{HandshakeDeadline, IdleDeadline, with_deadline};

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// ① 期限内完成 → Ok。
#[tokio::test]
async fn completes_within_deadline_is_ok() {
    let r = with_deadline(clock(), async { 21 * 2 }, Duration::from_secs(5)).await;
    assert_eq!(r.expect("期限内必 Ok"), 42);
}

/// ② 真超时 → Err(Elapsed)：10ms deadline + 永不完成的任务，断言不放宽。
#[tokio::test]
async fn real_timeout_is_elapsed_err() {
    let r: Result<(), Elapsed> =
        with_deadline(clock(), std::future::pending(), Duration::from_millis(10)).await;
    assert!(r.is_err(), "10ms deadline 必须真超时");
}

/// ③ 外部取消传播：取消错误原样穿出，不被改写成 Elapsed。
#[tokio::test]
async fn external_cancel_propagates_not_elapsed() {
    let (source, token) = cancel_pair();
    source.cancel();
    let fut = async move {
        token.cancelled().await;
        Err::<(), _>("scope-cancelled")
    };
    let r = with_deadline(clock(), fut, Duration::from_secs(5)).await;
    assert_eq!(r.expect("取消先于超时，deadline 不误伤"), Err("scope-cancelled"));
}

/// ④ 零真实等待：短 deadline（1ms）+ 永不完成的任务，墙钟 <100ms
/// （tokio `full` 不含 test-util，虚拟时钟不可用——走契约验收的「短 deadline」分支）。
#[tokio::test]
async fn short_deadline_timeout_costs_no_real_waiting() {
    let t0 = Instant::now();
    let r: Result<(), Elapsed> =
        with_deadline(clock(), std::future::pending(), Duration::from_millis(1)).await;
    assert!(r.is_err(), "1ms deadline 应判负");
    assert!(t0.elapsed() < Duration::from_millis(100), "零真实等待（实测 {:?}）", t0.elapsed());
}

/// ⑤ 构造零值 fail-fast：任一时限为 0 → panic（catch_unwind 断言）。
#[test]
fn zero_limits_are_fail_fast_panics() {
    assert!(
        std::panic::catch_unwind(|| HandshakeDeadline::new(Duration::ZERO, Duration::from_secs(5)))
            .is_err(),
        "limit=0 必须 panic"
    );
    assert!(
        std::panic::catch_unwind(|| HandshakeDeadline::new(Duration::from_secs(5), Duration::ZERO))
            .is_err(),
        "idle_limit=0 必须 panic"
    );
    assert!(
        std::panic::catch_unwind(|| IdleDeadline::new(Duration::ZERO)).is_err(),
        "IdleDeadline limit=0 必须 panic"
    );
    // 正常构造不受影响。
    let _ = HandshakeDeadline::new(Duration::from_secs(1), Duration::from_secs(2));
}

/// 默认档：5s（PM 拍板 2026-10-23：与停机超时同档减少魔数）。
#[test]
fn default_handshake_deadline_is_five_seconds() {
    let hd = HandshakeDeadline::default();
    assert_eq!(hd.limit, Duration::from_secs(5));
    assert_eq!(hd.idle_limit, Duration::from_secs(5));
}

/// guard 接线冒烟：HandshakeDeadline 按总时限判负；IdleDeadline 期限内放行。
#[tokio::test]
async fn guards_wire_through_with_deadline() {
    let hd = HandshakeDeadline::new(Duration::from_millis(1), Duration::from_secs(5));
    let r: Result<(), Elapsed> = hd.guard(clock(), std::future::pending()).await;
    assert!(r.is_err(), "handshake guard 应按总时限判负");
    let idle = IdleDeadline::new(Duration::from_secs(5));
    let r = idle.guard(clock(), async { "progress" }).await;
    assert_eq!(r.expect("期限内必 Ok"), "progress");
}
