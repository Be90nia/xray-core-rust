//! 面 3 验收（G2）：双源预算句柄 —— **tokio 虚拟推进语义未丢** + 墙钟源由
//! `Clock` 判定（冻结即不到期）。
//!
//! 判据：`#[tokio::test(start_paused = true)]` 下，`tokio::time::advance` 越过
//! 预算 → 预算**真判负**；且虚拟时钟只推进到预算点（`elapsed()` 精确 = 预算）
//! → 证明走的是虚拟时间轴而非真实时间。

use std::{sync::Arc, time::Duration};

use skeleton::clock::{Clock, MockClock};
use xray_frame::{
    PluginContext,
    deadline::{Budget, BudgetSource},
};

#[tokio::test(start_paused = true)]
async fn tokio_budget_expires_on_virtual_clock_advance() {
    let budget = Budget::tokio();
    let deadline = budget.deadline(Duration::from_secs(5));
    // 内层 future 永不完成（睡一小时的虚拟时间）→ 判负只能来自预算到期。
    let out = deadline.timeout(async { tokio::time::sleep(Duration::from_secs(3600)).await }).await;
    assert!(out.is_err(), "虚拟时钟越过预算 → 真判负（Elapsed）");
    // 虚拟时钟恰好停在预算点（tokio 暂停模式自动推进到最近的定时器）。
    assert_eq!(budget.elapsed(), Duration::from_secs(5), "虚拟时间只推进到预算点");
}

#[tokio::test(start_paused = true)]
async fn explicit_advance_triggers_budget_timeout() {
    let budget = Budget::tokio();
    let deadline = budget.deadline(Duration::from_secs(5));
    let fut = deadline.timeout(async { tokio::time::sleep(Duration::from_secs(3600)).await });
    let mut fut = std::pin::pin!(fut);

    // 未到期：手工 poll 一次 → 必须 Pending（预算未到不完成；证明判负来自预算
    // 而非内层 future）。
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    assert!(fut.as_mut().poll(&mut cx).is_pending(), "预算未到 → 未完成");

    // 显式推进越过预算 → 判负。
    tokio::time::advance(Duration::from_secs(6)).await;
    let out = fut.await;
    assert!(out.is_err(), "显式 advance 越过预算 → 真判负");
}

#[tokio::test(start_paused = true)]
async fn managed_scope_can_host_budget_task() {
    // 框架层自己的托管口（`PluginContext::spawn` 透传 `FxScope::spawn`）托管预算
    // 任务 —— 零裸 spawn（框架层自身示范合规：crate 级 clippy 禁令禁裸 spawn）。
    let ctx = PluginContext::for_plugin("budget_test");
    let budget = Budget::tokio();
    let deadline = budget.deadline(Duration::from_secs(5));
    let handle = ctx
        .spawn(async move {
            deadline.timeout(async { tokio::time::sleep(Duration::from_secs(3600)).await }).await
        })
        .expect("托管 spawn");
    tokio::time::advance(Duration::from_secs(6)).await;
    let joined = handle.join().await.expect("join");
    assert!(joined.is_err(), "托管任务内：虚拟推进越过预算 → 判负");
}

#[tokio::test(start_paused = true)]
async fn tokio_budget_not_expired_before_deadline() {
    let budget = Budget::tokio();
    let deadline = budget.deadline(Duration::from_secs(60));
    assert!(!deadline.is_expired(), "预算未到 → 未过期");
    assert_eq!(deadline.remaining(), Duration::from_secs(60), "剩余 = 预算");
    tokio::time::advance(Duration::from_secs(30)).await;
    assert!(!deadline.is_expired(), "推进一半 → 仍未过期");
    assert_eq!(deadline.remaining(), Duration::from_secs(30), "剩余随虚拟时钟递减");
    assert_eq!(budget.remaining(Duration::from_secs(60)), Duration::from_secs(30));
}

#[test]
fn wall_budget_follows_injected_clock() {
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let budget = Budget::wall(dyn_clock);
    assert!(matches!(budget.source(), BudgetSource::Wall(_)), "墙钟源");

    let deadline = budget.deadline(Duration::from_secs(10));
    assert!(!deadline.is_expired(), "未推进 → 未过期");
    assert_eq!(budget.elapsed(), Duration::ZERO, "冻结时钟 → 零耗时");

    clock.advance(Duration::from_secs(10));
    assert!(deadline.is_expired(), "推进越过预算 → 过期");
    assert_eq!(budget.elapsed(), Duration::from_secs(10), "耗时随 Clock 推进");
    assert_eq!(deadline.remaining(), Duration::ZERO, "过期后剩余 = 0");
}

#[tokio::test]
async fn wall_budget_stays_unexpired_while_clock_frozen() {
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let budget = Budget::wall(dyn_clock);
    let deadline = budget.deadline(Duration::from_millis(50));

    // 冻结时钟 + 真实时间流逝 → 预算**不**判负（到期判定完全由 Clock 决定）。
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!deadline.is_expired(), "冻结时钟 → 永不到期");

    // 推进时钟 → 判负（墙钟源可被 MockClock 推进触发）。
    clock.advance(Duration::from_millis(50));
    let out = deadline.timeout(async { std::future::pending::<()>().await }).await;
    assert!(out.is_err(), "推进越过截止点 → 判负");
}
