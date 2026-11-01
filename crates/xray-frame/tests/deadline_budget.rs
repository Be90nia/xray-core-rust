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
    deadline::{Budget, BudgetSource, BudgetTimer},
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

// ===== BudgetTimer（timer-arm 面，bd 23vrp）：tuic/anytls 豁免迁移的测试面 =====

/// 虚拟推进精确触发：arm(1s) → 999ms 未触发 → +1ms 触发（走虚拟时间轴，
/// 非真实等待——start_paused 下真实耗时为 0）。
#[tokio::test(start_paused = true)]
async fn timer_arm_fires_exactly_at_virtual_deadline() {
    let mut t = Budget::tokio().arm_timer(Duration::from_secs(1));
    assert!(!t.is_expired(), "arm 即触发 = 假计时器");
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(!t.is_expired(), "999ms 未到不得触发");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(t.is_expired(), "满 1s 必须触发");
    // 触发态下 expired() 立即完成（不挂起、不重挂）。
    t.expired().await;
}

/// reset 重武装（tuic idle-reset 的直接语义证据）：600ms 活动包 → reset(1s)
/// → 自 reset 起**重新计时**，不是沿用旧锚点。
#[tokio::test(start_paused = true)]
async fn timer_arm_reset_re_arms_window() {
    let mut t = Budget::tokio().arm_timer(Duration::from_secs(1));
    tokio::time::advance(Duration::from_millis(600)).await;
    t.reset(Duration::from_secs(1));
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(!t.is_expired(), "reset 后 999ms 不得触发（窗口重新计时）");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(t.is_expired(), "reset 后满 1s 触发");
    t.expired().await;
}

/// select 竞争取消安全（tuic udp_assoc 的真实 select 形态）：expired 输掉
/// 竞争（future 被 drop）后，计时状态保留在 timer 本体——重进 select 不丢窗。
#[tokio::test(start_paused = true)]
async fn timer_arm_survives_select_race_cancellation() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(4);
    let mut idle = Budget::tokio().arm_timer(Duration::from_secs(1));
    tx.send(7).await.unwrap();
    tokio::select! {
        _ = idle.expired() => panic!("有活动包时不得触发"),
        item = rx.recv() => {
            assert_eq!(item, Some(7));
            idle.reset(Duration::from_secs(1));
        }
    }
    // 竞争输掉后窗口完整重来（若状态丢失，这里会在旧锚点误触发/永不触发）。
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(!idle.is_expired());
    tokio::time::advance(Duration::from_millis(1)).await;
    idle.expired().await;
}

/// 触发态 reset 重武装（tuic：触发的 select 臂与 reset 臂交错时——
/// `Sleep::reset` 契约：已触发态 reset 同样有效）。
#[tokio::test(start_paused = true)]
async fn timer_arm_reset_after_fire_re_arms() {
    let mut t = Budget::tokio().arm_timer(Duration::from_millis(100));
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(t.is_expired());
    t.reset(Duration::from_secs(1));
    assert!(!t.is_expired(), "触发态 reset 必须重新武装");
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(!t.is_expired());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(t.is_expired());
}

/// Wall 源：到期判定完全由 `Clock` 决定（冻结 → 永不触发；推进 → 触发），
/// 语义同 [`BudgetDeadline::timeout`] 的 wall 臂。
#[tokio::test]
async fn timer_arm_wall_source_follows_clock() {
    let clock = Arc::new(MockClock::new());
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let mut t: BudgetTimer = Budget::wall(dyn_clock).arm_timer(Duration::from_secs(60));
    // 冻结 → 真实 50ms 内不得触发（若误挂 tokio 计时器，这里会假触发）。
    tokio::time::timeout(Duration::from_millis(50), t.expired())
        .await
        .expect_err("冻结墙钟不得触发");
    clock.advance(Duration::from_secs(120));
    // 推进 → WALL_POLL_INTERVAL 轮询间隔内检出。
    tokio::time::timeout(Duration::from_millis(200), t.expired())
        .await
        .expect("墙钟推进后必须触发");
}
