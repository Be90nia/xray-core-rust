//! 面 2 验收（G3）：进程级能力入口 —— 一次性安装 fail-visible + 作用域守卫
//! 还原 + 兜底语义 = SystemClock。
//!
//! **测试隔离纪律**（方案 §2 面 2 "测试隔离"表）：进程级单槽禁被并行测试改写。
//! 本文件的全局面用例（install 断言 + spawn 用例）用**作用域守卫互斥**串行化：
//! - `install_is_one_shot_and_fail_visible`：持一把作用域安装（占住全局互斥 →
//!   并发作用域安装被串行化），期间只断言**永久槽**（`installed_caps()`）。
//! - `scoped_install_shadows_and_is_dropped`：作用域安装优先；守卫 drop 后
//!   作用域那份**不再可见**（与永久槽/兜底是谁无关 → 与并发时序无关）。
//! - `process_scope_spawn_is_managed` / `process_scope_spawn_reaps_completed_entries`： 守卫持到
//!   join/断言完——窗口内 spawn 的任务归本用例装的 scope，且守卫期间 并发作用域安装被串行化（spawn
//!   窗口内零外来 compat::spawn 调用）。

// 时钟禁令只约束生产路径；集成测试为独立编译单元，lib.rs 的 cfg_attr(test) 豁免不覆盖，
// 文件顶显式豁免（惯例同 xray-app-router/tests/router_parallel_build.rs）。
#![allow(clippy::disallowed_methods)]

use std::{
    sync::{Arc, LazyLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use skeleton::clock::Clock;
use skeleton_infra::fx::{FxScope, TaskError};
use xray_frame::{
    compat::{CompatAlreadyInstalled, CompatCaps, caps, install, install_scoped, installed_caps},
    logging::LogFacade,
};

/// 固定读数的测试时钟（挂钟面 = UNIX_EPOCH → 与系统钟可区分）。
struct FixedClock;

impl Clock for FixedClock {
    fn now_instant(&self) -> Instant {
        static ANCHOR: LazyLock<Instant> = LazyLock::new(Instant::now);
        *ANCHOR
    }

    fn now_system(&self) -> SystemTime {
        UNIX_EPOCH
    }
}

/// 带固定时钟的能力集（每次调用 = 新的时钟实例 → 指针可区分）。
fn caps_with_fixed_clock() -> (Arc<dyn Clock>, CompatCaps) {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock);
    let caps = CompatCaps::new(
        Arc::clone(&clock),
        Arc::new(FxScope::new()),
        LogFacade::new("compat_test", Vec::new()),
    );
    (clock, caps)
}

#[test]
fn fallback_caps_use_system_clock() {
    let fallback = CompatCaps::fallback();
    let now = fallback.clock().now_system();
    let real = SystemTime::now();
    let delta = now.duration_since(real).or_else(|_| real.duration_since(now)).expect("两时刻可比");
    assert!(delta < Duration::from_secs(1), "兜底时钟 = 系统钟（now_system ≈ 真实挂钟）");
}

#[test]
fn install_is_one_shot_and_fail_visible() {
    // 占住全局互斥（作用域安装守卫）→ 并发作用域安装被串行化 → 本用例独占
    // 永久槽的观察窗口。
    let _hold = install_scoped(CompatCaps::fallback());
    assert!(installed_caps().is_none(), "初始：永久槽未安装");

    let (clock, caps_a) = caps_with_fixed_clock();
    install(caps_a).expect("首次安装成功");
    assert!(installed_caps().is_some(), "安装后：永久槽有值");
    let permanent = installed_caps().expect("permanent slot filled");
    assert!(Arc::ptr_eq(permanent.clock(), &clock), "永久槽 = 安装那份");

    let second = install(CompatCaps::fallback());
    assert!(matches!(second, Err(CompatAlreadyInstalled)), "重复安装 → fail-visible（禁静默覆盖）");
}

#[test]
fn scoped_install_shadows_and_is_dropped() {
    let (clock, scoped) = caps_with_fixed_clock();
    {
        let _guard = install_scoped(scoped);
        assert!(Arc::ptr_eq(caps().clock(), &clock), "作用域安装优先于永久槽/兜底");
    }
    assert!(
        !Arc::ptr_eq(caps().clock(), &clock),
        "守卫 drop → 作用域那份不再可见（还原到永久槽或兜底）"
    );
}

#[tokio::test]
async fn process_scope_spawn_is_managed() {
    // 本用例读的是**进程级槽**，而并行用例的作用域安装会把它临时换成本地 scope
    // （`install_scoped` 影子优先）——那份 scope 随守卫 drop 回收，JoinSet drop
    // = abort 在途任务 → `Spawned::join` 回 `Cancelled`。故持守卫独占进程级槽
    // 直到 join 完成：既保 join 期间 scope 存活，也与并发作用域安装串行化。
    let clock: Arc<dyn Clock> = Arc::new(FixedClock);
    let scope = Arc::new(FxScope::new());
    let _guard = install_scoped(CompatCaps::new(
        clock,
        Arc::clone(&scope),
        LogFacade::new("compat_test", Vec::new()),
    ));
    assert!(
        Arc::ptr_eq(&xray_frame::compat::spawn_scope(), &scope),
        "守卫期间进程级 scope = 本用例装的那份"
    );

    let handle = xray_frame::compat::spawn(async { 7u32 }).expect("进程级 scope 可 spawn");
    let joined = handle.join().await.expect("join");
    assert_eq!(joined, 7, "进程级 scope 托管的任务正常返回");
}

/// bd s3tig 验收（进程级接线）：`compat::spawn` 自带收割装配——panic 条目完成后
/// 滞留集合是修复前的泄漏形态；REAP_EVERY 次连发窗内必触发收割清出。判别器 =
/// 自装 scope 的 `try_reap()` 错误结局（Panicked 条目真在集合里才数得出）。
///
/// tick 为进程级共享静态、相位不可钉 → 用 2×REAP_EVERY 连发窗鸽笼保证 ≥2 个
/// 触发位落在窗内；本用例持守卫独占 SCOPED_LOCK，其余全局面用例窗口内不可能
/// 发 spawn，触发位不会被外来调用抢走（抢走也只判红，无假绿形态）。
#[tokio::test]
async fn process_scope_spawn_reaps_completed_entries() {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock);
    let scope = Arc::new(FxScope::new());
    let _guard = install_scoped(CompatCaps::new(
        clock,
        Arc::clone(&scope),
        LogFacade::new("compat_probe", Vec::new()),
    ));

    // ① 阳性对照：panic 条目真的入集（若不滞留，下面 ② 的判据就是空转）。
    let doomed = xray_frame::compat::spawn(async { panic!("probe-boom") }).expect("spawn accepted");
    while !doomed.is_finished() {
        tokio::task::yield_now().await;
    }
    drop(doomed); // 载荷只在集合面
    let held = scope.try_reap();
    assert_eq!(held.len(), 1, "完成条目必须滞留集合（阳性对照）: {held:?}");
    assert!(
        matches!(&held[0], TaskError::Panicked(m) if m.contains("probe-boom")),
        "滞留条目必须带 panic 载荷: {held:?}"
    );

    // ② 修复判据：进程级 spawn 连发 ≥REAP_EVERY 次必有触发位 → 条目被清出。
    let boom = xray_frame::compat::spawn(async { panic!("probe-boom-2") }).expect("spawn accepted");
    while !boom.is_finished() {
        tokio::task::yield_now().await;
    }
    drop(boom);
    for _ in 0..=(2 * xray_frame::compat::REAP_EVERY) {
        xray_frame::compat::spawn(async {}).expect("spawn accepted");
    }
    assert!(scope.try_reap().is_empty(), "进程级 compat::spawn 必须内置收割（panic 条目不得滞留）");
    // 守卫持到断言完：窗口内 spawn 的任务归本用例装的 scope（见文件头纪律）。
    drop(_guard);
}
