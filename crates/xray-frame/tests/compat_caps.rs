//! 面 2 验收（G3）：进程级能力入口 —— 一次性安装 fail-visible + 作用域守卫
//! 还原 + 兜底语义 = SystemClock。
//!
//! **测试隔离纪律**（方案 §2 面 2 "测试隔离"表）：进程级单槽禁被并行测试改写。
//! 本文件的两条全局面用例用**作用域守卫互斥**串行化：
//! - `install_is_one_shot_and_fail_visible`：持一把作用域安装（占住全局互斥 →
//!   并发作用域安装被串行化），期间只断言**永久槽**（`installed_caps()`）。
//! - `scoped_install_shadows_and_is_dropped`：作用域安装优先；守卫 drop 后
//!   作用域那份**不再可见**（与永久槽/兜底是谁无关 → 与并发时序无关）。

use std::{
    sync::{Arc, LazyLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use skeleton::clock::Clock;
use skeleton_infra::fx::FxScope;
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
    let handle = xray_frame::compat::spawn(async { 7u32 }).expect("进程级 scope 可 spawn");
    let joined = handle.join().await.expect("join");
    assert_eq!(joined, 7, "进程级 scope 托管的任务正常返回");
}
