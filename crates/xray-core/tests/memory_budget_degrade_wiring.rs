//! bd 2026-11-08 D-02：降档 `max_conns` 必须到达**执行点**（桥 `ConnSlot` 读的那份
//! 静态值），不是只写进 warn 文案。
//!
//! 本文件只有一个测试 ⇒ 独占进程：`XRAY_MEM_LIMIT_MB` / `XRAY_MAX_CONNS` 与
//! `MemoryPlan::cached()` 的进程级静态值都不受其它测试干扰，断言可确定性复现。
//! （跨进程读回是本测试的**唯一**目的；不能放 `memory_budget.rs` 的 `mod tests`
//! —— 同进程数十个用例并发写同一静态值，读回必然抖动。）

use xray_conf::BuiltConfig;

#[test]
fn degraded_conn_limit_reaches_execution_point() {
    // SAFETY: 本文件唯一测试，单线程；env 只在 `MemoryPlan::cached()` 首次读之前写。
    unsafe {
        std::env::set_var("XRAY_MEM_LIMIT_MB", "256"); // Tiny 档 = 40MiB 预算
        // 运维覆盖口（`XRAY_MAX_CONNS`）抬到 64 条 ⇒ 40MiB 档必然装不下 ⇒ 必定降档。
        std::env::set_var("XRAY_MAX_CONNS", "64");
    }
    let plan = *xray_frame::budget::plan::MemoryPlan::cached();
    assert_eq!(plan.tier.as_str(), "tiny", "档位必须由 XRAY_MEM_LIMIT_MB 钉死");
    assert_eq!(plan.max_conns, 64, "XRAY_MAX_CONNS 覆盖必须生效（档位派生值之上）");

    let before = plan.effective_max_conns();
    assert_eq!(before, plan.max_conns, "未装配前执行点读数 = 档位派生值");

    // 缺省 policy（512KiB/方向 ⇒ 每连接 1MiB pipe 双向）：40MiB 档装不下 64 条。
    let built = BuiltConfig::default();
    xray_core::memory_budget::check_startup_budget(&built)
        .expect("预算不足不得拒启（用户裁决 2026-11-07）");

    let after = plan.effective_max_conns();
    // 独立复算（文档口径，公开 API）：连接可用额 ÷ 每连接 pipe 双向。
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let fixed = xray_frame::budget::startup_fixed_floor_bytes_for(cores, 0);
    let per_conn =
        2 * usize::try_from(xray_features::policy::BufferPolicy::default().connection).unwrap();
    let expected = plan.max_conns.min(plan.total_budget.saturating_sub(fixed) / per_conn);

    assert!(after >= 1, "至少能跑 1 条连接");
    assert!(
        after < before,
        "超预算配置必须真的降档：执行点 {before} 条 → 仍 {after} 条（只写日志不接线 = D-02）"
    );
    assert_eq!(
        after, expected,
        "执行点实际使用的并发上限 {after} 必须 == 降档值 {expected}（预算 {}B，固定面 {fixed}B，\
         每连接 {per_conn}B）",
        plan.total_budget
    );
    println!(
        "D-02 wiring: tier tiny, override {} -> effective {after} == expected {expected} \
         (fixed {fixed}B, per-conn {per_conn}B, budget {}B)",
        plan.max_conns, plan.total_budget
    );
}
