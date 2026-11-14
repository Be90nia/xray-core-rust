//! bd 3gxez：小内存档的**执行点**连接上限必须 = 账本余量口径，不是档位设计表
//! 13/32/64/170。
//!
//! 缺陷形态（修前实测）：`XRAY_MEM_LIMIT_MB=256`（tiny / 40MiB）下上限被设计表压到
//! 13 条，20 并发即有 4-7 条在建连成功后 0 字节 EOF（`connection_limit_error`），
//! 用户感知 = 不稳定。账本自己能装下的条数 = `(预算 − 固定面) / 每连接 pipe 双向`，
//! 在 tiny 档比 13 多出 6-9 条（随核数变），在 512MB 档约为设计值 32 的 2.3 倍。
//!
//! 本文件只有一个测试 ⇒ 独占进程：`XRAY_MAX_CONNS` 与 `MemoryPlan::cached()` 的进程级
//! 静态值不受其它测试干扰，断言可确定性复现（同 `memory_budget_degrade_wiring.rs`）。

use xray_conf::BuiltConfig;
use xray_frame::budget::plan::MemoryPlan;

const MIB: u64 = 1024 * 1024;

/// 账本余量口径的独立复算（文档口径，公开 API）。
fn ledger_fit(plan: &MemoryPlan, listeners: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let fixed = xray_frame::budget::startup_fixed_floor_bytes_for(cores, listeners);
    let per_conn =
        2 * usize::try_from(xray_features::policy::BufferPolicy::default().connection).unwrap();
    plan.total_budget.saturating_sub(fixed) / per_conn
}

#[test]
fn tiny_tier_conn_cap_follows_ledger_remainder() {
    // SAFETY: 本文件唯一测试，单线程；env 只在 `MemoryPlan::cached()` 首次读之前写。
    unsafe {
        std::env::remove_var("XRAY_MAX_CONNS");
        std::env::set_var("XRAY_MEM_LIMIT_MB", "256"); // tiny 档 = 40MiB 预算
    }
    let plan = *MemoryPlan::cached();
    assert_eq!(plan.tier.as_str(), "tiny", "档位必须由 XRAY_MEM_LIMIT_MB 钉死");
    assert_eq!(plan.max_conns, 13, "未经预算门时执行点仍是档位设计值（13 条）");

    // ① 过预算门后上限抬到账本余量（设计表不再是天花板）。
    xray_core::memory_budget::check_startup_budget(&BuiltConfig::default())
        .expect("预算不足不得拒启（用户裁决 2026-11-07）");
    let fit = ledger_fit(&plan, 0);
    assert_eq!(plan.effective_max_conns(), fit, "执行点上限必须 == 账本余量口径");
    assert!(
        fit > plan.max_conns,
        "设计值 13 仍是天花板：账本余量算出 {fit} 条（预算 {}B）——bd 3gxez 修复点回退",
        plan.total_budget
    );
    println!("tiny: design 13 -> effective {fit} (budget {}B)", plan.total_budget);

    // 512MB 档（生产小节点主力）：余量口径约为设计值 32 的 2 倍以上。
    let small = MemoryPlan::from_available(512 * MIB);
    let small_report = xray_core::memory_budget::budget_report_with(&BuiltConfig::default(), small)
        .expect("report");
    let small_fit = ledger_fit(&small, 0);
    assert_eq!(small_report.max_conns, small_fit, "512MB 档同样按账本余量封顶");
    assert!(
        small_report.max_conns >= 2 * small.max_conns,
        "512MB 档账本余量 {} 应 ≥ 设计值 {} 的 2 倍",
        small_report.max_conns,
        small.max_conns
    );

    // ② 调大 XRAY_MAX_CONNS 不得越过账本余量（用户裁决 2026-11-13：不提供放大入口）。
    // SAFETY: 同上单线程；`explicit_max_conns()` 每次调用都重读 env（装配期一次性消费）。
    unsafe { std::env::set_var("XRAY_MAX_CONNS", "1000") };
    xray_core::memory_budget::check_startup_budget(&BuiltConfig::default()).expect("budget gate");
    assert_eq!(plan.effective_max_conns(), fit, "显式放大不得越过账本余量");

    // ③ 收紧仍生效（「只能收紧」那一半语义不许退化）。
    // SAFETY: 同上。
    unsafe { std::env::set_var("XRAY_MAX_CONNS", "3") };
    xray_core::memory_budget::check_startup_budget(&BuiltConfig::default()).expect("budget gate");
    assert_eq!(plan.effective_max_conns(), 3, "XRAY_MAX_CONNS 收紧必须继续生效");
}
