//! bd 3gxez：小内存档的**执行点**连接数上限 = `min(档位设计值, 账本余量)`。
//!
//! 口径（用户裁决 2026-11-14「代码不回退、**总数压小**」）：
//! - 设计表 `design_conn_cap` = 13/32/64/170（= 预算 / 3MiB，3MiB 含 2MiB 在途份额）；
//! - 账本余量 = `(预算 − 固定面 − 显式 socket) / 每连接 pipe 双向`（缺省 1MiB/条）；
//! - **余量恒大于设计值**（tiny 19 vs 13、small 75 vs 32），但**故意不用**——要的是低
//!   内存峰值，不是把预算吃满。这是事实与决策，**不是缺陷**。
//!
//! 修前实测（release 二进制）：tiny 上限 13 ⇒ 20 并发有 4 条建连成功后 0 字节 EOF，
//! 用户感知 = 不稳定。本单交付的是**可操作拒连文案 + 口径文档 + 根因 + 本语义锚**
//! （容量不变）；将来要抬容量，只需把 `memory_budget::budget_report_with` 里
//! `plan.max_conns.min(conns_fit)` 换成余量口径并改本文件期望。
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
fn tiny_tier_conn_cap_is_design_value_bounded_by_ledger() {
    // SAFETY: 本文件唯一测试，单线程；env 只在 `MemoryPlan::cached()` 首次读之前写。
    unsafe {
        std::env::remove_var("XRAY_MAX_CONNS");
        std::env::set_var("XRAY_MEM_LIMIT_MB", "256"); // tiny 档 = 40MiB 预算
    }
    let plan = *MemoryPlan::cached();
    assert_eq!(plan.tier.as_str(), "tiny", "档位必须由 XRAY_MEM_LIMIT_MB 钉死");
    assert_eq!(plan.max_conns, 13, "档位设计值 = 13 条");

    // ① 过预算门后上限仍是设计值（账本余量更大，但按裁决压小）。
    xray_core::memory_budget::check_startup_budget(&BuiltConfig::default())
        .expect("预算不足不得拒启（用户裁决 2026-11-07）");
    let fit = ledger_fit(&plan, 0);
    assert_eq!(plan.effective_max_conns(), plan.max_conns, "执行点上限 = 档位设计值 13 条");
    assert!(
        fit > plan.max_conns,
        "账本余量 {fit} 必须大于设计值 {}——余量更大是事实，压小是裁决（要低峰值）",
        plan.max_conns
    );
    println!(
        "tiny: effective {} (= design) <= ledger fit {fit}; extra headroom intentionally unused \
         (user ruling 2026-11-14)",
        plan.effective_max_conns()
    );

    // 512MB 档（生产小节点主力）：同样钉设计值 32，且账本余量 ≥ 2 倍。
    let small = MemoryPlan::from_available(512 * MIB);
    let small_report = xray_core::memory_budget::budget_report_with(&BuiltConfig::default(), small)
        .expect("report");
    assert_eq!(small_report.max_conns, small.max_conns, "512MB 档生效上限 = 设计值 32 条");
    assert_eq!(small.max_conns, 32, "档位设计值锚");
    assert!(
        ledger_fit(&small, 0) >= 2 * small.max_conns,
        "512MB 档账本余量 {} 应 ≥ 设计值 32 的 2 倍（余量存在但不用）",
        ledger_fit(&small, 0)
    );

    // ② `XRAY_MAX_CONNS` 放大仍受账本余量夹住（既有语义：它只是上界，不能吃满预算）。
    // 用 `MemoryPlan::detect()` 现读 env（`cached()` 已固化，不响应后置 env）⇒ 生效值走
    // 报告返回值，不碰进程级静态值。
    // SAFETY: 同上单线程；env 只影响本函数后续的 `detect()`。
    unsafe { std::env::set_var("XRAY_MAX_CONNS", "1000") };
    let raised = MemoryPlan::detect();
    assert_eq!(raised.max_conns, 1000, "显式值进 MemoryPlan");
    let raised_report =
        xray_core::memory_budget::budget_report_with(&BuiltConfig::default(), raised)
            .expect("report");
    assert_eq!(raised_report.max_conns, fit, "显式 1000 被账本余量 {fit} 夹住");

    // ③ 收紧仍生效（「只作上界」的另一半语义不许退化）。
    // SAFETY: 同上。
    unsafe { std::env::set_var("XRAY_MAX_CONNS", "3") };
    let tightened = MemoryPlan::detect();
    let tightened_report =
        xray_core::memory_budget::budget_report_with(&BuiltConfig::default(), tightened)
            .expect("report");
    assert_eq!(tightened_report.max_conns, 3, "XRAY_MAX_CONNS 收紧必须继续生效");
}
