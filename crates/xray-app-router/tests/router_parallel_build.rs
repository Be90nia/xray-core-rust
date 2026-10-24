//! P3-5 验收：路由 matcher 构建走互喂池（`RouterBuildPool`）。
//!
//! 三条硬验收（契约任务书 P3-5）：
//! 1. 池化构建与串行构建**行为完全等价**（同批规则输入 → 同批 dest → 逐条比对）；
//! 2. 池化批量构建耗时 ≤ 串行 × 1.05（3 轮中位数，不得更慢）；
//! 3. 提交侧拒绝（队列满）路径显式内联补位，不 panic。

#![allow(clippy::disallowed_macros)] // T3.1b：基准对照测试 println 输出对比数字（集成测试 crate 无 lib 层 cfg_attr(test) 豁免）；生产禁令不受影响
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use xray_app_router::{
    Condition,
    condition::{DomainMatcherCondition, RouterBuildPool},
    context::RoutingData,
};
use xray_geodata::matcher::domain::DomainRule;

/// 合成规则集：full/domain/substr/regex 四型轮转（regex 占 1/4，是最贵的编译面）。
fn make_rules(group: usize, count: usize) -> Vec<DomainRule> {
    (0..count)
        .map(|i| {
            let id = ((group * 1_000_000) + i) as u32;
            match i % 4 {
                0 => DomainRule::full(format!("full{group}.{i}.example.com"), id),
                1 => DomainRule::domain(format!("grp{group}.sub{i}.example.org"), id),
                2 => DomainRule::substr(format!("kw{group}-{i}"), id),
                _ => DomainRule::regex(format!(r"^r{group}x{i}\d+\.net$"), id),
            }
        })
        .collect()
}

/// 语义等价：同一批规则，串行 `new` 与池化 `new_pooled` 对同一批 dest 的
/// 匹配结果逐条一致（含空域名、未命中、大小写混合边界）。
#[test]
fn pooled_build_matches_serial_exactly() {
    let rules = make_rules(7, 2000);
    let serial = DomainMatcherCondition::new(rules.clone()).unwrap();

    let pool = RouterBuildPool::new(2, 2, 8, Duration::from_secs(10));
    let pooled = DomainMatcherCondition::new_pooled(&pool, rules).unwrap();
    pool.shutdown_join();

    let mut probes: Vec<String> = (0..500)
        .map(|i| match i % 4 {
            0 => format!("full7.{i}.example.com"),
            1 => format!("deep.grp7.sub{i}.example.org"),
            2 => format!("prefix.kw7-{i}.suffix"),
            _ => format!("r7x{i}77.net"),
        })
        .collect();
    probes.push(String::new());
    probes.push("unrelated.test".into());
    probes.push("FULL7.0.EXAMPLE.COM".into());

    for d in &probes {
        let hit_serial = serial.apply(&RoutingData::new().with_target_domain(d.clone()));
        let hit_pooled = pooled.apply(&RoutingData::new().with_target_domain(d.clone()));
        assert_eq!(hit_serial, hit_pooled, "matcher mismatch for dest {d:?}");
    }
}

/// 耗时对比：4 组规则集，串行逐组构建 vs 池化并行构建，3 轮取中位数，
/// 池化 ≤ 串行 × 1.05（2 worker 并行 4 组，理论加速 ~2x，余量充足）。
#[test]
fn pooled_build_is_not_slower_than_serial() {
    let groups: Vec<Vec<DomainRule>> = (0..4).map(|g| make_rules(g, 2000)).collect();

    let mut serial_ms: Vec<u128> = Vec::new();
    let mut pooled_ms: Vec<u128> = Vec::new();
    for _ in 0..3 {
        let t0 = Instant::now();
        for g in &groups {
            drop(DomainMatcherCondition::new(g.clone()).unwrap());
        }
        serial_ms.push(t0.elapsed().as_millis());

        let pool = RouterBuildPool::new(2, 2, 8, Duration::from_secs(10));
        let (tx, rx) = mpsc::channel();
        let t1 = Instant::now();
        for g in &groups {
            let tx = tx.clone();
            let g = g.clone();
            pool.submit(move |_| {
                let _ = tx.send(DomainMatcherCondition::new(g).unwrap());
            })
            .unwrap();
        }
        drop(tx);
        for _ in &groups {
            rx.recv().unwrap();
        }
        pooled_ms.push(t1.elapsed().as_millis());
        pool.shutdown_join();
    }
    serial_ms.sort();
    pooled_ms.sort();
    let (s_med, p_med) = (serial_ms[1], pooled_ms[1]);
    println!(
        "build 4x2000 rules x3 rounds: serial median {s_med}ms (runs {serial_ms:?}), \
         pooled median {p_med}ms (runs {pooled_ms:?})"
    );
    assert!(
        p_med * 100 <= s_med * 105,
        "pooled median {p_med}ms must be <= serial median {s_med}ms * 1.05"
    );
}

/// 拒绝路径：唯一 worker 被占 + 队列（cap=1）满后，`new_pooled` 的提交被
/// `RejectedTask` 拒绝 → 本线程内联补位（CallerRuns 等价），结果正确不 panic。
#[test]
fn rejected_submit_falls_back_inline_without_panic() {
    let pool = RouterBuildPool::new(1, 1, 1, Duration::from_secs(10));

    // 占住唯一 worker，直到测试放行。
    let (started_tx, started_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    pool.submit(move |_| {
        let _ = started_tx.send(());
        let _ = ack_rx.recv();
    })
    .unwrap();
    started_rx.recv().unwrap();

    // 填满队列唯一的槽位（该任务在 shutdown 排空时执行）。
    pool.submit(|_| {}).unwrap();

    // 队列已满：再提交必被拒 → 内联补位，构建结果照常可用。
    let rules = vec![DomainRule::full("inline.example.com", 1)];
    let m = DomainMatcherCondition::new_pooled(&pool, rules).unwrap();
    assert!(m.apply(&RoutingData::new().with_target_domain("inline.example.com")));
    assert!(!m.apply(&RoutingData::new().with_target_domain("other.example.com")));

    let _ = ack_tx.send(());
    pool.shutdown_join();
}
