//! P1-L4 行为夹具验收：四个宏 + `#[doc(hidden)]` 辅助面从集成测试（宏机制
//! 意义上的外部 crate 调用面，与协议 crate 后续接入完全同权）可调用，
//! 正/负用例齐备（规范源 §3 夹具表）。
//!
//! - `assert_conn_id_present!`（坑约束 3）：MockClock + 固定指纹连续取 N 个
//!   id——非零、单进程唯一（严格递增蕴含）、单调不倒退（含跨毫秒推进）；
//! - `assert_deadline_effective!`（坑约束 2）：期限内完成 → Ok / 永不完成 →
//!   `Err(Elapsed)`，真超时必红（墙钟下界断言，不放宽）；
//! - `assert_log_fields!`（坑约束 3/10/11）：target `xray_frame::<域>`、 四元组均在输出、secrets
//!   表内字符串不可见；
//! - `assert_pool_discipline!`（坑约束 4/9）：借 N 还 N 配平，借出不配平必红。

use std::{sync::Arc, time::Duration};

use skeleton::clock::MockClock;
use xray_frame::{
    assert_conn_id_present, assert_deadline_effective, assert_log_fields, assert_pool_discipline,
    context::PluginContext,
    contract_assert::{
        CapturedLog, DETERMINISTIC_FINGERPRINT, assert_conn_id_sequence, assert_log_fields_emitted,
        assert_log_fields_in_captures, assert_pool_settled, contract_test_context,
        contract_test_context_with,
    },
    pool::{BufferPool, ManagedBufferPool, XrayBufPool},
};

/// MockClock + 夹具默认指纹的最小 ctx（显式口子路径：需要时钟句柄推进时间线
/// 时用本 helper；不需要推进时钟就直接 `contract_test_context`）。
fn mock_ctx(plugin: &'static str) -> (Arc<MockClock>, PluginContext) {
    let clock = Arc::new(MockClock::new());
    clock.advance(Duration::from_millis(1)); // 对齐默认构造起点：首调走跨毫秒臂
    let ctx = contract_test_context_with(
        plugin,
        clock.clone() as Arc<dyn skeleton::clock::Clock>,
        DETERMINISTIC_FINGERPRINT,
    );
    (clock, ctx)
}

// ── 夹具一：conn_id ──

/// 正（PM 回归点）：**默认构造**直接连取 64 个 id 不 panic——固定指纹 +
/// MockClock ms=1 起点已把同毫秒配额风险从构造侧消除，调用方 crate 不需要
/// 也不应写 catch_unwind 重掷指纹的重试 helper。
#[test]
fn default_context_takes_64_ids_without_panic() {
    let ctx = contract_test_context("l4-default-ctx");
    assert_conn_id_present!(ctx, 64);
}

/// 正：宏从 ctx 连续取 64 个 id，全部非零且严格递增（唯一性蕴含）。
#[test]
fn conn_id_macro_takes_and_validates_sequence() {
    let (_clock, ctx) = mock_ctx("l4-conn-macro");
    assert_conn_id_present!(ctx, 64);
}

/// 正：MockClock 冻结/推进下序列单调不倒退（同毫秒 counter 臂 + 跨毫秒
/// 时间戳臂都覆盖）。
#[test]
fn conn_id_sequence_survives_clock_advance_monotonically() {
    let (clock, ctx) = mock_ctx("l4-conn-cross-ms");
    let mut ids: Vec<u128> = (0..32).map(|_| ctx.next_conn_id()).collect();
    clock.advance(Duration::from_millis(1));
    ids.extend((0..32).map(|_| ctx.next_conn_id()));
    assert_conn_id_sequence("l4-conn-cross-ms", ids);
}

/// 负：零 id 序列 → panic（0 = 生成器未接线，UUIDv7 ver 位面恒非零）。
#[test]
#[should_panic(expected = "为 0")]
fn zero_conn_id_fails_sequence() {
    assert_conn_id_sequence("neg:zero", [0u128, 0]);
}

/// 负：重复 id → panic（违反严格递增 = 违反唯一性）。
#[test]
#[should_panic(expected = "非单调递增")]
fn duplicate_conn_id_fails_sequence() {
    assert_conn_id_sequence("neg:dup", [5u128, 5]);
}

/// 负：倒退 id → panic。
#[test]
#[should_panic(expected = "非单调递增")]
fn regressing_conn_id_fails_sequence() {
    assert_conn_id_sequence("neg:regress", [9u128, 3]);
}

// ── 夹具二：deadline ──

/// 正：及时完成的工作经 with_deadline 与 guard 双入口都期限内 Ok；
/// 夹具自造的 pending 任务被掐成 Err(Elapsed) 且真实等待 ≥ d（真超时必红）。
#[tokio::test]
async fn deadline_fixture_passes_on_timely_work() {
    assert_deadline_effective!(Duration::from_millis(100), || async { 42 }).await;
}

/// 负：work 慢于 deadline（20ms 期限，1s 才完成）→ 夹具正向断言必红，
/// 且被 deadline 判负后快速失败（不等满 1s）。
#[tokio::test]
#[should_panic(expected = "期限内未完成")]
async fn slow_work_fails_deadline_fixture() {
    assert_deadline_effective!(Duration::from_millis(20), || async {
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
}

// ── 夹具三：日志字段 ──

/// 正：合规 emit——target 钉死 xray_frame::<域>、四元组齐全、secrets 掩码。
#[test]
fn log_fields_fixture_passes_on_compliant_emit() {
    assert_log_fields!(
        domain: "l4-fixture",
        conn_id: 0xDEADBEEFCAFEu128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["topsecret"]
    );
}

/// 正：不带 secrets 段的形态（可选组）同样通过。
#[test]
fn log_fields_fixture_passes_without_secrets_table() {
    assert_log_fields!(
        domain: "l4-fixture-nosec",
        conn_id: 7u128,
        stage: "Accept",
        peer: "198.51.100.9:80",
        dest: "example.org:443",
    );
}

/// 负：message 里出现 secrets 表内字符串（泄漏输出）→ 检查必红。
#[test]
#[should_panic(expected = "泄漏")]
fn leaked_secret_fails_capture_check() {
    let captured = vec![CapturedLog {
        target: "xray_frame::l4-neg".to_owned(),
        message: "conn_id=1 stage=Accept peer=p:1 dest=d:1 key is topsecret".to_owned(),
    }];
    assert_log_fields_in_captures(&captured, "l4-neg", "1", "Accept", "p:1", "d:1", &["topsecret"]);
}

/// 负：四元组任一为空 → 夹具入口 fail-fast（空串 contains 恒真 = 假通过）。
#[test]
#[should_panic(expected = "为空")]
fn empty_field_fails_log_fixture_at_entry() {
    assert_log_fields_emitted("l4-neg-empty", "", "Accept", "p:1", "d:1", &[]);
}

/// 负：target 不是 xray_frame::<域> → 检查必红。
#[test]
#[should_panic(expected = "xray_frame::")]
fn wrong_target_fails_capture_check() {
    let captured = vec![CapturedLog {
        target: "other::target".to_owned(),
        message: "conn_id=1 stage=Accept peer=p:1 dest=d:1".to_owned(),
    }];
    assert_log_fields_in_captures(&captured, "l4-neg-target", "1", "Accept", "p:1", "d:1", &[]);
}

// ── 夹具四：池纪律 ──

/// 正：借 4 块（xray-buf 内层 + 管理面壳）→ 还 4 块 → borrowed=0 且
/// dropped_overflow=0。
#[test]
fn pool_fixture_balances_borrow_and_return() {
    let pool = ManagedBufferPool::new(XrayBufPool::new(8, 8), 8, 8);
    assert_pool_discipline!(pool, 4);
}

/// 负：借 2 还 1（1 块仍在外）→ 配平断言必红（真实借还状态，非伪造读数）。
#[test]
#[should_panic(expected = "借还不配平")]
fn outstanding_borrow_fails_settled_check() {
    let pool = ManagedBufferPool::new(XrayBufPool::new(8, 8), 8, 8);
    let _keep = pool.acquire(64).expect("borrow 1");
    let drop_now = pool.acquire(64).expect("borrow 2");
    drop(drop_now);
    // _keep 仍在借出：borrowed=1 → 配平断言必红。
    assert_pool_settled("neg:pool", pool.metrics());
}
