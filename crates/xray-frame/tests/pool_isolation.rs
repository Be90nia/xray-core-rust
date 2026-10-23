//! P1-1 红线隔离测试（契约级任务书 P1P4 §P1-1 验收第 3 条）。
//!
//! 判据 = 分配路径的字节级行为未变（xray-buf 零改动红线，坑约束 12）：
//! 1. [`PooledBuffer`] 接缝路径与裸 `xray_buf::alloc` 同参调用产出**同容**缓冲 ——分层 tier
//!    选择未被接缝改写（分配算法归 xray-buf，管理面在外侧记账）。
//! 2. 借还配平：借 N → 还 N 后 `PoolMetrics { borrowed: 0, dropped_overflow: 0 }`。
//! 3. 审计 seq 单调；resize 拒绝不改状态。
//!
//! 分配计数一致性以「同参等容 + 账本配平」双断言表达，**不挂全局分配器钩子**
//! ——libtest 并发下全局 live 计数被并发线程净漂移打穿（udf CI flake 教训：
//! 期望值逐项推导 + 线程归属门，本单无此基建，不作数）。

use std::sync::Arc;

use skeleton::{clock::SystemClock, config::MockEnv, pool::PoolResizeError};
use skeleton_infra::fx::FxScope;
use xray_frame::{
    BufferPool, ManagedBufferPool, PluginContext, PoolError, XrayBufPool, derive_fingerprint,
    logging::LogFacade,
};

// ── 红线隔离①：接缝不改写 xray-buf 分配行为（同参等容）─────────────────

#[test]
fn pooled_path_preserves_xray_buf_tier_behavior() {
    let pool = XrayBufPool::new(128, 128);
    for size in [64usize, 2048, 8192, 32768, 131_072, 300_000] {
        let raw = xray_buf::alloc::alloc(size);
        let mut pooled = pool.acquire(size).expect("within max");
        assert_eq!(
            pooled.payload_mut().capacity(),
            raw.capacity(),
            "size={size}: 接缝不得改写 xray-buf 分层选择（含 >128KB 直通新分配路径）"
        );
        pooled.release();
        xray_buf::alloc::release(raw);
    }
    let m = pool.metrics();
    assert_eq!((m.borrowed, m.dropped_overflow), (0, 0), "借还配平");
}

// ── 红线隔离②：100 块借还配平（契约 §验收 3 明确项）────────────────────

#[test]
fn borrow_100_return_100_zeroes_borrowed_and_overflow() {
    let pool = ManagedBufferPool::new(XrayBufPool::new(128, 128), 128, 128);
    let bufs: Vec<_> = (0..100).map(|_| pool.acquire(8192).expect("within max")).collect();
    assert_eq!(pool.metrics().borrowed, 100);
    for b in bufs {
        b.release();
    }
    let m = pool.metrics();
    assert_eq!(m.borrowed, 0, "借还后 borrowed=0");
    assert_eq!(m.dropped_overflow, 0, "无溢出丢弃");
    assert_eq!(m.idle, 100, "keep 裁决全部留存（idle_cap=128 未触顶）");
}

// ── 红线隔离③：审计 seq 单调 + resize 拒绝不改状态 ─────────────────────

#[test]
fn audit_seq_monotonic_and_rejected_resize_touches_nothing() {
    let pool = XrayBufPool::new(8, 8);
    let _ticket = pool.subscribe_audit(|_| {}); // 绑定持有（must_use 纪律）
    let a = pool.acquire(64).expect("acquire");
    a.release();
    let b = pool.acquire(64).expect("acquire");
    drop(b); // Drop 路径归还

    let before = pool.metrics();
    assert_eq!(pool.resize(0, 1), Err(PoolResizeError::ZeroMax));
    assert_eq!(pool.resize(4, 0), Err(PoolResizeError::IdleCapZero));
    assert_eq!(pool.resize(4, 8), Err(PoolResizeError::IdleCapExceedsMax { idle_cap: 8, max: 4 }));
    assert_eq!(pool.metrics(), before, "resize 拒绝不改任何状态");

    let mut last = 0u64;
    for e in pool.take_audit_events() {
        assert!(e.seq > last, "seq 单调（{} then {}）", last, e.seq);
        last = e.seq;
    }
    assert!(last > 0, "审计流已记录借/还事件");
}

// ── 拍板①：池满立即 Err（不阻塞等 idle_cap）────────────────────────────

#[test]
fn pool_full_errs_immediately_no_blocking() {
    let pool = XrayBufPool::new(2, 2);
    let a = pool.acquire(64).expect("first");
    let _b = pool.acquire(64).expect("second");
    assert!(matches!(pool.acquire(64), Err(PoolError::Exhausted)), "池满立即 Err");
    drop(a);
    assert!(pool.acquire(64).is_ok(), "归还即恢复");
}

// ── RAII：Drop 与显式 release 都恰归还一次 ──────────────────────────────

#[test]
fn drop_and_explicit_release_both_return_exactly_once() {
    let pool = XrayBufPool::new(4, 4);
    {
        let _a = pool.acquire(64).expect("acquire");
    } // Drop 路径归还
    assert_eq!(pool.metrics().borrowed, 0);
    let b = pool.acquire(64).expect("acquire");
    b.release(); // 显式路径（句柄被消费，二次归还编译期不可能）
    assert_eq!(pool.metrics().borrowed, 0);
}

// ── Context 扩容件：pool() 句柄接线 + 未接线 fail-visible ───────────────

fn unwired_ctx() -> PluginContext {
    PluginContext::new(
        "pool-isolation",
        Arc::new(FxScope::new()),
        Arc::new(SystemClock),
        derive_fingerprint(Some("127.0.0.1:10808")),
        Arc::new(MockEnv::new()),
        serde_json::json!({}),
        LogFacade::new("pool-isolation", vec![]),
    )
}

#[test]
#[should_panic(expected = "pool capability not wired")]
fn context_pool_unwired_fails_visible() {
    let _ = unwired_ctx().pool();
}

#[test]
fn context_pool_roundtrip_acquires_through_handle() {
    let mut ctx = unwired_ctx();
    ctx.set_pool(Arc::new(ManagedBufferPool::new(XrayBufPool::new(8, 8), 8, 8)));
    let mut buf = ctx.pool().acquire(8192).expect("pool wired");
    let raw = xray_buf::alloc::alloc(8192);
    assert_eq!(buf.payload_mut().capacity(), raw.capacity(), "ctx.pool() 同参等容");
    drop(raw);
    buf.payload_mut().extend_from_slice(b"ping");
    assert_eq!(&buf.payload()[..4], b"ping");
    buf.release();
    assert_eq!(ctx.pool().acquire(64).expect("re-acquire").payload().len(), 0);
}
