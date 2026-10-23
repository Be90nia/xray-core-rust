//! P0-6 托管口行为回归（契约任务书 §P0-6 验收①）：`ctx.spawn` 唯一异步托管口的
//! 行为契约——值透传 / 闸关拒绝 / close 后在途收净 / 取消令牌观察。
//! 语义基准 = udf `skeleton_infra::fx`（Spawned/ScopeClosed/expect_idle/cancel_pair
//! 透传面，context.rs 不新造句柄类型）。

use std::sync::Arc;

use serde_json::json;
use skeleton::{clock::SystemClock, config::MockEnv};
use skeleton_infra::fx::{FxScope, ScopeClosed, cancel_pair, expect_idle};
use xray_frame::{
    context::{PluginContext, derive_fingerprint},
    logging::LogFacade,
};

const FIXED_ADDR: &str = "127.0.0.1:10808";

/// 组装配方：与 tests/plugin_context.rs 的 `ctx_at` 同形，fx 外提为参数——
/// 本文件要操纵 scope 闸（close）与泄漏断言（expect_idle），scope 生命周期
/// 须握在测试侧，不能埋进 ctx 构造内部。
fn ctx_with(fx: Arc<FxScope>) -> PluginContext {
    PluginContext::new(
        "stub",
        fx,
        Arc::new(SystemClock),
        derive_fingerprint(Some(FIXED_ADDR)),
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new("stub", vec![]),
    )
}

/// ① Spawned 契约值透传：join 收到任务返回值；收值后 in_flight 归零。
/// 自然完成路径上 FlightGuard 与结果 send 同一 poll 内落账，join 唤醒必晚于
/// 归零（udf fx.rs 测试①同形），expect_idle 直接断言不放宽。
#[tokio::test]
async fn spawn_joins_value_and_expect_idle_passes() {
    let fx = Arc::new(FxScope::new());
    let ctx = ctx_with(Arc::clone(&fx));
    let spawned = ctx.spawn(async { 40 + 2 }).expect("scope accepting");
    assert_eq!(spawned.join().await, Ok(42));
    expect_idle(&fx);
}

/// ② 闸关拒新：close 后 ctx.spawn → Err(ScopeClosed)（fail-closed 显式，
/// 禁静默丢弃 future）。
#[tokio::test]
async fn spawn_after_close_is_scope_closed() {
    let fx = Arc::new(FxScope::new());
    let ctx = ctx_with(Arc::clone(&fx));
    fx.close();
    assert!(fx.is_closed());
    assert!(matches!(ctx.spawn(async {}), Err(ScopeClosed)));
}

/// ③ close 放行在途：闸关后已 spawn 任务照常收值；收值即净，expect_idle 通过
/// （真泄漏此处必红，不放宽断言）。
#[tokio::test]
async fn close_allows_in_flight_join_and_expect_idle_passes() {
    let fx = Arc::new(FxScope::new());
    let ctx = ctx_with(Arc::clone(&fx));
    let spawned = ctx.spawn(async { "in-flight value" }).expect("scope accepting");
    fx.close();
    assert!(matches!(ctx.spawn(async {}), Err(ScopeClosed)), "闸关后新 spawn 必拒");
    assert_eq!(spawned.join().await, Ok("in-flight value"));
    expect_idle(&fx);
}

/// ④ 取消令牌可观察（按 udf 实测语义写，fx.rs 内测⑨同形，不臆造）：
/// 取消源留装配根（测试即装配根），任务经托管口携带观察面判停——
/// `cancelled()` 在 false→true 前不返回；close 只关 accepting 闸、不触发取消
/// （fx.rs close 契约），`source.cancel()` 才是触发点。
#[tokio::test]
async fn cancel_token_observable_and_close_does_not_cancel() {
    let (source, token) = cancel_pair();
    let fx = Arc::new(FxScope::new());
    let ctx = ctx_with(Arc::clone(&fx));

    let observe = ctx
        .spawn(async move {
            token.cancelled().await;
            token.is_cancelled()
        })
        .expect("scope accepting");

    fx.close();
    assert!(!ctx.token().is_cancelled(), "close 只关 accepting 闸，不触发取消");

    source.cancel();
    assert_eq!(observe.join().await, Ok(true));
}
