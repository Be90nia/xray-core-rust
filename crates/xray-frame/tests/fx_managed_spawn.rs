//! P0-6 托管口行为回归（契约任务书 §P0-6 验收①）：`ctx.spawn` 唯一异步托管口的
//! 行为契约——值透传 / 闸关拒绝 / close 后在途收净 / 取消令牌观察。
//! 语义基准 = udf `skeleton_infra::fx`（Spawned/ScopeClosed/expect_idle/cancel_pair
//! 透传面，context.rs 不新造句柄类型）。

use std::sync::Arc;

use serde_json::json;
use skeleton::{clock::SystemClock, config::MockEnv};
use skeleton_infra::fx::{ScopeClosed, cancel_pair, expect_idle};
use xray_frame::{
    context::{PluginContext, derive_fingerprint},
    logging::LogFacade,
    scope::{ArmScope, ConnScope},
};

const FIXED_ADDR: &str = "127.0.0.1:10808";

/// 组装配方：与 tests/plugin_context.rs 的 `ctx_at` 同形，fx 外提为参数——
/// 本文件要操纵 scope 闸（close）与泄漏断言（expect_idle），scope 生命周期
/// 须握在测试侧，不能埋进 ctx 构造内部。
fn ctx_with(fx: Arc<ArmScope>) -> PluginContext {
    PluginContext::new(
        "stub",
        fx,
        Arc::new(SystemClock),
        derive_fingerprint(Some(FIXED_ADDR)),
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new("stub", vec![]),
        Arc::new(xray_frame::AuditHandle::new(xray_frame::DEFAULT_AUDIT_RING_CAP)),
    )
}

/// ① Spawned 契约值透传：join 收到任务返回值；收值后 in_flight 归零。
/// 自然完成路径上 FlightGuard 与结果 send 同一 poll 内落账，join 唤醒必晚于
/// 归零（udf fx.rs 测试①同形），expect_idle 直接断言不放宽。
#[tokio::test]
async fn spawn_joins_value_and_expect_idle_passes() {
    let fx = ArmScope::new();
    let ctx = ctx_with(Arc::clone(&fx));
    let spawned = ctx.spawn(async { 40 + 2 }).expect("scope accepting");
    assert_eq!(spawned.join().await, Ok(42));
    expect_idle(fx.fx());
}

/// ② ArmScope.close 的本层独有语义（A2 收敛，bd bbvuo）：close = 关闸 + watch
/// 广播**复合**——udf `FxScope::close` 零通知、`ComponentScope::close_gate` 无
/// 广播，广播级联只在本层存在：`child_of` 子 scope 事件驱动级联（在途任务收
/// 取消形状 `None`、与完成可区分；取消令牌置位；子闸不关——子闸归子自己的
/// close）。机制级「关闸拒发 + 在途不 abort」由 src/scope.rs A2 canonical
/// （close_gate_rejects_new_spawns_but_keeps_in_flight）覆盖，此处不重复断言。
#[tokio::test]
async fn close_broadcasts_and_cascades_to_child_scope() {
    let fx = ArmScope::new();
    let child = ConnScope::child_of(&fx);
    let observe = child.spawn(std::future::pending::<()>()).expect("子 scope 新建即 accepting");

    fx.close();
    // 事件驱动级联（监视任务挂 watch `changed()`，无定时器）：纯让渡等监视任务
    // 跑一拍——无睡眠余量问题（CI timer 饿死面，bd P2-6 同款回避）。
    for _ in 0..200 {
        if child.token().is_cancelled() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(child.token().is_cancelled(), "父关必须经广播级联取消子 scope");
    assert_eq!(
        observe.join().await,
        Ok(None),
        "在途任务收取消形状 None（与完成可区分，禁静默当成功）"
    );
    assert!(!child.is_closed(), "级联只走取消通道，不关子闸（子闸归子自己的 close）");
}

/// ③ close 放行在途：闸关后已 spawn 任务照常收值；收值即净，expect_idle 通过
/// （真泄漏此处必红，不放宽断言）。
#[tokio::test]
async fn close_allows_in_flight_join_and_expect_idle_passes() {
    let fx = ArmScope::new();
    let ctx = ctx_with(Arc::clone(&fx));
    let spawned = ctx.spawn(async { "in-flight value" }).expect("scope accepting");
    fx.close();
    assert!(matches!(ctx.spawn(async {}), Err(ScopeClosed)), "闸关后新 spawn 必拒");
    assert_eq!(spawned.join().await, Ok("in-flight value"));
    expect_idle(fx.fx());
}

/// ④ 取消令牌可观察（按 udf 实测语义写，fx.rs 内测⑨同形，不臆造）：
/// 取消源留装配根（测试即装配根），任务经托管口携带观察面判停——
/// `cancelled()` 在 false→true 前不返回；close 只关 accepting 闸、不触发取消
/// （fx.rs close 契约），`source.cancel()` 才是触发点。
#[tokio::test]
async fn cancel_token_observable_and_close_does_not_cancel() {
    let (source, token) = cancel_pair();
    let fx = ArmScope::new();
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
