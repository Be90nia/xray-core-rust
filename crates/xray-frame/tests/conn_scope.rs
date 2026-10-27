//! 面 6 验收（G6）：两级 scope —— 父关 → 子任务结束；子关不影响父；
//! `in_flight` 归零；关闭后拒新任务。
//! mzput 验收：级联信号事件驱动（watch 广播，无 20ms 轮询）——父先关的
//! 注册窗口、挂起期间关闭窗口、无定时器依赖（start_paused 虚拟钟证伪轮询）。

use std::time::Duration;

use xray_frame::scope::{ArmScope, ConnScope};

/// 等到 scope 在途任务归零（真实 sleep 让核 → drop 序列能推进）。
async fn wait_idle(scope: &ConnScope) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while scope.in_flight() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("在途任务 5s 内归零");
}

#[tokio::test]
async fn parent_close_cancels_child_tasks() {
    let parent = ArmScope::new();
    let child = ConnScope::child_of(&parent);
    let handle = child
        .spawn(async {
            std::future::pending::<()>().await;
            "never"
        })
        .expect("子 scope 可 spawn");
    assert!(child.in_flight() >= 1, "任务在途");

    parent.close();
    wait_idle(&child).await;
    assert!(handle.is_finished(), "父关 → 子任务结束");
}

/// mzput 验收 2a：父已关闭 → **后注册**的子立刻观察到关闭（订阅即读终值，
/// 同步取消，不依赖任何轮询周期）。
#[tokio::test]
async fn parent_closed_before_child_registers_observed_immediately() {
    let parent = ArmScope::new();
    parent.close();

    let child = ConnScope::child_of(&parent);
    assert!(child.is_closed(), "父先关 → 子注册即已关（同步观察）");
    assert!(child.token().is_cancelled(), "级联取消令牌已置位");
    assert!(child.spawn(async {}).is_err(), "已级联关闭的子 scope 拒新任务（fail-closed）");
    // 幂等：重复观察仍为已关，子侧 close 不 panic。
    child.close();
    assert!(child.is_closed(), "重复观察幂等");
}

/// mzput 验收 2b：子监视任务挂起（watch changed 挂起，无定时器）期间父关闭
/// → 子被事件唤醒，50ms 上限内观察到级联取消。
#[tokio::test]
async fn child_wakes_on_parent_close_while_suspended() {
    let parent = ArmScope::new();
    let child = ConnScope::child_of(&parent);
    let handle = child
        .spawn(async {
            std::future::pending::<()>().await;
            1u32
        })
        .expect("子 scope 可 spawn");

    let started = std::time::Instant::now();
    parent.close();
    let joined = tokio::time::timeout(Duration::from_millis(50), handle.join())
        .await
        .expect("级联唤醒 < 50ms（事件驱动）")
        .expect("join");
    assert_eq!(joined, None, "父关 → 子任务取消（None 形状）");
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "挂起期间父关闭必须即时唤醒，实测 {:?}",
        started.elapsed()
    );
}

/// mzput 非轮询证明：`start_paused` 下 tokio 计时器全虚拟化且不自动推进——
/// 若级联依赖 sleep 轮询（旧 20ms 闸位轮询形态），本测试永久挂起；事件驱动
/// 则 watch 通知真实穿透，立即完成。
#[tokio::test(start_paused = true)]
async fn cascade_has_no_timer_dependency() {
    let parent = ArmScope::new();
    let child = ConnScope::child_of(&parent);
    let handle = child
        .spawn(async {
            std::future::pending::<()>().await;
        })
        .expect("子 scope 可 spawn");

    parent.close();
    let joined = handle.join().await.expect("join");
    assert_eq!(joined, None, "虚拟钟冻结下级联仍即时完成 = 无定时器依赖");
}

#[tokio::test]
async fn child_close_does_not_affect_parent() {
    let parent = ArmScope::new();
    let child = ConnScope::child_of(&parent);
    let parent_task = parent
        .spawn(async {
            std::future::pending::<()>().await;
        })
        .expect("父 scope 可 spawn");

    child.close();
    wait_idle(&child).await;
    assert_eq!(parent.fx().in_flight(), 1, "子关不影响父的在途任务");
    assert!(!parent_task.is_finished(), "父任务仍在跑");
    // 子关后父仍可继续派生子 scope 并正常关闭（中枢可复用）。
    let child2 = ConnScope::child_of(&parent);
    assert!(child2.spawn(async {}).is_ok(), "子先关后父仍可派生");
    child2.close();
    parent.close();
    assert!(parent.is_closed());
}

#[tokio::test]
async fn closed_scope_rejects_new_tasks() {
    let parent = ArmScope::new();
    let child = ConnScope::child_of(&parent);
    child.close();
    assert!(child.is_closed(), "关闭后闸关");
    assert!(child.spawn(async {}).is_err(), "关闭后拒新任务（fail-closed）");
}

#[tokio::test]
async fn completed_task_joins_with_some() {
    let child = ConnScope::new();
    let handle = child.spawn(async { 42u32 }).expect("spawn");
    let joined = handle.join().await.expect("join");
    assert_eq!(joined, Some(42), "正常完成 → Some(值)");
}

#[tokio::test]
async fn cancelled_task_joins_with_none() {
    let child = ConnScope::new();
    let handle = child
        .spawn(async {
            std::future::pending::<()>().await;
            1u32
        })
        .expect("spawn");
    child.close();
    wait_idle(&child).await;
    let joined = handle.join().await.expect("join");
    assert_eq!(joined, None, "被取消 → None（与完成可区分）");
}
