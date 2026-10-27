//! 面 6 验收（G6）：两级 scope —— 父关 → 子任务结束；子关不影响父；
//! `in_flight` 归零；关闭后拒新任务。

use std::{sync::Arc, time::Duration};

use skeleton_infra::fx::FxScope;
use xray_frame::scope::ConnScope;

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
    let parent = Arc::new(FxScope::new());
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

#[tokio::test]
async fn child_close_does_not_affect_parent() {
    let parent = Arc::new(FxScope::new());
    let child = ConnScope::child_of(&parent);
    let parent_task = parent
        .spawn(async {
            std::future::pending::<()>().await;
        })
        .expect("父 scope 可 spawn");

    child.close();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(parent.in_flight(), 1, "子关不影响父的在途任务");
    assert!(!parent_task.is_finished(), "父任务仍在跑");
}

#[tokio::test]
async fn closed_scope_rejects_new_tasks() {
    let parent = Arc::new(FxScope::new());
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
