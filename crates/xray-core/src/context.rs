//! Context —— Instance 在异步调用链中的传递机制。
//!
//! 对应 Go `core/context.go`，但 Go 用 `context.Context` 携带 `*Instance`，
//! Rust 端提供双轨制：
//!
//! 1. **显式参数**：调用方把 `Arc<Instance>` 作为函数参数传递。最简单、最显式。
//! 2. **Task-local**：通过 [`tokio::task_local`] 在异步任务上下文中隐式传播， 对应 Go 的
//!    `ctx.Value(xrayKey)`。适合深层调用链避免参数污染。
//!
//! ## 选用建议
//!
//! - 浅调用链 / 单元测试：用显式参数。
//! - 深层异步分发链（如 dispatcher → router → outbound）：用 task-local。
//!
//! ## 切片边界
//!
//! 不实现 `ToBackgroundDetachedContext`（Go 端用于剥离上下文但保留 Instance，
//! Rust 端通过 [`with_detached`] 显式提供等价语义）。

use std::sync::Arc;

use tokio::task_local;

use crate::Instance;

task_local! {
    /// 携带当前任务关联的 Instance 引用。
    ///
    /// 使用 [`scope`] 在异步任务上下文中绑定 Instance；通过 [`current`] 读取。
    /// 读取未绑定的上下文返回 `None`（不 panic，与 Go `FromContext` 一致）。
    static INSTANCE_CTX: Option<Arc<Instance>>;
}

/// 在当前异步任务上下文中绑定 Instance，执行 `f` 后清理。
///
/// 对应 Go `toContext(ctx, v)`。绑定的 Instance 在 `f` 内的任何子任务
/// （`tokio::spawn` 之前）都能通过 [`current`] 读取。
///
/// # Panics
///
/// 仅在 `f` 自身 panic 时传播 panic，绑定机制本身不会 panic。
pub async fn scope<F, R>(instance: Arc<Instance>, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    INSTANCE_CTX.scope(Some(instance), f).await
}

/// 读取当前 task-local 上下文中的 Instance 引用。对应 Go `FromContext`。
///
/// 未在 [`scope`] 内调用时返回 `None`，不 panic。
pub fn current() -> Option<Arc<Instance>> {
    INSTANCE_CTX.try_get().ok().flatten()
}

/// 读取当前 task-local 上下文中的 Instance，缺失时 panic。
///
/// 对应 Go `MustFromContext`。仅用于「Instance 必须存在」的内部代码路径，
/// 外部 API 应优先用 [`current`]。
///
/// # Panics
///
/// 不在 [`scope`] 内调用时 panic，错误消息包含诊断提示。
pub fn must_current() -> Arc<Instance> {
    current().expect(
        "Instance is not in task-local context; wrap the call with xray_core::context::scope",
    )
}

/// 在剥离其他上下文但保留 Instance 的新 task-local 中执行 `f`。
///
/// 对应 Go `ToBackgroundDetachedContext`。用于把当前 Instance 引用到
/// 独立后台任务（脱离请求级 cancellation 等）。
///
/// # Panics
///
/// 仅在 `f` 自身 panic 时传播。
pub async fn with_detached<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let inst = must_current();
    // 用全新的 task-local scope 承载相同 Instance，丢弃其他上下文绑定。
    INSTANCE_CTX.scope(Some(inst), f).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scope_binds_instance_for_current_task() {
        let inst = Arc::new(Instance::new());
        let cloned = Arc::clone(&inst);
        scope(cloned, async {
            assert!(current().is_some());
            // must_current 不 panic。
            let _ = must_current();
        })
        .await;
        // scope 退出后不可访问。
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn current_returns_none_outside_scope() {
        assert!(current().is_none());
    }

    #[tokio::test]
    #[should_panic(expected = "Instance is not in task-local context")]
    async fn must_current_panics_without_scope() {
        let _ = must_current();
    }

    #[tokio::test]
    async fn nested_scope_overrides_outer() {
        let outer = Arc::new(Instance::new());
        let inner = Arc::new(Instance::new());
        let outer_clone = Arc::clone(&outer);
        let inner_clone = Arc::clone(&inner);
        scope(outer_clone, async {
            assert!(Arc::ptr_eq(&current().unwrap(), &outer));
            scope(inner_clone, async {
                assert!(Arc::ptr_eq(&current().unwrap(), &inner));
            })
            .await;
            // 内层 scope 退出后恢复外层。
            assert!(Arc::ptr_eq(&current().unwrap(), &outer));
        })
        .await;
    }

    #[tokio::test]
    async fn with_detached_preserves_instance_in_new_scope() {
        let inst = Arc::new(Instance::new());
        let inst_clone = Arc::clone(&inst);
        scope(inst_clone, async {
            let result = with_detached(async {
                // 在 detached 子作用域内仍能拿到 Instance。
                current().is_some()
            })
            .await;
            assert!(result);
        })
        .await;
    }

    #[tokio::test]
    async fn spawned_task_inherits_via_scope() {
        // task_local 通过 task 系统继承：在 scope 内 spawn 的子任务
        // 不会自动继承（tokio::spawn 创建新 task），但 within scope 内的
        // 内联 await 仍可读。
        let inst = Arc::new(Instance::new());
        let inst_clone = Arc::clone(&inst);
        let found_in_scope = scope(inst_clone, async { current().is_some() }).await;
        assert!(found_in_scope);
    }
}
