//! 测试面 spawn 单入口（bd shexg）。
//!
//! 生产代码的裸 `tokio::spawn` 由 L3 静态闸（各 crate `clippy.toml` 的
//! `disallowed-methods`）拦下，唯一合法口是 `PluginContext::spawn`（透传
//! `FxScope` 生命周期记账）。测试脚手架没有 PluginContext，收口后每条测试
//! spawn 都走这里：命名 + span（`test_task.task`），任务 panic/超时时可按名
//! 归因，将来换托管实现也只改这一处。
//!
//! 本模块仅服务测试目标（`tests/*.rs` 与 `#[cfg(test)]` 模块）；生产代码引用
//! 它等于绕过 L3 闸，视为违规。

use std::future::Future;

use tokio::task::JoinHandle;
use tracing::Instrument as _;

/// 测试专用 spawn：等价 `tokio::spawn` + 任务名 span。
///
/// `task` 是测试内任务标签（如 `"mock-dns-server"`），出现在 `test_task` span 上。
pub fn spawn<F>(task: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // 本模块是 L3 闸唯一的测试面豁免点；不要在别处复制裸 spawn。
    tokio::spawn(fut.instrument(tracing::info_span!("test_task", task)))
}
