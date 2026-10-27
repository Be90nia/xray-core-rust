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
//!
//! **不加 feature/cfg 门（bd 5t916 评估判定）**：268 处调用横跨 17 个 crate，且集成
//! 测试编译 lib 时不带 `cfg(test)`——加门须改 17 份 `[dev-dependencies]` 否则全断，
//! 而收益只是省下产线包里这 5 行；代价面远大于收益，故保留无条件编入，闸门改由
//! 本 crate `clippy.toml`（禁裸 `tokio::spawn`）+ 本条违规声明共同把守。

use std::future::Future;

use tokio::task::JoinHandle;
use tracing::Instrument as _;

/// 测试专用 spawn：等价 `tokio::spawn` + 任务名 span。
///
/// `task` 是测试内任务标签（如 `"mock-dns-server"`），出现在 `test_task` span 上。
#[allow(clippy::disallowed_methods)] // 本模块是 L3 闸唯一的测试面裸 spawn 豁免点（见模块文档）；不要在别处复制
pub fn spawn<F>(task: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // 本模块是 L3 闸唯一的测试面豁免点；不要在别处复制裸 spawn。
    tokio::spawn(fut.instrument(tracing::info_span!("test_task", task)))
}

/// bind(:0)→drop→被测方再 bind 之间端口可能被并行测试/其他进程抢占（TOCTOU，
/// Windows os error 10048 / Unix EADDRINUSE 实证）。探测 N 个**互异**空闲端口：
/// 所有探测 listener 在取号全程存活（OS 保证组内互不重号），全部取齐后统一
/// 释放——把竞态窗口收敛为「释放→被测方 bind」一段，由调用方按占用重试兜底。
pub async fn pick_free_ports(n: usize) -> Vec<u16> {
    let mut probes = Vec::with_capacity(n);
    for _ in 0..n {
        probes.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe bind :0"));
    }
    let ports = probes.iter().map(|l| l.local_addr().expect("probe local_addr").port()).collect();
    drop(probes);
    ports
}

/// 地址占用判定（跨平台、免本地化消息）：错误 Debug 里出现
/// `(os error 10048)`/`(os error 98)`（Display 尾缀被格式化进错误串的形态，
/// 如 `FeatureError::InstanceStart(String)`）或 `AddrInUse`（io::Error Debug
/// 形态 `Os { code: 10048, kind: AddrInUse, .. }` 经 `#[from]` 透传）。
pub fn is_addr_in_use_err(err: impl std::fmt::Debug) -> bool {
    let s = format!("{err:?}");
    s.contains("(os error 10048)") || s.contains("(os error 98)") || s.contains("AddrInUse")
}
