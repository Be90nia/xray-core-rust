//! Tokio Runtime 健康监控（`RuntimeMetrics` 采样）。
//!
//! ## 背景
//!
//! `tokio` 的 `#[tokio::main]` 默认走 `Builder::new_multi_thread().enable_all()`，
//! 生产环境 worker 线程一旦出现异常行为（频繁假唤醒、`noop_count` 飙升、互相
//! `steal_count` 暴涨）会直接拉低吞吐并放大 CPU 占用。本模块在不动 tokio 配置的
//! 前提下提供这些计数器的一次性快照，供启动日志与外部探针调用。
//!
//! ## 计数器说明（tokio ≥1.53，`RuntimeMetrics`）
//!
//! - `worker_park_count(worker)` — worker 线程 park 次数。`cfg_64bit_metrics!` 下
//!   **默认可用**（target_has_atomic = "64"），64-bit 平台无条件开放。
//! - `worker_noop_count(worker)` / `worker_steal_count(worker)` — `cfg_unstable_metrics!`，
//!   需要构建期 `--cfg tokio_unstable`。本模块通过同名可选字段 + `#[cfg(...)]` 暴露，
//!   不强制该 flag 存在。
//!
//! ## 验收
//!
//! 仅暴露快照结构（`RuntimeMetricsSnapshot`）+ `snapshot(handle)` 函数，单元测试可
//! 在自己 `Builder::new_current_thread()` 起的 runtime 里调用并断言字段单调递增。
//! 不引入后台采样任务或周期性上报——这些留给 xray-cli 启动日志和后续 observability
//! 集成（P3 护栏票的下一站）。

// `tokio_unstable` 由调用方通过 `RUSTFLAGS=--cfg tokio_unstable` 启用；该 cfg 名
// 不在 workspace 集中 allowlist 中，本模块局部 allow 避免无关 warning。
#![allow(unexpected_cfgs)]

use std::time::Duration;
use tokio::runtime::Handle;

/// tokio `RuntimeMetrics` 字段快照。
///
/// `worker_count` 与 `alive_tasks` 总是存在；`*_count` 字段在 `tokio_unstable`
/// 未开启时为 0（不可见），通过 `#[cfg(tokio_unstable)]` 区分来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMetricsSnapshot {
    /// runtime 实际 worker 数（多线程 = 配置值；current_thread = 1）。
    pub worker_count: usize,
    /// 当前在 runtime 内活跃的 task 数。
    pub alive_tasks: usize,
    /// global queue 长度。
    pub global_queue_depth: usize,
    /// 0 号 worker 自 runtime 启动以来的 park 次数。
    pub worker_park_count: u64,
    /// 0 号 worker 自启动以来的累计 busy 时长。
    pub worker_busy_duration: Duration,
    /// 0 号 worker 假唤醒次数（unpark 但无任务可处理）。需 `tokio_unstable`。
    #[cfg(tokio_unstable)]
    pub worker_noop_count: u64,
    /// 0 号 worker 从其他 worker 偷到的任务数。需 `tokio_unstable`。
    /// current_thread runtime 恒为 0。
    #[cfg(tokio_unstable)]
    pub worker_steal_count: u64,
}

impl RuntimeMetricsSnapshot {
    /// 从当前 runtime 的 `Handle` 抓取 0 号 worker 快照。
    ///
    /// 单线程（`current_thread`）runtime 仍合法——`worker_park_count(0)` 等价于
    /// "主线程 park 次数"，可作为健康检查锚点。
    pub fn capture(handle: &Handle) -> Self {
        let metrics = handle.metrics();
        Self {
            worker_count: metrics.num_workers(),
            alive_tasks: metrics.num_alive_tasks(),
            global_queue_depth: metrics.global_queue_depth(),
            worker_park_count: metrics.worker_park_count(0),
            worker_busy_duration: metrics.worker_total_busy_duration(0),
            #[cfg(tokio_unstable)]
            worker_noop_count: metrics.worker_noop_count(0),
            #[cfg(tokio_unstable)]
            worker_steal_count: metrics.worker_steal_count(0),
        }
    }

    /// 推平为 Prometheus 文本片段（key=value 对，空格分隔）。
    ///
    /// `runtime_guard_*` 前缀与既有 `xray_*` metric 命名风格对齐；
    /// 调用方负责加注释/行尾换行。
    pub fn to_prometheus(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push_str(&format!("runtime_guard_worker_count {}\n", self.worker_count));
        s.push_str(&format!("runtime_guard_alive_tasks {}\n", self.alive_tasks));
        s.push_str(&format!(
            "runtime_guard_global_queue_depth {}\n",
            self.global_queue_depth
        ));
        s.push_str(&format!(
            "runtime_guard_worker_park_count {}\n",
            self.worker_park_count
        ));
        s.push_str(&format!(
            "runtime_guard_worker_busy_duration_seconds {:.6}\n",
            self.worker_busy_duration.as_secs_f64()
        ));
        #[cfg(tokio_unstable)]
        {
            s.push_str(&format!(
                "runtime_guard_worker_noop_count {}\n",
                self.worker_noop_count
            ));
            s.push_str(&format!(
                "runtime_guard_worker_steal_count {}\n",
                self.worker_steal_count
            ));
        }
        s
    }
}

/// 抓取当前 runtime 的 metrics 快照并以 `tracing::info!` 输出。
///
/// 启动期一次性调用，便于日志归档 worker 行为基线。无返回值，失败仅记 warn。
pub fn log_runtime_snapshot(prefix: &str) {
    match Handle::try_current() {
        Ok(handle) => {
            let snap = RuntimeMetricsSnapshot::capture(&handle);
            // 先把 cfg-gated 字段拍平成本地变量，避免 `#[cfg]` 出现在
            // tracing 宏的表达式位置（不稳定，rust#15701）。
            let worker_noop_count: u64 = {
                #[cfg(tokio_unstable)]
                {
                    snap.worker_noop_count
                }
                #[cfg(not(tokio_unstable))]
                {
                    0
                }
            };
            let worker_steal_count: u64 = {
                #[cfg(tokio_unstable)]
                {
                    snap.worker_steal_count
                }
                #[cfg(not(tokio_unstable))]
                {
                    0
                }
            };
            tracing::info!(
                target: "xray_runtime_guard",
                prefix = %prefix,
                worker_count = snap.worker_count,
                alive_tasks = snap.alive_tasks,
                global_queue_depth = snap.global_queue_depth,
                worker_park_count = snap.worker_park_count,
                worker_busy_duration_ms = snap.worker_busy_duration.as_millis() as u64,
                worker_noop_count,
                worker_steal_count,
                "runtime metrics snapshot: {}",
                snap.to_prometheus().trim_end()
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "xray_runtime_guard",
                "log_runtime_snapshot: no current tokio handle ({e})"
            );
        }
    }
}

// ponytail: 若未来加采样任务，这里只断言结构 + 计数增量；不要耦合具体数值。
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::{Duration as TokioDuration, sleep};

    /// current_thread runtime 上 sleep 让 worker park 一次；抓两次快照验证
    /// `worker_park_count` 单调递增。
    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_worker_park_count_increases_after_idle() {
        let before = RuntimeMetricsSnapshot::capture(&Handle::current());
        sleep(TokioDuration::from_millis(20)).await;
        let after = RuntimeMetricsSnapshot::capture(&Handle::current());
        assert!(
            after.worker_park_count >= before.worker_park_count,
            "park count must be non-decreasing (before={}, after={})",
            before.worker_park_count,
            after.worker_park_count,
        );
        assert_eq!(after.worker_count, 1, "current_thread runtime has 1 worker");
    }

    /// 多线程 runtime 上 spawn 一次 task，让 worker 在调度间隙 park 至少一次。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_thread_runtime_captures_park_and_busy_duration() {
        let before = RuntimeMetricsSnapshot::capture(&Handle::current());
        let h = tokio::spawn(async {
            sleep(TokioDuration::from_millis(15)).await;
        });
        h.await.unwrap();
        sleep(TokioDuration::from_millis(20)).await;
        let after = RuntimeMetricsSnapshot::capture(&Handle::current());
        assert_eq!(after.worker_count, 2, "explicit worker_threads = 2");
        assert!(
            after.worker_park_count >= before.worker_park_count,
            "park count must be non-decreasing",
        );
        assert!(
            after.worker_busy_duration >= before.worker_busy_duration,
            "busy duration must be non-decreasing",
        );
    }

    /// `log_runtime_snapshot` 在有 current handle 时不 panic。
    #[tokio::test(flavor = "current_thread")]
    async fn log_runtime_snapshot_emit_under_current_thread() {
        log_runtime_snapshot("unit-test");
        // 无断言：唯一契约是不 panic。tracing subscriber 默认无 + panic 即失败。
    }

    /// busy_duration 是 `Duration` 类型；并发任务下也能 capture 不报错。
    #[tokio::test(flavor = "current_thread")]
    async fn worker_busy_duration_capture_under_concurrent_task() {
        let captured = Arc::new(AtomicU64::new(0));
        let c2 = captured.clone();
        let _h = tokio::spawn(async move {
            let snap = RuntimeMetricsSnapshot::capture(&Handle::current());
            c2.store(snap.worker_busy_duration.as_nanos() as u64, Ordering::SeqCst);
        });
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let snap = RuntimeMetricsSnapshot::capture(&Handle::current());
        // 仅 smoke：capture 不 panic 且字段可读。具体数值受调度器影响不固定。
        let _ = captured.load(Ordering::SeqCst);
        let _ = snap.worker_busy_duration;
    }
}
