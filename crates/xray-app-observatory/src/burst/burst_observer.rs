//! BurstObserver：对应 Go `app/observatory/burst/burstobserver.go` 的 Observer。
//!
//! 实装三件套（对齐 Go）：
//! - `Check`（按需立即探测，对应 Go `healthping.go:148-155`）——
//!   `proxy/vless/inbound/inbound.go:664-666` 新 worker 注册后调用。
//! - `start_scheduler`（后台 ticker + 初始快测，对应 Go `healthping.go:91-135`）—— 周期 = `interval
//!   × sampling_count`；每 tick `do_check(rounds=sampling_count)`； `cancel_pending` 原子 swap
//!   取消上轮未完成的 do_check；tick 末尾 `Cleanup`。
//! - `create_result` / `get_observation`（对应 Go `burstobserver.go:30-62`）—— 返回
//!   `Vec<OutboundStatus>` 含 6 字段 `health_ping`，`alive = All != Fail`。
//!
//! Rust 此处将 Go 的 `HealthPing` 直接合入 `BurstObserver`（原 Rust 设计已扁平化
//! Results map，避免双层 Mutex）。scheduler 与 Results 共用 `Mutex` 互斥。
//!
//! ## IO 边界
//! - HTTP probe：`Arc<dyn ProbeExecutor>` 注入（sync trait，对应 Go `newPingClient.MeasureDelay`）
//! - tag 选择：scheduler 启动时注入 `TagSelector` 闭包 （对齐 Go
//!   `outbound.HandlerSelector.Select`）
//!
//! 非目标：HTTP method 维度探测（Go `HealthPingSettings.HttpMethod`）、
//! checkConnectivity（网络断开判定）、真 outbound 拨号。

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicPtr, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;

use super::{HealthPingRtts, HealthPingSettings, RTT_FAILED};
use crate::{
    config::{HealthPingMeasurement, ObservationResult, OutboundStatus},
    observer::ProbeExecutor,
};

/// 当前 Unix 时间（纳秒），与 healthping_stats 时间单位一致。
fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

/// Scheduler 状态：start_scheduler 后填充，stop_scheduler 后清空。
struct SchedulerHandle {
    /// watch channel sender：stop_scheduler 写 true 通知主循环退出。
    shutdown: tokio::sync::watch::Sender<bool>,
}
/// tag 选择回调（对应 Go `selector func() ([]string, error)`）。
pub type TagSelector = Arc<dyn Fn() -> Vec<String> + Send + Sync + 'static>;

/// Burst 观察者：按需 Check + 后台 scheduler + per-tag RTT 样本表。
///
/// 对应 Go `burst.Observer` + `HealthPing` 合并语义：
/// - `rtts` = Go `HealthPing.Results`（tag → 环形缓冲）
/// - `access`（Mutex）= Go `HealthPing.access`（读写 Results 时持有）
/// - `cancel_pending` = Go `HealthPing.cancelPending`
pub struct BurstObserver {
    settings: HealthPingSettings,
    rtts: Mutex<HashMap<String, HealthPingRtts>>,
    capacity: usize,
    validity_nanos: i64,
    /// cancel-pending 原子指针（Go `atomic.Pointer[context.CancelFunc]` 等价）。
    /// 仅作"新一轮覆盖"的占位标记——do_check 不实际监听此值（生产路径下
    /// 上一轮 do_check 的探测由 ProbeExecutor 同步返回，不会真正悬挂）。
    cancel_pending: AtomicPtr<()>,
    /// scheduler 句柄。None 表示未启动。
    scheduler: Mutex<Option<SchedulerHandle>>,
}

impl BurstObserver {
    /// 从 HealthPingSettings 构造。
    ///
    /// 容量 = `sampling_count`；有效期对应 Go `healthping.go:246`：
    /// `validity = interval * SamplingCount * 2`（采样在时间线上随机分布，
    /// 极端情况下早期检查偏左、晚期偏右，故取 2 倍采样周期）。
    pub fn new(settings: HealthPingSettings) -> Self {
        let capacity = settings.sampling_count.max(1) as usize;
        let validity_nanos = settings.interval * settings.sampling_count.max(1) as i64 * 2;
        Self {
            settings,
            rtts: Mutex::new(HashMap::new()),
            capacity,
            validity_nanos,
            cancel_pending: AtomicPtr::new(std::ptr::null_mut()),
            scheduler: Mutex::new(None),
        }
    }

    /// 获取归一化后的运行时设置（对应 Go `HealthPing.Settings`）。
    pub fn settings(&self) -> &HealthPingSettings {
        &self.settings
    }

    /// 对应 Go `Observer.Check(tag []string)`：对给定 tag 立即执行一轮探测。
    ///
    /// Go 语义（healthping.go:148-155）：
    /// - tags 为空 → no-op；
    /// - 否则 `doCheck(ctx, tags, 0, 1)`——每个 tag 探测一轮，RTT 记入样本表。
    pub fn check(&self, tags: &[String], executor: &dyn ProbeExecutor) -> HashMap<String, i64> {
        if tags.is_empty() {
            return HashMap::new(); // Go healthping.go:149-151：空 tags no-op
        }
        let now = now_unix_nanos();
        // 锁外探测（对齐 Go doCheck：MeasureDelay 不持 access 锁）。
        let mut results = Vec::with_capacity(tags.len());
        for tag in tags {
            let result = executor.probe(tag);
            let rtt = if result.alive { result.delay } else { RTT_FAILED };
            results.push((tag.clone(), rtt));
        }
        // 短临界区：仅结果写回（对齐 Go PutResult）。
        let mut g = self.rtts.lock();
        let mut out = HashMap::with_capacity(results.len());
        for (tag, rtt) in results {
            let entry = g
                .entry(tag.clone())
                .or_insert_with(|| HealthPingRtts::new(self.capacity, self.validity_nanos));
            entry.put(rtt, now);
            out.insert(tag, rtt);
        }
        out
    }

    /// 查某 tag 最新 RTT 样本：
    /// - 无样本（从未 check 过）→ `None`；
    /// - 有样本 → 最新写入值（可能是 `RTT_FAILED` 哨兵，用 [`super::is_valid_rtt`] 判断有效性）。
    pub fn latest_rtt(&self, tag: &str) -> Option<i64> {
        self.rtts.lock().get(tag)?.latest()
    }

    // ===========================================================================
    // 调度器：对应 Go `HealthPing.StartScheduler` / `StopScheduler` / `doCheck`
    // ===========================================================================

    /// 启动后台调度循环（对应 Go `healthping.go:91-135`）。
    ///
    /// 行为：
    /// 1. 已启动 → no-op（幂等）；
    /// 2. ticker 周期 = `interval × sampling_count`；
    /// 3. 初始快测：立即调用一次 `selector` 并 check（Go healthping.go:99-107）；
    /// 4. 主循环：每 tick 执行 `do_check(rounds=sampling_count)` 后 `cleanup`；
    /// 5. `cancel_pending` 原子 swap：新一轮覆盖旧 cancel（Go healthping.go:118-122）。
    pub fn start_scheduler(
        self: Arc<Self>,
        selector: TagSelector,
        executor: Arc<dyn ProbeExecutor>,
    ) {
        let mut g = self.scheduler.lock();
        if g.is_some() {
            return; // Go healthping.go:92-94：已启动直接返回
        }
        let interval = Duration::from_nanos(
            (self.settings.interval * self.settings.sampling_count as i64) as u64,
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        g.replace(SchedulerHandle { shutdown: shutdown_tx });
        drop(g);

        // 初始快测（Go healthping.go:99-107）
        let tags = selector();
        if !tags.is_empty() {
            let _ = self.check(&tags, executor.as_ref());
        }

        // 主循环（Go healthping.go:109-134）
        let observer = self.clone();
        let selector_for_loop = selector.clone();
        let executor_for_loop = executor.clone();
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    _ = ticker.tick() => {
                        let tags = selector_for_loop();
                        if tags.is_empty() {
                            continue;
                        }
                        // 新一轮 cancel-pending swap：覆盖旧 cancel（占位语义）
                        let new_cancel = Box::into_raw(Box::new(()));
                        let _ = observer.cancel_pending.swap(new_cancel, Ordering::AcqRel);
                        observer.do_check(&tags, executor_for_loop.as_ref());
                        let _ = observer.cancel_pending.compare_exchange(
                            new_cancel,
                            std::ptr::null_mut(),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        observer.cleanup(&tags);
                    }
                }
            }
        });
    }

    /// 停止后台调度循环（对应 Go `healthping.go:138-145`）。
    ///
    /// 未启动 → no-op。已启动 → 通知循环退出 + 清空 handle。
    pub fn stop_scheduler(&self) {
        let mut g = self.scheduler.lock();
        if let Some(h) = g.take() {
            let _ = h.shutdown.send(true);
        }
    }

    /// 是否已启动 scheduler。
    pub fn is_scheduler_running(&self) -> bool {
        self.scheduler.lock().is_some()
    }

    /// do_check：对应 Go `healthping.go:165-231`。
    ///
    /// 每个 tag × rounds 个 ping，结果写入 Results 表。
    /// rounds = sampling_count（由 settings 提供）。
    ///
    /// 锁形态对齐 Go `doCheck`/`PutResult`：探测（`executor.probe`，同步阻塞
    /// 最坏 connect-timeout 5s/次）在 `rtts` 锁外执行，临界区仅覆盖结果写回——
    /// 否则 `create_result` 等读者会被 `tags × rounds × 5s` 量级的探测整段堵死。
    ///
    /// 取消语义：`cancel_pending` 标记新一轮已覆盖——每轮探测前检查自身是否
    /// 已被覆盖，若是则提前退出；已探测完成的样本仍写回（对齐 Go 每轮
    /// `PutResult` 即时落表的语义）。
    pub fn do_check(&self, tags: &[String], executor: &dyn ProbeExecutor) {
        if tags.is_empty() {
            return; // Go healthping.go:167-169：count==0 早退
        }
        let rounds = self.settings.sampling_count.max(1) as usize;
        // 记录入口时的 cancel-pending 标记，逐轮比对：
        // 若被覆盖则提前退出（对应 Go healthping.go:217-229）。
        let entry_cancel = self.cancel_pending.load(Ordering::Acquire);
        let now = now_unix_nanos();
        // 锁外探测：收集 (tag, samples)，probe 不持 rtts 锁。
        let mut collected: Vec<(String, Vec<i64>)> = Vec::with_capacity(tags.len());
        let mut cancelled = false;
        for tag in tags {
            let mut samples = Vec::with_capacity(rounds);
            for _ in 0..rounds {
                if self.cancel_pending.load(Ordering::Acquire) != entry_cancel {
                    // 上轮已被新轮覆盖，提前退出；已完成轮次的样本保留
                    // （Go 每轮探测完立即 PutResult，已完成样本已入表）。
                    cancelled = true;
                    break;
                }
                // 真实探测：probe → rtt = alive ? delay : RTT_FAILED
                let result = executor.probe(tag);
                let rtt = if result.alive { result.delay } else { RTT_FAILED };
                samples.push(rtt);
            }
            collected.push((tag.clone(), samples));
            if cancelled {
                break; // Go healthping.go:224-228
            }
        }
        // 短临界区：仅结果写回（对齐 Go PutResult 的 access 锁范围）。
        let mut g = self.rtts.lock();
        for (tag, samples) in collected {
            let entry = g
                .entry(tag)
                .or_insert_with(|| HealthPingRtts::new(self.capacity, self.validity_nanos));
            for rtt in samples {
                entry.put(rtt, now);
            }
        }
    }

    /// Cleanup（对应 Go `healthping.go:255-270`）：删除 Results 中
    /// 不在 tags 列表里的 tag 条目。
    pub fn cleanup(&self, tags: &[String]) {
        let mut g = self.rtts.lock();
        let keep: std::collections::HashSet<&String> = tags.iter().collect();
        g.retain(|tag, _| keep.contains(tag));
    }

    /// do_check 接受 duration 参数版本（兼容 Go `doCheck(ctx, tags, duration, rounds)`）。
    ///
    /// 当前实装未使用 duration 做随机延迟分布——保留为兼容性方法。
    #[doc(hidden)]
    pub fn do_check_with_duration(
        &self,
        tags: &[String],
        executor: &dyn ProbeExecutor,
        _duration: Duration,
    ) {
        self.do_check(tags, executor);
    }

    // ===========================================================================
    // 观测快照：对应 Go `Observer.createResult` / `Observer.GetObservation`
    // ===========================================================================

    /// 拍快照（对应 Go `burstobserver.go:38-62 createResult`）。
    ///
    /// 遍历 `Results` 表，每条生成 `OutboundStatus`：
    /// - `alive = All != Fail`（Go burstobserver.go:44）
    /// - `delay = average.Milliseconds()`（Go burstobserver.go:45，纳秒→毫秒）
    /// - `health_ping` 含 All/Fail/Deviation/Average/Max/Min 6 字段 （Go burstobserver.go:50-57）
    /// - `last_seen_time` / `last_try_time` / `last_error_reason` 留默认（Go 端恒为 0/""）
    pub fn create_result(&self) -> Vec<OutboundStatus> {
        let now = now_unix_nanos();
        let g = self.rtts.lock();
        let mut result = Vec::with_capacity(g.len());
        for (name, value) in g.iter() {
            let stats = value.statistics(now);
            let alive = stats.all != stats.fail;
            // Go 端用 `time.Duration.Milliseconds()`：纳秒→毫秒（i64）。
            // Rust 直接除 1_000_000（纳秒→毫秒）。
            let delay_ms = stats.average / 1_000_000;
            result.push(OutboundStatus {
                alive,
                delay: delay_ms,
                last_error_reason: String::new(),
                outbound_tag: name.clone(),
                last_seen_time: 0,
                last_try_time: 0,
                health_ping: Some(HealthPingMeasurement {
                    all: stats.all,
                    fail: stats.fail,
                    deviation: stats.deviation,
                    average: stats.average,
                    max: stats.max,
                    min: stats.min,
                }),
            });
        }
        result
    }

    /// 全量观测快照（对应 Go `burstobserver.go:30-32 GetObservation`）。
    pub fn get_observation(&self) -> ObservationResult {
        ObservationResult { status: self.create_result() }
    }
}

impl Drop for BurstObserver {
    fn drop(&mut self) {
        // 通知 scheduler 退出，避免泄漏的 spawn 任务访问已 drop 的 self。
        if let Some(h) = self.scheduler.lock().take() {
            let _ = h.shutdown.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ProbeResult, observer::FixedProbeExecutor};

    fn observer_with_interval(sampling_count: i32, interval: i64) -> Arc<BurstObserver> {
        let settings =
            HealthPingSettings { interval, sampling_count, ..HealthPingSettings::default() };
        Arc::new(BurstObserver::new(settings))
    }

    fn alive(delay: i64) -> ProbeResult {
        ProbeResult { alive: true, delay, last_error_reason: String::new() }
    }

    fn dead(reason: &str) -> ProbeResult {
        ProbeResult { alive: false, delay: 0, last_error_reason: reason.into() }
    }

    #[test]
    fn check_empty_tags_is_noop_and_no_sample() {
        let obs = observer_with_interval(3, 60_000_000_000);
        assert!(obs.latest_rtt("never-checked").is_none());
        let executor = FixedProbeExecutor::new().with_result("a", alive(10));
        let out = obs.check(&[], &executor);
        assert!(out.is_empty());
        assert!(obs.latest_rtt("a").is_none());
    }

    #[test]
    fn check_records_rtt_sample() {
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("out-a", alive(50));
        let out = obs.check(&["out-a".to_string()], &executor);
        assert_eq!(out.get("out-a"), Some(&50));
        assert_eq!(obs.latest_rtt("out-a"), Some(50));
    }

    #[test]
    fn check_failed_probe_records_sentinel() {
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("out-dead", dead("timeout"));
        let out = obs.check(&["out-dead".to_string()], &executor);
        assert_eq!(out.get("out-dead"), Some(&RTT_FAILED));
        assert!(!super::super::is_valid_rtt(obs.latest_rtt("out-dead").unwrap()));
    }

    #[test]
    fn latest_reflects_most_recent_sample() {
        let obs = observer_with_interval(3, 60_000_000_000);
        let first = FixedProbeExecutor::new().with_result("t", alive(30));
        obs.check(&["t".to_string()], &first);
        let second = FixedProbeExecutor::new().with_result("t", alive(70));
        obs.check(&["t".to_string()], &second);
        assert_eq!(obs.latest_rtt("t"), Some(70));
    }

    #[test]
    fn new_derives_capacity_from_settings() {
        let obs = observer_with_interval(5, 10_000_000_000);
        for expected in 1..=5i64 {
            let e = FixedProbeExecutor::new().with_result("t", alive(expected));
            obs.check(&["t".to_string()], &e);
            assert_eq!(obs.latest_rtt("t"), Some(expected));
        }
    }

    // ===========================================================================
    // create_result / get_observation 测试
    // ===========================================================================

    #[test]
    fn create_result_populates_six_health_ping_fields() {
        // 对应 Go burstobserver.go:50-57：6 字段全填充
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("out-a", alive(50_000_000)); // 50ms in nanos
        obs.check(&["out-a".to_string()], &executor);

        let statuses = obs.create_result();
        assert_eq!(statuses.len(), 1);
        let s = &statuses[0];
        assert_eq!(s.outbound_tag, "out-a");
        assert!(s.alive, "All(1) != Fail(0) → alive=true");
        assert_eq!(s.delay, 50, "50ms = 50_000_000ns / 1_000_000");
        let hp = s.health_ping.as_ref().expect("health_ping must be set");
        assert_eq!(hp.all, 1);
        assert_eq!(hp.fail, 0);
        // average = 50ms in nanos
        assert_eq!(hp.average, 50_000_000);
        assert_eq!(hp.max, 50_000_000);
        assert_eq!(hp.min, 50_000_000);
    }

    #[test]
    fn create_result_alive_false_when_all_failed() {
        // 对应 Go burstobserver.go:44：All == Fail → alive=false
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("out-dead", dead("timeout"));
        obs.check(&["out-dead".to_string()], &executor);

        let statuses = obs.create_result();
        let s = &statuses[0];
        assert!(!s.alive, "All(1) == Fail(1) → alive=false");
        assert_eq!(s.health_ping.as_ref().unwrap().fail, 1);
    }

    #[test]
    fn create_result_empty_when_no_samples() {
        // 对应 Go burstobserver.go:38-62：Results 为空 → 返回空 Vec
        let obs = observer_with_interval(3, 60_000_000_000);
        assert!(obs.create_result().is_empty());
    }

    #[test]
    fn get_observation_wraps_create_result() {
        // 对应 Go burstobserver.go:30-32：ObservationResult{Status: createResult()}
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new()
            .with_result("a", alive(10_000_000))
            .with_result("b", dead("x"));
        obs.check(&["a".to_string(), "b".to_string()], &executor);

        let result = obs.get_observation();
        assert_eq!(result.status.len(), 2);
        let tags: std::collections::HashSet<&str> =
            result.status.iter().map(|s| s.outbound_tag.as_str()).collect();
        assert!(tags.contains("a"));
        assert!(tags.contains("b"));
    }

    #[test]
    fn create_result_delay_converts_nanos_to_millis() {
        // 对应 Go burstobserver.go:45：Average.Milliseconds()
        // 999_000_000 ns = 999ms (truncated, 与 Go Milliseconds() 一致)
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("t", alive(999_000_000));
        obs.check(&["t".to_string()], &executor);
        assert_eq!(obs.create_result()[0].delay, 999);
    }

    // ===========================================================================
    // scheduler 测试
    // ===========================================================================

    #[tokio::test]
    async fn scheduler_idempotent() {
        let obs = observer_with_interval(2, 60_000_000_000);
        let s: TagSelector = Arc::new(|| vec!["a".to_string()]);
        let e: Arc<dyn ProbeExecutor> = Arc::new(FixedProbeExecutor::new());
        obs.clone().start_scheduler(s.clone(), e.clone());
        obs.clone().start_scheduler(s, e); // 第二次无副作用
        assert!(obs.is_scheduler_running());
        obs.stop_scheduler();
    }

    #[test]
    fn scheduler_stop_when_not_started_is_noop() {
        // 对应 Go healthping.go:139-141：未启动 → 直接返回
        let obs = observer_with_interval(2, 60_000_000_000);
        obs.stop_scheduler();
        assert!(!obs.is_scheduler_running());
    }

    #[test]
    fn do_check_writes_samples_for_each_tag_round() {
        // 对应 Go healthping.go:165-231：每个 (tag, round) 写入一条样本
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("a", alive(100));
        obs.do_check(&["a".to_string(), "b".to_string()], &executor);
        let a_stats =
            obs.rtts.lock().get("a").expect("a should have samples").statistics(now_unix_nanos());
        assert_eq!(a_stats.all, 3);
        assert_eq!(a_stats.fail, 0);
    }

    #[test]
    fn do_check_empty_tags_is_noop() {
        // 对应 Go healthping.go:167-169：count==0 早退
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new();
        obs.do_check(&[], &executor);
        assert!(obs.rtts.lock().is_empty());
    }

    #[test]
    fn cleanup_removes_tags_not_in_list() {
        // 对应 Go healthping.go:255-270：不在 tags 列表的 tag 条目被删除
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new()
            .with_result("keep-a", alive(10))
            .with_result("keep-b", alive(20))
            .with_result("remove-me", alive(30));
        obs.check(&["keep-a".into(), "keep-b".into(), "remove-me".into()], &executor);
        assert!(obs.latest_rtt("remove-me").is_some());

        obs.cleanup(&["keep-a".into(), "keep-b".into()]);
        assert!(obs.latest_rtt("keep-a").is_some());
        assert!(obs.latest_rtt("keep-b").is_some());
        assert!(obs.latest_rtt("remove-me").is_none());
    }

    #[test]
    fn cleanup_empty_keeps_nothing() {
        // 对应 Go healthping.go：tags=[] 触发全部清理（极端情况）
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = FixedProbeExecutor::new().with_result("a", alive(10));
        obs.check(&["a".into()], &executor);
        obs.cleanup(&[]);
        assert!(obs.latest_rtt("a").is_none());
    }

    // ===========================================================================
    // 锁形态测试：probe 必须在 rtts 锁外执行（对齐 Go doCheck/PutResult）
    // ===========================================================================

    /// probe 内断言 rtts 锁此刻空闲——若 do_check/check 在临界区内调用 probe，
    /// parking_lot Mutex 不可重入，try_lock 必返回 None 使断言失败。
    struct LockAssertingExecutor {
        observer: Arc<BurstObserver>,
        context: &'static str,
    }

    impl ProbeExecutor for LockAssertingExecutor {
        fn probe(&self, _tag: &str) -> ProbeResult {
            assert!(
                self.observer.rtts.try_lock().is_some(),
                "probe must run outside the rtts lock ({})",
                self.context
            );
            alive(1)
        }
    }

    #[test]
    fn do_check_probe_runs_outside_rtts_lock() {
        let obs = observer_with_interval(2, 60_000_000_000);
        let executor = LockAssertingExecutor { observer: obs.clone(), context: "do_check" };
        obs.do_check(&["a".to_string(), "b".to_string()], &executor);
    }

    #[test]
    fn check_probe_runs_outside_rtts_lock() {
        let obs = observer_with_interval(2, 60_000_000_000);
        let executor = LockAssertingExecutor { observer: obs.clone(), context: "check" };
        obs.check(&["a".to_string()], &executor);
    }

    #[test]
    fn do_check_cancel_keeps_collected_samples_and_stops() {
        // 取消后：已完成轮次的样本写回、未完成轮次不再探测（对齐 Go 每轮
        // PutResult 即时落表 + cancelPending 提前退出）。
        struct CancelAfterSecondProbe {
            observer: Arc<BurstObserver>,
            probes: std::sync::atomic::AtomicUsize,
        }
        impl ProbeExecutor for CancelAfterSecondProbe {
            fn probe(&self, _tag: &str) -> ProbeResult {
                if self.probes.fetch_add(1, Ordering::SeqCst) == 1 {
                    // 第二轮完成后覆盖 cancel-pending，模拟新一轮到来
                    let new_cancel = Box::into_raw(Box::new(()));
                    let _ = self.observer.cancel_pending.swap(new_cancel, Ordering::AcqRel);
                }
                alive(7)
            }
        }
        let obs = observer_with_interval(3, 60_000_000_000);
        let executor = CancelAfterSecondProbe {
            observer: obs.clone(),
            probes: std::sync::atomic::AtomicUsize::new(0),
        };
        obs.do_check(&["a".to_string()], &executor);
        assert_eq!(executor.probes.load(Ordering::SeqCst), 2, "取消后不再继续探测第 3 轮");
        let stats =
            obs.rtts.lock().get("a").expect("已完成轮次的样本应写回").statistics(now_unix_nanos());
        assert_eq!(stats.all, 2, "已完成轮次的 2 条样本保留");
    }
}
