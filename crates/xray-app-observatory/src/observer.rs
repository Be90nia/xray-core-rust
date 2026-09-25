//! Observer 编排 + ProbeExecutor / OutboundSelector / Scheduler 注入 trait。
//!
//! 对应 Go `app/observatory/observer.go` 的 `Observer` struct + background loop。
//! 实际 HTTP probe + dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

// 4d7t：plain observatory 的 GET 语义不再从 burst healthping 借常量——
// 两套判定口径在此分离（见 HttpProbeExecutor::check_status）。
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::watch,
};
use xray_app_dispatcher::DefaultDispatcher;
use xray_buf::{
    io::{Reader as BufReader, Writer as BufWriter},
    multi::MultiBuffer,
};
use xray_transport::{connection::Connection, link::Link};

use crate::{
    config::{ObservationResult, ObservatoryConfig, ProbeResult},
    error::{ObservatoryError, at_error},
    status::StatusStore,
};

/// OutboundSelector trait：返回受观察的 outbound tag 列表。
///
/// 对应 Go `outbound.HandlerSelector.Select(subjectSelector)`。
pub trait OutboundSelector: Send + Sync {
    fn select(&self, subject_selector: &[String]) -> Result<Vec<String>, ObservatoryError>;
}

/// ProbeExecutor trait：对单个 outbound 执行一次 probe。
///
/// 对应 Go `Observer.probe(outbound)`：通过 tagged.Dialer + http.Client 探测一次。
pub trait ProbeExecutor: Send + Sync {
    fn probe(&self, outbound_tag: &str) -> ProbeResult;
}

/// 当前 Unix 时间（秒），用于 status 时间戳。
pub fn now_unix_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 对给定 tag 集合探测一轮（阻塞调用线程直到全部完成），返回是否任一存活。
///
/// 对应 Go `Observer.background()` 单轮探测部分（observer.go:81-110）。
/// `enable_concurrency` 为 true 时并行：每个 tag 起独立线程探测（Go
/// goroutine ↔ std::thread::spawn，scoped thread 借用非 'static 的 executor
/// 引用）；否则串行。4j5m：观察循环经 spawn_blocking 在独立线程池调用本函数，
/// runtime worker 不被同步 probe 占用。
fn probe_round_blocking(
    tags: &[String],
    executor: &dyn ProbeExecutor,
    status: &StatusStore,
    enable_concurrency: bool,
    now: i64,
) -> bool {
    let mut any_alive = false;
    if enable_concurrency {
        let results = std::thread::scope(|s| {
            let handles: Vec<_> = tags
                .iter()
                .map(|tag| {
                    let tag = tag.clone();
                    s.spawn(move || {
                        let result = executor.probe(&tag);
                        (tag, result)
                    })
                })
                .collect();
            handles
                .into_iter()
                // join 失败（panic）→ None，调用方跳过该 tag
                .map(|h| h.join().ok())
                .collect::<Vec<_>>()
        });
        for (tag, result) in results.into_iter().flatten() {
            any_alive |= result.alive;
            status.update_with_probe_result(&tag, &result, now);
        }
    } else {
        for tag in tags {
            let result = executor.probe(tag);
            any_alive |= result.alive;
            status.update_with_probe_result(tag, &result, now);
        }
    }
    any_alive
}

/// 失败轮的 linear backoff 倍数：连续失败 n 轮 → n+1 倍间隔，上限 8。
///
/// Go `background()` 固定 sleepTime（observer.go:76-79），无退避；
/// 任务要求 linear 失败退避（完整指数退避为 non-goal）。
pub fn backoff_multiplier(consecutive_failures: u32) -> u32 {
    consecutive_failures.saturating_add(1).min(8)
}

/// Observer：观察者编排类。
///
/// 持有 config + StatusStore + IO 注入 trait，编排：
///   - `probe_all(selector, executor)`：执行一轮探测（并发或串行由调用方决定）
///   - `get_observation()`：返回当前快照
///   - `clear_removed_outbounds(tags)`：清理已移除的 outbound
pub struct Observer {
    config: ObservatoryConfig,
    status: Arc<StatusStore>,
    state: Mutex<ObserverState>,
}

struct ObserverState {
    started: bool,
    cancel_tx: Option<watch::Sender<bool>>,
}

impl Observer {
    pub fn new(config: ObservatoryConfig) -> Self {
        Self {
            config,
            status: Arc::new(StatusStore::new()),
            state: Mutex::new(ObserverState { started: false, cancel_tx: None }),
        }
    }

    pub fn config(&self) -> &ObservatoryConfig {
        &self.config
    }

    pub fn status_store(&self) -> &Arc<StatusStore> {
        &self.status
    }

    /// 启动后台定期探测循环（同步：spawn 不需要 await）。
    ///
    /// 对应 Go `Observer.Start()`（observer.go:49-55）：SubjectSelector 非空才
    /// `go background()`；background（observer.go:64-113）每轮先 probe 后 sleep
    /// ProbeInterval（默认 10s）。
    ///
    /// 与 Go 的差异：连续失败轮（select 出错或全部 probe 死亡）触发 linear
    /// backoff——睡眠时长 = interval × [`backoff_multiplier`]（Go 固定 interval）。
    pub fn start(
        &self,
        selector: Arc<dyn OutboundSelector>,
        executor: Arc<dyn ProbeExecutor>,
    ) -> Result<(), ObservatoryError> {
        let mut g = self.state.lock();
        if g.started {
            return Err(ObservatoryError::AlreadyStarted);
        }
        if self.config.subject_selector.is_empty() {
            // 与 Go 一致（observer.go:50）：subject_selector 为空时不启动 background
            return Ok(());
        }
        g.started = true;

        let (cancel_tx, cancel_rx) = watch::channel(false);
        g.cancel_tx = Some(cancel_tx);
        drop(g);

        let interval_ms = self.config.effective_probe_interval_ms() as u64;
        let subject_selector = self.config.subject_selector.clone();
        let status = self.status.clone();
        let enable_concurrency = self.config.enable_concurrency;
        tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            let mut fail_streak: u32 = 0;
            loop {
                let round_failed = match selector.select(&subject_selector) {
                    Ok(tags) => {
                        status.clear_removed(&tags);
                        let now = now_unix_secs();
                        // 4j5m：probe 是同步阻塞契约（内部自建线程 + 独立
                        // runtime）。此前逐 tag 串行直调，async task 所在的
                        let exec = executor.clone();
                        let st = status.clone();
                        let tags_empty = tags.is_empty();
                        let any_alive = tokio::task::spawn_blocking(move || {
                            probe_round_blocking(&tags, exec.as_ref(), &st, enable_concurrency, now)
                        })
                        .await
                        .unwrap_or_else(|e| {
                            tracing::warn!("observatory probe round panicked: {e:?}");
                            false
                        });
                        // tags 非空且无一存活才算失败轮（空列表按正常间隔）
                        !tags_empty && !any_alive
                    },
                    Err(e) => {
                        at_error(&e);
                        true
                    },
                };

                fail_streak = if round_failed { fail_streak.saturating_add(1) } else { 0 };
                let delay =
                    Duration::from_millis(interval_ms * backoff_multiplier(fail_streak) as u64);
                tokio::select! {
                    // biased：cancel 恒优先——否则 cancel 与 sleep 同时 ready 时
                    // select 随机选 sleep 分支会多 probe 一轮（close 语义破坏）。
                    biased;
                    changed = cancel_rx.changed() => {
                        let _ = changed; // 关闭或 sender drop 均退出
                        break;
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        });

        Ok(())
    }

    /// 停止后台探测循环（对应 Go `Observer.Close()` → finished.Close()）。
    pub fn close(&self) -> Result<(), ObservatoryError> {
        let mut g = self.state.lock();
        if let Some(tx) = g.cancel_tx.take() {
            let _ = tx.send(true);
        }
        g.started = false;
        Ok(())
    }

    pub fn is_started(&self) -> bool {
        self.state.lock().started
    }

    /// 执行一轮探测：对 selector 返回的所有 tag 探测 + 更新 status。
    ///
    /// 这是同步阻塞版本，调用方可在 tokio::task::spawn_blocking 中执行。
    /// 对应 Go `background` 单轮的逻辑（不包含 sleep 循环）。
    ///
    /// `EnableConcurrency` 为 true 时按 Go observer.go:94-110 路径并行探测；
    /// 否则串行（observer.go:81-92）。探测量大场景（几十个 outbound）下
    /// 并行把 N×latency 压到 max(latency)。
    pub fn probe_all(
        &self,
        selector: &dyn OutboundSelector,
        executor: &dyn ProbeExecutor,
    ) -> Result<usize, ObservatoryError> {
        let tags = selector.select(&self.config.subject_selector)?;
        self.probe_tags(&tags, executor);
        Ok(tags.len())
    }

    /// 对给定 tag 集合探测一轮，按 `enable_concurrency` 决定串/并行。
    ///
    /// 对应 Go `Observer.background()` 单轮探测部分（observer.go:81-110）。
    /// 并行路径与 Go 一致：每个 tag 起独立线程探测（Go goroutine ↔
    /// std::thread::spawn），主循环在所有线程 join 后退出。
    pub fn probe_tags(&self, tags: &[String], executor: &dyn ProbeExecutor) {
        // 先清理已移除的 outbound（仅对"存活"集合——空集时等价 noop）
        self.status.clear_removed(tags);
        if tags.is_empty() {
            return;
        }
        probe_round_blocking(
            tags,
            executor,
            &self.status,
            self.config.enable_concurrency,
            now_unix_secs(),
        );
    }

    /// 仅探测单个 tag（用于按需触发）。
    pub fn probe_one(&self, tag: &str, executor: &dyn ProbeExecutor) {
        let result = executor.probe(tag);
        self.status.update_with_probe_result(tag, &result, now_unix_secs());
    }

    /// 返回当前观测快照。
    pub fn get_observation(&self) -> ObservationResult {
        ObservationResult { status: self.status.snapshot() }
    }

    /// 清理已移除的 outbound。
    pub fn clear_removed_outbounds(&self, keep: &[String]) {
        self.status.clear_removed(keep);
    }
}

/// Noop 实现：测试用 OutboundSelector。
pub struct NoopOutboundSelector {
    tags: Vec<String>,
}

impl NoopOutboundSelector {
    pub fn new(tags: Vec<String>) -> Self {
        Self { tags }
    }
}

impl OutboundSelector for NoopOutboundSelector {
    fn select(&self, _selector: &[String]) -> Result<Vec<String>, ObservatoryError> {
        Ok(self.tags.clone())
    }
}

/// 固定 ProbeResult 的 ProbeExecutor：测试用。
pub struct FixedProbeExecutor {
    results: std::collections::HashMap<String, ProbeResult>,
}

impl FixedProbeExecutor {
    pub fn new() -> Self {
        Self { results: std::collections::HashMap::new() }
    }

    pub fn with_result(mut self, tag: impl Into<String>, result: ProbeResult) -> Self {
        self.results.insert(tag.into(), result);
        self
    }
}

impl Default for FixedProbeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeExecutor for FixedProbeExecutor {
    fn probe(&self, tag: &str) -> ProbeResult {
        self.results.get(tag).cloned().unwrap_or_else(|| ProbeResult {
            alive: false,
            delay: 0,
            last_error_reason: format!("no fixture for {tag}"),
        })
    }
}

/// 计数 ProbeExecutor：测试用，统计 probe 调用次数。
#[cfg(test)]
pub(crate) struct CountingProbeExecutor {
    count: std::sync::atomic::AtomicUsize,
    alive: bool,
}

#[cfg(test)]
impl CountingProbeExecutor {
    pub(crate) fn new(alive: bool) -> Self {
        Self { count: std::sync::atomic::AtomicUsize::new(0), alive }
    }

    pub(crate) fn count(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
impl ProbeExecutor for CountingProbeExecutor {
    fn probe(&self, _tag: &str) -> ProbeResult {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ProbeResult {
            alive: self.alive,
            delay: if self.alive { 10 } else { 0 },
            last_error_reason: if self.alive {
                String::new()
            } else {
                "counting fixture failure".into()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_selector(tags: &[&str]) -> ObservatoryConfig {
        ObservatoryConfig {
            subject_selector: tags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn new_observer_not_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        assert!(!o.is_started());
    }

    #[tokio::test]
    async fn start_with_selector_marks_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let selector = Arc::new(NoopOutboundSelector::new(vec!["a".into()]));
        let executor = Arc::new(FixedProbeExecutor::new());
        o.start(selector, executor).unwrap();
        assert!(o.is_started());
    }

    #[tokio::test]
    async fn start_without_selector_not_started() {
        let o = Observer::new(ObservatoryConfig::default());
        let selector = Arc::new(NoopOutboundSelector::new(vec![]));
        let executor = Arc::new(FixedProbeExecutor::new());
        o.start(selector, executor).unwrap();
        assert!(!o.is_started()); // subject_selector 空
    }

    #[tokio::test]
    async fn start_twice_returns_already_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let selector = Arc::new(NoopOutboundSelector::new(vec!["a".into()]));
        let executor = Arc::new(FixedProbeExecutor::new());
        o.start(selector.clone(), executor.clone()).unwrap();
        let err = o.start(selector, executor).unwrap_err();
        assert!(matches!(err, ObservatoryError::AlreadyStarted));
    }

    #[tokio::test]
    async fn close_marks_not_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let selector = Arc::new(NoopOutboundSelector::new(vec!["a".into()]));
        let executor = Arc::new(FixedProbeExecutor::new());
        o.start(selector, executor).unwrap();
        o.close().unwrap();
        assert!(!o.is_started());
    }

    fn fast_cfg() -> ObservatoryConfig {
        ObservatoryConfig {
            subject_selector: vec!["a".into()],
            probe_interval: 50,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn start_spawns_probe_loop_writes_samples() {
        let o = Observer::new(fast_cfg());
        let executor = Arc::new(CountingProbeExecutor::new(true));
        o.start(Arc::new(NoopOutboundSelector::new(vec!["a".into()])), executor.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            executor.count() >= 2,
            "probe loop should run repeatedly, got {}",
            executor.count()
        );
        let obs = o.get_observation();
        assert!(obs.status.iter().any(|s| s.outbound_tag == "a" && s.alive));
    }

    #[tokio::test]
    async fn close_cancels_probe_loop() {
        let o = Observer::new(fast_cfg());
        let executor = Arc::new(CountingProbeExecutor::new(true));
        o.start(Arc::new(NoopOutboundSelector::new(vec!["a".into()])), executor.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(executor.count() >= 1);
        o.close().unwrap();
        let frozen = executor.count();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(executor.count(), frozen, "probe loop must stop after close");
    }

    #[test]
    fn backoff_multiplier_linear_capped() {
        assert_eq!(backoff_multiplier(0), 1);
        assert_eq!(backoff_multiplier(1), 2);
        assert_eq!(backoff_multiplier(2), 3);
        assert_eq!(backoff_multiplier(7), 8);
        assert_eq!(backoff_multiplier(100), 8, "capped at 8x");
    }

    #[test]
    fn close_without_start_is_ok() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        o.close().unwrap();
        assert!(!o.is_started());
    }

    #[test]
    fn probe_all_updates_status() {
        let o = Observer::new(cfg_with_selector(&["a", "b"]));
        let selector = NoopOutboundSelector::new(vec!["a".into(), "b".into()]);
        let executor = FixedProbeExecutor::new()
            .with_result(
                "a",
                ProbeResult { alive: true, delay: 50, last_error_reason: String::new() },
            )
            .with_result(
                "b",
                ProbeResult { alive: false, delay: 0, last_error_reason: "timeout".into() },
            );
        let count = o.probe_all(&selector, &executor).unwrap();
        assert_eq!(count, 2);
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 2);
        let a_status = obs.status.iter().find(|s| s.outbound_tag == "a").unwrap();
        assert!(a_status.alive);
        assert_eq!(a_status.delay, 50);
        let b_status = obs.status.iter().find(|s| s.outbound_tag == "b").unwrap();
        assert!(!b_status.alive);
        assert_eq!(b_status.last_error_reason, "timeout");
    }

    #[test]
    fn probe_one_updates_single_tag() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let executor = FixedProbeExecutor::new().with_result(
            "a",
            ProbeResult { alive: true, delay: 10, last_error_reason: String::new() },
        );
        o.probe_one("a", &executor);
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 1);
        assert_eq!(obs.status[0].outbound_tag, "a");
    }

    #[test]
    fn clear_removed_drops_unlisted() {
        let o = Observer::new(cfg_with_selector(&["a", "b"]));
        let selector = NoopOutboundSelector::new(vec!["a".into(), "b".into()]);
        let executor = FixedProbeExecutor::new();
        o.probe_all(&selector, &executor).unwrap();
        assert_eq!(o.get_observation().status.len(), 2);

        // 模拟 b 被移除
        let selector2 = NoopOutboundSelector::new(vec!["a".into()]);
        o.probe_all(&selector2, &executor).unwrap();
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 1);
        assert_eq!(obs.status[0].outbound_tag, "a");
    }

    #[test]
    fn get_observation_empty_initially() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let obs = o.get_observation();
        assert!(obs.status.is_empty());
    }

    #[test]
    fn noop_selector_returns_constructed_tags() {
        let s = NoopOutboundSelector::new(vec!["x".into()]);
        let r = s.select(&[]).unwrap();
        assert_eq!(r, vec!["x"]);
    }

    #[test]
    fn fixed_executor_returns_unknown_for_missing_tag() {
        let e = FixedProbeExecutor::new();
        let r = e.probe("missing");
        assert!(!r.alive);
        assert!(r.last_error_reason.contains("missing"));
    }

    #[test]
    fn now_unix_secs_nonzero() {
        let t = now_unix_secs();
        assert!(t > 1_700_000_000); // 2023+
    }

    #[test]
    fn probe_all_empty_selector_tags_returns_zero() {
        let o = Observer::new(cfg_with_selector(&[]));
        // subject_selector 空时，selector.select 仍可能返回 tags；测试用 noop 返回 []
        let selector = NoopOutboundSelector::new(vec![]);
        let executor = FixedProbeExecutor::new();
        let count = o.probe_all(&selector, &executor).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn observer_status_store_shared_arc() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        let store = o.status_store().clone();
        // 通过 store 直接更新（绕过 observer.probe_all）
        store.update_with_probe_result(
            "direct",
            &ProbeResult { alive: true, delay: 1, last_error_reason: String::new() },
            100,
        );
        let obs = o.get_observation();
        assert!(obs.status.iter().any(|s| s.outbound_tag == "direct"));
    }

    /// bd f23r：`RealOutboundSelector::with_selector` 把任意
    /// `xray_features::OutboundTagSelector` 后端桥成 `OutboundSelector`，
    /// 无 proxyman 直接依赖——验证桥按前缀筛 tag 行为。
    #[test]
    fn real_outbound_selector_with_selector_bridges_backend() {
        use std::sync::Arc;

        use xray_features::OutboundTagSelector;

        struct FixedBackend(Vec<String>);
        impl OutboundTagSelector for FixedBackend {
            fn select_by_prefix(&self, _prefixes: &[String]) -> Vec<String> {
                self.0.clone()
            }
        }

        let backend: Arc<dyn OutboundTagSelector> =
            Arc::new(FixedBackend(vec!["proxy1".into(), "proxy2".into()]));
        let sel = RealOutboundSelector::with_selector(backend);
        let tags = sel.select(&["any".into()]).unwrap();
        assert_eq!(tags, vec!["proxy1", "proxy2"]);
    }

    /// bd f23r：HttpProbeExecutor 经真实 HTTP echo server 探测——验证
    /// 探测读响应 + 写入请求路径都走真实 TCP（不依赖 mock）。
    #[tokio::test]
    async fn http_probe_executor_runs_against_echo_server() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap();
            // 任何 HTTP/1.1 请求 → 返 200 即可。
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            let _ = n;
        });

        let exec = HttpProbeExecutor::new(format!("http://{addr}/"), "GET".to_string(), 5_000);
        let result = tokio::task::spawn_blocking(move || exec.probe("test-tag"))
            .await
            .expect("spawn_blocking should not panic");
        assert!(result.alive, "expected alive probe, got: {:?}", result);
        assert!(result.delay >= 0);
        server.await.unwrap();
    }

    /// qyo6：probe_tags 按 enable_concurrency 分支。
    /// 并行分支下多 tag 应都能探测完，alive status 都写入。
    /// （实测通过 std::thread::spawn 真并行；本测试主要确认结果正确性。）
    #[test]
    fn probe_tags_concurrent_branch_writes_all_statuses() {
        let cfg = ObservatoryConfig {
            subject_selector: vec!["a".into(), "b".into(), "c".into()],
            enable_concurrency: true,
            ..Default::default()
        };
        let o = Observer::new(cfg);
        let exec = FixedProbeExecutor::new()
            .with_result(
                "a",
                ProbeResult { alive: true, delay: 10, last_error_reason: String::new() },
            )
            .with_result("b", ProbeResult { alive: false, delay: 0, last_error_reason: "x".into() })
            .with_result(
                "c",
                ProbeResult { alive: true, delay: 30, last_error_reason: String::new() },
            );
        let tags = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        o.probe_tags(&tags, &exec);
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 3);
        let a = obs.status.iter().find(|s| s.outbound_tag == "a").unwrap();
        assert!(a.alive);
        assert_eq!(a.delay, 10);
        let b = obs.status.iter().find(|s| s.outbound_tag == "b").unwrap();
        assert!(!b.alive);
        let c = obs.status.iter().find(|s| s.outbound_tag == "c").unwrap();
        assert!(c.alive);
        assert_eq!(c.delay, 30);
    }

    /// qyo6：enable_concurrency=false 时走串行分支（与原行为一致）。
    #[test]
    fn probe_tags_serial_branch_writes_all_statuses() {
        let cfg = ObservatoryConfig {
            subject_selector: vec!["x".into(), "y".into()],
            enable_concurrency: false,
            ..Default::default()
        };
        let o = Observer::new(cfg);
        let exec = FixedProbeExecutor::new()
            .with_result(
                "x",
                ProbeResult { alive: true, delay: 5, last_error_reason: String::new() },
            )
            .with_result(
                "y",
                ProbeResult { alive: true, delay: 7, last_error_reason: String::new() },
            );
        o.probe_tags(&["x".to_string(), "y".to_string()], &exec);
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 2);
    }

    /// qyo6：空 tags 时 EnableConcurrency 分支不退化、不 panic。
    #[test]
    fn probe_tags_empty_tags_noop() {
        let cfg = ObservatoryConfig { enable_concurrency: true, ..Default::default() };
        let o = Observer::new(cfg);
        let exec = FixedProbeExecutor::new();
        o.probe_tags(&[], &exec);
        assert!(o.get_observation().status.is_empty());
    }

    /// soqc：RealOutboundProbeExecutor — tag 未注册 → dispatch 同步 Err → dead。
    #[test]
    fn real_outbound_probe_missing_handler_returns_dead() {
        let dispatcher = Arc::new(DefaultDispatcher::new());
        let exec =
            RealOutboundProbeExecutor::from_config(&ObservatoryConfig::default(), dispatcher);
        let r = exec.probe("unknown-tag");
        assert!(!r.alive);
        assert!(r.last_error_reason.contains("unknown-tag"), "got: {}", r.last_error_reason);
    }

    /// qyo6：URL 为空 → dead 短路（不进 dispatch）。
    #[test]
    fn real_outbound_probe_empty_url_returns_dead() {
        let dispatcher = Arc::new(DefaultDispatcher::new());
        let exec = RealOutboundProbeExecutor::new(dispatcher, "", "GET", 5_000);
        let r = exec.probe("any");
        assert!(!r.alive);
        assert!(r.last_error_reason.contains("empty"));
    }

    /// soqc 验收：两 tag 探测结果相异性 — "good"（outbound 可达 mock HTTP
    /// 目标）alive，"dead"（outbound 恒拨号失败）dead。此前装配注入直连
    /// executor，所有 tag 探测结果 = 本机直连状况完全相同。
    #[test]
    fn real_outbound_probe_two_tags_diverge() {
        use xray_app_dispatcher::{
            Config as DispConfig,
            default::{DialBridge, DialFn, SimpleOhm},
        };
        use xray_transport::connection::TcpConnection;

        // mock HTTP 目标：accept 后写死 204 状态行。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let mock_ip = mock_addr.ip().to_string();
        let mock_port = mock_addr.port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                use std::io::{Read as _, Write as _};
                // 先读 GET 再回 204，最后半关闭（Write 侧 FIN）——写完立即
                // drop 会发 RST 吞掉响应字节，probe 读到 EOF 而非 204。
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                let _ = sock.flush();
                let _ = sock.shutdown(std::net::Shutdown::Write);
            }
        });
        let good: DialFn = Arc::new(move |_dest| {
            let target = format!("127.0.0.1:{mock_port}");
            Box::pin(async move {
                let tcp =
                    tokio::net::TcpStream::connect(&target).await.map_err(|e| e.to_string())?;
                Ok(Box::new(TcpConnection::new(tcp)) as Box<dyn Connection>)
            })
        });
        let dead: DialFn = Arc::new(|_dest| {
            Box::pin(async {
                Err("dead outbound: dial always fails".to_string())
                    as Result<Box<dyn Connection>, String>
            })
        });

        let ohm = Arc::new(SimpleOhm::new());
        ohm.add(
            "good",
            Arc::new(DialBridge::new("good", good))
                as Arc<dyn xray_app_dispatcher::DispatchHandler>,
        );
        ohm.add(
            "dead",
            Arc::new(DialBridge::new("dead", dead))
                as Arc<dyn xray_app_dispatcher::DispatchHandler>,
        );

        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.init(
            &DispConfig::default(),
            ohm,
            None,
            xray_features::policy::Policy::default(),
            None,
        );

        let cfg = ObservatoryConfig {
            probe_url: format!("http://{mock_ip}:{mock_port}/generate_204"),
            ..Default::default()
        };
        // 短预算：dead 路径要等 read timeout，5s 太拖。
        let exec =
            RealOutboundProbeExecutor::new(Arc::new(dispatcher), cfg.probe_url.clone(), "GET", 500);

        let good_r = exec.probe("good");
        assert!(good_r.alive, "good outbound must be alive, got: {:?}", good_r);

        let dead_r = exec.probe("dead");
        assert!(!dead_r.alive, "dead outbound must be dead, got: {:?}", dead_r);
        assert!(
            dead_r.last_error_reason.contains("dead"),
            "reason must name the outbound, got: {}",
            dead_r.last_error_reason
        );
    }

    /// soqc 验收：TLS 故障目标不误报 alive — https 目标 accept 后立即关闭
    /// （TCP 可达但 TLS 握手必败）必须判 dead。此前 use_tls 分支仅测 TCP
    /// 建连延迟，此类目标被误报 alive。
    #[test]
    fn tls_probe_rejects_syn_ack_only_target() {
        use xray_app_dispatcher::{
            Config as DispConfig,
            default::{DialBridge, DialFn, SimpleOhm},
        };
        use xray_transport::connection::TcpConnection;

        // accept 后立即 drop：TLS 握手读端 EOF → 必败。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let mock_ip = mock_addr.ip().to_string();
        let mock_port = mock_addr.port();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let dial: DialFn = Arc::new(move |_dest| {
            let target = format!("127.0.0.1:{mock_port}");
            Box::pin(async move {
                let tcp =
                    tokio::net::TcpStream::connect(&target).await.map_err(|e| e.to_string())?;
                Ok(Box::new(TcpConnection::new(tcp)) as Box<dyn Connection>)
            })
        });

        let ohm = Arc::new(SimpleOhm::new());
        ohm.add(
            "plain-tls",
            Arc::new(DialBridge::new("plain-tls", dial))
                as Arc<dyn xray_app_dispatcher::DispatchHandler>,
        );

        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.init(
            &DispConfig::default(),
            ohm,
            None,
            xray_features::policy::Policy::default(),
            None,
        );

        let cfg = ObservatoryConfig {
            probe_url: format!("https://{mock_ip}:{mock_port}/"),
            ..Default::default()
        };
        let exec = RealOutboundProbeExecutor::from_config(&cfg, Arc::new(dispatcher));
        let r = exec.probe("plain-tls");
        assert!(!r.alive, "tls-failed target must be dead, got: {:?}", r);
    }
}

/// 基于 OutboundManager 的 OutboundSelector 实现。
///
/// 对应 Go `outbound.HandlerSelector`：通过 Manager.Select 按前缀筛选 tag。
///
/// # 两个构造入口
///
/// - [`Self::new`]：直接持有 `Arc<dyn OutboundSelector>`（已实现的 trait object），
///   适用于观测器内部嵌套场景。
/// - [`Self::with_selector`]：接受任意实现了 [`xray_features::OutboundTagSelector`] 的后端（典型为
///   `xray-app-proxyman::OutboundManager`），无 proxyman 直接依赖，
///   避免循环依赖（xray-app-observatory 已被 proxyman 间接引用）。
pub struct RealOutboundSelector {
    manager: Arc<dyn OutboundSelector>,
}

impl RealOutboundSelector {
    pub fn new(manager: Arc<dyn OutboundSelector>) -> Self {
        Self { manager }
    }

    /// 从 `xray_features::OutboundTagSelector` 适配构造。
    ///
    /// 内部包装一个 `OutboundSelector` 适配器（每次 `select` 转发到
    /// `OutboundTagSelector::select_by_prefix`）。开销为一次间接调用 + 一次
    /// Vec<String> 分配；observatory 探测间隔 ≥ 1s，可忽略。
    pub fn with_selector(backend: Arc<dyn xray_features::OutboundTagSelector>) -> Self {
        struct BackendAdapter(Arc<dyn xray_features::OutboundTagSelector>);
        impl OutboundSelector for BackendAdapter {
            fn select(&self, subject_selector: &[String]) -> Result<Vec<String>, ObservatoryError> {
                Ok(self.0.select_by_prefix(subject_selector))
            }
        }
        Self { manager: Arc::new(BackendAdapter(backend)) }
    }
}

impl OutboundSelector for RealOutboundSelector {
    fn select(&self, subject_selector: &[String]) -> Result<Vec<String>, ObservatoryError> {
        self.manager.select(subject_selector)
    }
}
/// 基于 tokio::net::TcpStream 的 HTTP ProbeExecutor。
///
/// 两套语义（4d7t 分离）：
/// - **plain observatory**（`from_config`）：GET + 收到合法 HTTP 状态行即 alive——对齐 Go
///   `observer.go:175-186`（仅请求失败判 dead，**不查状态码**； CDN 对 HEAD/非 2xx 返回 405/403
///   时节点仍应判活）。
/// - **burst healthping**（`new`）：沿用配置的 method + 200-399 判 alive （Go
///   `healthping.go:175-179`）。
pub struct HttpProbeExecutor {
    /// 探测目标 URL（如 https://www.google.com/generate_204）
    url: String,
    /// HTTP 方法（如 HEAD）
    method: String,
    /// 连接超时（毫秒）
    timeout_ms: u64,
    /// true = 按状态码 200-399 判 alive（healthping 口径）；false = 收到合法
    /// HTTP 响应即 alive（plain observatory 口径，Go observer.go）。
    check_status: bool,
}

impl HttpProbeExecutor {
    pub fn new(url: impl Into<String>, method: impl Into<String>, timeout_ms: u64) -> Self {
        Self { url: url.into(), method: method.into(), timeout_ms, check_status: true }
    }

    /// 从 ObservatoryConfig 构造（plain observatory 语义）。
    ///
    /// 对齐 Go `observer.go:163/175`：默认 GET、**无状态码检查**——请求完成
    /// 即 alive。此前误用 burst healthping 的 HEAD 常量 + 200-399 判定，
    /// CDN 对 HEAD 返回 405/403 时全节点误判 dead。
    pub fn from_config(config: &ObservatoryConfig) -> Self {
        Self {
            url: config.effective_probe_url().to_string(),
            method: "GET".to_string(),
            timeout_ms: 5_000,
            check_status: false,
        }
    }
}

impl ProbeExecutor for HttpProbeExecutor {
    fn probe(&self, outbound_tag: &str) -> ProbeResult {
        let _start = Instant::now();
        // probe 是同步契约，可能从 async 上下文（background 探测循环）调用；
        // 在当前 runtime 上 block_on 会 panic（Cannot start a runtime from within
        // a runtime）。专用线程 + 独立 runtime 对任何调用上下文安全。
        let result = std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                rt.block_on(async { self.probe_async(outbound_tag).await })
            })
            .join()
            .unwrap_or_else(|e| Err(format!("thread panicked: {e:?}")))
        });
        match result {
            Ok(delay_ms) => {
                ProbeResult { alive: true, delay: delay_ms, last_error_reason: String::new() }
            },
            Err(reason) => ProbeResult { alive: false, delay: 0, last_error_reason: reason },
        }
    }
}

impl HttpProbeExecutor {
    async fn probe_async(&self, _outbound_tag: &str) -> Result<i64, String> {
        let url = self.url.trim();
        if url.is_empty() {
            return Err("probe url is empty".to_string());
        }

        let (host, port, use_tls) = parse_url_host_port(url)?;
        let addr = format!("{host}:{port}");
        let start = Instant::now();
        // Go http.Client.Timeout 口径：connect+TLS+GET 共享一个总预算。
        let deadline =
            tokio::time::Instant::from_std(start) + Duration::from_millis(self.timeout_ms);

        let stream = tokio::time::timeout_at(deadline, TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("tcp connect timeout after {}ms", self.timeout_ms))?
            .map_err(|e| format!("tcp connect failed: {e}"))?;

        if use_tls {
            // soqc：rustls 完整握手。此前仅 TCP 建连即返回 alive——443 有
            // SYN-ACK 但 TLS 层故障（中间盒）的目标被误报 alive。根证书 =
            // webpki-roots（Go nil RootCAs 用系统根的既有 Rust 等价决策）。
            let tls = tokio::time::timeout_at(
                deadline,
                xray_tls::utls::client(
                    xray_transport::connection::TcpConnection::new(stream),
                    &host,
                    xray_tls::utls::default_client_config(),
                ),
            )
            .await
            .map_err(|_| format!("tls handshake timeout after {}ms", self.timeout_ms))?
            .map_err(|e| format!("tls handshake failed: {e}"))?;
            let mut tls = tls;
            http_probe_io(&mut tls, &self.method, url, &host, deadline, self.check_status).await?;
        } else {
            let mut conn = xray_transport::connection::TcpConnection::new(stream);
            http_probe_io(&mut conn, &self.method, url, &host, deadline, self.check_status).await?;
        }

        Ok(start.elapsed().as_millis() as i64)
    }
}

/// 在已建立的连接上完成一次 HTTP 探测请求（write + 读状态行）。
///
/// 对齐 Go http.Client 语义：收到合法 HTTP/1.x 状态行即成功（`check_status`
/// 为 true 时再查 2xx-3xx，burst healthping 口径；plain observatory 不查——
/// Go observer.go:175-186，CDN 对 HEAD/非 2xx 的 405/403 不判死节点）。
/// `deadline` 是共享总预算（write/read 共用，Go Client.Timeout 口径）。
async fn http_probe_io<S>(
    stream: &mut S,
    method: &str,
    url: &str,
    host: &str,
    deadline: tokio::time::Instant,
    check_status: bool,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("{method} {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "probe write timeout".to_string())?
        .map_err(|e| format!("write failed: {e}"))?;

    // 读取响应（至少读到 HTTP/1.x 状态行）
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
        .await
        .map_err(|_| "probe read timeout".to_string())?
        .map_err(|e| format!("read failed: {e}"))?;
    if n == 0 {
        return Err("server closed connection".to_string());
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.starts_with("HTTP/1") {
        return Err(format!("invalid response: {}", response.lines().next().unwrap_or("")));
    }

    // 3oad/4d7t：状态行解析 + 口径分离见 parse_http_status_code。
    let status_code = parse_http_status_code(&response).ok_or_else(|| {
        format!("malformed status line: {}", response.lines().next().unwrap_or(""))
    })?;
    if check_status && !(200..400).contains(&status_code) {
        return Err(format!("http status {status_code}"));
    }
    Ok(())
}

// ── 真实 outbound probe（soqc）─────────────────────────────────────
//
// Go `Observer.probe`（observer.go:130-159）：tagged.Dialer(ctx, dispatcher,
// dest, outbound) 返回 net.Conn，http.Client 经该 conn 完整 HTTPS GET，请求
// 成功（不查状态码）即 alive。Rust 对应链：DefaultDispatcher::dispatch_tagged
// （bd kz1，Go tagged/taggedimpl.DialTaggedOutbound 等价物）→ [`Link`] →
// [`LinkConn`] → [rustls 握手（https）] → [`http_probe_io`]。
//

/// [`Link`]（`Box<dyn Reader/Writer>` future-trait 域）→ tokio
/// `AsyncRead + AsyncWrite` 域的桥接连接，实现 [`Connection`] 以接 rustls。
///
/// `read_multi_buffer`/`write_multi_buffer` 返回独立 future 且借走
/// `&mut self`，无法在 `poll_*` 内直接构造——take/complete 状态机：poll 时把
/// inner move 进 future（槽位置 `None`），完成时还回 inner 并暂存数据。
struct LinkConn {
    // Connection 要求 Send + Sync；`Box<dyn Reader/Writer>` 仅 Send——用
    // parking_lot::Mutex 使 LinkConn 整体 Sync（probe 连接独占，锁无争用）。
    inner: parking_lot::Mutex<LinkConnIo>,
}

struct LinkConnIo {
    reader: ReaderSlot,
    writer: WriterSlot,
}

struct ReaderSlot {
    inner: Option<Box<dyn BufReader>>,
    fut: Option<
        Pin<
            Box<
                dyn Future<Output = (Box<dyn BufReader>, xray_buf::io::Result<MultiBuffer>)> + Send,
            >,
        >,
    >,
    pending: Vec<u8>,
}

impl AsyncRead for ReaderSlot {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(out.remaining());
                if n == 0 {
                    // 调用方缓冲已满：保留 pending 下次再搬
                    return Poll::Ready(Ok(()));
                }
                let data = this.pending.split_off(this.pending.len() - n);
                out.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            if let Some(fut) = this.fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready((inner, res)) => {
                        this.fut = None;
                        this.inner = Some(inner);
                        match res {
                            Ok(mb) => {
                                this.pending = mb.into_vec();
                                if this.pending.is_empty() {
                                    // 空 MultiBuffer = 0 字节读出 = EOF：
                                    // put_slice 空 + Ready 即 tokio EOF 约定。
                                    // 必须直接返回——continue 会原地重建
                                    // future 无限自旋（挂死根因）。
                                    return Poll::Ready(Ok(()));
                                }
                                continue;
                            },
                            // pipe 写端关闭以 Err(Eof) 表达（xray-buf 约定）
                            // → 映射为 tokio 0 字节 EOF。
                            Err(xray_buf::io::Error::Eof) => {
                                return Poll::Ready(Ok(()));
                            },
                            Err(e) => {
                                return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                            },
                        }
                    },
                    Poll::Pending => return Poll::Pending,
                }
            }
            let Some(mut inner) = this.inner.take() else {
                return Poll::Ready(Err(std::io::Error::other("link reader slot empty")));
            };
            this.fut = Some(Box::pin(async move {
                let res = inner.read_multi_buffer().await;
                (inner, res)
            }));
        }
    }
}

struct WriterSlot {
    inner: Option<Box<dyn BufWriter>>,
    fut: Option<
        Pin<Box<dyn Future<Output = (Box<dyn BufWriter>, xray_buf::io::Result<()>)> + Send>>,
    >,
}

impl AsyncWrite for WriterSlot {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        loop {
            if let Some(fut) = this.fut.as_mut() {
                return match fut.as_mut().poll(cx) {
                    // MultiBuffer 写语义无部分写：future 完成即全量写入
                    Poll::Ready((inner, res)) => {
                        this.fut = None;
                        this.inner = Some(inner);
                        match res {
                            Ok(()) => Poll::Ready(Ok(buf.len())),
                            Err(e) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
                        }
                    },
                    Poll::Pending => Poll::Pending,
                };
            }
            let Some(mut inner) = this.inner.take() else {
                return Poll::Ready(Err(std::io::Error::other("link writer slot empty")));
            };
            let mut data = MultiBuffer::new();
            data.merge_bytes(buf);
            this.fut = Some(Box::pin(async move {
                let res = inner.write_multi_buffer(data).await;
                (inner, res)
            }));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(fut) = self.fut.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match fut.as_mut().poll(cx) {
            Poll::Ready((inner, res)) => {
                self.fut = None;
                self.inner = Some(inner);
                res.map_err(|e| std::io::Error::other(e.to_string())).into()
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl LinkConn {
    fn new(link: Link) -> Self {
        Self {
            inner: parking_lot::Mutex::new(LinkConnIo {
                reader: ReaderSlot { inner: Some(link.reader), fut: None, pending: Vec::new() },
                writer: WriterSlot { inner: Some(link.writer), fut: None },
            }),
        }
    }
}

impl AsyncRead for LinkConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut io = self.inner.lock();
        Pin::new(&mut io.reader).poll_read(cx, out)
    }
}

impl AsyncWrite for LinkConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut io = self.inner.lock();
        Pin::new(&mut io.writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut io = self.inner.lock();
        Pin::new(&mut io.writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Connection for LinkConn {
    fn remote_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

/// 经指定 outbound（dispatcher forced-tag dispatch，不经路由）拨号到探测
/// URL 并完成完整 HTTP(S) GET 的 [`ProbeExecutor`]。
///
/// - tag 未注册 → dispatch 同步 Err → dead（对齐 Go default.go:443-454 "tag 不存在直接丢弃链路"）。
/// - https 目标 → rustls 完整握手（webpki-roots），TLS 层故障判 dead—— 修复此前"443 SYN-ACK 即
///   alive"的误报。
/// - alive 判定 = 收到合法 HTTP 状态行（Go observer.go:175-186，不查状态码）。
pub struct RealOutboundProbeExecutor {
    dispatcher: Arc<DefaultDispatcher>,
    /// 探测 URL（如 `https://www.google.com/generate_204`）。
    probe_url: String,
    /// HTTP 方法（plain observatory = GET；burst = settings.http_method）。
    method: String,
    /// 全链路（dispatch+TLS+GET）总超时（毫秒，Go Client.Timeout 口径）。
    timeout_ms: u64,
}

impl std::fmt::Debug for RealOutboundProbeExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealOutboundProbeExecutor")
            .field("probe_url", &self.probe_url)
            .field("method", &self.method)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl RealOutboundProbeExecutor {
    /// 构造。
    #[must_use]
    pub fn new(
        dispatcher: Arc<DefaultDispatcher>,
        probe_url: impl Into<String>,
        method: impl Into<String>,
        timeout_ms: u64,
    ) -> Self {
        Self { dispatcher, probe_url: probe_url.into(), method: method.into(), timeout_ms }
    }

    /// 从 `ObservatoryConfig` + 生产 dispatcher 构造（plain observatory 语义：
    /// GET、默认 5s，对齐 Go observer.go:163 Client.Timeout）。
    #[must_use]
    pub fn from_config(config: &ObservatoryConfig, dispatcher: Arc<DefaultDispatcher>) -> Self {
        Self::new(dispatcher, config.effective_probe_url(), "GET", 5_000)
    }
}

impl ProbeExecutor for RealOutboundProbeExecutor {
    fn probe(&self, outbound_tag: &str) -> ProbeResult {
        let url = self.probe_url.trim();
        if url.is_empty() {
            return ProbeResult {
                alive: false,
                delay: 0,
                last_error_reason: "probe url is empty".into(),
            };
        }
        let (host, port, use_tls) = match parse_url_host_port(url) {
            Ok(t) => t,
            Err(e) => {
                return ProbeResult {
                    alive: false,
                    delay: 0,
                    last_error_reason: format!("parse probe url: {e}"),
                };
            },
        };

        let addr = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => xray_common::net::address::Address::from(ip),
            Err(_) => xray_common::net::address::Address::new_domain(host.clone()),
        };
        let dest = xray_common::net::destination::Destination::new(
            addr,
            xray_common::net::port::Port::from(port),
            xray_common::net::network::Network::TCP,
        );

        let dispatcher = self.dispatcher.clone();
        let tag = outbound_tag.to_string();
        let method = self.method.clone();
        let timeout_ms = self.timeout_ms;
        // probe 是同步契约，典型调用方是 spawn_blocking 探测轮（4j5m）。
        // 专用线程 + 独立 runtime 对任何调用上下文安全（block_on 不碰外层
        // runtime；Handle::current 在 blocking 线程池不可用）。
        std::thread::scope(|s| {
            s.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
                let Ok(rt) = rt else {
                    return ProbeResult {
                        alive: false,
                        delay: 0,
                        last_error_reason: format!("outbound '{tag}': probe runtime build failed"),
                    };
                };
                rt.block_on(async move {
                    let start = Instant::now();
                    let deadline =
                        tokio::time::Instant::from_std(start) + Duration::from_millis(timeout_ms);
                    // dispatch_tagged 是同步入口（内部 spawn handler）：
                    // tag 无效/no ohm 同步 Err，不落默认出站。
                    let link = match dispatcher.dispatch_tagged(&dest, &tag) {
                        Ok(l) => l,
                        Err(e) => {
                            return ProbeResult {
                                alive: false,
                                delay: 0,
                                last_error_reason: format!("outbound '{tag}' dispatch failed: {e}"),
                            };
                        },
                    };

                    let mut conn = LinkConn::new(link);
                    let io_res = if use_tls {
                        let tls_res = tokio::time::timeout_at(
                            deadline,
                            xray_tls::utls::client(
                                conn,
                                &host,
                                xray_tls::utls::default_client_config(),
                            ),
                        )
                        .await
                        .map_err(|_| format!("tls handshake timeout after {timeout_ms}ms"))
                        .and_then(|r| r.map_err(|e| format!("tls handshake failed: {e}")));
                        match tls_res {
                            Ok(mut tls) => {
                                http_probe_io(&mut tls, &method, url, &host, deadline, false).await
                            },
                            Err(reason) => Err(reason),
                        }
                    } else {
                        http_probe_io(&mut conn, &method, url, &host, deadline, false).await
                    };
                    match io_res {
                        Ok(()) => ProbeResult {
                            alive: true,
                            delay: start.elapsed().as_millis() as i64,
                            last_error_reason: String::new(),
                        },
                        Err(reason) => ProbeResult {
                            alive: false,
                            delay: 0,
                            last_error_reason: format!("outbound '{tag}' probe failed: {reason}"),
                        },
                    }
                })
            })
            .join()
            .unwrap_or_else(|e| ProbeResult {
                alive: false,
                delay: 0,
                last_error_reason: format!("probe thread panicked: {e:?}"),
            })
        })
    }
}

/// 从 URL 解析 host、port、是否使用 TLS。
///
/// 支持 http:// 和 https:// 前缀。
fn parse_url_host_port(url: &str) -> Result<(String, u16, bool), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("url is empty".to_string());
    }

    let (scheme, rest) = if let Some(pos) = url.find("://") {
        let scheme = &url[..pos];
        let rest = &url[pos + 3..];
        (scheme, rest)
    } else {
        ("http", url)
    };

    let use_tls = scheme.eq_ignore_ascii_case("https");

    // 提取 host:port
    let host_port = if let Some(pos) = rest.find('/') { &rest[..pos] } else { rest };

    let (host, port) = if let Some(pos) = host_port.rfind(':') {
        let host = &host_port[..pos];
        let port_str = &host_port[pos + 1..];
        let port =
            port_str.parse::<u16>().map_err(|e| format!("invalid port '{port_str}': {e}"))?;
        (host.to_string(), port)
    } else {
        let default_port = if use_tls { 443 } else { 80 };
        (host_port.to_string(), default_port)
    };

    if host.is_empty() {
        return Err("host is empty".to_string());
    }

    Ok((host, port, use_tls))
}

/// 3oad：从 HTTP 响应首行解析状态码（`HTTP/1.1 200 OK` → 200）。
///
/// 仅看第一行（响应头可能没读完，按 \r\n 切）；遇非数字 / 长度 < 12 / 切片越界
/// 返回 None（上层报 malformed）。
fn parse_http_status_code(response: &str) -> Option<u16> {
    let first_line = response.split("\r\n").next()?;
    // "HTTP/<ver> <code> <reason>"
    let mut parts = first_line.split_ascii_whitespace();
    let _proto = parts.next()?;
    let code_str = parts.next()?;
    code_str.parse::<u16>().ok()
}

#[cfg(test)]
mod status_code_tests {
    use super::parse_http_status_code;

    #[test]
    fn parses_200_ok() {
        let r = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        assert_eq!(parse_http_status_code(r), Some(200));
    }

    #[test]
    fn parses_204() {
        let r = "HTTP/1.1 204 No Content\r\n";
        assert_eq!(parse_http_status_code(r), Some(204));
    }

    #[test]
    fn parses_404_alive_false_via_caller() {
        let r = "HTTP/1.1 404 Not Found\r\n";
        assert_eq!(parse_http_status_code(r), Some(404));
    }

    #[test]
    fn returns_none_for_malformed() {
        assert!(parse_http_status_code("garbage").is_none());
        assert!(parse_http_status_code("HTTP/1.1 abc OK").is_none());
        assert!(parse_http_status_code("").is_none());
    }
}

#[cfg(test)]
mod link_conn_tests {
    use xray_buf::pipe;
    use xray_transport::link::Link;

    use super::LinkConn;

    /// LinkConn 状态机核心契约：写经 writer 槽位透传，读经 reader 槽位透传，
    /// EOF（pipe 写端关闭）读出 0 字节。
    #[tokio::test]
    async fn link_conn_roundtrip_and_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // (客户端读写端, 服务端读写端)——客户端侧的 reader/writer 交给 LinkConn。
        let (c_r, s_w) = pipe::new();
        let (s_r, c_w) = pipe::new();
        let link = Link::new(Box::new(c_r), Box::new(c_w));
        let mut conn = LinkConn::new(link);

        // 服务端：读请求 → 回响应 → 显式 shutdown 写端。
        // pipe 写端 drop 不触发 close（buf pipe 无 Drop impl）——不 shutdown
        // 读端永远 Pending。
        tokio::spawn(async move {
            use xray_buf::io::{Reader as _, Writer as _};
            let mut w = s_w;
            let mut r = s_r;
            let _ = r.read_multi_buffer().await;
            let mut mb = xray_buf::multi::MultiBuffer::new();
            mb.merge_bytes(b"HTTP/1.1 204 No Content\r\n\r\n");
            let _ = w.write_multi_buffer(mb).await;
            w.shutdown(); // BufWriter::shutdown → pipe Writer::close → 读端 EOF
        });

        conn.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 204"), "got: {:?}", buf);
    }
}
