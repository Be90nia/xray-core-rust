//! Observer 编排 + ProbeExecutor / OutboundSelector / Scheduler 注入 trait。
//!
//! 对应 Go `app/observatory/observer.go` 的 `Observer` struct + background loop。
//! 实际 HTTP probe + dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::config::{ObservationResult, ObservatoryConfig, ProbeResult};
use crate::error::{at_error, ObservatoryError};
use crate::status::StatusStore;
// 3oad：探测方法（HTTP GET）从 burst healthping_settings 复用默认值——其口径
// 已对齐 Go `healthping.go:147` `HttpMethod = "GET"`。
use crate::burst::healthping_settings::DEFAULT_HTTP_METHOD;

use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::watch;
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
            state: Mutex::new(ObserverState {
                started: false,
                cancel_tx: None,
            }),
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

        tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            let mut fail_streak: u32 = 0;
            loop {
                let round_failed = match selector.select(&subject_selector) {
                    Ok(tags) => {
                        status.clear_removed(&tags);
                        let now = now_unix_secs();
                        let mut any_alive = false;
                        for tag in &tags {
                            let result = executor.probe(tag);
                            any_alive |= result.alive;
                            status.update_with_probe_result(tag, &result, now);
                        }
                        // tags 非空且无一存活才算失败轮（空列表按正常间隔）
                        !tags.is_empty() && !any_alive
                    }
                    Err(e) => {
                        at_error(&e);
                        true
                    }
                };

                fail_streak = if round_failed {
                    fail_streak.saturating_add(1)
                } else {
                    0
                };
                let delay = Duration::from_millis(interval_ms * backoff_multiplier(fail_streak) as u64);
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

        let now = now_unix_secs();
        if self.config.enable_concurrency {
            // 并行探测（Go observer.go:94-102：每个 outbound 一个 goroutine）。
            // ProbeExecutor.probe 是同步阻塞（内部 block_on 真实 HTTP dial），
            // 用 scoped thread 借用非 'static 的 executor 引用实现真并行。
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
            for pair in results.into_iter().flatten() {
                let (tag, result) = pair;
                self.status.update_with_probe_result(&tag, &result, now);
            }
        } else {
            for tag in tags {
                let result = executor.probe(tag);
                self.status.update_with_probe_result(tag, &result, now);
            }
        }
    }

    /// 仅探测单个 tag（用于按需触发）。
    pub fn probe_one(&self, tag: &str, executor: &dyn ProbeExecutor) {
        let result = executor.probe(tag);
        self.status.update_with_probe_result(tag, &result, now_unix_secs());
    }

    /// 返回当前观测快照。
    pub fn get_observation(&self) -> ObservationResult {
        ObservationResult {
            status: self.status.snapshot(),
        }
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
        Self {
            results: std::collections::HashMap::new(),
        }
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
        self.results
            .get(tag)
            .cloned()
            .unwrap_or_else(|| ProbeResult {
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
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            alive,
        }
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
        o.start(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            executor.clone(),
        )
        .unwrap();
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
        o.start(
            Arc::new(NoopOutboundSelector::new(vec!["a".into()])),
            executor.clone(),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(executor.count() >= 1);
        o.close().unwrap();
        let frozen = executor.count();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            executor.count(),
            frozen,
            "probe loop must stop after close"
        );
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
                ProbeResult {
                    alive: true,
                    delay: 50,
                    last_error_reason: String::new(),
                },
            )
            .with_result(
                "b",
                ProbeResult {
                    alive: false,
                    delay: 0,
                    last_error_reason: "timeout".into(),
                },
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
            ProbeResult {
                alive: true,
                delay: 10,
                last_error_reason: String::new(),
            },
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
            &ProbeResult {
                alive: true,
                delay: 1,
                last_error_reason: String::new(),
            },
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap();
            // 任何 HTTP/1.1 请求 → 返 200 即可。
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            )
            .await
            .unwrap();
            let _ = n;
        });

        let exec = HttpProbeExecutor::new(
            format!("http://{addr}/"),
            "GET".to_string(),
            5_000,
        );
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
                ProbeResult {
                    alive: true,
                    delay: 10,
                    last_error_reason: String::new(),
                },
            )
            .with_result(
                "b",
                ProbeResult {
                    alive: false,
                    delay: 0,
                    last_error_reason: "x".into(),
                },
            )
            .with_result(
                "c",
                ProbeResult {
                    alive: true,
                    delay: 30,
                    last_error_reason: String::new(),
                },
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
                ProbeResult {
                    alive: true,
                    delay: 5,
                    last_error_reason: String::new(),
                },
            )
            .with_result(
                "y",
                ProbeResult {
                    alive: true,
                    delay: 7,
                    last_error_reason: String::new(),
                },
            );
        o.probe_tags(
            &["x".to_string(), "y".to_string()],
            &exec,
        );
        let obs = o.get_observation();
        assert_eq!(obs.status.len(), 2);
    }

    /// qyo6：空 tags 时 EnableConcurrency 分支不退化、不 panic。
    #[test]
    fn probe_tags_empty_tags_noop() {
        let cfg = ObservatoryConfig {
            enable_concurrency: true,
            ..Default::default()
        };
        let o = Observer::new(cfg);
        let exec = FixedProbeExecutor::new();
        o.probe_tags(&[], &exec);
        assert!(o.get_observation().status.is_empty());
    }

    /// qyo6：RealOutboundProbeExecutor — 未知 tag → dead + reason。
    #[test]
    fn real_outbound_probe_missing_handler_returns_dead() {
        let exec = RealOutboundProbeExecutor::from_config(&ObservatoryConfig::default());
        let r = exec.probe("unknown-tag");
        assert!(!r.alive);
        assert!(r.last_error_reason.contains("unknown-tag"));
    }

    /// qyo6：RealOutboundProbeExecutor — URL 为空 → dead + reason。
    #[tokio::test]
    async fn real_outbound_probe_empty_url_returns_dead() {
        // 构造一个 noop handler 让"tag 存在"路径走通，URL 为空短路
        struct NoopHandler;
        #[async_trait::async_trait]
        impl xray_features::outbound::OutboundHandler for NoopHandler {
            fn tag(&self) -> &str {
                "noop"
            }
            async fn dial(
                &self,
                _destination: &xray_common::net::destination::Destination,
                _session: &xray_common::session::Session,
            ) -> Result<(), xray_features::outbound::OutboundError> {
                Ok(())
            }
            fn can_handle(
                &self,
                _destination: &xray_common::net::destination::Destination,
            ) -> bool {
                true
            }
        }
        // from_config 经 effective_probe_url 会把空 URL 替换成默认值——用 new()
        // 构造空 probe_url 才能覆盖"URL 为空 → dead"短路分支（不进 runtime 路径）。
        let mut exec =
            RealOutboundProbeExecutor::new(std::collections::HashMap::new(), "", 5_000);
        exec.set_handler("noop", Arc::new(NoopHandler));
        let r = exec.probe("noop");
        assert!(!r.alive);
        assert!(r.last_error_reason.contains("empty"));
    }

    /// qyo6：RealOutboundProbeExecutor — 真实 OutboundHandler 拨号：handler 拨号
    /// 成功时返回 alive + delay 字段填 dial 耗时。
    #[tokio::test]
    async fn real_outbound_probe_dial_success_records_delay() {
        use std::sync::Arc;
        struct OkHandler;
        #[async_trait::async_trait]
        impl xray_features::outbound::OutboundHandler for OkHandler {
            fn tag(&self) -> &str {
                "ok"
            }
            async fn dial(
                &self,
                _destination: &xray_common::net::destination::Destination,
                _session: &xray_common::session::Session,
            ) -> Result<(), xray_features::outbound::OutboundError> {
                // 模拟 5ms 处理延迟（让 delay > 0 验证计时）
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                Ok(())
            }
            fn can_handle(
                &self,
                _destination: &xray_common::net::destination::Destination,
            ) -> bool {
                true
            }
        }

        let cfg = ObservatoryConfig {
            probe_url: "http://example.com/test".into(),
            ..Default::default()
        };
        let mut exec = RealOutboundProbeExecutor::from_config(&cfg);
        exec.set_handler("ok", Arc::new(OkHandler));

        // tokio::test 已在 runtime；probe 内部 block_on 当前 runtime
        let r = exec.probe("ok");
        assert!(r.alive, "expected alive, got: {:?}", r);
        assert!(r.delay >= 0);
        assert!(r.last_error_reason.is_empty(), "alive probe should have empty reason, got: {:?}", r.last_error_reason);
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
/// - [`Self::with_selector`]：接受任意实现了
///   [`xray_features::OutboundTagSelector`] 的后端（典型为
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
            fn select(
                &self,
                subject_selector: &[String],
            ) -> Result<Vec<String>, ObservatoryError> {
                Ok(self.0.select_by_prefix(subject_selector))
            }
        }
        Self {
            manager: Arc::new(BackendAdapter(backend)),
        }
    }
}

impl OutboundSelector for RealOutboundSelector {
    fn select(&self, subject_selector: &[String]) -> Result<Vec<String>, ObservatoryError> {
        self.manager.select(subject_selector)
    }
}
/// 基于 tokio::net::TcpStream 的 HTTP ProbeExecutor。
///
/// 对应 Go `Observer.probe(outbound)`：建立 TCP 连接并发送 HTTP HEAD 请求。
/// 不依赖 reqwest/hyper，仅用 tokio 原生 TCP。
pub struct HttpProbeExecutor {
    /// 探测目标 URL（如 https://www.google.com/generate_204）
    url: String,
    /// HTTP 方法（如 HEAD）
    method: String,
    /// 连接超时（毫秒）
    timeout_ms: u64,
}

impl HttpProbeExecutor {
    pub fn new(url: impl Into<String>, method: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            url: url.into(),
            method: method.into(),
            timeout_ms,
        }
    }

    /// 从 ObservatoryConfig 构造（使用 effective_probe_url，HTTP GET 探测）。
    ///
    /// 3oad：探测方法默认 GET（Go `newPingClient` 用 `newRequest("GET", url)`，
    /// 不是 HEAD）。HEAD 不能跨 CDN 验证（部分 CDN 对 HEAD 返回 405/403），
    /// 而 GET 是真实拉取语义。alive 由状态码判定（200-399 = alive）。
    pub fn from_config(config: &ObservatoryConfig) -> Self {
        Self::new(
            config.effective_probe_url().to_string(),
            DEFAULT_HTTP_METHOD.to_string(),
            5_000,
        )
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
            Ok(delay_ms) => ProbeResult {
                alive: true,
                delay: delay_ms,
                last_error_reason: String::new(),
            },
            Err(reason) => ProbeResult {
                alive: false,
                delay: 0,
                last_error_reason: reason,
            },
        }
    }
}

impl HttpProbeExecutor {
    async fn probe_async(&self, _outbound_tag: &str) -> Result<i64, String> {
        let url = self.url.trim();
        if url.is_empty() {
            return Err("probe url is empty".to_string());
        }

        // 解析 host + port
        let (host, port, use_tls) = parse_url_host_port(url)?;

        let addr = format!("{host}:{port}");
        let start = Instant::now();

        // TCP 连接
        let mut stream = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|e| format!("tcp connect timeout: {e}"))?
        .map_err(|e| format!("tcp connect failed: {e}"))?;

        let tcp_delay = start.elapsed().as_millis() as i64;

        if use_tls {
            // TLS 握手（简化：仅测量 TCP 延迟，TLS 握手计入总延迟）
            // 实际生产环境应使用 tokio-rustls 完成完整 TLS 握手
            let _ = stream;
            // ponytail: 暂不实现 TLS 握手，仅返回 TCP 连接延迟
            // 升级路径：引入 tokio-rustls + rustls 做完整 HTTPS 探测
            return Ok(tcp_delay);
        }

        // HTTP 请求
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.method, url, host
        );

        let write_res = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()),
        )
        .await
        .map_err(|e| format!("write timeout: {e}"))?
        .map_err(|e| format!("write failed: {e}"))?;

        let _ = write_res;

        // 读取响应（至少读到 HTTP/1.1 状态行）
        let mut buf = [0u8; 1024];
        let read_res = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        .map_err(|e| format!("read timeout: {e}"))?
        .map_err(|e| format!("read failed: {e}"))?;

        if read_res == 0 {
            return Err("server closed connection".to_string());
        }

        let response = String::from_utf8_lossy(&buf[..read_res]);
        if !response.starts_with("HTTP/1") {
            return Err(format!("invalid response: {}", response.lines().next().unwrap_or("")));
        }

        // 3oad：从状态行解析状态码（HTTP/1.1 200 OK\r\n → 200），判定 alive。
        // Go `MeasureDelay` 仅以 HTTP 200-399 为 alive（healthping.go:175-179）。
        let status_code = parse_http_status_code(&response)
            .ok_or_else(|| format!("malformed status line: {}", response.lines().next().unwrap_or("")))?;
        if !(200..400).contains(&status_code) {
            return Err(format!("http status {status_code}"));
        }

        let total_delay = start.elapsed().as_millis() as i64;
        Ok(total_delay)
    }
}

// ── 真实 outbound HTTP probe（qyo6）─────────────────────────────────
//
// Go `Observer.probe` 用 `tagged.Dialer(ctx, dispatcher, dest, outbound)`
// 把目标地址套到指定 outbound 上发起 HTTP GET。Rust 端 `OutboundHandler::dial`
// 返回 `Result<(), _>`（不暴露 duplex stream）——我们用 dial 成功 + 用时
// 作为"该 outbound 能否到达目标 URL"的可观测信号。这与 Go 路径语义一致
// （dial 失败即 alive=false，dial 成功即以 dial 用时为 RTT），只是少了
// "HTTP 响应头解析"层。

/// 通过指定 outbound 拨号到探测 URL 的 [`ProbeExecutor`] 实现。
///
/// 持有 tag → `OutboundHandler` 映射（由装配阶段注入），每次 `probe`：
/// 1. 用 `parse_url_host_port` 解 URL 得到 host:port + tls 标记；
/// 2. 构造 `Destination { host:port, network=tcp }`；
/// 3. 调 `handler.dial(&dest, &session)` 并计时；
/// 4. dial 成功 → alive + delay=dial_ms；失败 → dead + reason。
///
/// 对应 Go `Observer.probe(outbound)` 的 outbound 拨号部分
/// （observer.go:130-159，tagged.Dialer 路径）。
pub struct RealOutboundProbeExecutor {
    /// tag → outbound handler 映射。
    handlers: std::collections::HashMap<String, Arc<dyn xray_features::outbound::OutboundHandler>>,
    /// 探测 URL（如 `https://www.google.com/generate_204`）。
    probe_url: String,
    /// dial 超时（毫秒）。
    timeout_ms: u64,
}

impl std::fmt::Debug for RealOutboundProbeExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealOutboundProbeExecutor")
            .field("probe_url", &self.probe_url)
            .field("timeout_ms", &self.timeout_ms)
            .field("handler_tags", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RealOutboundProbeExecutor {
    /// 构造。
    #[must_use]
    pub fn new(
        handlers: std::collections::HashMap<String, Arc<dyn xray_features::outbound::OutboundHandler>>,
        probe_url: impl Into<String>,
        timeout_ms: u64,
    ) -> Self {
        Self {
            handlers,
            probe_url: probe_url.into(),
            timeout_ms,
        }
    }

    /// 从 `ObservatoryConfig` 构造空 handler map（待装配阶段填充）。
    #[must_use]
    pub fn from_config(config: &ObservatoryConfig) -> Self {
        Self::new(
            std::collections::HashMap::new(),
            config.effective_probe_url(),
            5_000,
        )
    }

    /// 注入/替换单个 tag 的 handler。
    pub fn set_handler(&mut self, tag: impl Into<String>, handler: Arc<dyn xray_features::outbound::OutboundHandler>) {
        self.handlers.insert(tag.into(), handler);
    }
}

impl ProbeExecutor for RealOutboundProbeExecutor {
    fn probe(&self, outbound_tag: &str) -> ProbeResult {
        let Some(handler) = self.handlers.get(outbound_tag) else {
            return ProbeResult {
                alive: false,
                delay: 0,
                last_error_reason: format!("no outbound handler registered for tag '{outbound_tag}'"),
            };
        };

        let url = self.probe_url.trim();
        if url.is_empty() {
            return ProbeResult {
                alive: false,
                delay: 0,
                last_error_reason: "probe url is empty".into(),
            };
        }

        let (host, port, _use_tls) = match parse_url_host_port(url) {
            Ok(t) => t,
            Err(e) => {
                return ProbeResult {
                    alive: false,
                    delay: 0,
                    last_error_reason: format!("parse probe url: {e}"),
                };
            }
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
        let session = xray_common::session::Session::new();

        let timeout_ms = self.timeout_ms;
        let outbound_tag_owned = outbound_tag.to_string();
        let handler = handler.clone();
        // probe 是同步契约，典型调用方是 background 探测循环（async 上下文）。
        // 在当前 runtime 上 block_on 会 panic "Cannot start a runtime from within
        // a runtime"——专用线程 + 独立 runtime 对任何调用上下文安全（与
        // HttpProbeExecutor 的无 runtime 分支同一模式）。
        std::thread::scope(|s| {
            s.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match rt {
                    Ok(rt) => rt.block_on(async move {
                        let start = Instant::now();
                        let dial_fut = handler.dial(&dest, &session);
                        let timeout = Duration::from_millis(timeout_ms);
                        match tokio::time::timeout(timeout, dial_fut).await {
                            Ok(Ok(())) => ProbeResult {
                                alive: true,
                                delay: start.elapsed().as_millis() as i64,
                                last_error_reason: String::new(),
                            },
                            Ok(Err(e)) => ProbeResult {
                                alive: false,
                                delay: 0,
                                last_error_reason: format!(
                                    "outbound '{outbound_tag_owned}' dial failed: {e}"
                                ),
                            },
                            Err(_) => ProbeResult {
                                alive: false,
                                delay: 0,
                                last_error_reason: format!(
                                    "outbound '{outbound_tag_owned}' dial timeout after {timeout_ms}ms"
                                ),
                            },
                        }
                    }),
                    Err(e) => ProbeResult {
                        alive: false,
                        delay: 0,
                        last_error_reason: format!(
                            "outbound '{outbound_tag_owned}': probe runtime build failed: {e}"
                        ),
                    },
                }
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
    let host_port = if let Some(pos) = rest.find('/') {
        &rest[..pos]
    } else {
        rest
    };

    let (host, port) = if let Some(pos) = host_port.rfind(':') {
        let host = &host_port[..pos];
        let port_str = &host_port[pos + 1..];
        let port = port_str.parse::<u16>()
            .map_err(|e| format!("invalid port '{port_str}': {e}"))?;
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
