//! Observer 编排 + ProbeExecutor / OutboundSelector / Scheduler 注入 trait。
//!
//! 对应 Go `app/observatory/observer.go` 的 `Observer` struct + background loop。
//! 实际 HTTP probe + dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::config::{ObservationResult, ObservatoryConfig, OutboundStatus, ProbeResult};
use crate::error::{at_error, at_warning, ObservatoryError};
use crate::status::StatusStore;

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
}

impl Observer {
    pub fn new(config: ObservatoryConfig) -> Self {
        Self {
            config,
            status: Arc::new(StatusStore::new()),
            state: Mutex::new(ObserverState { started: false }),
        }
    }

    pub fn config(&self) -> &ObservatoryConfig {
        &self.config
    }

    pub fn status_store(&self) -> &Arc<StatusStore> {
        &self.status
    }

    /// 标记为已启动。
    pub fn start(&self) -> Result<(), ObservatoryError> {
        let mut g = self.state.lock();
        if g.started {
            return Err(ObservatoryError::AlreadyStarted);
        }
        // 与 Go 一致：subject_selector 为空时不实际启动 background
        g.started = !self.config.subject_selector.is_empty();
        Ok(())
    }

    /// 标记为已停止。
    pub fn close(&self) -> Result<(), ObservatoryError> {
        let mut g = self.state.lock();
        if !g.started {
            return Ok(());
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
    pub fn probe_all(
        &self,
        selector: &dyn OutboundSelector,
        executor: &dyn ProbeExecutor,
    ) -> Result<usize, ObservatoryError> {
        let tags = selector.select(&self.config.subject_selector)?;

        // 先清理已移除的 outbound
        self.status.clear_removed(&tags);

        let now = now_unix_secs();
        for tag in &tags {
            let result = executor.probe(tag);
            self.status.update_with_probe_result(tag, &result, now);
        }
        Ok(tags.len())
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

    #[test]
    fn start_with_selector_marks_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        o.start().unwrap();
        assert!(o.is_started());
    }

    #[test]
    fn start_without_selector_not_started() {
        let o = Observer::new(ObservatoryConfig::default());
        o.start().unwrap();
        assert!(!o.is_started()); // subject_selector 空
    }

    #[test]
    fn start_twice_returns_already_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        o.start().unwrap();
        let err = o.start().unwrap_err();
        assert!(matches!(err, ObservatoryError::AlreadyStarted));
    }

    #[test]
    fn close_marks_not_started() {
        let o = Observer::new(cfg_with_selector(&["a"]));
        o.start().unwrap();
        o.close().unwrap();
        assert!(!o.is_started());
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
}
