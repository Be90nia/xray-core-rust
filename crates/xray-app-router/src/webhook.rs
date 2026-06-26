//! Webhook 通知器（含去重）。
//!
//! 翻译自 `app/router/webhook.go`。
//!
//! # IO 边界
//!
//! - 实际 HTTP POST 留 TODO（`post` 方法 stub）
//! - 事件构造、去重逻辑独立可测

use std::collections::HashSet;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use xray_proto::xray::app::router::WebhookConfig;

use crate::error::RouterError;

/// Webhook 事件。
///
/// 对应 Go `router.event`。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WebhookEvent {
    /// 出站 tag。
    pub outbound_tag: String,
    /// 规则 tag。
    pub rule_tag: String,
    /// 当前状态（`hit` / `miss`）。
    pub status: String,
    /// 附加信息（如错误原因）。
    pub message: String,
}

impl WebhookEvent {
    /// 创建 hit 事件。
    #[must_use]
    pub fn hit(outbound_tag: impl Into<String>, rule_tag: impl Into<String>) -> Self {
        Self {
            outbound_tag: outbound_tag.into(),
            rule_tag: rule_tag.into(),
            status: "hit".into(),
            message: String::new(),
        }
    }

    /// 去重用的键。
    fn dedup_key(&self) -> String {
        format!("{}|{}|{}", self.outbound_tag, self.rule_tag, self.status)
    }
}

/// Webhook 通知器。
///
/// 对应 Go `WebhookNotifier`。
pub struct WebhookNotifier {
    url: String,
    #[allow(dead_code)]
    headers: std::collections::HashMap<String, String>,
    dedup_window: Duration,
    seen: Mutex<Seen>,
    #[allow(dead_code)]
    closed: Mutex<bool>,
}

struct Seen {
    keys: HashSet<String>,
    /// 记录首见时刻，用于窗口过期清理。
    timestamps: Vec<(String, Instant)>,
}

impl WebhookNotifier {
    /// 从 proto `WebhookConfig` 构造。
    ///
    /// `deduplication` 字段单位为秒（与 Go 一致）；为 0 表示禁用去重。
    #[must_use]
    pub fn new(config: &WebhookConfig) -> Self {
        let dedup_window = if config.deduplication > 0 {
            Duration::from_secs(u64::from(config.deduplication))
        } else {
            Duration::ZERO
        };
        Self {
            url: config.url.clone(),
            headers: config.headers.clone(),
            dedup_window,
            seen: Mutex::new(Seen {
                keys: HashSet::new(),
                timestamps: Vec::new(),
            }),
            closed: Mutex::new(false),
        }
    }

    /// 返回目标 URL。
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// 触发事件（含去重）。返回是否真的发出。
    ///
    /// 对应 Go `WebhookNotifier.Fire`。
    pub fn fire(&self, event: &WebhookEvent) -> Result<bool, RouterError> {
        if *self.closed.lock() {
            return Ok(false);
        }
        if self.is_duplicate(event) {
            return Ok(false);
        }
        let body = serde_json::to_value(event)
            .map_err(|e| RouterError::Webhook(e.to_string()))?;
        self.post(&body)?;
        Ok(true)
    }

    /// 判重并记录。返回是否重复（true=重复，跳过）。
    pub fn is_duplicate(&self, event: &WebhookEvent) -> bool {
        if self.dedup_window.is_zero() {
            return false;
        }
        let mut seen = self.seen.lock();
        self.cleanup_expired_locked(&mut seen);
        let key = event.dedup_key();
        if seen.keys.contains(&key) {
            return true;
        }
        seen.keys.insert(key.clone());
        seen.timestamps.push((key, Instant::now()));
        false
    }

    /// 执行 HTTP POST。
    ///
    /// TODO: 接入 reqwest / hyper。当前仅记录 log。
    fn post(&self, _body: &serde_json::Value) -> Result<(), RouterError> {
        tracing::debug!(target: "xray_router::webhook", url = %self.url, "webhook post (stub)");
        // TODO: 实际 HTTP POST，带上 self.headers
        Ok(())
    }

    /// 关闭。后续 fire 返回 Ok(false)。
    pub fn close(&self) {
        *self.closed.lock() = true;
    }

    /// 清理过期去重条目（调用者持锁）。
    fn cleanup_expired_locked(&self, seen: &mut Seen) {
        if self.dedup_window.is_zero() {
            return;
        }
        let now = Instant::now();
        let cutoff = self.dedup_window;
        let mut keep_keys = HashSet::new();
        let mut keep_ts = Vec::new();
        for (k, t) in seen.timestamps.drain(..) {
            if now.duration_since(t) < cutoff {
                keep_keys.insert(k.clone());
                keep_ts.push((k, t));
            }
        }
        seen.keys = keep_keys;
        seen.timestamps = keep_ts;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str, dedup: u32) -> WebhookConfig {
        WebhookConfig {
            url: url.into(),
            deduplication: dedup,
            headers: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_fire_returns_true_when_no_dedup() {
        let n = WebhookNotifier::new(&cfg("http://x", 0));
        let ev = WebhookEvent::hit("tag", "rule");
        assert!(n.fire(&ev).unwrap());
    }

    #[test]
    fn test_dedup_blocks_second_within_window() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        let ev = WebhookEvent::hit("tag", "rule");
        assert!(n.fire(&ev).unwrap());
        assert!(!n.fire(&ev).unwrap());
    }

    #[test]
    fn test_dedup_different_events_pass() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        let ev1 = WebhookEvent::hit("tag1", "rule");
        let ev2 = WebhookEvent::hit("tag2", "rule");
        assert!(n.fire(&ev1).unwrap());
        assert!(n.fire(&ev2).unwrap());
    }

    #[test]
    fn test_close_blocks_subsequent_fire() {
        let n = WebhookNotifier::new(&cfg("http://x", 0));
        n.close();
        let ev = WebhookEvent::hit("x", "y");
        assert!(!n.fire(&ev).unwrap());
    }

    #[test]
    fn test_is_duplicate_zero_window_never_dupes() {
        let n = WebhookNotifier::new(&cfg("", 0));
        let ev = WebhookEvent::hit("a", "b");
        assert!(!n.is_duplicate(&ev));
        assert!(!n.is_duplicate(&ev));
    }

    #[test]
    fn test_event_dedup_key_stable() {
        let e1 = WebhookEvent::hit("a", "b");
        let e2 = WebhookEvent::hit("a", "b");
        assert_eq!(e1.dedup_key(), e2.dedup_key());
        let e3 = WebhookEvent::hit("a", "c");
        assert_ne!(e1.dedup_key(), e3.dedup_key());
    }
}
