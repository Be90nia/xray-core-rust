//! Webhook 通知器（含去重）。
//!
//! 翻译自 `app/router/webhook.go`。
//!
//! # 实现
//!
//! - `post` 通过 `tokio::net::TcpStream` 手写 HTTP POST（不引入 reqwest）
//! - 事件构造、去重逻辑独立可测

use std::collections::HashSet;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xray_proto::xray::app::router::WebhookConfig;

use crate::error::RouterError;

/// 默认 HTTP POST 超时（毫秒）。
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

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

    /// 执行 HTTP POST 到 webhook URL。
    ///
    /// 通过 `tokio::net::TcpStream` 手写 HTTP POST，不依赖 reqwest/hyper。
    /// 返回 2xx 视为成功，其余视为失败。
    fn post(&self, body: &serde_json::Value) -> Result<(), RouterError> {
        let body_str = serde_json::to_string(body)
            .map_err(|e| RouterError::Webhook(e.to_string()))?;

        let result = tokio::runtime::Handle::try_current()
            .map(|handle| handle.block_on(async { self.post_async(&body_str).await }))
            .unwrap_or_else(|_| {
                // 无 tokio runtime 时创建临时 runtime
                std::thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|e| RouterError::Webhook(e.to_string()))?;
                        rt.block_on(async { self.post_async(&body_str).await })
                    }).join().unwrap_or_else(|e| Err(RouterError::Webhook(format!("thread panicked: {e:?}"))))
                })
            });

        result
    }

    /// 异步 HTTP POST 实现。
    async fn post_async(&self, body: &str) -> Result<(), RouterError> {
        let url = self.url.trim();
        if url.is_empty() {
            return Err(RouterError::Webhook("empty webhook url".to_string()));
        }

        let (host, port) = parse_webhook_host_port(url)
            .map_err(|e| RouterError::Webhook(e))?;

        let addr = format!("{host}:{port}");
        let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);

        // TCP 连接
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|e| RouterError::Webhook(format!("connect timeout: {e}")))?
            .map_err(|e| RouterError::Webhook(format!("connect failed: {e}")))?;

        // 构造 HTTP POST 请求（手写，不含 TLS）
        // ponytail: 不实现 TLS，webhook 通常在内网。升级路径：引入 tokio-rustls。
        let path = extract_path(url);
        let mut header_lines = format!("POST {path} HTTP/1.1\r\n");
        header_lines.push_str(&format!("Host: {host}\r\n"));
        header_lines.push_str("Content-Type: application/json\r\n");
        header_lines.push_str(&format!("Content-Length: {}\r\n", body.len()));
        header_lines.push_str("Connection: close\r\n");
        // 自定义 headers
        for (k, v) in &self.headers {
            header_lines.push_str(&format!("{k}: {v}\r\n"));
        }
        header_lines.push_str("\r\n");

        let request = format!("{header_lines}{body}");

        // 写入请求
        tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|e| RouterError::Webhook(format!("write timeout: {e}")))?
            .map_err(|e| RouterError::Webhook(format!("write failed: {e}")))?;

        // 读取响应状态行
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|e| RouterError::Webhook(format!("read timeout: {e}")))?
            .map_err(|e| RouterError::Webhook(format!("read failed: {e}")))?;

        // 解析 HTTP 状态码
        let response = String::from_utf8_lossy(&buf[..n]);
        let status_code = parse_http_status(&response)
            .map_err(|e| RouterError::Webhook(e))?;

        if (200..300).contains(&status_code) {
            tracing::debug!(target: "xray_router::webhook", url = %self.url, status = status_code, "webhook post ok");
            Ok(())
        } else {
            Err(RouterError::Webhook(format!("webhook returned status {status_code}")))
        }
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

// ── HTTP 辅助函数 ────────────────────────────────────────────────

/// 从 URL 提取 (host, port)。
///
/// 支持格式：`http://host:port/path` 或 `host:port`。
/// 不支持 HTTPS（ponytail: TLS 升级路径：引入 tokio-rustls）。
fn parse_webhook_host_port(url: &str) -> Result<(String, u16), String> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let stripped = stripped.strip_prefix("https://").unwrap_or(stripped);
    // 找到第一个 / 分离路径
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some(idx) = host_port.rfind(':') {
        let host = host_port[..idx].to_string();
        let port: u16 = host_port[idx + 1..].parse().map_err(|e| format!("invalid port: {e}"))?;
        Ok((host, port))
    } else {
        // 默认端口 80
        Ok((host_port.to_string(), 80))
    }
}

/// 从 URL 提取路径部分（用于 HTTP 请求行）。
fn extract_path(url: &str) -> String {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let stripped = stripped.strip_prefix("https://").unwrap_or(stripped);
    if let Some(idx) = stripped.find('/') {
        stripped[idx..].to_string()
    } else {
        "/".to_string()
    }
}

/// 从 HTTP 响应解析状态码。
fn parse_http_status(response: &str) -> Result<u16, String> {
    // 期望格式: HTTP/1.1 200 OK
    let line = response.lines().next().unwrap_or("");
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().map_err(|e| format!("invalid status code: {e}"))
    } else {
        Err("malformed HTTP response".to_string())
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
    fn test_fire_attempts_post_and_returns_err_on_connect_failure() {
        // 端口 1 通常不可达，fire 返回连接错误
        let n = WebhookNotifier::new(&cfg("http://127.0.0.1:1", 0));
        let ev = WebhookEvent::hit("tag", "rule");
        assert!(n.fire(&ev).is_err());
    }

    #[test]
    fn test_dedup_blocks_second_within_window() {
        // 直接测试去重逻辑（不触发 fire 的 HTTP POST）
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        let ev = WebhookEvent::hit("tag", "rule");
        assert!(!n.is_duplicate(&ev));
        assert!(n.is_duplicate(&ev));
    }

    #[test]
    fn test_dedup_different_events_pass() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        let ev1 = WebhookEvent::hit("tag1", "rule");
        let ev2 = WebhookEvent::hit("tag2", "rule");
        assert!(!n.is_duplicate(&ev1));
        assert!(!n.is_duplicate(&ev2));
    }

    #[test]
    fn test_close_blocks_subsequent_fire() {
        let n = WebhookNotifier::new(&cfg("http://127.0.0.1:1", 0));
        n.close();
        let ev = WebhookEvent::hit("x", "y");
        // close 后 fire 返回 Ok(false)，不尝试 POST
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

    // ── HTTP 辅助函数 ──

    #[test]
    fn test_parse_webhook_host_port_with_scheme() {
        let (host, port) = parse_webhook_host_port("http://example.com:9090/hook").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 9090);
    }

    #[test]
    fn test_parse_webhook_host_port_default_port() {
        let (host, port) = parse_webhook_host_port("http://example.com/hook").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_webhook_host_port_bare() {
        let (host, port) = parse_webhook_host_port("192.168.1.1:8080").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_extract_path_with_scheme() {
        assert_eq!(extract_path("http://x.com/api/hook"), "/api/hook");
    }

    #[test]
    fn test_extract_path_no_path() {
        assert_eq!(extract_path("http://x.com"), "/");
    }

    #[test]
    fn test_parse_http_status_ok() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert_eq!(parse_http_status("HTTP/1.1 201 Created\r\n").unwrap(), 201);
    }

    #[test]
    fn test_parse_http_status_error() {
        assert_eq!(parse_http_status("HTTP/1.1 500 Internal Server Error\r\n").unwrap(), 500);
    }
}
