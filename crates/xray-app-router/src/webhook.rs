//! Webhook 通知器（含去重）。
//!
//! 翻译自 `app/router/webhook.go`。
//!
//! # 实现
//!
//! - `post` 走手写 HTTP/1.1 客户端（不引入 reqwest/hyper）：
//!   - `http://host:port/path`           → `tokio::net::TcpStream`
//!   - `https://host:port/path`          → TCP + `tokio-rustls` TLS 握手
//!   - `/path/to/socket[:/url-path]`     → `tokio::net::UnixStream`（UDS dial）
//!   - `@abstract-name` / `@@padded`     → 同上（Linux/Android 抽象命名空间）
//! - 事件构造、去重逻辑独立可测

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{client::TlsConnector, rustls::ClientConfig};
use xray_proto::xray::app::router::WebhookConfig;

use crate::error::RouterError;

/// 默认 HTTP POST 超时（毫秒）。
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Webhook 目标协议。
///
/// 由 `parse_target` 从 URL 字符串解出。`Http`/`Https` 走 TCP，
/// `UnixSocket` 走 [`tokio::net::UnixStream`]（Go `SplitHTTPUnixURL`
/// 等价物）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WebhookTarget {
    /// `http://host:port/path`
    Http { host: String, port: u16, path: String },
    /// `https://host:port/path`
    Https { host: String, port: u16, path: String },
    /// `/abs/path[:/url-path]` 或 `@abstract[:/url-path]` 或 `@@padded[:/url-path]`
    UnixSocket { socket_path: String, http_path: String },
}


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
    ///
    /// 依据 URL 形式分派：
    /// - `http://`      → [`tokio::net::TcpStream`] + 手写 HTTP/1.1
    /// - `https://`     → TCP + [`tokio_rustls`] TLS 握手 + 手写 HTTP/1.1
    /// - `/abs/path`    → [`tokio::net::UnixStream`] 抽象拨号（UDS）+ 手写 HTTP/1.1
    async fn post_async(&self, body: &str) -> Result<(), RouterError> {
        let url = self.url.trim();
        if url.is_empty() {
            return Err(RouterError::Webhook("empty webhook url".to_string()));
        }
        let target = parse_webhook_target(url)
            .map_err(|e| RouterError::Webhook(e))?;
        let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);

        let request = match &target {
            WebhookTarget::Http { host, path, .. } => build_request(host, "http", path, body, &self.headers),
            WebhookTarget::Https { host, path, .. } => build_request(host, "https", path, body, &self.headers),
            WebhookTarget::UnixSocket { http_path, .. } => build_request("localhost", "http", http_path, body, &self.headers),
        };

        // 连接 + 写 + 读 + 解析响应
        let status = match target {
            WebhookTarget::Http { host, port, .. } => {
                let mut s = tcp_connect(&host, port, timeout).await?;
                http_handshake(&mut s, request.as_bytes(), timeout).await?
            }
            WebhookTarget::Https { host, port, .. } => {
                let s = tcp_connect(&host, port, timeout).await?;
                let connector = tls_connector()?;
                let server_name = ServerName::try_from(host.clone())
                    .map_err(|e| RouterError::Webhook(format!("invalid tls server name: {e}")))?;
                let mut tls = tokio::time::timeout(timeout, connector.connect(server_name, s))
                    .await
                    .map_err(|e| RouterError::Webhook(format!("tls handshake timeout: {e}")))?
                    .map_err(|e| RouterError::Webhook(format!("tls handshake failed: {e}")))?;
                http_handshake(&mut tls, request.as_bytes(), timeout).await?
            }
            #[cfg(unix)]
            WebhookTarget::UnixSocket { socket_path, .. } => {
                let mut s = tokio::time::timeout(timeout, UnixStream::connect(&socket_path))
                    .await
                    .map_err(|e| RouterError::Webhook(format!("unix connect timeout: {e}")))?
                    .map_err(|e| RouterError::Webhook(format!("unix connect failed: {e}")))?;
                http_handshake(&mut s, request.as_bytes(), timeout).await?
            }
            #[cfg(not(unix))]
            WebhookTarget::UnixSocket { .. } => {
                return Err(RouterError::Webhook(
                    "unix socket webhook is not supported on this platform".to_string(),
                ));
            }
        };

        if (200..300).contains(&status) {
            tracing::debug!(target: "xray_router::webhook", url = %self.url, status = status, "webhook post ok");
            Ok(())
        } else {
            Err(RouterError::Webhook(format!("webhook returned status {status}")))
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

/// 默认 HTTPS 端口（无显式 `:port` 时）。
const DEFAULT_HTTPS_PORT: u16 = 443;
/// 默认 HTTP 端口（无显式 `:port` 时）。
const DEFAULT_HTTP_PORT: u16 = 80;

/// 解析 webhook URL → [`WebhookTarget`]。
///
/// 三种合法形式（对齐 Go `utils.SplitHTTPUnixURL`）：
/// - `http://host[:port][/path]`  → [`WebhookTarget::Http`]
/// - `https://host[:port][/path]` → [`WebhookTarget::Https`]
/// - 绝对路径或抽象 socket（`/abs/path` `@abs` `@@padded`），
///   可附 `:/url-path` 改 HTTP 请求路径 → [`WebhookTarget::UnixSocket`]
fn parse_webhook_target(url: &str) -> Result<WebhookTarget, String> {
    if url.starts_with("http://") {
        parse_httpish(url, "http://", DEFAULT_HTTP_PORT)
    } else if url.starts_with("https://") {
        parse_httpish(url, "https://", DEFAULT_HTTPS_PORT)
    } else if is_unix_socket_form(url) {
        // 与 Go `SplitHTTPUnixURL` 等价：含 `":/"` 则按 `":/"` 切分；
        // 否则 socket_path = 整个 url，HTTP path = `"/"`。
        let (socket_path, http_path) = if let Some(idx) = url.find(":/") {
            (url[..idx].to_string(), url[idx + 1..].to_string())
        } else {
            (url.to_string(), "/".to_string())
        };
        Ok(WebhookTarget::UnixSocket { socket_path, http_path })
    } else {
        Err(format!("unsupported webhook url scheme: {url}"))
    }
}

/// 是否应视为 Unix socket 形式：绝对路径或 `@` 开头（Go 规则）。
fn is_unix_socket_form(url: &str) -> bool {
    url.starts_with('/') || url.starts_with('@')
}

/// 解析 `http://` 或 `https://` 形式 → host / port / path。
fn parse_httpish(url: &str, scheme: &str, default_port: u16) -> Result<WebhookTarget, String> {
    let rest = &url[scheme.len()..];
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let port: u16 = host_port[i + 1..]
                .parse()
                .map_err(|e| format!("invalid port: {e}"))?;
            (&host_port[..i], port)
        }
        None => (host_port, default_port),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let target = if scheme == "https://" {
        WebhookTarget::Https { host: host.to_string(), port, path: path.to_string() }
    } else {
        WebhookTarget::Http { host: host.to_string(), port, path: path.to_string() }
    };
    Ok(target)
}

/// 构造 HTTP/1.1 POST 报文（含 `Host` / `Content-Type` / `Content-Length` / 自定义 headers）。
fn build_request(host: &str, scheme: &str, path: &str, body: &str, headers: &std::collections::HashMap<String, String>) -> String {
    let mut s = format!("POST {path} HTTP/1.1\r\n");
    s.push_str(&format!("Host: {host}\r\n"));
    if scheme == "https" {
        // 默认 HTTPS 端口可省去；显式非 443 仍拼 `:port` 以兼容反代
        // （Host 头中包含端口是允许的，参见 RFC 7230 §5.4）。
        // 这里为简化拼接 `host` 本身（含显式端口情形由 caller 提供）。
    }
    s.push_str("Content-Type: application/json\r\n");
    s.push_str(&format!("Content-Length: {}\r\n", body.len()));
    s.push_str("Connection: close\r\n");
    for (k, v) in headers {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    s.push_str("\r\n");
    s.push_str(body);
    s
}

/// TCP 连接（含超时）。
async fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, RouterError> {
    let addr = format!("{host}:{port}");
    tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|e| RouterError::Webhook(format!("connect timeout: {e}")))?
        .map_err(|e| RouterError::Webhook(format!("connect failed: {e}")))
}

/// 共享 `TlsConnector`（一次性装载 `webpki_roots`，后续请求复用）。
///
/// ponytail: 全进程共享单连接器。若未来支持自签 CA / 钉扎证书，扩展为
/// `LazyLock<HashMap<Profile, Arc<ClientConfig>>>`。
fn tls_connector() -> Result<TlsConnector, RouterError> {
    use std::sync::LazyLock;
    static CONNECTOR: LazyLock<Result<TlsConnector, String>> = LazyLock::new(|| {
        // rustls ring crypto provider：test 并发场景下 `install_default` 多次返回 Ok(()) 即可
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(cfg)))
    });
    CONNECTOR
        .clone()
        .map_err(|e| RouterError::Webhook(format!("tls config init failed: {e}")))
}

/// 对 plaintext stream 发 POST + 读响应头，解析 HTTP 状态码。
async fn http_handshake<S>(stream: &mut S, body: &[u8], timeout: Duration) -> Result<u16, RouterError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, stream.write_all(body))
        .await
        .map_err(|e| RouterError::Webhook(format!("write timeout: {e}")))?
        .map_err(|e| RouterError::Webhook(format!("write failed: {e}")))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|e| RouterError::Webhook(format!("read timeout: {e}")))?
        .map_err(|e| RouterError::Webhook(format!("read failed: {e}")))?;

    let response = String::from_utf8_lossy(&buf[..n]);
    parse_http_status(&response).map_err(RouterError::Webhook)
}

/// 从 HTTP 响应解析状态码。
fn parse_http_status(response: &str) -> Result<u16, String> {
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
    fn test_parse_target_http_with_scheme() {
        let t = parse_webhook_target("http://example.com:9090/hook").unwrap();
        assert_eq!(
            t,
            WebhookTarget::Http {
                host: "example.com".into(),
                port: 9090,
                path: "/hook".into(),
            }
        );
    }

    #[test]
    fn test_parse_target_http_default_port() {
        let t = parse_webhook_target("http://example.com/hook").unwrap();
        match t {
            WebhookTarget::Http { host, port, path } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(path, "/hook");
            }
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_target_https_explicit_port() {
        let t = parse_webhook_target("https://x.com:8443/api").unwrap();
        match t {
            WebhookTarget::Https { host, port, path } => {
                assert_eq!(host, "x.com");
                assert_eq!(port, 8443);
                assert_eq!(path, "/api");
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_parse_target_https_default_port() {
        let t = parse_webhook_target("https://x.com").unwrap();
        match t {
            WebhookTarget::Https { port, path, .. } => {
                assert_eq!(port, 443);
                assert_eq!(path, "/");
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_parse_target_unix_socket() {
        let t = parse_webhook_target("/var/run/webhook.sock:/hook").unwrap();
        match t {
            WebhookTarget::UnixSocket { socket_path, http_path } => {
                assert_eq!(socket_path, "/var/run/webhook.sock");
                assert_eq!(http_path, "/hook");
            }
            _ => panic!("expected UnixSocket"),
        }
    }

    #[test]
    fn test_parse_target_unix_socket_no_path() {
        let t = parse_webhook_target("/tmp/web.sock").unwrap();
        match t {
            WebhookTarget::UnixSocket { socket_path, http_path } => {
                assert_eq!(socket_path, "/tmp/web.sock");
                assert_eq!(http_path, "/");
            }
            _ => panic!("expected UnixSocket"),
        }
    }

    #[test]
    fn test_parse_target_abstract_socket() {
        let t = parse_webhook_target("@abstract-name:/api").unwrap();
        match t {
            WebhookTarget::UnixSocket { socket_path, http_path } => {
                assert_eq!(socket_path, "@abstract-name");
                assert_eq!(http_path, "/api");
            }
            _ => panic!("expected UnixSocket"),
        }
    }

    #[test]
    fn test_parse_target_invalid_scheme() {
        assert!(parse_webhook_target("ftp://x.com").is_err());
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
