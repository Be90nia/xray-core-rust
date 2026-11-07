//! Webhook 通知器（含去重）。
//!
//! 翻译自 `app/router/webhook.go`。
//!
//! # 实现
//!
//! - fire-and-forget：`fire` 只做事件构造 + 去重，POST 走旁路任务 （tokio 上下文内 `spawn`，无
//!   runtime 时起临时线程），**绝不阻塞路由**。
//! - `post` 走手写 HTTP/1.1 客户端（不引入 reqwest/hyper）：
//!   - `http://host:port/path`           → `tokio::net::TcpStream`
//!   - `https://host:port/path`          → TCP + `tokio-rustls` TLS 握手
//!   - `/path/to/socket[:/url-path]`     → `tokio::net::UnixStream`（UDS dial）
//!   - `@abstract-name` / `@@padded`     → 同上（Linux/Android 抽象命名空间）
//! - 事件构造、去重逻辑独立可测

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use skeleton::clock::{Clock, SystemClock};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    client::TlsConnector,
    rustls::{ClientConfig, pki_types::ServerName},
};
use xray_proto::xray::app::router::WebhookConfig;

use crate::{context::RoutingContext, error::RouterError};

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
/// 对应 Go `app/router/webhook.go:23-37` 的 `event`：13 个字段、JSON 键名逐字
/// 对齐（Go `*T` 指针语义 → `Option`，缺值序列化为 `null`；Go 无 omitempty）。
///
/// 4 个字段在 Rust 侧无来源（Go 从 `routing_session.Context` 的 Inbound/Outbound
/// 载荷填充）——[`RoutingContext`] 不承载
/// user level / inbound name / originalTarget / routeTarget ⇒ 恒 `null`。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookEvent {
    /// 用户邮箱（Go `email`；**也是去重键**）。
    pub email: Option<String>,
    /// 用户 level（Go `level`）。
    pub level: Option<u32>,
    /// 嗅探出的协议（Go `protocol`）。
    pub protocol: Option<String>,
    /// 网络类型（Go `network`）。
    pub network: Option<String>,
    /// `src_ip:src_port`（Go `source`）。
    pub source: Option<String>,
    /// `dst_ip|domain:port`（Go `destination`）。
    pub destination: Option<String>,
    /// 原始目标（Go `originalTarget`）。
    #[serde(rename = "originalTarget")]
    pub original_target: Option<String>,
    /// 路由目标（Go `routeTarget`）。
    #[serde(rename = "routeTarget")]
    pub route_target: Option<String>,
    /// 入站 tag（Go `inboundTag`）。
    #[serde(rename = "inboundTag")]
    pub inbound_tag: Option<String>,
    /// 入站名（Go `inboundName`）。
    #[serde(rename = "inboundName")]
    pub inbound_name: Option<String>,
    /// `local_ip:local_port`（Go `inboundLocal`）。
    #[serde(rename = "inboundLocal")]
    pub inbound_local: Option<String>,
    /// 出站 tag（Go `outboundTag`）。
    #[serde(rename = "outboundTag")]
    pub outbound_tag: Option<String>,
    /// 事件时间（Unix 秒；Go `ts`）。
    pub ts: i64,
}

impl WebhookEvent {
    /// 从路由上下文构造。对应 Go `buildEvent`。
    ///
    /// `now` = Go `time.Now()`：由调用方从注入时钟（`WebhookNotifier.clock`）取，
    /// 不在此直取挂钟（713x6 时钟唯一源 = `skeleton::clock`）。
    #[must_use]
    pub fn from_context(ctx: &dyn RoutingContext, outbound_tag: &str, now: SystemTime) -> Self {
        let destination = if ctx.get_target_domain().is_empty() {
            ctx.get_target_ips()
                .first()
                .map(|ip| join_host_port(&ip.to_string(), ctx.get_target_port().value()))
        } else {
            Some(join_host_port(ctx.get_target_domain(), ctx.get_target_port().value()))
        };
        Self {
            email: non_empty(ctx.get_user()),
            level: None,
            protocol: Some(ctx.get_protocol().to_string()),
            network: Some(ctx.get_network().as_str().to_string()),
            source: ctx
                .get_source_ips()
                .first()
                .map(|ip| join_host_port(&ip.to_string(), ctx.get_source_port().value())),
            destination,
            original_target: None,
            route_target: None,
            inbound_tag: Some(ctx.get_inbound_tag().to_string()),
            inbound_name: None,
            inbound_local: ctx
                .get_local_ips()
                .first()
                .map(|ip| join_host_port(&ip.to_string(), ctx.get_local_port().value())),
            outbound_tag: Some(outbound_tag.to_string()),
            ts: unix_secs(now),
        }
    }
}

/// Go `net.JoinHostPort`：主机含 `:`（IPv6）时加方括号。
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// Go `if user != "" { ev.Email = ptr(user) }`。
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}

/// Go `time.Now().Unix()`。
fn unix_secs(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Webhook 通知器。
///
/// 对应 Go `WebhookNotifier`。
pub struct WebhookNotifier {
    url: String,
    headers: std::collections::HashMap<String, String>,
    dedup_window: Duration,
    seen: Mutex<Seen>,
    closed: Mutex<bool>,
    /// 713x6：去重窗口时间源；生产 `SystemClock`，测试可注入 `MockClock`。
    clock: Arc<dyn Clock>,
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
            seen: Mutex::new(Seen { keys: HashSet::new(), timestamps: Vec::new() }),
            closed: Mutex::new(false),
            clock: Arc::new(SystemClock),
        }
    }

    /// 713x6：注入时钟（`new` 缺省 `SystemClock`，行为不变）。
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// 返回目标 URL。
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// 触发事件（fire-and-forget）。返回是否真的排队发送（close / 去重拦截 = false）。
    ///
    /// 对应 Go `WebhookNotifier.Fire`：旁路发送，不阻塞路由、不 panic。
    pub fn fire(&self, ctx: &dyn RoutingContext, outbound_tag: &str) -> bool {
        if *self.closed.lock() {
            return false;
        }
        let event = WebhookEvent::from_context(ctx, outbound_tag, self.clock.now_system());
        if self.is_duplicate(event.email.as_deref().unwrap_or_default()) {
            return false;
        }
        self.spawn_post(event);
        true
    }

    /// 判重并记录。返回是否重复（true = 重复，跳过）。
    ///
    /// 对应 Go `isDuplicate`：去重键 = **email**；`deduplication == 0` 或 email
    /// 为空时一律不去重。
    pub fn is_duplicate(&self, email: &str) -> bool {
        if self.dedup_window.is_zero() || email.is_empty() {
            return false;
        }
        let mut seen = self.seen.lock();
        self.cleanup_expired_locked(&mut seen);
        let key = email.to_string();
        if seen.keys.contains(&key) {
            return true;
        }
        seen.keys.insert(key.clone());
        // 713x6：首见时刻取自注入时钟（原 std 直通语义）。
        seen.timestamps.push((key, self.clock.now_instant()));
        false
    }

    /// Go `webhook.go:113` 的 goroutine 旁路：tokio 上下文内 `spawn`，
    /// 无 runtime（同步调用/测试）起临时线程。
    ///
    /// nqs31：原实现在 async 上下文里调 `Handle::block_on`——tokio 语义必然
    /// panic（"Cannot start a runtime from within a runtime"），且 `let _ =` 吞不掉 panic。
    fn spawn_post(&self, event: WebhookEvent) {
        let body = match serde_json::to_string(&event) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!(target: "xray_router::webhook", error = %e, "webhook: marshal failed");
                return;
            },
        };
        let url = self.url.clone();
        let headers = self.headers.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = post_url(&url, &headers, &body).await {
                    tracing::warn!(target: "xray_router::webhook", url = %url, error = %e, "webhook post failed");
                }
            });
            return;
        }
        // ② 豁免类（CLAUDE.md §3.5.6）：webhook POST 必须活得比调用方久
        // （fire-and-forget I/O，Go 同样是裸 goroutine），且**无 tokio runtime 的
        // 同步调用方**只能借 OS 线程起临时 runtime。
        #[allow(
            clippy::disallowed_methods,
            reason = "webhook POST 属豁免类任务（须活得比调用方久）；无 runtime 的同步调用方只能走 OS 线程兜底"
        )]
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(target: "xray_router::webhook", error = %e, "webhook: runtime build failed");
                    return;
                },
            };
            if let Err(e) = rt.block_on(post_url(&url, &headers, &body)) {
                tracing::warn!(target: "xray_router::webhook", url = %url, error = %e, "webhook post failed");
            }
        });
    }

    /// 关闭。后续 fire 返回 false。
    pub fn close(&self) {
        *self.closed.lock() = true;
    }

    /// 清理过期去重条目（调用者持锁）。
    fn cleanup_expired_locked(&self, seen: &mut Seen) {
        if self.dedup_window.is_zero() {
            return;
        }
        // 713x6：窗口判定取自注入时钟（原 std 直通语义）。
        let now = self.clock.now_instant();
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

/// 异步 HTTP POST 实现（自由函数：旁路任务持 owned 参数，无需 `&self`）。
///
/// 依据 URL 形式分派：
/// - `http://`      → [`tokio::net::TcpStream`] + 手写 HTTP/1.1
/// - `https://`     → TCP + [`tokio_rustls`] TLS 握手 + 手写 HTTP/1.1
/// - `/abs/path`    → [`tokio::net::UnixStream`] 抽象拨号（UDS）+ 手写 HTTP/1.1
async fn post_url(
    url: &str,
    headers: &std::collections::HashMap<String, String>,
    body: &str,
) -> Result<(), RouterError> {
    let url = url.trim();
    if url.is_empty() {
        return Err(RouterError::Webhook("empty webhook url".to_string()));
    }
    let target = parse_webhook_target(url).map_err(RouterError::Webhook)?;
    let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);

    let request = match &target {
        WebhookTarget::Http { host, path, .. } => build_request(host, "http", path, body, headers),
        WebhookTarget::Https { host, path, .. } => {
            build_request(host, "https", path, body, headers)
        },
        WebhookTarget::UnixSocket { http_path, .. } => {
            build_request("localhost", "http", http_path, body, headers)
        },
    };

    // 连接 + 写 + 读 + 解析响应
    let status = match target {
        WebhookTarget::Http { host, port, .. } => {
            let mut s = tcp_connect(&host, port, timeout).await?;
            http_handshake(&mut s, request.as_bytes(), timeout).await?
        },
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
        },
        #[cfg(unix)]
        WebhookTarget::UnixSocket { socket_path, .. } => {
            let mut s = tokio::time::timeout(timeout, UnixStream::connect(&socket_path))
                .await
                .map_err(|e| RouterError::Webhook(format!("unix connect timeout: {e}")))?
                .map_err(|e| RouterError::Webhook(format!("unix connect failed: {e}")))?;
            http_handshake(&mut s, request.as_bytes(), timeout).await?
        },
        #[cfg(not(unix))]
        WebhookTarget::UnixSocket { .. } => {
            return Err(RouterError::Webhook(
                "unix socket webhook is not supported on this platform".to_string(),
            ));
        },
    };

    if (200..300).contains(&status) {
        tracing::debug!(target: "xray_router::webhook", url = %url, status = status, "webhook post ok");
        Ok(())
    } else {
        Err(RouterError::Webhook(format!("webhook returned status {status}")))
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
/// - 绝对路径或抽象 socket（`/abs/path` `@abs` `@@padded`）， 可附 `:/url-path` 改 HTTP 请求路径 →
///   [`WebhookTarget::UnixSocket`]
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
            let port: u16 = host_port[i + 1..].parse().map_err(|e| format!("invalid port: {e}"))?;
            (&host_port[..i], port)
        },
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
fn build_request(
    host: &str,
    scheme: &str,
    path: &str,
    body: &str,
    headers: &std::collections::HashMap<String, String>,
) -> String {
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
        // rustls ring provider 经 xray-common 集中入口幂等安装（bd jrh7）。
        xray_common::ensure_default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(cfg)))
    });
    CONNECTOR.clone().map_err(|e| RouterError::Webhook(format!("tls config init failed: {e}")))
}

/// 对 plaintext stream 发 POST + 读响应头，解析 HTTP 状态码。
async fn http_handshake<S>(
    stream: &mut S,
    body: &[u8],
    timeout: Duration,
) -> Result<u16, RouterError>
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
    use crate::context::RoutingData;

    fn cfg(url: &str, dedup: u32) -> WebhookConfig {
        WebhookConfig {
            url: url.into(),
            deduplication: dedup,
            headers: std::collections::HashMap::new(),
        }
    }

    /// nqs31 回归：async 执行上下文里 fire 不得 panic。
    ///
    /// 原实现走 `Handle::block_on`（tokio 语义必 panic"不能从 runtime 内部启动
    /// runtime"），`let _ =` 只吞 `Result` 吞不掉 panic ⇒ 配置了 webhook 的规则
    /// 首次命中即打穿任务边界。
    #[tokio::test]
    async fn test_fire_in_async_context_does_not_panic() {
        // 端口 1 不可达：fire 只排队，连接失败在旁路任务里记日志。
        let n = WebhookNotifier::new(&cfg("http://127.0.0.1:1", 0));
        let ctx = RoutingData::new().with_target_domain("example.com");
        assert!(n.fire(&ctx, "direct"), "首次命中应排队发送");
    }

    #[test]
    fn test_close_blocks_subsequent_fire() {
        let n = WebhookNotifier::new(&cfg("http://127.0.0.1:1", 0));
        n.close();
        let ctx = RoutingData::new();
        // close 后 fire 返回 false，不排队 POST。
        assert!(!n.fire(&ctx, "x"));
    }

    #[test]
    fn test_dedup_blocks_second_within_window() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        assert!(!n.is_duplicate("tag@example.com"));
        assert!(n.is_duplicate("tag@example.com"));
    }

    /// 713x6 时钟可注入性验收：MockClock 推进越过去重窗口 → 同键重新放行
    /// （行为断言，非"不 panic"；SystemClock 下需真等 60s 不可测）。
    #[test]
    fn mock_clock_advance_expires_dedup_window() {
        let clock = Arc::new(skeleton::clock::MockClock::new());
        let n = WebhookNotifier::new(&cfg("http://x", 60)).with_clock(clock.clone());
        assert!(!n.is_duplicate("a@example.com"), "首见非重复");
        assert!(n.is_duplicate("a@example.com"), "窗口内重复");
        clock.advance(Duration::from_secs(61));
        assert!(!n.is_duplicate("a@example.com"), "窗口过期后重新放行");
    }

    #[test]
    fn test_dedup_different_emails_pass() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        assert!(!n.is_duplicate("a@example.com"));
        assert!(!n.is_duplicate("b@example.com"));
    }

    /// yh01f-b 回归：去重键 = **email**（Go `isDuplicate`），与 tag/rule 无关；
    /// 空 email 一律不去重。
    #[test]
    fn test_dedup_key_is_email_and_empty_is_never_duplicate() {
        let n = WebhookNotifier::new(&cfg("http://x", 60));
        assert!(!n.is_duplicate(""), "空 email 不去重");
        assert!(!n.is_duplicate(""), "空 email 仍不去重");
        assert!(!n.is_duplicate("a@example.com"));
        assert!(n.is_duplicate("a@example.com"));
    }

    #[test]
    fn test_is_duplicate_zero_window_never_dupes() {
        let n = WebhookNotifier::new(&cfg("", 0));
        assert!(!n.is_duplicate("a@example.com"));
        assert!(!n.is_duplicate("a@example.com"));
    }

    /// yh01f-b 回归：事件 JSON 键名逐字对齐 Go `router.event`（13 键，缺值为
    /// `null`，无 omitempty），接 Go 生态接收端不会解析失败。
    #[test]
    fn test_event_json_schema_matches_go() {
        let ctx = RoutingData::new()
            .with_target_domain("example.com")
            .with_inbound_tag("in0")
            .with_protocol("tls")
            .with_user("a@example.com");
        let v = serde_json::to_value(WebhookEvent::from_context(
            &ctx,
            "direct",
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ))
        .unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "destination",
                "email",
                "inboundLocal",
                "inboundName",
                "inboundTag",
                "level",
                "network",
                "originalTarget",
                "outboundTag",
                "protocol",
                "routeTarget",
                "source",
                "ts",
            ]
        );
        assert_eq!(obj["outboundTag"], serde_json::json!("direct"));
        assert_eq!(obj["inboundTag"], serde_json::json!("in0"));
        assert_eq!(obj["protocol"], serde_json::json!("tls"));
        assert_eq!(obj["network"], serde_json::json!("tcp"));
        assert_eq!(obj["email"], serde_json::json!("a@example.com"));
        // 无来源的四个字段（Go 从 session 载荷填充）序列化为 null。
        assert!(obj["level"].is_null());
        assert!(obj["inboundName"].is_null());
        assert!(obj["originalTarget"].is_null());
        assert!(obj["routeTarget"].is_null());
    }

    // ── HTTP 辅助函数 ──

    #[test]
    fn test_parse_target_http_with_scheme() {
        let t = parse_webhook_target("http://example.com:9090/hook").unwrap();
        assert_eq!(
            t,
            WebhookTarget::Http { host: "example.com".into(), port: 9090, path: "/hook".into() }
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
            },
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
            },
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
            },
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
            },
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
            },
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
            },
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
