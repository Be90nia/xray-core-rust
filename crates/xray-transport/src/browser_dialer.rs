//! # Browser dialer
//!
//! 对应 Go `transport/internet/browser_dialer/dialer.go`。
//!
//! 通过内嵌 HTML/JS 页面 + WebSocket 连接到浏览器扩展，将浏览器作为代理拨号器。
//! 浏览器扩展加载内嵌页面后，通过 WS 接收任务（WS/GET/POST），在浏览器内发起请求并回传结果。

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

// ── 内嵌 HTML/JS 资源 ──────────────────────────────────────────────
// 对应 Go 的 `//go:embed dialer.html`。将浏览器扩展页面作为 const str 内嵌。
// csrfToken 占位符在运行时替换为实际 CSRF token。

/// 内嵌的浏览器拨号器 HTML 页面。`csrfToken` 在运行时替换为实际 token。
const DIALER_HTML_TEMPLATE: &str = include_str!("browser_dialer.html");

// ── 错误类型 ──────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BrowserDialerError {
    #[error("browser dialer not active")]
    NotActive,
    #[error("no available browser connection")]
    NoConnection,
    #[error("browser connection failed: {0}")]
    ConnectionFailed(String),
    #[error("browser task rejected: {0}")]
    TaskRejected(String),
    #[error("websocket error: {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

// ── 任务类型 ──────────────────────────────────────────────────────
// 对应 Go `task` struct。

/// 浏览器拨号器任务。通过 WS 发送给浏览器扩展执行。
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserTask {
    method: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<serde_json::Value>,
    stream_response: bool,
}

/// WS 拨号额外参数。对应 Go `webSocketExtra`。
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WsExtra {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}

/// HTTP 拨号额外参数。对应 Go `httpExtra`。
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpExtra {
    #[serde(skip_serializing_if = "Option::is_none")]
    referrer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<std::collections::HashMap<String, String>>,
}

// ── 配置 ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct BrowserDialerConfig {
    pub listen: Option<SocketAddr>,
}

// ── BrowserDialer ─────────────────────────────────────────────────

/// 浏览器拨号器。管理 WS 连接池，派发任务到浏览器扩展。
///
/// 对应 Go `browser_dialer` 包的核心逻辑：
/// - 内嵌 HTML/JS 页面供浏览器加载
/// - WS 连接池（浏览器扩展主动连接）
/// - 任务派发（WS/GET/POST）
pub struct BrowserDialer {
    config: BrowserDialerConfig,
    /// CSRF token，用于验证 WS 连接来源。
    csrf_token: String,
    /// WS 连接池。浏览器扩展连接后放入此队列。
    conns: Arc<Mutex<Vec<WebSocketStream<tokio::net::TcpStream>>>>,
    /// 替换 CSRF token 后的 HTML 页面。
    html_page: String,
}

impl BrowserDialer {
    #[must_use]
    pub fn new(config: BrowserDialerConfig) -> Self {
        let csrf_token = uuid::Uuid::new_v4().to_string();
        let html_page = DIALER_HTML_TEMPLATE.replace("csrfToken", &csrf_token);
        Self {
            config,
            csrf_token,
            conns: Arc::new(Mutex::new(Vec::new())),
            html_page,
        }
    }

    #[must_use]
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.config.listen
    }

    /// 返回替换 CSRF token 后的 HTML 页面内容。
    #[must_use]
    pub fn html_page(&self) -> &str {
        &self.html_page
    }

    /// 返回 CSRF token（用于 WS 升级时验证 query 参数）。
    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// 浏览器拨号器是否活跃（有可用连接）。
    pub async fn is_active(&self) -> bool {
        !self.conns.lock().await.is_empty()
    }

    /// 将新的 WS 连接加入连接池。
    pub async fn add_connection(&self, ws: WebSocketStream<tokio::net::TcpStream>) {
        self.conns.lock().await.push(ws);
    }

    /// 从连接池取出一个可用连接。
    async fn take_connection(&self) -> Option<WebSocketStream<tokio::net::TcpStream>> {
        self.conns.lock().await.pop()
    }

    /// 派发 WS 拨号任务。对应 Go `DialWS`。
    ///
    /// 通过浏览器扩展建立到目标 URI 的 WebSocket 连接。
    /// `ed` 为 early data（base64 编码后作为 WS 子协议传递）。
    pub async fn dial_ws(
        &self,
        uri: &str,
        ed: &[u8],
    ) -> Result<WebSocketStream<tokio::net::TcpStream>, BrowserDialerError> {
        let protocol = if ed.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ed))
        };

        let task = BrowserTask {
            method: "WS".to_string(),
            url: uri.to_string(),
            extra: Some(serde_json::to_value(WsExtra { protocol })?),
            stream_response: true,
        };

        self.dial_task(task).await
    }

    /// 派发 HTTP GET 流式任务。对应 Go `DialGet`。
    pub async fn dial_get(
        &self,
        uri: &str,
        headers: std::collections::HashMap<String, String>,
        cookies: std::collections::HashMap<String, String>,
    ) -> Result<WebSocketStream<tokio::net::TcpStream>, BrowserDialerError> {
        let extra = HttpExtra {
            referrer: headers.get("Referer").cloned(),
            headers: if headers.is_empty() {
                None
            } else {
                let mut h = headers;
                h.remove("Referer");
                Some(h)
            },
            cookies: if cookies.is_empty() {
                None
            } else {
                Some(cookies)
            },
        };

        let task = BrowserTask {
            method: "GET".to_string(),
            url: uri.to_string(),
            extra: Some(serde_json::to_value(extra)?),
            stream_response: true,
        };

        self.dial_task(task).await
    }

    /// 派发 HTTP 数据包任务（POST/PUT 等）。对应 Go `DialPacket` / `dialWithBody`。
    pub async fn dial_packet(
        &self,
        method: &str,
        uri: &str,
        headers: std::collections::HashMap<String, String>,
        cookies: std::collections::HashMap<String, String>,
        payload: &[u8],
    ) -> Result<(), BrowserDialerError> {
        let extra = HttpExtra {
            referrer: headers.get("Referer").cloned(),
            headers: if headers.is_empty() {
                None
            } else {
                let mut h = headers;
                h.remove("Referer");
                Some(h)
            },
            cookies: if cookies.is_empty() {
                None
            } else {
                Some(cookies)
            },
        };

        let task = BrowserTask {
            method: method.to_string(),
            url: uri.to_string(),
            extra: Some(serde_json::to_value(extra)?),
            stream_response: false,
        };

        let mut conn = self.dial_task(task).await?;
        // 发送 payload 到浏览器扩展
        conn.send(Message::Binary(payload.to_vec().into())).await?;
        // 等待浏览器确认
        check_ok(&mut conn).await?;
        Ok(())
    }

    /// 核心任务派发。从连接池取连接，发送任务 JSON，等待 "ok" 确认。
    /// 对应 Go `dialTask`。
    async fn dial_task(
        &self,
        task: BrowserTask,
    ) -> Result<WebSocketStream<tokio::net::TcpStream>, BrowserDialerError> {
        let data = serde_json::to_string(&task)?;

        // 从连接池取连接，失败则重试（对应 Go 的 for 循环从 conns channel 取）
        let mut conn = loop {
            match self.take_connection().await {
                Some(c) => break c,
                None => {
                    return Err(BrowserDialerError::NoConnection);
                }
            }
        };

        // 发送任务 JSON
        if conn.send(Message::Text(data.into())).await.is_err() {
            // 连接已断开，丢弃并报错
            return Err(BrowserDialerError::ConnectionFailed(
                "failed to send task to browser".to_string(),
            ));
        }

        // 等待浏览器确认 "ok"
        check_ok(&mut conn).await?;

        Ok(conn)
    }
}

/// 检查浏览器返回的确认消息。对应 Go `CheckOK`。
async fn check_ok<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut WebSocketStream<S>,
) -> Result<(), BrowserDialerError> {
    match conn.next().await {
        Some(Ok(Message::Text(msg))) if msg.as_str() == "ok" => Ok(()),
        Some(Ok(Message::Text(msg))) => {
            Err(BrowserDialerError::TaskRejected(msg.to_string()))
        }
        Some(Ok(Message::Close(_))) => {
            Err(BrowserDialerError::ConnectionFailed("connection closed".to_string()))
        }
        Some(Ok(_)) => {
            // 非 text 消息视为异常
            Err(BrowserDialerError::TaskRejected("unexpected message type".to_string()))
        }
        Some(Err(e)) => Err(BrowserDialerError::from(e)),
        None => Err(BrowserDialerError::ConnectionFailed(
            "stream ended unexpectedly".to_string(),
        )),
    }
}

/// 将已建立的 TCP 流升级为 WS 服务端连接（带 CSRF token 验证）。
/// 对应 Go 的 `upgrader.Upgrade` + token 检查。
pub async fn upgrade_tcp_to_ws(
    stream: tokio::net::TcpStream,
    expected_token: &str,
) -> Result<WebSocketStream<tokio::net::TcpStream>, BrowserDialerError> {
    // tokio-tungstenite 的 accept_hdr_async 支持在握手时检查请求
    let callback = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                    resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
        // 验证 CSRF token
        let token_ok = req
            .uri()
            .query()
            .map(|q| q.contains(&format!("token={expected_token}")))
            .unwrap_or(false);

        if token_ok {
            Ok(resp)
        } else {
            let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                .status(403)
                .body(Some("invalid token".into()))
                .map_err(|e| {
                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(
                        Some(e.to_string().into()),
                    )
                })?;
            Err(denied)
        }
    };

    let ws = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
    Ok(ws)
}
