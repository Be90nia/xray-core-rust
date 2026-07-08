//! WebSocket 服务端：TCP/TLS 监听 + Upgrade + early data 提取。
//!
//! 对应 Go `transport/internet/websocket/hub.go` 的 `ListenWS` +
//! `requestHandler.ServeHTTP`。Rust 端用 `tokio-tungstenite::accept_hdr_async`
//! 拦截 HTTP Upgrade 请求，校验 Host / Path，提取 `Sec-WebSocket-Protocol`
//! header 中的 early data（base64 RawURL 编码）。
//!
//! # 流程
//!
//! 1. `WsListener::bind` 绑 TcpListener
//! 2. `accept()` 收一条 TCP 连接（+ 可选 TLS 包装）
//! 3. `accept_hdr_async` 触发握手，callback 内：
//!    - 校验 `Sec-WebSocket-Key` → 自动由 tungstenite 处理
//!    - 校验 Host / Path → 不匹配返回 `404` 拒绝
//!    - 提取 `Sec-WebSocket-Protocol` base64 → early data
//!    - 回写 `Sec-WebSocket-Protocol` 响应头（必须回写客户端才认）
//! 4. 把握手完成的 `WebSocketStream` + early data 包装为 `WsConnWithEarlyData`

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use tokio::net::TcpListener as TokioTcpListener;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, StatusCode};

use xray_transport::connection::Connection;

use crate::config::Config;
use crate::error::{Result, WsError};
use crate::ws_bridge::WsConnection;

/// 服务端 accept 出的连接 + 服务端从 `Sec-WebSocket-Protocol` 解出的 early data。
///
/// early data 对应 Go `extraReader`（连接首批字节，调用方需先消费再进入帧循环）。
pub struct AcceptedConn {
    /// 字节流包装的 WS 连接。
    pub conn: Box<dyn Connection>,
    /// 解码后的 early data（可能为空）。
    pub early_data: Vec<u8>,
    /// TCP peer 地址。
    pub remote: SocketAddr,
}

/// WebSocket 服务端监听器。
///
/// 对应 Go `Listener`（`hub.go`）。本结构持有 TcpListener + WS 配置；
/// TLS 包装由调用方在 `accept` 后注入（ponytail：避免 listener 持 TLS acceptor
/// 让数据流走 trait object）。
pub struct WsListener {
    listener: TokioTcpListener,
    config: Arc<Config>,
}

impl WsListener {
    /// 绑定到 `addr`，使用给定 WS 配置（host/path/heartbeat）。
    pub async fn bind(addr: SocketAddr, config: Arc<Config>) -> Result<Self> {
        let listener = TokioTcpListener::bind(addr)
            .await
            .map_err(|e| WsError::Io(e))?;
        Ok(Self { listener, config })
    }

    /// 本地地址。
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(WsError::Io)
    }

    /// 接受一条新连接，完成 WS 握手 + 校验 host/path + 提取 early data。
    ///
    /// **不支持 TLS**：明文 ws:// only。TLS 包装应由调用方在传入 `TcpStream`
    /// 之前先 accept TLS（典型场景：外层 nginx/Caddy 终止 TLS，内部明文 WS）。
    /// 切片2 follow-up 可加 `accept_tls(Arc<ServerConfig>)` 变体。
    pub async fn accept(&self) -> Result<AcceptedConn> {
        let (tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp
            .local_addr()
            .ok();

        // 用 callback 在握手过程中拿 Request 头，做 host/path 校验 + early data 提取。
        // ponytail: callback 通过 Mutex<Vec<u8>> 收集 early data（多线程 callback 不会并发，
        // 但 Mutex 满足 callback FnMut 的 Send + Sync 要求）。
        let expected_host = self.config.host.clone();
        let expected_path = self.config.normalized_path();
        let early_data_slot: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let slot_clone = Arc::clone(&early_data_slot);

        let callback = move |req: &Request, resp: Response| {
            let headers = req.headers();
            // 1. Host 校验：空配置放行；非空严格匹配（对齐 Go IsValidHTTPHost）。
            if !expected_host.is_empty() {
                let req_host = headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if req_host != expected_host {
                    let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Some("host mismatch".into()))
                        .unwrap();
                    return Err(denied);
                }
            }
            // 2. Path 校验。
            let req_path = req.uri().path();
            if req_path != expected_path {
                let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Some("path mismatch".into()))
                    .unwrap();
                return Err(denied);
            }
            // 3. Early data 提取：Sec-WebSocket-Protocol (base64 RawURL no pad)。
            let mut response = resp;
            if let Some(ed_header) = extract_early_data(headers) {
                // 必须把原 header 回写响应（对齐 Go responseHeader.Set）。
                if let Ok(val) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&ed_header.raw) {
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", val);
                }
                // 把解码后的字节塞进 slot，握手后由调用方消费。
                if let Ok(mut guard) = slot_clone.lock() {
                    *guard = ed_header.bytes;
                }
            }
            Ok(response)
        };

        let ws_stream = accept_hdr_async(tcp, callback)
            .await
            .map_err(|e| WsError::HandshakeFailed(format!("accept_hdr_async: {e}")))?;

        let early_data = early_data_slot
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        let mut conn = WsConnection::from_stream(ws_stream, Some(remote), local);
        // 若有 early data：让 conn 的 read_buf 先吐这些字节，调用方先读到。
        // ponytail: 直接塞 read_buf，poll_read 优先消费。
        if !early_data.is_empty() {
            conn.read_buf.extend(&early_data);
        }
        Ok(AcceptedConn {
            conn: Box::new(conn) as Box<dyn Connection>,
            early_data,
            remote,
        })
    }
}

/// 解析出的 early data（原始 header 字符串 + 解码后字节）。
struct EarlyDataHeader {
    raw: String,
    bytes: Vec<u8>,
}

/// 从 `Sec-WebSocket-Protocol` header 解出 early data。
///
/// 对齐 Go `replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")` +
/// `base64.RawURLEncoding.DecodeString`。Go 用 RawURLEncoding 但 replacer
/// 兼容标准 base64 客户端（把 +/= 替换为 -_ 空）。Rust 端用 URL_SAFE_NO_PAD
/// 直接解码（与 client.rs 编码端对称），不匹配返回 None。
fn extract_early_data(headers: &HeaderMap) -> Option<EarlyDataHeader> {
    let raw = headers.get("Sec-WebSocket-Protocol")?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    // 兼容 Go replacer：标准 base64 → RawURL。
    let normalized: String = raw.chars().map(|c| match c {
        '+' => '-',
        '/' => '_',
        '=' => '\0', // 移除 padding
        _ => c,
    }).filter(|c| *c != '\0').collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&normalized)
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(EarlyDataHeader {
        raw: raw.to_string(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_early_data_decodes_url_safe_no_pad() {
        // 客户端编码：URL_SAFE_NO_PAD("hello") = "aGVsbG8"
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "aGVsbG8".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded");
        assert_eq!(ed.bytes, b"hello");
        assert_eq!(ed.raw, "aGVsbG8");
    }

    #[test]
    fn extract_early_data_accepts_standard_base64_with_replacer() {
        // 标准 base64("hi!") = "aGkh"（no pad），含 +/= 时：("??") = "Pz8="
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "Pz8=".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded via replacer");
        assert_eq!(ed.bytes, b"??");
    }

    #[test]
    fn extract_early_data_empty_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_missing_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_invalid_base64_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "@@@invalid".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }
}
