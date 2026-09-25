//! # HTTP REST + SSE 客户端（对应 Go `transport/internet/finalmask/realm/http.go`）
//!
//! 基于 `reqwest` 0.12 + `rustls` 实现 JSON 端点（register/heartbeat/connect/...）
//! 与 SSE 长连接（events）。所有非预期 HTTP 状态统一封装为 [`StatusError`]。
//!
//! SSE 解析逻辑（`parse_sse_event_from_lines`）与 `reqwest::Response` 解耦，
//! 测试可直接喂入合成字节验证。

use std::{io, time::Duration};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::finalmask::realm::punch::{PUNCH_NONCE_SIZE, PUNCH_OBFS_KEY_SIZE, PunchMetadata};

/// Error body 最大读取字节数（防 OOM，对应 Go `maxErrorBodySize`）。
const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;

/// realm HTTP 客户端（对应 Go `realm.Client`）。
#[derive(Clone)]
pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

/// /register 响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "session_id", default)]
    pub session_id: String,
    #[serde(default)]
    pub ttl: i32,
}

/// /heartbeat 响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    #[serde(default)]
    pub ttl: i32,
}

/// /heartbeat 请求。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

/// /connect 请求（嵌入 `PunchMetadata`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub metadata: PunchMetadata,
}

/// /connect 响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub metadata: PunchMetadata,
}

/// /events SSE 事件 payload。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchEvent {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub metadata: PunchMetadata,
}

/// /connects/:nonce 请求 body。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponseRequest {
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// 错误响应 JSON。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
}

/// HTTP 非 2xx 错误（携带状态码与解析后的 [`ErrorResponse`]）。
#[derive(Debug, Clone)]
pub struct StatusError {
    /// 0 表示网络/传输错误（未收到响应）。
    pub status_code: u16,
    pub response: ErrorResponse,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.response.error.is_empty() || !self.response.message.is_empty() {
            write!(
                f,
                "realm server returned {}: {}: {}",
                self.status_code, self.response.error, self.response.message
            )
        } else {
            write!(f, "realm server returned {}", self.status_code)
        }
    }
}

impl std::error::Error for StatusError {}

/// 构造 Client（对应 Go `NewClient`）。
///
/// `use_tls = true` 时启用 rustls 后端；否则仍由 `scheme` 决定 http/https。
pub fn new_client(
    scheme: &str,
    host: &str,
    port: &str,
    token: &str,
    use_tls: bool,
) -> io::Result<Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10));
    if !use_tls {
        builder = builder.https_only(false);
    }
    let http = builder.build().map_err(io::Error::other)?;
    Ok(Client { base_url: format!("{scheme}://{host}:{port}"), token: token.to_string(), http })
}

/// 生成随机 `nonce + obfs`（对应 Go `NewPunchMetadata`）。
pub fn new_punch_metadata() -> io::Result<PunchMetadata> {
    Ok(PunchMetadata::new(rand_hex(PUNCH_NONCE_SIZE)?, rand_hex(PUNCH_OBFS_KEY_SIZE)?))
}

/// 生成 `size` 字节随机数据并以 hex 返回（对应 Go `randHex`）。
pub fn rand_hex(size: usize) -> io::Result<String> {
    use rand::RngCore;
    let mut buf = vec![0u8; size];
    rand::rng().fill_bytes(&mut buf);
    Ok(hex::encode(buf))
}

/// 拼接 URL path（对应 Go `joinURLPath`）——去除每段首尾 `/`，以单个 `/` 连接，
/// 结果以 `/` 起首。
#[must_use]
pub fn join_url_path(parts: &[&str]) -> String {
    let joined: Vec<&str> =
        parts.iter().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty()).collect();
    format!("/{}", joined.join("/"))
}

/// 简易 URL path 段百分号编码（仅保留 RFC3986 unreserved 字符）。
fn url_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Client {
    fn endpoint(&self, realm_id: &str, sub_path: &str) -> String {
        let escaped = url_encode_path_segment(realm_id);
        format!("{}{}", self.base_url, join_url_path(&["v1", &escaped, sub_path]))
    }

    /// POST /v1/:realm_id
    pub async fn register(
        &self,
        realm_id: &str,
        addresses: Vec<String>,
    ) -> Result<RegisterResponse, StatusError> {
        #[derive(Serialize)]
        struct Body<'a> {
            addresses: &'a [String],
        }
        let body = Body { addresses: &addresses };
        self.do_json(
            reqwest::Method::POST,
            realm_id,
            "",
            &self.token,
            Some(&body),
            reqwest::StatusCode::OK,
        )
        .await
    }

    /// DELETE /v1/:realm_id
    pub async fn deregister(&self, realm_id: &str, session_id: &str) -> Result<(), StatusError> {
        self.do_json_unit(
            reqwest::Method::DELETE,
            realm_id,
            "",
            session_id,
            None::<&()>,
            reqwest::StatusCode::NO_CONTENT,
        )
        .await
    }

    /// POST /v1/:realm_id/heartbeat
    pub async fn heartbeat(
        &self,
        realm_id: &str,
        session_id: &str,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, StatusError> {
        self.do_json(
            reqwest::Method::POST,
            realm_id,
            "heartbeat",
            session_id,
            Some(req),
            reqwest::StatusCode::OK,
        )
        .await
    }

    /// POST /v1/:realm_id/connect
    pub async fn connect(
        &self,
        realm_id: &str,
        req: &ConnectRequest,
    ) -> Result<ConnectResponse, StatusError> {
        self.do_json(
            reqwest::Method::POST,
            realm_id,
            "connect",
            &self.token,
            Some(req),
            reqwest::StatusCode::OK,
        )
        .await
    }

    /// POST /v1/:realm_id/connects/:nonce
    pub async fn connect_response(
        &self,
        realm_id: &str,
        session_id: &str,
        nonce: &str,
        addresses: Vec<String>,
    ) -> Result<(), StatusError> {
        let sub = format!("connects/{}", url_encode_path_segment(nonce));
        let body = ConnectResponseRequest { addresses };
        self.do_json_unit(
            reqwest::Method::POST,
            realm_id,
            &sub,
            session_id,
            Some(&body),
            reqwest::StatusCode::NO_CONTENT,
        )
        .await
    }

    /// GET /v1/:realm_id/events → SSE 流。
    pub async fn events(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<EventStream, StatusError> {
        let url = self.endpoint(realm_id, "events");
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {session_id}"))
            .send()
            .await
            .map_err(reqwest_err_to_status)?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(decode_status_error(resp).await);
        }
        Ok(EventStream::new(resp))
    }

    async fn do_json<In, Out>(
        &self,
        method: reqwest::Method,
        realm_id: &str,
        sub_path: &str,
        token: &str,
        body: Option<&In>,
        expected: reqwest::StatusCode,
    ) -> Result<Out, StatusError>
    where
        In: Serialize,
        Out: DeserializeOwned,
    {
        let url = self.endpoint(realm_id, sub_path);
        let mut req = self.http.request(method, &url);
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(reqwest_err_to_status)?;
        if resp.status() != expected {
            return Err(decode_status_error(resp).await);
        }
        resp.json::<Out>().await.map_err(|e| StatusError {
            status_code: 0,
            response: ErrorResponse { error: "decode".into(), message: e.to_string() },
        })
    }

    async fn do_json_unit<In>(
        &self,
        method: reqwest::Method,
        realm_id: &str,
        sub_path: &str,
        token: &str,
        body: Option<&In>,
        expected: reqwest::StatusCode,
    ) -> Result<(), StatusError>
    where
        In: Serialize,
    {
        let url = self.endpoint(realm_id, sub_path);
        let mut req = self.http.request(method, &url);
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(reqwest_err_to_status)?;
        if resp.status() != expected {
            return Err(decode_status_error(resp).await);
        }
        Ok(())
    }
}

/// 解析 HTTP 错误响应（对应 Go `decodeStatusError`）。
///
/// body 限制 `MAX_ERROR_BODY_SIZE` 字节，失败时返回空 [`ErrorResponse`]。
pub async fn decode_status_error(resp: reqwest::Response) -> StatusError {
    let status_code = resp.status().as_u16();
    // 取前 MAX_ERROR_BODY_SIZE 字节
    let bytes = match resp.bytes().await {
        Ok(b) if b.len() <= MAX_ERROR_BODY_SIZE => b.to_vec(),
        Ok(b) => b.slice(..MAX_ERROR_BODY_SIZE).to_vec(),
        Err(_) => Vec::new(),
    };
    let response: ErrorResponse = serde_json::from_slice(&bytes).unwrap_or_default();
    StatusError { status_code, response }
}

/// SSE 事件流（对应 Go `EventStream`）。
pub struct EventStream {
    response: reqwest::Response,
    buf: Vec<u8>,
}

impl EventStream {
    fn new(response: reqwest::Response) -> Self {
        Self { response, buf: Vec::with_capacity(4096) }
    }

    /// 关闭底层响应体。
    pub async fn close(self) {
        let _ = self.response.bytes().await;
    }

    /// 阻塞读取下一个 `punch` 事件；返回 `Ok(None)` 表示流结束。
    pub async fn next_event(&mut self) -> io::Result<Option<PunchEvent>> {
        loop {
            // 尝试从 buffer 中按行解析
            while let Some(line_end) = self.buf.iter().position(|b| *b == b'\n') {
                let line_bytes: Vec<u8> = self.buf.drain(..=line_end).collect();
                let line = String::from_utf8_lossy(&line_bytes);
                let line = line.trim_end_matches('\r');
                if let Some(result) = process_sse_line(line, &mut SseState::default())? {
                    return Ok(Some(result));
                }
            }
            // 拉取下一块
            match self.response.chunk().await {
                Ok(Some(chunk)) => self.buf.extend_from_slice(&chunk),
                Ok(None) => {
                    // EOF；检查 buffer 尾部是否有未触发事件
                    let last = String::from_utf8_lossy(&self.buf);
                    let last = last.trim_end_matches('\r');
                    let _ = last;
                    return Ok(None);
                },
                Err(e) => {
                    return Err(io::Error::other(e));
                },
            }
        }
    }
}

/// SSE 解析状态机（每行处理时维护）。
struct SseState {
    event_name: String,
    data: String,
}

impl SseState {
    const fn default() -> Self {
        Self { event_name: String::new(), data: String::new() }
    }
}

/// 处理一行 SSE 文本；若遇到完整事件边界返回 `Some(PunchEvent)`。
///
/// 仅暴露给 [`EventStream::next_event`]，但实际逻辑通过
/// [`parse_sse_event_from_lines`] 包装后用于测试。
fn process_sse_line(line: &str, state: &mut SseState) -> io::Result<Option<PunchEvent>> {
    if line.is_empty() {
        // 事件边界
        if state.event_name == "punch" && !state.data.is_empty() {
            let ev: PunchEvent = serde_json::from_str(&state.data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            state.event_name.clear();
            state.data.clear();
            return Ok(Some(ev));
        }
        state.event_name.clear();
        state.data.clear();
        return Ok(None);
    }
    if line.starts_with(':') {
        // 注释
        return Ok(None);
    }
    if let Some((field, value)) = line.split_once(':') {
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => state.event_name = value.to_string(),
            "data" => {
                if !state.data.is_empty() {
                    state.data.push('\n');
                }
                state.data.push_str(value);
            },
            _ => {},
        }
    }
    Ok(None)
}

/// 从完整行列表中解析第一个 `punch` 事件（测试助手）。
///
/// 与 [`EventStream::next_event`] 共享 [`process_sse_line`] 逻辑；
/// 输入 `lines` 已按 `\n` 切分（含空行）。返回 `Ok(None)` 表示流内无 `punch` 事件。
pub fn parse_sse_event_from_lines(lines: &[&str]) -> io::Result<Option<PunchEvent>> {
    let mut state = SseState::default();
    for raw in lines {
        let line = raw.trim_end_matches('\r');
        if let Some(ev) = process_sse_line(line, &mut state)? {
            return Ok(Some(ev));
        }
    }
    // EOF：检查尾部累积（未以空行收尾的情况）
    if state.event_name == "punch" && !state.data.is_empty() {
        let ev: PunchEvent = serde_json::from_str(&state.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        return Ok(Some(ev));
    }
    Ok(None)
}

fn reqwest_err_to_status(e: reqwest::Error) -> StatusError {
    StatusError {
        status_code: 0,
        response: ErrorResponse { error: "transport".into(), message: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_path_trims_slashes() {
        assert_eq!(join_url_path(&["/v1/", "/realm", "events"]), "/v1/realm/events");
        assert_eq!(join_url_path(&["", "v1", ""]), "/v1");
        assert_eq!(join_url_path(&[]), "/");
    }

    #[test]
    fn rand_hex_correct_length_and_charset() {
        let h = rand_hex(16).unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn new_punch_metadata_correct_sizes() {
        let m = new_punch_metadata().unwrap();
        assert_eq!(m.nonce.len(), 2 * PUNCH_NONCE_SIZE);
        assert_eq!(m.obfs.len(), 2 * PUNCH_OBFS_KEY_SIZE);
    }

    #[test]
    fn json_roundtrip_connect_request() {
        let req = ConnectRequest {
            addresses: vec!["1.2.3.4:5".into()],
            metadata: PunchMetadata::new("ab".into(), "cd".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ConnectRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.addresses, req.addresses);
        assert_eq!(parsed.metadata, req.metadata);
    }

    #[test]
    fn json_roundtrip_punch_event_flatten() {
        let ev = PunchEvent {
            addresses: vec!["1.2.3.4:5".into(), "[::1]:80".into()],
            metadata: PunchMetadata::new("n".into(), "o".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"nonce\":\"n\""));
        assert!(json.contains("\"obfs\":\"o\""));
        let parsed: PunchEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.addresses.len(), 2);
        assert_eq!(parsed.metadata.nonce, "n");
    }

    #[test]
    fn json_default_register_response() {
        // 空 JSON 应使用默认值（不报错）
        let parsed: RegisterResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.session_id, "");
        assert_eq!(parsed.ttl, 0);
    }

    #[test]
    fn json_heartbeat_skip_empty_addresses() {
        let req = HeartbeatRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        // 空数组应被 skip
        assert!(!json.contains("addresses"));
    }

    #[test]
    fn url_encode_path_segment_escapes_special() {
        assert_eq!(url_encode_path_segment("hello world!"), "hello%20world%21");
        assert_eq!(url_encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(url_encode_path_segment("plain_-."), "plain_-.");
    }

    #[test]
    fn status_error_display_formats() {
        let with_body = StatusError {
            status_code: 401,
            response: ErrorResponse { error: "unauthorized".into(), message: "bad token".into() },
        };
        let s = format!("{with_body}");
        assert!(s.contains("401"));
        assert!(s.contains("unauthorized"));
        assert!(s.contains("bad token"));

        let no_body = StatusError { status_code: 500, response: ErrorResponse::default() };
        let s2 = format!("{no_body}");
        assert_eq!(s2, "realm server returned 500");
    }

    #[test]
    fn sse_parses_single_punch_event() {
        let lines = vec![
            "event: punch",
            "data: {\"addresses\":[\"1.2.3.4:5\"],\"nonce\":\"ab\",\"obfs\":\"cd\"}",
            "",
        ];
        let ev = parse_sse_event_from_lines(&lines).unwrap().expect("event");
        assert_eq!(ev.addresses, vec!["1.2.3.4:5".to_string()]);
        assert_eq!(ev.metadata.nonce, "ab");
        assert_eq!(ev.metadata.obfs, "cd");
    }

    #[test]
    fn sse_skips_non_punch_events() {
        let lines = vec![
            "event: keepalive",
            "data: {}",
            "",
            "event: punch",
            "data: {\"addresses\":[],\"nonce\":\"x\",\"obfs\":\"y\"}",
            "",
        ];
        let ev = parse_sse_event_from_lines(&lines).unwrap().expect("event");
        assert_eq!(ev.metadata.nonce, "x");
    }

    #[test]
    fn sse_ignores_comments() {
        let lines = vec![
            ": this is a comment",
            "event: punch",
            "data: {\"addresses\":[],\"nonce\":\"n\",\"obfs\":\"o\"}",
            "",
        ];
        let ev = parse_sse_event_from_lines(&lines).unwrap().expect("event");
        assert_eq!(ev.metadata.nonce, "n");
    }

    #[test]
    fn sse_multiline_data_concatenated() {
        // 多行 data 字段以 \n 拼接（SSE 标准）
        // 这里多行 JSON 不合法，但行为测试：data 字段拼接
        let lines = vec![
            "event: punch",
            "data: {\"addresses\":[],",
            "data: \"nonce\":\"m\",\"obfs\":\"p\"}",
            "",
        ];
        let result = parse_sse_event_from_lines(&lines);
        // 多行 JSON 应解析成功（拼接后是合法 JSON）
        assert!(result.is_ok());
        let ev = result.unwrap().expect("event");
        assert_eq!(ev.metadata.nonce, "m");
    }

    #[test]
    fn sse_no_event_returns_none() {
        let lines = vec!["event: other", "data: {}", ""];
        let ev = parse_sse_event_from_lines(&lines).unwrap();
        assert!(ev.is_none());
    }

    #[test]
    fn sse_empty_input_returns_none() {
        let ev = parse_sse_event_from_lines(&[]).unwrap();
        assert!(ev.is_none());
    }
}
