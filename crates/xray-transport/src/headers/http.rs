//! # HTTP header authenticator
//!
//! 对应 Go `transport/internet/headers/http/`。
//!
//! 三个核心：
//! - [`HeaderReader`]：从字节流读出 HTTP header 边界（按 `\r\n\r\n` 切分）， 可选校验首行 URI
//!   是否在期待列表中。
//! - [`HeaderWriter`]：把预构造的 header 字节一次性写出。
//! - [`HttpAuthenticator`]：`HeaderAuthenticator` 的 HTTP 实现，持有 `HeaderConfig`，按 default
//!   fallback（Chrome UA）或用户自定义生成字节。
//!
//! ## 与 4t8 边界
//!
//! 本模块是 **trait + 字节工厂**，不直接拿 conn 包装。
// 4t8 的 `Client(conn)/Server(conn) net.Conn` 包装层（Go http.go:284-308）
// 把 reader/writer 串成异步包装。Rust 端异步包装是单独任务。

use super::authenticator::{
    HeaderAuthenticator, HeaderConfig, HeaderError, HeaderNameValues, MAX_HEADER_LENGTH,
    RequestConfig, ResponseConfig, pick_string,
};

/// HTTP header 终结符。
pub const CRLF: &str = "\r\n";
pub const ENDING: &str = "\r\n\r\n";

/// 读 HTTP header 边界并校验路径。
///
/// 对应 Go `http.HeaderReader`（http.go:55-137）的语义，简化版：
/// - 提供 `feed(&[u8])`：喂一坨字节，多次直到 `ENDING` 出现或 `MAX_HEADER_LENGTH` 触发 `TooLong`。
/// - 状态机：`buffered` 累积未消费的字节；`done` 终止。
///
/// Rust 端与 Go 不同之处：Go 的 `Read(io.Reader)` 直接阻塞读 async reader，
//  Rust 的对应物交由调用方在 `AsyncRead` 之上做 `read().await` + `feed(buf)`。
#[derive(Debug, Default)]
pub struct HeaderReader {
    buffered: Vec<u8>,
    done: bool,
}

impl HeaderReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入字节。
    ///
    /// 返回：
    /// - `Ok(Some(_))`：检测到完整 header + body 起始字节（body 已剥离）。
    /// - `Ok(None)`：还需更多字节。
    /// - `Err(TooLong)`：超出 [`MAX_HEADER_LENGTH`] 上限。
    /// - `Err(PathMismatch)`：URI 不在期待列表（当 `expected_uris` 非空时）。
    pub fn feed(
        &mut self,
        chunk: &[u8],
        expected_uris: &[String],
    ) -> Result<Option<Vec<u8>>, HeaderError> {
        if self.done {
            return Ok(None);
        }
        self.buffered.extend_from_slice(chunk);
        if self.buffered.len() > MAX_HEADER_LENGTH {
            self.done = true;
            return Err(HeaderError::TooLong);
        }
        match find_ending(&self.buffered) {
            Some(end_idx) => {
                // header 在 end_idx 处结束；body 紧随（从 end_idx+ENDING.len 开始）。
                // 先拷贝 header 切片并校验（不持 borrow 跨 swap），再剥离 body。
                let header_bytes = self.buffered[..end_idx].to_vec();
                let expected_uris_owned = expected_uris.to_vec();
                let body_bytes = self.buffered[end_idx + ENDING.len()..].to_vec();
                if !expected_uris_owned.is_empty() {
                    let path = parse_request_line_path(&header_bytes)
                        .ok_or_else(|| HeaderError::Io("malformed request line".into()))?;
                    if !expected_uris_owned.iter().any(|u| u == &path) {
                        self.done = true;
                        return Err(HeaderError::PathMismatch);
                    }
                }
                self.buffered.clear();
                self.done = true;
                Ok(Some(body_bytes))
            },
            None => Ok(None),
        }
    }
}
/// 在 `buf` 中查找 `ENDING` 第一次出现的位置（bytes，不是字符索引）。
///
/// 返回结束位置（包含 `ENDING` 起始处）。
fn find_ending(buf: &[u8]) -> Option<usize> {
    if buf.len() < ENDING.len() {
        return None;
    }
    for i in 0..=buf.len() - ENDING.len() {
        if &buf[i..i + ENDING.len()] == ENDING.as_bytes() {
            return Some(i);
        }
    }
    None
}

/// 从 HTTP request 行中解析 URI：`METHOD SP URI SP HTTP/x.y`。
///
/// 接受 `GET /foo HTTP/1.1` 格式。
fn parse_request_line_path(header: &[u8]) -> Option<String> {
    let line_end = header.iter().position(|&b| b == b'\r').unwrap_or(header.len());
    let line = &header[..line_end];
    // split by SP，期望 3 个字段
    let mut parts = line.split(|&b| b == b' ');
    let _method = parts.next()?;
    let path = parts.next()?;
    let _version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(String::from_utf8_lossy(path).into_owned())
}

/// 预构造的 header 字节工厂。
///
/// 对应 Go `http.HeaderWriter`（http.go:139-157）：持有一个构造好的 header，
//  第一次 `write()` 后清空（one-shot），与 Go `w.header = nil` 等价。
#[derive(Debug)]
pub struct HeaderWriter {
    header: Option<Vec<u8>>,
}

impl HeaderWriter {
    pub fn new(header: Vec<u8>) -> Self {
        Self { header: Some(header) }
    }

    /// 把 header 字节一次性写入 `buf`，清空自身。
    pub fn write_to(&mut self, buf: &mut Vec<u8>) -> Result<(), HeaderError> {
        if let Some(h) = self.header.take() {
            buf.extend_from_slice(&h);
        }
        Ok(())
    }

    /// 是否还有未写出的 header（对应 Go `if w.header == nil` 跳过）。
    pub fn is_empty(&self) -> bool {
        self.header.is_none()
    }
}

/// HTTP authenticator 实现。
///
/// 对应 Go `http.Authenticator`（http.go:259-314）：持有 `Config`，
// `client_header()` 拼出 "METHOD URI HTTP/x.y\r\nheader\r\n...\r\n\r\n"，
// `server_header()` 拼出 "HTTP/x.y STATUS REASON\r\nheader\r\n...\r\n\r\n"，
// `expected_request_uris()` 返回 `config.request.uri`（用于服务端校验）。
/// 注意：本类型 **不** 走 `Conn` 包装层（那是 4t8 范围）；trait 输出的是字节，
// 由 4t8 的连接层装配进 tokio `AsyncRead+AsyncWrite`。
#[derive(Debug, Clone)]
pub struct HttpAuthenticator {
    config: HeaderConfig,
}

impl HttpAuthenticator {
    pub fn new(config: HeaderConfig) -> Self {
        Self { config }
    }

    /// 取 request 部分；若为空（None）→ 不发 request header（服务端走默认透传）。
    pub fn request(&self) -> Option<&RequestConfig> {
        self.config.request.as_ref()
    }

    /// 取 response 部分。
    pub fn response(&self) -> Option<&ResponseConfig> {
        self.config.response.as_ref()
    }
}

impl HeaderAuthenticator for HttpAuthenticator {
    fn client_header(&self) -> Vec<u8> {
        let Some(req) = self.config.request.as_ref() else {
            return Vec::new();
        };
        render_request(req)
    }

    fn server_header(&self) -> Vec<u8> {
        let Some(resp) = self.config.response.as_ref() else {
            return Vec::new();
        };
        render_response(resp)
    }

    fn expected_request_uris(&self) -> Vec<String> {
        self.config.request.as_ref().map(|r| r.uri.clone()).unwrap_or_default()
    }
}

/// 渲染 `METHOD URI HTTP/x.y\r\nh1: v1\r\nh2: v2\r\n...\r\n\r\n`。
///
/// 对应 Go `Authenticator.GetClientWriter`（http.go:263-278）。
pub fn render_request(req: &RequestConfig) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    let uri = pick_string(&req.uri);
    out.push_str(req.get_method());
    out.push(' ');
    if uri.is_empty() {
        out.push('/');
    } else {
        out.push_str(uri);
    }
    out.push(' ');
    out.push_str(&req.get_full_version());
    out.push_str(CRLF);
    for h in &req.header {
        out.push_str(&h.name);
        out.push_str(": ");
        let v = pick_string(&h.value);
        if !v.is_empty() {
            out.push_str(v);
        }
        out.push_str(CRLF);
    }
    out.push_str(CRLF);
    out.into_bytes()
}

/// 渲染 `HTTP/x.y STATUS REASON\r\nh1: v1\r\n...\r\n\r\n`。
///
/// 对应 Go `formResponseHeader`（http.go:238-257）。
pub fn render_response(resp: &ResponseConfig) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str(&resp.get_full_version());
    out.push(' ');
    out.push_str(resp.get_status_code());
    out.push(' ');
    out.push_str(resp.get_status_reason());
    out.push_str(CRLF);
    for h in &resp.header {
        out.push_str(&h.name);
        out.push_str(": ");
        let v = pick_string(&h.value);
        if !v.is_empty() {
            out.push_str(v);
        }
        out.push_str(CRLF);
    }
    if !resp.has_header("Date") {
        out.push_str("Date: ");
        // 不引入 chrono；输出 RFC1123 的占位（精确日期由调用方注入）。
        out.push_str("Thu, 01 Jan 1970 00:00:00 GMT");
        out.push_str(CRLF);
    }
    out.push_str(CRLF);
    out.into_bytes()
}

/// 默认 400 Bad Request 响应（对应 Go resp.go:resp400）。
pub fn default_resp_400() -> ResponseConfig {
    ResponseConfig {
        version: Some("1.1".into()),
        status: Some("400".into()),
        reason: Some("Bad Request".into()),
        header: vec![
            HeaderNameValues::new("Connection", ["close"]),
            HeaderNameValues::new("Cache-Control", ["private"]),
            HeaderNameValues::new("Content-Length", ["0"]),
        ],
    }
}

/// 默认 404 Not Found 响应（对应 Go resp.go:resp404）。
pub fn default_resp_404() -> ResponseConfig {
    ResponseConfig {
        version: Some("1.1".into()),
        status: Some("404".into()),
        reason: Some("Not Found".into()),
        header: vec![
            HeaderNameValues::new("Connection", ["close"]),
            HeaderNameValues::new("Cache-Control", ["private"]),
            HeaderNameValues::new("Content-Length", ["0"]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_request() -> RequestConfig {
        let mut req = RequestConfig::chrome_default();
        req.method = Some("GET".into());
        req.uri = vec!["/".into()];
        req.header.push(HeaderNameValues::new("Test", ["Value"]));
        req
    }

    #[test]
    fn chrome_request_header_renders_expected_layout() {
        // 对应 Go http_test.go:TestRequestHeader 期望值
        let req = chrome_request();
        let bytes = render_request(&req);
        let s = std::str::from_utf8(&bytes).unwrap();
        // 多值 header（如 Sec-Fetch-Mode）走 pick_string 随机，所以不能精确字面比对。
        // 校验：起止 + 用户 header + 所有单值 header 必须出现。
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.ends_with("Test: Value\r\n\r\n"));
        assert!(s.contains("Sec-CH-UA-Mobile: ?0\r\n"));
        assert!(s.contains("Connection: keep-alive\r\n"));
        // 多值 header：值至少是 3 选 1 之一
        assert!(
            s.contains("Sec-Fetch-Mode: no-cors\r\n")
                || s.contains("Sec-Fetch-Mode: cors\r\n")
                || s.contains("Sec-Fetch-Mode: same-origin\r\n")
        );
    }

    #[test]
    fn response_header_renders_status_line_and_date_fallback() {
        let resp = ResponseConfig::chrome_default();
        let bytes = render_response(&resp);
        let s = std::str::from_utf8(&bytes).unwrap();
        // 默认 status="200" reason="OK" version="1.1"
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        // Date 由 has_header=false 触发 fallback
        assert!(s.contains("\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn response_header_skips_date_when_user_supplied() {
        let mut resp = ResponseConfig::chrome_default();
        resp.header.push(HeaderNameValues::new("Date", ["Wed, 21 Oct 2015 07:28:00 GMT"]));
        let bytes = render_response(&resp);
        let s = std::str::from_utf8(&bytes).unwrap();
        let date_count = s.matches("Date:").count();
        // 用户已提供 Date → 只出现 1 次（fallback 不再加）
        assert_eq!(date_count, 1);
        assert!(s.contains("Date: Wed, 21 Oct 2015 07:28:00 GMT"));
    }

    #[test]
    fn http_authenticator_trait_renders_via_config() {
        // 直接构造与 Go TestRequestHeader 完全相同的 RequestConfig
        let req = chrome_request();
        let cfg = HeaderConfig { request: Some(req), response: None };
        let auth = HttpAuthenticator::new(cfg);
        let header = auth.client_header();
        let s = std::str::from_utf8(&header).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        assert!(s.contains("Test: Value"));

        // expected_request_uris 反映 request.uri
        assert_eq!(auth.expected_request_uris(), vec!["/".to_string()]);

        // server_header: response=None → 空 Vec（与 Go http.go:280-282 等价：nil 走 noop）
        assert!(auth.server_header().is_empty());
    }

    #[test]
    fn header_reader_detects_ending_and_returns_body() {
        let mut r = HeaderReader::new();
        // 分两次喂：先 header，再 body
        let part1 = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(r.feed(part1, &[]).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn header_reader_splits_body_after_ending() {
        let mut r = HeaderReader::new();
        let part1 = b"GET / HTTP/1.1\r\n\r\n";
        let part2 = b"hello body";
        // 一次性喂完
        let mut combined = Vec::new();
        combined.extend_from_slice(part1);
        combined.extend_from_slice(part2);
        let body = r.feed(&combined, &[]).unwrap().unwrap();
        assert_eq!(body, b"hello body");
    }

    #[test]
    fn header_reader_returns_none_until_ending_seen() {
        let mut r = HeaderReader::new();
        assert_eq!(r.feed(b"GET / HTTP/1.1\r\n", &[]).unwrap(), None);
        assert_eq!(r.feed(b"User-Agent: x\r\n", &[]).unwrap(), None);
        assert_eq!(r.feed(b"\r\n", &[]).unwrap().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn header_reader_rejects_oversize_header() {
        let mut r = HeaderReader::new();
        let huge = vec![b'a'; MAX_HEADER_LENGTH + 1];
        let err = r.feed(&huge, &[]).unwrap_err();
        assert_eq!(err, HeaderError::TooLong);
    }

    #[test]
    fn header_reader_validates_path_against_expected_uris() {
        let mut r = HeaderReader::new();
        let data = b"POST /wrong HTTP/1.1\r\n\r\n";
        let err = r.feed(data, &["/expected".to_string()]).unwrap_err();
        assert_eq!(err, HeaderError::PathMismatch);
    }

    #[test]
    fn header_reader_accepts_matching_path() {
        let mut r = HeaderReader::new();
        let data = b"POST /expected HTTP/1.1\r\n\r\n";
        assert!(r.feed(data, &["/expected".to_string()]).is_ok());
    }

    #[test]
    fn header_writer_is_one_shot() {
        let mut w = HeaderWriter::new(b"hello".to_vec());
        let mut buf = Vec::new();
        w.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"hello");
        // 第二次写是空（与 Go w.header = nil 行为对齐）
        assert!(w.is_empty());
        w.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"hello"); // buf 不变
    }

    #[test]
    fn default_resp_400_and_404_have_correct_status() {
        let r400 = default_resp_400();
        assert_eq!(r400.get_status_code(), "400");
        assert_eq!(r400.get_status_reason(), "Bad Request");
        assert!(r400.has_header("Connection"));

        let r404 = default_resp_404();
        assert_eq!(r404.get_status_code(), "404");
        assert_eq!(r404.get_status_reason(), "Not Found");
    }
}
