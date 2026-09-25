//! 服务端握手——HTTP/1.1 GET 请求解析 + 101 Switching Protocols 响应构造。
//!
//! 对应 Go `transport/internet/httpupgrade/hub.go`。
//!
//! ## 切片1 边界
//!
//! 实现握手字节流的纯函数解析与构造（`parse_upgrade_request` /
//! `build_upgrade_response`），不涉及实际网络 IO。`keepAccepting` 循环、
//! TLS 包装、PROXY protocol 解析留切片2。

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use crate::{
    config::Config,
    error::{HttpUpgradeError, Result},
};

/// 服务端解析后的请求摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// 请求行 path（`req.URL.Path`）。已校验与 `config.normalized_path()` 一致。
    pub path: String,
    /// `Host` header 值。已校验（若配置要求）。
    pub host: String,
    /// 所有 header（小写键），保留原始顺序信息丢失（HashMap）。
    pub headers: HashMap<String, String>,
    /// `X-Forwarded-For` 解析结果（按从近到远顺序，`0` 是最源端）。
    pub forwarded_for: Vec<IpAddr>,
}

/// 解析客户端 HTTP/1.1 GET upgrade 请求，并按 `config` 校验。
///
/// 入参 `bytes` 应包含完整请求头（`\r\n\r\n` 结束）。
/// 返回解析后的 [`UpgradeRequest`]。
///
/// 对应 Go `hub.go::server.upgrade`（请求部分）+ host/path 校验。
pub fn parse_upgrade_request(bytes: &[u8], config: &Config) -> Result<UpgradeRequest> {
    let sep = find_header_end(bytes).ok_or_else(|| {
        HttpUpgradeError::InvalidHttpFormat("missing \\r\\n\\r\\n terminator".into())
    })?;
    let head = std::str::from_utf8(&bytes[..sep])
        .map_err(|e| HttpUpgradeError::InvalidHttpFormat(format!("non-utf8 request: {e}")))?;
    let mut lines = head.split("\r\n");
    let request_line =
        lines.next().ok_or_else(|| HttpUpgradeError::InvalidHttpFormat("empty request".into()))?;
    // 请求行 "GET <path> HTTP/1.1"
    let req_parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if req_parts.len() != 3 {
        return Err(HttpUpgradeError::InvalidHttpFormat(format!(
            "malformed request line: {request_line:?}"
        )));
    }
    if req_parts[0] != "GET" {
        return Err(HttpUpgradeError::InvalidHttpFormat(format!(
            "expected GET, got {:?}",
            req_parts[0]
        )));
    }
    let path = req_parts[1].to_string();

    // 收集 header
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key_lower = k.trim().to_ascii_lowercase();
            let value = v.trim().to_string();
            // 多值 header 用逗号拼接（与 HTTP 标准一致）。
            headers
                .entry(key_lower)
                .and_modify(|existing| {
                    existing.push(',');
                    existing.push_str(&value);
                })
                .or_insert(value);
        }
    }

    // 提取 Host（首个 Host header，与 Go http.Request.Host 一致）。
    let host = headers.get("host").cloned().unwrap_or_default();

    // 校验 Host（如果 config 配置了 host）。
    if !config.host.is_empty() && !is_valid_http_host(&host, &config.host) {
        return Err(HttpUpgradeError::BadHost { host });
    }

    // 校验 Path。
    let expected_path = config.normalized_path();
    if path != expected_path {
        return Err(HttpUpgradeError::BadPath { path });
    }

    // 校验 Connection / Upgrade header。
    let connection = headers.get("connection").cloned().unwrap_or_default();
    let upgrade = headers.get("upgrade").cloned().unwrap_or_default();
    if !connection.eq_ignore_ascii_case("upgrade") || !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(HttpUpgradeError::UnrecognizedRequest { connection, upgrade });
    }

    // 解析 X-Forwarded-For。
    let forwarded_for =
        headers.get("x-forwarded-for").map(|v| parse_x_forwarded_for(v)).unwrap_or_default();

    Ok(UpgradeRequest { path, host, headers, forwarded_for })
}

/// 构造 101 Switching Protocols 响应字节流。对应 Go `hub.go::server.upgrade`
/// 响应部分。
#[must_use]
pub fn build_upgrade_response() -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    buf.extend_from_slice(b"Connection: Upgrade\r\n");
    buf.extend_from_slice(b"Upgrade: websocket\r\n");
    buf.extend_from_slice(b"\r\n");
    buf
}

/// 解析 `X-Forwarded-For` header 值为 IP 列表。
///
/// 格式：`client, proxy1, proxy2`（按从源到近的顺序）。
/// 无效条目静默跳过（与 Go `ParseXForwardedFor` 一致）。
///
/// 对应 Go `common/protocol/http.ParseXForwardedFor`。
pub fn parse_x_forwarded_for(value: &str) -> Vec<IpAddr> {
    value.split(',').map(|s| s.trim()).filter_map(|s| s.parse::<IpAddr>().ok()).collect()
}

/// 按信任门控从请求头提取 `X-Forwarded-For` 覆盖源地址。对应 Go
/// `common/protocol/http/headers.go::ApplyTrustedXForwardedFor`（hub.go:89-94 应用点）。
///
/// 返回 `Some(addr)`（端口恒 0，对齐 Go `TCPAddr{IP, 0}`）仅当：`trusted`
/// 名单中任一 header 出现在请求中，且 XFF 首段（逗号前）解析为 IP。
/// 其余情况一律返回 `None`（调用方保持真实连接地址）：
/// - 请求无 XFF —— 无日志
/// - 名单命中但 XFF 首段非 IP —— 无日志（对齐 Go for 循环内直接 return）
/// - 无名单（默认不信任，防伪造）—— Go LogWarning
/// - 有名单但名单 header 均不在场 —— Go LogError（疑似伪造）
///
/// `headers` 为 `parse_upgrade_request` 产出的小写键 map；`trusted` 条目
/// 按小写匹配（Go `http.Header` 大小写不敏感语义）。
pub fn apply_trusted_x_forwarded_for(
    headers: &HashMap<String, String>,
    trusted: &[String],
) -> Option<SocketAddr> {
    let value = headers.get("x-forwarded-for").filter(|v| !v.is_empty())?;
    // 首段 + trim（Go value[:idx] 后 ParseAddress 对首尾非 alnum 串 TrimSpace）。
    let first = value.split(',').next().unwrap_or(value).trim();
    if trusted.iter().any(|t| headers.contains_key(t.to_ascii_lowercase().as_str())) {
        return first.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0));
    }
    if trusted.is_empty() {
        tracing::warn!(
            xff = value,
            "received \"X-Forwarded-For\" but \"sockopt.trustedXForwardedFor\" is not configured; \
             ignoring it and using the real remote address"
        );
    } else {
        tracing::warn!(xff = value, "ignored potentially forged \"X-Forwarded-For\"");
    }
    None
}

/// 校验请求 Host 是否匹配配置允许的 host 列表（逗号分隔）。
///
/// 单个 host 的比对走 Go `internet.IsValidHTTPHost`（H2 对齐 internet.go:8-16：
/// lowercase + 请求侧剥端口 + 精确匹配，见
/// [`xray_common::protocol::http::is_valid_http_host`]）。
fn is_valid_http_host(actual: &str, allowed: &str) -> bool {
    allowed
        .split(',')
        .map(str::trim)
        .any(|allowed_host| xray_common::protocol::http::is_valid_http_host(actual, allowed_host))
}

/// 在字节流中查找 `\r\n\r\n`（header 终止符）位置。返回起始下标。
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(host: &str, path: &str) -> Config {
        Config { host: host.into(), path: path.into(), ..Default::default() }
    }

    fn make_request(host: &str, path: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             \r\n"
        )
        .into_bytes()
    }

    #[test]
    fn parse_valid_request() {
        let cfg = make_config("", "/ws");
        let bytes = make_request("example.com", "/ws");
        let req = parse_upgrade_request(&bytes, &cfg).unwrap();
        assert_eq!(req.path, "/ws");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.headers.get("connection").map(String::as_str), Some("Upgrade"));
        assert!(req.forwarded_for.is_empty());
    }

    #[test]
    fn parse_rejects_wrong_path() {
        let cfg = make_config("", "/ws");
        let bytes = make_request("h", "/other");
        let err = parse_upgrade_request(&bytes, &cfg).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::BadPath { .. }));
    }

    #[test]
    fn parse_rejects_wrong_host_when_configured() {
        let cfg = make_config("allowed.example", "/ws");
        let bytes = make_request("evil.example", "/ws");
        let err = parse_upgrade_request(&bytes, &cfg).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::BadHost { .. }));
    }

    #[test]
    fn parse_allows_any_host_when_config_empty() {
        let cfg = make_config("", "/ws");
        let bytes = make_request("anything.example", "/ws");
        parse_upgrade_request(&bytes, &cfg).unwrap();
    }

    #[test]
    fn parse_allows_multiple_allowed_hosts() {
        let cfg = make_config("a.com, b.com, c.com", "/ws");
        for h in &["a.com", "b.com", "c.com"] {
            let bytes = make_request(h, "/ws");
            parse_upgrade_request(&bytes, &cfg).unwrap();
        }
    }

    #[test]
    fn parse_rejects_missing_upgrade_header() {
        let cfg = make_config("", "/ws");
        let bytes = b"GET /ws HTTP/1.1\r\n\
                       Host: h\r\n\
                       Connection: Upgrade\r\n\
                       \r\n";
        let err = parse_upgrade_request(bytes, &cfg).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::UnrecognizedRequest { .. }));
    }

    #[test]
    fn parse_rejects_non_get_method() {
        let cfg = make_config("", "/");
        let bytes = b"POST / HTTP/1.1\r\n\r\n";
        let err = parse_upgrade_request(bytes, &cfg).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::InvalidHttpFormat(_)));
    }

    #[test]
    fn parse_extracts_x_forwarded_for() {
        let cfg = make_config("", "/ws");
        let bytes = b"GET /ws HTTP/1.1\r\n\
                       Host: h\r\n\
                       Connection: Upgrade\r\n\
                       Upgrade: websocket\r\n\
                       X-Forwarded-For: 10.0.0.1, 192.168.1.1, 172.16.0.1\r\n\
                       \r\n";
        let req = parse_upgrade_request(bytes, &cfg).unwrap();
        assert_eq!(req.forwarded_for.len(), 3);
        assert_eq!(req.forwarded_for[0].to_string(), "10.0.0.1");
        assert_eq!(req.forwarded_for[2].to_string(), "172.16.0.1");
    }

    #[test]
    fn parse_skips_invalid_xff_entries() {
        let cfg = make_config("", "/ws");
        let bytes = b"GET /ws HTTP/1.1\r\n\
                       Host: h\r\n\
                       Connection: Upgrade\r\n\
                       Upgrade: websocket\r\n\
                       X-Forwarded-For: 10.0.0.1, not-an-ip, ::1\r\n\
                       \r\n";
        let req = parse_upgrade_request(bytes, &cfg).unwrap();
        assert_eq!(req.forwarded_for.len(), 2);
    }

    #[test]
    fn build_response_format() {
        let bytes = build_upgrade_response();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parse_xff_helper_directly() {
        let ips = parse_x_forwarded_for("1.2.3.4, ::1, not-ip");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "1.2.3.4");
        assert_eq!(ips[1].to_string(), "::1");
    }

    #[test]
    fn parse_xff_empty_returns_empty() {
        assert!(parse_x_forwarded_for("").is_empty());
        assert!(parse_x_forwarded_for("not-an-ip").is_empty());
    }

    #[test]
    fn roundtrip_server_side() {
        // 客户端构造请求 → 服务端解析 → 服务端构造响应。
        let cfg = make_config("example.com", "/ws");
        let req = crate::dialer::build_upgrade_request("example.com", &cfg);
        let parsed = parse_upgrade_request(&req, &cfg).unwrap();
        assert_eq!(parsed.path, "/ws");
        let resp = build_upgrade_response();
        assert!(!resp.is_empty());
    }

    #[test]
    fn xff_gate_empty_trusted_never_adopts() {
        // 名单为空（默认）→ 永不采纳，即使请求带 XFF。
        let mut h = HashMap::new();
        h.insert("x-forwarded-for".to_string(), "10.0.0.1".to_string());
        assert!(apply_trusted_x_forwarded_for(&h, &[]).is_none());
    }

    #[test]
    fn xff_gate_trusted_header_present_adopts_first_ip_with_zero_port() {
        let mut h = HashMap::new();
        h.insert("x-forwarded-for".to_string(), "10.0.0.1, 192.168.1.1".to_string());
        h.insert("x-real-ip".to_string(), "1.2.3.4".to_string());
        let trusted = vec!["X-Real-IP".to_string()]; // 大小写不敏感匹配
        let addr = apply_trusted_x_forwarded_for(&h, &trusted).unwrap();
        assert_eq!(addr.port(), 0);
        assert_eq!(addr.ip().to_string(), "10.0.0.1"); // 首段
    }

    #[test]
    fn xff_gate_trusted_configured_but_header_absent_rejects() {
        let mut h = HashMap::new();
        h.insert("x-forwarded-for".to_string(), "10.0.0.1".to_string());
        let trusted = vec!["X-Real-IP".to_string()];
        assert!(apply_trusted_x_forwarded_for(&h, &trusted).is_none());
    }

    #[test]
    fn xff_gate_non_ip_first_segment_rejects() {
        let mut h = HashMap::new();
        h.insert("x-forwarded-for".to_string(), "evil.example, 1.2.3.4".to_string());
        h.insert("x-real-ip".to_string(), "1.2.3.4".to_string());
        let trusted = vec!["X-Real-IP".to_string()];
        assert!(apply_trusted_x_forwarded_for(&h, &trusted).is_none());
    }

    #[test]
    fn xff_gate_no_xff_returns_none() {
        let h: HashMap<String, String> = HashMap::new();
        let trusted = vec!["X-Real-IP".to_string()];
        assert!(apply_trusted_x_forwarded_for(&h, &trusted).is_none());
        // XFF 值为空串等同不存在（Go header.Get == ""）。
        let mut h_empty = HashMap::new();
        h_empty.insert("x-forwarded-for".to_string(), String::new());
        assert!(apply_trusted_x_forwarded_for(&h_empty, &trusted).is_none());
    }
}
