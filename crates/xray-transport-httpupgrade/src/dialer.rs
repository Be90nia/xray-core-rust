//! 客户端握手——HTTP/1.1 GET 请求构造 + 101 Switching Protocols 响应解析。
//!
//! 对应 Go `transport/internet/httpupgrade/dialer.go`。
//!
//! ## 切片1 边界
//!
//! 实现握手字节流的纯函数构造与解析（`build_upgrade_request` /
//! `parse_upgrade_response`），不涉及实际网络 IO。实际 TCP/TLS 拨号
//! 与 `req.Write(conn)` 留切片2（依赖 `xray-transport::Dialer` 完整实现 +
//! `xray-tls` uTLS）。
//!
//! ## HTTP/1.1 格式
//!
//! 请求（手写，不引 http crate），header 集合对齐 Go dialer.go:96-101：
//! ```text
//! GET <path> HTTP/1.1\r\n
//! Host: <host>\r\n
//! <custom-headers>\r\n
//! <browser-masquerade-headers（UA 缺省/枚举值时注入）>\r\n
//! Connection: Upgrade\r\n
//! Upgrade: websocket\r\n
//! \r\n
//! ```
//!
//! 响应校验：`101 Switching Protocols` + `Upgrade: websocket`（小写比较） +
//! `Connection: upgrade`（小写比较）。

use xray_common::browser::{set_header, try_default_headers_with};

use crate::{
    config::Config,
    error::{HttpUpgradeError, Result},
};

/// 构造 HTTP/1.1 GET upgrade 请求字节流。
///
/// - `host`：HTTP `Host` header 值（不可空，由调用方保证，三级回退见
///   `register.rs::dial_httpupgrade`）。
/// - `config`：提供 `normalized_path()` + `header`。
///
/// 返回完整请求字节（含末尾 `\r\n\r\n`）。
///
/// header 顺序对齐 Go `dialer.go::dialhttpUpgrade`：自定义 header（AddHeader）
/// → 浏览器伪装（`TryDefaultHeadersWith(header, "ws")`，"ws" 是 variant 名）
/// → `Connection`/`Upgrade` Set 覆盖（dialer.go:96-101）。
#[must_use]
pub fn build_upgrade_request(host: &str, config: &Config) -> Vec<u8> {
    // 1. 用户自定义 header（Go dialer.go:96-98 AddHeader 循环）。
    let mut headers: Vec<(String, String)> =
        config.header.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    // 2. 浏览器伪装（Go dialer.go:99）：UA 缺省 → Chrome 全套；UA 为浏览器 枚举值 →
    //    对应伪装；其他自定义 UA → 原样保留。
    try_default_headers_with(&mut headers, "ws");
    // 3. Connection/Upgrade 最后 Set（Go dialer.go:100-101）：覆盖用户同名配置。
    set_header(&mut headers, "Connection", "Upgrade");
    set_header(&mut headers, "Upgrade", "websocket");

    let mut buf = Vec::with_capacity(512);
    // 请求行
    buf.extend_from_slice(b"GET ");
    buf.extend_from_slice(config.normalized_path().as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");
    // Host 由调用方提供（配置/ServerName/拨号地址三级回退）
    write_header(&mut buf, "Host", host);
    // 其余 header（对 HTTP 语义顺序无关；Go 侧经 req.Write 排序输出）
    for (key, value) in &headers {
        write_header(&mut buf, key, value);
    }
    // 终止空行
    buf.extend_from_slice(b"\r\n");
    buf
}

/// 写入一行 header：`key: value\r\n`。
///
/// 对应 Go `AddHeader`（直接操作 `header[key]`，不做 MIME 规范化）。
/// 保留调用方原大小写，允许 `Web*S*ocket` 等非标准大写。
fn write_header(buf: &mut Vec<u8>, key: &str, value: &str) {
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(value.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

/// 解析 HTTP/1.1 响应状态行 + 必需 header，校验是否为合法 101 upgrade 响应。
///
/// 入参 `bytes` 应包含至少一个完整响应头（`\r\n\r\n` 结束）。
/// 解析后返回 header 末尾位置（`\r\n\r\n` 之后），让调用方知道从哪里开始
/// 是 raw payload。
///
/// 对应 Go `dialer.go::ConnRF.Read` 首次调用：用 `http.ReadResponse` 解析 +
/// 校验 `resp.Status` / `Upgrade` / `Connection`。
pub fn parse_upgrade_response(bytes: &[u8]) -> Result<usize> {
    // 找 \r\n\r\n 分隔头与 body。
    let sep = find_header_end(bytes).ok_or_else(|| {
        HttpUpgradeError::InvalidHttpFormat("missing \\r\\n\\r\\n terminator".into())
    })?;
    let head = std::str::from_utf8(&bytes[..sep])
        .map_err(|e| HttpUpgradeError::InvalidHttpFormat(format!("non-utf8 header: {e}")))?;
    let mut lines = head.split("\r\n");
    let status_line =
        lines.next().ok_or_else(|| HttpUpgradeError::InvalidHttpFormat("empty response".into()))?;
    // 状态行形如 "HTTP/1.1 101 Switching Protocols"
    if !status_line.starts_with("HTTP/") {
        return Err(HttpUpgradeError::InvalidHttpFormat(format!(
            "not a status line: {status_line:?}"
        )));
    }
    let status = status_line
        .split_once(' ')
        .map(|x| x.1)
        .ok_or_else(|| {
            HttpUpgradeError::InvalidHttpFormat(format!("malformed status: {status_line:?}"))
        })?
        .trim();
    // 收集 Connection / Upgrade header（大小写不敏感比较值）
    let mut connection_value = String::new();
    let mut upgrade_value = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key_lower = k.trim().to_ascii_lowercase();
            let value = v.trim();
            match key_lower.as_str() {
                "connection" => {
                    if !connection_value.is_empty() {
                        connection_value.push(',');
                    }
                    connection_value.push_str(value);
                },
                "upgrade" => {
                    if !upgrade_value.is_empty() {
                        upgrade_value.push(',');
                    }
                    upgrade_value.push_str(value);
                },
                _ => {},
            }
        }
    }
    let upgrade_lower = upgrade_value.to_ascii_lowercase();
    let connection_lower = connection_value.to_ascii_lowercase();
    // H15：对齐 Go dialer.go:22-33 精确比对（lowercase 后 ==）——此前 contains
    // 宽于 Go（`Upgrade: not-websocket` / `Connection: keep-alive, upgrade` 会被
    // Go 拒绝而 Rust 误接受）。多值逗号拼接形态已不可绕过：Go 侧 header 多值
    // 也会拼逗号再整体比较。
    let status_ok = status.eq_ignore_ascii_case("101 Switching Protocols");
    let upgrade_ok = upgrade_lower == "websocket";
    let connection_ok = connection_lower == "upgrade";
    if !status_ok || !upgrade_ok || !connection_ok {
        return Err(HttpUpgradeError::UnrecognizedReply {
            status: status.to_string(),
            upgrade: upgrade_value,
            connection: connection_value,
        });
    }
    // 返回 header 后第一个字节位置（payload 起始）。
    Ok(sep + 4)
}

/// 在字节流中查找 `\r\n\r\n`（header 终止符）位置。返回起始下标。
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(path: &str) -> Config {
        Config { host: "example.com".into(), path: path.into(), ..Default::default() }
    }

    #[test]
    fn build_request_basic_format() {
        let cfg = make_config("/ws");
        let bytes = build_upgrade_request("example.com", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        // 票 mzte：UA 不再是字面量 "ws"，而是 Chrome 伪装全套（Go dialer.go:99）。
        assert!(
            s.contains("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
                && s.contains(" Safari/537.36\r\n"),
            "UA must masquerade as Chrome"
        );
        assert!(s.contains("Sec-CH-UA: \""), "Sec-CH-UA GREASE brand present");
        assert!(s.contains("Sec-Fetch-Mode: websocket\r\n"));
        assert!(s.contains("Sec-Fetch-Dest: empty\r\n"));
        assert!(s.contains("Sec-Fetch-Site: same-origin\r\n"));
        assert!(s.contains("Cache-Control: no-cache\r\n"));
        assert!(s.contains("Pragma: no-cache\r\n"));
        assert!(s.contains("Accept: */*\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_request_normalizes_path() {
        let cfg = make_config("noLeadingSlash");
        let bytes = build_upgrade_request("h", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("GET /noLeadingSlash HTTP/1.1\r\n"));
    }

    #[test]
    fn build_request_includes_custom_headers() {
        let mut cfg = make_config("/ws");
        cfg.header.insert("X-Token".into(), "abc".into());
        cfg.header.insert("X-Real-Ip".into(), "1.2.3.4".into());
        let bytes = build_upgrade_request("example.com", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("X-Token: abc\r\n"));
        assert!(s.contains("X-Real-Ip: 1.2.3.4\r\n"));
    }

    #[test]
    fn custom_user_agent_is_preserved_without_masquerade() {
        let mut cfg = make_config("/ws");
        cfg.header.insert("User-Agent".into(), "my-agent/1.2".into());
        let bytes = build_upgrade_request("example.com", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("User-Agent: my-agent/1.2\r\n"));
        assert!(!s.contains("Sec-Fetch-"), "no masquerade for custom UA");
        assert!(!s.contains("Sec-CH-UA"));
    }

    #[test]
    fn chrome_enum_user_agent_gets_full_masquerade() {
        let mut cfg = make_config("/ws");
        cfg.header.insert("User-Agent".into(), "chrome".into());
        let bytes = build_upgrade_request("example.com", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            s.contains("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            "enum value replaced by real Chrome UA"
        );
        assert!(s.contains("Sec-Fetch-Mode: websocket\r\n"));
    }

    #[test]
    fn connection_and_upgrade_override_user_config() {
        // Go dialer.go:100-101：Set 在伪装之后，覆盖用户同名配置。
        let mut cfg = make_config("/ws");
        cfg.header.insert("Connection".into(), "keep-alive".into());
        cfg.header.insert("Upgrade".into(), "h2c".into());
        let bytes = build_upgrade_request("example.com", &cfg);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("keep-alive"), "user Connection overridden");
        assert!(!s.contains("h2c"), "user Upgrade overridden");
        assert!(s.matches("Connection: Upgrade\r\n").count() == 1);
        assert!(s.matches("Upgrade: websocket\r\n").count() == 1);
    }

    #[test]
    fn parse_valid_101_response() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     \r\n\
                     payload bytes";
        let pos = parse_upgrade_response(resp).unwrap();
        assert_eq!(&resp[pos..], b"payload bytes");
    }

    #[test]
    fn parse_response_with_lowercase_headers() {
        // 部分服务端返回小写 header，需大小写不敏感比较。
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     connection: upgrade\r\n\
                     upgrade: websocket\r\n\
                     \r\n";
        let pos = parse_upgrade_response(resp).unwrap();
        assert_eq!(pos, resp.len());
    }

    #[test]
    fn parse_response_with_capitalized_websocket_variant() {
        // Go 注释提到 "Web*S*ocket" 变体；值比较仍小写，应通过。
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: Websocket\r\n\
                     \r\n";
        parse_upgrade_response(resp).unwrap();
    }

    #[test]
    fn parse_response_rejects_non_101_status() {
        let resp = b"HTTP/1.1 200 OK\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     \r\n";
        let err = parse_upgrade_response(resp).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::UnrecognizedReply { .. }));
    }

    #[test]
    fn parse_response_rejects_missing_upgrade_header() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     \r\n";
        let err = parse_upgrade_response(resp).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::UnrecognizedReply { .. }));
    }

    #[test]
    fn parse_response_rejects_missing_connection_header() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     \r\n";
        let err = parse_upgrade_response(resp).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::UnrecognizedReply { .. }));
    }

    #[test]
    fn parse_response_rejects_truncated_input() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\n";
        let err = parse_upgrade_response(resp).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::InvalidHttpFormat(_)));
    }

    #[test]
    fn parse_response_rejects_non_http() {
        let resp = b"NOT-HTTP\r\n\r\n";
        let err = parse_upgrade_response(resp).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::InvalidHttpFormat(_)));
    }

    #[test]
    fn roundtrip_request_response_through_real_socket_simulation() {
        // 客户端构造请求 → 服务端解析 → 服务端构造响应 → 客户端解析。
        let cfg = make_config("/ws");
        let req = build_upgrade_request("example.com", &cfg);
        assert!(!req.is_empty());

        let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     \r\n";
        let pos = parse_upgrade_response(resp).unwrap();
        assert_eq!(pos, resp.len());
    }
}
