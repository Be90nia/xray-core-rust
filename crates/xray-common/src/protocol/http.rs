//! HTTP 协议公共 helper。对应 Go `common/protocol/http/` 包中与传输层共享的
//! 纯函数（`headers.go` / `internet.go::IsValidHTTPHost`）。

/// 复刻 Go `net.SplitHostPort` 的 host 提取（仅 `IsValidHTTPHost` 消费的形态）。
///
/// 与 Go 一致：任何解析失败（缺 `]`、`]` 后不是端口冒号、裸 IPv6 多冒号、
/// 非法 port 字符）返回 `None`——Go 返回空串 + err，调用方忽略 err 只用空串。
#[must_use]
pub fn go_split_host_port(host_port: &str) -> Option<&str> {
    // Go：The port starts after the last colon.
    let i = host_port.rfind(':')?;
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // bracket 形式 `[host]:port`：`]` 必须存在，且其后恰好是最后那个冒号。
        // Go end = index(']')（全串）；switch end+1 { case i: ok; default: err }。
        let end = rest.find(']')?; // 缺 ']' → err
        if end + 2 != i {
            return None;
        }
        &rest[..end]
    } else {
        // 无 bracket：出现多个冒号 = 裸 IPv6 → Go tooManyColons err。
        if host_port.find(':') != Some(i) {
            return None;
        }
        &host_port[..i]
    };
    // Go validOptionalPort(":"+port)：空或全 ASCII 数字。
    let port = &host_port[i + 1..];
    if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(host)
}

/// 复刻 Go `transport/internet.IsValidHTTPHost`（internet.go:8-16）。
///
/// 双侧 lowercase；request 含 `:` 时经 `net.SplitHostPort` 剥端口后与 config
/// **精确**比较（解析失败按空串——Go 忽略 SplitHostPort 的 err）；不含 `:`
/// 时整串精确比较。
#[must_use]
pub fn is_valid_http_host(request: &str, config: &str) -> bool {
    let r = request.to_ascii_lowercase();
    let c = config.to_ascii_lowercase();
    let host = if r.contains(':') { go_split_host_port(&r).unwrap_or("") } else { r.as_str() };
    host == c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_http_host_matches_go_semantics() {
        // 精确匹配（对齐 Go internet.go），子串不通过（H2 修复语义）。
        assert!(is_valid_http_host("example.com", "example.com"));
        assert!(!is_valid_http_host("notevil.example.com", "evil.example.com"));
        // 大小写不敏感。
        assert!(is_valid_http_host("Example.COM", "example.com"));
        // 带端口请求剥端口（Go SplitHostPort）。
        assert!(is_valid_http_host("example.com:443", "example.com"));
        assert!(is_valid_http_host("Example.com:8443", "example.com"));
        // IPv6 bracket。
        assert!(is_valid_http_host("[::1]:8080", "::1"));
        // 裸 IPv6：Go SplitHostPort tooManyColons err → 空串 → 不匹配。
        assert!(!is_valid_http_host("::1", "::1"));
        // 端口非数字 → err → 不匹配。
        assert!(!is_valid_http_host("example.com:http", "example.com"));
        // 非法 bracket → 不匹配。
        assert!(!is_valid_http_host("[::1:80", "::1"));
        // config 侧 lowercase 但不剥端口（Go 只对 request split）。
        assert!(is_valid_http_host("example.com:443", "EXAMPLE.com"));
        assert!(!is_valid_http_host("example.com", "example.com:443"));
    }

    #[test]
    fn go_split_host_port_edge_cases() {
        assert_eq!(go_split_host_port("example.com:80"), Some("example.com"));
        assert_eq!(go_split_host_port("[::1]:443"), Some("::1"));
        assert_eq!(go_split_host_port("host:"), Some("host")); // 空 port 合法
        assert_eq!(go_split_host_port(":8080"), Some(""));
        assert_eq!(go_split_host_port("nocolon"), None); // Go missingPort
        assert_eq!(go_split_host_port("[::1]"), None); // 缺端口
        assert_eq!(go_split_host_port("[::1]x:80"), None); // ] 后非冒号
    }
}
