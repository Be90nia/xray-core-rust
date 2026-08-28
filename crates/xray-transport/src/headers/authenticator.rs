//! # Header authenticator trait + 配置类型
//!
//! 对应 Go `transport/internet/headers/`（http + noop）的接口层。
//!
//! 命名注意：Go 的 `Authenticator` 在 Rust 端名 `HeaderAuthenticator`，
//! 因为 `xray_crypto::authenticator::Authenticator`（AEAD）已占用 `Authenticator`。
//!
//! ## 与 4t8 的边界
//!
//! - 本 crate：本 trait + Request/Response 配置结构 + http/noop 实现
//! - 4t8 (xray-conf)：把 `streamSettings.header.type` JSON 装配成 `Config`
//!
//! ## 类型对应
//!
//! | Go                                  | Rust                              |
//! |-------------------------------------|-----------------------------------|
//! | `http.Authenticator`                | `HttpAuthenticator`               |
//! | `http.RequestConfig`/`ResponseConfig` | `RequestConfig`/`ResponseConfig` |
//! | `http.Config`                       | `HeaderConfig`                    |
//! | `noop.NoOpConnectionHeader`         | `NoopHeaderAuthenticator`         |
//! | `http.HeaderReader`                 | `HeaderReader`（同步 byte 切片）  |
//! | `http.HeaderWriter`                 | `HeaderWriter`                    |

use std::fmt;

/// 单个 HTTP header 项（name + 多 value 候选）。
///
/// 对应 Go `headers.http.Header`（proto `message Header`）：
/// name = header 名；value = 多个候选，每次发送随机挑一个。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderNameValues {
    pub name: String,
    pub value: Vec<String>,
}

impl HeaderNameValues {
    pub fn new(name: impl Into<String>, value: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            value: value.into_iter().map(Into::into).collect(),
        }
    }
}

/// HTTP 请求伪装配置。
///
/// 对应 Go `http.RequestConfig`（proto）。`version`/`method` 缺省 → "1.1"/"GET"；
/// `uri` 缺省 → `["/"]`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestConfig {
    pub version: Option<String>,
    pub method: Option<String>,
    pub uri: Vec<String>,
    pub header: Vec<HeaderNameValues>,
}

impl RequestConfig {
    /// 默认（Chrome 浏览器的 `GET / HTTP/1.1` + 12 个固定 header）。
    ///
    /// 对应 Go `infra/conf/transport_authenticators.go:36-88` 的硬编码默认。
    pub fn chrome_default() -> Self {
        Self {
            version: None,
            method: None,
            uri: vec!["/".to_string()],
            header: chrome_default_request_headers(),
        }
    }

    pub fn get_version(&self) -> &str {
        self.version.as_deref().unwrap_or("1.1")
    }

    pub fn get_method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }

    pub fn get_full_version(&self) -> String {
        format!("HTTP/{}", self.get_version())
    }
}

/// HTTP 响应伪装配置。
///
/// 对应 Go `http.ResponseConfig`（proto）。`version` 缺省 "1.1"；`status` 缺省 "200 OK"。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseConfig {
    pub version: Option<String>,
    pub status: Option<String>,
    pub reason: Option<String>,
    pub header: Vec<HeaderNameValues>,
}

impl ResponseConfig {
    /// 默认（Chrome 风格的 5 个固定响应头）。
    pub fn chrome_default() -> Self {
        Self {
            version: None,
            status: None,
            reason: None,
            header: chrome_default_response_headers(),
        }
    }

    pub fn get_version(&self) -> &str {
        self.version.as_deref().unwrap_or("1.1")
    }

    pub fn get_full_version(&self) -> String {
        format!("HTTP/{}", self.get_version())
    }

    pub fn get_status_code(&self) -> &str {
        self.status.as_deref().unwrap_or("200")
    }

    pub fn get_status_reason(&self) -> &str {
        self.reason.as_deref().unwrap_or("OK")
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    }
}

/// Header authenticator 顶层配置。
///
/// 对应 Go `http.Config`（proto）：request + response 都可缺省（缺省→noop）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderConfig {
    pub request: Option<RequestConfig>,
    pub response: Option<ResponseConfig>,
}

/// Header authenticator trait。
///
/// 对应 Go `http.Authenticator` 的最小接口（http.go:259）：
/// - `client_header` → 客户端要发送的请求 header 字节
/// - `server_header` → 服务端要发送的响应 header 字节
/// - `expected_request` → 服务端期待的请求 URI 列表（用于校验）
///
/// 注意：`Client(conn)/Server(conn) net.Conn` 包装层（http.go:284-308）属于 4t8
/// （连接层装配）范围，本 trait 只覆盖「我要发送/期待什么字节」。
pub trait HeaderAuthenticator: Send + Sync {
    /// 客户端请求 header 字节（首行 + 各 header + 空行结束）。
    fn client_header(&self) -> Vec<u8>;

    /// 服务端响应 header 字节（首行 + 各 header + 空行结束）。
    fn server_header(&self) -> Vec<u8>;

    /// 服务端期待的请求 URI 列表。空 → 跳过 URI 校验。
    fn expected_request_uris(&self) -> Vec<String>;
}

/// Chrome 浏览器的 12 个默认请求 header 值（对应 Go transport_authenticators.go:38-87）。
fn chrome_default_request_headers() -> Vec<HeaderNameValues> {
    vec![
        HeaderNameValues::new("Host", ["www.baidu.com", "www.bing.com"]),
        HeaderNameValues::new("User-Agent", [CHROME_UA]),
        HeaderNameValues::new("Sec-CH-UA", [CHROME_UACH]),
        HeaderNameValues::new("Sec-CH-UA-Mobile", ["?0"]),
        HeaderNameValues::new("Sec-CH-UA-Platform", ["Windows"]),
        HeaderNameValues::new("Sec-Fetch-Mode", ["no-cors", "cors", "same-origin"]),
        HeaderNameValues::new("Sec-Fetch-Dest", ["empty"]),
        HeaderNameValues::new("Sec-Fetch-Site", ["none"]),
        HeaderNameValues::new("Sec-Fetch-User", ["?1"]),
        HeaderNameValues::new("Accept-Encoding", ["gzip, deflate"]),
        HeaderNameValues::new("Connection", ["keep-alive"]),
        HeaderNameValues::new("Pragma", ["no-cache"]),
    ]
}

/// Chrome 浏览器的 5 个默认响应 header 值（对应 Go transport_authenticators.go:128-150）。
fn chrome_default_response_headers() -> Vec<HeaderNameValues> {
    vec![
        HeaderNameValues::new(
            "Content-Type",
            ["application/octet-stream", "video/mpeg"],
        ),
        HeaderNameValues::new("Transfer-Encoding", ["chunked"]),
        HeaderNameValues::new("Connection", ["keep-alive"]),
        HeaderNameValues::new("Pragma", ["no-cache"]),
        HeaderNameValues::new("Cache-Control", ["private", "no-cache"]),
    ]
}

// Chrome UA 常量（对应 Go common/utils.ChromeUA / ChromeUACH）。
// 取 Go v26.6.1 stable 值（Common-utils.go: CHROME 常量随版本同步）。
// 精确字面值不参与行为契约，仅在测试中作为 fixture 出现。
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const CHROME_UACH: &str = "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"";

/// 错误：HTTP header 超过 `maxHeaderLength`（DDoS 防护）。
///
/// 对应 Go `ErrHeaderToLong`（http.go:30）。常量 8192 与 Go 一致。
pub const MAX_HEADER_LENGTH: usize = 8192;

/// Header 解析/读取错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// header 超过 [`MAX_HEADER_LENGTH`]。
    TooLong,
    /// request 行不匹配 `expected_request_uris`。
    PathMismatch,
    /// I/O 错误（读字节流时遇到）。
    Io(String),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("header too long"),
            Self::PathMismatch => f.write_str("header path mismatch"),
            Self::Io(msg) => write!(f, "io: {msg}"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// 暴露给外部的「pick one from multiple values」helper。
///
/// 对应 Go `common/dice.Roll` + `pickString`（config.go:9-19）。
/// 0 个值 → 返回空串；1 个 → 返回该值；n 个 → 随机返回一个。
pub fn pick_string(values: &[String]) -> &str {
    if values.is_empty() {
        return "";
    }
    if values.len() == 1 {
        return &values[0];
    }
    // rand 0.9 用 random_range 替代 random::<T>() % n
    let idx = rand::random_range(0..values.len());
    &values[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_request_default_has_twelve_holders_and_user_agent() {
        let cfg = RequestConfig::chrome_default();
        assert_eq!(cfg.uri, vec!["/"]);
        assert_eq!(cfg.get_method(), "GET");
        assert_eq!(cfg.get_version(), "1.1");
        assert_eq!(cfg.get_full_version(), "HTTP/1.1");
        assert_eq!(cfg.header.len(), 12);
        let ua = cfg.header.iter().find(|h| h.name == "User-Agent").unwrap();
        assert_eq!(ua.value.len(), 1);
        assert!(ua.value[0].starts_with("Mozilla/5.0"));
    }

    #[test]
    fn chrome_response_default_has_five_holders_and_content_type() {
        let cfg = ResponseConfig::chrome_default();
        assert_eq!(cfg.get_version(), "1.1");
        assert_eq!(cfg.get_status_code(), "200");
        assert_eq!(cfg.get_status_reason(), "OK");
        assert_eq!(cfg.header.len(), 5);
        assert!(cfg.has_header("Content-Type"));
        assert!(cfg.has_header("content-type"));
        assert!(!cfg.has_header("X-Custom"));
    }

    #[test]
    fn pick_string_empty_returns_empty() {
        assert_eq!(pick_string(&[]), "");
    }

    #[test]
    fn pick_string_single_returns_that() {
        let v = vec!["only".to_string()];
        assert_eq!(pick_string(&v), "only");
    }

    #[test]
    fn pick_string_multi_returns_one_of_them() {
        let v = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let picked = pick_string(&v);
        assert!(["a", "b", "c"].contains(&picked));
    }
}