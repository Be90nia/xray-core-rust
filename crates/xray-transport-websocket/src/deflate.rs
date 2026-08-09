//! WebSocket permessage-deflate（RFC 7692）压缩。
//!
//! 使用 soketto 的 deflate 扩展。当客户端/服务端协商启用 deflate 时，
//! WS 帧的 payload 会被 DEFLATE 压缩/解压。
//!
//! ## 集成方式
//!
//! 在现有 tungstenite WS 握手中添加 `Sec-WebSocket-Extensions: permessage-deflate`
//! 请求头。如果服务端接受，创建 soketto `Deflate` 扩展用于帧级压缩。
//!
//! ponytail: tungstenite 上游不支持 deflate（PR 搁置多年），soketto 原生支持。
//! 当前实现提供 deflate 扩展配置 + header 协商辅助。
//! 完整 soketto 替换 tungstenite 可逐步进行。

use soketto::extension::deflate::Deflate;

/// permessage-deflate 协商 header 值。
pub const DEFLATE_HEADER_VALUE: &str = "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

/// 创建客户端 Deflate 扩展实例。
///
/// Soketto `Deflate::new(Client)` 已默认启用 `client_no_context_takeover`
/// + `server_no_context_takeover` 以减少内存。
pub fn create_deflate_extension() -> Deflate {
    Deflate::new(soketto::Mode::Client)
}

/// 检查服务端响应是否接受了 permessage-deflate。
pub fn server_accepted_deflate(response_headers: &http::HeaderMap) -> bool {
    response_headers
        .get_all(http::header::SEC_WEBSOCKET_EXTENSIONS)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.contains("permessage-deflate"))
                .unwrap_or(false)
        })
}

/// 在客户端请求中添加 permessage-deflate 协商头。
pub fn add_deflate_request(request: &mut http::Request<()>) {
    request.headers_mut().insert(
        http::header::SEC_WEBSOCKET_EXTENSIONS,
        http::HeaderValue::from_static(DEFLATE_HEADER_VALUE),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_extension_creates() {
        let _d = create_deflate_extension();
    }

    #[test]
    fn header_detection() {
        let mut headers = http::HeaderMap::new();
        assert!(!server_accepted_deflate(&headers));
        headers.insert(
            http::header::SEC_WEBSOCKET_EXTENSIONS,
            http::HeaderValue::from_static("permessage-deflate"),
        );
        assert!(server_accepted_deflate(&headers));
    }
}
