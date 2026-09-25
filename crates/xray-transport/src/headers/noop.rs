//! # Noop header authenticator
//!
//! 对应 Go `transport/internet/headers/noop/NoOpConnectionHeader`（noop.go:23-35）：
//! 客户端/服务端 header 都不发，URI 不校验。fallback 实现。
//!
//! ## 与 `http::HttpAuthenticator` 的关系
//!
//! 当 `HeaderConfig.request == None && .response == None` 时
//! （Go `Authenticator.Client/Server` http.go:285-287 / 301-303 直接返回原 conn），
//! 应使用 `NoopHeaderAuthenticator`，避免无谓的字节切分。
//!
//! 当 `http::HttpAuthenticator::client_header()` 返回空 Vec 时
//! （response=None），调用方也能用 `NoopHeaderAuthenticator` 替代。

use super::authenticator::HeaderAuthenticator;

/// Noop fallback：不发任何 header，不校验任何 URI。
///
/// 对应 Go `noop.NoOpConnectionHeader{}.Client(conn) = conn` / `.Server(conn) = conn`。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopHeaderAuthenticator;

impl NoopHeaderAuthenticator {
    pub const fn new() -> Self {
        Self
    }
}

impl HeaderAuthenticator for NoopHeaderAuthenticator {
    fn client_header(&self) -> Vec<u8> {
        Vec::new()
    }

    fn server_header(&self) -> Vec<u8> {
        Vec::new()
    }

    fn expected_request_uris(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_authenticator_returns_empty_for_everything() {
        let auth = NoopHeaderAuthenticator::new();
        assert!(auth.client_header().is_empty());
        assert!(auth.server_header().is_empty());
        assert!(auth.expected_request_uris().is_empty());
    }

    #[test]
    fn noop_is_send_sync_and_zero_sized() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopHeaderAuthenticator>();
        assert_eq!(std::mem::size_of::<NoopHeaderAuthenticator>(), 0);
    }
}
