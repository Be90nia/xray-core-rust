//! Inbound handler trait for accepting incoming connections.
//!
//! Corresponds to Go's `features/inbound` package.

use async_trait::async_trait;

/// Feature type identifier for Inbound.
pub const FEATURE_INBOUND: &str = "inbound";

/// Inbound handler trait for accepting incoming connections.
///
/// Corresponds to Go's `features/inbound.Handler`.
#[async_trait]
pub trait InboundHandler: Send + Sync {
    /// Get the handler tag (unique identifier).
    fn tag(&self) -> &str;

    /// Start the inbound handler, listening for connections.
    async fn start(&self) -> Result<(), InboundError>;

    /// Close the inbound handler, stopping all listeners.
    async fn close(&self) -> Result<(), InboundError>;

    /// Get the listening port (0 if not applicable or not started).
    fn port(&self) -> u16;
}

/// Inbound handler error.
#[derive(Debug, Clone)]
pub enum InboundError {
    /// Handler is already started.
    AlreadyStarted(String),
    /// Handler is closed.
    Closed(String),
    /// Error while listening.
    ListenError(String),
    /// Error while accepting connections.
    AcceptError(String),
}

impl std::fmt::Display for InboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboundError::AlreadyStarted(tag) => {
                write!(f, "inbound handler already started: {}", tag)
            }
            InboundError::Closed(tag) => write!(f, "inbound handler closed: {}", tag),
            InboundError::ListenError(msg) => write!(f, "inbound listen error: {}", msg),
            InboundError::AcceptError(msg) => write!(f, "inbound accept error: {}", msg),
        }
    }
}

impl std::error::Error for InboundError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_inbound_constant() {
        assert_eq!(FEATURE_INBOUND, "inbound");
    }

    #[test]
    fn test_inbound_error_display() {
        assert_eq!(
            format!("{}", InboundError::AlreadyStarted("http".to_string())),
            "inbound handler already started: http"
        );
        assert_eq!(
            format!("{}", InboundError::Closed("socks".to_string())),
            "inbound handler closed: socks"
        );
        assert_eq!(
            format!("{}", InboundError::ListenError("port in use".to_string())),
            "inbound listen error: port in use"
        );
        assert_eq!(
            format!("{}", InboundError::AcceptError("eof".to_string())),
            "inbound accept error: eof"
        );
    }

    #[test]
    fn test_inbound_error_is_std_error() {
        let err = InboundError::Closed("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    /// Mock inbound handler for testing the trait is object-safe.
    struct MockInboundHandler {
        tag: String,
        port: u16,
        started: std::sync::atomic::AtomicBool,
    }

    impl MockInboundHandler {
        fn new(tag: &str, port: u16) -> Self {
            Self {
                tag: tag.to_string(),
                port,
                started: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl InboundHandler for MockInboundHandler {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn start(&self) -> Result<(), InboundError> {
            if self
                .started
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(InboundError::AlreadyStarted(self.tag.clone()));
            }
            Ok(())
        }

        async fn close(&self) -> Result<(), InboundError> {
            self.started
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn port(&self) -> u16 {
            self.port
        }
    }

    #[tokio::test]
    async fn test_mock_inbound_start_close() {
        let handler = MockInboundHandler::new("http", 8080);
        assert_eq!(handler.tag(), "http");
        assert_eq!(handler.port(), 8080);

        assert!(handler.start().await.is_ok());
        assert!(handler.start().await.is_err());

        assert!(handler.close().await.is_ok());
        assert!(handler.start().await.is_ok());
    }
}
