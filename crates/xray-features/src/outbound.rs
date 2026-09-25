//! Outbound handler trait for proxying connections outbound.
//!
//! Corresponds to Go's `features/outbound` package.

use async_trait::async_trait;
use xray_common::{net::destination::Destination, session::Session};

/// Feature type identifier for Outbound.
pub const FEATURE_OUTBOUND: &str = "outbound";

/// Outbound handler trait for proxying connections outbound.
///
/// Corresponds to Go's `features/outbound.Handler`.
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    /// Get the handler tag (unique identifier).
    fn tag(&self) -> &str;

    /// Proxy a connection to the given destination.
    async fn dial(&self, destination: &Destination, session: &Session)
    -> Result<(), OutboundError>;

    /// Check if this handler can handle the given destination.
    fn can_handle(&self, destination: &Destination) -> bool;
}

/// Outbound handler error.
#[derive(Debug, Clone)]
pub enum OutboundError {
    /// No available outbound handler for the destination.
    NoOutbound(String),
    /// Connection to the destination failed.
    ConnectionFailed(String),
    /// Connection timed out.
    Timeout(String),
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundError::NoOutbound(dest) => {
                write!(f, "no available outbound for destination: {}", dest)
            },
            OutboundError::ConnectionFailed(msg) => {
                write!(f, "outbound connection failed: {}", msg)
            },
            OutboundError::Timeout(msg) => write!(f, "outbound timeout: {}", msg),
        }
    }
}

impl std::error::Error for OutboundError {}

#[cfg(test)]
mod tests {
    use xray_common::net::{address::Address, network::Network, port::Port};

    use super::*;

    #[test]
    fn test_feature_outbound_constant() {
        assert_eq!(FEATURE_OUTBOUND, "outbound");
    }

    #[test]
    fn test_outbound_error_display() {
        assert_eq!(
            format!("{}", OutboundError::NoOutbound("blocked".to_string())),
            "no available outbound for destination: blocked"
        );
        assert_eq!(
            format!("{}", OutboundError::ConnectionFailed("refused".to_string())),
            "outbound connection failed: refused"
        );
        assert_eq!(
            format!("{}", OutboundError::Timeout("30s".to_string())),
            "outbound timeout: 30s"
        );
    }

    #[test]
    fn test_outbound_error_is_std_error() {
        let err = OutboundError::ConnectionFailed("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    /// Mock outbound handler for testing the trait is object-safe.
    struct MockOutboundHandler {
        tag: String,
    }

    impl MockOutboundHandler {
        fn new(tag: &str) -> Self {
            Self { tag: tag.to_string() }
        }
    }

    #[async_trait]
    impl OutboundHandler for MockOutboundHandler {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn dial(
            &self,
            _destination: &Destination,
            _session: &Session,
        ) -> Result<(), OutboundError> {
            Ok(())
        }

        fn can_handle(&self, _destination: &Destination) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_mock_outbound_dial() {
        let handler = MockOutboundHandler::new("direct");
        assert_eq!(handler.tag(), "direct");

        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        let session = Session::new();
        assert!(handler.dial(&dest, &session).await.is_ok());
    }

    #[test]
    fn test_mock_outbound_can_handle() {
        let handler = MockOutboundHandler::new("proxy");
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        assert!(handler.can_handle(&dest));
    }
}
