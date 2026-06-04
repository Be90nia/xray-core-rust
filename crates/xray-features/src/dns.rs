//! DNS client trait for resolving domain names.
//!
//! Corresponds to Go's `features/dns` package.

use async_trait::async_trait;
use xray_common::net::address::Address;

/// Feature type identifier for DNS.
pub const FEATURE_DNS: &str = "dns";

/// DNS client trait for resolving domain names.
///
/// Corresponds to Go's `features/dns.Client`.
#[async_trait]
pub trait DnsClient: Send + Sync {
    /// Look up IP addresses for a domain.
    ///
    /// Returns list of resolved addresses (may include both IPv4 and IPv6).
    async fn lookup(&self, domain: &str) -> Result<Vec<Address>, DnsError>;

    /// Look up IPv4 addresses only.
    async fn lookup_ipv4(&self, domain: &str) -> Result<Vec<Address>, DnsError>;

    /// Look up IPv6 addresses only.
    async fn lookup_ipv6(&self, domain: &str) -> Result<Vec<Address>, DnsError>;
}

/// DNS resolution error.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// Domain not found (NXDOMAIN).
    DomainNotFound(String),
    /// DNS server returned an error.
    ServerError(String),
    /// DNS query timed out.
    Timeout,
    /// Other DNS resolution failure.
    Other(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::DomainNotFound(domain) => write!(f, "domain not found: {}", domain),
            DnsError::ServerError(msg) => write!(f, "DNS server error: {}", msg),
            DnsError::Timeout => write!(f, "DNS timeout"),
            DnsError::Other(msg) => write!(f, "DNS resolution failed: {}", msg),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_dns_constant() {
        assert_eq!(FEATURE_DNS, "dns");
    }

    #[test]
    fn test_dns_error_display() {
        assert_eq!(
            format!("{}", DnsError::DomainNotFound("example.com".to_string())),
            "domain not found: example.com"
        );
        assert_eq!(
            format!("{}", DnsError::ServerError("refused".to_string())),
            "DNS server error: refused"
        );
        assert_eq!(format!("{}", DnsError::Timeout), "DNS timeout");
        assert_eq!(
            format!("{}", DnsError::Other("network error".to_string())),
            "DNS resolution failed: network error"
        );
    }

    #[test]
    fn test_dns_error_is_std_error() {
        let err = DnsError::Timeout;
        let _: &dyn std::error::Error = &err;
    }

    /// Mock DNS client for testing the trait is object-safe.
    struct MockDnsClient;

    #[async_trait]
    impl DnsClient for MockDnsClient {
        async fn lookup(&self, _domain: &str) -> Result<Vec<Address>, DnsError> {
            Ok(vec![])
        }

        async fn lookup_ipv4(&self, _domain: &str) -> Result<Vec<Address>, DnsError> {
            Ok(vec![])
        }

        async fn lookup_ipv6(&self, _domain: &str) -> Result<Vec<Address>, DnsError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_mock_dns_client_lookup() {
        let client = MockDnsClient;
        assert!(client.lookup("example.com").await.is_ok());
        assert!(client.lookup_ipv4("example.com").await.is_ok());
        assert!(client.lookup_ipv6("example.com").await.is_ok());
    }
}
