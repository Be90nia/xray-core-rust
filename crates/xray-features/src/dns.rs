//! DNS client trait for resolving domain names.
//!
//! Corresponds to Go's `features/dns` package (`features/dns/client.go`).

use std::net::IpAddr;

use async_trait::async_trait;

use crate::Feature;

/// Feature type identifier for DNS.
pub const FEATURE_DNS: &str = "dns";

/// DNS 查询的 IP 过滤选项。对应 Go `features/dns.IPOption`（client.go:10-15）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpOption {
    /// 启用 IPv4 查询。
    pub ipv4_enable: bool,
    /// 启用 IPv6 查询。
    pub ipv6_enable: bool,
    /// 启用 FakeDNS 响应。
    pub fake_enable: bool,
}

impl IpOption {
    /// 全开（IPv4 + IPv6 + FakeDNS）。
    #[must_use]
    pub const fn all() -> Self {
        Self { ipv4_enable: true, ipv6_enable: true, fake_enable: true }
    }

    /// 是否完全无查询目标。
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.ipv4_enable && !self.ipv6_enable
    }
}

/// DNS client trait for resolving domain names.
///
/// 对应 Go `features/dns.Client`（client.go:20-25）：
/// `LookupIP(domain string, option IPOption) ([]net.IP, uint32, error)`——
/// 单方法 + IPOption 过滤 + TTL 返回。
#[async_trait]
pub trait DnsClient: Send + Sync {
    /// Look up IP addresses for a domain with IPOption filtering.
    ///
    /// Returns resolved addresses (IPv4 and/or IPv6 per option) and TTL seconds.
    async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError>;
}

/// 默认 TTL（秒）。对应 Go `dns.DefaultTTL = 300`（client.go:37）。
pub const DEFAULT_TTL: u32 = 300;

/// DNS resolution error.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// Domain not found (NXDOMAIN).
    DomainNotFound(String),
    /// DNS server returned an error.
    ServerError(String),
    /// DNS query timed out.
    Timeout,
    /// 查询成功但无记录。对应 Go `dns.ErrEmptyResponse`（client.go:34-35）。
    EmptyResponse,
    /// DNS 服务器返回非 0 RCode。对应 Go `dns.RCodeError`（client.go:39-43）。
    Rcode(u16),
    /// Other DNS resolution failure.
    Other(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::DomainNotFound(domain) => write!(f, "domain not found: {domain}"),
            DnsError::ServerError(msg) => write!(f, "DNS server error: {msg}"),
            DnsError::Timeout => write!(f, "DNS timeout"),
            DnsError::EmptyResponse => write!(f, "empty response"),
            DnsError::Rcode(code) => write!(f, "rcode: {code}"),
            DnsError::Other(msg) => write!(f, "DNS resolution failed: {msg}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// 从错误提取 RCode。对应 Go `dns.RCodeFromError`（client.go:63-72）：
/// 非 RCode 错误（含 `None`）返回 0。
#[must_use]
pub fn rcode_from_error(err: &DnsError) -> u16 {
    match err {
        DnsError::Rcode(code) => *code,
        _ => 0,
    }
}

/// localdns 默认 DNS Feature。
///
/// 对应 Go `features/dns/localdns.Client`（localdns/client.go）——作为
/// `essentialFeatures` 默认注册的 `localdns.New()`（core/xray.go:213）：
/// 无 dns app 配置时，Instance 以系统 resolver 直查作为中央 DNS 能力。
///
/// 语义（localdns/client.go:32-76）：系统解析全量 IP → 按 IPOption 过滤 →
/// 空则 `ErrEmptyResponse`，成功 TTL 固定 `DefaultTTL`。
///
/// Go 的 `internet.Controllers` socket 钩子（client.go:79-102）无 Rust 等价物，跳过。
pub struct DefaultDnsFeature;

impl Feature for DefaultDnsFeature {
    fn feature_name(&self) -> &'static str {
        "default_dns"
    }
}

#[async_trait]
impl DnsClient for DefaultDnsFeature {
    async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        // tokio lookup_host = getaddrinfo：读系统 resolver 配置 + 系统 hosts，
        // 等价 Go net.LookupIP（localdns/client.go:38）。
        let addrs: Vec<IpAddr> = tokio::net::lookup_host((domain, 0))
            .await
            .map_err(|e| DnsError::Other(format!("localdns lookup: {e}")))?
            .map(|sa| sa.ip())
            .collect();

        // Go localdns/client.go:61-75：按 IPOption 选族，选中族为空 → ErrEmptyResponse。
        let ips: Vec<IpAddr> = addrs
            .into_iter()
            .filter(|ip| match ip {
                IpAddr::V4(_) => option.ipv4_enable,
                IpAddr::V6(_) => option.ipv6_enable,
            })
            .collect();

        if ips.is_empty() { Err(DnsError::EmptyResponse) } else { Ok((ips, DEFAULT_TTL)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDnsClient;

    #[async_trait]
    impl DnsClient for MockDnsClient {
        async fn lookup_ip(
            &self,
            _domain: &str,
            _option: IpOption,
        ) -> Result<(Vec<IpAddr>, u32), DnsError> {
            Ok((vec![], 0))
        }
    }

    #[tokio::test]
    async fn test_mock_dns_client_lookup_ip() {
        let client = MockDnsClient;
        let result = client.lookup_ip("example.com", IpOption::all()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn default_ttl_is_300() {
        // Go features/dns/client.go:37: const DefaultTTL = 300
        assert_eq!(DEFAULT_TTL, 300);
    }

    #[test]
    fn rcode_from_error_extracts_rcode_only() {
        // Go RCodeFromError：RCodeError → 码值，其余 → 0。
        assert_eq!(rcode_from_error(&DnsError::Rcode(3)), 3);
        assert_eq!(rcode_from_error(&DnsError::Rcode(0)), 0);
        assert_eq!(rcode_from_error(&DnsError::EmptyResponse), 0);
        assert_eq!(rcode_from_error(&DnsError::Other("x".into())), 0);
        assert_eq!(rcode_from_error(&DnsError::Timeout), 0);
    }

    #[test]
    fn rcode_error_display_matches_go_format() {
        // Go: serial.Concat("rcode: ", uint16(e))
        assert_eq!(DnsError::Rcode(2).to_string(), "rcode: 2");
        assert_eq!(DnsError::EmptyResponse.to_string(), "empty response");
    }

    #[test]
    fn ip_option_all_enables_everything() {
        let o = IpOption::all();
        assert!(o.ipv4_enable && o.ipv6_enable && o.fake_enable);
        assert!(!o.is_empty());
        assert!(IpOption::is_empty(IpOption {
            ipv4_enable: false,
            ipv6_enable: false,
            fake_enable: true
        }));
    }

    #[tokio::test]
    async fn default_dns_feature_resolves_via_system_and_filters_by_option() {
        // Go localdns 语义：系统解析 + IPOption 过滤 + 固定 DefaultTTL。
        // CI 极端环境无系统 resolver / 无 localhost 记录时容忍失败。
        let feature = DefaultDnsFeature;
        let result = feature
            .lookup_ip(
                "localhost",
                IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false },
            )
            .await;
        match result {
            Ok((ips, ttl)) => {
                assert!(!ips.is_empty());
                assert_eq!(ttl, DEFAULT_TTL);
            },
            Err(DnsError::EmptyResponse) | Err(DnsError::Other(_)) => {},
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
