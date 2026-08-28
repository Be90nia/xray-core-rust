//! 本地系统 DNS nameserver。对应 Go `app/dns/nameserver_local.go`。
//!
//! 用 `hickory_resolver::TokioResolver` 读取系统 DNS 配置
//! （`/etc/resolv.conf` 或 Windows 注册表），实现 `Server` trait。

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use hickory_resolver::TokioResolver;

use crate::config::IpOption;
use crate::error::DnsError;
use crate::nameserver::Server;

/// 默认 TTL（Go `dns.DefaultTTL` = 300，features/dns/client.go:37）。
pub use xray_features::dns::DEFAULT_TTL;

/// 本地系统 DNS nameserver。对应 Go `LocalNameServer`。
///
/// 持有 `TokioResolver`（`Resolver<TokioRuntimeProvider>`），通过系统 DNS 配置解析域名。
pub struct LocalNameServer {
    resolver: TokioResolver,
}

impl LocalNameServer {
    /// 构造。读取系统 DNS 配置（`/etc/resolv.conf` / Windows 注册表）。
    ///
    /// 对应 Go `NewLocalNameServer`。
    ///
    /// # Errors
    /// - [`DnsError::SystemResolve`]：系统 DNS 配置读取或 resolver 构建失败。
    pub fn new() -> Result<Self, DnsError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| DnsError::SystemResolve(format!("read system config: {e}")))?
            .build()
            .map_err(|e| DnsError::SystemResolve(format!("build resolver: {e}")))?;
        Ok(Self { resolver })
    }
}

impl Server for LocalNameServer {
    fn name(&self) -> &str {
        "localhost"
    }

    fn is_disable_cache(&self) -> bool {
        true
    }

    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let lookup = self
                .resolver
                .lookup_ip(domain)
                .await
                .map_err(|e| DnsError::SystemResolve(format!("lookup_ip: {e}")))?;

            // 按 IpOption 过滤。
            let ips: Vec<IpAddr> = lookup
                .iter()
                .filter(|ip| match ip {
                    IpAddr::V4(_) => option.ipv4_enable,
                    IpAddr::V6(_) => option.ipv6_enable,
                })
                .collect();

            if ips.is_empty() {
                Err(DnsError::EmptyResponse)
            } else {
                Ok((ips, DEFAULT_TTL))
            }
        })
    }
}

/// 构造本地 nameserver。对应 Go `NewLocalNameServer`。
///
/// # Errors
/// - [`DnsError::SystemResolve`]：系统 DNS 配置读取失败。
pub fn new_local_name_server() -> Result<Box<dyn Server>, DnsError> {
    Ok(Box::new(LocalNameServer::new()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_returns_local_name_server() {
        let server = new_local_name_server();
        // CI 环境可能无系统 DNS 配置，仅验证类型正确。
        if let Ok(s) = server {
            assert_eq!(s.name(), "localhost");
            assert!(s.is_disable_cache());
        }
    }

    #[test]
    fn local_name_server_name_and_cache_flag() {
        if let Ok(s) = LocalNameServer::new() {
            assert_eq!(s.name(), "localhost");
            assert!(s.is_disable_cache());
        }
    }

    #[tokio::test]
    async fn query_ip_resolves_localhost() {
        if let Ok(s) = LocalNameServer::new() {
            // localhost 应在所有系统可解析。
            let result = s.query_ip("localhost.", IpOption::all()).await;
            match result {
                Ok((ips, ttl)) => {
                    assert!(!ips.is_empty());
                    assert_eq!(ttl, DEFAULT_TTL);
                }
                Err(DnsError::EmptyResponse) => {
                    // 极端环境：localhost 被过滤或无记录。
                }
                Err(DnsError::SystemResolve(_)) => {
                    // 网络/DNS 不可用。
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
    }

    #[tokio::test]
    async fn query_ip_filters_by_ip_option() {
        if let Ok(s) = LocalNameServer::new() {
            let v4_only = IpOption {
                ipv4_enable: true,
                ipv6_enable: false,
                fake_enable: false,
            };
            if let Ok((ips, _)) = s.query_ip("localhost.", v4_only).await {
                assert!(ips.iter().all(|ip| matches!(ip, IpAddr::V4(_))));
            }
        }
    }
}
