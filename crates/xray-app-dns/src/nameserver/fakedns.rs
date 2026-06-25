//! FakeDNS server：实现 `Server` trait，委托给 `FakeDnsEngine`。
//!
//! 对应 Go `app/dns/nameserver_fakedns.go`。

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use crate::config::{to_net_ip, IpOption};
use crate::error::DnsError;
use crate::fakedns::{Holder, HolderMulti};
use crate::nameserver::Server;
use xray_common::net::address::Address;

/// FakeDNS 引擎抽象。对应 Go `features/dns.FakeDNSEngine` 接口。
///
/// `Holder` 与 `HolderMulti` 都实现此 trait（对应 Go `FakeDNSEngineRev0` 子接口）。
pub trait FakeDnsEngine: Send + Sync {
    /// 为域名生成 Fake IP（不带 v4/v6 过滤）。
    fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr>;

    /// 为域名生成 Fake IP，按 v4/v6 过滤。
    fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr>;

    /// 反查域名。
    fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String>;

    /// IP 是否在池中。
    fn is_ip_in_pool(&self, ip: IpAddr) -> bool;
}

impl FakeDnsEngine for Holder {
    fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        Holder::get_fake_ip_for_domain(self, domain)
    }
    fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
        Holder::get_fake_ip_for_domain_3(self, domain, ipv4, ipv6)
    }
    fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String> {
        Holder::get_domain_from_fake_dns(self, ip)
    }
    fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        Holder::is_ip_in_pool(self, ip)
    }
}

impl FakeDnsEngine for HolderMulti {
    fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        HolderMulti::get_fake_ip_for_domain(self, domain)
    }
    fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
        HolderMulti::get_fake_ip_for_domain_3(self, domain, ipv4, ipv6)
    }
    fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String> {
        HolderMulti::get_domain_from_fake_dns(self, ip)
    }
    fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        HolderMulti::is_ip_in_pool(self, ip)
    }
}

/// FakeDNS 名称服务器。对应 Go `FakeDNSServer`。
pub struct FakeDnsServer<E: FakeDnsEngine> {
    engine: E,
}

impl<E: FakeDnsEngine> FakeDnsServer<E> {
    /// 构造。对应 Go `NewFakeDNSServer`。
    #[must_use]
    pub fn new(engine: E) -> Self {
        Self { engine }
    }
}

impl<E: FakeDnsEngine> Server for FakeDnsServer<E> {
    fn name(&self) -> &str {
        "FakeDNS"
    }

    fn is_disable_cache(&self) -> bool {
        true
    }

    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        let engine = &self.engine;
        Box::pin(async move {
            // 优先用 _3 方法（支持 v4/v6 过滤，对应 Go FakeDNSEngineRev0 探测）。
            let raw = engine.get_fake_ip_for_domain_3(
                domain,
                option.ipv4_enable,
                option.ipv6_enable,
            );
            let addresses: Vec<Address> = raw
                .into_iter()
                .map(|ip| match ip {
                    IpAddr::V4(v) => Address::IPv4(v),
                    IpAddr::V6(v) => Address::IPv6(v),
                })
                .collect();
            let ips = to_net_ip(&addresses)?;
            if !ips.is_empty() {
                Ok((ips, 1)) // fakeIP ttl 是 1（与 Go 一致）
            } else {
                Err(DnsError::EmptyResponse)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedns::FakeDnsPool;
    use std::net::Ipv4Addr;

    #[test]
    fn name_and_cache_flag_match_go() {
        let holder = Holder::new_default().unwrap();
        let s = FakeDnsServer::new(holder);
        assert_eq!(s.name(), "FakeDNS");
        assert!(s.is_disable_cache());
    }

    #[tokio::test]
    async fn query_ip_returns_fake_ip_with_ttl_one() {
        let holder = Holder::new_default().unwrap();
        let s = FakeDnsServer::new(holder);
        let (ips, ttl) = s.query_ip("example.com", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 1);
    }

    #[tokio::test]
    async fn query_ip_filters_by_ip_option() {
        let holder = Holder::new_default().unwrap();
        let s = FakeDnsServer::new(holder);
        let v6_only = IpOption {
            ipv4_enable: false,
            ipv6_enable: true,
            fake_enable: false,
        };
        // holder 是 v4 池，v6 查询应返回空响应。
        match s.query_ip("example.com", v6_only).await {
            Err(DnsError::EmptyResponse) => {}
            other => panic!("expected EmptyResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn holder_multi_also_serves() {
        let multi = HolderMulti::new(vec![FakeDnsPool::default_v4()]).unwrap();
        let s = FakeDnsServer::new(multi);
        let (ips, _) = s.query_ip("x.com", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert!(matches!(ips[0], IpAddr::V4(_)));
    }

    #[test]
    fn fake_dns_engine_trait_implemented_for_holder_variants() {
        // 验证 trait object 可创建（编译期检查）。
        let h: Box<dyn FakeDnsEngine> = Box::new(Holder::new_default().unwrap());
        assert!(h.is_ip_in_pool(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))) == false);
    }
}
