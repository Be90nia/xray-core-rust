//! FakeDNS server：实现 `Server` trait，委托给 `FakeDnsEngine`。
//!
//! 对应 Go `app/dns/nameserver_fakedns.go`。

use std::{future::Future, net::IpAddr, pin::Pin};

use xray_common::net::address::Address;

use crate::{
    config::{IpOption, to_net_ip},
    error::DnsError,
    fakedns::{Holder, HolderMulti},
    nameserver::Server,
};

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

/// DNS 侧共享引擎（bd 9vu4）。对应 Go `nameserver.go:70-79` 经
/// `RequireFeatures` 取到的全局唯一 `FakeDNSEngine`。
///
/// 查询时优先取 fakeDns app 经 [`crate::fakedns::set_shared_multi`] 注册的
/// [`HolderMulti`]（与 dispatcher 嗅探同引擎同池）；无 fakeDns app 配置时
/// 退回 `new_default` 兼容实例，保持旧行为。
pub struct SharedFakeDnsEngine {
    fallback: Holder,
}

impl SharedFakeDnsEngine {
    /// 以兼容兜底实例构造。
    #[must_use]
    pub fn new(fallback: Holder) -> Self {
        Self { fallback }
    }
}

impl FakeDnsEngine for SharedFakeDnsEngine {
    fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        match crate::fakedns::shared_multi() {
            Some(m) => HolderMulti::get_fake_ip_for_domain(&m, domain),
            None => Holder::get_fake_ip_for_domain(&self.fallback, domain),
        }
    }

    fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
        match crate::fakedns::shared_multi() {
            Some(m) => HolderMulti::get_fake_ip_for_domain_3(&m, domain, ipv4, ipv6),
            None => Holder::get_fake_ip_for_domain_3(&self.fallback, domain, ipv4, ipv6),
        }
    }

    fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String> {
        match crate::fakedns::shared_multi() {
            Some(m) => HolderMulti::get_domain_from_fake_dns(&m, ip),
            None => Holder::get_domain_from_fake_dns(&self.fallback, ip),
        }
    }

    fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        match crate::fakedns::shared_multi() {
            Some(m) => HolderMulti::is_ip_in_pool(&m, ip),
            None => Holder::is_ip_in_pool(&self.fallback, ip),
        }
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
            let raw =
                engine.get_fake_ip_for_domain_3(domain, option.ipv4_enable, option.ipv6_enable);
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
    use std::net::Ipv4Addr;

    use super::*;
    use crate::fakedns::FakeDnsPool;

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
        let v6_only = IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false };
        // holder 是 v4 池，v6 查询应返回空响应。
        match s.query_ip("example.com", v6_only).await {
            Err(DnsError::EmptyResponse) => {},
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

    /// 共享槽是进程级全局：两条 e2e 须串行（parking_lot TEST_LOCK 惯例）。
    static SLOT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// bd 9vu4 验收：DNS 侧 fakedns server 发的 fake IP 来自共享池
    /// （fakeDns app 配置的 198.18.0.0/15，而非 new_default 的 240.0.0.0/4），
    /// 且能被共享引擎（dispatcher 同引擎）反查命中。
    #[tokio::test]
    async fn factory_serves_shared_engine_and_reverse_resolves() {
        let _slot_guard = SLOT_LOCK.lock();
        let multi = std::sync::Arc::new(
            HolderMulti::new(vec![FakeDnsPool {
                ip_pool: "198.18.0.0/15".to_string(),
                lru_size: 65535,
            }])
            .unwrap(),
        );
        crate::fakedns::set_shared_multi(Some(multi.clone()));

        let (server, _) =
            crate::nameserver::new_server_with_config("fakedns", Default::default()).unwrap();
        let (ips, ttl) = server.query_ip("example.com", IpOption::all()).await.unwrap();

        assert_eq!(ttl, 1);
        assert!(
            multi.is_ip_in_pool(ips[0]),
            "must come from the shared 198.18.0.0/15 pool, got {ips:?}"
        );
        // dispatcher 侧同引擎反查命中。
        assert_eq!(
            multi.get_domain_from_fake_dns(ips[0]).as_deref(),
            Some("example.com"),
            "shared pool must reverse-resolve the DNS-side fake IP"
        );

        crate::fakedns::set_shared_multi(None);
    }

    /// 无 fakeDns app（共享槽空）时保持 `new_default` 兼容行为。
    #[tokio::test]
    async fn factory_falls_back_to_new_default_without_shared_engine() {
        let _slot_guard = SLOT_LOCK.lock();
        crate::fakedns::set_shared_multi(None);
        let (server, _) =
            crate::nameserver::new_server_with_config("fakedns", Default::default()).unwrap();
        let (ips, _) = server.query_ip("example.com", IpOption::all()).await.unwrap();
        assert!(
            matches!(ips[0], IpAddr::V4(v) if (240..=255).contains(&v.octets()[0])),
            "fallback must serve the default 240.0.0.0/4 pool, got {ips:?}"
        );
    }
}
