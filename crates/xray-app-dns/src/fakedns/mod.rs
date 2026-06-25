//! Fake DNS：域名为虚拟 IP 池中的地址建立双向映射。对应 Go `app/dns/fakedns/`。
//!
//! 业务核心独立可测，依赖：
//! - `lru` crate 提供 LRU（Go `cache.Lru`）
//! - `ipnet` crate 提供 CIDR 解析（Go `net.IPNet`）
//!
//! **跳过范围**（IO 边界）：`init()` 全局 `RegisterConfig` —— Rust 无副作用全局。

use std::net::IpAddr;

use ipnet::IpNet;
use lru::LruCache;
use parking_lot::Mutex;

#[cfg(test)]
use xray_common::net::address::Address;

use crate::error::DnsError;

/// Fake DNS 池配置。对应 Go proto `FakeDnsPool`。
#[derive(Debug, Clone)]
pub struct FakeDnsPool {
    /// CIDR 表示的 IP 池范围（例 `240.0.0.0/4`）。
    pub ip_pool: String,
    /// LRU 容量。
    pub lru_size: u64,
}

impl FakeDnsPool {
    /// 构造默认 IPv4 Fake DNS 池（`240.0.0.0/4`, 65535 条目）。
    ///
    /// 对应 Go `dns.FakeIPv4Pool`。
    #[must_use]
    pub fn default_v4() -> Self {
        Self {
            ip_pool: "240.0.0.0/4".to_string(),
            lru_size: 65535,
        }
    }
}

/// 单个 Fake DNS holder。对应 Go `Holder`。
pub struct Holder {
    inner: Mutex<HolderInner>,
    ip_range: IpNet,
    config: FakeDnsPool,
}

struct HolderInner {
    domain_to_ip: LruCache<String, IpAddr>,
}

impl Holder {
    /// 仅以配置构造（未初始化，需调 `initialize`）。对应 Go `NewFakeDNSHolderConfigOnly`。
    #[must_use]
    pub fn with_config(conf: FakeDnsPool) -> Self {
        Self {
            inner: Mutex::new(HolderInner {
                domain_to_ip: LruCache::unbounded(),
            }),
            // 暂填一个占位 range，initialize() 才会真正设置。
            ip_range: "0.0.0.0/32".parse().unwrap(),
            config: conf,
        }
    }

    /// 默认 IPv4 池构造。对应 Go `NewFakeDNSHolder`。
    pub fn new_default() -> Result<Self, DnsError> {
        let mut h = Self::with_config(FakeDnsPool::default_v4());
        h.initialize()?;
        Ok(h)
    }

    /// 初始化或重新初始化 IP 池与 LRU。对应 Go `(*Holder).initialize`。
    ///
    /// `lru_size` 受子网空间约束（`log2(lru_size) < rooms`）。
    pub fn initialize(&mut self) -> Result<(), DnsError> {
        self.initialize_with(self.config.ip_pool.clone(), self.config.lru_size as usize)
    }

    /// 用指定 CIDR + LRU 大小初始化。对应 Go `(*Holder).initialize(ipPoolCidr, lruSize)`。
    pub fn initialize_with(
        &mut self,
        ip_pool_cidr: String,
        lru_size: usize,
    ) -> Result<(), DnsError> {
        let ip_range: IpNet = ip_pool_cidr
            .parse()
            .map_err(|e: ipnet::AddrParseError| DnsError::InvalidFakeDnsCidr(e.to_string()))?;

        // 子网空间检查。
        let rooms = subnet_rooms(&ip_range);
        if rooms < u32::BITS && (lru_size as u64) >= (1u64 << rooms) {
            return Err(DnsError::LruBiggerThanSubnet {
                lru: lru_size,
                rooms,
            });
        }

        self.ip_range = ip_range;
        let mut inner = self.inner.lock();
        inner.domain_to_ip = LruCache::new(std::num::NonZeroUsize::new(lru_size).unwrap_or_else(|| {
            // ponytail: lru_size 为 0 时退回 1（Go 行为是 panic）。
            std::num::NonZeroUsize::new(1).unwrap()
        }));
        Ok(())
    }

    /// 启动 holder（Rust 端 noop，对应 Go `Start`）。
    pub fn start(&self) -> Result<(), DnsError> {
        if self.config.ip_pool.is_empty() || self.config.lru_size == 0 {
            return Err(DnsError::InvalidFakeDnsSetting);
        }
        Ok(())
    }

    /// 关闭（noop）。
    pub fn close(&self) {}

    /// 判断 IP 是否在池中。对应 Go `(*Holder).IsIPInIPPool`。
    #[must_use]
    pub fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        self.ip_range.contains(&ip)
    }

    /// 为域名生成一个 Fake IP（每次同域名返回同 IP）。对应 Go `GetFakeIPForDomain`。
    pub fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        let mut inner = self.inner.lock();
        if let Some(ip) = inner.domain_to_ip.get(domain) {
            return vec![*ip];
        }

        // 用时间戳映射到 IP（与 Go 一致）。
        let mut ts = now_millis() & ((1u64 << self.rooms()) - 1);
        let mut ip = self.ts_to_ip(ts);
        // 跳过已占用的 IP。
        while inner.domain_to_ip.iter().any(|(_, v)| *v == ip) {
            ts = ts.wrapping_add(1) & ((1u64 << self.rooms()) - 1);
            ip = self.ts_to_ip(ts);
            if ip == self.ip_range.network() {
                // 轮回一圈，跳出。
                break;
            }
        }
        inner.domain_to_ip.put(domain.to_string(), ip);
        vec![ip]
    }

    /// 三参数版本（按 v4/v6 启用过滤）。对应 Go `GetFakeIPForDomain3`。
    pub fn get_fake_ip_for_domain_3(
        &self,
        domain: &str,
        ipv4: bool,
        ipv6: bool,
    ) -> Vec<IpAddr> {
        let is_v6 = matches!(self.ip_range, IpNet::V6(_));
        if (is_v6 && ipv6) || (!is_v6 && ipv4) {
            self.get_fake_ip_for_domain(domain)
        } else {
            Vec::new()
        }
    }

    /// 反查：从 Fake IP 取域名。对应 Go `GetDomainFromFakeDNS`。
    ///
    /// 未找到返回空字符串。
    #[must_use]
    pub fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String> {
        if !self.is_ip_in_pool(ip) {
            return None;
        }
        let inner = self.inner.lock();
        inner
            .domain_to_ip
            .iter()
            .find(|(_, v)| **v == ip)
            .map(|(k, _)| k.clone())
    }

    /// 当前池类型（IPv4/IPv6）。
    #[must_use]
    pub fn is_v6_pool(&self) -> bool {
        matches!(self.ip_range, IpNet::V6(_))
    }

    /// 当前已缓存域名数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().domain_to_ip.len()
    }

    /// 子网地址位数。
    fn rooms(&self) -> u32 {
        subnet_rooms(&self.ip_range)
    }

    /// 时间戳偏移生成 IP。
    fn ts_to_ip(&self, ts: u64) -> IpAddr {
        match self.ip_range.network() {
            IpAddr::V4(v) => {
                let base = u32::from(v);
                let new = base.wrapping_add(ts as u32);
                IpAddr::V4(std::net::Ipv4Addr::from(new))
            }
            IpAddr::V6(v) => {
                let mut octets = v.octets();
                add_to_be_bytes(&mut octets, ts);
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
        }
    }
}

/// 多池 holder。对应 Go `HolderMulti`。
pub struct HolderMulti {
    holders: Vec<Holder>,
}

impl HolderMulti {
    /// 从多个 pool 配置构造。
    pub fn new(pools: Vec<FakeDnsPool>) -> Result<Self, DnsError> {
        if pools.is_empty() {
            return Err(DnsError::InvalidFakeDnsSetting);
        }
        let mut holders = Vec::with_capacity(pools.len());
        for p in pools {
            let mut h = Holder::with_config(p);
            h.initialize()?;
            holders.push(h);
        }
        Ok(Self { holders })
    }

    /// 任意池包含此 IP。
    #[must_use]
    pub fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        self.holders.iter().any(|h| h.is_ip_in_pool(ip))
    }

    /// 在所有适用池中查询。对应 Go `(*HolderMulti).GetFakeIPForDomain`。
    pub fn get_fake_ip_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        let mut all = Vec::new();
        for h in &self.holders {
            all.extend(h.get_fake_ip_for_domain(domain));
        }
        all
    }

    /// 按 v4/v6 过滤。
    pub fn get_fake_ip_for_domain_3(
        &self,
        domain: &str,
        ipv4: bool,
        ipv6: bool,
    ) -> Vec<IpAddr> {
        let mut all = Vec::new();
        for h in &self.holders {
            all.extend(h.get_fake_ip_for_domain_3(domain, ipv4, ipv6));
        }
        all
    }

    /// 反查域名。
    #[must_use]
    pub fn get_domain_from_fake_dns(&self, ip: IpAddr) -> Option<String> {
        for h in &self.holders {
            if let Some(d) = h.get_domain_from_fake_dns(ip) {
                return Some(d);
            }
        }
        None
    }
}

/// 将 `u64` 加到大端字节序列上（IPv6 用）。
fn add_to_be_bytes(b: &mut [u8; 16], add: u64) {
    let mut carry = add;
    for i in (0..8).rev() {
        let pos = 8 + i; // 低 8 字节
        let cur = u64::from(b[pos]);
        let sum = cur.wrapping_add(carry & 0xFF);
        b[pos] = sum as u8;
        carry = (carry >> 8).wrapping_add(sum >> 8);
    }
}

/// 子网可寻址位数（bits - prefix_len）。
fn subnet_rooms(net: &IpNet) -> u32 {
    let prefix = u32::from(net.prefix_len());
    let bits = match net {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    };
    bits - prefix
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
/// 将 `Address` 转为 `IpAddr`，域名返回 `None`。
fn address_to_ip(addr: &Address) -> Option<IpAddr> {
    match addr {
        Address::IPv4(v) => Some(IpAddr::V4(*v)),
        Address::IPv6(v) => Some(IpAddr::V6(*v)),
        Address::Domain(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn holder_initializes_with_v4_pool() {
        let mut h = Holder::with_config(FakeDnsPool::default_v4());
        h.initialize().unwrap();
        assert!(!h.is_v6_pool());
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn holder_rejects_lru_bigger_than_subnet() {
        // /30 只有 4 个地址（2 bit），LRU 16 太大。
        let mut h = Holder::with_config(FakeDnsPool {
            ip_pool: "10.0.0.0/30".to_string(),
            lru_size: 16,
        });
        match h.initialize() {
            Err(DnsError::LruBiggerThanSubnet { lru: 16, rooms: 2 }) => {}
            other => panic!("expected LruBiggerThanSubnet, got {other:?}"),
        }
    }

    #[test]
    fn get_fake_ip_returns_same_ip_for_same_domain() {
        let h = Holder::new_default().unwrap();
        let ip1 = h.get_fake_ip_for_domain("example.com");
        let ip2 = h.get_fake_ip_for_domain("example.com");
        assert_eq!(ip1, ip2);
        assert_eq!(ip1.len(), 1);
    }

    #[test]
    fn get_fake_ip_returns_different_ip_for_different_domain() {
        let h = Holder::new_default().unwrap();
        let ip1 = h.get_fake_ip_for_domain("a.com");
        let ip2 = h.get_fake_ip_for_domain("b.com");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn is_ip_in_pool_correct_for_v4_range() {
        let h = Holder::new_default().unwrap();
        let in_pool = h.get_fake_ip_for_domain("x.com")[0];
        assert!(h.is_ip_in_pool(in_pool));
        assert!(!h.is_ip_in_pool(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn get_domain_returns_original_domain_for_known_ip() {
        let h = Holder::new_default().unwrap();
        let ip = h.get_fake_ip_for_domain("example.com")[0];
        assert_eq!(
            h.get_domain_from_fake_dns(ip).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn get_domain_returns_none_for_unknown_ip() {
        let h = Holder::new_default().unwrap();
        assert_eq!(h.get_domain_from_fake_dns(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
    }

    fn unwrap_multi(r: Result<HolderMulti, DnsError>) -> HolderMulti {
        match r {
            Ok(m) => m,
            Err(e) => panic!("expected Ok HolderMulti, got {e:?}"),
        }
    }

    #[test]
    fn holder_multi_aggregates_pools() {
        let multi = unwrap_multi(HolderMulti::new(vec![FakeDnsPool::default_v4()]));
        let ips = multi.get_fake_ip_for_domain("x.com");
        assert_eq!(ips.len(), 1);
        assert!(multi.is_ip_in_pool(ips[0]));
        assert_eq!(
            multi.get_domain_from_fake_dns(ips[0]).as_deref(),
            Some("x.com")
        );
    }

    #[test]
    fn holder_multi_rejects_empty_pools() {
        match HolderMulti::new(Vec::new()) {
            Err(DnsError::InvalidFakeDnsSetting) => {}
            Err(e) => panic!("expected InvalidFakeDnsSetting, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn holder_multi_filters_by_ip_version_when_only_v4_pool() {
        let multi = unwrap_multi(HolderMulti::new(vec![FakeDnsPool::default_v4()]));
        let v4_only = multi.get_fake_ip_for_domain_3("x.com", true, false);
        assert_eq!(v4_only.len(), 1);
        let v6_only = multi.get_fake_ip_for_domain_3("x.com", false, true);
        assert!(v6_only.is_empty(), "v6 查询应返回空，因为仅有 v4 池");
    }

    #[test]
    fn start_rejects_empty_config() {
        let h = Holder::with_config(FakeDnsPool {
            ip_pool: String::new(),
            lru_size: 0,
        });
        match h.start() {
            Err(DnsError::InvalidFakeDnsSetting) => {}
            other => panic!("expected InvalidFakeDnsSetting, got {other:?}"),
        }
    }

    #[test]
    fn address_to_ip_helper() {
        assert_eq!(
            address_to_ip(&Address::IPv4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(address_to_ip(&Address::Domain("x".to_string())), None);
    }
}
