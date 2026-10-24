//! Fake DNS：域名为虚拟 IP 池中的地址建立双向映射。对应 Go `app/dns/fakedns/`。
//!
//! 业务核心独立可测，依赖：
//! - `lru` crate 提供 LRU（Go `cache.Lru`）
//! - `ipnet` crate 提供 CIDR 解析（Go `net.IPNet`）
//!
//! **跳过范围**（IO 边界）：`init()` 全局 `RegisterConfig` —— 改由
//! [`set_shared_multi`] 显式注册共享引擎（见其文档）。

use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

use ipnet::IpNet;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
#[cfg(test)]
use xray_common::net::address::Address;

use crate::error::DnsError;

/// fakeDns app 注册的共享引擎槽（bd 9vu4）。
///
/// Go `nameserver.go:70-79` 经 `RequireFeatures` 取全局唯一 `FakeDNSEngine`，
/// DNS 名 server 与 dispatcher 嗅探共享同实例同池。xray-app-dns 不能反向依赖
/// xray-core，且 dns app 可能先于 fakeDns app 构建（config app 固定顺序），
/// 故经 crate 级共享槽在查询时惰性取用，而非构造期注入。
static SHARED_MULTI: LazyLock<RwLock<Option<Arc<HolderMulti>>>> =
    LazyLock::new(|| RwLock::new(None));

/// 注册/清除共享引擎。`fake_dns_factory`（xray-core）构建 `HolderMulti` 后
/// 以 `Some` 写入；重复调用以最后一次为准。测试传 `None` 清除。
pub fn set_shared_multi(holder: Option<Arc<HolderMulti>>) {
    *SHARED_MULTI.write() = holder;
}

/// 取共享引擎。fakeDns app 已配置时为 `Some`，否则 `None`（调用方走兼容路径）。
#[must_use]
pub fn shared_multi() -> Option<Arc<HolderMulti>> {
    SHARED_MULTI.read().clone()
}

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
        Self { ip_pool: "240.0.0.0/4".to_string(), lru_size: 65535 }
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
    ip_to_domain: HashMap<IpAddr, String>,
}

impl Holder {
    /// 仅以配置构造（未初始化，需调 `initialize`）。对应 Go `NewFakeDNSHolderConfigOnly`。
    #[must_use]
    pub fn with_config(conf: FakeDnsPool) -> Self {
        Self {
            inner: Mutex::new(HolderInner {
                domain_to_ip: LruCache::unbounded(),
                ip_to_domain: HashMap::new(),
            }),
            // 暂填一个占位 range，initialize() 才会真正设置。
            ip_range: "0.0.0.0/32".parse().expect("placeholder CIDR literal is valid"),
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
            return Err(DnsError::LruBiggerThanSubnet { lru: lru_size, rooms });
        }

        self.ip_range = ip_range;
        let mut inner = self.inner.lock();
        // ponytail: lru_size 为 0 时退回 1（Go 行为是 panic）。
        inner.domain_to_ip =
            LruCache::new(NonZeroUsize::new(lru_size).unwrap_or(NonZeroUsize::MIN));
        // 值→键反查索引与主表同步重建（池重建不得残留旧映射）。
        inner.ip_to_domain.clear();
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

        // 用时间戳映射到 IP（与 Go 一致）。Go fake.go:146-150：只有 rooms < 64 才把
        // 时间戳取模折进子网；rooms >= 64（如 fc00::/12 = 116）在 Go 里不取模——
        // Rust 侧 `1u64 << rooms` 在 rooms >= 64 时 debug panic / release 静默错移。
        let rooms = self.rooms();
        let mut ts = now_millis();
        if rooms < 64 {
            ts %= 1u64 << rooms;
        }
        let ip = acquire_slot(&self.ip_range, ts_to_ip(&self.ip_range, ts), |cand| {
            inner.ip_to_domain.contains_key(&cand)
        });
        // put 前已确认 domain 未占用（上方 get 早退），仅新键路径。
        // 用 `push` 而非 `put`：lru 0.18 的 put 淘汰时不回传被逐条目，
        // 拿不到 (k, v) 就无法同步摘除值→键索引（对齐 Go lru.Put 双表同临界区维护）。
        if let Some((_, evicted_ip)) = inner.domain_to_ip.push(domain.to_string(), ip) {
            inner.ip_to_domain.remove(&evicted_ip);
        }
        inner.ip_to_domain.insert(ip, domain.to_string());
        vec![ip]
    }

    /// 三参数版本（按 v4/v6 启用过滤）。对应 Go `GetFakeIPForDomain3`。
    pub fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
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
        // O(1) 值→键索引（Go cache.Lru.GetKeyFromValue 同款 valueToElement 面）。
        self.inner.lock().ip_to_domain.get(&ip).cloned()
    }

    /// 当前池类型（IPv4/IPv6）。
    #[must_use]
    pub fn is_v6_pool(&self) -> bool {
        matches!(self.ip_range, IpNet::V6(_))
    }

    /// 当前已缓存域名数。
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // len 语义为条目计数
    pub fn len(&self) -> usize {
        self.inner.lock().domain_to_ip.len()
    }

    /// 值→键反查索引条目数，与 `len()` 对账用（仅测试可见）。
    #[cfg(test)]
    fn reverse_index_len(&self) -> usize {
        self.inner.lock().ip_to_domain.len()
    }

    /// 子网地址位数。
    fn rooms(&self) -> u32 {
        subnet_rooms(&self.ip_range)
    }
}

/// 时间戳偏移生成 IP（对齐 Go `fake.go` 的 `bigIntIP = network + ts`）。
fn ts_to_ip(range: &IpNet, ts: u64) -> IpAddr {
    match range.network() {
        IpAddr::V4(v) => {
            let base = u32::from(v);
            let new = base.wrapping_add(ts as u32);
            IpAddr::V4(std::net::Ipv4Addr::from(new))
        },
        IpAddr::V6(v) => {
            let mut octets = v.octets();
            add_to_be_bytes(&mut octets, ts);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        },
    }
}

/// 池内 +1，越界回绕到子网基址（Go `if !ipRange.Contains(bigIntIP) { bigIntIP = network }`）。
fn next_ip_in_pool(range: &IpNet, ip: IpAddr) -> IpAddr {
    let incremented = match ip {
        IpAddr::V4(v) => IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v).wrapping_add(1))),
        IpAddr::V6(v) => {
            let mut octets = v.octets();
            add_to_be_bytes(&mut octets, 1);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        },
    };
    if range.contains(&incremented) { incremented } else { range.network() }
}

/// 从 `start` 起找第一个未占用槽位。Go `fake.go:152-165` 同款：**每轮顶部查占用**，
/// 越界回绕到子网基址后继续查（旧实现在回绕处直接 break，会返回已被占用的地址）。
///
/// 不会死循环：`initialize` 保证 `lru_size < 2^rooms`，占用数恒小于池容量。
fn acquire_slot(range: &IpNet, start: IpAddr, occupied: impl Fn(IpAddr) -> bool) -> IpAddr {
    let mut ip = start;
    while occupied(ip) {
        let next = next_ip_in_pool(range, ip);
        debug_assert_ne!(next, ip, "池容量必须大于占用数（initialize 已校验 lru < 2^rooms）");
        ip = next;
    }
    ip
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
    pub fn get_fake_ip_for_domain_3(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
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
    use std::net::Ipv4Addr;

    use super::*;

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
        let mut h =
            Holder::with_config(FakeDnsPool { ip_pool: "10.0.0.0/30".to_string(), lru_size: 16 });
        match h.initialize() {
            Err(DnsError::LruBiggerThanSubnet { lru: 16, rooms: 2 }) => {},
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
        assert_eq!(h.get_domain_from_fake_dns(ip).as_deref(), Some("example.com"));
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
        assert_eq!(multi.get_domain_from_fake_dns(ips[0]).as_deref(), Some("x.com"));
    }

    #[test]
    fn holder_multi_rejects_empty_pools() {
        match HolderMulti::new(Vec::new()) {
            Err(DnsError::InvalidFakeDnsSetting) => {},
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
        let h = Holder::with_config(FakeDnsPool { ip_pool: String::new(), lru_size: 0 });
        match h.start() {
            Err(DnsError::InvalidFakeDnsSetting) => {},
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

    #[test]
    fn reverse_lookup_round_trips_all_entries_and_index_accounting() {
        // 大池（rooms=28）：把「ts 回绕落到 network 且被占用」的退化相位
        // （skip-loop break 不查占用，先于本任务存在）压到统计上不可触发，
        // 保证断言不依赖墙钟相位。
        let mut h = Holder::with_config(FakeDnsPool {
            ip_pool: "240.0.0.0/4".to_string(),
            lru_size: 10_000,
        });
        h.initialize().unwrap();
        let domains: Vec<String> = (0..10_000).map(|i| format!("host{i}.example.com")).collect();
        let ips: Vec<IpAddr> = domains.iter().map(|d| h.get_fake_ip_for_domain(d)[0]).collect();
        assert_eq!(h.len(), 10_000);
        assert_eq!(h.reverse_index_len(), 10_000, "值→键索引必须与主表条数一致");
        for (d, ip) in domains.iter().zip(&ips) {
            assert_eq!(h.get_domain_from_fake_dns(*ip).as_deref(), Some(d.as_str()));
        }
    }

    #[test]
    fn recycled_entry_misses_reverse_lookup() {
        // 大池 + 容量 2：淘汰路径确定（第三个分配按 LRU 逐出 a.com），
        // 且 rooms=28 使回绕相位彩票统计上不可触发（见 10k 测试注释）。
        let mut h =
            Holder::with_config(FakeDnsPool { ip_pool: "240.0.0.0/4".to_string(), lru_size: 2 });
        h.initialize().unwrap();
        let recycled_ip = h.get_fake_ip_for_domain("a.com")[0];
        let b_ip = h.get_fake_ip_for_domain("b.com")[0];
        let _c_ip = h.get_fake_ip_for_domain("c.com")[0];
        assert_eq!(h.len(), 2);
        assert_eq!(h.reverse_index_len(), 2, "回收（LRU 淘汰）后索引必须同步摘除");
        assert_eq!(h.get_domain_from_fake_dns(recycled_ip), None, "回收后反查不命中");
        assert_eq!(h.get_domain_from_fake_dns(b_ip).as_deref(), Some("b.com"));
    }

    #[test]
    fn lru_hit_promotes_recency_so_eviction_skips_recent() {
        // 钉住淘汰序语义（Go cache.Lru 同款）：命中读提升 recency——
        // cap=2 时 a,b 入表后读 a，再入 c 必须逐 b（未被刷新的最旧项）而非 a。
        let mut h =
            Holder::with_config(FakeDnsPool { ip_pool: "240.0.0.0/4".to_string(), lru_size: 2 });
        h.initialize().unwrap();
        let a_ip = h.get_fake_ip_for_domain("a.com")[0];
        let b_ip = h.get_fake_ip_for_domain("b.com")[0];
        // 命中 a：返回同 IP 且 recency 提到最新。
        assert_eq!(h.get_fake_ip_for_domain("a.com")[0], a_ip);
        let c_ip = h.get_fake_ip_for_domain("c.com")[0];
        assert_eq!(h.len(), 2);
        assert_eq!(h.get_domain_from_fake_dns(a_ip).as_deref(), Some("a.com"), "命中刷新后 a 存活");
        assert_eq!(h.get_domain_from_fake_dns(b_ip), None, "未被刷新的 b 被逐");
        assert_eq!(h.get_domain_from_fake_dns(c_ip).as_deref(), Some("c.com"));
        assert_eq!(h.reverse_index_len(), 2, "反查索引与主表同步");
    }

    #[test]
    fn pool_rebuild_clears_reverse_index() {
        let mut h = Holder::new_default().unwrap();
        let old_ip = h.get_fake_ip_for_domain("example.com")[0];
        assert!(h.get_domain_from_fake_dns(old_ip).is_some());
        h.initialize().unwrap();
        assert_eq!(h.len(), 0);
        assert_eq!(h.reverse_index_len(), 0, "池重建后索引不得残留");
        assert_eq!(h.get_domain_from_fake_dns(old_ip), None);
        let new_ip = h.get_fake_ip_for_domain("example.com")[0];
        assert_eq!(h.get_domain_from_fake_dns(new_ip).as_deref(), Some("example.com"));
    }

    #[test]
    fn holder_multi_reverse_lookup_resolves_each_pool() {
        // 双 v4 池验证索引按 holder 隔离（v6 池分配路径存在先于本任务的
        // `1u64 << rooms` 溢出问题（rooms ≥ 64 时 debug panic），不在本票范围）。
        let multi = unwrap_multi(HolderMulti::new(vec![
            FakeDnsPool { ip_pool: "240.0.0.0/12".to_string(), lru_size: 64 },
            FakeDnsPool { ip_pool: "100.64.0.0/24".to_string(), lru_size: 64 },
        ]));
        let ips = multi.get_fake_ip_for_domain("x.com");
        assert_eq!(ips.len(), 2, "双池各出一个 fake IP");
        for ip in ips {
            assert_eq!(multi.get_domain_from_fake_dns(ip).as_deref(), Some("x.com"));
        }
    }

    /// bd 8s84：rooms >= 64 的 v6 池（fc00::/12 → rooms=116）分配不得溢出——
    /// 旧实现 `1u64 << rooms` debug panic / release 静默错移（shift mod 64）。
    #[test]
    fn v6_pool_with_rooms_ge_64_allocates_unique_in_pool() {
        let mut h =
            Holder::with_config(FakeDnsPool { ip_pool: "fc00::/12".to_string(), lru_size: 100 });
        h.initialize().unwrap();
        assert!(h.is_v6_pool());
        let mut seen = std::collections::HashSet::new();
        for i in 0..60 {
            let ip = h.get_fake_ip_for_domain(&format!("d{i}.example.com"))[0];
            assert!(ip.is_ipv6(), "v6 池必须产出 v6 地址");
            assert!(h.is_ip_in_pool(ip), "分配结果必须落在池内: {ip}");
            assert!(seen.insert(ip), "重复分配: {ip}");
        }
        assert_eq!(h.reverse_index_len(), 60);
    }

    /// bd xkpb：回绕到子网基址后必须继续查占用（Go fake.go:152-165 循环顶部查）。
    /// 旧实现在回绕处直接 break，会返回已被占用的基址。
    #[test]
    fn acquire_slot_skips_occupied_network_address_on_wrap() {
        let range: IpNet = "10.0.0.0/30".parse().unwrap();
        let occupied = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), // 子网基址（回绕目标）
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), // 起点
        ];
        let slot = acquire_slot(&range, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), |ip| {
            occupied.contains(&ip)
        });
        assert_eq!(
            slot,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "回绕过占用基址后必须落到 .1（不是已占用的 .0）"
        );
    }

    /// 池内 +1 越界即回绕基址（Go `!ipRange.Contains` 分支）。
    #[test]
    fn next_ip_in_pool_wraps_at_range_end() {
        let range: IpNet = "10.0.0.0/30".parse().unwrap();
        let from = |a: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, a));
        assert_eq!(next_ip_in_pool(&range, from(1)), from(2));
        assert_eq!(next_ip_in_pool(&range, from(3)), from(0), "/30 边界回绕到基址");
    }
}
