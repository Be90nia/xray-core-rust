//! IP matcher
//!
//! 对应 Go 版本 `common/geodata/ip_matcher`，提供 IP 地址匹配功能。

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;
use xray_frame::HotSlot;

use crate::{
    loader::{GeoDataLoader, LoaderError},
    pb::{self, Cidr, GeoIpRule, IpRule},
    weak_cache::WeakCacheMap,
};

// ── 常量 ────────────────────────────────────────────────────────

/// IPv4 无条目标记
const IPV4_NO_ENTRIES: u8 = 0xff;
/// IPv6 无条目标记
const IPV6_NO_ENTRIES: u8 = 0xff;
/// IPv4 /0 全匹配标记
const IPV4_MATCH_ALL: u8 = 0xfe;
/// IPv6 /0 全匹配标记
const IPV6_MATCH_ALL: u8 = 0xfe;

// ── IPMatcher trait ─────────────────────────────────────────────

/// IP 匹配器 trait。
///
/// 对应 Go 版本 `IPMatcher` 接口，提供单 IP 匹配、批量匹配和过滤功能。
pub trait IPMatcher: Send + Sync {
    /// 判断单个 IP 地址是否匹配。
    #[must_use]
    fn match_ip(&self, ip: IpAddr) -> bool;

    /// 判断 IP 列表中是否有任意一个匹配。
    #[must_use]
    fn any_match(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() {
            return false;
        }
        if ips.len() == 1 {
            return self.match_ip(ips[0]);
        }
        ips.iter().any(|ip| self.match_ip(*ip))
    }

    /// 判断 IP 列表中是否全部匹配。
    #[must_use]
    fn matches(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() {
            return false;
        }
        if ips.len() == 1 {
            return self.match_ip(ips[0]);
        }
        ips.iter().all(|ip| self.match_ip(*ip))
    }

    /// 过滤出匹配的 IP 地址列表。
    #[must_use]
    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        if ips.is_empty() {
            return Vec::new();
        }
        ips.iter().filter(|ip| self.match_ip(**ip)).copied().collect()
    }

    /// 获取反向匹配标志。
    #[must_use]
    fn reverse(&self) -> bool;

    /// 设置反向匹配标志。
    fn set_reverse(&mut self, reverse: bool);

    /// 切换反向匹配标志。
    fn toggle_reverse(&mut self) {
        self.set_reverse(!self.reverse());
    }
}

// ── CIDR 范围（手动实现，不依赖 ipnet）────────────────────────

/// IPv4 CIDR 范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    addr: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        Self { addr: u32::from_be_bytes(addr.octets()), prefix }
    }

    // 生产路径走 range() 区间匹配；contains 仅测试断言锚点用。
    #[cfg(test)]
    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let ip_val = u32::from_be_bytes(ip.octets());
        let mask = if self.prefix == 32 { !0u32 } else { !0u32 << (32 - self.prefix) };
        (ip_val & mask) == (self.addr & mask)
    }

    /// CIDR 覆盖的 inclusive 地址区间 [start, end]。
    fn range(&self) -> (u32, u32) {
        if self.prefix == 0 {
            return (0, u32::MAX);
        }
        let mask = if self.prefix >= 32 { !0u32 } else { !0u32 << (32 - self.prefix) };
        let base = self.addr & mask;
        (base, base | !mask)
    }
}

/// IPv6 CIDR 范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6Cidr {
    addr: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    fn new(addr: Ipv6Addr, prefix: u8) -> Self {
        let prefix = prefix.min(128);
        Self { addr: u128::from_be_bytes(addr.octets()), prefix }
    }

    // 生产路径走 range() 区间匹配；contains 仅测试断言锚点用。
    #[cfg(test)]
    fn contains(&self, ip: Ipv6Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let ip_val = u128::from_be_bytes(ip.octets());
        let mask = if self.prefix == 128 { !0u128 } else { !0u128 << (128 - self.prefix) };
        (ip_val & mask) == (self.addr & mask)
    }

    /// CIDR 覆盖的 inclusive 地址区间 [start, end]。
    fn range(&self) -> (u128, u128) {
        if self.prefix == 0 {
            return (0, u128::MAX);
        }
        let mask = if self.prefix >= 128 { !0u128 } else { !0u128 << (128 - self.prefix) };
        let base = self.addr & mask;
        (base, base | !mask)
    }
}

// ── IPSet ───────────────────────────────────────────────────────

/// 基于 CIDR 前缀列表的 IP 集合。
///
/// 内部存储为排序合并不相交的地址区间，`contains` 走二分查找
/// （O(log n)，GeoIP 千级 CIDR 下替代线性扫描）。
///
/// `max4`/`max6` 记录最大前缀位数，用于启发式优化判断：
/// - `0xff` 表示无条目
/// - `0xfe` 表示包含 /0（匹配所有）
pub struct IPSet {
    ipv4_ranges: Vec<(u32, u32)>,
    ipv6_ranges: Vec<(u128, u128)>,
    max4: u8,
    max6: u8,
}

/// 合并排序区间中的重叠项，输出升序不相交区间。
/// （相邻不合并：不影响二分正确性，只少一次边界运算。）
fn merge_sorted_ranges<T: Copy + Ord>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match merged.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            },
            _ => merged.push((s, e)),
        }
    }
    merged
}

impl IPSet {
    /// 创建空的 IPSet。
    pub fn new() -> Self {
        Self {
            ipv4_ranges: Vec::new(),
            ipv6_ranges: Vec::new(),
            max4: IPV4_NO_ENTRIES,
            max6: IPV6_NO_ENTRIES,
        }
    }

    /// 从 CIDR 列表构建 IPSet。
    pub fn from_cidrs(cidrs: &[Cidr]) -> Self {
        let mut ipv4_ranges = Vec::new();
        let mut ipv6_ranges = Vec::new();
        let mut max4: u8 = IPV4_NO_ENTRIES;
        let mut max6: u8 = IPV6_NO_ENTRIES;

        for cidr in cidrs {
            if cidr.ip.len() == 4 {
                let addr = Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
                let prefix = cidr.prefix.min(32) as u8;
                let net = Ipv4Cidr::new(addr, prefix);

                if prefix == 0 {
                    max4 = IPV4_MATCH_ALL;
                } else if max4 != IPV4_MATCH_ALL && (prefix > max4 || max4 == IPV4_NO_ENTRIES) {
                    // 存**最细**前缀（Go BuildIPSet：`b > max4`，ip_matcher.go:922）。
                    // 启发式桶门控要求全部前缀 ≤24，即最细 ≤24；存最小（最粗）
                    // 会让含 /32 的 geo 集合误开桶记忆化（bd 5dzf）。
                    max4 = prefix;
                }
                ipv4_ranges.push(net.range());
            } else if cidr.ip.len() == 16 {
                let bytes: [u8; 16] = cidr.ip[..16].try_into().unwrap_or([0; 16]);
                let addr = Ipv6Addr::from(bytes);
                let prefix = cidr.prefix.min(128) as u8;
                let net = Ipv6Cidr::new(addr, prefix);

                if prefix == 0 {
                    max6 = IPV6_MATCH_ALL;
                } else if max6 != IPV6_MATCH_ALL && (prefix > max6 || max6 == IPV6_NO_ENTRIES) {
                    max6 = prefix;
                }
                ipv6_ranges.push(net.range());
            }
        }

        Self {
            ipv4_ranges: merge_sorted_ranges(ipv4_ranges),
            ipv6_ranges: merge_sorted_ranges(ipv6_ranges),
            max4,
            max6,
        }
    }

    /// 判断 IPv4 地址是否在集合内。
    #[must_use]
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        if self.max4 == IPV4_NO_ENTRIES {
            return false;
        }
        if self.max4 == IPV4_MATCH_ALL {
            return true;
        }
        let v = u32::from_be_bytes(ip.octets());
        let idx = self.ipv4_ranges.partition_point(|&(_, e)| e < v);
        self.ipv4_ranges.get(idx).is_some_and(|&(s, _)| s <= v)
    }

    /// 判断 IPv6 地址是否在集合内。
    #[must_use]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        if self.max6 == IPV6_NO_ENTRIES {
            return false;
        }
        if self.max6 == IPV6_MATCH_ALL {
            return true;
        }
        let v = u128::from_be_bytes(ip.octets());
        let idx = self.ipv6_ranges.partition_point(|&(_, e)| e < v);
        self.ipv6_ranges.get(idx).is_some_and(|&(s, _)| s <= v)
    }

    /// 判断 IP 地址是否在集合内。
    ///
    /// v4-mapped 的 16 字节地址（`::ffff:1.2.3.4`，双栈监听端的常见形态）先归一
    /// 成 4 字节再查 v4 表——Go `matchAddr` 同样先 `To4()`
    /// （common/geodata/ip_matcher.go:195）。
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }

    /// IPv4 最大前缀位数。
    #[must_use]
    pub fn max4(&self) -> u8 {
        self.max4
    }

    /// IPv6 最大前缀位数。
    #[must_use]
    pub fn max6(&self) -> u8 {
        self.max6
    }

    /// IPv4 条目是否为空。
    #[must_use]
    pub fn is_empty_v4(&self) -> bool {
        self.max4 == IPV4_NO_ENTRIES
    }

    /// IPv6 条目是否为空。
    #[must_use]
    pub fn is_empty_v6(&self) -> bool {
        self.max6 == IPV6_NO_ENTRIES
    }
}

impl Default for IPSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for IPSet {
    fn clone(&self) -> Self {
        Self {
            ipv4_ranges: self.ipv4_ranges.clone(),
            ipv6_ranges: self.ipv6_ranges.clone(),
            max4: self.max4,
            max6: self.max6,
        }
    }
}

// ── 启发式桶键 ──────────────────────────────────────────────────

/// 计算 IPv4 地址的 /24 桶键。
fn prefix_key_v4(ip: Ipv4Addr) -> [u8; 9] {
    let o = ip.octets();
    [4, o[0], o[1], o[2], 0, 0, 0, 0, 0]
}

/// 计算 IPv6 地址的 /64 桶键。
fn prefix_key_v6(ip: Ipv6Addr) -> [u8; 9] {
    let o = ip.octets();
    [6, o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
}

/// 计算 IP 地址的桶键。
///
/// Go `prefixKeyFromIP` 先 `To4()`（ip_matcher.go:210）——v4-mapped 归一到 v4 桶，
/// 否则归一后的 v4 匹配会落到 v6 桶键上，记忆化跨族串味。
fn prefix_key(ip: IpAddr) -> [u8; 9] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => prefix_key_v4(v4),
        IpAddr::V6(v6) => prefix_key_v6(v6),
    }
}

// ── HeuristicIPMatcher ──────────────────────────────────────────

/// 带启发式桶优化的 IP 匹配器。
pub struct HeuristicIPMatcher {
    /// 共享持有：geoip 组经注册表弱缓存去重，多个 matcher 共用同一 IPSet。
    ipset: Arc<IPSet>,
    reverse: bool,
}

impl HeuristicIPMatcher {
    /// 从 IPSet 创建启发式匹配器。
    pub fn new(ipset: IPSet) -> Self {
        Self::from_shared(Arc::new(ipset))
    }

    /// 从共享 IPSet 创建（注册表缓存命中时零拷贝，Go `HeuristicIPMatcher{ipset}`）。
    pub fn from_shared(ipset: Arc<IPSet>) -> Self {
        Self { ipset, reverse: false }
    }

    /// 从 CIDR 列表创建启发式匹配器。
    pub fn from_cidrs(cidrs: &[Cidr]) -> Self {
        Self::new(IPSet::from_cidrs(cidrs))
    }

    /// 内部匹配实现：Contains XOR reverse。
    ///
    /// v4-mapped 的 16 字节地址（`::ffff:1.2.3.4`，双栈监听端形态）归一到 v4 表：
    /// Go `netipx.FromStdIP` 之后 `ipx.Is4()` 对 v4-mapped 为真（ip_matcher.go:195），
    /// 不归一会去查 v6 表而漏命中 v4 规则。V4 输入路径与归一前逐字相同（零额外成本）。
    fn match_addr(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.match_v4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => self.match_v4(v4),
                None => self.match_v6(v6),
            },
        }
    }

    fn match_v4(&self, v4: Ipv4Addr) -> bool {
        if self.ipset.max4() == IPV4_NO_ENTRIES {
            return false;
        }
        self.ipset.contains_v4(v4) != self.reverse
    }

    fn match_v6(&self, v6: Ipv6Addr) -> bool {
        if self.ipset.max6() == IPV6_NO_ENTRIES {
            return false;
        }
        self.ipset.contains_v6(v6) != self.reverse
    }

    // 桶记忆化正确性前提：集合内全部前缀 ≤ 桶宽（/24、/64）。max4/max6 存
    // 最细前缀（from_cidrs），NO_ENTRIES(0xff)/MATCH_ALL(0xfe) 均 >24/64 自然
    // 排除——与 Go AnyMatch 门控 `m.ipset.max4 <= 24` 逐字对齐（ip_matcher.go:149）。
    fn heuristic_v4(&self) -> bool {
        self.ipset.max4() <= 24
    }

    fn heuristic_v6(&self) -> bool {
        self.ipset.max6() <= 64
    }

    /// 获取内部 IPSet 的引用。
    #[must_use]
    pub fn ipset(&self) -> &IPSet {
        &self.ipset
    }
}

impl IPMatcher for HeuristicIPMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.match_addr(ip)
    }

    fn any_match(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() {
            return false;
        }
        if ips.len() == 1 {
            return self.match_ip(ips[0]);
        }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter().any(|ip| self.match_ip(*ip));
        }

        let mut seen: HashMap<[u8; 9], bool> = HashMap::new();
        for ip in ips {
            let key = prefix_key(*ip);
            // 桶族由**归一后**的键族决定（Go `key[0] == 4 && heur4`，ip_matcher.go:127）。
            let use_heur = if key[0] == 4 { heur4 } else { heur6 };

            if use_heur {
                if let Some(&r) = seen.get(&key) {
                    if r {
                        return true;
                    }
                    continue;
                }
            }
            let r = self.match_ip(*ip);
            if use_heur {
                seen.insert(key, r);
            }
            if r {
                return true;
            }
        }
        false
    }

    fn matches(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() {
            return false;
        }
        if ips.len() == 1 {
            return self.match_ip(ips[0]);
        }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter().all(|ip| self.match_ip(*ip));
        }

        let mut buckets: HashMap<[u8; 9], bool> = HashMap::new();
        for ip in ips {
            let key = prefix_key(*ip);
            // 桶族由**归一后**的键族决定（Go `key[0] == 4 && heur4`，ip_matcher.go:127）。
            let use_heur = if key[0] == 4 { heur4 } else { heur6 };

            if use_heur {
                if let Some(&r) = buckets.get(&key) {
                    if !r {
                        return false;
                    }
                    continue;
                }
            }
            let r = self.match_ip(*ip);
            if use_heur {
                buckets.insert(key, r);
            }
            if !r {
                return false;
            }
        }
        true
    }

    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        if ips.is_empty() {
            return Vec::new();
        }
        if ips.len() == 1 {
            return if self.match_ip(ips[0]) { vec![ips[0]] } else { Vec::new() };
        }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter().filter(|ip| self.match_ip(**ip)).copied().collect();
        }

        let mut buckets: HashMap<[u8; 9], bool> = HashMap::new();
        let mut result = Vec::new();
        for ip in ips {
            let key = prefix_key(*ip);
            // 桶族由**归一后**的键族决定（Go `key[0] == 4 && heur4`，ip_matcher.go:127）。
            let use_heur = if key[0] == 4 { heur4 } else { heur6 };

            if use_heur {
                let matched = *buckets.entry(key).or_insert_with(|| self.match_ip(*ip));
                if matched {
                    result.push(*ip);
                }
            } else if self.match_ip(*ip) {
                result.push(*ip);
            }
        }
        result
    }

    fn reverse(&self) -> bool {
        self.reverse
    }

    fn set_reverse(&mut self, reverse: bool) {
        self.reverse = reverse;
    }
}

// ── GeneralMultiIPMatcher ───────────────────────────────────────

/// 通用多 IP 匹配器。
pub struct GeneralMultiIPMatcher {
    matchers: Vec<Box<dyn IPMatcher>>,
}

impl GeneralMultiIPMatcher {
    /// 从匹配器列表创建。
    pub fn new(matchers: Vec<Box<dyn IPMatcher>>) -> Self {
        Self { matchers }
    }
}

impl IPMatcher for GeneralMultiIPMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.matchers.iter().any(|m| m.match_ip(ip))
    }

    fn any_match(&self, ips: &[IpAddr]) -> bool {
        self.matchers.iter().any(|m| m.any_match(ips))
    }

    fn matches(&self, ips: &[IpAddr]) -> bool {
        self.matchers.iter().all(|m| m.matches(ips))
    }

    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        ips.iter().filter(|ip| self.match_ip(**ip)).copied().collect()
    }

    fn reverse(&self) -> bool {
        false
    }

    fn set_reverse(&mut self, _reverse: bool) {}
}

// ── HeuristicMultiIPMatcher ─────────────────────────────────────

/// 启发式多 IP 匹配器。
pub struct HeuristicMultiIPMatcher {
    matchers: Vec<HeuristicIPMatcher>,
}

impl HeuristicMultiIPMatcher {
    /// 从匹配器列表创建。
    pub fn new(matchers: Vec<HeuristicIPMatcher>) -> Self {
        Self { matchers }
    }
}

impl IPMatcher for HeuristicMultiIPMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.matchers.iter().any(|m| m.match_ip(ip))
    }

    fn any_match(&self, ips: &[IpAddr]) -> bool {
        self.matchers.iter().any(|m| m.any_match(ips))
    }

    fn matches(&self, ips: &[IpAddr]) -> bool {
        self.matchers.iter().all(|m| m.matches(ips))
    }

    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        ips.iter().filter(|ip| self.match_ip(**ip)).copied().collect()
    }

    fn reverse(&self) -> bool {
        false
    }

    fn set_reverse(&mut self, _reverse: bool) {}
}

// ── IPSetFactory ────────────────────────────────────────────────

/// IPSet 缓存工厂。
///
/// 对应 Go `IPSetFactory`（`common/geodata/ip_matcher.go:806-867`）：把「同极性
/// geoip 规则的 tag 组」解析成一个 IPSet 并按组 key 弱缓存——多个消费方构造同
/// 一组规则时共享同一个 `Arc<IPSet>`（幂等，和 Go 的 `WeakCacheMap` 同构）。
///
/// 资产读取复用 [`GeoDataLoader`]（本 crate 已是文件属主，对应 Go
/// `common/geodata/geodat_loader.go`），不新增资产来源抽象。
pub struct IPSetFactory {
    loader: GeoDataLoader,
    cache: WeakCacheMap<String, IPSet>,
}

impl IPSetFactory {
    /// 以 geodata 资产目录构造（对应 Go `newIPSetFactory` + 全局 `loadIP`）。
    #[must_use]
    pub fn new(datadir: PathBuf) -> Self {
        Self { loader: GeoDataLoader::new(datadir), cache: WeakCacheMap::new() }
    }

    /// 同极性 geoip 规则组 → 单个 IPSet（Go `GetOrCreateFromGeoIPRules`）。
    ///
    /// 组内**每个 tag 的 CIDR 并进同一个集合**（不是每 tag 一个集合），这样
    /// neg 组整组取反才是 `¬OR(in_i)` 而非 `OR(¬in_i)`。
    ///
    /// 失败语义对齐 Go：文件缺失 / tag 不存在 / 解码失败 ⇒ `Err`（Go 的 err 直上
    /// `BuildIPMatcher`，消费方拒启）。tag 有效但 CIDR 全非法 ⇒ `IPSet::from_cidrs`
    /// 跳过非 4/16 字节条目 ⇒ 空集（log-and-skip，无错），见 `ip_matcher.go:881-899`。
    pub fn get_or_create_from_geoip_rules(
        &self,
        rules: &[GeoIpRule],
    ) -> Result<Arc<IPSet>, LoaderError> {
        let key = build_geoip_rules_key(rules);
        if let Some(ipset) = self.cache.load(&key).and_then(|w| w.upgrade()) {
            return Ok(ipset);
        }

        let mut cidrs: Vec<Cidr> = Vec::new();
        for rule in rules {
            cidrs.extend(self.loader.load_ip(geoip_file(rule), &rule.code)?.cidr);
        }
        let ipset = Arc::new(IPSet::from_cidrs(&cidrs));
        self.cache.store(key, Arc::clone(&ipset));
        Ok(ipset)
    }
}

/// 规则里的文件名归一：空 → 默认 `geoip.dat`（沿用仓内既有约定，如
/// `xray-app-router` 的 geoip 展开与 `xray-app-dns` 的 jsonconf）。
fn geoip_file(rule: &GeoIpRule) -> &str {
    if rule.file.is_empty() { crate::rule_parser::DEFAULT_GEOIP_DAT } else { &rule.file }
}

/// 组 key：按 `file:code` 排序去重后逗号拼接。
///
/// 逐字对应 Go `buildGeoIPRulesKey`（`ip_matcher.go:843-866`）：顺序无关、
/// 重复 tag 只算一次 ⇒ 同组规则的任何消费方命中同一缓存条目。
fn build_geoip_rules_key(rules: &[GeoIpRule]) -> String {
    let mut pairs: Vec<(&str, &str)> =
        rules.iter().map(|r| (geoip_file(r), r.code.as_str())).collect();
    pairs.sort_unstable();
    pairs.dedup();

    let mut key = String::with_capacity(pairs.len() * 20);
    for (file, code) in pairs {
        key.push_str(file);
        key.push(':');
        key.push_str(code);
        key.push(',');
    }
    key
}

// ── 构建优化匹配器 ─────────────────────────────────────────────

/// 构建优化 IP 匹配器的错误类型。
#[derive(Debug, thiserror::Error)]
pub enum BuildIPMatcherError {
    /// 规则列表为空 / 无任何可编译子匹配器（Go `no valid ip matcher`）
    #[error("规则列表为空")]
    EmptyRules,
    /// 构造期读 geodata 资产失败（Go：`GetOrCreateFromGeoIPRules` 的 err 直上
    /// `BuildIPMatcher` ⇒ 消费方拒启，**不**静默退化成空集）
    #[error("加载 geoip 资产失败: {0}")]
    Loader(#[from] LoaderError),
}

/// 从 IpRule 列表构建优化 IP 匹配器。
///
/// 对应 Go 版本 `buildOptimizedIPMatcher`（ip_matcher.go:940-1013）：规则按
/// reverse 分 pos/neg 两组，**每组一个 matcher**；Custom 组 CIDR 并成一个 IPSet，
/// Geoip 组经 [`IPSetFactory::get_or_create_from_geoip_rules`] 把该极性下**所有
/// tag 的 CIDR 并成一个** IPSet（构造期解析一次，per-match 只读快照）；neg 组整
/// 组取反（match = ¬OR(in_i)）。逐条单例取反再 `any()` 聚合是德摩根错误
/// （OR(¬in_i) ≠ ¬OR(in_i)）：`!geoip:cn` 展开的多条 reverse CIDR 会反向命中
/// 组内其它 CIDR 未覆盖的 CN IP（bd 5fc7）。
///
/// 构造期读资产失败 ⇒ `Err`（⚠️ 旧实现此分支恒造空集并注释称「与 Go 缺数据路径
/// 一致」——不成立：Go 该路径返 err，无静默 false）。
pub fn build_optimized_ip_matcher(
    rules: &[IpRule],
) -> Result<Box<dyn IPMatcher>, BuildIPMatcherError> {
    build_with_factory(&IP_REG.factory.current(), rules)
}

/// [`build_optimized_ip_matcher`] 的显式工厂形态（Go `buildOptimizedIPMatcher(f, rules)`）。
///
/// 工厂决定资产世代：全局入口用当前世代，`IpRegistry::reload` 用新世代工厂重建。
fn build_with_factory(
    factory: &IPSetFactory,
    rules: &[IpRule],
) -> Result<Box<dyn IPMatcher>, BuildIPMatcherError> {
    if rules.is_empty() {
        return Err(BuildIPMatcherError::EmptyRules);
    }

    let mut pos_custom: Vec<Cidr> = Vec::new();
    let mut neg_custom: Vec<Cidr> = Vec::new();
    let mut pos_geoip: Vec<GeoIpRule> = Vec::new();
    let mut neg_geoip: Vec<GeoIpRule> = Vec::new();

    for rule in rules {
        match &rule.value {
            Some(pb::ip_rule::Value::Geoip(geoip)) => {
                if geoip.reverse_match {
                    neg_geoip.push(geoip.clone());
                } else {
                    pos_geoip.push(geoip.clone());
                }
            },
            Some(pb::ip_rule::Value::Custom(cidr_rule)) => {
                if let Some(cidr) = &cidr_rule.cidr {
                    if cidr_rule.reverse_match {
                        neg_custom.push(cidr.clone());
                    } else {
                        pos_custom.push(cidr.clone());
                    }
                }
            },
            None => {},
        }
    }

    let mut subs: Vec<HeuristicIPMatcher> = Vec::with_capacity(4);
    if !pos_custom.is_empty() {
        subs.push(HeuristicIPMatcher::from_cidrs(&pos_custom));
    }
    if !neg_custom.is_empty() {
        let mut m = HeuristicIPMatcher::from_cidrs(&neg_custom);
        m.set_reverse(true);
        subs.push(m);
    }
    if !pos_geoip.is_empty() {
        subs.push(HeuristicIPMatcher::from_shared(
            factory.get_or_create_from_geoip_rules(&pos_geoip)?,
        ));
    }
    if !neg_geoip.is_empty() {
        let mut m =
            HeuristicIPMatcher::from_shared(factory.get_or_create_from_geoip_rules(&neg_geoip)?);
        m.set_reverse(true);
        subs.push(m);
    }

    match subs.len() {
        0 => Err(BuildIPMatcherError::EmptyRules),
        1 => Ok(Box::new(subs.pop().expect("len==1 guaranteed"))),
        _ => Ok(Box::new(HeuristicMultiIPMatcher::new(subs))),
    }
}

// 历史布局：正式 item（IpRegistry/DynamicIPMatcher 等）在测试模块之后，
// 整体移动是大 diff 重构，保持现状。
#[allow(clippy::items_after_test_module)] // 历史布局保持，整体移动属大 diff 重构
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::CidrRule;

    // ── Ipv4Cidr/Ipv6Cidr 测试 ──────────────────────────────

    #[test]
    fn ipv4_cidr_contains() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16);
        assert!(cidr.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(cidr.contains(Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!cidr.contains(Ipv4Addr::new(192, 169, 0, 0)));
        assert!(!cidr.contains(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ipv4_cidr_prefix0() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        assert!(cidr.contains(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(cidr.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn ipv4_cidr_prefix32() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 1), 32);
        assert!(cidr.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!cidr.contains(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn ipv6_cidr_contains() {
        let addr = Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let cidr = Ipv6Cidr::new(addr, 32);
        let ip_in = Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]);
        let ip_out = Ipv6Addr::from([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(cidr.contains(ip_in));
        assert!(!cidr.contains(ip_out));
    }

    #[test]
    fn ipv6_cidr_prefix0() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0);
        assert!(cidr.contains(Ipv6Addr::LOCALHOST));
    }

    // ── IPSet 测试 ────────────────────────────────────────────

    #[test]
    fn ipset_new_empty() {
        let ipset = IPSet::new();
        assert!(ipset.is_empty_v4());
        assert!(ipset.is_empty_v6());
        assert_eq!(ipset.max4(), IPV4_NO_ENTRIES);
        assert_eq!(ipset.max6(), IPV6_NO_ENTRIES);
    }

    #[test]
    fn ipset_from_ipv4_cidrs() {
        let cidrs = vec![Cidr::new(vec![192, 168, 0, 0], 16), Cidr::new(vec![10, 0, 0, 0], 8)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(!ipset.is_empty_v4());
        assert!(ipset.is_empty_v6());
        // max4 存最细前缀（/16 与 /8 之最细 = 16），供桶门控 max<=24 判定。
        assert_eq!(ipset.max4(), 16);

        assert!(ipset.contains_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn ipset_from_ipv6_cidrs() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let cidrs = vec![Cidr::new(addr.to_vec(), 32)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.is_empty_v4());
        assert!(!ipset.is_empty_v6());
    }

    #[test]
    fn ipset_match_all_prefix0() {
        let cidrs = vec![Cidr::new(vec![0, 0, 0, 0], 0)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert_eq!(ipset.max4(), IPV4_MATCH_ALL);
        assert!(ipset.contains_v4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn ipset_contains_generic() {
        let cidrs = vec![Cidr::new(vec![127, 0, 0, 0], 8)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains(IpAddr::from([127, 0, 0, 1])));
        assert!(!ipset.contains(IpAddr::from([192, 168, 1, 1])));
    }

    // ── HeuristicIPMatcher 测试 ──────────────────────────────

    #[test]
    fn heuristic_match_basic() {
        let cidrs = vec![Cidr::new(vec![192, 168, 0, 0], 16)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        assert!(matcher.match_ip(IpAddr::from([192, 168, 1, 1])));
        assert!(!matcher.match_ip(IpAddr::from([10, 0, 0, 1])));
    }

    #[test]
    fn heuristic_reverse() {
        let cidrs = vec![Cidr::new(vec![192, 168, 0, 0], 16)];
        let mut matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        assert!(!matcher.reverse());
        matcher.set_reverse(true);
        assert!(matcher.reverse());
        assert!(!matcher.match_ip(IpAddr::from([192, 168, 1, 1])));
        assert!(matcher.match_ip(IpAddr::from([10, 0, 0, 1])));
    }

    #[test]
    fn heuristic_toggle_reverse() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8)];
        let mut matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        assert!(!matcher.reverse());
        matcher.toggle_reverse();
        assert!(matcher.reverse());
        matcher.toggle_reverse();
        assert!(!matcher.reverse());
    }

    #[test]
    fn heuristic_any_match() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let ips = vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([192, 168, 1, 1])];
        assert!(matcher.any_match(&ips));
        assert!(!matcher.any_match(&[]));
    }

    #[test]
    fn heuristic_matches() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let all_match = vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2])];
        assert!(matcher.matches(&all_match));
        let partial = vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([192, 168, 1, 1])];
        assert!(!matcher.matches(&partial));
    }

    #[test]
    fn heuristic_filter_ips() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let ips = vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([192, 168, 1, 1]),
            IpAddr::from([10, 1, 2, 3]),
        ];
        let filtered = matcher.filter_ips(&ips);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn heuristic_empty_ipset() {
        let matcher = HeuristicIPMatcher::from_cidrs(&[]);
        assert!(!matcher.match_ip(IpAddr::from([192, 168, 1, 1])));
        assert!(!matcher.any_match(&[IpAddr::from([10, 0, 0, 1])]));
    }

    /// 5dzf 回归：集合含 /32（最细前缀 > 24）时必须禁用桶记忆化。
    ///
    /// 旧实现 max4 存最小（最粗）前缀 /8 ≤ 24 → 启发式误开：同一 /24 桶内
    /// 首个未命中 IP 会把后续 IP 短路成同结果——any_match([1.2.3.4, 1.2.3.5])
    /// 漏判、matches([1.2.3.5, 1.2.3.4]) 误判。
    #[test]
    fn heuristic_bucket_memoization_disabled_with_fine_prefix() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8), Cidr::new(vec![1, 2, 3, 5], 32)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let miss_first = [IpAddr::from([1, 2, 3, 4]), IpAddr::from([1, 2, 3, 5])];
        let hit_first = [IpAddr::from([1, 2, 3, 5]), IpAddr::from([1, 2, 3, 4])];
        // 同桶内首失后有命中 → any_match 必须真
        assert!(matcher.any_match(&miss_first));
        // 同桶内首中后有未命中 → matches 必须假、any_match 仍真
        assert!(!matcher.matches(&hit_first));
        assert!(matcher.any_match(&hit_first));
        // 修正后门控关闭：filter_ips 等价逐 IP 线性匹配
        assert_eq!(matcher.filter_ips(&miss_first), vec![IpAddr::from([1, 2, 3, 5])]);
    }

    // ── build_optimized_ip_matcher 测试 ──────────────────────

    #[test]
    fn build_optimized_empty_rules() {
        let result = build_optimized_ip_matcher(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn build_optimized_custom_cidr() {
        let rule = IpRule {
            value: Some(pb::ip_rule::Value::Custom(CidrRule {
                cidr: Some(Cidr::new(vec![192, 168, 0, 0], 16)),
                reverse_match: false,
            })),
        };
        let matcher = build_optimized_ip_matcher(&[rule]).unwrap();
        assert!(matcher.match_ip(IpAddr::from([192, 168, 1, 1])));
    }

    #[test]
    fn build_optimized_multi_matcher() {
        let rules = vec![
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![10, 0, 0, 0], 8)),
                    reverse_match: false,
                })),
            },
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![192, 168, 0, 0], 16)),
                    reverse_match: false,
                })),
            },
        ];
        let matcher = build_optimized_ip_matcher(&rules).unwrap();
        assert!(matcher.match_ip(IpAddr::from([10, 0, 0, 1])));
        assert!(matcher.match_ip(IpAddr::from([192, 168, 1, 1])));
        assert!(!matcher.match_ip(IpAddr::from([8, 8, 8, 8])));
    }

    /// bd 5fc7 回归：`!geoip:cn` 展开为多条 reverse Custom CIDR。neg 组必须
    /// 合并为单 IPSet 后组级取反（¬OR(in_i)）——CN IP 不命中、非 CN 命中。
    /// 修复前逐条单例取反 any() 聚合（OR(¬in_i)）：CN IP 落在第一条 CIDR 时
    /// 被其余单例的取反命中，反向放行。
    #[test]
    fn build_optimized_neg_group_de_morgan() {
        // 模拟 geoip:cn 展开（两条 CIDR，均 reverse=true）。
        let rules = vec![
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![103, 0, 0, 0], 8)),
                    reverse_match: true,
                })),
            },
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![114, 114, 0, 0], 16)),
                    reverse_match: true,
                })),
            },
        ];
        let matcher = build_optimized_ip_matcher(&rules).unwrap();
        // CN IP（组内 CIDR 覆盖）不命中。
        assert!(!matcher.match_ip(IpAddr::from([103, 1, 2, 3])));
        assert!(!matcher.match_ip(IpAddr::from([114, 114, 114, 114])));
        // 非 CN IP 命中。
        assert!(matcher.match_ip(IpAddr::from([8, 8, 8, 8])));
    }

    /// bd 5fc7 回归：pos/neg 混合——pos 组 OR(in_pos) 与 neg 组组级取反
    /// ¬OR(in_neg) 由 MultiIPMatcher any() 聚合。
    #[test]
    fn build_optimized_mixed_pos_neg_groups() {
        let rules = vec![
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![192, 168, 0, 0], 16)),
                    reverse_match: false,
                })),
            },
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![103, 0, 0, 0], 8)),
                    reverse_match: true,
                })),
            },
            IpRule {
                value: Some(pb::ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr::new(vec![114, 114, 0, 0], 16)),
                    reverse_match: true,
                })),
            },
        ];
        let matcher = build_optimized_ip_matcher(&rules).unwrap();
        assert!(matcher.match_ip(IpAddr::from([192, 168, 1, 1])), "pos 组命中");
        assert!(!matcher.match_ip(IpAddr::from([103, 1, 2, 3])), "neg 组内不命中");
        assert!(matcher.match_ip(IpAddr::from([8, 8, 8, 8])), "两组都不覆盖 → neg 取反命中");
    }

    // ── geoip 资产注册表（bd hdgz9）────────────────────────────

    /// 合成 `geoip.dat`（`GeoIPList` 顶层 repeated 编码，与真实资产同形）。
    fn write_geoip_dat(dir: &std::path::Path, entries: &[(&str, Vec<Cidr>)]) {
        use prost::Message;

        let mut list = crate::pb::GeoIpList::new();
        for (code, cidrs) in entries {
            let mut geo = crate::pb::GeoIp::new(code);
            geo.cidr = cidrs.clone();
            list = list.with_entry(geo);
        }
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(crate::rule_parser::DEFAULT_GEOIP_DAT), list.encode_to_vec())
            .unwrap();
    }

    fn tmp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("xray_geodata_ip_{label}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn geoip_group_rule(file: &str, code: &str, reverse_match: bool) -> GeoIpRule {
        GeoIpRule { file: file.to_string(), code: code.to_string(), reverse_match }
    }

    fn geoip_rule(file: &str, code: &str, reverse_match: bool) -> IpRule {
        IpRule {
            value: Some(pb::ip_rule::Value::Geoip(geoip_group_rule(file, code, reverse_match))),
        }
    }

    /// bd hdgz9 正向门：`IpRuleValue::Geoip` 必须在**构造期**从资产解析。
    /// 旧实现恒造空集 stub ⇒ 资产内 IP 也不命中，本用例即红。
    #[test]
    fn geoip_rule_resolves_registry_asset() {
        let dir = tmp_dir("geoip_asset");
        write_geoip_dat(&dir, &[("CN", vec![Cidr::new(vec![103, 0, 0, 0], 8)])]);
        let factory = IPSetFactory::new(dir);

        // 幂等：同组规则重复解析命中同一 IPSet（Go WeakCacheMap 同）。
        let group = [geoip_group_rule("", "CN", false)];
        let first = factory.get_or_create_from_geoip_rules(&group).unwrap();
        let again = factory.get_or_create_from_geoip_rules(&group).unwrap();
        assert!(Arc::ptr_eq(&first, &again), "同组 key 必须共享同一 IPSet");

        let matcher = build_with_factory(&factory, &[geoip_rule("", "CN", false)]).unwrap();
        assert!(matcher.match_ip("103.1.2.3".parse().unwrap()), "资产内 IP 必须命中");
        assert!(!matcher.match_ip("8.8.8.8".parse().unwrap()), "资产外 IP 不得命中");
    }

    /// `!geoip:CN` 德摩根：组内 tag 的 CIDR 并成**一个**集合后整组取反
    /// （¬OR(in)）——CN 不命中、非 CN 命中（Go ip_matcher.go:996-1010）。
    #[test]
    fn build_optimized_geoip_neg_reverses_whole_group() {
        let dir = tmp_dir("geoip_neg");
        write_geoip_dat(
            &dir,
            &[
                ("CN", vec![Cidr::new(vec![103, 0, 0, 0], 8)]),
                ("US", vec![Cidr::new(vec![8, 8, 8, 0], 24)]),
            ],
        );
        let factory = IPSetFactory::new(dir);

        let neg_cn = build_with_factory(&factory, &[geoip_rule("", "CN", true)]).unwrap();
        assert!(!neg_cn.match_ip("103.1.2.3".parse().unwrap()), "CN IP 反向不命中");
        assert!(neg_cn.match_ip("8.8.8.8".parse().unwrap()), "非 CN IP 反向命中");

        // 两条 neg 规则 = ¬(CN∪US)。若实现成「每 tag 一个 matcher 再 any()」
        // （OR(¬A,¬B)），CN IP 会被 US 的取反命中 ⇒ 下面这条必红。
        let neg_both =
            build_with_factory(&factory, &[geoip_rule("", "CN", true), geoip_rule("", "US", true)])
                .unwrap();
        assert!(!neg_both.match_ip("103.1.2.3".parse().unwrap()), "CN∈并集 ⇒ 不命中");
        assert!(!neg_both.match_ip("8.8.8.8".parse().unwrap()), "US∈并集 ⇒ 不命中");
        assert!(neg_both.match_ip("1.1.1.1".parse().unwrap()), "并集外 ⇒ 命中");
    }

    /// 三前缀 `geoip:` / `ext:` / `ext-ip:` 在注册表层完全同形（前缀归一发生在
    /// rule_parser）——三条规则产出等价 matcher。
    #[test]
    fn geoip_three_prefixes_build_equivalent_matchers() {
        let dir = tmp_dir("geoip_prefixes");
        write_geoip_dat(&dir, &[("CN", vec![Cidr::new(vec![103, 0, 0, 0], 8)])]);

        let rules: Vec<IpRule> = ["geoip:CN", "ext:geoip.dat:CN", "ext-ip:geoip.dat:CN"]
            .iter()
            .flat_map(|raw| {
                crate::rule_parser::parse_ip_rules(&[(*raw).to_string()], &dir).unwrap()
            })
            .collect();
        assert_eq!(rules.len(), 3);

        let matcher = build_with_factory(&IPSetFactory::new(dir), &rules).unwrap();
        assert!(matcher.match_ip("103.1.2.3".parse().unwrap()));
        assert!(!matcher.match_ip("8.8.8.8".parse().unwrap()));
    }

    /// 构造期读资产失败 ⇒ `Err`（**不是**空集）：Go 该路径返 err 让消费方拒启。
    /// parse 期 `check_file` 已通过，构造前把文件删掉。
    #[test]
    fn geoip_missing_asset_is_build_error() {
        let dir = tmp_dir("geoip_missing");
        write_geoip_dat(&dir, &[("CN", vec![Cidr::new(vec![103, 0, 0, 0], 8)])]);
        let rules = crate::rule_parser::parse_ip_rules(&["geoip:CN".to_string()], &dir).unwrap();
        std::fs::remove_file(dir.join(crate::rule_parser::DEFAULT_GEOIP_DAT)).unwrap();

        let err = match build_with_factory(&IPSetFactory::new(dir), &rules) {
            Ok(_) => panic!("资产缺失必须 Err"),
            Err(e) => e,
        };
        assert!(matches!(err, BuildIPMatcherError::Loader(_)), "Got {err:?}");
    }

    /// 双栈监听端给的是 v4-mapped 的 16 字节地址：Go 匹配前 `To4()` 归一
    /// （ip_matcher.go:195）⇒ `::ffff:10.0.0.1` 必须命中 `10.0.0.0/8`。
    /// 未归一（旧实现）时走 v6 表 ⇒ 本用例必红。
    #[test]
    fn v4_mapped_address_matches_v4_rules() {
        let matcher = HeuristicIPMatcher::from_cidrs(&[Cidr::new(vec![10, 0, 0, 0], 8)]);
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(mapped.is_ipv6(), "前提：解析成 v6 形态（v4-mapped）");

        assert!(matcher.match_ip(mapped));
        assert!(matcher.any_match(&[mapped, IpAddr::from([8, 8, 8, 8])]));
        assert!(matcher.matches(&[mapped, IpAddr::from([10, 0, 0, 2])]));
        assert_eq!(matcher.filter_ips(&[mapped, IpAddr::from([8, 8, 8, 8])]).len(), 1);
        // IPSet 入口同归一。
        let set = IPSet::from_cidrs(&[Cidr::new(vec![192, 168, 0, 0], 16)]);
        assert!(set.contains("::ffff:192.168.1.1".parse().unwrap()));
    }

    /// 改动前 `match_addr` 的逐字复刻（**无归一**，ISet 内联形态），仅作性能基线。
    fn match_addr_pre_canonical(set: &IPSet, reverse: bool, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if set.max4() == IPV4_NO_ENTRIES {
                    return false;
                }
                set.contains_v4(v4) != reverse
            },
            IpAddr::V6(v6) => {
                if set.max6() == IPV6_NO_ENTRIES {
                    return false;
                }
                set.contains_v6(v6) != reverse
            },
        }
    }

    fn time_ns(iters: usize, mut f: impl FnMut() -> bool) -> u128 {
        use std::time::Instant;

        let mut hits = 0usize;
        let start = Instant::now();
        for _ in 0..iters {
            hits += usize::from(f());
        }
        std::hint::black_box(hits);
        start.elapsed().as_nanos() / iters as u128
    }

    fn median(mut v: Vec<u128>) -> u128 {
        v.sort_unstable();
        v[v.len() / 2]
    }

    /// 性能锚点（bd hdgz9 门：`match_ip` 相对改动前 ≤ +5%）。
    ///
    /// 三条臂同一二进制、同一轮次内交错跑，各自取 5 轮中位：
    /// - **A 改动前**：`match_addr` 逐字复刻（IPSet 内联持有，无归一）；
    /// - **B 新结构**：`match_v4`（IPSet 改 `Arc` 共享，无归一）；
    /// - **C 生产路径**：`match_ip`（`Arc` + v4-mapped 归一）。
    ///
    /// A→B 是设计强制的共享 `Arc<IPSet>` 成本，B→C 才是归一本身的成本。
    #[test]
    #[allow(clippy::print_stdout, reason = "性能锚点：ns/op 只能以 --nocapture 打印进报告")]
    fn match_ip_cost_anchor() {
        use std::hint::black_box;

        let cidrs: Vec<Cidr> =
            (0..4000u32).map(|i| Cidr::new(vec![10, (i >> 8) as u8, i as u8, 0], 24)).collect();
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let set = matcher.ipset();
        let reverse = matcher.reverse();

        let samples = [
            black_box("203.0.113.7".parse::<IpAddr>().unwrap()),
            black_box("10.0.0.0".parse::<IpAddr>().unwrap()),
        ];
        let iters = 200_000usize;
        let per = iters * samples.len();

        let mut a = Vec::with_capacity(5);
        let mut b = Vec::with_capacity(5);
        let mut c = Vec::with_capacity(5);
        for round in 0..5 {
            let run_a = || {
                time_ns(per, || {
                    let mut hit = false;
                    for sample in samples {
                        hit |= match_addr_pre_canonical(set, reverse, black_box(sample));
                    }
                    hit
                })
            };
            let run_b = || {
                time_ns(per, || {
                    let mut hit = false;
                    for sample in samples {
                        if let IpAddr::V4(v4) = black_box(sample) {
                            hit |= matcher.match_v4(v4);
                        }
                    }
                    hit
                })
            };
            let run_c = || {
                time_ns(per, || {
                    let mut hit = false;
                    for sample in samples {
                        hit |= matcher.match_ip(black_box(sample));
                    }
                    hit
                })
            };
            if round % 2 == 0 {
                a.push(run_a());
                b.push(run_b());
                c.push(run_c());
            } else {
                c.push(run_c());
                b.push(run_b());
                a.push(run_a());
            }
        }
        let (a_ns, b_ns, c_ns) = (median(a), median(b), median(c));
        let pct = |x: u128, y: u128| (y as f64 - x as f64) / x as f64 * 100.0;
        println!("A 改动前 (内联 IPSet, 无归一):  {a_ns} ns/op");
        println!("B 新结构 (Arc 共享, 无归一):    {b_ns} ns/op  (A→B {:+.1}%)", pct(a_ns, b_ns));
        println!(
            "C 生产路径 (Arc + 归一):        {c_ns} ns/op  (B→C {:+.1}%, A→C {:+.1}%)",
            pct(b_ns, c_ns),
            pct(a_ns, c_ns)
        );
        assert!(c_ns < 5_000, "match_ip 单次 {c_ns} ns 异常（量级检查）");

        // v4-mapped 归一的成本（Go 同样有 To4()，应同量级）。
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let mapped_ns = median(
            (0..5).map(|_| time_ns(iters, || matcher.match_ip(black_box(mapped)))).collect(),
        );
        println!("match_ip (v4-mapped 输入):      {mapped_ns} ns/op");
    }

    /// 注册表给的 per-match 入口（`DynamicIPMatcher`）的读成本：
    /// `HotSlot::with`（生产路径，纯原子 load）vs `HotSlot::current`（refcount RMW）。
    #[test]
    #[allow(clippy::print_stdout, reason = "性能锚点：ns/op 只能以 --nocapture 打印进报告")]
    fn dynamic_matcher_read_cost_anchor() {
        use std::hint::black_box;

        let cidrs: Vec<Cidr> =
            (0..4000u32).map(|i| Cidr::new(vec![10, (i >> 8) as u8, i as u8, 0], 24)).collect();
        let dynamic = DynamicIPMatcher::new(
            Vec::new(),
            Box::new(HeuristicIPMatcher::from_cidrs(&cidrs)),
            PathBuf::new(),
        );
        let probe: IpAddr = black_box("10.0.0.0".parse().unwrap());
        let iters = 200_000usize;

        let with_ns: Vec<u128> =
            (0..5).map(|_| time_ns(iters, || dynamic.match_ip(black_box(probe)))).collect();
        let current_ns: Vec<u128> = (0..5)
            .map(|_| time_ns(iters, || dynamic.state.current().matcher.match_ip(black_box(probe))))
            .collect();
        println!("DynamicIPMatcher::match_ip (HotSlot::with):    {} ns/op", median(with_ns));
        println!("DynamicIPMatcher::match_ip (HotSlot::current): {} ns/op", median(current_ns));
    }

    // ── IPSet 语义契约（6nxp：区间化/前缀查找必须与线性扫描逐点一致）──

    /// xorshift64 伪随机源：固定种子，无外部 rand 依赖。
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// 独立参考：直接掩码计算 CIDR 的 [start, end] inclusive 区间。
    fn v4_range_ref(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
        let a = u32::from_be_bytes(addr.octets());
        if prefix == 0 {
            return (0, u32::MAX);
        }
        let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
        let base = a & mask;
        (base, base | !mask)
    }

    fn v6_range_ref(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
        let a = u128::from_be_bytes(addr.octets());
        if prefix == 0 {
            return (0, u128::MAX);
        }
        let mask = if prefix >= 128 { u128::MAX } else { u128::MAX << (128 - prefix) };
        let base = a & mask;
        (base, base | !mask)
    }

    #[test]
    fn ipset_random_cidrs_match_linear_reference_v4() {
        let mut rng: u64 = 0x6e78_7070;
        let mut raws: Vec<(Ipv4Addr, u8)> = Vec::new();
        let mut ref_nets: Vec<Ipv4Cidr> = Vec::new();
        let mut cidrs: Vec<Cidr> = Vec::new();
        for _ in 0..300 {
            let raw = xorshift64(&mut rng) as u32;
            let prefix = (xorshift64(&mut rng) % 33) as u8;
            let addr = Ipv4Addr::from(raw);
            raws.push((addr, prefix));
            ref_nets.push(Ipv4Cidr::new(addr, prefix));
            cidrs.push(Cidr::new(addr.octets().to_vec(), prefix as u32));
        }
        let ipset = IPSet::from_cidrs(&cidrs);

        for i in 0..4000u32 {
            let pick = raws[(xorshift64(&mut rng) % raws.len() as u64) as usize];
            let ip_raw: u32 = match i % 4 {
                // 区间 base（命中点）/ end（右边界）/ base+1（左邻界）
                0 => v4_range_ref(pick.0, pick.1).0,
                1 => v4_range_ref(pick.0, pick.1).1,
                2 => v4_range_ref(pick.0, pick.1).0.wrapping_add(1),
                _ => xorshift64(&mut rng) as u32,
            };
            let ip = Ipv4Addr::from(ip_raw);
            let want = ref_nets.iter().any(|n| n.contains(ip));
            assert_eq!(ipset.contains_v4(ip), want, "mismatch at {ip}");
        }
    }

    #[test]
    fn ipset_random_cidrs_match_linear_reference_v6() {
        let mut rng: u64 = 0x6e78_7226;
        let mut raws: Vec<(Ipv6Addr, u8)> = Vec::new();
        let mut ref_nets: Vec<Ipv6Cidr> = Vec::new();
        let mut cidrs: Vec<Cidr> = Vec::new();
        for _ in 0..300 {
            let hi = xorshift64(&mut rng);
            let lo = xorshift64(&mut rng);
            let prefix = (xorshift64(&mut rng) % 129) as u8;
            let addr = Ipv6Addr::from(((hi as u128) << 64) | lo as u128);
            raws.push((addr, prefix));
            ref_nets.push(Ipv6Cidr::new(addr, prefix));
            cidrs.push(Cidr::new(addr.octets().to_vec(), prefix as u32));
        }
        let ipset = IPSet::from_cidrs(&cidrs);

        for i in 0..4000u32 {
            let pick = raws[(xorshift64(&mut rng) % raws.len() as u64) as usize];
            let ip_raw: u128 = match i % 4 {
                0 => v6_range_ref(pick.0, pick.1).0,
                1 => v6_range_ref(pick.0, pick.1).1,
                2 => v6_range_ref(pick.0, pick.1).0.wrapping_add(1),
                _ => {
                    let hi = xorshift64(&mut rng);
                    let lo = xorshift64(&mut rng);
                    ((hi as u128) << 64) | lo as u128
                },
            };
            let ip = Ipv6Addr::from(ip_raw);
            let want = ref_nets.iter().any(|n| n.contains(ip));
            assert_eq!(ipset.contains_v6(ip), want, "mismatch at {ip}");
        }
    }

    #[test]
    fn ipset_prefix0_matches_all_v4_and_v6() {
        let cidrs = vec![
            Cidr::new(vec![0, 0, 0, 0], 0),
            Cidr::new(Ipv6Addr::UNSPECIFIED.octets().to_vec(), 0),
        ];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(ipset.contains_v4(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(ipset.contains_v6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn ipset_host_route_exact_and_neighbor() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 1], 32)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 2)));

        let cidrs6 = vec![Cidr::new(Ipv6Addr::LOCALHOST.octets().to_vec(), 128)];
        let ipset6 = IPSet::from_cidrs(&cidrs6);
        assert!(ipset6.contains_v6(Ipv6Addr::LOCALHOST));
        let neighbor = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(!ipset6.contains_v6(neighbor));
    }

    #[test]
    fn ipset_overlapping_prefixes_union_semantics() {
        // 10.0.0.0/8 与 10.128.0.0/9 嵌套重叠：并集语义不受区间合并影响
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8), Cidr::new(vec![10, 128, 0, 0], 9)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 127, 255, 255)));
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 128, 0, 0)));
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(9, 255, 255, 255)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(11, 0, 0, 0)));
    }

    #[test]
    fn ipset_adjacent_ranges_boundary() {
        // 10.0.0.0/8 与 11.0.0.0/8 相邻不相交：两侧边界全命中，外部 miss
        let cidrs = vec![Cidr::new(vec![11, 0, 0, 0], 8), Cidr::new(vec![10, 0, 0, 0], 8)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(ipset.contains_v4(Ipv4Addr::new(11, 0, 0, 0)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(12, 0, 0, 0)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(9, 255, 255, 255)));
    }

    #[test]
    fn ipset_v4_v6_families_isolated() {
        let v4_only = IPSet::from_cidrs(&[Cidr::new(vec![127, 0, 0, 0], 8)]);
        assert!(v4_only.is_empty_v6());
        assert!(!v4_only.contains_v6(Ipv6Addr::LOCALHOST));

        let v6_only = IPSet::from_cidrs(&[Cidr::new(Ipv6Addr::LOCALHOST.octets().to_vec(), 128)]);
        assert!(v6_only.is_empty_v4());
        assert!(!v6_only.contains_v4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn ipset_duplicate_cidrs() {
        let cidrs = vec![Cidr::new(vec![192, 168, 0, 0], 16), Cidr::new(vec![192, 168, 0, 0], 16)];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(192, 169, 0, 0)));
    }

    #[test]
    fn ipset_ranges_sorted_disjoint_invariant() {
        let mut rng: u64 = 0x1234_5678;
        let mut cidrs = Vec::new();
        for _ in 0..200 {
            let raw = xorshift64(&mut rng) as u32;
            let prefix = (xorshift64(&mut rng) % 33) as u8;
            cidrs.push(Cidr::new(Ipv4Addr::from(raw).octets().to_vec(), prefix as u32));
        }
        let ipset = IPSet::from_cidrs(&cidrs);
        for w in ipset.ipv4_ranges.windows(2) {
            assert!(
                w[0].1 < w[1].0,
                "ranges must be sorted and disjoint: {:?} then {:?}",
                w[0],
                w[1]
            );
        }
        assert!(
            ipset.ipv6_ranges.windows(2).all(|w| w[0].1 < w[1].0),
            "ipv6 ranges must be sorted and disjoint"
        );
    }
}

// ── IP registry (世代热替换) ─────────────────────────────────────

/// IP 匹配器注册表 + 世代热替换。
///
/// 对应 Go `IPRegistry`（`common/geodata/ip_registry.go:14-70`）：`factory` 是当前
/// 世代 [`IPSetFactory`]（读侧无锁）；`matchers` 是弱引用登记簿（消费方丢 `Arc`
/// 即回收，无后台线程）；`reload` 逐 matcher 用**自己的 rules** 重建后整体换世代，
/// 任一条 err ⇒ 整体 err，不半切。
pub struct IpRegistry {
    datadir: PathBuf,
    factory: HotSlot<IPSetFactory>,
    matchers: WeakCacheMap<u64, DynamicIPMatcher>,
    /// 登记序号（单调 `u64` 代替 Go 的 `uuid.New()`）。
    next_id: AtomicU64,
    /// 登记 / 热换互斥（Go `mu`）：保证「全部重建成功后才整体切换」不被打断。
    sync: Mutex<()>,
}

impl IpRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::with_datadir(xray_common::platform::get_asset_dir())
    }

    /// 指定 geodata 资产目录（自定义资产 / 测试注入；生产走 [`IpRegistry::new`]）。
    #[must_use]
    pub fn with_datadir(datadir: PathBuf) -> Self {
        Self {
            factory: HotSlot::new(Arc::new(IPSetFactory::new(datadir.clone()))),
            datadir,
            matchers: WeakCacheMap::new(),
            next_id: AtomicU64::new(0),
            sync: Mutex::new(()),
        }
    }

    /// 构建并登记一个动态 IP 匹配器（Go `IPRegistry.BuildIPMatcher`）。
    ///
    /// 构造期读资产失败 ⇒ `Err`（不登记）；登记后消费方持 `Arc`，drop 即从弱表回收。
    pub fn build_ip_matcher(
        &self,
        rules: &[IpRule],
    ) -> Result<Arc<DynamicIPMatcher>, BuildIPMatcherError> {
        let _guard = self.sync.lock();
        let factory = self.factory.current();
        let initial = build_with_factory(&factory, rules)?;

        let matcher =
            Arc::new(DynamicIPMatcher::new(rules.to_vec(), initial, self.datadir.clone()));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.matchers.store(id, Arc::clone(&matcher));
        Ok(matcher)
    }

    /// 用每个 matcher **自己的 rules** 重建（Go `IPRegistry.Reload`）。
    ///
    /// 失败语义：任一 matcher 重建失败 ⇒ 立即 `Err`，**不切换**任何快照与世代
    /// （Go 同：错误在切换循环之前返回）。
    pub fn reload(&self) -> Result<(), BuildIPMatcherError> {
        let _guard = self.sync.lock();
        let registered = self.matchers.upgrade_all();

        let factory = Arc::new(IPSetFactory::new(self.datadir.clone()));
        let mut reloaded = Vec::with_capacity(registered.len());
        for matcher in &registered {
            reloaded.push((Arc::clone(matcher), build_with_factory(&factory, &matcher.rules)?));
        }
        for (matcher, fresh) in reloaded {
            matcher.replace(fresh);
        }
        self.factory.replace(factory);
        Ok(())
    }

    /// 当前登记的动态匹配器数量（含尚未清理的失效弱引用）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.matchers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 动态匹配器的当前快照（Go `ipMatcherState`）：整体原子换，无部分更新。
struct MatcherState {
    matcher: Box<dyn IPMatcher>,
}

/// 动态 IP 匹配器。
///
/// 对应 Go `DynamicIPMatcher`（`ip_registry.go:80-140`）：`state` 是当前快照，
/// per-match 只做一次原子读（零锁零分配）；`reverse` / `reverse_set` 是控制面
/// 标志，读取同样无锁。
pub struct DynamicIPMatcher {
    /// 构建时用的规则（`reload` 按**自己的**规则重建，Go `d.rules`）。
    rules: Vec<IpRule>,
    datadir: PathBuf,
    state: HotSlot<MatcherState>,
    reverse: AtomicBool,
    reverse_set: AtomicBool,
    /// 控制面写互斥（Go `d.mu`）：重建 / 换快照 / 改 reverse 串行。
    sync: Mutex<()>,
}

impl DynamicIPMatcher {
    fn new(rules: Vec<IpRule>, initial: Box<dyn IPMatcher>, datadir: PathBuf) -> Self {
        Self {
            rules,
            datadir,
            state: HotSlot::new(Arc::new(MatcherState { matcher: initial })),
            reverse: AtomicBool::new(false),
            reverse_set: AtomicBool::new(false),
            sync: Mutex::new(()),
        }
    }

    /// 热替换内部快照，保留调用方的 reverse 语义（Go `DynamicIPMatcher.Reload`）。
    fn replace(&self, mut fresh: Box<dyn IPMatcher>) {
        let _guard = self.sync.lock();
        let reverse = self.reverse.load(Ordering::Acquire);
        if self.reverse_set.load(Ordering::Acquire) {
            fresh.set_reverse(reverse);
        } else if reverse {
            fresh.toggle_reverse();
        }
        self.state.replace(Arc::new(MatcherState { matcher: fresh }));
    }

    /// 设置 reverse 标志并记录已显式设置过（Go `SetReverse`：逐 sub **赋值**）。
    ///
    /// 快照不可变 ⇒ 以自有 rules 重建一份再赋值（控制面路径，数据面无额外成本）。
    pub fn set_reverse(&self, reverse: bool) -> Result<(), BuildIPMatcherError> {
        let _guard = self.sync.lock();
        let mut fresh = self.rebuild()?;
        fresh.set_reverse(reverse);
        self.reverse.store(reverse, Ordering::Release);
        self.reverse_set.store(true, Ordering::Release);
        self.state.replace(Arc::new(MatcherState { matcher: fresh }));
        Ok(())
    }

    /// 切换 reverse 标志（Go `ToggleReverse`：逐 sub **翻转**当前值）。
    pub fn toggle_reverse(&self) -> Result<(), BuildIPMatcherError> {
        let _guard = self.sync.lock();
        let next = !self.reverse.load(Ordering::Acquire);
        let mut fresh = self.rebuild()?;
        if self.reverse_set.load(Ordering::Acquire) {
            // 已显式赋值过 ⇒ 全部 sub 同值，翻转等价于整体置反。
            fresh.set_reverse(next);
        } else {
            // 未赋值过 ⇒ sub 保持规则派生极性（pos 组 false / neg 组 true），逐 sub 翻转。
            fresh.toggle_reverse();
        }
        self.reverse.store(next, Ordering::Release);
        self.state.replace(Arc::new(MatcherState { matcher: fresh }));
        Ok(())
    }

    /// 用自有 rules 重建一份（Go `buildOptimizedIPMatcher(factory, d.rules)`）。
    ///
    /// 走独立工厂实例：控制面路径（reverse 变更）冷，不必挂到世代工厂上。
    fn rebuild(&self) -> Result<Box<dyn IPMatcher>, BuildIPMatcherError> {
        build_with_factory(&IPSetFactory::new(self.datadir.clone()), &self.rules)
    }

    /// 获取当前 reverse 标志。
    #[must_use]
    pub fn reverse(&self) -> bool {
        self.reverse.load(Ordering::Acquire)
    }
}

impl IPMatcher for DynamicIPMatcher {
    // per-match 读走 `HotSlot::with`（一次纯原子 load、无 refcount），与 Go
    // `d.state.Load()` 同成本；`current()` 的 refcount RMW 留在需要 owned Arc 的场合。
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.state.with(|s| s.matcher.match_ip(ip))
    }

    fn any_match(&self, ips: &[IpAddr]) -> bool {
        self.state.with(|s| s.matcher.any_match(ips))
    }

    fn matches(&self, ips: &[IpAddr]) -> bool {
        self.state.with(|s| s.matcher.matches(ips))
    }

    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        self.state.with(|s| s.matcher.filter_ips(ips))
    }

    fn reverse(&self) -> bool {
        self.reverse.load(Ordering::Acquire)
    }

    fn set_reverse(&mut self, _reverse: bool) {
        // 控制面 API 走 `DynamicIPMatcher::set_reverse(&self)`（比 &mut 覆盖点更强）。
    }

    fn toggle_reverse(&mut self) {
        // 同上：通过 `DynamicIPMatcher::toggle_reverse(&self)` 调用。
    }
}

impl std::fmt::Debug for DynamicIPMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicIPMatcher").field("reverse", &self.reverse()).finish()
    }
}

/// 全局 IP 注册表实例。
///
/// 对应 Go `commongeodata.IPReg`。资产目录 = [`xray_common::platform::get_asset_dir`]；
/// 热更落盘后由 `xray-app-geodata` 的 `ReloadBothRegistries` 触发 [`IpRegistry::reload`]。
/// 如需独立资产目录（测试/多实例），用 [`IpRegistry::with_datadir`]。
pub static IP_REG: LazyLock<IpRegistry> = LazyLock::new(IpRegistry::new);
