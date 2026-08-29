//! IP matcher
//!
//! 对应 Go 版本 `common/geodata/ip_matcher`，提供 IP 地址匹配功能。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::pb::{self, Cidr, GeoIpRule, IpRule};

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
        Self {
            addr: u32::from_be_bytes(addr.octets()),
            prefix,
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let ip_val = u32::from_be_bytes(ip.octets());
        let mask = if self.prefix == 32 {
            !0u32
        } else {
            !0u32 << (32 - self.prefix)
        };
        (ip_val & mask) == (self.addr & mask)
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
        Self {
            addr: u128::from_be_bytes(addr.octets()),
            prefix,
        }
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let ip_val = u128::from_be_bytes(ip.octets());
        let mask = if self.prefix == 128 {
            !0u128
        } else {
            !0u128 << (128 - self.prefix)
        };
        (ip_val & mask) == (self.addr & mask)
    }
}

// ── IPSet ───────────────────────────────────────────────────────

/// 基于 CIDR 前缀列表的 IP 集合。
///
/// `max4`/`max6` 记录最大前缀位数，用于启发式优化判断：
/// - `0xff` 表示无条目
/// - `0xfe` 表示包含 /0（匹配所有）
pub struct IPSet {
    ipv4_ranges: Vec<Ipv4Cidr>,
    ipv6_ranges: Vec<Ipv6Cidr>,
    max4: u8,
    max6: u8,
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
                let addr = Ipv4Addr::new(
                    cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3],
                );
                let prefix = cidr.prefix.min(32) as u8;
                let net = Ipv4Cidr::new(addr, prefix);

                if prefix == 0 {
                    max4 = IPV4_MATCH_ALL;
                } else if max4 != IPV4_MATCH_ALL
                    && (prefix < max4 || max4 == IPV4_NO_ENTRIES)
                {
                    max4 = prefix;
                }
                ipv4_ranges.push(net);
            } else if cidr.ip.len() == 16 {
                let bytes: [u8; 16] =
                    cidr.ip[..16].try_into().unwrap_or([0; 16]);
                let addr = Ipv6Addr::from(bytes);
                let prefix = cidr.prefix.min(128) as u8;
                let net = Ipv6Cidr::new(addr, prefix);

                if prefix == 0 {
                    max6 = IPV6_MATCH_ALL;
                } else if max6 != IPV6_MATCH_ALL
                    && (prefix < max6 || max6 == IPV6_NO_ENTRIES)
                {
                    max6 = prefix;
                }
                ipv6_ranges.push(net);
            }
        }

        ipv4_ranges.sort_by_key(|n| n.prefix);
        ipv6_ranges.sort_by_key(|n| n.prefix);

        Self { ipv4_ranges, ipv6_ranges, max4, max6 }
    }

    /// 判断 IPv4 地址是否在集合内。
    #[must_use]
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        if self.max4 == IPV4_NO_ENTRIES { return false; }
        if self.max4 == IPV4_MATCH_ALL { return true; }
        self.ipv4_ranges.iter().any(|net| net.contains(ip))
    }

    /// 判断 IPv6 地址是否在集合内。
    #[must_use]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        if self.max6 == IPV6_NO_ENTRIES { return false; }
        if self.max6 == IPV6_MATCH_ALL { return true; }
        self.ipv6_ranges.iter().any(|net| net.contains(ip))
    }

    /// 判断 IP 地址是否在集合内。
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }

    /// IPv4 最大前缀位数。
    #[must_use]
    pub fn max4(&self) -> u8 { self.max4 }

    /// IPv6 最大前缀位数。
    #[must_use]
    pub fn max6(&self) -> u8 { self.max6 }

    /// IPv4 条目是否为空。
    #[must_use]
    pub fn is_empty_v4(&self) -> bool { self.max4 == IPV4_NO_ENTRIES }

    /// IPv6 条目是否为空。
    #[must_use]
    pub fn is_empty_v6(&self) -> bool { self.max6 == IPV6_NO_ENTRIES }
}

impl Default for IPSet {
    fn default() -> Self { Self::new() }
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
fn prefix_key(ip: IpAddr) -> [u8; 9] {
    match ip {
        IpAddr::V4(v4) => prefix_key_v4(v4),
        IpAddr::V6(v6) => prefix_key_v6(v6),
    }
}

// ── HeuristicIPMatcher ──────────────────────────────────────────

/// 带启发式桶优化的 IP 匹配器。
pub struct HeuristicIPMatcher {
    ipset: IPSet,
    reverse: bool,
}

impl HeuristicIPMatcher {
    /// 从 IPSet 创建启发式匹配器。
    pub fn new(ipset: IPSet) -> Self {
        Self { ipset, reverse: false }
    }

    /// 从 CIDR 列表创建启发式匹配器。
    pub fn from_cidrs(cidrs: &[Cidr]) -> Self {
        Self::new(IPSet::from_cidrs(cidrs))
    }

    /// 内部匹配实现：Contains XOR reverse。
    fn match_addr(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if self.ipset.max4() == IPV4_NO_ENTRIES {
                    return false;
                }
                self.ipset.contains_v4(v4) != self.reverse
            }
            IpAddr::V6(v6) => {
                if self.ipset.max6() == IPV6_NO_ENTRIES {
                    return false;
                }
                self.ipset.contains_v6(v6) != self.reverse
            }
        }
    }

    fn heuristic_v4(&self) -> bool {
        self.ipset.max4() <= 24 && self.ipset.max4() != IPV4_NO_ENTRIES
    }
    fn heuristic_v6(&self) -> bool {
        self.ipset.max6() <= 64 && self.ipset.max6() != IPV6_NO_ENTRIES
    }

    /// 获取内部 IPSet 的引用。
    #[must_use]
    pub fn ipset(&self) -> &IPSet { &self.ipset }
}

impl IPMatcher for HeuristicIPMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool { self.match_addr(ip) }

    fn any_match(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() { return false; }
        if ips.len() == 1 { return self.match_ip(ips[0]); }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter().any(|ip| self.match_ip(*ip));
        }

        let mut seen: HashMap<[u8; 9], bool> = HashMap::new();
        for ip in ips {
            let key = prefix_key(*ip);
            let is_v4 = matches!(ip, IpAddr::V4(_));
            let use_heur = if is_v4 { heur4 } else { heur6 };

            if use_heur {
                if let Some(&r) = seen.get(&key) {
                    if r { return true; }
                    continue;
                }
            }
            let r = self.match_ip(*ip);
            if use_heur { seen.insert(key, r); }
            if r { return true; }
        }
        false
    }

    fn matches(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() { return false; }
        if ips.len() == 1 { return self.match_ip(ips[0]); }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter().all(|ip| self.match_ip(*ip));
        }

        let mut buckets: HashMap<[u8; 9], bool> = HashMap::new();
        for ip in ips {
            let key = prefix_key(*ip);
            let is_v4 = matches!(ip, IpAddr::V4(_));
            let use_heur = if is_v4 { heur4 } else { heur6 };

            if use_heur {
                if let Some(&r) = buckets.get(&key) {
                    if !r { return false; }
                    continue;
                }
            }
            let r = self.match_ip(*ip);
            if use_heur { buckets.insert(key, r); }
            if !r { return false; }
        }
        true
    }

    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        if ips.is_empty() { return Vec::new(); }
        if ips.len() == 1 {
            return if self.match_ip(ips[0]) {
                vec![ips[0]]
            } else {
                Vec::new()
            };
        }

        let heur4 = self.heuristic_v4();
        let heur6 = self.heuristic_v6();
        if !heur4 && !heur6 {
            return ips.iter()
                .filter(|ip| self.match_ip(**ip))
                .copied()
                .collect();
        }

        let mut buckets: HashMap<[u8; 9], bool> = HashMap::new();
        let mut result = Vec::new();
        for ip in ips {
            let key = prefix_key(*ip);
            let is_v4 = matches!(ip, IpAddr::V4(_));
            let use_heur = if is_v4 { heur4 } else { heur6 };

            if use_heur {
                let matched = *buckets
                    .entry(key)
                    .or_insert_with(|| self.match_ip(*ip));
                if matched { result.push(*ip); }
            } else if self.match_ip(*ip) {
                result.push(*ip);
            }
        }
        result
    }

    fn reverse(&self) -> bool { self.reverse }
    fn set_reverse(&mut self, reverse: bool) { self.reverse = reverse; }
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
        ips.iter()
            .filter(|ip| self.match_ip(**ip))
            .copied()
            .collect()
    }

    fn reverse(&self) -> bool { false }
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
        ips.iter()
            .filter(|ip| self.match_ip(**ip))
            .copied()
            .collect()
    }

    fn reverse(&self) -> bool { false }
    fn set_reverse(&mut self, _reverse: bool) {}
}

// ── IPSetFactory ────────────────────────────────────────────────

/// IPSet 缓存工厂。
///
/// 对应 Go 版本 `IPSetFactory`，使用 Mutex + HashMap 缓存已创建的 IPSet。
pub struct IPSetFactory {
    cache: Mutex<HashMap<String, IPSet>>,
}

impl IPSetFactory {
    /// 创建新的工厂实例。
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }

    /// 从 GeoIP 规则获取或创建 IPSet。
    ///
    /// 先计算缓存 key，若命中则返回克隆，否则创建后缓存。
    pub fn get_or_create_from_geoip_rules(
        &self,
        rules: &[GeoIpRule],
    ) -> IPSet {
        let key = build_geoip_rules_key(rules);
        {
            let cache = self.cache.lock().expect("IPSetFactory lock poisoned");
            if let Some(ipset) = cache.get(&key) {
                return ipset.clone();
            }
        }
        let cidrs = collect_cidrs_from_rules(rules);
        let ipset = IPSet::from_cidrs(&cidrs);
        {
            let mut cache = self.cache.lock().expect("IPSetFactory lock poisoned");
            cache.insert(key, ipset.clone());
        }
        ipset
    }

    /// 从 CIDR 列表创建 IPSet 并缓存。
    pub fn create_from_cidrs(&self, key: &str, cidrs: &[Cidr]) -> IPSet {
        {
            let cache = self.cache.lock().expect("IPSetFactory lock poisoned");
            if let Some(ipset) = cache.get(key) {
                return ipset.clone();
            }
        }
        let ipset = IPSet::from_cidrs(cidrs);
        {
            let mut cache = self.cache.lock().expect("IPSetFactory lock poisoned");
            cache.insert(key.to_string(), ipset.clone());
        }
        ipset
    }
}

impl Default for IPSetFactory {
    fn default() -> Self { Self::new() }
}

/// 构建 GeoIP 规则缓存 key。
///
/// 按 File+Code 排序去重，拼接为 "file:code,file:code" 格式。
fn build_geoip_rules_key(rules: &[GeoIpRule]) -> String {
    let mut pairs: Vec<(String, String)> = rules
        .iter()
        .map(|r| (r.file.clone(), r.code.clone()))
        .collect();
    pairs.sort();
    pairs.dedup();
    pairs
        .iter()
        .map(|(f, c)| format!("{f}:{c}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// 从 GeoIP 规则列表收集所有 CIDR。
fn collect_cidrs_from_rules(_rules: &[GeoIpRule]) -> Vec<Cidr> {
    // GeoIpRule 只有 file/code/reverse_match，
    // 实际使用中需要从外部 GeoIP 数据加载 CIDR
    Vec::new()
}

// ── 构建优化匹配器 ─────────────────────────────────────────────

/// 构建优化 IP 匹配器的错误类型。
#[derive(Debug, thiserror::Error)]
pub enum BuildIPMatcherError {
    /// 规则列表为空
    #[error("规则列表为空")]
    EmptyRules,
}

/// 从 IpRule 列表构建优化 IP 匹配器。
///
/// 对应 Go 版本 `buildOptimizedIPMatcher`，将规则分为正向/反向，
/// Custom/Geoip 四组，构建 HeuristicMultiIPMatcher。
pub fn build_optimized_ip_matcher(
    rules: &[IpRule],
) -> Result<Box<dyn IPMatcher>, BuildIPMatcherError> {
    if rules.is_empty() {
        return Err(BuildIPMatcherError::EmptyRules);
    }

    let mut pos_matchers: Vec<HeuristicIPMatcher> = Vec::new();
    let mut neg_matchers: Vec<HeuristicIPMatcher> = Vec::new();

    for rule in rules {
        match &rule.value {
            Some(pb::ip_rule::Value::Geoip(geo_rule)) => {
                let matcher = HeuristicIPMatcher::from_cidrs(&[]);
                if geo_rule.reverse_match {
                    neg_matchers.push(matcher);
                } else {
                    pos_matchers.push(matcher);
                }
            }
            Some(pb::ip_rule::Value::Custom(cidr_rule)) => {
                if let Some(ref cidr) = cidr_rule.cidr {
                    let matcher = HeuristicIPMatcher::from_cidrs(&[cidr.clone()]);
                    if cidr_rule.reverse_match {
                        neg_matchers.push(matcher);
                    } else {
                        pos_matchers.push(matcher);
                    }
                }
            }
            None => {}
        }
    }

    let total = pos_matchers.len() + neg_matchers.len();
    if total == 0 {
        return Err(BuildIPMatcherError::EmptyRules);
    }

    let mut all_matchers = pos_matchers;
    all_matchers.extend(neg_matchers);

    if all_matchers.len() == 1 {
        let matcher = all_matchers.pop().expect("len==1 guaranteed");
        Ok(Box::new(matcher))
    } else {
        Ok(Box::new(HeuristicMultiIPMatcher::new(all_matchers)))
    }
}

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
        let addr = Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let cidr = Ipv6Cidr::new(addr, 32);
        let ip_in = Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        let ip_out = Ipv6Addr::from([
            0x20, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]);
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
        let cidrs = vec![
            Cidr::new(vec![192, 168, 0, 0], 16),
            Cidr::new(vec![10, 0, 0, 0], 8),
        ];
        let ipset = IPSet::from_cidrs(&cidrs);
        assert!(!ipset.is_empty_v4());
        assert!(ipset.is_empty_v6());
        assert_eq!(ipset.max4(), 8);

        assert!(ipset.contains_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(ipset.contains_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!ipset.contains_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn ipset_from_ipv6_cidrs() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1];
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
        let ips = vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([192, 168, 1, 1]),
        ];
        assert!(matcher.any_match(&ips));
        assert!(!matcher.any_match(&[]));
    }

    #[test]
    fn heuristic_matches() {
        let cidrs = vec![Cidr::new(vec![10, 0, 0, 0], 8)];
        let matcher = HeuristicIPMatcher::from_cidrs(&cidrs);
        let all_match = vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([10, 0, 0, 2]),
        ];
        assert!(matcher.matches(&all_match));
        let partial = vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([192, 168, 1, 1]),
        ];
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

    // ── IPSetFactory 测试 ────────────────────────────────────

    #[test]
    fn ipset_factory_create_from_cidrs() {
        let factory = IPSetFactory::new();
        let cidrs = vec![Cidr::new(vec![172, 16, 0, 0], 12)];
        let ipset = factory.create_from_cidrs("test_key", &cidrs);
        assert!(ipset.contains_v4(Ipv4Addr::new(172, 16, 0, 1)));

        // 缓存命中
        let ipset2 = factory.create_from_cidrs("test_key", &[]);
        assert!(ipset2.contains_v4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn ipset_factory_default() {
        let factory = IPSetFactory::default();
        let ipset = factory.create_from_cidrs("k", &[]);
        assert!(ipset.is_empty_v4());
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
}

// ── IP registry (热替换) ─────────────────────────────────────────

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// IP 匹配器注册表 + 热替换。
///
/// 对应 Go `IPRegistry`：管理多个 `DynamicIPMatcher`，`Reload` 时
/// 用新规则重建所有 matcher，原子切换内部状态。
pub struct IpRegistry {
    inner: RwLock<IpRegistryInner>,
}

struct IpRegistryInner {
    entries: Vec<RegistryEntry>,
}

struct RegistryEntry {
    matcher: Arc<DynamicIPMatcher>,
    rules: Vec<IpRule>,
}

impl IpRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(IpRegistryInner {
                entries: Vec::new(),
            }),
        }
    }

    /// 添加一组规则并返回动态 IP 匹配器。
    pub fn add_rules(
        &self,
        rules: &[IpRule],
    ) -> Result<Arc<DynamicIPMatcher>, BuildIPMatcherError> {
        let initial = build_optimized_ip_matcher(rules)?;
        let matcher = Arc::new(DynamicIPMatcher::new(initial));
        let mut g = self.inner.write().expect("IpRegistry poisoned");
        g.entries.push(RegistryEntry {
            matcher: Arc::clone(&matcher),
            rules: rules.to_vec(),
        });
        Ok(matcher)
    }

    /// 用新规则列表重建所有匹配器（原子热切换）。
    ///
    /// 对应 Go `IPRegistry.Reload`：每个 entry 用 new_rules 重建 matcher。
    pub fn reload_with(
        &self,
        new_rules: &[IpRule],
    ) -> Result<(), BuildIPMatcherError> {
        // 一次拷出 entries 引用，避免长时间持写锁。
        let entries: Vec<Arc<DynamicIPMatcher>> = {
            let g = self.inner.read().expect("IpRegistry poisoned");
            g.entries.iter().map(|e| Arc::clone(&e.matcher)).collect()
        };

        // 重建一份（每个 entry 持有独立 Box<dyn IPMatcher>，避免共享 &mut）。
        for entry in &entries {
            let fresh = build_optimized_ip_matcher(new_rules)?;
            entry.replace(fresh);
        }
        Ok(())
    }

    /// 当前注册的动态匹配器数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().expect("IpRegistry poisoned").entries.len()
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

/// 动态 IP 匹配器。
///
/// 对应 Go `DynamicIPMatcher`：`RwLock<Box<dyn IPMatcher>>` 持当前状态；
/// `reverse` / `reverse_set` 是 `AtomicBool`，读取无锁。
pub struct DynamicIPMatcher {
    state: RwLock<Box<dyn IPMatcher>>,
    reverse: AtomicBool,
    reverse_set: AtomicBool,
}

impl DynamicIPMatcher {
    fn new(initial: Box<dyn IPMatcher>) -> Self {
        Self {
            state: RwLock::new(initial),
            reverse: AtomicBool::new(false),
            reverse_set: AtomicBool::new(false),
        }
    }

    /// 热替换内部状态。保留调用方的 reverse 标志语义（对齐 Go `Reload`）。
    fn replace(&self, new_matcher: Box<dyn IPMatcher>) {
        let reverse = self.reverse.load(Ordering::Acquire);
        let reverse_set = self.reverse_set.load(Ordering::Acquire);
        let mut new = new_matcher;
        if reverse_set {
            new.set_reverse(reverse);
        } else if reverse {
            new.toggle_reverse();
        }
        let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");
        *g = new;
    }

    /// 设置 reverse 标志并记录已显式设置过。
    pub fn set_reverse(&self, reverse: bool) {
        self.reverse.store(reverse, Ordering::Release);
        self.reverse_set.store(true, Ordering::Release);
        let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");
        g.set_reverse(reverse);
    }

    /// 切换 reverse 标志。
    pub fn toggle_reverse(&self) {
        let new = !self.reverse.load(Ordering::Acquire);
        self.reverse.store(new, Ordering::Release);
        let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");
        g.toggle_reverse();
    }

    /// 获取当前 reverse 标志。
    #[must_use]
    pub fn reverse(&self) -> bool {
        self.reverse.load(Ordering::Acquire)
    }

    fn with_state<R>(&self, f: impl FnOnce(&dyn IPMatcher) -> R) -> R {
        let g = self.state.read().expect("DynamicIPMatcher state poisoned");
        f(&**g)
    }
}

impl IPMatcher for DynamicIPMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.with_state(|m| m.match_ip(ip))
    }
    fn any_match(&self, ips: &[IpAddr]) -> bool {
        self.with_state(|m| m.any_match(ips))
    }
    fn matches(&self, ips: &[IpAddr]) -> bool {
        self.with_state(|m| m.matches(ips))
    }
    fn filter_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        self.with_state(|m| m.filter_ips(ips))
    }
    fn reverse(&self) -> bool {
        self.reverse.load(Ordering::Acquire)
    }
    fn set_reverse(&mut self, _reverse: bool) {
        // DynamicIPMatcher 顶层 API 请用 set_reverse(&self)。
    }
    fn toggle_reverse(&mut self) {
        // 同上：通过顶层 toggle_reverse(&self) 调用。
    }
}

impl std::fmt::Debug for DynamicIPMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicIPMatcher")
            .field("reverse", &self.reverse())
            .finish()
    }
}

/// 全局 IP 注册表实例。
///
/// 对应 Go `commongeodata.IPReg`。`routing` 层在 reload 时通过此处触达
/// 所有已注册的 IP matcher。如需 per-instance registry，优先本地 `new()`。
pub static IP_REG: std::sync::LazyLock<IpRegistry> = std::sync::LazyLock::new(IpRegistry::new);

