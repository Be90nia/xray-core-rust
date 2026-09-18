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

    /// CIDR 覆盖的 inclusive 地址区间 [start, end]。
    fn range(&self) -> (u32, u32) {
        if self.prefix == 0 {
            return (0, u32::MAX);
        }
        let mask = if self.prefix >= 32 {
            !0u32
        } else {
            !0u32 << (32 - self.prefix)
        };
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

    /// CIDR 覆盖的 inclusive 地址区间 [start, end]。
    fn range(&self) -> (u128, u128) {
        if self.prefix == 0 {
            return (0, u128::MAX);
        }
        let mask = if self.prefix >= 128 {
            !0u128
        } else {
            !0u128 << (128 - self.prefix)
        };
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
            }
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
                ipv4_ranges.push(net.range());
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
        if self.max4 == IPV4_NO_ENTRIES { return false; }
        if self.max4 == IPV4_MATCH_ALL { return true; }
        let v = u32::from_be_bytes(ip.octets());
        let idx = self.ipv4_ranges.partition_point(|&(_, e)| e < v);
        self.ipv4_ranges.get(idx).is_some_and(|&(s, _)| s <= v)
    }

    /// 判断 IPv6 地址是否在集合内。
    #[must_use]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        if self.max6 == IPV6_NO_ENTRIES { return false; }
        if self.max6 == IPV6_MATCH_ALL { return true; }
        let v = u128::from_be_bytes(ip.octets());
        let idx = self.ipv6_ranges.partition_point(|&(_, e)| e < v);
        self.ipv6_ranges.get(idx).is_some_and(|&(s, _)| s <= v)
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
/// 对应 Go 版本 `buildOptimizedIPMatcher`（ip_matcher.go:940-1013）：Custom
/// 规则按 reverse 分 pos/neg 两组，**每组 CIDR 合并为单个 IPSet**，neg 组
/// 整组取反（match = ¬OR(in_i)）。逐条单例取反再 any() 聚合是德摩根错误
/// （OR(¬in_i) ≠ ¬OR(in_i)）：`!geoip:cn` 展开的多条 reverse CIDR 会反向
/// 命中组内其它 CIDR 未覆盖的 CN IP（bd 5fc7）。
///
/// Geoip 直收分支保持空集 stub：上游（router condition / dns jsonconf）已把
/// geoip 展开为 Custom CIDR，此处无 geodata loader；空集 `max == NO_ENTRIES`
/// 恒 false，与 Go `GetOrCreateFromGeoIPRules` 缺数据路径的空 IPSet 行为一致。
pub fn build_optimized_ip_matcher(
    rules: &[IpRule],
) -> Result<Box<dyn IPMatcher>, BuildIPMatcherError> {
    if rules.is_empty() {
        return Err(BuildIPMatcherError::EmptyRules);
    }

    let mut pos_custom: Vec<Cidr> = Vec::new();
    let mut neg_custom: Vec<Cidr> = Vec::new();
    let mut geo_matchers: Vec<HeuristicIPMatcher> = Vec::new();

    for rule in rules {
        match &rule.value {
            Some(pb::ip_rule::Value::Geoip(_)) => {
                geo_matchers.push(HeuristicIPMatcher::from_cidrs(&[]));
            }
            Some(pb::ip_rule::Value::Custom(cidr_rule)) => {
                if let Some(cidr) = &cidr_rule.cidr {
                    if cidr_rule.reverse_match {
                        neg_custom.push(cidr.clone());
                    } else {
                        pos_custom.push(cidr.clone());
                    }
                }
            }
            None => {}
        }
    }

    let mut subs: Vec<HeuristicIPMatcher> = Vec::new();
    if !pos_custom.is_empty() {
        subs.push(HeuristicIPMatcher::from_cidrs(&pos_custom));
    }
    if !neg_custom.is_empty() {
        let mut m = HeuristicIPMatcher::from_cidrs(&neg_custom);
        m.set_reverse(true);
        subs.push(m);
    }
    subs.extend(geo_matchers);

    if subs.is_empty() {
        return Err(BuildIPMatcherError::EmptyRules);
    }

    if subs.len() == 1 {
        let matcher = subs.pop().expect("len==1 guaranteed");
        Ok(Box::new(matcher))
    } else {
        Ok(Box::new(HeuristicMultiIPMatcher::new(subs)))
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
        let mask = if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix)
        };
        let base = a & mask;
        (base, base | !mask)
    }

    fn v6_range_ref(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
        let a = u128::from_be_bytes(addr.octets());
        if prefix == 0 {
            return (0, u128::MAX);
        }
        let mask = if prefix >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix)
        };
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
                }
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
        let cidrs = vec![
            Cidr::new(vec![10, 0, 0, 0], 8),
            Cidr::new(vec![10, 128, 0, 0], 9),
        ];
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
        let cidrs = vec![
            Cidr::new(vec![11, 0, 0, 0], 8),
            Cidr::new(vec![10, 0, 0, 0], 8),
        ];
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

        let v6_only = IPSet::from_cidrs(&[Cidr::new(
            Ipv6Addr::LOCALHOST.octets().to_vec(),
            128,
        )]);
        assert!(v6_only.is_empty_v4());
        assert!(!v6_only.contains_v4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn ipset_duplicate_cidrs() {
        let cidrs = vec![
            Cidr::new(vec![192, 168, 0, 0], 16),
            Cidr::new(vec![192, 168, 0, 0], 16),
        ];
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
            cidrs.push(Cidr::new(
                Ipv4Addr::from(raw).octets().to_vec(),
                prefix as u32,
            ));
        }
        let ipset = IPSet::from_cidrs(&cidrs);
        for w in ipset.ipv4_ranges.windows(2) {
            assert!(
                w[0].1 < w[1].0,
                "ranges must be sorted and disjoint: {:?} then {:?}",
                w[0], w[1]
            );
        }
        assert!(
            ipset.ipv6_ranges.windows(2).all(|w| w[0].1 < w[1].0),
            "ipv6 ranges must be sorted and disjoint"
        );
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

