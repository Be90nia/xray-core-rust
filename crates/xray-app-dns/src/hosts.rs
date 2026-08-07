//! 静态 hosts 表。对应 Go `app/dns/hosts.go`。
//!
//! 业务核心独立可测，仅依赖 `xray_geodata::matcher::domain::DomainMatcher` trait。

use std::net::IpAddr;

use xray_common::net::address::Address;
use xray_features::dns::DnsError as FeaturesDnsError;
use xray_geodata::matcher::domain::DomainMatcher;

use crate::config::IpOption;
use crate::error::DnsError;

/// 一条 hosts 映射记录。对应 Go `Config_HostMapping` proto message。
///
/// `proxied_domain` 非空时：
/// - 以 `#` 开头后接数字：表示 RCode 错误码。
/// - 否则为重定向目标域名。
#[derive(Debug, Clone)]
pub struct HostMapping {
    /// 匹配的源域名。
    pub domain: String,
    /// 匹配返回的 IP 列表（与 `proxied_domain` 互斥）。
    pub ips: Vec<IpAddr>,
    /// 重定向域名或 `#<rcode>`。
    pub proxied_domain: String,
}

/// 静态 hosts 表。对应 Go `StaticHosts`。
///
/// 根据 `DomainMatcher` 的 rule_id 索引到 `responses`。
pub struct StaticHosts {
    /// 与 matcher rule_id 对齐的响应数组。
    responses: Vec<Vec<ResponseEntry>>,
    matcher: Option<Box<dyn xray_geodata::matcher::domain::DomainMatcher>>,
}

/// 一条 hosts 响应：IP 或域名重定向或 RCode。
#[derive(Debug, Clone)]
enum ResponseEntry {
    Ip(IpAddr),
    Domain(String),
    RCode(u16),
}

impl StaticHosts {
    /// 从 hosts 映射列表构造。对应 Go `NewStaticHosts`。
    ///
    /// `mappings` 为空返回空实例（matcher 为 `None`，`Lookup` 始终返回空）。
    pub fn new(mappings: Vec<HostMapping>) -> Result<Self, DnsError> {
        if mappings.is_empty() {
            return Ok(Self {
                responses: Vec::new(),
                matcher: None,
            });
        }

        // 构造响应数组。
        let mut responses: Vec<Vec<ResponseEntry>> = Vec::with_capacity(mappings.len());
        for m in &mappings {
            let mut reps = Vec::new();
            if !m.proxied_domain.is_empty() {
                if let Some(rcode_str) = m.proxied_domain.strip_prefix('#') {
                    let rcode: u16 = rcode_str
                        .parse()
                        .map_err(|_| {
                            DnsError::Features(FeaturesDnsError::Other(format!(
                                "invalid rcode in proxied_domain: {}",
                                m.proxied_domain
                            )))
                        })?;
                    reps.push(ResponseEntry::RCode(rcode));
                } else {
                    reps.push(ResponseEntry::Domain(m.proxied_domain.clone()));
                }
            } else {
                for ip in &m.ips {
                    reps.push(ResponseEntry::Ip(*ip));
                }
            }
            responses.push(reps);
        }

        // 构造 matcher。
        // 当前实现：xray-geodata 未提供从多规则一次性构造 DomainMatcher 的 API，
        // ponytail: 在内存里构造 `FullMatcher` 的聚合，单规则查表。
        // TODO: 等 xray-geodata 暴露 `DomainRegistry::build_many` 或类似 API 后替换。
        let matcher: Box<dyn DomainMatcher> = Box::new(InMemoryMatcher {
            rules: mappings
                .into_iter()
                .enumerate()
                .map(|(i, m)| (m.domain.to_lowercase(), i as u32))
                .collect(),
        });

        Ok(Self {
            responses,
            matcher: Some(matcher),
        })
    }

    /// 查询域名，返回 IP/重定向域名或 RCode 错误。
    ///
    /// 对应 Go `(*StaticHosts).Lookup`。递归最大 5 次防止 A->B->A 循环。
    pub fn lookup(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<Vec<Address>, DnsError> {
        let Some(m) = &self.matcher else {
            return Ok(Vec::new());
        };
        let m: &dyn DomainMatcher = m.as_ref();
        self.lookup_inner(domain, option, 5, m)
    }

    fn lookup_inner(
        &self,
        domain: &str,
        option: IpOption,
        max_depth: i32,
        matcher: &dyn DomainMatcher,
    ) -> Result<Vec<Address>, DnsError> {
        let lower = domain.to_lowercase();
        let matched_ids = matcher.match_domain(&lower);

        let mut entries: Vec<&ResponseEntry> = Vec::new();
        for id in matched_ids {
            let idx = id as usize;
            if idx < self.responses.len() {
                for e in &self.responses[idx] {
                    entries.push(e);
                }
            }
        }

        if entries.is_empty() {
            return Ok(Vec::new());
        }

        // 先处理首个 RCode（Go 行为：单返回匹配返回 rcode）。
        for e in &entries {
            if let ResponseEntry::RCode(code) = e {
                return Err(DnsError::from_rcode(*code));
            }
        }

        // 单个域名响应：递归 unwrap。
        if entries.len() == 1 {
            if let ResponseEntry::Domain(d) = entries[0] {
                if max_depth > 0 {
                    let inner = self.lookup_inner(d, option, max_depth - 1, matcher)?;
                    if !inner.is_empty() {
                        return Ok(inner);
                    }
                }
                // unwrap 失败：返回原域名。
                return Ok(vec![Address::Domain(d.clone())]);
            }
        }

        // 过滤 IP。
        Ok(filter_ip_entries(&entries, option))
    }
}

/// 按 IPOption 过滤 IP（同 Go `filterIP`）。
fn filter_ip_entries(entries: &[&ResponseEntry], option: IpOption) -> Vec<Address> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if let ResponseEntry::Ip(ip) = e {
            let keep = match ip {
                IpAddr::V4(_) => option.ipv4_enable,
                IpAddr::V6(_) => option.ipv6_enable,
            };
            if keep {
                out.push(Address::ipv4_or_v6(*ip));
            }
        }
    }
    out
}

/// Hash 域名 matcher（O(1) exact match + 大小写不敏感）。
///
/// 对齐 Go 的 `MphDomainMatcher` 语义但简化为 exact match only
///（hosts 表不支持 wildcard，对齐 Go `StaticHosts` 行为）。
struct InMemoryMatcher {
    rules: std::collections::HashMap<String, u32>,
}

impl DomainMatcher for InMemoryMatcher {
    fn match_domain(&self, input: &str) -> Vec<u32> {
        self.rules.get(input).copied().into_iter().collect()
    }

    fn match_any(&self, input: &str) -> bool {
        self.rules.contains_key(input)
    }
}

// Address 构造辅助。
trait AddressExt {
    fn ipv4_or_v6(ip: IpAddr) -> Self;
}
impl AddressExt for Address {
    fn ipv4_or_v6(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v) => Self::IPv4(v),
            IpAddr::V6(v) => Self::IPv6(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mapping_ip(domain: &str, ips: &[&str]) -> HostMapping {
        let ips: Vec<IpAddr> = ips
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        HostMapping {
            domain: domain.to_string(),
            ips,
            proxied_domain: String::new(),
        }
    }

    fn mapping_redirect(domain: &str, target: &str) -> HostMapping {
        HostMapping {
            domain: domain.to_string(),
            ips: Vec::new(),
            proxied_domain: target.to_string(),
        }
    }

    #[test]
    fn empty_mappings_returns_empty_lookup() {
        let h = StaticHosts::new(Vec::new()).unwrap();
        let out = h.lookup("anything.com", IpOption::all()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn lookup_returns_ips_for_known_domain() {
        let h = StaticHosts::new(vec![mapping_ip("example.com", &["1.2.3.4"])]).unwrap();
        let out = h.lookup("example.com", IpOption::all()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].is_ipv4());
    }

    #[test]
    fn lookup_case_insensitive() {
        let h = StaticHosts::new(vec![mapping_ip("example.com", &["1.2.3.4"])]).unwrap();
        let out = h.lookup("EXAMPLE.COM", IpOption::all()).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn lookup_returns_empty_for_unknown_domain() {
        let h = StaticHosts::new(vec![mapping_ip("example.com", &["1.2.3.4"])]).unwrap();
        let out = h.lookup("other.com", IpOption::all()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn lookup_filters_by_ip_option() {
        let h = StaticHosts::new(vec![mapping_ip("example.com", &["1.2.3.4", "::1"])]).unwrap();
        let v4_only = IpOption {
            ipv4_enable: true,
            ipv6_enable: false,
            fake_enable: true,
        };
        let out = h.lookup("example.com", v4_only).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].is_ipv4());
    }

    #[test]
    fn lookup_unwraps_redirect_domain() {
        let h = StaticHosts::new(vec![
            mapping_redirect("alias.com", "target.com"),
            mapping_ip("target.com", &["9.9.9.9"]),
        ])
        .unwrap();
        let out = h.lookup("alias.com", IpOption::all()).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            Address::IPv4(v) => assert_eq!(*v, Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn lookup_returns_rcode_when_hash_prefix() {
        let h = StaticHosts::new(vec![HostMapping {
            domain: "blocked.com".to_string(),
            ips: Vec::new(),
            proxied_domain: "#3".to_string(), // NX_DOMAIN
        }])
        .unwrap();
        match h.lookup("blocked.com", IpOption::all()) {
            Err(DnsError::RCodeError(3)) => {}
            other => panic!("expected RCodeError(3), got {other:?}"),
        }
    }

    #[test]
    fn lookup_keeps_redirect_domain_when_unwrap_fails() {
        let h =
            StaticHosts::new(vec![mapping_redirect("alias.com", "unknown.com")]).unwrap();
        let out = h.lookup("alias.com", IpOption::all()).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            Address::Domain(d) => assert_eq!(d, "unknown.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }
}
