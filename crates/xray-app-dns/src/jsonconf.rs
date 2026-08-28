//! JSON 配置 → [`DnsServiceConfig`] 桥接。
//!
//! 对应 Go `infra/conf.DNSConfig`（JSON）→ `app/dns/config.go::Config` 的转换。
//! `xray-conf` 把顶层 `dns` 配置作为 `serde_json::Value` 占位序列化为 JSON 字节，
//! 由本模块反序列化为强类型 [`DnsAppConfig`]，再经 [`DnsAppConfig::build`] 构造
//! [`DnsServiceConfig`]（含真实 nameserver clients + 静态 hosts）。
//!
//! ## ponytail 限制
//!
//! - nameserver `address` 为域名时（如 `"dns.google"`），[`new_server`] 仅接受 IP
//!   地址（避免 DNS 引导循环）。域名地址会在 `build` 阶段被跳过并告警；升级路径：
//!   接入 bootstrap resolver 后在此预解析为 IP。
//! - EDNS0 `clientIp` 当前仅存入 `DnsServiceConfig`，不传透到 `new_server` 构造的
//!   Server（`new_server` API 未暴露 client_ip 参数）。

use std::net::IpAddr;
use std::sync::Arc;

use serde::Deserialize;

use crate::config::{IpOption, QueryStrategy, generate_random_tag, ip_option_from_strategy, validate_client_ip_len};
use crate::error::DnsError;
use crate::hosts::{HostMapping, StaticHosts};
use crate::nameserver::{Client, NameServerConfig, new_server};
use crate::server::{DnsServiceConfig, DomainMatcherInfo};
use xray_geodata::matcher::domain::{
    DomainRule as MatcherDomainRule, MphDomainMatcher,
};

/// 顶层 DNS app JSON 配置。对应 Go `infra/conf.DNSConfig`。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DnsAppConfig {
    /// Nameserver 列表（每个含 address/port/skipFallback 等）。
    pub servers: Vec<NameServerJson>,
    /// 静态 hosts：key 可带类型前缀（`domain:` / `full:`），value 为 IP 字符串或数组。
    pub hosts: serde_json::Map<String, serde_json::Value>,
    /// 全局 EDNS0 client IP（字符串形式，如 `"1.2.3.4"`）。
    pub client_ip: Option<String>,
    /// 服务 tag（用于日志）；缺省生成随机 tag。
    pub tag: Option<String>,
    #[serde(rename = "queryStrategy")]
    pub query_strategy: Option<String>,
    /// 禁用 fallback（所有 nameserver 都失败时不再兜底）。
    pub disable_fallback: Option<bool>,
    /// 命中匹配后禁用 fallback。
    pub disable_fallback_if_match: Option<bool>,
    /// 禁用 DNS 缓存。对应 Go `disableCache`。
    #[serde(rename = "disableCache")]
    pub disable_cache: Option<bool>,
    /// 缓存过期后继续提供过期数据。对应 Go `serveStale`。
    #[serde(rename = "serveStale")]
    pub serve_stale: Option<bool>,
    /// 过期数据的 TTL（秒）。对应 Go `serveExpiredTTL`。
    #[serde(rename = "serveExpiredTTL")]
    pub serve_expired_ttl: Option<u32>,
    /// 启用并行查询。对应 Go `enableParallelQuery`。
    #[serde(rename = "enableParallelQuery")]
    pub enable_parallel_query: Option<bool>,
    /// 使用系统 hosts 文件。对应 Go `useSystemHosts`。
    #[serde(rename = "useSystemHosts")]
    pub use_system_hosts: Option<bool>,
}

/// 单个 nameserver JSON 配置。对应 Go `infra/conf.NameServerConfig`。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NameServerJson {
    /// 服务地址（IP / `tcp://` / `tls://` / `https://` / `quic://`）。
    pub address: String,
    /// 端口覆盖（地址已含端口时忽略）。
    pub port: Option<u16>,
    /// 本 server 的 EDNS0 client IP。
    pub client_ip: Option<String>,
    /// 是否跳过 fallback。
    #[serde(rename = "skipFallback")]
    pub skip_fallback: bool,
    /// 自定义超时（毫秒）；0 表示默认 4000ms。
    pub timeout: Option<u32>,
    /// 本 server 的查询策略覆写。
    #[serde(rename = "queryStrategy")]
    pub query_strategy: Option<String>,
    /// 仅解析这些域名时使用本 server。对应 Go `domains`。
    pub domains: Option<Vec<String>>,
    /// 期望返回的 IP 列表（CIDR）。对应 Go `expectedIPs`。
    #[serde(rename = "expectedIPs")]
    pub expected_ips: Option<Vec<String>>,
    /// 不期望返回的 IP 列表（CIDR）。对应 Go `unexpectedIPs`。
    #[serde(rename = "unexpectedIPs")]
    pub unexpected_ips: Option<Vec<String>>,
    /// 本 server 的 tag（路由引用用）。对应 Go `tag`。
    pub tag: Option<String>,
    /// 是否最终查询。对应 Go `finalQuery`。
    #[serde(rename = "finalQuery")]
    pub final_query: Option<bool>,
    /// 本 server 禁用缓存。对应 Go `disableCache`。
    #[serde(rename = "disableCache")]
    pub disable_cache: Option<bool>,
}

impl DnsAppConfig {
    /// 构造 [`DnsServiceConfig`]：解析全局策略 → 构建 clients → 构建 hosts。
    ///
    /// 不可构造的 nameserver（如域名地址）被跳过并告警，而非让整个 dns feature
    /// 注册失败——保持 Go 的「尽力而为」语义。
    pub fn build(self) -> Result<DnsServiceConfig, DnsError> {
        let query_strategy = parse_query_strategy(self.query_strategy.as_deref());
        let base_ip_option = ip_option_from_strategy(query_strategy);

        let client_ip = parse_client_ip(self.client_ip.as_deref())?;
        validate_client_ip_len(client_ip.len())?;

        let datadir = resolve_asset_dir();
        let loader = xray_geodata::loader::GeoDataLoader::new(datadir.clone());

        let mut clients: Vec<Arc<Client>> = Vec::with_capacity(self.servers.len());
        // kvl：聚合 per-nameserver domain 规则（对应 Go dns.go effectiveRules/matcherInfos）。
        let mut all_rules: Vec<MatcherDomainRule> = Vec::new();
        let mut matcher_infos: Vec<DomainMatcherInfo> = Vec::new();
        for ns in &self.servers {
            match build_client(ns, &client_ip, base_ip_option, &datadir) {
                Ok(c) => {
                    let client_idx = clients.len() as u16;
                    clients.push(Arc::new(c));
                    // localhost server 优先本地域（Go localTLDsAndDotlessDomainsRules）。
                    let push_rule = |dt, value: &str, infos: &mut Vec<DomainMatcherInfo>, rules: &mut Vec<MatcherDomainRule>| {
                        infos.push(DomainMatcherInfo { client_idx, domain_rule: value.to_string() });
                        rules.push(MatcherDomainRule::new(dt, value, rules.len() as u32));
                    };
                    if ns.address.trim().eq_ignore_ascii_case("localhost") {
                        for (dt, v) in local_tlds_and_dotless_rules() {
                            push_rule(dt, &v, &mut matcher_infos, &mut all_rules);
                        }
                    }
                    for s in ns.domains.iter().flatten() {
                        match parse_ns_domain_rule(s, &datadir, &loader) {
                            Ok(entries) => {
                                for (dt, v) in entries {
                                    matcher_infos.push(DomainMatcherInfo {
                                        client_idx,
                                        domain_rule: s.clone(),
                                    });
                                    all_rules.push(MatcherDomainRule::new(
                                        dt,
                                        v,
                                        all_rules.len() as u32,
                                    ));
                                }
                            }
                            Err(e) => tracing::warn!(rule = %s, error = %e, "dns: skip bad domain rule"),
                        }
                    }
                }
                Err(e) => {
                    // ponytail: 域名地址需 bootstrap 解析，new_server 暂不支持。
                    // 跳过并告警，避免单个 server 阻断整个 dns feature。
                    tracing::warn!(
                        address = %ns.address,
                        error = %e,
                        "dns: skip unbuildable nameserver"
                    );
                }
            }
        }

        // Go dns.go:167-170：无任何 nameserver 时注入 `localhost` client
        // （NewLocalDNSClient —— nameserver_local.go:51-53，系统 resolver 兜底）。
        // 注意：Go 此路径不走 updateRules，故不加 localTLDs 域名规则。
        if clients.is_empty() {
            match crate::nameserver::local::new_local_name_server() {
                Ok(server) => {
                    clients.push(Arc::new(Client::new(
                        NameServerConfig::default(),
                        base_ip_option,
                        server,
                    )?));
                }
                // Go NewLocalNameServer 不会失败；Rust 系统 resolver 配置不可读时
                // 保持空 clients（查询时返回 EmptyResponse）而非阻断整个 feature。
                Err(e) => tracing::warn!(error = %e, "dns: default localhost client unavailable"),
            }
        }
        let domain_matcher = if all_rules.is_empty() {
            None
        } else {
            match MphDomainMatcher::build(&all_rules) {
                Ok(m) => Some(Box::new(m) as Box<dyn xray_geodata::matcher::domain::DomainMatcher>),
                Err(e) => {
                    tracing::warn!(error = %e, "dns: domain matcher build failed, fallback only");
                    None
                }
            }
        };

        let mut mappings = parse_hosts(&self.hosts)?;
        // 98g：useSystemHosts → 系统 hosts 合并（对应 Go readSystemHosts）
        if self.use_system_hosts.unwrap_or(false) {
            mappings.extend(crate::hosts::read_system_hosts());
        }
        let hosts = StaticHosts::new(mappings)?;

        let tag = self.tag.unwrap_or_else(generate_random_tag);

        Ok(DnsServiceConfig {
            client_ip,
            query_strategy,
            tag,
            hosts,
            clients,
            disable_fallback: self.disable_fallback.unwrap_or(false),
            disable_fallback_if_match: self.disable_fallback_if_match.unwrap_or(false),
            enable_parallel_query: self.enable_parallel_query.unwrap_or(false),
            disable_cache: self.disable_cache.unwrap_or(false),
            serve_stale: self.serve_stale.unwrap_or(false),
            serve_expired_ttl: self.serve_expired_ttl.unwrap_or(0),
            use_system_hosts: self.use_system_hosts.unwrap_or(false),
            domain_matcher,
            matcher_infos,
        })
    }
}

/// 解析查询策略字符串。未知值回退到 `UseIp`（与 Go 默认一致）。
fn parse_query_strategy(s: Option<&str>) -> QueryStrategy {
    match s.map(str::to_ascii_lowercase).as_deref() {
        Some("useip4") => QueryStrategy::UseIp4,
        Some("useip6") => QueryStrategy::UseIp6,
        Some("usesys") => QueryStrategy::UseSys,
        _ => QueryStrategy::UseIp,
    }
}

/// 解析 EDNS0 client IP 字符串为字节（空串 → 空 Vec）。
fn parse_client_ip(s: Option<&str>) -> Result<Vec<u8>, DnsError> {
    match s.filter(|t| !t.is_empty()) {
        None => Ok(Vec::new()),
        Some(text) => {
            let ip: IpAddr = text.parse().map_err(|_| {
                DnsError::Features(xray_features::dns::DnsError::Other(format!(
                    "invalid clientIp: {text}"
                )))
            })?;
            Ok(match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            })
        }
    }
}

/// 把 JSON `port` 注入地址字符串（地址已含端口或 scheme 路径时不重复注入）。
fn build_server_url(address: &str, port: Option<u16>) -> String {
    let Some(p) = port.filter(|&p| p != 0) else {
        return address.to_string();
    };
    if let Some((scheme, rest)) = address.split_once("://") {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if host.contains(':') {
            return address.to_string();
        }
        if path.is_empty() {
            format!("{scheme}://{host}:{p}")
        } else {
            format!("{scheme}://{host}:{p}/{path}")
        }
    } else if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:{p}")
    }
}

/// 从 JSON nameserver 构造 [`Client`]。
fn build_client(
    ns: &NameServerJson,
    global_client_ip: &[u8],
    base_ip_option: IpOption,
    datadir: &std::path::Path,
) -> Result<Client, DnsError> {
    let url = build_server_url(&ns.address, ns.port);
    let server = new_server(&url)?;

    let client_ip = parse_client_ip(ns.client_ip.as_deref())?;
    let client_ip = if client_ip.is_empty() {
        global_client_ip.to_vec()
    } else {
        validate_client_ip_len(client_ip.len())?;
        client_ip
    };

    // 6r0：expectedIPs/unexpectedIPs → IpRule（CIDR + geoip 展开）。
    let expected_ip_rules =
        parse_ns_ip_rules(ns.expected_ips.as_deref().unwrap_or(&[]), datadir)?;
    let unexpected_ip_rules =
        parse_ns_ip_rules(ns.unexpected_ips.as_deref().unwrap_or(&[]), datadir)?;

    let ns_cfg = NameServerConfig {
        client_ip,
        skip_fallback: ns.skip_fallback,
        timeout_ms: ns.timeout.unwrap_or(0),
        query_strategy: ns.query_strategy.as_deref().map(|s| parse_query_strategy(Some(s))),
        tag: ns.tag.clone().unwrap_or_default(),
        final_query: ns.final_query.unwrap_or(false),
        disable_cache: ns.disable_cache,
        serve_stale: None,
        serve_expired_ttl: None,
        expected_ip_rules,
        unexpected_ip_rules,
        ..Default::default()
    };

    Client::new(ns_cfg, base_ip_option, server)
}

/// 资源目录（geosite.dat / geoip.dat 查找路径）。对应 Go `XRAY_LOCATION_ASSET`。
fn resolve_asset_dir() -> std::path::PathBuf {
    std::env::var("XRAY_LOCATION_ASSET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// 本地域 TLD + 无点域名规则（Go `localTLDsAndDotlessDomainsRules`，app/dns/config.go）。
fn local_tlds_and_dotless_rules()
-> Vec<(xray_geodata::matcher::domain::DomainType, &'static str)> {
    use xray_geodata::matcher::domain::DomainType;
    vec![
        (DomainType::Regex, "^[^.]+$"),
        (DomainType::Domain, "local"),
        (DomainType::Domain, "localdomain"),
        (DomainType::Domain, "localhost"),
        (DomainType::Domain, "lan"),
        (DomainType::Domain, "home.arpa"),
        (DomainType::Domain, "example"),
        (DomainType::Domain, "invalid"),
        (DomainType::Domain, "test"),
    ]
}

/// 解析单条 nameserver domain 规则字符串（Go `ParseDomainRule(s, Domain_Substr)`）。
///
/// 返回 `(DomainType, value)`；geosite 条目经 loader 展开为多条（此处返回首条，
/// 展开型多规则由调用方聚合——见 `parse_ns_domain_rule` 内 geosite 分支）。
fn parse_ns_domain_rule(
    s: &str,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> Result<Vec<(xray_geodata::matcher::domain::DomainType, String)>, DnsError> {
    use xray_geodata::matcher::domain::DomainType;
    use xray_geodata::pb::domain_rule::Value as DV;

    let pb_rule = xray_geodata::rule_parser::parse_domain_rule(
        s,
        xray_geodata::geosite::DomainType::Substr,
        datadir,
    )
    .map_err(|e| DnsError::Features(xray_features::dns::DnsError::Other(e.to_string())))?;
    let Some(value) = pb_rule.value else {
        return Ok(Vec::new());
    };
    let to_matcher_type = |t: i32| {
        DomainType::from_i32(t).ok_or_else(|| {
            DnsError::Features(xray_features::dns::DnsError::Other(format!(
                "unknown domain type: {t}"
            )))
        })
    };
    match value {
        DV::Custom(d) => Ok(vec![(to_matcher_type(d.r#type)?, d.value)]),
        DV::Geosite(g) => {
            let file = if g.file.is_empty() { "geosite.dat" } else { &g.file };
            let site = loader
                .load_site_with_attrs(file, &g.code, &g.attrs)
                .map_err(|e| {
                    DnsError::Features(xray_features::dns::DnsError::Other(e.to_string()))
                })?;
            Ok(site
                .domain
                .into_iter()
                .filter_map(|d| {
                    Some((to_matcher_type(d.r#type).ok()?, d.value))
                })
                .collect())
        }
    }
}

/// 解析 nameserver IP 规则字符串列表（CIDR / `!` 反向 / geoip 展开）。
fn parse_ns_ip_rules(
    rules: &[String],
    datadir: &std::path::Path,
) -> Result<Vec<xray_geodata::pb::IpRule>, DnsError> {
    use xray_geodata::pb::ip_rule::Value as IV;

    let mut out = Vec::with_capacity(rules.len());
    for s in rules {
        let r = xray_geodata::rule_parser::parse_ip_rules(
            &[s.clone()],
            datadir,
        )
        .map_err(|e| {
            DnsError::Features(xray_features::dns::DnsError::Other(e.to_string()))
        })?;
        for rule in r {
            // geoip 条目展开为 Custom CIDR 列表（build_optimized_ip_matcher 的 geoip 分支为空 stub）。
            if let Some(IV::Geoip(g)) = rule.value.as_ref() {
                let file = if g.file.is_empty() { "geoip.dat" } else { &g.file };
                let loader = xray_geodata::loader::GeoDataLoader::new(datadir.to_path_buf());
                let geo = loader.load_ip(file, &g.code).map_err(|e| {
                    DnsError::Features(xray_features::dns::DnsError::Other(e.to_string()))
                })?;
                for cidr in geo.cidr {
                    out.push(xray_geodata::pb::IpRule {
                        value: Some(IV::Custom(xray_geodata::pb::CidrRule {
                            cidr: Some(cidr),
                            reverse_match: g.reverse_match,
                        })),
                    });
                }
            } else {
                out.push(rule);
            }
        }
    }
    Ok(out)
}

/// 解析静态 hosts map 为 [`HostMapping`] 列表。
///
/// key 可带类型前缀：`domain:` / `full:` 走精确匹配；其它前缀（`geosite:` / `regexp:`）
/// 需 matcher 支持，当前跳过并告警。value 为 IP 字符串、IP 数组，或域名重定向字符串。
fn parse_hosts(
    hosts: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<HostMapping>, DnsError> {
    let mut mappings = Vec::new();
    for (key, value) in hosts {
        let domain = match key.split_once(':') {
            Some(("domain" | "full", d)) => d.to_ascii_lowercase(),
            Some(_) => {
                tracing::warn!(key = %key, "dns hosts: skip non-exact matcher prefix");
                continue;
            }
            None => key.to_ascii_lowercase(),
        };

        let (ips, proxied) = parse_host_value(value);
        if ips.is_empty() && proxied.is_empty() {
            tracing::warn!(key = %key, "dns hosts: skip entry with no IPs and no redirect");
            continue;
        }
        mappings.push(HostMapping {
            domain,
            ips,
            proxied_domain: proxied,
        });
    }
    Ok(mappings)
}

/// 解析单个 host value：返回 (IP 列表, 域名重定向)。两者互斥（非 IP 串视为重定向）。
fn parse_host_value(v: &serde_json::Value) -> (Vec<IpAddr>, String) {
    match v {
        serde_json::Value::String(s) => parse_one_host_value(s),
        serde_json::Value::Array(arr) => {
            let mut ips = Vec::new();
            for item in arr {
                if let serde_json::Value::String(s) = item {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        ips.push(ip);
                    } else {
                        return (Vec::new(), s.clone());
                    }
                }
            }
            (ips, String::new())
        }
        _ => (Vec::new(), String::new()),
    }
}

fn parse_one_host_value(s: &str) -> (Vec<IpAddr>, String) {
    match s.parse::<IpAddr>() {
        Ok(ip) => (vec![ip], String::new()),
        Err(_) => (Vec::new(), s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_empty_config_injects_localhost_client() {
        // Go dns.go:167-170：无任何 nameserver → 注入 localhost 默认 client
        // （NewLocalDNSClient，系统 resolver 兜底）。
        let cfg: DnsAppConfig = serde_json::from_str("{}").unwrap();
        let built = cfg.build().unwrap();
        // 系统 resolver 配置不可读的极端环境注入失败 → 0；正常环境恰 1。
        assert!(built.clients.len() <= 1, "unexpected client count: {}", built.clients.len());
        if let Some(c) = built.clients.first() {
            assert_eq!(c.server.name(), "localhost");
            assert!(c.server.is_disable_cache());
        }
        assert_eq!(built.query_strategy, QueryStrategy::UseIp);
        assert!(!built.disable_fallback);
        assert!(built.tag.starts_with("xray.system."));
    }

    #[test]
    fn build_with_udp_server_and_hosts() {
        let json = r#"{
            "servers": [{"address": "8.8.8.8", "port": 53}],
            "hosts": {"example.com": "1.2.3.4", "domain:test.com": ["10.0.0.1", "10.0.0.2"]},
            "queryStrategy": "UseIP4",
            "tag": "my_dns"
        }"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        assert_eq!(built.clients.len(), 1);
        assert_eq!(built.query_strategy, QueryStrategy::UseIp4);
        assert_eq!(built.tag, "my_dns");
        // hosts lookup 走 StaticHosts::lookup，这里只验证不 panic。
    }

    #[test]
    fn build_skips_domain_address_server() {
        let json = r#"{"servers": [{"address": "dns.google"}]}"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        // 域名地址不可构造 → 跳过；clients 落空后同样触发 localhost 兜底注入
        // （Go：New() 在 clients 循环之后判空注入）。
        assert!(built.clients.len() <= 1);
        if let Some(c) = built.clients.first() {
            assert_eq!(c.server.name(), "localhost");
        }
    }

    #[test]
    fn parse_query_strategy_variants() {
        assert_eq!(parse_query_strategy(None), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(Some("UseIP")), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(Some("useip4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("UseIP6")), QueryStrategy::UseIp6);
        assert_eq!(parse_query_strategy(Some("UseSys")), QueryStrategy::UseSys);
        assert_eq!(parse_query_strategy(Some("bogus")), QueryStrategy::UseIp);
    }

    #[test]
    fn build_server_url_injects_port() {
        assert_eq!(build_server_url("1.1.1.1", Some(53)), "1.1.1.1:53");
        assert_eq!(build_server_url("1.1.1.1:5353", Some(53)), "1.1.1.1:5353");
        assert_eq!(
            build_server_url("https://8.8.8.8/dns-query", Some(443)),
            "https://8.8.8.8:443/dns-query"
        );
        assert_eq!(build_server_url("tls://1.1.1.1", None), "tls://1.1.1.1");
        assert_eq!(build_server_url("8.8.8.8", Some(0)), "8.8.8.8");
    }

    /// kvl：per-nameserver domains 路由——命中域名的 server 优先。
    #[test]
    fn build_domains_rule_routes_matching_domain_first() {
        let json = r#"{
            "servers": [
                {"address": "8.8.8.8", "tag": "fallback"},
                {"address": "1.1.1.1", "tag": "cn", "domains": ["domain:cn.test"]}
            ]
        }"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let svc = crate::server::DnsService::new(cfg.build().unwrap());

        // 命中 domain:cn.test → cn client 优先。
        let sorted = svc.sort_clients("www.cn.test");
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].tag, "cn");

        // 未命中 → 按配置顺序 fallback。
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted[0].tag, "fallback");
    }

    /// kvl：localhost server 自动附加本地域规则（Go localTLDsAndDotlessDomainsRules）。
    #[test]
    fn build_localhost_server_prioritizes_local_domains() {
        let json = r#"{
            "servers": [
                {"address": "8.8.8.8", "tag": "remote"},
                {"address": "localhost", "tag": "local"}
            ]
        }"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let svc = crate::server::DnsService::new(cfg.build().unwrap());

        // 无点域名（^[^.]+$）与 *.lan 命中 local client。
        let sorted = svc.sort_clients("myhost");
        assert_eq!(sorted[0].tag, "local");
        let sorted = svc.sort_clients("printer.lan");
        assert_eq!(sorted[0].tag, "local");
        // 普通域名不命中。
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted[0].tag, "remote");
    }
}
