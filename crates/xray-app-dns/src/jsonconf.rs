//! JSON 配置 → [`DnsServiceConfig`] 桥接。
//!
//! 对应 Go `infra/conf.DNSConfig`（JSON）→ `app/dns/config.go::Config` 的转换。
//! `xray-conf` 把顶层 `dns` 配置作为 `serde_json::Value` 占位序列化为 JSON 字节，
//! 由本模块反序列化为强类型 [`DnsAppConfig`]，再经 [`DnsAppConfig::build`] 构造
//! [`DnsServiceConfig`]（含真实 nameserver clients + 静态 hosts）。
//!
//! ## bd mcpo 后的形态
//!
//! - nameserver `address` 接受域名（如 `"https://dns.google"`）：不再启动期
//!   bootstrap 钉死 IP。经路由出站时由路由系统/outbound 解析；直连兜底每查询
//!   经 `dial::HostResolver` 现解析（上游地址变更后新查询用新 IP）。
//! - nameserver 构造失败（未知 scheme 等）→ `build` 返回错误（Go NewClient
//!   失败 → 实例启动失败语义），不再跳过。
//! - EDNS0 `clientIp` 经 `new_server_with_config` 全量透传到 Server 构造
//!   （4ah3 接通；`new_server` 薄包装保留默认字段行为）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Deserialize;

use crate::config::{IpOption, QueryStrategy, generate_random_tag, ip_option_from_strategy, validate_client_ip_len};
use crate::error::DnsError;
use crate::hosts::{HostMapping, StaticHosts};
use crate::nameserver::{Client, NameServerConfig, new_server_with_config};
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
    /// 全局 EDNS0 client IP（字符串形式，如 `"1.2.3.4"`）。Go tag `clientIp`
    /// （infra/conf/dns.go:163）；此前缺 rename，camelCase 配置被静默忽略（8kha 修复）。
    #[serde(rename = "clientIp")]
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
    /// 本 server 的 EDNS0 client IP。Go tag `clientIp`（infra/conf/dns.go:21）；
    /// 此前缺 rename，camelCase 配置被静默忽略（8kha 修复——policy key 依赖此字段）。
    #[serde(rename = "clientIp")]
    pub client_ip: Option<String>,
    /// 是否跳过 fallback。
    #[serde(rename = "skipFallback")]
    pub skip_fallback: bool,
    /// 自定义超时（毫秒）；0 表示默认 4000ms。对应 Go `timeoutMs`
    /// （infra/conf/dns.go:29；此前缺 rename，Go 键被静默丢弃恒 4000ms，
    /// `timeout` 仅作 Rust 旧配置别名保留）。
    #[serde(rename = "timeoutMs", alias = "timeout")]
    pub timeout: Option<u32>,
    /// 本 server 的查询策略覆写。
    #[serde(rename = "queryStrategy")]
    pub query_strategy: Option<String>,
    /// 仅解析这些域名时使用本 server。对应 Go `domains`。
    pub domains: Option<Vec<String>>,
    /// 期望返回的 IP 列表（CIDR）。对应 Go `expectedIPs`。
    #[serde(rename = "expectedIPs")]
    pub expected_ips: Option<Vec<String>>,
    /// 期望 IP 列表旧名（`expectedIPs` 为空时回填）。对应 Go `expectIPs`
    /// （infra/conf/dns.go:26、dns.go:94-96）。
    #[serde(rename = "expectIPs")]
    pub expect_ips: Option<Vec<String>>,
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
    /// 是否优先解析（本 server 命中 expectedIPs 时强制启用）。对应 Go `NameServer.ActPrior`。
    #[serde(rename = "actPrior")]
    pub act_prior: Option<bool>,
    /// 是否降级解析（本 server 命中 unexpectedIPs 时强制启用）。对应 Go `NameServer.ActUnprior`。
    #[serde(rename = "actUnprior")]
    pub act_unprior: Option<bool>,
    /// 策略 ID。供上游派生 hash（独立 issue 8kha）。对应 Go proto `NameServer.policyID`。
    #[serde(rename = "policyID")]
    pub policy_id: Option<u32>,
    /// 缓存过期后继续提供过期数据。对应 Go `serveStale`。
    #[serde(rename = "serveStale")]
    pub serve_stale: Option<bool>,
    /// 过期数据可服务的负 TTL（秒）。对应 Go `serveExpiredTTL`。
    #[serde(rename = "serveExpiredTTL")]
    pub serve_expired_ttl: Option<u32>,
    /// 负缓存 TTL（秒）；None/0 = 禁用。Rust 内部 cache 字段，Go 端无对应 JSON 字段。
    #[serde(rename = "negativeTtlSecs")]
    pub negative_ttl_secs: Option<u32>,
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
        // 8kha：policy_id = 8 元组等价类的顺序编号。对应 Go `buildPolicyID`
        // （infra/conf/dns.go:288-352）：规范化 key → map 去重，`nextPolicyID`
        // 从 1 递增；相同元组复用同 id。非 hash（Go 语义如此），消费端
        // `make_groups` 仅按 id 相等分组。
        let mut policy_map: HashMap<String, u32> = HashMap::new();
        let mut next_policy_id: u32 = 1;
        for ns in &self.servers {
            // JSON `policyID` 非零为手动覆盖（4ah3 钦定扩展，Go 无此字段）；
            // 否则用派生值。
            let policy_id = match ns.policy_id.filter(|&v| v != 0) {
                Some(v) => v,
                None => *policy_map.entry(policy_key(ns)).or_insert_with(|| {
                    let id = next_policy_id;
                    next_policy_id += 1;
                    id
                }),
            };
            // Go nameserver.go:150-153：NewClient 失败（nameserver 构造/matcher
            // 构建等）→ NewClient 返回错误 → dns app 整体启动失败，而非跳过。
            let c = build_client(ns, &client_ip, base_ip_option, &datadir, policy_id)?;
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
                // Go infra/conf/dns.go:89-92 ParseDomainRules 失败 → 整体报错
                // 启动失败。修复前 warn+skip 静默丢规则 → domain 限定失效，
                // server 退化全域名 fallback（bd wmdn③）。
                let entries = parse_ns_domain_rule(s, &datadir, &loader).map_err(|e| {
                    DnsError::Features(xray_features::dns::DnsError::Other(format!(
                        "parse dns domain rule {s}: {e}"
                    )))
                })?;
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

        let mut mappings = parse_hosts(&self.hosts, &datadir, &loader)?;
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
///
/// 别名表完整对齐 Go `resolveQueryStrategy`（infra/conf/dns.go:381-394）：
/// - `UseIP`：useip / use_ip / use-ip
/// - `UseIPv4`：useip4 / useipv4 / use_ip4 / use_ipv4 / use_ip_v4 / use-ip4 /
///   use-ipv4 / use-ip-v4
/// - `UseIPv6`：useip6 / useipv6 / use_ip6 / use_ipv6 / use_ip_v6 / use-ip6 /
///   use-ipv6 / use-ip-v6
/// - `UseSys`：usesys / usesystem / use_sys / use_system / use-sys / use-system
/// `Lookup` 不在 Go 别名表内——保留为未知。
fn parse_query_strategy(s: Option<&str>) -> QueryStrategy {
    match s.map(str::to_ascii_lowercase).as_deref() {
        Some("useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4"
            | "use-ip4" | "use-ipv4" | "use-ip-v4") => QueryStrategy::UseIp4,
        Some("useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6"
            | "use-ip6" | "use-ipv6" | "use-ip-v6") => QueryStrategy::UseIp6,
        Some("usesys" | "usesystem" | "use_sys" | "use_system"
            | "use-sys" | "use-system") => QueryStrategy::UseSys,
        Some("useip" | "use_ip" | "use-ip") => QueryStrategy::UseIp,
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
///
/// `derived_policy_id` 为上游按 8 元组派生的策略 id（`build` 循环）；
/// JSON `policyID` 非零时覆盖之（Go 无此字段，见 `build`）。
fn build_client(
    ns: &NameServerJson,
    global_client_ip: &[u8],
    base_ip_option: IpOption,
    datadir: &std::path::Path,
    derived_policy_id: u32,
) -> Result<Client, DnsError> {
    let client_ip = parse_client_ip(ns.client_ip.as_deref())?;
    let client_ip = if client_ip.is_empty() {
        global_client_ip.to_vec()
    } else {
        validate_client_ip_len(client_ip.len())?;
        client_ip
    };
    // bd mcpo：域名地址（如 `tls://dns.example.com`）不再启动期 bootstrap 钉死 IP，
    // 直接把域名传给 nameserver——经路由出站时由路由系统解析，直连兜底每查询
    // 现解析（上游地址变更后新查询用新 IP）。
    let url = build_server_url(&ns.address, ns.port);

    // 6r0：expectedIPs/unexpectedIPs → IpRule（CIDR + geoip 展开）。
    // expectedIPs 为空时回填 expectIPs（Go dns.go:94-96，policy key 同读回填值）。
    // Go infra/conf/dns.go:98-116："*" 哨兵剥离并推导 actPrior/actUnprior
    // （此前 "*" 不剥离，混合列表变硬过滤且优先/降级语义丢失）。
    let (expected_entries, star_prior) =
        strip_star_sentinel(effective_expected_ips(ns));
    let (unexpected_entries, star_unprior) =
        strip_star_sentinel(ns.unexpected_ips.as_deref().unwrap_or(&[]));
    let expected_ip_rules = parse_ns_ip_rules(&expected_entries, datadir)?;
    let unexpected_ip_rules = parse_ns_ip_rules(&unexpected_entries, datadir)?;

    let ns_cfg = NameServerConfig {
        client_ip,
        skip_fallback: ns.skip_fallback,
        timeout_ms: ns.timeout.unwrap_or(0),
        query_strategy: ns.query_strategy.as_deref().map(|s| parse_query_strategy(Some(s))),
        tag: ns.tag.clone().unwrap_or_default(),
        final_query: ns.final_query.unwrap_or(false),
        disable_cache: ns.disable_cache,
        act_prior: ns.act_prior.unwrap_or(false) || star_prior,
        act_unprior: ns.act_unprior.unwrap_or(false) || star_unprior,
        negative_ttl_secs: ns.negative_ttl_secs,
        policy_id: ns.policy_id.filter(|&v| v != 0).unwrap_or(derived_policy_id),
        expected_ip_rules,
        unexpected_ip_rules,
        ..Default::default()
    };

    // 4ah3：ns_cfg 全量经 new_server_with_config 流入具体 nameserver 构造
    // （Go nameserver.go NewServer 收全量 proto——cache/timeout/clientIp 不丢字段）。
    let (server, ns_cfg) = new_server_with_config(&url, ns_cfg)?;
    Client::new(ns_cfg, base_ip_option, server)
}

/// Go dns.go:94-96：`expectedIPs` 为空时回填 `expectIPs`（`Build` 内改写，
/// `buildPolicyID` 与 IP 规则解析均读回填后的值）。
fn effective_expected_ips(ns: &NameServerJson) -> &[String] {
    const EMPTY: &[String] = &[];
    let expected = ns.expected_ips.as_deref().unwrap_or(EMPTY);
    if expected.is_empty() {
        ns.expect_ips.as_deref().unwrap_or(EMPTY)
    } else {
        expected
    }
}

/// Go infra/conf/dns.go:98-116：列表中 `"*"` 哨兵剥离，返回（剥离后列表, 是否含 *）。
fn strip_star_sentinel(list: &[String]) -> (Vec<String>, bool) {
    let mut out = Vec::with_capacity(list.len());
    let mut starred = false;
    for s in list {
        if s == "*" {
            starred = true;
        } else {
            out.push(s.clone());
        }
    }
    (out, starred)
}

/// 构造 policy 等价键。对应 Go `buildPolicyID` 的 key 段构造
/// （infra/conf/dns.go:291-343）：`client|skip|qs|tag|domains|expected|expect|unexpected`
/// 8 段，`|` 分隔；列表段元素 trim + 小写 + 排序后逗号连接，空列表为 `=[]`；
/// `*` 不剥离（dns.go:99-106 的 actPrior 剥离只写局部变量，不影响 key）；
/// `client` 段用 per-server JSON 值的规范化 IP 形式（全局 `clientIp` 不参与）。
fn policy_key(ns: &NameServerJson) -> String {
    fn write_list(sb: &mut String, tag: &str, lst: &[String]) {
        sb.push_str(tag);
        if lst.is_empty() {
            sb.push_str("=[]|");
            return;
        }
        let mut cp: Vec<String> = lst.iter().map(|s| s.trim().to_lowercase()).collect();
        cp.sort();
        sb.push('=');
        sb.push_str(&cp.join(","));
        sb.push('|');
    }

    let mut sb = String::new();
    match ns.client_ip.as_deref().filter(|t| !t.is_empty()) {
        Some(text) => {
            // Go 写 net.Address 规范化形式（IP canonical，如 v6 压缩小写）。
            let canon = text
                .parse::<IpAddr>()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| text.to_string());
            sb.push_str("client=");
            sb.push_str(&canon);
            sb.push('|');
        }
        None => sb.push_str("client=none|"),
    }
    sb.push_str(if ns.skip_fallback { "skip=1|" } else { "skip=0|" });
    sb.push_str("qs=");
    sb.push_str(&ns.query_strategy.as_deref().unwrap_or_default().trim().to_lowercase());
    sb.push('|');
    sb.push_str("tag=");
    sb.push_str(&ns.tag.as_deref().unwrap_or_default().trim().to_lowercase());
    sb.push('|');
    write_list(&mut sb, "domains", ns.domains.as_deref().unwrap_or(&[]));
    write_list(&mut sb, "expected", effective_expected_ips(ns));
    write_list(&mut sb, "expect", ns.expect_ips.as_deref().unwrap_or(&[]));
    write_list(&mut sb, "unexpected", ns.unexpected_ips.as_deref().unwrap_or(&[]));
    sb
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

/// 解析单条 domain 规则字符串。`default_type`：ns domains 用 Substr
/// （Go `ParseDomainRule(s, Domain_Substr)`），hosts key 用 Full。
///
/// 返回 `(DomainType, value)`；geosite 条目经 loader 展开为多条。
fn parse_domain_rule_entries(
    s: &str,
    default_type: xray_geodata::geosite::DomainType,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> Result<Vec<(xray_geodata::matcher::domain::DomainType, String)>, DnsError> {
    use xray_geodata::matcher::domain::DomainType;
    use xray_geodata::pb::domain_rule::Value as DV;

    let pb_rule = xray_geodata::rule_parser::parse_domain_rule(s, default_type, datadir)
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

/// ns `domains` 条目（Go `ParseDomainRule(s, Domain_Substr)`）。
fn parse_ns_domain_rule(
    s: &str,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> Result<Vec<(xray_geodata::matcher::domain::DomainType, String)>, DnsError> {
    parse_domain_rule_entries(s, xray_geodata::geosite::DomainType::Substr, datadir, loader)
}

/// hosts key（Go `ParseDomainRule(rule, Domain_Full)`，infra/conf/dns.go:258）。
fn parse_hosts_key(
    s: &str,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> Result<Vec<(xray_geodata::matcher::domain::DomainType, String)>, DnsError> {
    parse_domain_rule_entries(s, xray_geodata::geosite::DomainType::Full, datadir, loader)
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
/// 对齐 Go `HostsWrapper.Build`（infra/conf/dns.go:254-266）：key 全部走
/// `geodata.ParseDomainRule(rule, Domain_Full)` —— 无前缀 = Full 精确匹配，
/// `domain:`/`full:`/`regexp:`/`keyword:`/`geosite:`/`ext:` 全前缀均支持
/// （此前仅 domain:/full:，其余前缀告警跳过 = 静默失效）。value 为 IP 字符串、
/// IP 数组，或域名重定向字符串。
fn parse_hosts(
    hosts: &serde_json::Map<String, serde_json::Value>,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> Result<Vec<HostMapping>, DnsError> {
    let mut mappings = Vec::new();
    for (key, value) in hosts {
        // Go infra/conf/dns.go:258-261/444-447 hosts key 解析失败 → 整体报错
        // 启动失败。修复前 warn+skip 静默丢映射（bd wmdn③）。
        let matcher_rules = parse_hosts_key(key, datadir, loader).map_err(|e| {
            DnsError::Features(xray_features::dns::DnsError::Other(format!(
                "parse dns hosts key {key}: {e}"
            )))
        })?;
        let (ips, proxied) = parse_host_value(value);
        if ips.is_empty() && proxied.is_empty() {
            tracing::warn!(key = %key, "dns hosts: skip entry with no IPs and no redirect");
            continue;
        }
        mappings.push(HostMapping {
            domain: key.to_ascii_lowercase(),
            ips,
            proxied_domain: proxied,
            matcher_rules,
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

    /// bd mcpo：域名 NS 运行期解析——域名地址 server 正常构造（不再跳过），
    /// DoH 经 443 默认端口 + /dns-query 路径。
    #[test]
    fn build_accepts_domain_address_server() {
        // workspace feature unification 可能同时启用 ring+aws-lc-rs 两个
        // CryptoProvider，rustls 进程级自动裁决会 panic；测试显式安装 ring。
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let json = r#"{"servers": [{"address": "https://dns.google"}]}"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        assert_eq!(built.clients.len(), 1, "domain nameserver must build");
        assert!(built.clients[0].server.name().starts_with("DoH:"));
    }

    /// bd mcpo：bootstrap 失败语义对齐 Go——不可构造的 nameserver 使
    /// build() 返回错误（Go NewClient 失败 → 实例启动失败），而非静默跳过。
    #[test]
    fn build_propagates_unbuildable_nameserver_error() {
        let json = r#"{"servers": [{"address": "foo://8.8.8.8"}]}"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.build().is_err(), "unknown scheme must fail the build");
    }

    /// bd wmdn③ 回归：nameserver domains 规则解析失败 → 启动硬错（Go
    /// infra/conf/dns.go:89-92），不再 warn+skip 静默丢规则。
    #[test]
    fn build_hard_fails_on_bad_nameserver_domain_rule() {
        // 不存在的 geosite code → parse_ns_domain_rule 必败。
        let json = r#"{
            "servers": [{"address": "8.8.8.8", "domains": ["geosite:zz-no-such-code-xyz"]}]
        }"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.build().is_err(), "bad domains rule must fail the build");
    }

    /// bd wmdn③ 回归：hosts key 解析失败 → 启动硬错（Go
    /// infra/conf/dns.go:258-261/444-447），不再 warn+skip 静默丢映射。
    #[test]
    fn build_hard_fails_on_bad_hosts_key() {
        let json = r#"{
            "servers": [{"address": "8.8.8.8"}],
            "hosts": {"geosite:zz-no-such-code-xyz": "1.2.3.4"}
        }"#;
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.build().is_err(), "bad hosts key must fail the build");
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

    /// 4ah3：6 字段（actPrior/actUnprior/policyID/serveStale/serveExpiredTTL/negativeTtlSecs）
    /// JSON 反序列化正确（含 camelCase rename + Option 默认 None）。
    #[test]
    fn nameserver_json_6_extra_fields_roundtrip() {
        let json = r#"{
            "address": "1.1.1.1",
            "actPrior": true,
            "actUnprior": false,
            "policyID": 42,
            "serveStale": true,
            "serveExpiredTTL": 60,
            "negativeTtlSecs": 30
        }"#;
        let ns: NameServerJson = serde_json::from_str(json).unwrap();
        assert_eq!(ns.act_prior, Some(true));
        assert_eq!(ns.act_unprior, Some(false));
        assert_eq!(ns.policy_id, Some(42));
        assert_eq!(ns.serve_stale, Some(true));
        assert_eq!(ns.serve_expired_ttl, Some(60));
        assert_eq!(ns.negative_ttl_secs, Some(30));

        // 缺省：6 字段全部 None（serde(default)）。
        let empty: NameServerJson = serde_json::from_str(r#"{"address": "1.1.1.1"}"#).unwrap();
        assert_eq!(empty.act_prior, None);
        assert_eq!(empty.act_unprior, None);
        assert_eq!(empty.policy_id, None);
        assert_eq!(empty.serve_stale, None);
        assert_eq!(empty.serve_expired_ttl, None);
        assert_eq!(empty.negative_ttl_secs, None);
    }

    /// 4ah3：6 字段透传到 NameServerConfig（最终落 Client.policy_id/act_prior/act_unprior +
    /// Server 内 cache 的 serve_stale/serve_expired_ttl/negative_ttl_secs）。
    #[test]
    fn build_client_propagates_6_extra_fields() {
        use crate::nameserver::Client;
        let json = r#"{
            "address": "1.1.1.1",
            "actPrior": true,
            "actUnprior": true,
            "policyID": 7,
            "serveStale": true,
            "serveExpiredTTL": 45,
            "negativeTtlSecs": 15,
            "disableCache": true
        }"#;
        let ns: NameServerJson = serde_json::from_str(json).unwrap();
        let datadir = std::path::Path::new("");
        let client: Client =
            build_client(&ns, &[], crate::config::IpOption::all(), datadir, 0).unwrap();

        // Client 公开字段。
        assert_eq!(client.policy_id, 7);
        assert!(client.act_prior);
        assert!(client.act_unprior);

        // Server 公开接口：is_disable_cache 验证 disableCache 全链路接线
        // （JSON → build_client → new_server_with_config → UdpNameServer cache）。
        // serveStale/serveExpiredTTL/negativeTtlSecs 落 Server 内 CacheController，
        // dyn Server 不暴露 cache——字段级断言见 udp.rs from_config 测试。
        assert!(client.server.is_disable_cache());
        assert!(client.server.name().starts_with("UDP:"));
    }

    /// 8kha：构建 DNS 配置并返回各 client 的 policy_id（按 servers 顺序）。
    fn policy_ids(json: &str) -> Vec<u32> {
        let cfg: DnsAppConfig = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        built.clients.iter().map(|c| c.policy_id).collect()
    }

    /// 8kha：8 元组相同（address 不参与 key）→ 复用同 id；规范化（大小写/
    /// 空白/列表序）后等价视为相同；id 从 1 顺序递增（Go buildPolicyID，
    /// infra/conf/dns.go:288-352，非 hash）。
    #[test]
    fn policy_id_same_tuple_shares_sequential_id() {
        let ids = policy_ids(
            r#"{
            "servers": [
                {"address": "8.8.8.8", "tag": "dns-a", "queryStrategy": "UseIPv4",
                 "domains": ["b.com", "a.com"]},
                {"address": "1.1.1.1", "tag": "DNS-A ", "queryStrategy": " useipv4 ",
                 "domains": ["A.com", " b.com"]},
                {"address": "9.9.9.9", "tag": "other"}
            ]
        }"#,
        );
        assert_eq!(ids, vec![1, 1, 2]);
    }

    /// 8kha：8 元组任一字段不同 → 不同 id（client/skip/qs/tag/domains/
    /// expected/expect/unexpected 逐项变异）。
    #[test]
    fn policy_id_any_tuple_field_difference_changes_id() {
        let baseline = r#"{"address":"8.8.8.8"}"#;
        let mutants = [
            r#"{"address":"8.8.8.8","clientIp":"1.2.3.4"}"#,
            r#"{"address":"8.8.8.8","skipFallback":true}"#,
            r#"{"address":"8.8.8.8","queryStrategy":"useIPv6"}"#,
            r#"{"address":"8.8.8.8","tag":"t"}"#,
            r#"{"address":"8.8.8.8","domains":["a.com"]}"#,
            r#"{"address":"8.8.8.8","expectedIPs":["10.0.0.0/8"]}"#,
            r#"{"address":"8.8.8.8","expectIPs":["192.168.0.0/16"]}"#,
            r#"{"address":"8.8.8.8","unexpectedIPs":["172.16.0.0/12"]}"#,
        ];
        for m in mutants {
            let ids = policy_ids(&format!(r#"{{"servers":[{baseline},{m}]}}"#));
            assert_eq!(ids.len(), 2, "mutant {m}: both servers must build");
            assert_ne!(ids[0], ids[1], "mutant {m} must yield distinct policy_id");
        }
    }

    /// 8kha：expectedIPs 为空时回填 expectIPs（Go dns.go:94-96）——key 的
    /// expected/expect 两段为 (X, X)；显式 expectedIPs=X（expect 空）段为
    /// (X, [])，故与回填形式不同 id。
    #[test]
    fn policy_id_expected_backfill_from_expectips() {
        let ids = policy_ids(
            r#"{
            "servers": [
                {"address": "8.8.8.8", "expectIPs": ["10.0.0.0/8"]},
                {"address": "1.1.1.1", "expectIPs": ["10.0.0.0/8"]},
                {"address": "9.9.9.9", "expectedIPs": ["10.0.0.0/8"]}
            ]
        }"#,
        );
        assert_eq!(ids, vec![1, 1, 2]);
    }

    /// 8kha：JSON `policyID` 非零手动覆盖派生值（4ah3 扩展，Go 无此字段）；
    /// 覆盖不消耗派生计数器，未覆盖 server 仍从 1 派生。
    #[test]
    fn policy_id_json_override_wins_over_derivation() {
        let ids = policy_ids(
            r#"{
            "servers": [
                {"address": "8.8.8.8", "policyID": 100},
                {"address": "1.1.1.1", "policyID": 100},
                {"address": "9.9.9.9"}
            ]
        }"#,
        );
        assert_eq!(ids, vec![100, 100, 1]);
    }

    // 8b4c：queryStrategy 别名完整对齐 Go `resolveQueryStrategy`
    // （infra/conf/dns.go:381-394）。覆盖 useip/ipv4/ipv6/sys 全部分隔形式。
    #[test]
    fn query_strategy_aliases_match_go_resolve_query_strategy() {
        use crate::config::QueryStrategy;
        use super::parse_query_strategy;
        assert_eq!(parse_query_strategy(Some("UseIp")), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(Some("use_ip")), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(Some("use-ip")), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(Some("useipv4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use_ip4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use_ipv4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use_ip_v4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use-ip4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use-ipv4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("use-ip-v4")), QueryStrategy::UseIp4);
        assert_eq!(parse_query_strategy(Some("USEIPV6")), QueryStrategy::UseIp6);
        assert_eq!(parse_query_strategy(Some("use_ipv6")), QueryStrategy::UseIp6);
        assert_eq!(parse_query_strategy(Some("use-ipv6")), QueryStrategy::UseIp6);
        assert_eq!(parse_query_strategy(Some("usesystem")), QueryStrategy::UseSys);
        assert_eq!(parse_query_strategy(Some("use-sys")), QueryStrategy::UseSys);
        // 未知值 → UseIp 默认
        assert_eq!(parse_query_strategy(Some("uselookup")), QueryStrategy::UseIp);
        assert_eq!(parse_query_strategy(None), QueryStrategy::UseIp);
    }
}
