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

use crate::config::{IpOption, QueryStrategy, generate_random_tag, validate_client_ip_len};
use crate::error::DnsError;
use crate::hosts::{HostMapping, StaticHosts};
use crate::nameserver::{Client, NameServerConfig, new_server};
use crate::server::DnsServiceConfig;

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
    /// 查询策略：`"UseIP"` / `"UseIP4"` / `"UseIP6"` / `"UseSys"`。缺省 `UseIP`。
    pub query_strategy: Option<String>,
    /// 禁用 fallback（所有 nameserver 都失败时不再兜底）。
    pub disable_fallback: Option<bool>,
    /// 命中匹配后禁用 fallback。
    pub disable_fallback_if_match: Option<bool>,
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
}

impl DnsAppConfig {
    /// 构造 [`DnsServiceConfig`]：解析全局策略 → 构建 clients → 构建 hosts。
    ///
    /// 不可构造的 nameserver（如域名地址）被跳过并告警，而非让整个 dns feature
    /// 注册失败——保持 Go 的「尽力而为」语义。
    pub fn build(self) -> Result<DnsServiceConfig, DnsError> {
        let query_strategy = parse_query_strategy(self.query_strategy.as_deref());
        let base_ip_option = IpOption::from_strategy(query_strategy);

        let client_ip = parse_client_ip(self.client_ip.as_deref())?;
        validate_client_ip_len(client_ip.len())?;

        let mut clients: Vec<Arc<Client>> = Vec::with_capacity(self.servers.len());
        for ns in &self.servers {
            match build_client(ns, &client_ip, base_ip_option) {
                Ok(c) => clients.push(Arc::new(c)),
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

        let mappings = parse_hosts(&self.hosts)?;
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
            enable_parallel_query: false,
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

    let ns_cfg = NameServerConfig {
        client_ip,
        skip_fallback: ns.skip_fallback,
        timeout_ms: ns.timeout.unwrap_or(0),
        query_strategy: ns.query_strategy.as_deref().map(|s| parse_query_strategy(Some(s))),
        ..Default::default()
    };

    Client::new(ns_cfg, base_ip_option, server)
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
    fn build_empty_config_succeeds() {
        let cfg: DnsAppConfig = serde_json::from_str("{}").unwrap();
        let built = cfg.build().unwrap();
        assert!(built.clients.is_empty());
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
        // 域名地址不可构造 → 跳过，clients 为空但不报错。
        assert!(built.clients.is_empty());
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
}
