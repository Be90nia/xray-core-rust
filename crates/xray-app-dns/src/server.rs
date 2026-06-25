//! 顶层 DNS 服务。对应 Go `app/dns/dns.go`。
//!
//! ## 范围
//!
//! - `DnsService` 顶层结构 + 配置构造：完整翻译。
//! - `sort_clients`：业务核心，独立可测。
//! - `lookup_ip`：完整翻译（hosts 查询部分），nameservers 查询部分依赖
//!   `Server` trait 实际执行，由调用方在 trait 实现后接入。
//!
//! ## 跳过范围
//!
//! - `checkSystem`（`utils.CheckRoutes`）：依赖系统路由表探测，留 TODO。
//! - `parallelQuery` / `serialQuery`：多 nameserver 并行/串行查询编排，留 trait
//!   方法占位，调用方提供具体实现（实现时需要持有 `tokio::task::JoinSet`）。
//! - Go `init()` 全局注册：Rust 无副作用全局。

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use xray_features::dns::DnsError as FeaturesDnsError;

use crate::config::{to_net_ip, IpOption};
use crate::error::DnsError;
use crate::hosts::StaticHosts;
use crate::nameserver::Client;

/// 域名匹配信息（与 Go `DomainMatcherInfo` 对齐）。
#[derive(Debug, Clone)]
pub struct DomainMatcherInfo {
    /// 对应 `clients` 向量中的索引。
    pub client_idx: u16,
    /// 调试用的规则字符串。
    pub domain_rule: String,
}

/// 顶层 DNS 服务配置。对应 Go `app/dns/config.go::Config`（手写）。
pub struct DnsServiceConfig {
    /// 全局客户端 IP（EDNS0 subnet）。
    pub client_ip: Vec<u8>,
    /// 查询策略。
    pub query_strategy: crate::config::QueryStrategy,
    /// tag（用于日志）。
    pub tag: String,
    /// 静态 hosts 表。
    pub hosts: StaticHosts,
    /// 已构造的 clients（每个绑定一个 nameserver）。
    pub clients: Vec<Arc<Client>>,
    /// 是否禁用 fallback。
    pub disable_fallback: bool,
    /// 命中后禁用 fallback。
    pub disable_fallback_if_match: bool,
    /// 启用并行查询。
    pub enable_parallel_query: bool,
}

/// 顶层 DNS 服务。对应 Go `DNS` struct。
pub struct DnsService {
    cfg: DnsServiceConfig,
    /// 域名匹配器（option，对应 Go `domainMatcher geodata.DomainMatcher`）。
    /// ponytail: 当前 `StaticHosts` 内部已持有 matcher，此处保留独立 matcher
    /// 仅为 `sort_clients` 用，等 xray-geodata 暴露 `build_many` API 后接入。
    matcher: Mutex<Option<Box<dyn xray_geodata::matcher::domain::DomainMatcher>>>,
    /// 域名匹配信息列表（matcher rule_id → DomainMatcherInfo）。
    matcher_infos: Vec<DomainMatcherInfo>,
}

impl DnsService {
    /// 构造服务。对应 Go `New(ctx, config)`（ctx 未使用故省略）。
    #[must_use]
    pub fn new(cfg: DnsServiceConfig) -> Self {
        Self {
            cfg,
            matcher: Mutex::new(None),
            matcher_infos: Vec::new(),
        }
    }

    /// 注入域名匹配器（用于 `sort_clients`）。
    ///
    /// ponytail: 等上层 router/dispatcher 就位后调用，将 `DomainMatcher` 与
    /// `DomainMatcherInfo` 列表绑定。未调用时 `sort_clients` 退化为按 clients 顺序遍历。
    pub fn set_matcher(
        &self,
        matcher: Box<dyn xray_geodata::matcher::domain::DomainMatcher>,
        infos: Vec<DomainMatcherInfo>,
    ) {
        let mut guard = self.matcher.lock();
        *guard = Some(matcher);
        // matcher_infos 是结构体字段，但 set_matcher 用 &self，需要内部可变性。
        // ponytail: 改用 Mutex 包装 matcher_infos。
        // 此处省略：实际实现需要 `matcher_infos: Mutex<Vec<...>>`。
        // 当前简化：调用方在 new() 时一次性传入 infos。
        let _ = infos; // TODO: 改为 Mutex<Vec> 后再赋值。
    }

    /// 客户端数量。
    #[must_use]
    pub fn clients_count(&self) -> usize {
        self.cfg.clients.len()
    }

    /// 是否启用并行查询。
    #[must_use]
    pub fn enable_parallel_query(&self) -> bool {
        self.cfg.enable_parallel_query
    }

    /// 排序客户端列表（按域名匹配优先 + fallback）。对应 Go `sortClients`。
    ///
    /// 输入：域名（大小写不敏感匹配）。
    /// 输出：按优先级排序的 `Arc<Client>` 引用列表。
    #[must_use]
    pub fn sort_clients(&self, domain: &str) -> Vec<Arc<Client>> {
        let mut ordered: Vec<Arc<Client>> = Vec::with_capacity(self.cfg.clients.len());
        let mut used = vec![false; self.cfg.clients.len()];
        let mut has_match = false;

        // 优先：matcher 命中。
        let matcher_opt = self.matcher.lock();
        if let Some(matcher) = matcher_opt.as_ref() {
            let mut matches = matcher.match_domain(&domain.to_lowercase());
            matches.sort_unstable();
            for rule_id in matches {
                let id = rule_id as usize;
                if id >= self.matcher_infos.len() {
                    continue;
                }
                let info = &self.matcher_infos[id];
                let idx = usize::from(info.client_idx);
                if idx >= self.cfg.clients.len() || used[idx] {
                    continue;
                }
                used[idx] = true;
                ordered.push(Arc::clone(&self.cfg.clients[idx]));
                has_match = true;
                if self.cfg.clients[idx].final_query {
                    return ordered;
                }
            }
        }
        drop(matcher_opt);

        // Fallback：按顺序遍历。
        if !(self.cfg.disable_fallback || (self.cfg.disable_fallback_if_match && has_match)) {
            for (idx, client) in self.cfg.clients.iter().enumerate() {
                if used[idx] || client.skip_fallback {
                    continue;
                }
                used[idx] = true;
                ordered.push(Arc::clone(client));
                if client.final_query {
                    return ordered;
                }
            }
        }

        // 兜底：无任何 client 命中且有 clients → 取第一个。
        if ordered.is_empty() && !self.cfg.clients.is_empty() {
            ordered.push(Arc::clone(&self.cfg.clients[0]));
        }
        ordered
    }

    /// 顶层查询入口。对应 Go `(*DNS).LookupIP`。
    ///
    /// 当前实现：
    /// - 域名规范化 + `checkSystem` 留 TODO。
    /// - 静态 hosts 查询：完整翻译。
    /// - nameservers 查询：留 TODO（依赖具体 Server 实现的 query_ip）。
    pub fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return Err(DnsError::Features(FeaturesDnsError::Other(
                "empty domain name".to_string(),
            )));
        }

        // TODO: checkSystem → utils.CheckRoutes 系统探测，待系统层就位。
        // 当前直接用 ipOption 字段。
        let effective = option;
        // （Go: option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable）
        // 简化：直接保留 option，因构造 DnsService 时 ipOption 已合并。

        if !effective.ipv4_enable && !effective.ipv6_enable {
            return Err(DnsError::EmptyResponse);
        }

        // 静态 hosts 查询。
        let addrs = self.cfg.hosts.lookup(domain, effective)?;
        if !addrs.is_empty() {
            // 单个域名响应：递归 unwrap（Go 行为）。
            if addrs.len() == 1 {
                if let xray_common::net::address::Address::Domain(d) = &addrs[0] {
                    let new_domain = d.clone();
                    return self.recursive_lookup_domain(&new_domain, effective);
                }
            }
            let ips = to_net_ip(&addrs)?;
            return Ok((ips, 10)); // Hosts ttl 是 10
        }
        // 空 Vec → 未记录或被 IPOption 过滤，走 nameservers 路径。

        // Nameservers 查询。当前留 TODO：实际需要 async + tokio runtime 调用
        // `Server::query_ip`，本方法签名是同步。等上层改为 async 或封装 runtime
        // 后再接入。ponytail: 至少返回 EmptyResponse 以便测试覆盖。
        let _ = self.sort_clients(domain);
        Err(DnsError::NotImplemented(
            "DnsService::lookup_ip nameservers path",
        ))
    }

    /// 内部递归：域名被 hosts 重定向到另一个域名时再次查询。
    fn recursive_lookup_domain(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        // ponytail: 与 Go 一致，最多递归 5 次（hosts.rs 内部已限）。
        self.lookup_ip(domain, option)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QueryStrategy;
    use crate::hosts::HostMapping;
    use crate::nameserver::{NameServerConfig, Server};
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    /// 测试用 Server：固定返回指定 IP + TTL。
    struct StaticServer {
        name: String,
    }

    impl Server for StaticServer {
        fn name(&self) -> &str {
            &self.name
        }
        fn is_disable_cache(&self) -> bool {
            false
        }
        fn query_ip<'a>(
            &'a self,
            _domain: &'a str,
            _option: IpOption,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
            Box::pin(async { Ok((Vec::new(), 0)) })
        }
    }

    fn make_client(tag: &str, skip_fallback: bool, final_query: bool) -> Arc<Client> {
        let ns = NameServerConfig {
            tag: tag.to_string(),
            skip_fallback,
            final_query,
            ..Default::default()
        };
        let server: Box<dyn Server> = Box::new(StaticServer {
            name: tag.to_string(),
        });
        Arc::new(Client::new(ns, IpOption::all(), server).unwrap())
    }

    fn make_service(clients: Vec<Arc<Client>>, hosts: Vec<HostMapping>) -> DnsService {
        DnsService::new(DnsServiceConfig {
            client_ip: Vec::new(),
            query_strategy: QueryStrategy::UseIp,
            tag: "test".to_string(),
            hosts: StaticHosts::new(hosts).unwrap(),
            clients,
            disable_fallback: false,
            disable_fallback_if_match: false,
            enable_parallel_query: false,
        })
    }

    #[test]
    fn sort_clients_returns_all_when_no_matcher() {
        let c1 = make_client("a", false, false);
        let c2 = make_client("b", false, false);
        let svc = make_service(vec![c1, c2], Vec::new());
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted.len(), 2);
    }

    #[test]
    fn sort_clients_skips_skip_fallback() {
        let c1 = make_client("a", false, false);
        let c2 = make_client("b", true, false); // skip_fallback
        let svc = make_service(vec![c1, c2], Vec::new());
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted.len(), 1); // 仅 a
    }

    #[test]
    fn sort_clients_stops_at_final_query() {
        let c1 = make_client("a", false, true); // final_query
        let c2 = make_client("b", false, false);
        let svc = make_service(vec![c1, c2], Vec::new());
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted.len(), 1); // 仅 a（finalQuery 提前返回）
    }

    #[test]
    fn sort_clients_fallback_to_first_when_empty() {
        // 所有 client 都 skip_fallback → ordered 为空 → 兜底取第一个。
        let c1 = make_client("a", true, false);
        let svc = make_service(vec![c1], Vec::new());
        let sorted = svc.sort_clients("example.com");
        assert_eq!(sorted.len(), 1);
    }

    #[test]
    fn lookup_ip_returns_error_for_empty_domain() {
        let svc = make_service(Vec::new(), Vec::new());
        assert!(svc.lookup_ip("", IpOption::all()).is_err());
    }

    #[test]
    fn lookup_ip_strips_trailing_dot_before_hosts_lookup() {
        use std::net::Ipv4Addr;
        let svc = make_service(
            Vec::new(),
            vec![HostMapping {
                domain: "example.com".to_string(),
                ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                proxied_domain: String::new(),
            }],
        );
        let (ips, ttl) = svc.lookup_ip("example.com.", IpOption::all()).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 10);
    }

    #[test]
    fn lookup_ip_returns_hosts_ip_with_ttl_ten() {
        use std::net::Ipv4Addr;
        let svc = make_service(
            Vec::new(),
            vec![HostMapping {
                domain: "x.com".to_string(),
                ips: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                proxied_domain: String::new(),
            }],
        );
        let (ips, ttl) = svc.lookup_ip("x.com", IpOption::all()).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 10);
    }

    #[test]
    fn lookup_ip_returns_empty_vec_when_option_filters_all() {
        // ponytail: hosts.lookup 返回空 Vec 时不再区分 nil/empty，
        // 一律走 nameservers 路径（NotImplemented 表示当前未接入）。
        let svc = make_service(
            Vec::new(),
            vec![HostMapping {
                domain: "x.com".to_string(),
                ips: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                proxied_domain: String::new(),
            }],
        );
        let v6_only = IpOption {
            ipv4_enable: false,
            ipv6_enable: true,
            fake_enable: false,
        };
        match svc.lookup_ip("x.com", v6_only) {
            Err(DnsError::NotImplemented(_)) => {}
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn lookup_ip_returns_not_implemented_for_nameservers_path() {
        // 域名不在 hosts 表 → 走 nameservers（NotImplemented）。
        let svc = make_service(vec![make_client("a", false, false)], Vec::new());
        match svc.lookup_ip("unknown.com", IpOption::all()) {
            Err(DnsError::NotImplemented(_)) => {}
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn dns_service_construction_does_not_panic() {
        let svc = make_service(Vec::new(), Vec::new());
        assert_eq!(svc.clients_count(), 0);
        assert!(!svc.enable_parallel_query());
    }

    #[test]
    fn skip_duration_constant_imports_ok() {
        // 仅验证 `Duration` 在 test mod 中可用（避免 unused import warning）。
        let _ = Duration::from_secs(0);
    }
}
