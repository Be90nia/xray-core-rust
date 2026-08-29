//! 顶层 DNS 服务。对应 Go `app/dns/dns.go`。
//!
//! ## 范围
//!
//! - `DnsService` 顶层结构 + 配置构造：完整翻译。
//! - `sort_clients`：业务核心，独立可测。
//! - `lookup_ip`：完整翻译（hosts 查询部分），nameservers 查询部分依赖
//!   `Server` trait 实际执行，由调用方在 trait 实现后接入。
//! - `check_routes`：系统路由探测（IPv4/IPv6 可达性），对应 Go `utils.CheckRoutes`。
//!
//! ## 跳过范围
//!
//! - `parallelQuery` / `serialQuery`：多 nameserver 并行/串行查询编排，留 trait
//!   方法占位，调用方提供具体实现（实现时需要持有 `tokio::task::JoinSet`）。
//! - Go `init()` 全局注册：Rust 无副作用全局。

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;

use parking_lot::Mutex;
use xray_features::Feature;
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
    /// 禁用 DNS 缓存。对应 Go `disableCache`。
    pub disable_cache: bool,
    /// 缓存过期后继续提供过期数据。对应 Go `serveStale`。
    pub serve_stale: bool,
    /// 过期数据的 TTL（秒）。对应 Go `serveExpiredTTL`。
    pub serve_expired_ttl: u32,
    /// 使用系统 hosts 文件。对应 Go `useSystemHosts`。
    pub use_system_hosts: bool,
    /// 聚合域名匹配器（per-nameserver domains 路由）。对应 Go `DNS.domainMatcher`。
    pub domain_matcher: Option<Box<dyn xray_geodata::matcher::domain::DomainMatcher>>,
    /// 匹配信息（rule_id → client 索引）。对应 Go `DNS.matcherInfos`。
    pub matcher_infos: Vec<DomainMatcherInfo>,
}

/// 顶层 DNS 服务。对应 Go `DNS` struct。
pub struct DnsService {
    cfg: DnsServiceConfig,
    /// 域名匹配器（option，对应 Go `domainMatcher geodata.DomainMatcher`）。
    /// ponytail: 当前 `StaticHosts` 内部已持有 matcher，此处保留独立 matcher
    /// 仅为 `sort_clients` 用，等 xray-geodata 暴露 `build_many` API 后接入。
    matcher: Mutex<Option<Box<dyn xray_geodata::matcher::domain::DomainMatcher>>>,
    /// 域名匹配信息列表（matcher rule_id → DomainMatcherInfo）。
    matcher_infos: Mutex<Vec<DomainMatcherInfo>>,
}

impl DnsService {
    /// 构造服务。对应 Go `New(ctx, config)`（ctx 未使用故省略）。
    #[must_use]
    pub fn new(mut cfg: DnsServiceConfig) -> Self {
        let domain_matcher = cfg.domain_matcher.take();
        let matcher_infos = std::mem::take(&mut cfg.matcher_infos);
        Self {
            cfg,
            matcher: Mutex::new(domain_matcher),
            matcher_infos: Mutex::new(matcher_infos),
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
        *self.matcher.lock() = Some(matcher);
        *self.matcher_infos.lock() = infos;
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

    /// 判断连接是否源自本 DNS 服务自身。对应 Go `(*DNS).IsOwnLink`
    /// （app/dns/dns.go:202——proxy/dns ownLink 防环用）。
    ///
    /// inbound tag 与任一 nameserver client tag 相同即视为自身流量
    /// （本服务发出的上游查询经 dispatcher 回环到 dns outbound 的场景）。
    #[must_use]
    pub fn is_own_link(&self, inbound_tag: &str) -> bool {
        if inbound_tag.is_empty() {
            return false; // Go: inbound == nil → false
        }
        self.cfg.clients.iter().any(|c| c.tag == inbound_tag)
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
        let infos = self.matcher_infos.lock();
        if let Some(matcher) = matcher_opt.as_ref() {
            let mut matches = matcher.match_domain(&domain.to_lowercase());
            matches.sort_unstable();
            for rule_id in matches {
                let id = rule_id as usize;
                if id >= infos.len() {
                    continue;
                }
                let info = &infos[id];
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
        drop(infos);

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
    /// 流程：域名规范化 → check_routes → hosts 查询 → nameservers 查询。
    /// nameservers 查询支持串行/并行（由 `enable_parallel_query` 配置决定）。
    pub async fn lookup_ip(
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

        // checkSystem：探测系统 IPv4/IPv6 路由可达性。
        // 对应 Go: option.IPv4Enable &&= supportIPv4; option.IPv6Enable &&= supportIPv6
        let (support_v4, support_v6) = check_routes();
        let effective = IpOption {
            ipv4_enable: option.ipv4_enable && support_v4,
            ipv6_enable: option.ipv6_enable && support_v6,
            ..option
        };

        if !effective.ipv4_enable && !effective.ipv6_enable {
            return Err(DnsError::EmptyResponse);
        }

        // 静态 hosts 查询。
        let addrs = self.cfg.hosts.lookup(domain, effective)?;
        if !addrs.is_empty() {
            if addrs.len() == 1 {
                if let xray_common::net::address::Address::Domain(d) = &addrs[0] {
                    let new_domain = d.clone();
                    return self.recursive_lookup_domain(&new_domain, effective).await;
                }
            }
            let ips = to_net_ip(&addrs)?;
            return Ok((ips, 10));
        }

        // Nameservers 查询。
        let clients = self.sort_clients(domain);
        if clients.is_empty() {
            return Err(DnsError::EmptyResponse);
        }

        if self.cfg.enable_parallel_query {
            parallel_query(&clients, domain, effective).await
        } else {
            serial_query(&clients, domain, effective).await
        }
    }

    /// 内部递归：域名被 hosts 重定向到另一个域名时再次查询。
    fn recursive_lookup_domain<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        Box::pin(self.lookup_ip(domain, option))
    }
}

/// `DnsService` 即 Go 的 `DNS` struct，本身即为 Feature（Go 中以 `dns.ClientType()` 注册）。
///
/// 直接实现 [`Feature`]（不另建 wrapper），与 LogFeature 的分层相反——此处服务本身
/// 就是 Feature 的唯一承载者，wrapper 是多余的一层。
impl Feature for DnsService {
    fn feature_name(&self) -> &'static str {
        "dns"
    }
}

/// Go：`*DNS` 实现 `dns.Client` 接口（`LookupIP(domain, option) -> ([]IP, ttl, err)`，
/// app/dns/dns.go:215-265）。路由 domainStrategy 经此解析。
///
/// 方法名与固有 [`DnsService::lookup_ip`] 同名——固有方法在具体类型上优先，
/// `dyn DnsClient` 上调用走本实现（与 Go `(*DNS).LookupIP` 同名实现接口一致）。
#[async_trait::async_trait]
impl xray_features::dns::DnsClient for DnsService {
    async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), xray_features::dns::DnsError> {
        self.lookup_ip(domain, option).await.map_err(Into::into)
    }
}

// ── Nameserver 查询编排 ──────────────────────────────────────────
/// 串行查询：按优先级顺序遍历 clients，返回第一个成功结果。
///
/// 对应 Go `(*DNS).queryIP` 串行路径（dns.go:365-369：`!option.FakeEnable`
/// 且 client 为 FakeDNS 时跳过）。
async fn serial_query(
    clients: &[Arc<Client>],
    domain: &str,
    option: IpOption,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    let mut last_err = DnsError::EmptyResponse;
    for client in clients {
        if !option.fake_enable && client.server.name().eq_ignore_ascii_case("FakeDNS") {
            continue;
        }
        match client.query_ip(domain).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if client.final_query {
                    return Err(e);
                }
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// 名称服务器组（按相邻 `policy_id` 合并）。对应 Go `type group struct{ start, end int }`。
#[derive(Debug, Clone, Copy)]
struct Group {
    start: usize,
    end: usize, // inclusive
}

/// 把相邻且 `policy_id` 相同的 client 合并为一个 group。
/// 对应 Go `(*DNS).makeGroups`（app/dns/dns.go:479-533）。
///
/// 返回 `(groups, group_of)`：`groups[i].start..=groups[i].end` 是第 i 组的下标范围；
/// `group_of[j]` 是下标 j 所属的组下标。
fn make_groups(clients: &[Arc<Client>]) -> (Vec<Group>, Vec<usize>) {
    let n = clients.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }
    let mut groups: Vec<Group> = Vec::with_capacity(n);
    let mut group_of: Vec<usize> = vec![0; n];
    let (mut s, mut e) = (0usize, 0usize);
    for i in 1..n {
        if clients[i - 1].policy_id == clients[i].policy_id {
            e = i;
        } else {
            for k in s..=e {
                group_of[k] = groups.len();
            }
            groups.push(Group { start: s, end: e });
            (s, e) = (i, i);
        }
    }
    for k in s..=e {
        group_of[k] = groups.len();
    }
    groups.push(Group { start: s, end: e });
    (groups, group_of)
}

/// 并行查询：按 `policy_id` 相邻合并分组，组内 race minimum rtt，组间串行。
///
/// 对应 Go `(*DNS).parallelQuery`（app/dns/dns.go:386-438）：
/// - `makeGroups` 合并相邻同 `policy_id` 的 client；
/// - `asyncQueryAll` 同时向所有 client 发起查询；
/// - 收集结果时按 group 序遍历：当前组内已收到任一成功即返回（组内 race）；
///   当前组全部失败再进入下一组。
/// 单个 client 的查询结果分类（避免 clone DnsError）。
#[derive(Debug, Clone)]
enum ClientOutcome {
    Success(Vec<IpAddr>, u32),
    Failure,
    Pending,
}

async fn parallel_query(
    clients: &[Arc<Client>],
    domain: &str,
    option: IpOption,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    use tokio::task::JoinSet;

    let (groups, _group_of) = make_groups(clients);
    if groups.is_empty() {
        return Err(DnsError::EmptyResponse);
    }

    let domain_owned = domain.to_string();
    let mut set: JoinSet<(usize, Result<(Vec<IpAddr>, u32), DnsError>)> = JoinSet::new();
    let mut spawned = 0usize;

    for (i, client) in clients.iter().enumerate() {
        if !option.fake_enable && client.server.name().eq_ignore_ascii_case("FakeDNS") {
            continue;
        }
        let c = Arc::clone(client);
        let d = domain_owned.clone();
        set.spawn(async move { (i, c.query_ip(&d).await) });
        spawned += 1;
    }

    if spawned == 0 {
        return Err(DnsError::EmptyResponse);
    }

    // 每个 client 的结果（Pending=未到，Success/Failure=已到）。
    let mut outcomes: Vec<ClientOutcome> =
        (0..clients.len()).map(|_| ClientOutcome::Pending).collect();
    // 每个 group 剩余未完成 client 数（仅计入真实 spawned）。
    // ponytail: 用 HashMap<group_idx, pending> 简化：group_idx 0..=len-1 顺序遍历。
    let group_count = groups.len();
    // 已聚合错误（仅 Debug 字符串，避免 clone DnsError）。
    let mut errs: Vec<String> = Vec::new();
    let mut non_empty_err_seen = false;

    let mut next_group = 0usize;
    while next_group < group_count {
        let recv = set.join_next().await;
        let (idx, outcome) = match recv {
            Some(Ok(v)) => v,
            _ => continue,
        };
        // 登记结果。
        match &outcome {
            Ok((ips, ttl)) if !ips.is_empty() => {
                outcomes[idx] = ClientOutcome::Success(ips.clone(), *ttl);
            }
            Ok(_) => {
                // Ok 但空 IP → 视为 Failure（Go 同步 dns.ErrEmptyResponse）。
                outcomes[idx] = ClientOutcome::Failure;
                non_empty_err_seen |= false; // 空响应 → 后续聚合按 EmptyResponse 处理
            }
            Err(e) => {
                outcomes[idx] = ClientOutcome::Failure;
                non_empty_err_seen |= !matches!(e, DnsError::EmptyResponse);
                errs.push(format!("{:?}", e));
            }
        }

        // 当前 group 内任一成功 → 组内 race 立即返回。
        let g = groups[next_group];
        let mut success: Option<(Vec<IpAddr>, u32)> = None;
        for j in g.start..=g.end {
            if let ClientOutcome::Success(ips, ttl) = &outcomes[j] {
                success = Some((ips.clone(), *ttl));
                break;
            }
        }
        if let Some((ips, ttl)) = success {
            set.abort_all();
            return Ok((ips, ttl));
        }

        // 当前 group 仍有人在跑：检查是否还有 pending。
        // ponytail: 用 group 内 outcomes 状态推断（Pending 即未完成）。
        let mut still_pending = 0usize;
        for j in g.start..=g.end {
            if matches!(outcomes[j], ClientOutcome::Pending) {
                still_pending += 1;
            }
        }
        if still_pending > 0 {
            continue;
        }

        // 当前 group 全部到齐且全部失败 → 推进 next_group。
        next_group += 1;
    }

    if non_empty_err_seen {
        Err(DnsError::Features(xray_features::dns::DnsError::Other(
            errs.join("; "),
        )))
    } else {
        Err(DnsError::EmptyResponse)
    }
}


// ── 系统路由探测 ──────────────────────────────────────────────────

/// 系统路由探测缓存。对应 Go `common/utils/probe_routes.go` 的 `routeCache`。
///
/// ponytail: Go 区分 GUI/非 GUI 平台用不同缓存策略（Once vs 100ms TTL），
/// Rust 端统一用 OnceLock（探测结果在进程生命周期内稳定）。
/// 如需动态刷新，改用 `parking_lot::Mutex` + 时间戳。
static ROUTE_CACHE: OnceLock<(bool, bool)> = OnceLock::new();

/// 探测系统 IPv4/IPv6 路由可达性。对应 Go `utils.CheckRoutes()`。
///
/// 通过 UDP connect 到已知根服务器地址（192.33.4.12:53 / [2001:500:2::c]:53）
/// 判断对应协议栈是否可用。`connect` 不发送数据，仅检查路由。
///
/// 结果缓存到进程生命周期（`OnceLock`），首次调用后不再重复探测。
#[must_use]
pub fn check_routes() -> (bool, bool) {
    *ROUTE_CACHE.get_or_init(probe_routes)
}

/// 实际探测逻辑。对应 Go `probeRoutes()`。
fn probe_routes() -> (bool, bool) {
    // Go: net.Dial("udp4", "192.33.4.12:53") —— 创建 UDP socket 并 connect。
    // Rust std: UdpSocket::bind → connect。connect 不发送数据，仅检查路由可达性。
    let ipv4 = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.33.4.12:53"))
        .is_ok();
    let ipv6 = std::net::UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:500:2::c]:53"))
        .is_ok();
    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QueryStrategy;
    use crate::hosts::HostMapping;
    use crate::nameserver::{NameServerConfig, Server};
    use std::net::Ipv4Addr;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    /// 测试用 Server：固定返回指定 IP + TTL。
    struct StaticServer {
        name: String,
        ips: Vec<IpAddr>,
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
            let ips = self.ips.clone();
            Box::pin(async move { Ok((ips, 60)) })
        }
    }

    fn make_client(tag: &str, skip_fallback: bool, final_query: bool) -> Arc<Client> {
        make_client_with_ips(tag, skip_fallback, final_query, Vec::new())
    }

    fn make_client_with_ips(tag: &str, skip_fallback: bool, final_query: bool, ips: Vec<IpAddr>) -> Arc<Client> {
        make_client_with_policy(tag, skip_fallback, final_query, ips, 0)
    }

    fn make_client_with_policy(
        tag: &str,
        skip_fallback: bool,
        final_query: bool,
        ips: Vec<IpAddr>,
        policy_id: u32,
    ) -> Arc<Client> {
        let ns = NameServerConfig {
            tag: tag.to_string(),
            skip_fallback,
            final_query,
            policy_id,
            ..Default::default()
        };
        let server: Box<dyn Server> = Box::new(StaticServer {
            name: tag.to_string(),
            ips,
        });
        Arc::new(Client::new(ns, IpOption::all(), server).unwrap())
    }

    /// 测试用 Server：先 sleep `delay`，再返回固定 IP+TTL。
    /// 用于构造 rtt 差异以验证 race minimum rtt 语义。
    struct DelayedServer {
        name: String,
        ips: Vec<IpAddr>,
        delay: Duration,
    }

    impl Server for DelayedServer {
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
            let ips = self.ips.clone();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok((ips, 60))
            })
        }
    }

    fn make_delayed_client(
        tag: &str,
        policy_id: u32,
        ips: Vec<IpAddr>,
        delay: Duration,
    ) -> Arc<Client> {
        let ns = NameServerConfig {
            tag: tag.to_string(),
            policy_id,
            ..Default::default()
        };
        let server: Box<dyn Server> = Box::new(DelayedServer {
            name: tag.to_string(),
            ips,
            delay,
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
            disable_cache: false,
            serve_stale: false,
            serve_expired_ttl: 0,
            use_system_hosts: false,
            domain_matcher: None,
            matcher_infos: Vec::new(),
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

    /// 6r0：expectedIPs 过滤——仅保留匹配 IP；全不匹配 → ErrEmptyResponse。
    #[tokio::test]
    async fn client_query_ip_filters_by_expected_ips() {
        use xray_geodata::pb::Cidr;
        let ns = NameServerConfig {
            tag: "exp".to_string(),
            expected_ip_rules: vec![xray_geodata::pb::IpRule {
                value: Some(xray_geodata::pb::ip_rule::Value::Custom(
                    xray_geodata::pb::CidrRule {
                        cidr: Some(Cidr {
                            ip: vec![10, 0, 0, 0],
                            prefix: 8,
                        }),
                        reverse_match: false,
                    },
                )),
            }],
            ..Default::default()
        };
        let server: Box<dyn Server> = Box::new(StaticServer {
            name: "exp".to_string(),
            ips: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            ],
        });
        let client = Client::new(ns, IpOption::all(), server).unwrap();

        let (ips, _) = client.query_ip("x.com").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]);

        // 返回 IP 全部不在期望范围 → ErrEmptyResponse。
        let server2: Box<dyn Server> = Box::new(StaticServer {
            name: "exp".to_string(),
            ips: vec![IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1))],
        });
        let client2 = Client::new(
            NameServerConfig {
                tag: "exp2".to_string(),
                expected_ip_rules: vec![xray_geodata::pb::IpRule {
                    value: Some(xray_geodata::pb::ip_rule::Value::Custom(
                        xray_geodata::pb::CidrRule {
                            cidr: Some(Cidr {
                                ip: vec![10, 0, 0, 0],
                                prefix: 8,
                            }),
                            reverse_match: false,
                        },
                    )),
                }],
                ..Default::default()
            },
            IpOption::all(),
            server2,
        )
        .unwrap();
        assert!(matches!(
            client2.query_ip("x.com").await,
            Err(DnsError::EmptyResponse)
        ));
    }

    /// kvl：set_matcher 注入的 matcher + infos 必须都被 sort_clients 使用。
    #[test]
    fn set_matcher_binds_matcher_and_infos() {
        use xray_geodata::matcher::domain::{DomainRule as MR, DomainType, MphDomainMatcher};

        let c1 = make_client("a", false, false);
        let c2 = make_client("b", false, false);
        let svc = make_service(vec![c2, c1], Vec::new());

        let matcher = Box::new(
            MphDomainMatcher::build(&[MR::new(DomainType::Domain, "priority.test", 0)]).unwrap(),
        );
        svc.set_matcher(
            matcher,
            vec![DomainMatcherInfo {
                client_idx: 1, // → client "a"（配置顺序第二个）
                domain_rule: "domain:priority.test".to_string(),
            }],
        );

        let sorted = svc.sort_clients("www.priority.test");
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].tag, "a", "matcher+infos 注入后命中 client a");
        // 未命中域名按 fallback 顺序。
        assert_eq!(svc.sort_clients("other.com")[0].tag, "b");
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

    #[tokio::test]
    async fn lookup_ip_returns_error_for_empty_domain() {
        let svc = make_service(Vec::new(), Vec::new());
        assert!(svc.lookup_ip("", IpOption::all()).await.is_err());
    }

    #[tokio::test]
    async fn lookup_ip_strips_trailing_dot_before_hosts_lookup() {
        use std::net::Ipv4Addr;
        let svc = make_service(
            Vec::new(),
            vec![HostMapping {
                domain: "example.com".to_string(),
                ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                proxied_domain: String::new(),
            }],
        );
        let (ips, ttl) = svc.lookup_ip("example.com.", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 10);
    }

    #[tokio::test]
    async fn lookup_ip_returns_hosts_ip_with_ttl_ten() {
        use std::net::Ipv4Addr;
        let svc = make_service(
            Vec::new(),
            vec![HostMapping {
                domain: "x.com".to_string(),
                ips: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                proxied_domain: String::new(),
            }],
        );
        let (ips, ttl) = svc.lookup_ip("x.com", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 10);
    }

    #[tokio::test]
    async fn lookup_ip_returns_empty_response_when_option_filters_all() {
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
        match svc.lookup_ip("x.com", v6_only).await {
            Err(DnsError::EmptyResponse) => {}
            other => panic!("expected EmptyResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lookup_ip_queries_nameservers_when_not_in_hosts() {
        use std::net::Ipv4Addr;
        let client = make_client_with_ips(
            "a", false, false,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        );
        let svc = make_service(vec![client], Vec::new());
        let (ips, ttl) = svc.lookup_ip("unknown.com", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(ttl, 60);
    }

    #[test]
    fn dns_service_construction_does_not_panic() {
        let svc = make_service(Vec::new(), Vec::new());
        assert_eq!(svc.clients_count(), 0);
        assert!(!svc.enable_parallel_query());
    }

    /// Go app/dns/dns.go:202 IsOwnLink——inbound tag 命中任一 client tag。
    #[test]
    fn is_own_link_matches_client_tags() {
        let c1 = make_client("dns-remote", false, false);
        let c2 = make_client("dns-local", false, false);
        let svc = make_service(vec![c1, c2], Vec::new());
        assert!(svc.is_own_link("dns-remote"));
        assert!(svc.is_own_link("dns-local"));
        assert!(!svc.is_own_link("other-inbound"));
        // Go: inbound == nil → false；空 tag 等价无 inbound。
        assert!(!svc.is_own_link(""));
    }

    /// Go dns.go:365-369——!FakeEnable 时 FakeDNS client 不参与查询。
    #[tokio::test]
    async fn lookup_ip_skips_fakedns_when_fake_disabled() {
        use crate::nameserver::fakedns::FakeDnsServer;
        use crate::fakedns::Holder;

        // FakeDNS client（tag 无关，server name 决定跳过）。
        let ns = NameServerConfig { tag: "fake".into(), ..Default::default() };
        let fake: Box<dyn Server> = Box::new(FakeDnsServer::new(Holder::new_default().unwrap()));
        let fake_client = Arc::new(Client::new(ns, IpOption::all(), fake).unwrap());
        // 真实 client 兜底。
        let real = make_client_with_ips(
            "real", false, false,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        );
        let svc = make_service(vec![fake_client, real], Vec::new());

        // fake_enable=false：跳过 FakeDNS，拿到 real 的 9.9.9.9。
        let no_fake = IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false };
        let (ips, _) = svc.lookup_ip("x.com", no_fake).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);

        // fake_enable=true：FakeDNS 优先，返回池内地址（240.0.0.0/4）。
        let with_fake = IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: true };
        let (ips, ttl) = svc.lookup_ip("x.com", with_fake).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 1);
        assert!(matches!(ips[0], IpAddr::V4(v4) if v4.octets()[0] >= 240));
    }

    #[test]
    fn skip_duration_constant_imports_ok() {
        // 仅验证 `Duration` 在 test mod 中可用（避免 unused import warning）。
        let _ = Duration::from_secs(0);
    }

    #[test]
    fn check_routes_returns_bool_pair() {
        let (v4, v6) = check_routes();
        // 至少 IPv4 在大多数测试环境可用。
        // 不做硬断言——CI 可能无网络。
        let _ = (v4, v6);
    }

    #[test]
    fn check_routes_is_cached() {
        // 两次调用应返回相同值（OnceLock 缓存）。
        let first = check_routes();
        let second = check_routes();
        assert_eq!(first, second);
    }

    // ---- features::dns::DnsClient trait 边界（drj：单方法 + IPOption + TTL）----

    fn make_trait_service(hosts: Vec<HostMapping>) -> std::sync::Arc<dyn xray_features::dns::DnsClient>
    {
        std::sync::Arc::new(make_service(Vec::new(), hosts))
    }

    #[tokio::test]
    async fn trait_lookup_ip_returns_ips_and_ttl() {
        // Go：*DNS 实现 dns.Client（dns.go:215），hosts 命中 → (ips, ttl=10)。
        let svc = make_trait_service(vec![HostMapping {
            domain: "example.com".to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            proxied_domain: String::new(),
        }]);
        let (ips, ttl) = svc
            .lookup_ip("example.com", IpOption::all())
            .await
            .expect("hosts hit must resolve");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(ttl, 10);
    }

    #[tokio::test]
    async fn trait_lookup_ip_propagates_rcode_error() {
        // hosts `#<rcode>` 映射 → Err(Rcode)（Go hosts.go:84 经 dns.RCodeError 上抛）。
        let svc = make_trait_service(vec![HostMapping {
            domain: "blocked.com".to_string(),
            ips: Vec::new(),
            proxied_domain: "#3".to_string(),
        }]);
        let err = svc
            .lookup_ip("blocked.com", IpOption::all())
            .await
            .expect_err("rcode mapping must error");
        assert!(matches!(err, xray_features::dns::DnsError::Rcode(3)));
        assert_eq!(xray_features::dns::rcode_from_error(&err), 3);
    }

    #[tokio::test]
    async fn trait_lookup_ip_propagates_empty_response_when_option_filters_all() {
        // IPOption 双禁 → EmptyResponse 跨 trait 边界保真（Go dns.ErrEmptyResponse）。
        let svc = make_trait_service(Vec::new());
        let err = svc
            .lookup_ip(
                "example.com",
                IpOption { ipv4_enable: false, ipv6_enable: false, fake_enable: false },
            )
            .await
            .expect_err("no family enabled must error");
        assert!(matches!(err, xray_features::dns::DnsError::EmptyResponse));
    }

    /// hmot：3 clients 同 policyID → 1 group race。
    /// 验证 `make_groups` 相邻合并 + 组内 race minimum rtt（最快返回者胜出）。
    #[tokio::test]
    async fn parallel_query_same_policy_groups_into_one_race() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        // 同一 policy_id=7，3 个 client，rtt 差异：b 最快、a 次之、c 最慢。
        let c_a = make_delayed_client(
            "a", 7, vec![ip_a],
            Duration::from_millis(50),
        );
        let c_b = make_delayed_client(
            "b", 7, vec![ip_b],
            Duration::from_millis(10),
        );
        let c_c = make_delayed_client(
            "c", 7, vec![ip_c],
            Duration::from_millis(100),
        );
        let clients = vec![c_a, c_b, c_c];
        // 先单独验证 make_groups：3 个同 policy → 1 group。
        let (groups, group_of) = make_groups(&clients);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].start, 0);
        assert_eq!(groups[0].end, 2);
        for j in 0..3 {
            assert_eq!(group_of[j], 0);
        }
        // 跑并行查询：应返回最快者（b，10ms）。
        let (ips, _ttl) = parallel_query(&clients, "x.com", IpOption::all()).await.unwrap();
        assert_eq!(ips, vec![ip_b], "组内 race 应返回最快完成的 client (b)");
    }

    /// hmot：3 clients 异 policyID → 3 groups 串行。
    /// 验证组间 fallback：前组全失败 → 推进到后组；后组成功 → 返回。
    #[tokio::test]
    async fn parallel_query_diff_policy_serial_groups() {
        // group0 (policy=1): 全失败（空响应）。
        let g0_a = make_client_with_policy("g0a", false, false, Vec::new(), 1);
        let g0_b = make_client_with_policy("g0b", false, false, Vec::new(), 1);
        // group1 (policy=2): 也全失败。
        let g1_a = make_client_with_policy("g1a", false, false, Vec::new(), 2);
        let g1_b = make_client_with_policy("g1b", false, false, Vec::new(), 2);
        // group2 (policy=3): 成功。
        let success_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let g2_a = make_delayed_client(
            "g2a", 3, vec![success_ip],
            Duration::from_millis(20),
        );
        let clients = vec![g0_a, g0_b, g1_a, g1_b, g2_a];
        // make_groups：3 个不同 policy → 3 个 group，邻接合并按 [0..1][2..3][4..4]。
        let (groups, group_of) = make_groups(&clients);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].start, 0);
        assert_eq!(groups[0].end, 1);
        assert_eq!(groups[1].start, 2);
        assert_eq!(groups[1].end, 3);
        assert_eq!(groups[2].start, 4);
        assert_eq!(groups[2].end, 4);
        assert_eq!(group_of, vec![0, 0, 1, 1, 2]);
        // 跑并行查询：group0+1 全失败 → 推进到 group2 → 返回成功 IP。
        let (ips, _ttl) = parallel_query(&clients, "x.com", IpOption::all()).await.unwrap();
        assert_eq!(ips, vec![success_ip], "组间串行：前组全败 → 后组成功");
    }
}
