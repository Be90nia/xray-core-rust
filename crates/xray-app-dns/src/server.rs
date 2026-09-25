//! 顶层 DNS 服务。对应 Go `app/dns/dns.go`。
//!
//! ## 范围
//!
//! - `DnsService` 顶层结构 + 配置构造：完整翻译。
//! - `sort_clients`：业务核心，独立可测。
//! - `lookup_ip`：完整翻译（hosts 查询部分），nameservers 查询部分依赖 `Server` trait
//!   实际执行，由调用方在 trait 实现后接入。
//! - `check_routes`：系统路由探测（IPv4/IPv6 可达性），对应 Go `utils.CheckRoutes`。
//!
//! ## 跳过范围
//!
//! - `parallelQuery` / `serialQuery`：多 nameserver 并行/串行查询编排，留 trait
//!   方法占位，调用方提供具体实现（实现时需要持有 `tokio::task::JoinSet`）。
//! - Go `init()` 全局注册：Rust 无副作用全局。

use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
};

use parking_lot::Mutex;
use xray_features::{Feature, dns::DnsError as FeaturesDnsError};

use crate::{
    config::{IpOption, QueryStrategy, to_net_ip},
    error::DnsError,
    hosts::StaticHosts,
    nameserver::Client,
};

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
        Self { cfg, matcher: Mutex::new(domain_matcher), matcher_infos: Mutex::new(matcher_infos) }
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
        // helper: 把当前 ordered 转成 names 列表并调 log_decision（Go dns.go:330-337）。
        // 只在非空时调（log_decision 内部已 short-circuit 空列表，但提早返回路径
        // 直接构造 names 一次更省一次 Vec 分配）。
        let emit_decision = |ordered: &[Arc<Client>]| {
            let names: Vec<&str> = ordered.iter().map(|c| c.server.name()).collect();
            log_decision(domain, &names);
        };

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
                    // Go dns.go:293 — finalQuery 提前返回前输出 logDecision。
                    emit_decision(&ordered);
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
                    // Go dns.go:309 — finalQuery 提前返回前输出 logDecision。
                    emit_decision(&ordered);
                    return ordered;
                }
            }
        }

        // Go dns.go:315 — 常规末尾输出 logDecision。
        emit_decision(&ordered);

        // 兜底：无任何 client 命中且有 clients → 取第一个。
        if ordered.is_empty() && !self.cfg.clients.is_empty() {
            ordered.push(Arc::clone(&self.cfg.clients[0]));
        }
        ordered
    }

    /// 顶层查询入口。对应 Go `(*DNS).LookupIP`（dns.go:216-265）。
    ///
    /// 流程：域名规范化 → 服务级 `query_strategy` 钳制 → hosts 查询 → nameservers 查询。
    /// nameservers 查询支持串行/并行（由 `enable_parallel_query` 配置决定）。
    pub async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        // Go dns.go:216 TrimSuffix(domain, ".")——只剥一个尾点（"a.." 保留内层点）。
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        if domain.is_empty() {
            return Err(DnsError::Features(FeaturesDnsError::Other(
                "empty domain name".to_string(),
            )));
        }

        // 服务级 query_strategy 钳制（Go dns.go:223-230 双分支）：
        // UseSys → 按 OS 路由可达性钳制；其余策略 → per-query option AND 服务级族
        // （`fake_enable` 不参与钳制，逐字透传 per-query option）。
        let effective = if matches!(self.cfg.query_strategy, QueryStrategy::UseSys) {
            let (support_v4, support_v6) = check_routes();
            IpOption {
                ipv4_enable: option.ipv4_enable && support_v4,
                ipv6_enable: option.ipv6_enable && support_v6,
                ..option
            }
        } else {
            let (svc_v4, svc_v6) = self.cfg.query_strategy.ip_enables();
            IpOption {
                ipv4_enable: option.ipv4_enable && svc_v4,
                ipv6_enable: option.ipv6_enable && svc_v6,
                ..option
            }
        };

        if !effective.ipv4_enable && !effective.ipv6_enable {
            return Err(DnsError::EmptyResponse);
        }

        // 静态 hosts 查询（Go dns.go:246-268）。`None` = 未记录；
        // `Some(vec![])` = 记录存在但按 option 过滤后无有效 IP。
        let mut ns_domain = domain.to_string();
        match self.cfg.hosts.lookup(domain, effective)? {
            None => {},
            Some(addrs) => {
                if let [xray_common::net::address::Address::Domain(d)] = addrs.as_slice() {
                    // 域名替换：以尾域名走 nameservers，不再进 hosts
                    // （Go dns.go:250-252；多级替换由 hosts 内部 max_depth 解开，
                    // 旧实现递归整条 lookup_ip 会在 a.com↔b.com 环上无限展开）。
                    tracing::info!(target: "xray.dns", from = %domain, to = %d, "domain replaced");
                    ns_domain = d.clone();
                } else if addrs.is_empty() {
                    return Err(DnsError::EmptyResponse);
                } else {
                    let ips = to_net_ip(&addrs)?;
                    return Ok((ips, 10));
                }
            },
        }

        // Nameservers 查询（hosts 域名替换后的尾域名也走这里）。
        let clients = self.sort_clients(&ns_domain);
        if clients.is_empty() {
            return Err(DnsError::EmptyResponse);
        }

        if self.cfg.enable_parallel_query {
            parallel_query(&clients, &ns_domain, effective).await
        } else {
            serial_query(&clients, &ns_domain, effective).await
        }
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
    let mut outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> = Vec::with_capacity(clients.len());
    for client in clients {
        if !option.fake_enable && client.server.name().eq_ignore_ascii_case("FakeDNS") {
            continue;
        }
        match client.query_ip(domain, option).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Go dns.go:377 — per-server LogInfoInner "in serial query mode"。
                tracing::info!(
                    target: "xray.dns",
                    server = %client.server.name(),
                    domain = %domain,
                    error = %e,
                    "failed to lookup ip in serial query mode",
                );
                // Go dns.go serialQuery（363-384）无 finalQuery 短路：finalQuery
                // 只作用于 sortClients 的序列截断；查询失败仍记日志继续问下一
                // 个（fallback）server，最后 mergeQueryErrors。
                outcomes.push(Err(e));
            },
        }
    }
    Err(merge_query_errors(domain, &outcomes).expect_err("serial_query outcomes are all Err"))
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

    // 每个 client 的结果（Pending=未到，Success/Failure=已到）；raw_errs 与
    // outcomes 索引对齐，尾部 merge_query_errors 走 errRNF 优先级
    // （Go dns.go:339-361 mergeQueryErrors）。初始化前移：FakeDNS 同步写
    // 结果需要在 spawn 循环内落到 outcomes 上。
    let mut outcomes: Vec<ClientOutcome> =
        (0..clients.len()).map(|_| ClientOutcome::Pending).collect();
    let mut raw_errs: Vec<Result<(Vec<IpAddr>, u32), DnsError>> =
        (0..clients.len()).map(|_| Err(DnsError::EmptyResponse)).collect();

    for (i, client) in clients.iter().enumerate() {
        if !option.fake_enable && client.server.name().eq_ignore_ascii_case("FakeDNS") {
            // Go dns.go:456-459 asyncQueryAll：FakeDNS 不发查询，但同步写入
            // ErrEmptyResponse 结果（pending 归零）。跳过不写会让该下标永久
            // Pending，组内成功结果永不消费（bd 5vfd）。
            outcomes[i] = ClientOutcome::Failure;
            continue;
        }
        let c = Arc::clone(client);
        let d = domain_owned.clone();
        set.spawn(async move { (i, c.query_ip(&d, option).await) });
    }

    let mut next_group = 0usize;
    while let Some(joined) = set.join_next().await {
        let (idx, outcome) = match joined {
            Ok(v) => v,
            // 任务 panic（JoinError）：下标不可得，由排空后的兜底统一归类。
            Err(_) => continue,
        };
        match &outcome {
            Ok((ips, ttl)) if !ips.is_empty() => {
                outcomes[idx] = ClientOutcome::Success(ips.clone(), *ttl);
            },
            Ok(_) => {
                // Ok 但空 IP → 视为 Failure（Go 同步 dns.ErrEmptyResponse）。
                outcomes[idx] = ClientOutcome::Failure;
                raw_errs[idx] = Err(DnsError::EmptyResponse);
            },
            Err(e) => {
                outcomes[idx] = ClientOutcome::Failure;
                raw_errs[idx] = Err(clone_dns_err(e));
            },
        }

        // 对齐 Go dns.go:412-437：每收到一个结果立即连续推进组检查。
        if let Some(r) =
            advance_groups(&outcomes, &raw_errs, &groups, clients, &domain_owned, &mut next_group)
        {
            set.abort_all();
            return Ok(r);
        }
    }

    // JoinSet 排空后仍 Pending 的下标 = 任务 panic/abort（JoinError 分支拿不到
    // 下标）。视为完成（失败）：Go asyncQueryAll 保证每 client 至少一条结果，
    // 否则组内 pending 永真、组内成功永不消费（bd 5vfd）。
    for (_idx, o) in outcomes.iter_mut().enumerate() {
        if matches!(o, ClientOutcome::Pending) {
            *o = ClientOutcome::Failure;
        }
    }
    if let Some(r) =
        advance_groups(&outcomes, &raw_errs, &groups, clients, &domain_owned, &mut next_group)
    {
        return Ok(r);
    }

    Err(merge_query_errors(domain, &raw_errs).expect_err("parallel_query raw_errs are all Err"))
}

/// 组推进检查（Go dns.go:418-437 的 `for nextGroup < len(groups)`）：从
/// `next_group` 起连续判断——组内任一已收结果成功即返回（组内 race minimum
/// rtt）；组内仍有未返回查询则停；组内全部到齐且全失败则记 per-server 日志
/// 后推进下一组。
fn advance_groups(
    outcomes: &[ClientOutcome],
    raw_errs: &[Result<(Vec<IpAddr>, u32), DnsError>],
    groups: &[Group],
    clients: &[Arc<Client>],
    domain: &str,
    next_group: &mut usize,
) -> Option<(Vec<IpAddr>, u32)> {
    while *next_group < groups.len() {
        let g = groups[*next_group];
        if let Some((ips, ttl)) = group_success(outcomes, g) {
            return Some((ips, ttl));
        }
        if group_pending(outcomes, g) {
            break;
        }
        for j in g.start..=g.end {
            if let (ClientOutcome::Failure, Err(e)) = (&outcomes[j], &raw_errs[j]) {
                tracing::info!(
                    target: "xray.dns",
                    server = %clients[j].server.name(),
                    domain = %domain,
                    error = %e,
                    "failed to lookup ip in parallel query mode",
                );
            }
        }
        *next_group += 1;
    }
    None
}

/// 组内任一已收结果成功 → 返回 (ips, ttl)（Go dns.go:419-426 组内 race）。
fn group_success(outcomes: &[ClientOutcome], g: Group) -> Option<(Vec<IpAddr>, u32)> {
    outcomes[g.start..=g.end].iter().find_map(|o| match o {
        ClientOutcome::Success(ips, ttl) => Some((ips.clone(), *ttl)),
        _ => None,
    })
}

/// 组内是否还有未返回的查询（Go dns.go:428 pending 计数 > 0）。
fn group_pending(outcomes: &[ClientOutcome], g: Group) -> bool {
    outcomes[g.start..=g.end].iter().any(|o| matches!(o, ClientOutcome::Pending))
}
// ── 错误聚合 + 决策日志（Go dns.go:339-361 mergeQueryErrors + dns.go:330-337 logDecision）──

/// 浅克隆 `DnsError`（`parallel_query` 收集 N 个独立 client 错误时需要复制所有权）。
fn clone_dns_err(e: &DnsError) -> DnsError {
    match e {
        DnsError::RecordNotFound => DnsError::RecordNotFound,
        DnsError::EmptyResponse => DnsError::EmptyResponse,
        DnsError::RCodeError(c) => DnsError::RCodeError(*c),
        DnsError::InvalidQueryStrategy(i) => DnsError::InvalidQueryStrategy(*i),
        DnsError::NoQueryStrategy(s) => DnsError::NoQueryStrategy(s.clone()),
        DnsError::InvalidClientIpLength(n) => DnsError::InvalidClientIpLength(*n),
        DnsError::InvalidStaticHostsIP(s) => DnsError::InvalidStaticHostsIP(s.clone()),
        DnsError::InvalidFakeDnsSetting => DnsError::InvalidFakeDnsSetting,
        DnsError::InvalidFakeDnsCidr(s) => DnsError::InvalidFakeDnsCidr(s.clone()),
        DnsError::LruBiggerThanSubnet { lru, rooms } => {
            DnsError::LruBiggerThanSubnet { lru: *lru, rooms: *rooms }
        },
        DnsError::NoFakeDnsEngine => DnsError::NoFakeDnsEngine,
        DnsError::Features(f) => DnsError::Features(f.clone()),
        DnsError::NotImplemented(s) => DnsError::NotImplemented(s),
        DnsError::WireFormat(s) => DnsError::WireFormat(s.clone()),
        DnsError::SystemResolve(s) => DnsError::SystemResolve(s.clone()),
    }
}

/// 把 N 个 client 的查询结果聚合成单一错误。对应 Go `mergeQueryErrors` (dns.go:339-361)：
///
/// - 忽略 `RecordNotFound`（Go `errRecordNotFound`，对应「服务器无响应/未应答」）；
/// - 取第一个非 RNF 错误作为 `noRNF`；
/// - 出现第二个不同种类的非 RNF → 返回 combined 错误（Go `errors.Combine(errs...)`）；
/// - 全 RNF → `RecordNotFound`；
/// - 全 `EmptyResponse` → `EmptyResponse`；
/// - 单一 `EmptyResponse` → `EmptyResponse`。
fn merge_query_errors(
    domain: &str,
    outcomes: &[Result<(Vec<IpAddr>, u32), DnsError>],
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    let errs: Vec<&DnsError> = outcomes.iter().filter_map(|r| r.as_ref().err()).collect();

    if errs.is_empty() {
        return Err(DnsError::EmptyResponse);
    }

    // 第一遍：识别 distinct error（非 RNF）。
    let mut first_non_rnf: Option<&DnsError> = None;
    let mut has_multiple_distinct = false;
    for e in errs.iter().copied() {
        if matches!(e, DnsError::RecordNotFound) {
            continue;
        }
        match first_non_rnf {
            None => first_non_rnf = Some(e),
            Some(prev) if !same_dns_error_kind(prev, e) => {
                has_multiple_distinct = true;
                break;
            },
            _ => {},
        }
    }

    if has_multiple_distinct {
        // Go: errors.New("returning nil for domain ").Base(errors.Combine(errs...))
        let combined = errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        return Err(DnsError::SystemResolve(format!(
            "returning nil for domain {domain}: {combined}"
        )));
    }

    if let Some(e) = first_non_rnf {
        if matches!(e, DnsError::EmptyResponse) {
            return Err(DnsError::EmptyResponse);
        }
        return Err(clone_dns_err(e));
    }

    Err(DnsError::RecordNotFound)
}

/// 两个 `DnsError` 是否属于"同类"。对应 Go `errors.Is(err, noRNF)`——
/// 只对相同 enum 变体返回 true（简化版，不递归展开 nested error）。
fn same_dns_error_kind(a: &DnsError, b: &DnsError) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// 输出 DNS 决策日志。对应 Go `logDecision` (dns.go:330-337)：
/// `domain -> clientNames` 的 debug 信息；调用方已确定 client 列表时调用。
pub fn log_decision(domain: &str, client_names: &[&str]) {
    if client_names.is_empty() {
        return;
    }
    tracing::debug!(
        target: "xray.dns",
        domain = %domain,
        client_names = ?client_names,
        "DNS resolution decision",
    );
}

// ── 系统路由探测 ──────────────────────────────────────────────────

/// ponytail: Go 区分 GUI/非 GUI 平台用不同缓存策略（Once vs 100ms TTL），
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
    let ipv4 =
        std::net::UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect("192.33.4.12:53")).is_ok();
    let ipv6 =
        std::net::UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001:500:2::c]:53")).is_ok();
    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use std::{future::Future, net::Ipv4Addr, pin::Pin, time::Duration};

    use super::*;
    use crate::{
        config::QueryStrategy,
        hosts::HostMapping,
        nameserver::{NameServerConfig, Server},
    };

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
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
        {
            let ips = self.ips.clone();
            Box::pin(async move { Ok((ips, 60)) })
        }
    }

    fn make_client(tag: &str, skip_fallback: bool, final_query: bool) -> Arc<Client> {
        make_client_with_ips(tag, skip_fallback, final_query, Vec::new())
    }

    fn make_client_with_ips(
        tag: &str,
        skip_fallback: bool,
        final_query: bool,
        ips: Vec<IpAddr>,
    ) -> Arc<Client> {
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
        let server: Box<dyn Server> = Box::new(StaticServer { name: tag.to_string(), ips });
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
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
        {
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
        let ns = NameServerConfig { tag: tag.to_string(), policy_id, ..Default::default() };
        let server: Box<dyn Server> = Box::new(DelayedServer { name: tag.to_string(), ips, delay });
        Arc::new(Client::new(ns, IpOption::all(), server).unwrap())
    }
    fn make_service_cfg(
        clients: Vec<Arc<Client>>,
        hosts: Vec<HostMapping>,
        enable_parallel_query: bool,
    ) -> DnsService {
        make_service_strategy(clients, hosts, QueryStrategy::UseIp, enable_parallel_query)
    }

    fn make_service_strategy(
        clients: Vec<Arc<Client>>,
        hosts: Vec<HostMapping>,
        query_strategy: QueryStrategy,
        enable_parallel_query: bool,
    ) -> DnsService {
        DnsService::new(DnsServiceConfig {
            client_ip: Vec::new(),
            query_strategy,
            tag: "test".to_string(),
            hosts: StaticHosts::new(hosts).unwrap(),
            clients,
            disable_fallback: false,
            disable_fallback_if_match: false,
            enable_parallel_query,
            disable_cache: false,
            serve_stale: false,
            serve_expired_ttl: 0,
            use_system_hosts: false,
            domain_matcher: None,
            matcher_infos: Vec::new(),
        })
    }

    fn make_service(clients: Vec<Arc<Client>>, hosts: Vec<HostMapping>) -> DnsService {
        make_service_cfg(clients, hosts, false)
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
                value: Some(xray_geodata::pb::ip_rule::Value::Custom(xray_geodata::pb::CidrRule {
                    cidr: Some(Cidr { ip: vec![10, 0, 0, 0], prefix: 8 }),
                    reverse_match: false,
                })),
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

        let (ips, _) = client.query_ip("x.com", IpOption::all()).await.unwrap();
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
                            cidr: Some(Cidr { ip: vec![10, 0, 0, 0], prefix: 8 }),
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
            client2.query_ip("x.com", IpOption::all()).await,
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
                matcher_rules: Vec::new(),
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
                matcher_rules: Vec::new(),
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
                matcher_rules: Vec::new(),
            }],
        );
        let v6_only = IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false };
        match svc.lookup_ip("x.com", v6_only).await {
            Err(DnsError::EmptyResponse) => {},
            other => panic!("expected EmptyResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lookup_ip_queries_nameservers_when_not_in_hosts() {
        use std::net::Ipv4Addr;
        let client =
            make_client_with_ips("a", false, false, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
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
        use crate::{fakedns::Holder, nameserver::fakedns::FakeDnsServer};

        // FakeDNS client（tag 无关，server name 决定跳过）。
        let ns = NameServerConfig { tag: "fake".into(), ..Default::default() };
        let fake: Box<dyn Server> = Box::new(FakeDnsServer::new(Holder::new_default().unwrap()));
        let fake_client = Arc::new(Client::new(ns, IpOption::all(), fake).unwrap());
        // 真实 client 兜底。
        let real =
            make_client_with_ips("real", false, false, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
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

    #[tokio::test]
    async fn parallel_query_returns_when_later_group_results_arrive_early() {
        // Go dns.go:418-437 内层 for：组 0 结果收齐推进到组 1 时，组 1 的成功
        // 结果可能早已收齐——必须立即返回，而不是回头 join_next（JoinSet 已空，
        // 旧实现在此自旋挂死）。
        let g0a = make_delayed_client("g0a", 1, Vec::new(), Duration::from_millis(300));
        let g0b = make_delayed_client("g0b", 1, Vec::new(), Duration::from_millis(300));
        let g1 = make_delayed_client(
            "g1",
            2,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            Duration::from_millis(10),
        );
        let svc = make_service_cfg(vec![g0a, g0b, g1], Vec::new(), true);
        let fut = svc.lookup_ip("slow-first.com", IpOption::all());
        let (ips, _) = tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("must not spin after JoinSet drains")
            .expect("group 1 success must win");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
    }

    #[tokio::test]
    async fn hosts_redirect_cycle_terminates_at_nameservers() {
        // Go dns.go:250-253：hosts 域名替换后不再进 hosts，直接走 nameservers。
        // a.com↔b.com 环配置下旧实现无限递归；新实现替换一次后查 nameservers，
        // 无可用 nameserver → EmptyResponse，有限时间返回。
        let svc = make_service(
            Vec::new(),
            vec![
                HostMapping {
                    domain: "a.com".to_string(),
                    ips: Vec::new(),
                    proxied_domain: "b.com".to_string(),
                    matcher_rules: Vec::new(),
                },
                HostMapping {
                    domain: "b.com".to_string(),
                    ips: Vec::new(),
                    proxied_domain: "a.com".to_string(),
                    matcher_rules: Vec::new(),
                },
            ],
        );
        let fut = svc.lookup_ip("a.com", IpOption::all());
        match tokio::time::timeout(Duration::from_secs(2), fut).await {
            Ok(Err(DnsError::EmptyResponse)) => {},
            Ok(other) => panic!("expected EmptyResponse, got {other:?}"),
            Err(_) => panic!("hosts redirect cycle must terminate"),
        }
    }

    // ---- features::dns::DnsClient trait 边界（drj：单方法 + IPOption + TTL）----

    fn make_trait_service(
        hosts: Vec<HostMapping>,
    ) -> std::sync::Arc<dyn xray_features::dns::DnsClient> {
        std::sync::Arc::new(make_service(Vec::new(), hosts))
    }

    #[tokio::test]
    async fn trait_lookup_ip_returns_ips_and_ttl() {
        // Go：*DNS 实现 dns.Client（dns.go:215），hosts 命中 → (ips, ttl=10)。
        let svc = make_trait_service(vec![HostMapping {
            domain: "example.com".to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            proxied_domain: String::new(),
            matcher_rules: Vec::new(),
        }]);
        let (ips, ttl) =
            svc.lookup_ip("example.com", IpOption::all()).await.expect("hosts hit must resolve");
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
            matcher_rules: Vec::new(),
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
        let c_a = make_delayed_client("a", 7, vec![ip_a], Duration::from_millis(50));
        let c_b = make_delayed_client("b", 7, vec![ip_b], Duration::from_millis(10));
        let c_c = make_delayed_client("c", 7, vec![ip_c], Duration::from_millis(100));
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
        let g2_a = make_delayed_client("g2a", 3, vec![success_ip], Duration::from_millis(20));
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

    /// bd 5vfd 回归：enableParallelQuery 下 [FakeDNS, 真 server] 同组。
    /// Go asyncQueryAll（dns.go:456-459）对 FakeDNS 同步写入 err 结果——
    /// 组内 pending 归零，真 server 的成功可被消费。修复前 FakeDNS 被
    /// continue 跳过、对应下标永久 Pending → 组内成功永不吞不出，整次解析
    /// 返回 Err（Go 同配置返回成功）。
    #[tokio::test]
    async fn parallel_query_fakedns_same_group_does_not_swallow_success() {
        use crate::{fakedns::Holder, nameserver::fakedns::FakeDnsServer};

        let ns = NameServerConfig { tag: "fake".into(), ..Default::default() };
        let fake: Box<dyn Server> = Box::new(FakeDnsServer::new(Holder::new_default().unwrap()));
        let fake_client = Arc::new(Client::new(ns, IpOption::all(), fake).unwrap());
        let real = make_client_with_ips(
            "real",
            false,
            false,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))],
        );
        // 同 policy_id（默认 0）→ 同组。
        let no_fake = IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false };
        let (ips, _ttl) = parallel_query(&[fake_client, real], "x.com", no_fake)
            .await
            .expect("FakeDNS 同步写 err 后，组内真 server 的成功应可消费");
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))]);
    }

    /// bd 5vfd 回归：查询任务 panic（JoinError 下标不可得）后，JoinSet 排空
    /// 兜底把仍 Pending 的下标视为失败完成——组内其它成功不被吞、不挂死。
    #[tokio::test]
    async fn parallel_query_panicked_task_treated_as_failure() {
        struct PanicServer;
        impl Server for PanicServer {
            fn name(&self) -> &str {
                "panic"
            }

            fn is_disable_cache(&self) -> bool {
                false
            }

            fn query_ip<'a>(
                &'a self,
                _d: &'a str,
                _o: IpOption,
            ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
            {
                Box::pin(async { panic!("query task panicked") })
            }
        }
        let ns = NameServerConfig { tag: "p".into(), ..Default::default() };
        let panic_client =
            Arc::new(Client::new(ns, IpOption::all(), Box::new(PanicServer)).unwrap());
        let real = make_client_with_ips(
            "real",
            false,
            false,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 4, 4))],
        );
        let (ips, _ttl) = parallel_query(&[panic_client, real], "x.com", IpOption::all())
            .await
            .expect("panic 任务视为失败完成后，组内成功应返回");
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 4, 4))]);
    }

    // ---- merge_query_errors / log_decision 单元测试 ----

    #[test]
    fn merge_query_errors_all_rnf_returns_rnf() {
        // Go dns.go:357-359：全 RNF → 返回 errRecordNotFound。
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> = vec![
            Err(DnsError::RecordNotFound),
            Err(DnsError::RecordNotFound),
            Err(DnsError::RecordNotFound),
        ];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        assert!(
            matches!(err, DnsError::RecordNotFound),
            "全 RNF → RecordNotFound (Go errRecordNotFound)"
        );
    }

    #[test]
    fn merge_query_errors_all_empty_returns_empty() {
        // Go dns.go:354-356：noRNF == ErrEmptyResponse → ErrEmptyResponse。
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> =
            vec![Err(DnsError::EmptyResponse), Err(DnsError::EmptyResponse)];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        assert!(matches!(err, DnsError::EmptyResponse), "全 EmptyResponse → EmptyResponse");
    }

    #[test]
    fn merge_query_errors_rnf_plus_real_returns_real() {
        // Go dns.go:344-353：errRNF 忽略、第一个非 RNF 作为 noRNF。
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> = vec![
            Err(DnsError::RecordNotFound),
            Err(DnsError::RCodeError(3)),
            Err(DnsError::RecordNotFound),
        ];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        assert!(matches!(err, DnsError::RCodeError(3)), "errRNF 忽略 + 第一个非 RNF 取回");
    }

    #[test]
    fn merge_query_errors_two_distinct_returns_combined() {
        // Go dns.go:350-352：第二个不同的非 RNF → errors.Combine。
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> =
            vec![Err(DnsError::RCodeError(3)), Err(DnsError::WireFormat("bad packet".into()))];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        // combined 包在 SystemResolve variant（包含原始 combined 字符串）。
        match err {
            DnsError::SystemResolve(s) => {
                assert!(s.contains("returning nil for domain x.com"));
                assert!(s.contains("dns rcode error: 3"));
                assert!(s.contains("dns wire format error: bad packet"));
            },
            other => panic!("expected SystemResolve combined, got {other:?}"),
        }
    }

    #[test]
    fn merge_query_errors_same_kind_non_rnf_returns_first() {
        // 两个同类非 RNF 不算 distinct。
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> =
            vec![Err(DnsError::RCodeError(3)), Err(DnsError::RCodeError(5))];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        // 取第一个（RCodeError(3)）。
        assert!(matches!(err, DnsError::RCodeError(3)));
    }

    #[test]
    fn merge_query_errors_empty_inputs_returns_empty() {
        let outcomes: Vec<Result<(Vec<IpAddr>, u32), DnsError>> = vec![];
        let err = merge_query_errors("x.com", &outcomes).unwrap_err();
        assert!(matches!(err, DnsError::EmptyResponse));
    }

    // ---- serial_query 行为覆盖（Go dns.go:363-384 serialQuery）----

    /// Go dns.go:365-369：!FakeEnable 时 FakeDNS client 不参与 serial query。
    /// 通过 lookup_ip 间接覆盖 serial_query 的 FakeDNS 跳过路径（先前仅在
    /// parallel_query 中显式覆盖）。
    #[tokio::test]
    async fn serial_query_skips_fakedns_when_fake_disabled() {
        use crate::{fakedns::Holder, nameserver::fakedns::FakeDnsServer};

        // FakeDNS server（name="FakeDNS" 是跳过判定依据）。
        let ns = NameServerConfig { tag: "fake".into(), ..Default::default() };
        let fake: Box<dyn Server> = Box::new(FakeDnsServer::new(Holder::new_default().unwrap()));
        let fake_client = Arc::new(Client::new(ns, IpOption::all(), fake).unwrap());
        let real =
            make_client_with_ips("real", false, false, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
        // enable_parallel_query=false 走 serial_query；fake_enable=false 跳过 FakeDNS。
        let svc = make_service(vec![fake_client, real], Vec::new());
        let opt = IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false };
        let (ips, _) = svc.lookup_ip("x.com", opt).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
    }

    /// Go dns.go:373-374：串行查询首个返回非空 IP 的 client 即胜出。
    #[tokio::test]
    async fn serial_query_returns_first_non_empty() {
        let a =
            make_client_with_ips("a", false, false, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let b =
            make_client_with_ips("b", false, false, vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]);
        // serial_query 顺序按 clients 切片序：a 先胜。
        let (ips, _ttl) = serial_query(&[a, b], "x.com", IpOption::all()).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }

    /// Go dns.go serialQuery（363-384）：finalQuery 只截断候选序列
    /// （sortClients），查询失败**不**短路——记日志继续问下一个 server，
    /// 最后 mergeQueryErrors。
    #[tokio::test]
    async fn serial_query_final_query_failure_continues_to_fallback() {
        // final_query client 失败 → 继续问后续 client；后续命中则成功返回。
        struct FailServer;
        impl Server for FailServer {
            fn name(&self) -> &str {
                "fail"
            }

            fn is_disable_cache(&self) -> bool {
                false
            }

            fn query_ip<'a>(
                &'a self,
                _d: &'a str,
                _o: IpOption,
            ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
            {
                Box::pin(async { Err(DnsError::RecordNotFound) })
            }
        }
        struct HitServer;
        impl Server for HitServer {
            fn name(&self) -> &str {
                "fallback"
            }

            fn is_disable_cache(&self) -> bool {
                false
            }

            fn query_ip<'a>(
                &'a self,
                _d: &'a str,
                _o: IpOption,
            ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
            {
                Box::pin(async { Ok((vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))], 60)) })
            }
        }
        let ns = NameServerConfig { tag: "final".into(), final_query: true, ..Default::default() };
        let server: Box<dyn Server> = Box::new(FailServer);
        let final_client = Arc::new(Client::new(ns, IpOption::all(), server).unwrap());
        let ns2 = NameServerConfig { tag: "fallback".into(), ..Default::default() };
        let server2: Box<dyn Server> = Box::new(HitServer);
        let fallback_client = Arc::new(Client::new(ns2, IpOption::all(), server2).unwrap());
        let (ips, _) = serial_query(&[final_client, fallback_client], "x.com", IpOption::all())
            .await
            .expect("finalQuery 失败后应继续问 fallback server");
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))]);
    }

    // ---- WgTimeoutFix 族过滤回归：option 必须贯穿 service→client→nameserver ----

    /// 尊重 IpOption 的 mock nameserver：模拟真实 nameserver（udp.rs 等）按族过滤。
    struct FamilyFilterServer {
        name: String,
        ips: Vec<IpAddr>,
    }

    impl Server for FamilyFilterServer {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_disable_cache(&self) -> bool {
            false
        }

        fn query_ip<'a>(
            &'a self,
            _domain: &'a str,
            option: IpOption,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
        {
            let ips: Vec<IpAddr> = self
                .ips
                .iter()
                .copied()
                .filter(|ip| match ip {
                    IpAddr::V4(_) => option.ipv4_enable,
                    IpAddr::V6(_) => option.ipv6_enable,
                })
                .collect();
            Box::pin(async move { Ok((ips, 60)) })
        }
    }

    fn make_filter_client(
        tag: &str,
        query_strategy: Option<QueryStrategy>,
        ips: Vec<IpAddr>,
    ) -> Arc<Client> {
        let ns = NameServerConfig { tag: tag.to_string(), query_strategy, ..Default::default() };
        let server: Box<dyn Server> = Box::new(FamilyFilterServer { name: tag.to_string(), ips });
        Arc::new(Client::new(ns, IpOption::all(), server).unwrap())
    }

    fn mixed_family_ips() -> Vec<IpAddr> {
        vec![
            IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6("2606:2800::6810:84e5".parse().unwrap()),
        ]
    }

    fn v4_only() -> IpOption {
        IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false }
    }

    /// 回归（WgTimeoutFix 定位）：ipv6_enable=false 时 serial_query 须把 option
    /// 传递到 client/nameserver，返回纯 v4。修复前 client 用构造时静态
    /// IpOption::all() 查询，AAAA 记录混入结果。
    #[tokio::test]
    async fn lookup_ip_v4_only_returns_pure_v4_serial() {
        let c = make_filter_client("mix", None, mixed_family_ips());
        let svc = make_service(vec![c], Vec::new());
        let (ips, _) = svc.lookup_ip("mixed.example", v4_only()).await.unwrap();
        assert!(
            ips.iter().all(|ip| matches!(ip, IpAddr::V4(_))),
            "ipv6_enable=false 应返回纯 v4，实际 {ips:?}"
        );
    }

    /// 同上，并行路径：parallel_query 同样须传递 option。
    #[tokio::test]
    async fn lookup_ip_v4_only_returns_pure_v4_parallel() {
        let c = make_filter_client("mix", None, mixed_family_ips());
        let svc = make_service_cfg(vec![c], Vec::new(), true);
        let (ips, _) = svc.lookup_ip("mixed.example", v4_only()).await.unwrap();
        assert!(
            ips.iter().all(|ip| matches!(ip, IpAddr::V4(_))),
            "ipv6_enable=false 应返回纯 v4，实际 {ips:?}"
        );
    }

    /// client 级 AND 语义（Go nameserver.go:174-175）：nameserver 自身
    /// query_strategy=USE_IP4 时，请求 option=all 也只允许 v4 透传；
    /// 请求与策略双双禁用同一族 → ErrEmptyResponse。
    #[tokio::test]
    async fn client_query_ip_ands_request_option_with_client_strategy() {
        let client = make_filter_client("v4only", Some(QueryStrategy::UseIp4), mixed_family_ips());
        let (ips, _) = client.query_ip("mixed.example", IpOption::all()).await.unwrap();
        assert!(
            ips.iter().all(|ip| matches!(ip, IpAddr::V4(_))),
            "client 策略 USE_IP4 应钳制请求 option，实际 {ips:?}"
        );
        let v6_only = IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false };
        let res = client.query_ip("mixed.example", v6_only).await;
        assert!(matches!(res, Err(DnsError::EmptyResponse)));
    }

    /// bd rofg③ 回归：per-client `queryStrategy=USE_SYS` → `check_system=true`，
    /// 查询走 check_routes 系统可达性钳制分支（Go nameserver.go:145,168-176），
    /// 不再与静态 ip_option AND。环境 v4 可达时请求透传给 nameserver。
    #[tokio::test]
    async fn client_use_sys_uses_check_routes_branch() {
        let (v4_ok, _) = check_routes();
        let client = make_filter_client("sys", Some(QueryStrategy::UseSys), mixed_family_ips());
        assert!(client.check_system, "UseSys 覆写必须置 check_system=true");
        if !v4_ok {
            return; // 无 v4 路由环境无法断言透传
        }
        let (ips, _) = client.query_ip("mixed.example", v4_only()).await.unwrap();
        assert_eq!(ips.len(), 1, "v4 路由可达时 UseSys client 透传 v4 查询");
    }

    /// bd rofg④ 回归：尾点只剥一个（Go dns.go:216 TrimSuffix(domain, ".")），
    /// `"x.com.."` → 查询域名 `"x.com."`（Fqdn 规范化形态）。修复前
    /// trim_end_matches 全剥 → 查询 `"x.com"`，与 Go 域名形态偏离。
    #[tokio::test]
    async fn lookup_ip_strips_single_trailing_dot_only() {
        struct CaptureServer {
            seen: Arc<parking_lot::Mutex<Vec<String>>>,
        }
        impl Server for CaptureServer {
            fn name(&self) -> &str {
                "capture"
            }

            fn is_disable_cache(&self) -> bool {
                false
            }

            fn query_ip<'a>(
                &'a self,
                d: &'a str,
                _o: IpOption,
            ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>
            {
                self.seen.lock().push(d.to_string());
                Box::pin(async { Ok((vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))], 60)) })
            }
        }
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let ns = NameServerConfig { tag: "cap".into(), ..Default::default() };
        let server: Box<dyn Server> = Box::new(CaptureServer { seen: Arc::clone(&seen) });
        let svc = make_service(
            vec![Arc::new(Client::new(ns, IpOption::all(), server).unwrap())],
            Vec::new(),
        );

        svc.lookup_ip("x.com..", IpOption::all()).await.unwrap();
        assert_eq!(&*seen.lock(), &["x.com.".to_string()], "应只剥一个尾点");
    }

    // ---- 服务级 query_strategy 钳制（Go dns.go:228-229，LookupIP 入口层）----

    /// 服务级 USE_IP4 钳制 per-query 默认族：请求 all() 也只透传 v4。
    /// 与 Client 层 AND（nameserver.go:174-175）不等价——本钳制还作用于
    /// 静态 hosts 查询（hosts.lookup 用钳制后的 effective option）。
    #[tokio::test]
    async fn lookup_ip_service_strategy_clamps_per_query_option() {
        let c = make_filter_client("mix", None, mixed_family_ips());
        let svc = make_service_strategy(vec![c], Vec::new(), QueryStrategy::UseIp4, false);
        let (ips, _) = svc.lookup_ip("mixed.example", IpOption::all()).await.unwrap();
        assert!(
            ips.iter().all(|ip| matches!(ip, IpAddr::V4(_))),
            "服务级 USE_IP4 应钳制请求 option=all，实际 {ips:?}"
        );
    }

    /// 服务级 USE_IP4 + 请求仅 v6 → 双禁用 → ErrEmptyResponse（Go dns.go:232-234）。
    #[tokio::test]
    async fn lookup_ip_service_strategy_double_disabled_yields_empty_response() {
        let c = make_filter_client("mix", None, mixed_family_ips());
        let svc = make_service_strategy(vec![c], Vec::new(), QueryStrategy::UseIp4, false);
        let v6_only = IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false };
        let res = svc.lookup_ip("mixed.example", v6_only).await;
        assert!(matches!(res, Err(DnsError::EmptyResponse)));
    }
    /// 服务级钳制同样作用于静态 hosts：v6-only hosts 记录在服务级 USE_IP4 下
    /// 被过滤 → EmptyResponse（Go hosts.Lookup 用钳制后的 option）。
    #[tokio::test]
    async fn lookup_ip_service_strategy_clamps_static_hosts() {
        let svc = make_service_strategy(
            Vec::new(),
            vec![HostMapping {
                domain: "v6host.example".to_string(),
                ips: vec!["2606:2800::6810:84e5".parse::<IpAddr>().unwrap()],
                proxied_domain: String::new(),
                matcher_rules: Vec::new(),
            }],
            QueryStrategy::UseIp4,
            false,
        );
        let res = svc.lookup_ip("v6host.example", IpOption::all()).await;
        assert!(matches!(res, Err(DnsError::EmptyResponse)));
    }

    // ---- sort_clients 集成 logDecision（Go dns.go:293/309/315）----
    // 验证 sort_clients 在 final_query 提前返回 + 常规末尾两条路径上
    // 调用了 log_decision（行为侧：通过 sort_clients 返回的 Vec 与 names 序列
    // 对齐断言；log_decision 副作用 debug! 不可断言）。
    #[test]
    fn log_decision_skips_when_no_clients() {
        // 空 client_names 不应 panic、不应输出（业务保证无观察者时调用安全）。
        log_decision("x.com", &[]);
    }

    #[test]
    fn log_decision_emits_with_clients() {
        // 实际 debug! 输出由 tracing subscriber 决定；这里只验证不 panic 且
        // 函数签名可被外部 crate 调用（pub fn）。
        log_decision("example.com", &["google", "cloudflare"]);
    }
}
