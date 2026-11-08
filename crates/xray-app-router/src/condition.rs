//! 路由条件（Condition）与 9 种匹配器。
//!
//! 翻译自 `app/router/condition.go`。
//!
//! # 设计
//!
//! - `Condition` trait：对象安全，`apply(ctx) -> bool`
//! - `ConditionChan`：多个 Condition 的 AND（任一不匹配则全不匹配）
//! - 各 matcher 独立可测（不依赖 proto 也不依赖网络）
//!
//! # IO 边界
//!
//! - ProcessNameMatcher 的 `find_process`：跨平台进程反查（Linux /proc、Windows iphelper）
//! - GeoSite 文件加载（domain rule 的 GeoSiteRule 变体）走 rule.rs 调用 geodata loader

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, mpsc},
    time::Duration,
};

use regex::Regex;
use skeleton_infra::{
    memgov::MemoryPool,
    pool::{RejectedTask, ThreadPool, ThreadPoolTuning},
    pooled_thread_pool::PooledThreadPool,
};
use xray_common::net::{
    network::Network,
    port::{MemoryPortList, Port},
};
use xray_geodata::{
    matcher::{
        domain::{DomainMatcher as GeoDomainMatcher, DomainRule as GeoDomainRule},
        ip::{IPMatcher as GeoIPMatcher, build_optimized_ip_matcher},
    },
    pb::IpRule,
};

use crate::{context::RoutingContext, error::RouterError};

/// 路由条件 trait：对上下文返回是否匹配。
///
/// 对应 Go `router.Condition`。
pub trait Condition: Send + Sync {
    /// 返回是否匹配。
    fn apply(&self, ctx: &dyn RoutingContext) -> bool;
}

impl Condition for Box<dyn Condition> {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        (**self).apply(ctx)
    }
}

/// 多个 Condition 的 AND。
///
/// 对应 Go `ConditionChan`。空 chan 视为永真（Go 行为一致）。
#[derive(Default)]
pub struct ConditionChan {
    conds: Vec<Box<dyn Condition>>,
}

impl ConditionChan {
    /// 创建空 chan。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加一个条件。
    pub fn add(&mut self, c: Box<dyn Condition>) {
        self.conds.push(c);
    }

    /// 是否为空（无任何条件）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.conds.is_empty()
    }

    /// 内部条件数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.conds.len()
    }
}

impl Condition for ConditionChan {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        self.conds.iter().all(|c| c.apply(ctx))
    }
}

impl Condition for &ConditionChan {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        (*self).apply(ctx)
    }
}

// ── DomainMatcher ────────────────────────────────────────────

/// 域名匹配器。
///
/// 对应 Go `DomainMatcher`：包装 xray-geodata 的 `DomainMatcher` trait，
/// `apply` 返回 `matcher.match_any(ctx.get_target_domain())`。
pub struct DomainMatcherCondition {
    matcher: Box<dyn GeoDomainMatcher>,
}

impl DomainMatcherCondition {
    /// 从 geodata 解析后的 DomainRule 列表构造。
    ///
    /// 调用者负责把 proto `DomainRule`（oneof GeoSiteRule/Domain）转换为
    /// geodata matcher 层的 `DomainRule`（含 DomainType + value）。
    pub fn new(rules: Vec<GeoDomainRule>) -> Result<Self, RouterError> {
        use xray_geodata::matcher::domain::MphDomainMatcher;
        let matcher = MphDomainMatcher::build(&rules)
            .map_err(|e| RouterError::GeodataBuild(e.to_string()))?;
        Ok(Self { matcher: Box::new(matcher) })
    }

    /// 互喂版构建（xray-frame 任务书 P3-5）：`MphDomainMatcher::build` 在
    /// [`RouterBuildPool`] worker 内执行（worker 借缓冲 → 跑纯内存 CPU 活 →
    /// RAII 还），调用线程只等结果。与 [`Self::new`] 调同一 build 函数，同输入
    /// 匹配行为逐位等价。
    ///
    /// 规则集经 `Arc` 共享：常规路径零拷贝；提交侧拒绝（队列满/shutdown）时
    /// 池任务原样退还，本线程用同一 `Arc` 内联补位（CallerRuns 等价，不 panic）。
    /// worker 内 panic 的任务不回传结果 → `recv` 报错上抛 = fail-visible（同
    /// P1-2 geodata loader 收集面语义）。
    pub fn new_pooled(
        pool: &RouterBuildPool,
        rules: Vec<GeoDomainRule>,
    ) -> Result<Self, RouterError> {
        use xray_geodata::matcher::domain::MphDomainMatcher;
        let shared = Arc::new(rules);
        let (tx, rx) = mpsc::channel();
        let submitted = pool.submit({
            let shared = Arc::clone(&shared);
            let tx = tx.clone();
            move |_buf: &mut Vec<u8>| {
                let _ = tx.send(
                    MphDomainMatcher::build(shared.as_slice())
                        .map_err(|e| RouterError::GeodataBuild(e.to_string())),
                );
            }
        });
        drop(tx);
        let matcher = match submitted {
            Ok(()) => rx.recv().map_err(|_| {
                RouterError::GeodataBuild("matcher build task lost: pool worker died".into())
            })??,
            Err(_) => MphDomainMatcher::build(shared.as_slice())
                .map_err(|e| RouterError::GeodataBuild(e.to_string()))?,
        };
        Ok(Self { matcher: Box::new(matcher) })
    }
}

impl Condition for DomainMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let d = ctx.get_target_domain();
        if d.is_empty() {
            return false;
        }
        // hloi：Go `domainMatcher` 内部对输入统一 ToLower（router.go:165）。
        // Rust geodata MphDomainMatcher 假设输入已规范化；混合大小写域名会漏匹配。
        // 性能：to_lowercase 在 ASCII 域名上是 O(n) 且 alloc-free 在小字符串上；
        // 已在 condition.rs 注释"非 hot path"故无需再降级。
        self.matcher.match_any(&d.to_lowercase())
    }
}

// ── IPMatcher + MatcherAsType ──────────────────────────────

/// IP 匹配的上下文维度（对应 Go `MatcherAsType`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMatchAsType {
    /// `ctx.get_target_ips()`
    Target,
    /// `ctx.get_source_ips()`
    Source,
    /// `ctx.get_local_ips()`
    Local,
    /// `ctx.get_vless_route()` — VLESS 路由用的端口不是 IP，仅保留枚举位
    VlessRoute,
}

/// IP 匹配器。
///
/// 对应 Go `IPMatcher`：包装 xray-geodata 的 `IPMatcher`，
/// `apply` 返回任一对应类型 IP 命中任一 CIDR。
pub struct IPMatcherCondition {
    matcher: Box<dyn GeoIPMatcher>,
    as_type: IpMatchAsType,
}

impl IPMatcherCondition {
    /// 从 proto `IpRule` 列表构造。
    pub fn new(rules: Vec<IpRule>, as_type: IpMatchAsType) -> Result<Self, RouterError> {
        let matcher = build_optimized_ip_matcher(&rules)
            .map_err(|e| RouterError::GeodataBuild(e.to_string()))?;
        Ok(Self { matcher, as_type })
    }

    fn ips_for<'a>(&self, ctx: &'a dyn RoutingContext) -> &'a [IpAddr] {
        match self.as_type {
            IpMatchAsType::Target => ctx.get_target_ips(),
            IpMatchAsType::Source => ctx.get_source_ips(),
            IpMatchAsType::Local => ctx.get_local_ips(),
            IpMatchAsType::VlessRoute => &[], // VLESS 路由不使用 IP
        }
    }
}

impl Condition for IPMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let ips = self.ips_for(ctx);
        ips.iter().any(|ip| self.matcher.match_ip(*ip))
    }
}

// ── PortMatcher ──────────────────────────────────────────────

/// 端口匹配的上下文维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMatchAsType {
    /// `ctx.get_target_port()`
    Target,
    /// `ctx.get_source_port()`
    Source,
    /// `ctx.get_local_port()`
    Local,
    /// `ctx.get_vless_route()`
    VlessRoute,
}

/// 端口匹配器。
///
/// 对应 Go `PortMatcher`：包装 `MemoryPortList`，
/// `apply` 返回对应类型的端口在列表中。
pub struct PortMatcherCondition {
    list: MemoryPortList,
    as_type: PortMatchAsType,
}

impl PortMatcherCondition {
    /// 从端口列表构造。
    #[must_use]
    pub fn new(list: MemoryPortList, as_type: PortMatchAsType) -> Self {
        Self { list, as_type }
    }

    fn port_for(&self, ctx: &dyn RoutingContext) -> Port {
        match self.as_type {
            PortMatchAsType::Target => ctx.get_target_port(),
            PortMatchAsType::Source => ctx.get_source_port(),
            PortMatchAsType::Local => ctx.get_local_port(),
            PortMatchAsType::VlessRoute => ctx.get_vless_route(),
        }
    }
}

impl Condition for PortMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        self.list.contains(self.port_for(ctx))
    }
}

// ── NetworkMatcher ────────────────────────────────────────────

/// 网络类型匹配器。
///
/// 对应 Go `NetworkMatcher`：以 `[8]bool` 位集合表示允许的网络。
/// Network 枚举值（0..=2）作为索引。
pub struct NetworkMatcherCondition {
    /// 位集合（索引为 Network 的 discriminant）。
    allowed: [bool; 8],
}

impl NetworkMatcherCondition {
    /// 从允许的网络列表构造。
    #[must_use]
    pub fn new(networks: &[Network]) -> Self {
        let mut allowed = [false; 8];
        for n in networks {
            let idx = match n {
                Network::TCP => 0,
                Network::UDP => 1,
                Network::Unix => 2,
            };
            allowed[idx] = true;
        }
        Self { allowed }
    }
}

impl Condition for NetworkMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let idx = match ctx.get_network() {
            Network::TCP => 0,
            Network::UDP => 1,
            Network::Unix => 2,
        };
        self.allowed[idx]
    }
}

// ── UserMatcher ──────────────────────────────────────────────

/// 用户匹配器（邮箱/标识，严格等值）。
///
/// 对应 Go `UserMatcher`：ctx user 与任一 pattern 全等匹配即命中。
/// pattern 以 `regexp:` 开头时按正则匹配；否则字面 **严格等值**（Go `u == user`），
/// 不做子串/前缀/包含——子串匹配历史上易误命中，官方亦不推荐。
pub struct UserMatcherCondition {
    patterns: Vec<UserPattern>,
}

#[derive(Debug)]
enum UserPattern {
    /// 字面严格等值（`u == s`，对应 Go `u == user`）。
    Literal(String),
    /// 正则匹配（去掉 `regexp:` 前缀后编译）。
    Regex(Regex),
}

impl UserMatcherCondition {
    /// 从 proto `user_email` 列表构造。
    ///
    /// 对齐 Go `NewUserMatcher`（condition.go:162-181）：空项跳过；`regexp:` 前缀
    /// 仅在整串长度 > 7（前缀外至少 1 字符）时生效，编译失败的项**忽略**并保留
    /// 其余项（Go "Items of users slice with an invalid regexp syntax are
    /// ignored"）；`regexp:` 恰好无正文时按字面量处理。
    #[must_use]
    pub fn new(patterns: Vec<String>) -> Self {
        let mut parsed = Vec::with_capacity(patterns.len());
        for p in patterns {
            if p.is_empty() {
                continue;
            }
            if p.len() > 7 {
                if let Some(rest) = p.strip_prefix("regexp:") {
                    // 坏正则项忽略（fail-open per item），不阻断启动。
                    if let Ok(re) = Regex::new(rest) {
                        parsed.push(UserPattern::Regex(re));
                    }
                    continue;
                }
            }
            parsed.push(UserPattern::Literal(p));
        }
        Self { patterns: parsed }
    }
}

impl Condition for UserMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let u = ctx.get_user();
        if u.is_empty() {
            return false;
        }
        self.patterns.iter().any(|p| match p {
            UserPattern::Literal(s) => u == s,
            UserPattern::Regex(r) => r.is_match(u),
        })
    }
}

// ── LocalOSMatcher ───────────────────────────────────────────

/// 本机 OS 匹配器（Go a12801c1 `LocalOSMatcher`，condition.go:397-415）。
///
/// 运行期间 OS 不变，构造时即解析结果（`matched` 缓存），`apply` 恒返缓存值。
/// 候选名与 `std::env::consts::OS`（= Go `runtime.GOOS`）大小写不敏感比较：
/// Windows=`windows` / Linux=`linux` / macOS=`macos`。
pub struct LocalOsMatcherCondition {
    matched: bool,
}

impl LocalOsMatcherCondition {
    /// 从 proto `local_os` 列表构造。对齐 Go `NewLocalOSMatcher`：
    /// `slices.ContainsFunc(names, EqualFold(runtime.GOOS))`。
    #[must_use]
    pub fn new(names: &[String]) -> Self {
        Self { matched: names.iter().any(|n| n.eq_ignore_ascii_case(std::env::consts::OS)) }
    }
}

impl Condition for LocalOsMatcherCondition {
    fn apply(&self, _ctx: &dyn RoutingContext) -> bool {
        self.matched
    }
}

// ── InboundTagMatcher ────────────────────────────────────────

/// 入站 tag 匹配器（任一相等）。
pub struct InboundTagMatcherCondition {
    tags: Vec<String>,
}

impl InboundTagMatcherCondition {
    /// 从 proto `inbound_tag` 列表构造。
    ///
    /// Go `NewInboundTagMatcher`（condition.go:212-220）构造期**剔除空串**——
    /// 否则 gRPC `AddRule` 推 `[""]` 会绕过 JSON 侧校验，得到一条恒真规则。
    #[must_use]
    pub fn new(tags: Vec<String>) -> Self {
        Self { tags: tags.into_iter().filter(|t| !t.is_empty()).collect() }
    }
}

impl Condition for InboundTagMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let tag = ctx.get_inbound_tag();
        // Go condition.go:226-228：ctx 无 inbound tag ⇒ 不命中（空 == 空不算命中）。
        if tag.is_empty() {
            return false;
        }
        self.tags.iter().any(|t| t == tag)
    }
}

// ── ProtocolMatcher ─────────────────────────────────────────

/// 协议匹配器（前缀任一命中）。
///
/// 对应 Go `ProtocolMatcher`：`protocols` 中任一为 ctx protocol 的前缀。
pub struct ProtocolMatcherCondition {
    prefixes: Vec<String>,
}

impl ProtocolMatcherCondition {
    /// 构造。Go `NewProtocolMatcher`（condition.go:237-245）构造期**剔除空串**——
    /// 空串前缀 `starts_with("")` 恒真，会让一条空条件规则命中全部流量。
    #[must_use]
    pub fn new(prefixes: Vec<String>) -> Self {
        Self { prefixes: prefixes.into_iter().filter(|p| !p.is_empty()).collect() }
    }
}

impl Condition for ProtocolMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let p = ctx.get_protocol();
        // Go condition.go:249-251：ctx 无 protocol ⇒ 不命中。
        if p.is_empty() {
            return false;
        }
        self.prefixes.iter().any(|x| p.starts_with(x.as_str()))
    }
}

// ── AttributeMatcher ────────────────────────────────────────

/// 属性匹配器（大小写不敏感）。
///
/// 对应 Go `AttributeMatcher`：每个 key 对应一个正则；
/// key 两侧（配置与 ctx attribute）`strings.ToLower` 折叠以匹配 HTTP header
/// 大小写不敏感惯例；value 用原值跑正则。
pub struct AttributeMatcherCondition {
    /// 已折叠到小写的 (lowercase key → compiled regex) 映射。
    patterns: HashMap<String, Regex>,
}

impl AttributeMatcherCondition {
    /// 从 proto `attributes` map 构造。所有 value 作为正则；key 预先 ToLower 折叠。
    pub fn new(attrs: HashMap<String, String>) -> Result<Self, regex::Error> {
        let mut patterns = HashMap::with_capacity(attrs.len());
        for (k, v) in attrs {
            patterns.insert(k.to_lowercase(), Regex::new(&v)?);
        }
        Ok(Self { patterns })
    }
}

impl Condition for AttributeMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let attrs = ctx.get_attributes();
        for (k, re) in &self.patterns {
            // key 已在构造时 ToLower，attrs 侧也 ToLower 再查。
            let folded = attrs.keys().find(|orig| orig.to_lowercase() == *k);
            match folded.and_then(|orig| attrs.get(orig)) {
                Some(v) => {
                    if !re.is_match(v) {
                        return false;
                    }
                },
                None => return false,
            }
        }
        true
    }
}

// ── ProcessNameMatcher ────────────────────────────────────────

/// 进程名匹配器（接入 sysinfo 查询进程）。
///
/// 对应 Go `ProcessNameMatcher`：4 类配置项分别匹配：
/// - `process_names`：进程名字面集合
/// - `abs_paths`：进程 exe 绝对路径集合
/// - `folders`：进程 exe 所在目录前缀
/// - `match_xray_self`：是否匹配当前进程自身
pub struct ProcessNameMatcherCondition {
    process_names: Vec<String>,
    abs_paths: Vec<String>,
    folders: Vec<String>,
    match_xray_self: bool,
}

/// 进程查询结果。
struct ProcessInfo {
    /// 进程名。
    name: String,
    /// exe 绝对路径（可能为空）。
    exe_path: String,
    /// 进程 PID。
    pid: u32,
}

/// 根据源地址和端口查找对应进程。
///
/// 对应 Go `net.FindProcess(network, srcIP, srcPort, dstIP, dstPort)`。
/// 通过 OS-specific 网络连接表反查 PID：
/// - Linux：`/proc/net/tcp`(+`tcp6`) 取 socket inode，再扫描 `/proc/*/fd/*` 匹配 inode → PID
/// - Windows：`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` 直接取 owning PID
/// - 其他平台（macOS 等）：返回 `None`（进程匹配不生效，不影响路由）
///
/// 匹配语义：`(source_ip, source_port)` 对应连接表中的 **local** endpoint
/// （发起方 socket 的本地端，即 xray 看到的对端地址）。任一步失败返回 `None`
/// （权限不足/不可达），仅令进程匹配不生效，不阻断路由决策。
fn find_process(source_ip: std::net::IpAddr, source_port: u16) -> Option<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        proc_linux::find_process(source_ip, source_port)
    }
    #[cfg(target_os = "windows")]
    {
        proc_windows::find_process(source_ip, source_port)
    }
    // macOS/FreeBSD：对齐 Go find_process_others.go——明确不支持进程反查
    // （lsof/procstat 方案在 CI 环境时序不可控，Go 语义仅 linux/windows）。
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (source_ip, source_port);
        None
    }
}

/// `/proc/net/tcp`(+`tcp6`) 行格式纯解析（无 cfg 依赖，便于跨平台单测）。
#[cfg(any(target_os = "linux", test))]
mod proc_parse {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// 解析 hex 编码的 IP 地址。
    ///
    /// - IPv4：8 个 hex 字符，单个 `u32` 按**小端序**（kernel 写入格式）。
    /// - IPv6：32 个 hex 字符，4 个 `u32` 字，每个按小端序。
    pub(super) fn parse_hex_ip(hex: &str) -> Option<IpAddr> {
        if hex.len() == 8 {
            // IPv4：kernel 以 host-byte-order（x86/ARM LE 即小端）u32 写入
            let n = u32::from_str_radix(hex, 16).ok()?;
            let b = n.to_le_bytes();
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        } else if hex.len() == 32 {
            // IPv6：4 个小端 u32 字
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
                octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }

    /// 解析 `/proc/net/tcp`(或 `tcp6`) 的单行 → (local_ip, local_port, inode)。
    ///
    /// 行格式（跳过表头）：`sl local:port remote:port st tx:rx tr retr uid timeout inode ...`
    /// `inode == 0` 表示该 socket 无属主（TIME_WAIT 等），跳过。
    pub(super) fn parse_tcp_line(line: &str) -> Option<(IpAddr, u16, u64)> {
        let mut f = line.split_whitespace();
        let _sl = f.next()?;
        let local = f.next()?;
        let _remote = f.next()?;
        let _st = f.next()?;
        let _tx_rx = f.next()?;
        let _tr = f.next()?;
        let _retr = f.next()?;
        let _uid = f.next()?;
        let _timeout = f.next()?;
        let inode: u64 = f.next()?.parse().ok()?;
        if inode == 0 {
            return None;
        }
        let (ip_hex, port_hex) = local.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let ip = parse_hex_ip(ip_hex)?;
        Some((ip, port, inode))
    }
}

/// Linux `/proc` 实现。
#[cfg(target_os = "linux")]
mod proc_linux {
    use std::{fs, net::IpAddr};

    use super::{ProcessInfo, proc_parse::parse_tcp_line};

    pub(super) fn find_process(source_ip: IpAddr, source_port: u16) -> Option<ProcessInfo> {
        let inode = find_socket_inode(source_ip, source_port)?;
        let pid = find_pid_by_inode(inode)?;
        read_process_info(pid)
    }

    /// 在 `/proc/net/tcp`(+`tcp6`) 中查找 local endpoint 匹配的 socket inode。
    fn find_socket_inode(source_ip: IpAddr, source_port: u16) -> Option<u64> {
        let file = match source_ip {
            IpAddr::V4(_) => "/proc/net/tcp",
            IpAddr::V6(_) => "/proc/net/tcp6",
        };
        let content = fs::read_to_string(file).ok()?;
        content.lines().skip(1).find_map(|line| {
            let (ip, port, inode) = parse_tcp_line(line)?;
            (ip == source_ip && port == source_port).then_some(inode)
        })
    }

    /// 扫描 `/proc/*/fd/*`，找到拥有该 socket inode 的 PID。
    fn find_pid_by_inode(inode: u64) -> Option<u32> {
        let target = format!("socket:[{inode}]");
        let entries = fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    if link.to_string_lossy() == target {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    /// 读 `/proc/<pid>/comm`（进程名）+ `/proc/<pid>/exe`（exe 路径）。
    fn read_process_info(pid: u32) -> Option<ProcessInfo> {
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default();
        let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() && exe_path.is_empty() {
            return None;
        }
        Some(ProcessInfo { name, exe_path, pid })
    }
}

/// Windows iphelper 实现。
#[cfg(target_os = "windows")]
mod proc_windows {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::windows::ffi::OsStringExt,
    };

    use windows_sys::Win32::{
        Foundation::CloseHandle,
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        },
        System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    };

    use super::ProcessInfo;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const NO_ERROR: u32 = 0;

    pub(super) fn find_process(source_ip: IpAddr, source_port: u16) -> Option<ProcessInfo> {
        let pid = match source_ip {
            IpAddr::V4(ip) => find_pid_v4(ip, source_port),
            IpAddr::V6(ip) => find_pid_v6(ip, source_port),
        }?;
        read_process_info(pid)
    }

    fn find_pid_v4(ip: Ipv4Addr, port: u16) -> Option<u32> {
        let buf = tcp_table(AF_INET)?;
        // SAFETY: buf 为 Vec<u32>（align=4 ≥ 表结构对齐），由 tcp_table 按
        // GetExtendedTcpTable 所需 size 分配并刚填充，布局即 MIB_TCPTABLE_OWNER_PID；
        // 行数按缓冲容量夹取（dwNumEntries 为内核回填，越界声明不得越缓冲读）。
        unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let max_rows = (buf.len() * std::mem::size_of::<u32>() - std::mem::size_of::<u32>())
                / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                (table.dwNumEntries as usize).min(max_rows),
            );
            // dwLocalAddr 为网络字节序；from_be 还原后与 octets 比较。
            let want_addr = u32::from_be_bytes(ip.octets());
            for row in rows {
                if u32::from_be(row.dwLocalAddr) == want_addr && ntohs(row.dwLocalPort) == port {
                    return Some(row.dwOwningPid);
                }
            }
        }
        None
    }

    fn find_pid_v6(ip: Ipv6Addr, port: u16) -> Option<u32> {
        let buf = tcp_table(AF_INET6)?;
        // SAFETY: 同 v4 路径：Vec<u32>（align=4）按所需 size 分配且刚填充，布局即
        // MIB_TCP6TABLE_OWNER_PID；行数按缓冲容量夹取（越界声明不越缓冲读）。
        unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let max_rows = (buf.len() * std::mem::size_of::<u32>() - std::mem::size_of::<u32>())
                / std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                (table.dwNumEntries as usize).min(max_rows),
            );
            let octets = ip.octets();
            for row in rows {
                // ucLocalAddr 已是网络序原始 16 字节，直接比较。
                // SAFETY: row 指向 table 内有效内存，ucLocalAddr 是 [u8;16] 内联字段。
                if row.ucLocalAddr == octets && ntohs(row.dwLocalPort) == port {
                    return Some(row.dwOwningPid);
                }
            }
        }
        None
    }

    /// 取低 16 位端口（网络字节序）转主机序。
    #[inline]
    fn ntohs(port_field: u32) -> u16 {
        u16::from_be((port_field & 0xFFFF) as u16)
    }

    /// 调 `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` 取整张表。
    ///
    /// 返回 `Vec<u32>`（align=4）：表结构含 `u32` 字段，`Vec<u8>`（align=1）
    /// cast 结构体指针是形式对齐 UB（兄弟实现 portmap 同款修法）。
    fn tcp_table(af: u32) -> Option<Vec<u32>> {
        let row_bytes = if af == AF_INET {
            std::mem::size_of::<MIB_TCPROW_OWNER_PID>()
        } else {
            std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>()
        };
        // SAFETY: 两段式 Win32 契约：首调 null buf 填 size，二调以该 size 分配
        // 的缓冲接收整表（Vec<u32> 保证对齐；尾部多留一行的 u32 余量）。
        unsafe {
            let mut size: u32 = 0;
            // 第一次取所需大小（返回 ERROR_INSUFFICIENT_BUFFER，size 被填入）。
            GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if size == 0 {
                return None;
            }
            let mut buf = vec![
                0u32;
                size as usize / std::mem::size_of::<u32>()
                    + row_bytes / std::mem::size_of::<u32>()
            ];
            let rc = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            (rc == NO_ERROR).then_some(buf)
        }
    }

    fn read_process_info(pid: u32) -> Option<ProcessInfo> {
        let exe_path = query_image_name(pid)?;
        let name = exe_path.rsplit(['\\', '/']).next().unwrap_or(&exe_path).to_string();
        Some(ProcessInfo { name, exe_path, pid })
    }

    /// `QueryFullProcessImageNameW` → 完整 exe 路径。权限不足/系统进程返回 None。
    fn query_image_name(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess 句柄非 null 已检查；QueryFullProcessImageNameW 写入本函数 1024×u16
        // 缓冲
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            if ok == 0 {
                return None;
            }
            Some(std::ffi::OsString::from_wide(&buf[..len as usize]).to_string_lossy().into_owned())
        }
    }
}

/// 获取当前进程信息。
fn current_process_info() -> Option<ProcessInfo> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let current_pid = sysinfo::get_current_pid().ok()?.as_u32();
    let proc = sys.process(sysinfo::Pid::from_u32(current_pid))?;
    Some(ProcessInfo {
        name: proc.name().to_string_lossy().into_owned(),
        exe_path: proc.exe().map_or(String::new(), |p| p.to_string_lossy().into_owned()),
        pid: current_pid,
    })
}

impl ProcessNameMatcherCondition {
    /// 从 proto `process` 列表构造。对齐 Go `NewProcessNameMatcher`
    /// （condition.go:299-338）：
    /// - 精确 `"self/"`：`match_xray_self = true`
    /// - 精确 `"xray/"`：替换为当前可执行文件全路径（获取失败记日志并跳过该项）
    /// - 其余项路径分隔符归一为 `/`（Go `filepath.ToSlash`）后三分： `/` 结尾 → 目录前缀集；含 `/`
    ///   → 绝对路径集；否则进程名且裁掉 `.exe` 后缀（Windows `curl.exe` 与配置 `curl` 互通）
    #[must_use]
    pub fn new(process: Vec<String>) -> Self {
        let mut process_names = Vec::new();
        let mut abs_paths = Vec::new();
        let mut folders = Vec::new();
        let mut match_xray_self = false;
        for p in process {
            if p == "self/" {
                match_xray_self = true;
                continue;
            }
            let mut name = p;
            if name == "xray/" {
                match std::env::current_exe() {
                    Ok(path) => name = path.to_string_lossy().into_owned(),
                    Err(e) => {
                        // Go condition.go:311-315 获取失败记日志跳过该项。
                        tracing::warn!(target: "xray_router", error = %e, "failed to get xray executable path");
                        continue;
                    },
                }
            }
            let name = name.replace('\\', "/");
            if name.ends_with('/') {
                folders.push(name);
            } else if name.contains('/') {
                abs_paths.push(name);
            } else {
                process_names.push(name.strip_suffix(".exe").unwrap_or(&name).to_string());
            }
        }
        Self { process_names, abs_paths, folders, match_xray_self }
    }

    /// 判断进程信息是否匹配配置。
    ///
    /// info 侧对齐 Go `FindProcess` 返回语义（find_process_windows.go:115-122）：
    /// 进程名裁 `.exe` 后缀、exe 路径分隔符归一为 `/` 后再比较。
    fn matches_info(&self, info: &ProcessInfo) -> bool {
        let name = info.name.strip_suffix(".exe").unwrap_or(&info.name);
        let exe_path = info.exe_path.replace('\\', "/");
        // 匹配当前进程自身
        if self.match_xray_self {
            let current = current_process_info();
            if let Some(cur) = current {
                if cur.pid == info.pid {
                    return true;
                }
            }
        }
        // 进程名字面匹配
        if self.process_names.iter().any(|n| n == name) {
            return true;
        }
        // exe 绝对路径匹配
        if self.abs_paths.iter().any(|p| p == &exe_path) {
            return true;
        }
        // 目录前缀匹配
        if self.folders.iter().any(|f| exe_path.starts_with(f.as_str())) {
            return true;
        }
        false
    }

    /// `apply`：查询源进程并匹配配置。
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let source_ips = ctx.get_source_ips();
        let source_port = ctx.get_source_port().value();
        // 尝试按源地址查找进程
        let source_ip = source_ips.first().copied();
        if let Some(ip) = source_ip {
            if let Some(info) = find_process(ip, source_port) {
                return self.matches_info(&info);
            }
        }
        // find_process 无法按网络连接反查时，退化为 match_xray_self 检查
        if self.match_xray_self {
            // 无源进程信息时，不匹配（Go 行为一致：FindProcess 失败则不匹配）
            return false;
        }
        false
    }
}

impl Condition for ProcessNameMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        ProcessNameMatcherCondition::apply(self, ctx)
    }
}

// ── RouterBuildPool（P3-5 互喂池壳）───────────────────────────

// PM 拍板（拍板清单 §4 P3-5.1）：热更（add_rule/reload_rules）复用 Router 持有
// 的同一池，不每次新建线程池。池参数固定默认 + env 覆盖（同 P1-2 拍板形态）。
// 默认 core=1：构建触发频率远低于 geodata 加载，保活成本压到最低。
const DEFAULT_CORE: usize = 1;
const DEFAULT_MAX: usize = 2;
const DEFAULT_QUEUE_CAP: usize = 8;
const DEFAULT_BORROW_TIMEOUT_MS: usize = 10_000;

/// 池参数 env 覆盖项：worker 保活数。
pub const ENV_CORE: &str = "XRAY_ROUTER_POOL_CORE";
/// 池参数 env 覆盖项：worker 上限（同时决定内存池缓冲上限）。
pub const ENV_MAX: &str = "XRAY_ROUTER_POOL_MAX";
/// 池参数 env 覆盖项：中央队列容量（溢出 = 提交侧 `RejectedTask` 退还 → 调用
/// 线程内联补位，不 panic）。
pub const ENV_QUEUE_CAP: &str = "XRAY_ROUTER_POOL_QUEUE_CAP";
/// 池参数 env 覆盖项：worker 借缓冲超时（毫秒）。
pub const ENV_BORROW_TIMEOUT_MS: &str = "XRAY_ROUTER_POOL_BORROW_TIMEOUT_MS";

// 留主仓（方向件：内容域绑定）——壳编排的输入是路由 matcher 构建（路由规则内容域），
// 属内容方向件（CLAUDE.md §3.5.3），不进 udf；池件本体仍白拿 udf。
/// 路由 matcher 构建互喂池：[`PooledThreadPool`] 薄壳（P1-2 `GeodataLoadPool`
/// 同款形态；壳是内容域方向件，留消费 crate，不上浮 udf）。
///
/// 硬边界：只接启动期/热更期 matcher 构建（CPU 密集、纯内存、不持 IO）；
/// 数据面 `apply` 与持 socket 任务禁入（契约坑约束 12）。
pub struct RouterBuildPool {
    pool: PooledThreadPool<Vec<u8>, fn() -> Vec<u8>>,
}

impl RouterBuildPool {
    /// 显式参数组装。非法组合（0 值 / `core > max`）由 udf 构造期 fail-fast
    /// panic（恒不合法 = 调用方 bug，同 udf 纪律）。内存池上限 = `max`：每
    /// worker 至多持 1 块缓冲，恒不借空。
    pub fn new(core: usize, max: usize, queue_cap: usize, borrow_timeout: Duration) -> Self {
        let mem = Arc::new(MemoryPool::<Vec<u8>>::new(max, max, Vec::new));
        let threads = ThreadPool::new(ThreadPoolTuning::new(core, max, queue_cap));
        Self { pool: PooledThreadPool::new(mem, threads, borrow_timeout) }
    }

    /// 固定默认 + env 覆盖装配。非法 env 值 `tracing::warn` 后回落默认/修正，
    /// 不 panic（启动配置打错字不炸进程，也不静默吞掉）。
    pub fn from_env() -> Self {
        let num = |name: &str, default: usize| -> usize {
            match std::env::var(name) {
                Err(_) => default,
                Ok(raw) => match raw.trim().parse::<usize>() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        tracing::warn!("invalid {name}={raw:?}; falling back to default {default}");
                        default
                    },
                },
            }
        };
        let (core, max) = (num(ENV_CORE, DEFAULT_CORE), num(ENV_MAX, DEFAULT_MAX));
        let (core, max) = if core > max {
            tracing::warn!("{ENV_CORE}={core} > {ENV_MAX}={max}; clamping core to max");
            (max, max)
        } else {
            (core, max)
        };
        Self::new(
            core,
            max,
            num(ENV_QUEUE_CAP, DEFAULT_QUEUE_CAP),
            Duration::from_millis(num(ENV_BORROW_TIMEOUT_MS, DEFAULT_BORROW_TIMEOUT_MS) as u64),
        )
    }

    /// 提交一个构建任务（worker 内借缓冲 → 跑 → RAII 还）。
    /// `Err(RejectedTask)` = 提交侧拒绝（队列满/shutdown），任务原样退还，
    /// 不 panic；调用方应内联补位（CallerRuns 等价）。
    pub fn submit(
        &self,
        f: impl FnOnce(&mut Vec<u8>) + Send + 'static,
    ) -> Result<(), RejectedTask> {
        self.pool.submit(f)
    }

    /// 停机面：停止接收新任务 → 排空已入队任务 → 等 worker 退役。幂等。
    pub fn shutdown_join(&self) {
        self.pool.threads().shutdown();
        self.pool.threads().join();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use xray_common::net::port::PortRange;

    use super::*;
    use crate::context::RoutingData;

    fn ctx_target_domain(d: &str) -> RoutingData {
        RoutingData::new().with_target_domain(d)
    }

    // ── ConditionChan ──

    #[test]
    fn test_condition_chan_empty_is_true() {
        let chan = ConditionChan::new();
        let ctx = ctx_target_domain("any");
        assert!(chan.apply(&ctx));
    }

    #[test]
    fn test_condition_chan_all_must_match() {
        let mut chan = ConditionChan::new();
        chan.add(Box::new(ProtocolMatcherCondition::new(vec!["http".into()])));
        chan.add(Box::new(InboundTagMatcherCondition::new(vec!["in".into()])));
        let hit = RoutingData::new().with_protocol("http/1.1").with_inbound_tag("in");
        let miss = RoutingData::new().with_protocol("http/1.1").with_inbound_tag("other");
        assert!(chan.apply(&hit));
        assert!(!chan.apply(&miss));
    }

    // ── DomainMatcher ──

    #[test]
    fn test_domain_matcher_full() {
        let rule = GeoDomainRule::full("example.com", 1);
        let m = DomainMatcherCondition::new(vec![rule]).unwrap();
        assert!(m.apply(&ctx_target_domain("example.com")));
        assert!(!m.apply(&ctx_target_domain("not.match")));
    }

    #[test]
    fn test_domain_matcher_substr() {
        let rule = GeoDomainRule::substr("example", 1);
        let m = DomainMatcherCondition::new(vec![rule]).unwrap();
        assert!(m.apply(&ctx_target_domain("my.example.io")));
    }

    #[test]
    fn test_domain_matcher_empty_domain_returns_false() {
        let rule = GeoDomainRule::full("x", 1);
        let m = DomainMatcherCondition::new(vec![rule]).unwrap();
        assert!(!m.apply(&ctx_target_domain("")));
    }

    // ── IPMatcher ──

    #[test]
    fn test_ip_matcher_target() {
        use xray_geodata::pb::{Cidr, CidrRule, IpRule};
        let rule = IpRule {
            value: Some(xray_geodata::pb::ip_rule::Value::Custom(CidrRule {
                cidr: Some(Cidr { ip: vec![192, 168, 0, 0], prefix: 16 }),
                reverse_match: false,
            })),
        };
        let m = IPMatcherCondition::new(vec![rule], IpMatchAsType::Target).unwrap();
        let hit = RoutingData::new().with_target_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let miss = RoutingData::new().with_target_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    // ── PortMatcher ──

    #[test]
    fn test_port_matcher_target() {
        let list = MemoryPortList::new(vec![
            PortRange::new(Port::new(80), Port::new(80)),
            PortRange::new(Port::new(443), Port::new(445)),
        ]);
        let m = PortMatcherCondition::new(list, PortMatchAsType::Target);
        let hit = RoutingData::new().with_target_port(Port::new(444));
        let miss = RoutingData::new().with_target_port(Port::new(81));
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    // ── NetworkMatcher ──

    #[test]
    fn test_network_matcher() {
        let m = NetworkMatcherCondition::new(&[Network::TCP]);
        let tcp = RoutingData::new().with_network(Network::TCP);
        let udp = RoutingData::new().with_network(Network::UDP);
        assert!(m.apply(&tcp));
        assert!(!m.apply(&udp));
    }

    // ── UserMatcher（严格等值语义，对齐 Go UserMatcher）──

    #[test]
    fn test_user_matcher_strict_equality() {
        // 与 Go `if u == user` (condition.go:190) 一致：ctx user 与 pattern 全等才命中。
        let m =
            UserMatcherCondition::new(vec!["admin@example.com".into(), "root@example.com".into()]);
        let hit = RoutingData::new().with_user("admin@example.com");
        let hit2 = RoutingData::new().with_user("root@example.com");
        let miss = RoutingData::new().with_user("user@example.com");
        let miss_empty = RoutingData::new();
        assert!(m.apply(&hit));
        assert!(m.apply(&hit2));
        assert!(!m.apply(&miss));
        assert!(!m.apply(&miss_empty));
    }

    #[test]
    fn test_user_matcher_substring_must_miss() {
        // 子串不再命中：修复前的 bug 是 `u.contains(s)`，会把 "admin" 误匹配
        // "admin@example.com"。修复后严格等值，子串必须 miss。
        let m = UserMatcherCondition::new(vec!["admin".into()]);
        let ctx = RoutingData::new().with_user("admin@example.com");
        assert!(!m.apply(&ctx), "严格等值下 'admin' 子串不应命中 'admin@example.com'");
        let full = RoutingData::new().with_user("admin");
        assert!(m.apply(&full), "全等仍是命中");
    }

    #[test]
    fn test_user_matcher_regex() {
        let m = UserMatcherCondition::new(vec!["regexp:^admin@".into()]);
        let hit = RoutingData::new().with_user("admin@x.com");
        let miss = RoutingData::new().with_user("user@x.com");
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    #[test]
    fn test_user_matcher_empty_user() {
        let m = UserMatcherCondition::new(vec!["x".into()]);
        let empty = RoutingData::new();
        assert!(!m.apply(&empty));
    }

    #[test]
    fn test_user_matcher_bad_regexp_item_ignored() {
        // 对齐 Go condition.go:171 "Items of users slice with an invalid regexp
        // syntax are ignored"：坏正则项跳过，同列表其余项保留。
        let m = UserMatcherCondition::new(vec![
            "regexp:([bad".into(), // 编译失败 → 忽略
            "admin".into(),        // 字面项保留
        ]);
        let hit = RoutingData::new().with_user("admin");
        assert!(m.apply(&hit), "坏正则项不应阻断其余项匹配");
        let miss = RoutingData::new().with_user("anything");
        assert!(!m.apply(&miss));
    }

    #[test]
    fn test_user_matcher_regexp_prefix_needs_nonempty_body() {
        // Go len(user) > 7 门槛：恰好 "regexp:"（7 字符）按字面量处理，不空正则。
        let m = UserMatcherCondition::new(vec!["regexp:".into()]);
        let ctx = RoutingData::new().with_user("regexp:");
        assert!(m.apply(&ctx), "'regexp:' 本体按字面量等值匹配");
        let other = RoutingData::new().with_user("x");
        assert!(!m.apply(&other), "字面量 'regexp:' 不应匹配任意串（空正则会全匹配）");
    }

    // ── InboundTagMatcher ──

    #[test]
    fn test_inbound_tag_matcher() {
        let m = InboundTagMatcherCondition::new(vec!["tag1".into(), "tag2".into()]);
        let hit = RoutingData::new().with_inbound_tag("tag1");
        let miss = RoutingData::new().with_inbound_tag("other");
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    /// yh01f-c 回归：空串条目 + 空 ctx tag 都不得命中（Go `NewInboundTagMatcher`
    /// / `Apply` 的双重防线）。旧实现 `[""]` 恒真 ⇒ gRPC `AddRule` 推 `[""]`
    /// 可绕过 JSON 侧校验，一条空条件规则命中全部流量。
    #[test]
    fn test_inbound_tag_matcher_ignores_empty_strings() {
        let m = InboundTagMatcherCondition::new(vec![String::new()]);
        assert!(!m.apply(&RoutingData::new()), "空 ctx tag 不得与空串条目相等命中");
        assert!(!m.apply(&RoutingData::new().with_inbound_tag("in0")));
        // 空串与真实 tag 混排：只保留真实 tag 的语义。
        let m2 = InboundTagMatcherCondition::new(vec![String::new(), "in0".into()]);
        assert!(m2.apply(&RoutingData::new().with_inbound_tag("in0")));
        assert!(!m2.apply(&RoutingData::new().with_inbound_tag("in1")));
    }

    // ── ProtocolMatcher ──

    #[test]
    fn test_protocol_matcher_prefix() {
        let m = ProtocolMatcherCondition::new(vec!["http".into(), "tls".into()]);
        let hit1 = RoutingData::new().with_protocol("http/1.1");
        let hit2 = RoutingData::new().with_protocol("tls/1.3");
        let miss = RoutingData::new().with_protocol("tcp");
        assert!(m.apply(&hit1));
        assert!(m.apply(&hit2));
        assert!(!m.apply(&miss));
    }

    /// yh01f-c 回归：空串前缀恒真（`starts_with("")`）必须被构造期剔除，
    /// 且 ctx 无 protocol 时不命中（Go `NewProtocolMatcher` / `Apply`）。
    #[test]
    fn test_protocol_matcher_ignores_empty_prefix() {
        let m = ProtocolMatcherCondition::new(vec![String::new()]);
        assert!(!m.apply(&RoutingData::new().with_protocol("http/1.1")));
        assert!(!m.apply(&RoutingData::new()), "空 ctx protocol 不得命中");
    }

    // ── AttributeMatcher ──

    #[test]
    fn test_attribute_matcher_match() {
        let mut attrs = HashMap::new();
        attrs.insert(":path".into(), "/api/.*".into());
        let m = AttributeMatcherCondition::new(attrs).unwrap();
        let mut ctx_attrs = HashMap::new();
        ctx_attrs.insert(":path".into(), "/api/v1".into());
        let hit = RoutingData::new().with_attributes(ctx_attrs);
        assert!(m.apply(&hit));
    }

    #[test]
    fn test_attribute_matcher_missing_key() {
        let mut attrs = HashMap::new();
        attrs.insert(":path".into(), ".*".into());
        let m = AttributeMatcherCondition::new(attrs).unwrap();
        let ctx = RoutingData::new();
        assert!(!m.apply(&ctx));
    }

    #[test]
    fn test_attribute_matcher_case_insensitive_keys() {
        // 对齐 Go `AttributeMatcher.Match` (condition.go:269-280)：
        // 配置 key 与 ctx attribute key 两侧 ToLower 后比对。
        let mut attrs = HashMap::new();
        // 配置写成大写，ctx 用小写；两侧仍能匹配。
        attrs.insert(":PATH".into(), "/api/.*".into());
        let m = AttributeMatcherCondition::new(attrs).unwrap();
        let mut ctx_attrs = HashMap::new();
        ctx_attrs.insert(":path".into(), "/api/v1".into());
        let hit = RoutingData::new().with_attributes(ctx_attrs);
        assert!(m.apply(&hit), "key 大小写差异下应仍命中（两侧 ToLower 等价）");

        // 反向：配置小写，ctx 大写，也匹配。
        let mut attrs2 = HashMap::new();
        attrs2.insert(":path".into(), "/api/.*".into());
        let m2 = AttributeMatcherCondition::new(attrs2).unwrap();
        let mut ctx_attrs2 = HashMap::new();
        ctx_attrs2.insert(":PATH".into(), "/api/v1".into());
        let hit2 = RoutingData::new().with_attributes(ctx_attrs2);
        assert!(m2.apply(&hit2));

        // value 不匹配正则时即便 key 命中也应 fail。
        let mut attrs3 = HashMap::new();
        attrs3.insert(":Path".into(), "/api/.*".into());
        let m3 = AttributeMatcherCondition::new(attrs3).unwrap();
        let mut ctx_attrs3 = HashMap::new();
        ctx_attrs3.insert(":path".into(), "/static/file".into());
        let miss = RoutingData::new().with_attributes(ctx_attrs3);
        assert!(!m3.apply(&miss));
    }

    // ── ProcessNameMatcher ──

    #[test]
    fn test_process_name_matcher_config_parsing() {
        // 对齐 Go condition.go:304-331 合法形态：精确 "xray/"（→当前 exe 全路径）、
        // 精确 "self/"（仅置 match_xray_self）、"/" 结尾 → 目录、裸名 → 裁 ".exe"。
        let m = ProcessNameMatcherCondition::new(vec![
            "plain".into(),
            "xray/".into(),
            "self/".into(),
            "folder/".into(),
            "curl.exe".into(),
        ]);
        assert_eq!(m.process_names, vec!["plain".to_string(), "curl".to_string()]);
        assert_eq!(m.folders, vec!["folder/".to_string()]);
        assert!(m.match_xray_self, "self/ 必须只置 match_xray_self，不产生进程名");
        assert_eq!(m.abs_paths.len(), 1, "xray/ 替换为当前可执行文件全路径");
        assert!(m.abs_paths[0].contains('/'), "xray/ 产生的路径必须已 ToSlash 归一");
    }

    #[test]
    fn test_process_name_matcher_apply_no_source_returns_false() {
        // 无源 IP 时 find_process 无法查找，apply 返回 false
        let m = ProcessNameMatcherCondition::new(vec!["x".into()]);
        let ctx = RoutingData::new();
        assert!(!m.apply(&ctx));
    }

    #[test]
    fn test_local_os_matcher_matches_runtime_goos() {
        // Go a12801c1 condition_test.go TestLocalOSMatcher：候选含 runtime.GOOS → true
        let m = LocalOsMatcherCondition::new(&[std::env::consts::OS.to_string(), "other".into()]);
        let ctx = RoutingData::new();
        assert!(m.apply(&ctx));
    }

    #[test]
    fn test_local_os_matcher_case_insensitive() {
        // Go strings.EqualFold：大小写不敏感（"Windows"/"LINUX" 等文档写法均可）
        let upper = std::env::consts::OS.to_uppercase();
        let m = LocalOsMatcherCondition::new(std::slice::from_ref(&upper));
        let ctx = RoutingData::new();
        assert!(m.apply(&ctx), "候选 {upper} 须命中本机 OS {}", std::env::consts::OS);
    }

    #[test]
    fn test_local_os_matcher_other_os_misses() {
        // 其余 OS 名不命中（缓存于构造期，apply 恒 false）
        let wrong = if std::env::consts::OS == "windows" { "darwin" } else { "windows" };
        let m = LocalOsMatcherCondition::new(&[wrong.to_string()]);
        let ctx = RoutingData::new();
        assert!(!m.apply(&ctx));
    }

    #[test]
    fn test_process_name_matcher_matches_info_by_name() {
        let m = ProcessNameMatcherCondition::new(vec!["test_proc".into()]);
        let info =
            ProcessInfo { name: "test_proc".to_string(), exe_path: String::new(), pid: 1234 };
        assert!(m.matches_info(&info));
    }

    #[test]
    fn test_process_name_matcher_matches_info_by_abs_path() {
        // Go 语义：无前缀且含分隔符 → 绝对路径集；info 侧 exe_path 反斜杠
        // 由 matches_info 归一为 slash 后比对（find_process_windows.go:115-122）。
        let m = ProcessNameMatcherCondition::new(vec!["C:/xray.exe".into()]);
        let info = ProcessInfo {
            name: "xray".to_string(),
            exe_path: "C:/xray.exe".to_string(),
            pid: 5678,
        };
        assert!(m.matches_info(&info));
        let win_info = ProcessInfo {
            name: "xray.exe".to_string(),
            exe_path: "C:\\xray.exe".to_string(),
            pid: 5679,
        };
        assert!(m.matches_info(&win_info), "Windows 原生路径 + .exe 进程名也须命中");
    }

    #[test]
    fn test_process_name_matcher_matches_info_by_folder() {
        let m = ProcessNameMatcherCondition::new(vec!["C:/bin/".into()]);
        let info = ProcessInfo {
            name: "app".to_string(),
            exe_path: "C:/bin/app.exe".to_string(),
            pid: 9999,
        };
        assert!(m.matches_info(&info));
    }

    #[test]
    fn test_process_name_matcher_no_match() {
        let m = ProcessNameMatcherCondition::new(vec!["other".into()]);
        let info = ProcessInfo {
            name: "myapp".to_string(),
            exe_path: "/usr/bin/myapp".to_string(),
            pid: 100,
        };
        assert!(!m.matches_info(&info));
    }

    // ── find_process / proc_parse ──

    #[test]
    fn test_parse_hex_ip_v4_loopback() {
        // /proc/net/tcp 中 127.0.0.1 的 hex（小端 u32）= "0100007F"
        assert_eq!(
            proc_parse::parse_hex_ip("0100007F"),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_hex_ip_v4_any() {
        // 192.168.1.100 → 小端 u32 hex
        assert_eq!(
            proc_parse::parse_hex_ip("6401A8C0"),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
    }

    #[test]
    fn test_parse_hex_ip_v6_loopback() {
        // ::1 在 /proc/net/tcp6 = 4 个小端 u32 字，末字 = htonl(1) = "01000000"
        assert_eq!(
            proc_parse::parse_hex_ip("00000000000000000000000001000000"),
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn test_parse_hex_ip_invalid() {
        assert_eq!(proc_parse::parse_hex_ip("XYZ"), None);
        assert_eq!(proc_parse::parse_hex_ip("123"), None); // 长度非 8/32
    }

    #[test]
    fn test_parse_tcp_line_established() {
        // local=127.0.0.1:8080(0x1F90)，inode=12345
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 \
                    00:00000000 00000000     0        0 12345 1 0000000000000000";
        let (ip, port, inode) = proc_parse::parse_tcp_line(line).expect("应解析成功");
        assert_eq!(ip, std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 8080);
        assert_eq!(inode, 12345);
    }

    #[test]
    fn test_parse_tcp_line_zero_inode_skipped() {
        // inode=0（TIME_WAIT 等无属主 socket）应返回 None
        let line = "   1: 0100007F:0050 00000000:0000 06 00000000:00000000 \
                    00:00000000 00000000     0        0 0 1 0000000000000000";
        assert!(proc_parse::parse_tcp_line(line).is_none());
    }

    #[test]
    fn test_find_process_resolves_self_connection() {
        // 建立一条本进程的 loopback 连接，验证 find_process 能反查到本进程 PID。
        // 仅在已实现平台（linux/windows）强校验；其他平台恒返回 None。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let local = client.local_addr().unwrap();
        // accept 完成 3 次握手，确保连接进入 ESTABLISHED
        let server = listener.accept().ok();

        // 连接表更新可能有微小延迟，重试若干次。
        let mut info = None;
        for _ in 0..20 {
            info = find_process(local.ip(), local.port());
            if info.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // 对齐 Go find_process_others.go：仅 linux/windows 支持进程反查，
        // macOS/FreeBSD 恒 None（CI 上 lsof/procstat 时序不可控）。
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let info = info.expect("find_process 应能解析本进程 loopback 连接");
            assert_eq!(info.pid, std::process::id(), "应解析到本测试进程");
            assert!(!info.name.is_empty(), "进程名不应为空");
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            assert!(info.is_none(), "未支持平台应返回 None（对齐 Go）");
        }

        drop(server);
        drop(client);
    }
}
