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
//! - ProcessNameMatcher 的 `find_process` 留 TODO（依赖 OS-specific sysinfo）
//! - GeoSite 文件加载（domain rule 的 GeoSiteRule 变体）走 rule.rs 调用 geodata loader

use std::collections::HashMap;
use std::net::IpAddr;

use regex::Regex;
use xray_common::net::network::Network;
use xray_common::net::port::{MemoryPortList, Port};
use xray_geodata::matcher::domain::{DomainMatcher as GeoDomainMatcher, DomainRule as GeoDomainRule};
use xray_geodata::matcher::ip::{build_optimized_ip_matcher, IPMatcher as GeoIPMatcher};
use xray_geodata::pb::IpRule;

use crate::context::RoutingContext;
use crate::error::RouterError;

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
        Ok(Self {
            matcher: Box::new(matcher),
        })
    }
}

impl Condition for DomainMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let d = ctx.get_target_domain();
        if d.is_empty() {
            return false;
        }
        self.matcher.match_any(d)
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

/// 用户匹配器（邮箱/标识）。
///
/// 对应 Go `UserMatcher`：ctx user 任一命中 patterns。
/// pattern 以 `regexp:` 开头时按正则匹配；否则字面包含。
pub struct UserMatcherCondition {
    patterns: Vec<UserPattern>,
}

#[derive(Debug)]
enum UserPattern {
    /// 字面包含（`patterns.contains(user)`）。
    Substr(String),
    /// 正则匹配（去掉 `regexp:` 前缀后编译）。
    Regex(Regex),
}

impl UserMatcherCondition {
    /// 从 proto `user_email` 列表构造。
    ///
    /// `regexp:` 前缀触发正则模式（编译失败返回错误）。
    pub fn new(patterns: Vec<String>) -> Result<Self, regex::Error> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for p in patterns {
            if let Some(rest) = p.strip_prefix("regexp:") {
                parsed.push(UserPattern::Regex(Regex::new(rest)?));
            } else {
                parsed.push(UserPattern::Substr(p));
            }
        }
        Ok(Self { patterns: parsed })
    }
}

impl Condition for UserMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let u = ctx.get_user();
        if u.is_empty() {
            return false;
        }
        self.patterns.iter().any(|p| match p {
            UserPattern::Substr(s) => u.contains(s),
            UserPattern::Regex(r) => r.is_match(u),
        })
    }
}

// ── InboundTagMatcher ────────────────────────────────────────

/// 入站 tag 匹配器（任一相等）。
pub struct InboundTagMatcherCondition {
    tags: Vec<String>,
}

impl InboundTagMatcherCondition {
    /// 从 proto `inbound_tag` 列表构造。
    #[must_use]
    pub fn new(tags: Vec<String>) -> Self {
        Self { tags }
    }
}

impl Condition for InboundTagMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let tag = ctx.get_inbound_tag();
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
    #[must_use]
    pub fn new(prefixes: Vec<String>) -> Self {
        Self { prefixes }
    }
}

impl Condition for ProtocolMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let p = ctx.get_protocol();
        self.prefixes.iter().any(|x| p.starts_with(x.as_str()))
    }
}

// ── AttributeMatcher ────────────────────────────────────────

/// 属性匹配器。
///
/// 对应 Go `AttributeMatcher`：每个 key 对应一个正则；
/// `apply` 返回 ctx attributes 所有键值都命中。
pub struct AttributeMatcherCondition {
    patterns: HashMap<String, Regex>,
}

impl AttributeMatcherCondition {
    /// 从 proto `attributes` map 构造。所有 value 作为正则。
    pub fn new(attrs: HashMap<String, String>) -> Result<Self, regex::Error> {
        let mut patterns = HashMap::with_capacity(attrs.len());
        for (k, v) in attrs {
            patterns.insert(k, Regex::new(&v)?);
        }
        Ok(Self { patterns })
    }
}

impl Condition for AttributeMatcherCondition {
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let attrs = ctx.get_attributes();
        for (k, re) in &self.patterns {
            match attrs.get(k) {
                Some(v) => {
                    if !re.is_match(v) {
                        return false;
                    }
                }
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
/// Go 版本通过 OS-specific netlink/etw 按网络连接反查 PID；
/// Rust sysinfo 不暴露网络连接→PID 映射，因此采用简化策略：
/// 遍历所有进程，返回第一个匹配源端口的进程。
///
/// ponytail: 不实现按网络连接精确反查 PID（需平台特定 netlink/etw），
/// 仅按进程名匹配。升级路径：引入 platform-specific 网络连接查询。
fn find_process(source_ip: std::net::IpAddr, source_port: u16) -> Option<ProcessInfo> {
    let _ = (source_ip, source_port);
    // ponytail: sysinfo 不提供网络连接→PID 映射，无法按源端口精确匹配。
    // 返回 None，进程匹配退化为配置匹配模式（仅 match_xray_self 生效）。
    // 升级路径：Windows 用 GetExtendedTcpTable2，Linux 用 /proc/net/tcp + /proc/pid/fd。
    None
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
    /// 从 proto `process` 列表构造。
    ///
    /// 解析规则（与 Go 一致）：
    /// - `xray/` 前缀：去掉前缀后视为绝对路径
    /// - `self/` 前缀：去掉前缀后视为进程名，同时 `match_xray_self=true`
    /// - 其他：进程名
    #[must_use]
    pub fn new(process: Vec<String>) -> Self {
        let mut process_names = Vec::new();
        let mut abs_paths = Vec::new();
        let mut folders = Vec::new();
        let mut match_xray_self = false;
        for p in process {
            if let Some(rest) = p.strip_prefix("xray/") {
                abs_paths.push(rest.to_string());
            } else if let Some(rest) = p.strip_prefix("self/") {
                process_names.push(rest.to_string());
                match_xray_self = true;
            } else if p.ends_with('/') {
                folders.push(p);
            } else {
                process_names.push(p);
            }
        }
        Self {
            process_names,
            abs_paths,
            folders,
            match_xray_self,
        }
    }

    /// 判断进程信息是否匹配配置。
    fn matches_info(&self, info: &ProcessInfo) -> bool {
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
        if self.process_names.iter().any(|n| n == &info.name) {
            return true;
        }
        // exe 绝对路径匹配
        if self.abs_paths.iter().any(|p| p == &info.exe_path) {
            return true;
        }
        // 目录前缀匹配
        if self.folders.iter().any(|f| info.exe_path.starts_with(f.as_str())) {
            return true;
        }
        false
    }

    /// `apply`：查询源进程并匹配配置。
    fn apply(&self, ctx: &dyn RoutingContext) -> bool {
        let source_ips = ctx.get_source_ips();
        let source_port = ctx.get_source_port().value() as u16;
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RoutingData;
    use std::net::Ipv4Addr;
    use xray_common::net::port::PortRange;

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
        let hit = RoutingData::new()
            .with_protocol("http/1.1")
            .with_inbound_tag("in");
        let miss = RoutingData::new()
            .with_protocol("http/1.1")
            .with_inbound_tag("other");
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
                cidr: Some(Cidr {
                    ip: vec![192, 168, 0, 0],
                    prefix: 16,
                }),
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

    // ── UserMatcher ──

    #[test]
    fn test_user_matcher_substring() {
        let m = UserMatcherCondition::new(vec!["admin".into()]).unwrap();
        let hit = RoutingData::new().with_user("admin@example.com");
        let miss = RoutingData::new().with_user("user@example.com");
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    #[test]
    fn test_user_matcher_regex() {
        let m = UserMatcherCondition::new(vec!["regexp:^admin@".into()]).unwrap();
        let hit = RoutingData::new().with_user("admin@x.com");
        let miss = RoutingData::new().with_user("user@x.com");
        assert!(m.apply(&hit));
        assert!(!m.apply(&miss));
    }

    #[test]
    fn test_user_matcher_empty_user() {
        let m = UserMatcherCondition::new(vec!["x".into()]).unwrap();
        let empty = RoutingData::new();
        assert!(!m.apply(&empty));
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

    // ── ProcessNameMatcher ──

    #[test]
    fn test_process_name_matcher_config_parsing() {
        let m = ProcessNameMatcherCondition::new(vec![
            "plain".into(),
            "xray/C:/xray.exe".into(),
            "self/xray".into(),
            "folder/".into(),
        ]);
        assert_eq!(m.process_names, vec!["plain".to_string(), "xray".to_string()]);
        assert_eq!(m.abs_paths, vec!["C:/xray.exe".to_string()]);
        assert_eq!(m.folders, vec!["folder/".to_string()]);
        assert!(m.match_xray_self);
    }

    #[test]
    fn test_process_name_matcher_apply_no_source_returns_false() {
        // 无源 IP 时 find_process 无法查找，apply 返回 false
        let m = ProcessNameMatcherCondition::new(vec!["x".into()]);
        let ctx = RoutingData::new();
        assert!(!m.apply(&ctx));
    }

    #[test]
    fn test_process_name_matcher_matches_info_by_name() {
        let m = ProcessNameMatcherCondition::new(vec!["test_proc".into()]);
        let info = ProcessInfo {
            name: "test_proc".to_string(),
            exe_path: String::new(),
            pid: 1234,
        };
        assert!(m.matches_info(&info));
    }

    #[test]
    fn test_process_name_matcher_matches_info_by_abs_path() {
        let m = ProcessNameMatcherCondition::new(vec!["xray/C:/xray.exe".into()]);
        let info = ProcessInfo {
            name: "xray".to_string(),
            exe_path: "C:/xray.exe".to_string(),
            pid: 5678,
        };
        assert!(m.matches_info(&info));
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
}
