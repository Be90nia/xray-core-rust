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

/// 旧 API 别名：保留历史子串匹配语义以兼容未迁移调用方。
///
/// ⚠ 语义与 Go `UserMatcher` 不一致。仅用于兼容历史配置，正式路由请用 `UserMatcherCondition`。
#[deprecated(note = "substring semantics differ from Go UserMatcher; use UserMatcherCondition")]
pub type UserMatcherLenient = UserMatcherCondition;

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
    /// `regexp:` 前缀触发正则模式（编译失败返回错误）；其余走严格等值。
    pub fn new(patterns: Vec<String>) -> Result<Self, regex::Error> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for p in patterns {
            if let Some(rest) = p.strip_prefix("regexp:") {
                parsed.push(UserPattern::Regex(Regex::new(rest)?));
            } else {
                parsed.push(UserPattern::Literal(p));
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
            UserPattern::Literal(s) => u == s,
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
    #[cfg(target_os = "macos")]
    {
        proc_macos::find_process(source_ip, source_port)
    }
    #[cfg(target_os = "freebsd")]
    {
        proc_freebsd::find_process(source_ip, source_port)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos", target_os = "freebsd")))]
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
    use super::ProcessInfo;
    use super::proc_parse::parse_tcp_line;
    use std::fs;
    use std::net::IpAddr;

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
    use super::ProcessInfo;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

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
        unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            // dwLocalAddr 为网络字节序；from_be 还原后与 octets 比较。
            let want_addr = u32::from_be_bytes(ip.octets());
            for row in rows {
                if u32::from_be(row.dwLocalAddr) == want_addr
                    && ntohs(row.dwLocalPort) == port
                {
                    return Some(row.dwOwningPid);
                }
            }
        }
        None
    }

    fn find_pid_v6(ip: Ipv6Addr, port: u16) -> Option<u32> {
        let buf = tcp_table(AF_INET6)?;
        unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
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

    /// 调 `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` 取整张表字节。
    fn tcp_table(af: u32) -> Option<Vec<u8>> {
        unsafe {
            let mut size: u32 = 0;
            // 第一次取所需大小（返回 ERROR_INSUFFICIENT_BUFFER，size 被填入）。
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
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
        let name = exe_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&exe_path)
            .to_string();
        Some(ProcessInfo { name, exe_path, pid })
    }

    /// `QueryFullProcessImageNameW` → 完整 exe 路径。权限不足/系统进程返回 None。
    fn query_image_name(pid: u32) -> Option<String> {
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
            Some(
                std::ffi::OsString::from_wide(&buf[..len as usize])
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}


/// lsof -F 输出解析器（纯文本，与平台无关）。
///
/// proc_macos::find_process 调 /usr/sbin/lsof 取原始字节流；
/// 这里抽出 parse 逻辑便于在所有平台单测（不依赖 macOS shell-out）。
///
/// 输入格式（man lsof FIELD OUTPUT）：每行 <tag><value> 单字符前缀：
/// - p<pid>：进程 ID
/// - c<command>：进程命令名
/// - i<local-addr>:<local-port>-<remote-addr>:<remote-port>：internet socket
///
/// 匹配语义：给定 (source_ip, source_port)，找出 i 行 local endpoint 等于该 (ip, port) 的第一个 PID。
#[allow(dead_code)] // 仅 macOS proc_macos + tests 使用；其它平台构建时警告关闭
mod lsof_parser {
    use super::ProcessInfo;
    use std::net::IpAddr;

    pub(super) fn parse_lsof_output(
        raw: &[u8],
        want_ip: IpAddr,
        want_port: u16,
    ) -> Option<ProcessInfo> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut cur_pid: Option<u32> = None;
        let mut cur_cmd: Option<String> = None;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let (tag, rest) = line.split_at(1);
            match tag {
                "p" => {
                    cur_pid = rest.parse::<u32>().ok();
                    cur_cmd = None;
                }
                "c" => {
                    cur_cmd = Some(rest.to_string());
                }
                "i" => {
                    if let Some(pid) = cur_pid {
                        if lsof_line_matches(rest, want_ip, want_port) {
                            let cmd = cur_cmd.unwrap_or_default();
                            return Some(ProcessInfo {
                                name: cmd,
                                exe_path: String::new(),
                                pid,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// lsof `-F` `i` 行内容（去掉前缀 `i`）：形如 `TCPv4:1.2.3.4:54321-5.6.7.8:80` 或 `TCPv4:*:22-LISTEN`。
    /// 委托给 [`endpoint_matches`]。
    fn lsof_line_matches(rest: &str, want_ip: IpAddr, want_port: u16) -> bool {
        endpoint_matches(rest, want_ip, want_port)
    }


    fn endpoint_matches(ep: &str, want_ip: IpAddr, want_port: u16) -> bool {
        // ep 形如 "TCPv4:1.2.3.4:54321-5.6.7.8:80"（lsof -F i 行去掉 'i' 前缀）。
        // 1) 剥协议前缀（第一个 ':' 之前为协议名）。
        let Some(colon_pos) = ep.find(':') else {
            return false;
        };
        let after_proto = &ep[colon_pos + 1..];
        // 2) split at last '-' 区分 local / remote；rfind 避免 IP 含 '-'（IPv6 无 '-'）。
        let Some(dash_pos) = after_proto.rfind('-') else {
            // LISTEN 之类无 remote：local = after_proto。
            return parse_addr_port(after_proto)
                .is_some_and(|(ip, port)| ip == want_ip && port == want_port);
        };
        let local = &after_proto[..dash_pos];
        parse_addr_port(local)
            .is_some_and(|(ip, port)| ip == want_ip && port == want_port)
    }

    /// 解析 `<addr>:<port>`（IPv6 不带括号；lsof -F 输出对 IPv6 用 `[addr]:port`）。
    /// IPv6 在 lsof -F 中是 `[xxxx]:port` 形式；用 '[' 起始当作 v6。
    fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
        if let Some(rest) = s.strip_prefix('[') {
            // IPv6: [xxxx]:port
            let Some(bracket) = rest.find(']') else { return None; };
            let addr_str = &rest[..bracket];
            let after = &rest[bracket + 1..];
            let port_str = after.strip_prefix(':')?;
            let port = port_str.parse::<u16>().ok()?;
            let ip = addr_str.parse::<IpAddr>().ok()?;
            Some((ip, port))
        } else {
            // IPv4: <addr>:<port>；v4 addr 无 ':'，用最后一个 ':' 分。
            let Some(colon_pos) = s.rfind(':') else { return None; };
            let addr_str = &s[..colon_pos];
            let port_str = &s[colon_pos + 1..];
            let port = port_str.parse::<u16>().ok()?;
            let ip = addr_str.parse::<IpAddr>().ok()?;
            Some((ip, port))
        }
    }
}

 /// macOS lsof shell-out 实现。
 ///
 /// 对应 Go find_process_others.go：Go 在 macOS 上明确返回 process lookup is not supported。
 /// Rust 实现调 /usr/sbin/lsof -F pcnTi -i :<port>[@ip] -nP 取机器可读输出，
 /// 解析委托给 lsof_parser 模块。
#[cfg(target_os = "macos")]
mod proc_macos {
    use super::lsof_parser::parse_lsof_output;
    use std::net::IpAddr;
    use std::process::Command;

    pub(super) fn find_process(source_ip: IpAddr, source_port: u16) -> Option<super::ProcessInfo> {
        let port_filter = format!(":{source_port}");
        let ip_filter = match source_ip {
            IpAddr::V4(v4) => Some(format!("@{}", v4)),
            IpAddr::V6(v6) => Some(format!("@{}", v6)),
        };
        let mut args: Vec<&str> = vec!["-nP", "-F", "pcTi", "-i", &port_filter];
        if let Some(ip) = &ip_filter {
            args.insert(4, ip);
        }
        let output = Command::new("/usr/sbin/lsof").args(&args).output().ok()?;
        if !output.status.success() && output.status.code() != Some(1) {
            return None;
        }
        parse_lsof_output(&output.stdout, source_ip, source_port)
    }
}



/// FreeBSD libprocstat 实现。
///
/// 对应 Go `find_process_others.go`：Go 在 FreeBSD 上同样明确返回
/// "process lookup is not supported on this platform"。Rust 实现走
/// `<libprocstat.h>`（FreeBSD 13+ 标准）：`procstat_open_sysctl` → 对每个 PID
/// `procstat_getprocs(KERN_PROC_PID, pid)` → `procstat_getfiles` 列 fd → 筛
/// `PS_FTYPE_SOCKET` → `procstat_get_socket_info` 读 `sockstat.ss_laddr`/`ss_lport`
/// 与目标 local endpoint 比对。
#[cfg(target_os = "freebsd")]
mod proc_freebsd {
    use super::ProcessInfo;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use libc::{
        procstat_close, procstat_freefiles, procstat_freeprocs, procstat_getfiles,
        procstat_getprocs, procstat_get_socket_info, procstat_open_sysctl,
    };

    /// `<sys/proc.h>` `PS_FTYPE_SOCKET = 2`（libc 未导出，本地固定）。
    /// 见 `https://github.com/freebsd/freebsd-src/blob/main/sys/sys/proc.h`。
    const PS_FTYPE_SOCKET: i32 = 2;

    /// `<sys/socket.h>` 地址族。
    const AF_INET: libc::sa_family_t = 2;
    const AF_INET6: libc::sa_family_t = 28; // FreeBSD 值

    /// `procstat_get_socket_info` errbuf 长度（`<libprocstat.h>` 写 1024）。
    const ERRBUF_LEN: usize = 1024;

    pub(super) fn find_process(source_ip: IpAddr, source_port: u16) -> Option<ProcessInfo> {
        let ps = unsafe { procstat_open_sysctl() };
        if ps.is_null() {
            return None;
        }
        let result = scan_all_pids(ps, source_ip, source_port);
        unsafe { procstat_close(ps) };
        result
    }

    fn scan_all_pids(
        ps: *mut libc::procstat,
        source_ip: IpAddr,
        source_port: u16,
    ) -> Option<ProcessInfo> {
        // 取全进程表。
        let mut cnt: libc::c_uint = 0;
        let kp = unsafe { procstat_getprocs(ps, libc::KERN_PROC_ALL, 0, &mut cnt) };
        if kp.is_null() || cnt == 0 {
            if !kp.is_null() {
                unsafe { procstat_freeprocs(ps, kp) };
            }
            return None;
        }
        let mut hit: Option<ProcessInfo> = None;
        let procs = unsafe { std::slice::from_raw_parts(kp, cnt as usize) };
        for p in procs {
            let pid = p.ki_pid as u32;
            if pid <= 0 {
                continue;
            }
            // 取该 PID 的 fd 链表头。
            let files_head = unsafe { procstat_getfiles(ps, p as *const _ as *mut _, 0) };
            if files_head.is_null() {
                continue;
            }
            // 遍历 STAILQ（filestat.next.stqe_next 串联）。
            let mut cur = unsafe { (*files_head).stqh_first };
            while !cur.is_null() {
                let f: &libc::filestat = unsafe { &*cur };
                if f.fs_type == PS_FTYPE_SOCKET {
                    let mut ss: libc::sockstat = unsafe { std::mem::zeroed() };
                    let mut errbuf = [0i8; ERRBUF_LEN];
                    let rc = unsafe {
                        procstat_get_socket_info(ps, cur, &mut ss, errbuf.as_mut_ptr())
                    };
                    if rc == 0 && socket_matches(&ss, source_ip, source_port) {
                        hit = read_process_info(pid);
                        break;
                    }
                }
                cur = unsafe { (*cur).next.stqe_next };
            }
            unsafe { procstat_freefiles(ps, files_head) };
            if hit.is_some() {
                break;
            }
        }
        unsafe { procstat_freeprocs(ps, kp) };
        hit
    }

    /// 从 `sockstat.sa_local: sockaddr_storage` 解 (family, addr, port) 比对。
    fn socket_matches(ss: &libc::sockstat, want_ip: IpAddr, want_port: u16) -> bool {
        // sockaddr_storage 布局：offset 0 = ss_len (u8), offset 1 = ss_family (sa_family_t=u8 on FreeBSD).
        // ss_len 头 1 字节：FreeBSD sockaddr_storage 与 sockaddr_in/in6 头字段一致，
        // 直接按 sockaddr_in/sockaddr_in6 解释。
        let raw: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &ss.sa_local as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_storage>(),
            )
        };
        let len = raw[0] as usize;
        if len < 2 {
            return false;
        }
        // sa_family_t 在 BSD 系统上是 u8。
        let family = raw[1] as libc::sa_family_t;
        match (family, want_ip) {
            (AF_INET, IpAddr::V4(v4)) => {
                // sockaddr_in { u8 sin_len; u8 sin_family; u16 sin_port; struct in_addr sin_addr; }
                if len < 8 {
                    return false;
                }
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                if port != want_port {
                    return false;
                }
                let addr = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
                let have = Ipv4Addr::from(addr);
                have == v4
            }
            (AF_INET6, IpAddr::V6(v6)) => {
                // sockaddr_in6 { u8 sin6_len; u8 sin6_family; u16 sin6_port; u32 sin6_flowinfo;
                //                  struct in6_addr sin6_addr; u32 sin6_scope_id; }
                if len < 24 {
                    return false;
                }
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                if port != want_port {
                    return false;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw[8..24]);
                let have = Ipv6Addr::from(octets);
                have == v6
            }
            _ => false,
        }
    }

    /// sysinfo 兜底取进程名/exe。
    fn read_process_info(pid: u32) -> Option<ProcessInfo> {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(
            sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
            true,
        );
        let proc = sys.process(sysinfo::Pid::from_u32(pid))?;
        let name = proc.name().to_string_lossy().into_owned();
        let exe_path = proc.exe().map_or(String::new(), |p| p.to_string_lossy().into_owned());
        if name.is_empty() && exe_path.is_empty() {
            return None;
        }
        Some(ProcessInfo { name, exe_path, pid })
    }

    #[cfg(test)]
    pub(super) fn socket_matches_for_test(ss: &libc::sockstat, ip: IpAddr, port: u16) -> bool {
        socket_matches(ss, ip, port)
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

    // ── UserMatcher（严格等值语义，对齐 Go UserMatcher）──

    #[test]
    fn test_user_matcher_strict_equality() {
        // 与 Go `if u == user` (condition.go:190) 一致：ctx user 与 pattern 全等才命中。
        let m = UserMatcherCondition::new(vec![
            "admin@example.com".into(),
            "root@example.com".into(),
        ])
        .unwrap();
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
        let m = UserMatcherCondition::new(vec!["admin".into()]).unwrap();
        let ctx = RoutingData::new().with_user("admin@example.com");
        assert!(
            !m.apply(&ctx),
            "严格等值下 'admin' 子串不应命中 'admin@example.com'"
        );
        let full = RoutingData::new().with_user("admin");
        assert!(m.apply(&full), "全等仍是命中");
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

    #[test]
    fn test_user_matcher_lenient_alias_still_compiles() {
        // 历史 API 别名仍可用——编译期兜底（不验证 substring 行为，因为该类型已弃用）。
        #[allow(deprecated)]
        let _m: UserMatcherLenient =
            UserMatcherCondition::new(vec!["x@example.com".into()]).unwrap();
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
        assert!(
            m.apply(&hit),
            "key 大小写差异下应仍命中（两侧 ToLower 等价）"
        );

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

        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", target_os = "freebsd"))]
        {
            let info = info.expect("find_process 应能解析本进程 loopback 连接");
            assert_eq!(info.pid, std::process::id(), "应解析到本测试进程");
            assert!(!info.name.is_empty(), "进程名不应为空");
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos", target_os = "freebsd")))]
        {
            assert!(info.is_none(), "未支持平台应返回 None");
        }

        drop(server);
        drop(client);
    }

    // ── lsof (macOS) 解析器单元测试 ──
    // 纯文本解析，与平台 FFI 无关；macOS+FreeBSD+Windows 全部能跑。

    #[test]
    fn test_macos_lsof_parser_extracts_pid_and_command() {
        let raw = b"p1234\nccurl\ntiPv4\niTCPv4:1.2.3.4:54321-5.6.7.8:80\n";
        let info = lsof_parser::parse_lsof_output(
            raw,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            54321,
        );
        let info = info.expect("lsof 解析应命中");
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "curl");
    }

    #[test]
    fn test_macos_lsof_parser_no_match() {
        let raw = b"p1234\nccurl\ntiPv4\niTCPv4:1.2.3.4:11111-5.6.7.8:80\n";
        let info = lsof_parser::parse_lsof_output(
            raw,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            54321,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_macos_lsof_parser_multi_pid_first_hit() {
        let raw = b"\
p111\ncnope\ntiPv4\niTCPv4:9.9.9.9:11111-1.1.1.1:80\n\
p222\ncmatch\ntiPv4\niTCPv4:1.2.3.4:54321-5.6.7.8:80\n\
";
        let info = lsof_parser::parse_lsof_output(
            raw,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            54321,
        );
        let info = info.expect("第二个 PID 应匹配");
        assert_eq!(info.pid, 222);
        assert_eq!(info.name, "match");
    }

    #[test]
    fn test_macos_lsof_parser_ipv6() {
        let raw = b"p9001\nctest\ntiPv6\niTCPv6:[2001:db8::1]:443-2001:db8::2:54321\n";
        let info = lsof_parser::parse_lsof_output(
            raw,
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let info = info.expect("IPv6 端点应匹配");
        assert_eq!(info.pid, 9001);
    }

    #[test]
    fn test_macos_lsof_parser_wildcard_listen_no_match() {
        let raw = b"p333\ncsshd\ntiPv4\niTCPv4:*:22-LISTEN\n";
        let info = lsof_parser::parse_lsof_output(
            raw,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            22,
        );
        assert!(info.is_none(), "通配符端点不应匹配具体 IP");
    }


    // ── FreeBSD sockstat 解析器 mock 测试（仅 freebsd 编译运行） ──

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_freebsd_sockstat_matches_v4_endpoint() {
        // 手工构造 sockaddr_storage：len(1) + family(1) + port(2) + addr(4) = 8 bytes。
        let ss: libc::sockstat = unsafe { std::mem::zeroed() };
        // sa_local 头 8 字节：len=16（sizeof sockaddr_in），family=2（AF_INET），port=0xD431（54321 BE），
        // addr=1.2.3.4（network byte order = 0x01020304）。
        let raw = [
            16u8, 2u8, 0xD4, 0x31, 0x01, 0x02, 0x03, 0x04,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let raw_ptr = raw.as_ptr() as *const u8;
        let sa_ptr = &ss.sa_local as *const _ as *mut u8;
        unsafe {
            std::ptr::copy_nonoverlapping(raw_ptr, sa_ptr, raw.len());
        }
        assert!(proc_freebsd::socket_matches_for_test(
            &ss,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            54321
        ));
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_freebsd_sockstat_no_match_on_port_mismatch() {
        let ss: libc::sockstat = unsafe { std::mem::zeroed() };
        let raw = [
            16u8, 2u8, 0xD4, 0x31, 0x01, 0x02, 0x03, 0x04,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let raw_ptr = raw.as_ptr() as *const u8;
        let sa_ptr = &ss.sa_local as *const _ as *mut u8;
        unsafe {
            std::ptr::copy_nonoverlapping(raw_ptr, sa_ptr, raw.len());
        }
        // 端口不匹配（want 54322 vs real 54321）→ 不应命中
        assert!(!proc_freebsd::socket_matches_for_test(
            &ss,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            54322
        ));
    }

}

