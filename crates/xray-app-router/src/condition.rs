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

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let info = info.expect("find_process 应能解析本进程 loopback 连接");
            assert_eq!(info.pid, std::process::id(), "应解析到本测试进程");
            assert!(!info.name.is_empty(), "进程名不应为空");
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            assert!(info.is_none(), "未支持平台应返回 None");
        }

        drop(server);
        drop(client);
    }
}
