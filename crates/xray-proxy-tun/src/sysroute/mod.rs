//! TUN 系统路由表（A3）与系统 DNS 接管（A4）——纯函数计划层。
//!
//! 对应 Go `proxy/tun/{tun_linux.go, tun_windows.go, tun_system_dns.go, handler.go}` 的
//! 系统级变更，拆成两层以便在不动真机的前提下测试：
//!
//! - **计划层**（本模块）：输入（接口列表、配置）→ 输出「路由/DNS 变更计划」
//!   （增/删条目列表，平台无关数据结构 [`RoutePlan`] / [`DnsPlan`]）。
//! - **执行器层**（[`executor`]）：把计划渲染成平台命令字符串（`ip route` /
//!   `route.exe` / `netsh` / `resolvectl`），**只拼参数，不执行**——真实执行需
//!   管理员权限且须用户在场，属后续接线。
//!
//! ## 安全边界
//!
//! 本模块与执行器在本仓内**从不**执行任何系统命令；测试只用伪造接口值 +
//! Recording 执行器断言「计划生成的命令行字符串」。默认（配置未开启）不生成
//! 任何计划、不做任何接口枚举。
//!
//! ## 与 Go 的语义对应（file:line 见 docs 报告）
//!
//! - 路由：`autoSystemRoutingTable` 每条 CIDR → masked → 挂 TUN 接口
//!   （Linux `Priority 1`，tun_linux.go:451-458；Windows `Metric 0` + 接口
//!   metric 0，tun_windows.go:120-150）。失败宁可无 TUN（handler.go:196-205）。
//! - 出口接口：`findDefaultInterface` 排除回环/未 Up/TUN 自身/索引 0
//!   （tun_linux.go:545-576）。
//! - 系统 DNS：`autoSystemDnsToGateway`（默认 false，仅 Linux 语义）→
//!   源=gateway 首地址、指向=gateway 后继（tun_linux.go:47-64）→
//!   `resolvectl dns/domain/default-route`，失败 `revert`（tun_linux.go:105-160）。
//!   Windows 无接管 flag 语义，`dns` 配置写 TUN 适配器自身
//!   （tun_windows.go:157 SetDNS；Close FlushDNS 只清 TUN，不动物理网卡）。

pub mod executor;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use xray_common::net::interface::{Interface, InterfaceAddr, InterfaceFlags};

use crate::config::{StackOptions, parse_ip_cidr};
use crate::error::{Result, TunError};

pub use executor::{
    Cmd, DnsExecutor, LinuxDns, LinuxRoutes, Recording, RouteExecutor, WindowsDns, WindowsRoutes,
    default_executors,
};

/// 目标平台——决定 metric 语义与执行器命令渲染面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux：`ip route`（metric = Go `Priority 1`）+ `resolvectl` DNS 接管。
    Linux,
    /// Windows：`route.exe`/`netsh`（metric = Go `Metric 0`）+ TUN 适配器 DNS。
    Windows,
    /// 其余平台：Go darwin/freebsd 有实现但不在本切片范围——计划层拒绝。
    Other,
}

impl Platform {
    /// 编译目标平台。
    #[must_use]
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Self::Other
        }
    }
}

/// 单条路由条目（计划层最小单元，平台无关）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// 目标网段地址（已按 prefix 掩码，对齐 Go `prefix.Masked()`）。
    pub destination: IpAddr,
    /// 前缀长度。
    pub prefix: u8,
    /// metric：Linux=1（Go `Priority: 1`）；Windows=0（Go `Metric: 0`）。
    pub metric: u32,
}

/// 路由变更计划（A3）。回滚与 [`RoutePlan::add`] 对称反序（执行器 `rollback`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub platform: Platform,
    /// TUN 接口名（Linux `dev`/Windows `interface=`）。
    pub interface: String,
    /// TUN 接口索引（Linux `LinkIndex` / Windows `IF`）。
    pub interface_index: u32,
    /// 待新增路由（按配置顺序，已掩码去重）。
    pub add: Vec<RouteEntry>,
    /// 物理出口接口选择（Go `autoOutboundsInterface`="auto" 的选择结果，排除回环/未 Up/TUN）。
    pub outbound_interface: Option<String>,
}

/// DNS 变更目标（平台分派）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTarget {
    /// Linux 接管（Go `autoSystemDnsToGateway`）：`source` 为路由探针源地址
    /// （gateway 首地址），`dns` 为解析器指向（gateway 后继，属 TUN）。
    LinuxTakeover { source: IpAddr, dns: IpAddr },
    /// Windows：TUN 适配器自身 DNS 服务器列表（Go `dns` 配置 + `LUID.SetDNS`）。
    WindowsAdapterServers { servers: Vec<IpAddr> },
}

/// DNS 变更计划（A4）。回滚：Linux=`resolvectl revert`；Windows=清空 TUN 适配器
/// DNS（对齐 Go Close 的 `FlushDNS`——Go 从不动物理网卡，故无需备份外部状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPlan {
    pub platform: Platform,
    /// 生效接口名（Linux=TUN 名；Windows=TUN 适配器名）。
    pub interface: String,
    pub target: DnsTarget,
}

/// 一次启动实际应用的系统变更集合（close 时整体回滚）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedSystemChanges {
    pub routes: Option<RoutePlan>,
    pub dns: Option<DnsPlan>,
}

/// 该平台上 DNS 计划是否需要生成（Go 语义按平台分派）。
fn dns_wanted(platform: Platform, options: &StackOptions) -> bool {
    match platform {
        // Linux：仅 flag 显式开启（Go tun_linux.go:106-108）。
        Platform::Linux => options.auto_system_dns_to_gateway,
        // Windows：`dns` 配置写 TUN 适配器（Go tun_windows.go:157 无条件 SetDNS，
        // 空列表等价清空→无事可做）；接管 flag 在 Windows 无运行时实现（Go 同）。
        Platform::Windows => !options.dns.is_empty(),
        // Go macOS 忽略 dns 字段（README "SYSTEM DNS" 节），同忽略。
        Platform::Other => false,
    }
}

/// 计划入口：接口列表 + 配置 → 变更计划。默认关闭 → `Ok(None)`。
///
/// `interfaces` 生产路径传 `xray_common::net::interfaces()`；测试传伪造值。
pub fn plan_changes(
    platform: Platform,
    interfaces: &[Interface],
    options: &StackOptions,
) -> Result<Option<AppliedSystemChanges>> {
    let routes_wanted = !options.auto_system_routing_table.is_empty();
    let dns_wanted = dns_wanted(platform, options);
    if !routes_wanted && !dns_wanted {
        return Ok(None);
    }
    let routes =
        if routes_wanted { Some(plan_routes(platform, interfaces, options)?) } else { None };
    let dns = if dns_wanted { plan_dns(platform, options)? } else { None };
    Ok(Some(AppliedSystemChanges { routes, dns }))
}

/// A3：由 `autoSystemRoutingTable` 生成路由计划。
///
/// 对应 Go `LinuxTun.setSystemRoutes`（tun_linux.go:438-470）与 Windows 侧
/// `routesMap` 构造（tun_windows.go:120-150）。
pub fn plan_routes(
    platform: Platform,
    interfaces: &[Interface],
    options: &StackOptions,
) -> Result<RoutePlan> {
    if platform == Platform::Other {
        return Err(TunError::InvalidConfig(
            "automatic system routes are not supported on this platform".into(),
        ));
    }
    let tun = interfaces.iter().find(|i| i.name == options.name).ok_or_else(|| {
        TunError::DeviceNotFound(format!(
            "tun interface {:?} not present in system interface list",
            options.name
        ))
    })?;
    // Go 有效索引从 1 起；0 = 数据源哨兵（不得消费，见 interface.rs 模块文档）。
    if tun.index == 0 {
        return Err(TunError::InvalidConfig(format!(
            "interface {:?} has no usable index",
            options.name
        )));
    }
    // Go Linux `Priority: 1`（tun_linux.go:455）；Windows `Metric: 0`（tun_windows.go:125）。
    let metric = match platform {
        Platform::Windows => 0,
        Platform::Linux | Platform::Other => 1,
    };
    let mut add: Vec<RouteEntry> = Vec::new();
    for cidr in &options.auto_system_routing_table {
        let Some((addr, prefix)) = parse_ip_cidr(cidr) else {
            return Err(TunError::InvalidConfig(format!("invalid system route {cidr:?}")));
        };
        // Go `prefix.Masked()`：清掉主机位再下发。
        let entry = RouteEntry { destination: mask_prefix(addr, prefix), prefix, metric };
        // 去重保序：Go Windows 用 map 去重；Linux 重复 CIDR 会在 RouteAdd 处
        // EEXIST——计划层统一去重（更宽容，host 级配置无 wire 语义）。
        if !add.contains(&entry) {
            add.push(entry);
        }
    }
    let outbound_interface =
        select_outbound_interface(interfaces, tun.index).map(|i| i.name.clone());
    Ok(RoutePlan {
        platform,
        interface: options.name.clone(),
        interface_index: tun.index,
        add,
        outbound_interface,
    })
}

/// 物理出口接口选择：Go `findDefaultInterface`（tun_linux.go:545-576）的排除规则
/// （跳过未 Up、回环、TUN 自身、索引 0）。选优 Go 用内核路由 metric（if-addrs
/// 数据源不提供路由表）——以 [`score`](crate::config::score) 启发式替代，高分胜出。
#[must_use]
pub fn select_outbound_interface(interfaces: &[Interface], tun_index: u32) -> Option<&Interface> {
    let mut best: Option<(&Interface, i32)> = None;
    for iface in interfaces {
        if !iface.is_up() || iface.flags.contains(InterfaceFlags::LOOPBACK) {
            continue;
        }
        if iface.index == tun_index || iface.index == 0 {
            continue;
        }
        let addr_strs: Vec<String> = iface
            .addresses
            .iter()
            .map(|a| match a {
                InterfaceAddr::V4(v4) => format!("{}/{}", v4.ip, v4.prefixlen),
                InterfaceAddr::V6(v6) => format!("{}/{}", v6.ip, v6.prefixlen),
            })
            .collect();
        let strs: Vec<&str> = addr_strs.iter().map(String::as_str).collect();
        let s = crate::config::score(&iface.name, &strs);
        let better = match best {
            None => true,
            Some((_, best_score)) => s > best_score,
        };
        if better {
            best = Some((iface, s));
        }
    }
    best.map(|(iface, _)| iface)
}

/// A4：按平台生成 DNS 计划（见 [`dns_wanted`] 的平台分派）。
pub fn plan_dns(platform: Platform, options: &StackOptions) -> Result<Option<DnsPlan>> {
    match platform {
        Platform::Linux => {
            if !options.auto_system_dns_to_gateway {
                return Ok(None);
            }
            // Go infra/conf/tun.go:62-65 在配置期拒绝缺 gateway；此处运行期双保险。
            let (source, dns) = system_dns_addrs(&options.gateway).ok_or_else(|| {
                TunError::InvalidConfig("no gateway, cannot derive a system DNS address".into())
            })?;
            Ok(Some(DnsPlan {
                platform,
                interface: options.name.clone(),
                target: DnsTarget::LinuxTakeover { source, dns },
            }))
        },
        Platform::Windows => {
            if options.dns.is_empty() {
                return Ok(None);
            }
            let mut servers = Vec::with_capacity(options.dns.len());
            for s in &options.dns {
                let ip: IpAddr = s
                    .parse()
                    .map_err(|_| TunError::InvalidConfig(format!("invalid dns address {s:?}")))?;
                servers.push(ip);
            }
            Ok(Some(DnsPlan {
                platform,
                interface: options.name.clone(),
                target: DnsTarget::WindowsAdapterServers { servers },
            }))
        },
        // Go macOS 忽略 dns 字段。
        Platform::Other => Ok(None),
    }
}

/// Go `systemDNSAddrs`（tun_linux.go:47-64）：首个 IPv4 gateway（否则首个 IPv6）——
/// gateway 地址即本接口查询的源地址，其后继地址属 TUN、由 Xray 应答。
fn system_dns_addrs(gateway: &[String]) -> Option<(IpAddr, IpAddr)> {
    let mut first_v6 = None;
    for cidr in gateway {
        let Some((addr, _)) = parse_ip_cidr(cidr) else { continue };
        if let IpAddr::V4(v4) = addr {
            let a = IpAddr::V4(v4);
            return Some((a, next_ip(a)));
        }
        if first_v6.is_none() {
            first_v6 = Some(addr);
        }
    }
    first_v6.map(|a| {
        let dns = next_ip(a);
        (a, dns)
    })
}

/// 地址后继（Go `netip.Addr.Next`：加一，尾界回绕）。
fn next_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4).wrapping_add(1))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6).wrapping_add(1))),
    }
}

/// 按 prefix 清主机位（Go `netip.Prefix.Masked`）。`prefix` 已由
/// [`parse_ip_cidr`] 保证 ≤ 32/128。
fn mask_prefix(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = if prefix == 0 { 0 } else { u32::from(v4) & (u32::MAX << (32 - prefix)) };
            IpAddr::V4(Ipv4Addr::from(bits))
        },
        IpAddr::V6(v6) => {
            let bits = if prefix == 0 { 0 } else { u128::from(v6) & (u128::MAX << (128 - prefix)) };
            IpAddr::V6(Ipv6Addr::from(bits))
        },
    }
}

/// prefix → 点分十进制掩码（Windows `route.exe` 的 `mask` 参数）。
pub(crate) fn v4_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ipv4Addr::from(bits)
}

/// 启动侧接线：按配置门控 → 枚举真实接口 → 生成计划 → **真实执行**。
///
/// 默认关闭：直接 `Ok(None)`，**不枚举接口、不生成任何计划、不执行任何命令**。
/// 执行失败（任一命令 spawn 失败/非零退出，或平台无执行器）→ 错误上抛 →
/// 调用方关设备拒启动（对齐 Go handler.go:196-205 "宁可无 TUN"）。
pub(crate) fn prepare(options: &StackOptions) -> Result<Option<AppliedSystemChanges>> {
    let Some(applied) =
        plan_changes(Platform::current(), &xray_common::net::interface::interfaces()?, options)?
    else {
        return Ok(None);
    };
    let (routes, dns) = default_executors();
    apply_changes_exec(&applied, routes.as_deref(), dns.as_deref())?;
    Ok(Some(applied))
}

/// 启动侧渲染（审计/DryRun 面）：路由先于 DNS（对应 Go Start → ConfigureSystemDNS），
/// 返回将下发的命令行文本。**不执行**。
pub fn apply_changes(
    applied: &AppliedSystemChanges,
    routes: Option<&dyn RouteExecutor>,
    dns: Option<&dyn DnsExecutor>,
) -> Vec<String> {
    let mut commands = Vec::new();
    if let (Some(plan), Some(rx)) = (&applied.routes, routes) {
        commands.extend(rx.apply(plan).iter().map(ToString::to_string));
    }
    if let (Some(plan), Some(dx)) = (&applied.dns, dns) {
        commands.extend(dx.apply(plan).iter().map(ToString::to_string));
    }
    commands
}

/// 启动侧**真实执行**：路由先于 DNS；任一命令失败即停并上抛。计划存在而执行器
/// 缺失（平台未支持）→ 显式报错，绝不静默跳过。
///
/// # Errors
/// 任一命令 spawn 失败或非零退出（[`Cmd::run`]）；或对应平台无执行器。
pub fn apply_changes_exec(
    applied: &AppliedSystemChanges,
    routes: Option<&dyn RouteExecutor>,
    dns: Option<&dyn DnsExecutor>,
) -> std::io::Result<()> {
    if let Some(plan) = &applied.routes {
        let Some(rx) = routes else {
            return Err(std::io::Error::other(format!(
                "no route executor for platform {:?}",
                plan.platform
            )));
        };
        rx.apply_exec(plan)?;
    }
    if let Some(plan) = &applied.dns {
        let Some(dx) = dns else {
            return Err(std::io::Error::other(format!(
                "no dns executor for platform {:?}",
                plan.platform
            )));
        };
        dx.apply_exec(plan)?;
    }
    Ok(())
}

/// 关闭侧渲染（审计面）：DNS 先于路由（对齐 Go Close：`unsetSystemDNS` → `unsetSystemRoutes`）。
pub fn revert_changes(
    applied: &AppliedSystemChanges,
    routes: Option<&dyn RouteExecutor>,
    dns: Option<&dyn DnsExecutor>,
) -> Vec<String> {
    let mut commands = Vec::new();
    if let (Some(plan), Some(dx)) = (&applied.dns, dns) {
        commands.extend(dx.rollback(plan).iter().map(ToString::to_string));
    }
    if let (Some(plan), Some(rx)) = (&applied.routes, routes) {
        commands.extend(rx.rollback(plan).iter().map(ToString::to_string));
    }
    commands
}

/// 关闭侧**真实执行**（[`revert_changes`] 的逆序执行）。
///
/// # Errors
/// 任一命令 spawn 失败或非零退出；或对应平台无执行器。
pub fn revert_changes_exec(
    applied: &AppliedSystemChanges,
    routes: Option<&dyn RouteExecutor>,
    dns: Option<&dyn DnsExecutor>,
) -> std::io::Result<()> {
    if let Some(plan) = &applied.dns {
        let Some(dx) = dns else {
            return Err(std::io::Error::other(format!(
                "no dns executor for platform {:?}",
                plan.platform
            )));
        };
        dx.rollback_exec(plan)?;
    }
    if let Some(plan) = &applied.routes {
        let Some(rx) = routes else {
            return Err(std::io::Error::other(format!(
                "no route executor for platform {:?}",
                plan.platform
            )));
        };
        rx.rollback_exec(plan)?;
    }
    Ok(())
}

/// 关闭侧接线（[`prepare`] 的逆操作）。回滚失败显式 `tracing::error!` 上报
/// （系统状态可能残留），但不阻塞设备关闭——对齐 Go Close 对 unset 错误的
/// 记日志不中止语义（tun_linux.go:353-367）。
pub(crate) fn revert(applied: &AppliedSystemChanges) {
    let (routes, dns) = default_executors();
    if let Err(e) = revert_changes_exec(applied, routes.as_deref(), dns.as_deref()) {
        tracing::error!(
            target: "xray_proxy_tun", error = %e,
            "tun system route/dns revert FAILED; system state may remain dirty"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysroute::executor::{LinuxDns, LinuxRoutes, WindowsDns, WindowsRoutes};
    use xray_common::net::interface::{InterfaceAddr, InterfaceAddrV4};

    const UP: InterfaceFlags = InterfaceFlags::UP;
    const LOOPBACK: InterfaceFlags = InterfaceFlags::LOOPBACK;

    fn v4_addr(ip: [u8; 4], prefix: u8) -> InterfaceAddr {
        InterfaceAddr::V4(InterfaceAddrV4 {
            ip: Ipv4Addr::from(ip),
            netmask: v4_mask(prefix),
            prefixlen: prefix,
            broadcast: None,
        })
    }

    /// 伪造接口：mtu=0 / mac=None 为数据源哨兵，计划层不得消费（红线）。
    fn iface(
        name: &str,
        index: u32,
        flags: InterfaceFlags,
        addrs: Vec<InterfaceAddr>,
    ) -> Interface {
        Interface {
            index,
            mtu: 0,
            name: name.to_string(),
            hardware_addr: None,
            flags,
            addresses: addrs,
        }
    }

    fn opts(routing: &[&str], dns: &[&str], dns_takeover: bool) -> StackOptions {
        StackOptions {
            name: "xray0".into(),
            gateway: vec!["192.168.100.1/30".into()],
            dns: dns.iter().map(|s| s.to_string()).collect(),
            auto_system_routing_table: routing.iter().map(|s| s.to_string()).collect(),
            auto_system_dns_to_gateway: dns_takeover,
            ..StackOptions::default()
        }
    }

    fn tun_and_eth() -> Vec<Interface> {
        vec![
            iface(
                "xray0",
                24,
                UP | InterfaceFlags::POINT_TO_POINT,
                vec![v4_addr([10, 0, 0, 1], 24)],
            ),
            iface("eth0", 5, UP, vec![v4_addr([192, 168, 1, 10], 24)]),
        ]
    }

    // ===== 验收 1：固定接口集合 + 配置 → 路由计划逐条匹配（含 metric/index/网段） =====

    #[test]
    fn route_plan_linux_entries_match_config() {
        let o = opts(&["0.0.0.0/0", "10.9.8.7/24", "2001:db8::/32"], &[], false);
        let plan = plan_routes(Platform::Linux, &tun_and_eth(), &o).expect("plan");
        assert_eq!(plan.interface_index, 24);
        assert_eq!(plan.interface, "xray0");
        assert_eq!(
            plan.add,
            vec![
                RouteEntry { destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix: 0, metric: 1 },
                RouteEntry {
                    destination: IpAddr::V4(Ipv4Addr::new(10, 9, 8, 0)),
                    prefix: 24,
                    metric: 1
                },
                RouteEntry {
                    destination: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                    prefix: 32,
                    metric: 1
                },
            ]
        );
        // 出口接口：TUN 自身被排除，eth0 带 192.168 得分入选。
        assert_eq!(plan.outbound_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn route_plan_windows_uses_metric_zero() {
        let o = opts(&["10.9.8.7/24"], &[], false);
        let plan = plan_routes(Platform::Windows, &tun_and_eth(), &o).expect("plan");
        assert_eq!(
            plan.add,
            vec![RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(10, 9, 8, 0)),
                prefix: 24,
                metric: 0
            }]
        );
    }

    #[test]
    fn route_plan_masks_host_bits_and_dedups() {
        // 主机位被清掉 + 掩码后重复只留一条（保序）。
        let o = opts(&["10.9.8.7/24", "10.9.8.99/24", "0.0.0.0/0", "0.0.0.0/0"], &[], false);
        let plan = plan_routes(Platform::Linux, &tun_and_eth(), &o).expect("plan");
        assert_eq!(
            plan.add,
            vec![
                RouteEntry {
                    destination: IpAddr::V4(Ipv4Addr::new(10, 9, 8, 0)),
                    prefix: 24,
                    metric: 1
                },
                RouteEntry { destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix: 0, metric: 1 },
            ]
        );
    }

    #[test]
    fn route_plan_requires_tun_interface_present() {
        let mut ifs = tun_and_eth();
        ifs[0].name = "other0".into();
        let o = opts(&["0.0.0.0/0"], &[], false);
        let err = plan_routes(Platform::Linux, &ifs, &o).unwrap_err();
        assert!(matches!(err, TunError::DeviceNotFound(_)), "{err:?}");
    }

    #[test]
    fn route_plan_rejects_unsupported_platform() {
        let o = opts(&["0.0.0.0/0"], &[], false);
        let err = plan_routes(Platform::Other, &tun_and_eth(), &o).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    // ===== 验收 2：排除回环与未 Up 接口 =====

    #[test]
    fn select_outbound_excludes_loopback_down_tun_and_zero_index() {
        let interfaces = vec![
            iface("xray0", 24, UP, vec![v4_addr([10, 0, 0, 1], 24)]), // TUN 自身
            iface("lo", 1, UP | LOOPBACK, vec![v4_addr([127, 0, 0, 1], 8)]), // 回环
            iface("dead0", 7, InterfaceFlags::empty(), vec![v4_addr([10, 1, 1, 1], 24)]), // 未 Up
            iface("zero0", 0, UP, vec![v4_addr([10, 2, 2, 2], 24)]),  // 索引哨兵 0
            iface("eth1", 9, UP, vec![v4_addr([10, 3, 3, 3], 24)]),   // 候选（score 0）
            iface("wlan0", 8, UP, vec![v4_addr([192, 168, 50, 2], 24)]), // 最优（score 3）
        ];
        assert_eq!(
            select_outbound_interface(&interfaces, 24).map(|i| i.name.as_str()),
            Some("wlan0")
        );
    }

    #[test]
    fn select_outbound_none_when_only_loopback() {
        let interfaces = vec![iface("lo", 1, UP | LOOPBACK, vec![v4_addr([127, 0, 0, 1], 8)])];
        assert!(select_outbound_interface(&interfaces, 24).is_none());
    }

    // ===== 验收 5：配置未开启 → 不生成任何计划 =====

    #[test]
    fn disabled_config_generates_no_plan() {
        let interfaces = tun_and_eth();
        let disabled = StackOptions::default();
        assert_eq!(plan_changes(Platform::Linux, &interfaces, &disabled).unwrap(), None);
        assert_eq!(plan_changes(Platform::Windows, &interfaces, &disabled).unwrap(), None);
        // 路由关但 Windows 带 dns 列表 → 仅 DNS 计划，无路由计划。
        let dns_only = opts(&[], &["1.1.1.1"], false);
        let applied = plan_changes(Platform::Windows, &interfaces, &dns_only).unwrap().unwrap();
        assert!(applied.routes.is_none());
        assert!(applied.dns.is_some());
    }

    #[test]
    fn dns_disabled_by_default_on_linux() {
        // flag 缺省 false：不生成 DNS 计划（Go TestConfigureSystemDNSDisabledByDefault）。
        let o = opts(&[], &[], false);
        assert_eq!(plan_dns(Platform::Linux, &o).unwrap(), None);
        let applied = plan_changes(Platform::Linux, &tun_and_eth(), &o).unwrap();
        assert_eq!(applied, None);
    }

    // ===== 验收 4：系统 DNS 计划（目标 + 回滚恢复） =====

    #[test]
    fn dns_linux_takeover_matches_go_shape() {
        // Go tun_linux_dns_test.go fixture：gateway 192.168.100.1/30 → 源 .1、指向 .2。
        let o = opts(&[], &[], true);
        let plan = plan_dns(Platform::Linux, &o).unwrap().expect("plan");
        assert_eq!(plan.interface, "xray0");
        assert_eq!(
            plan.target,
            DnsTarget::LinuxTakeover {
                source: "192.168.100.1".parse().unwrap(),
                dns: "192.168.100.2".parse().unwrap(),
            }
        );
        let ex = LinuxDns;
        assert_eq!(
            render(&ex.apply(&plan)),
            vec![
                "resolvectl dns xray0 192.168.100.2",
                "resolvectl domain xray0 ~.",
                "resolvectl default-route xray0 true",
            ]
        );
        // 回滚恢复 = Go unsetSystemDNS 的 `resolvectl revert <iface>`。
        assert_eq!(render(&ex.rollback(&plan)), vec!["resolvectl revert xray0"]);
    }

    #[test]
    fn dns_linux_requires_gateway() {
        let mut o = opts(&[], &[], true);
        o.gateway.clear();
        let err = plan_dns(Platform::Linux, &o).unwrap_err();
        assert!(err.to_string().contains("no gateway"), "{err}");
    }

    #[test]
    fn dns_linux_ipv6_fallback_when_no_v4_gateway() {
        let mut o = opts(&[], &[], true);
        o.gateway = vec!["fc00::1/64".into()];
        let plan = plan_dns(Platform::Linux, &o).unwrap().expect("plan");
        assert_eq!(
            plan.target,
            DnsTarget::LinuxTakeover {
                source: "fc00::1".parse().unwrap(),
                dns: "fc00::2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn dns_windows_adapter_servers_apply_and_rollback_clear() {
        let o = opts(&[], &["1.1.1.1", "8.8.8.8", "fd00::1"], false);
        let plan = plan_dns(Platform::Windows, &o).unwrap().expect("plan");
        let ex = WindowsDns;
        assert_eq!(
            render(&ex.apply(&plan)),
            vec![
                "netsh interface ipv4 set dnsservers name=xray0 source=static address=1.1.1.1 validate=no",
                "netsh interface ipv4 add dnsservers name=xray0 address=8.8.8.8 index=2 validate=no",
                "netsh interface ipv6 set dnsservers name=xray0 source=static address=fd00::1 validate=no",
            ]
        );
        // 回滚 = 清空 TUN 适配器 DNS（Go Close FlushDNS 的命令面；不动物理网卡）。
        assert_eq!(
            render(&ex.rollback(&plan)),
            vec![
                "netsh interface ipv4 set dnsservers name=xray0 source=static address=none validate=no",
                "netsh interface ipv6 set dnsservers name=xray0 source=static address=none validate=no",
            ]
        );
    }

    #[test]
    fn next_ip_wraps_at_family_boundary() {
        assert_eq!(
            next_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1))).to_string(),
            "192.168.100.2"
        );
        assert_eq!(next_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))).to_string(), "0.0.0.0");
    }

    // ===== 验收 3：回滚计划与添加计划对称 + Recording 执行器 =====

    #[test]
    fn route_rollback_is_symmetric_reverse_of_apply() {
        let o = opts(&["0.0.0.0/0", "10.9.8.7/24"], &[], false);
        let plan = plan_routes(Platform::Linux, &tun_and_eth(), &o).expect("plan");
        let rx = Recording::new(LinuxRoutes);
        let added = rx.apply(&plan);
        let removed = rx.rollback(&plan);
        // 逐条对称：del 与 add 同参数，反序回滚（对齐 Go unsetSystemRoutes 反序删除）。
        let added_text: Vec<String> = added.iter().map(ToString::to_string).collect();
        let expect_removed: Vec<String> = added_text
            .iter()
            .rev()
            .map(|cmd| cmd.replace("ip route add", "ip route del"))
            .collect();
        assert_eq!(render(&removed), expect_removed);
        // Recording 记录了全部渲染命令（DryRun 审计面）。
        assert_eq!(rx.recorded().len(), added.len() + removed.len());
    }

    #[test]
    fn windows_route_commands_cover_both_families() {
        let o = opts(&["0.0.0.0/0", "2001:db8::/32"], &[], false);
        let plan = plan_routes(Platform::Windows, &tun_and_eth(), &o).expect("plan");
        let rx = Recording::new(WindowsRoutes);
        let added = rx.apply(&plan);
        assert_eq!(
            render(&added),
            vec![
                "route add 0.0.0.0 mask 0.0.0.0 metric 0 if 24",
                "netsh interface ipv6 add route 2001:db8::/32 interface=xray0 metric=0",
            ]
        );
        let removed = rx.rollback(&plan);
        assert_eq!(
            render(&removed),
            vec![
                "netsh interface ipv6 delete route 2001:db8::/32 interface=xray0 metric=0",
                "route delete 0.0.0.0 mask 0.0.0.0 metric 0 if 24",
            ]
        );
    }

    /// `Cmd` → 完整命令行文本（Display 即未来 spawn 的 argv 拼接）。
    fn render(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn apply_and_revert_change_sets_are_symmetric() {
        // 路由 + DNS 同时开启：apply 顺序 路由→DNS，revert 顺序 DNS→路由（Go Close 序）。
        let o = opts(&["0.0.0.0/0"], &[], true);
        let applied = plan_changes(Platform::Linux, &tun_and_eth(), &o).unwrap().expect("applied");
        let rr = Recording::new(LinuxRoutes);
        let dr = Recording::new(LinuxDns);
        let applied_cmds = apply_changes(&applied, Some(&rr), Some(&dr));
        let reverted_cmds = revert_changes(&applied, Some(&rr), Some(&dr));
        assert_eq!(
            applied_cmds,
            vec![
                "ip route add 0.0.0.0/0 metric 1 dev xray0",
                "resolvectl dns xray0 192.168.100.2",
                "resolvectl domain xray0 ~.",
                "resolvectl default-route xray0 true",
            ]
        );
        assert_eq!(
            reverted_cmds,
            vec!["resolvectl revert xray0", "ip route del 0.0.0.0/0 metric 1 dev xray0"]
        );
        assert_eq!(rr.recorded().len(), 2);
        assert_eq!(dr.recorded().len(), 4);
    }

    /// `Cmd::run` 是全模块唯一执行点：spawn 失败必须显式上抛（不吞）。
    /// 本测试只 spawn 一个必然不存在的程序名——零系统命令、零副作用。
    #[test]
    fn cmd_run_reports_spawn_failure() {
        let err = Cmd::new("definitely-not-a-real-program-9f3a", Vec::new()).run().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    }

    /// 平台缺执行器时执行面必须显式报错，绝不静默跳过（防「名义接管」）。
    #[test]
    fn apply_exec_without_executor_is_explicit_error() {
        let o = opts(&["0.0.0.0/0"], &[], false);
        let applied = plan_changes(Platform::Linux, &tun_and_eth(), &o).unwrap().expect("applied");
        let err = apply_changes_exec(&applied, None, None).unwrap_err();
        assert!(err.to_string().contains("no route executor"), "{err}");
    }
}
