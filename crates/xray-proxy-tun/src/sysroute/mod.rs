//! TUN 系统路由表（A3）与系统 DNS 接管（A4）——计划层 + 执行器层。
//!
//! 对应 Go `proxy/tun/{tun_linux.go, tun_windows.go, tun_system_dns.go, handler.go}` 的
//! 系统级变更，拆成两层：计划层是纯函数（可离线单测），执行器层负责渲染与落盘。
//!
//! - **计划层**（本模块）：输入（接口列表、配置）→ 输出「路由/DNS 变更计划」
//!   （增/删条目列表，平台无关数据结构 [`RoutePlan`] / [`DnsPlan`]）。
//! - **执行器层**（[`executor`]）：把计划渲染成平台命令（`ip route` / `route.exe` / `netsh` /
//!   `resolvectl`）。**渲染面**（`apply`/`rollback` →
//!   [`Cmd`]）只拼参数不执行；**执行面**（`apply_exec`/`rollback_exec` → [`Cmd::run`]）逐条真实
//!   spawn 系统进程——**真实执行需管理员权限**。
//!
//! ## 安全边界
//!
//! 默认（配置未开启）不生成任何计划、不枚举接口、不执行任何命令；配置显式开启
//! 且接线到位时，启动侧 `prepare` 会调 `apply_changes_exec` 真实 spawn——
//! **需管理员权限**。测试只用伪造接口值 + [`Recording`] 执行器替身断言
//! 「计划生成的命令行字符串」，从不触发真实执行。
//!
//! ## 与 Go 的语义对应（file:line 见 docs 报告）
//!
//! - 路由：`autoSystemRoutingTable` 每条 CIDR → masked → 挂 TUN 接口 （Linux `Priority
//!   1`，tun_linux.go:451-458；Windows `Metric 0` + 接口 metric
//!   0，tun_windows.go:120-150）。失败宁可无 TUN（handler.go:196-205）。 **两族都下发**：v4 →
//!   `route.exe`，v6 → `netsh interface ipv6 add route` （`route.exe` 不认 v6）。
//! - Windows IPv6 双栈（票 1qmer B-8）：地址由 [`crate::device::TunDevice::create`] 的 tun-rs
//!   builder 下发（`CreateUnicastIpAddressEntry(AF_INET6)` = Go
//!   `SetIPAddressesForFamily`，tun_windows.go:192-204）；适配器属性补 v6 侧
//!   （`adapter_props_cmds`）；DNS 按族（[`executor::WindowsDns`]）；关闭侧清地址
//!   （`flush_address_cmds` = Go `FlushIPAddresses`）。**配了 IPv6 而系统 `DisabledComponents`
//!   关掉它 ⇒ 拒启**（`ensure_ipv6_supported`，Go 那边只记日志—— 本仓按票判 fail-loud）。
//! - 出口接口：`findDefaultInterface` 排除回环/未 Up/TUN 自身/索引 0 （tun_linux.go:545-576）。
//! - 系统 DNS：`autoSystemDnsToGateway`（默认 false，仅 Linux 语义）→ 源=gateway
//!   首地址、指向=gateway 后继（tun_linux.go:47-64）→ **应用前防环路验证**
//!   （`dns_verify::verify_dns_routing`，tun_system_dns.go:29-96；验证不过拒启）→ `resolvectl
//!   dns/domain/default-route`，失败 `revert`（tun_linux.go:105-160）。 Windows 无接管 flag
//!   语义，`dns` 配置写 TUN 适配器自身 （tun_windows.go:157 SetDNS；Close FlushDNS 只清
//!   TUN，不动物理网卡；无验证语义， 显式记日志跳过）。

pub mod executor;
/// weak host send 守卫（Go `tun_windows_outbound.go`）——仅 Windows。
#[cfg(target_os = "windows")]
pub mod guard;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

pub use executor::{
    Cmd, DnsExecutor, LinuxDns, LinuxRoutes, Recording, RouteExecutor, WindowsDns, WindowsRoutes,
    default_executors,
};
use xray_common::net::interface::{Interface, InterfaceAddr, InterfaceFlags};
use xray_transport::dns_skip::skip_dns_servers;

use crate::{
    config::{StackOptions, parse_ip_cidr},
    dns_verify::{DnsRoutingProbe, verify_dns_routing},
    error::{Result, TunError},
};

/// 目标平台——决定 metric 语义与执行器命令渲染面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux：`ip route`（metric = Go `Priority 1`）+ `resolvectl` DNS 接管。
    Linux,
    /// Windows：`route.exe`/`netsh`（metric = Go `Metric 0`）+ TUN 适配器 DNS。
    Windows,
    /// 其余平台（macOS/FreeBSD 等）：Go 的 `tun_darwin.go`/`tun_freebsd.go` 系统层
    /// （utun 地址/SIOCAIFADDR、AF_ROUTE 路由报文、resolvconf）尚未接线 ⇒ 计划层
    /// **入口即拒绝**（fail-loud）。绝不返回「无变更」让 TUN 静默起来却不配路由/DNS
    /// ——那样的 TUN 一个包也过不去，用户只会看到「代理没生效」却没有报错（bd bv98n）。
    Other,
}

/// 未接线平台的统一错误文案（计划层各入口共用；单测断言此串，别再散落字面量）。
const UNWIRED_PLATFORM: &str = "TUN is not wired on this platform yet; supported: Linux/Windows \
     (Android/iOS take a host-injected fd)";

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
        // 未接线平台：`plan_changes` 已先行拒绝，本分支不会被问到——保留只为平台分派
        // 穷尽。`plan_dns` 自身对 `Platform::Other` 是 `Err`（见 [`UNWIRED_PLATFORM`]）。
        Platform::Other => false,
    }
}

/// 计划入口：接口列表 + 配置 → 变更计划。默认关闭 → `Ok(None)`；未接线平台 → `Err`
/// （即使配置全关也不放行——见 [`Platform::Other`]）。
///
/// `interfaces` 生产路径传 `xray_common::net::interfaces()`；测试传伪造值。
pub fn plan_changes(
    platform: Platform,
    interfaces: &[Interface],
    options: &StackOptions,
) -> Result<Option<AppliedSystemChanges>> {
    // 平台门闸先于「配没配」判断：平台系统层没接线时起 TUN 本身就没意义
    // （无路由 → 流量永不经 TUN），必须显式拒启而不是静默返回无变更（bd bv98n）。
    if platform == Platform::Other {
        return Err(TunError::InvalidConfig(UNWIRED_PLATFORM.into()));
    }
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
        return Err(TunError::InvalidConfig(UNWIRED_PLATFORM.into()));
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

// ===== 出站接口绑定（Go InterfaceUpdater + RegisterDialerController，handler.go:130-164）=====

/// 出站绑定状态：物理网卡 `(索引, 名字)`。对应 Go `InterfaceUpdater.iface`
/// （config.go:14-21；名字只用于日志，Go 的 `iface.Name`）。Go 在路由/链路变化时
/// `Update()` 重选，Rust 无监控器，仅 Start 时选一次——动态重选留后续票。
static OUTBOUND_IFACE: parking_lot::RwLock<Option<(u32, String)>> = parking_lot::RwLock::new(None);

/// controller 进程级只注册一次的闸。Go 每次 Start 追加注册一个读同一包级
/// `updater` 的闭包；Rust 状态收敛进 [`OUTBOUND_IFACE`]，闭包无状态，
/// 重复注册只添冗余。
static OUTBOUND_CONTROLLER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// 更新出站绑定状态。`None` = 解除（TUN 关闭/回滚/换配置重启后，dialer
/// controller 变 no-op，拨号回归系统路由表）。
pub(crate) fn set_outbound_iface(iface: Option<(u32, String)>) {
    *OUTBOUND_IFACE.write() = iface;
}

/// 当前绑定的物理网卡（[`guard`] 取网卡名做日志，Go `updater.Get()`）。
///
/// 仅 Windows：唯一调用方是 `inbound.rs` 里 `#[cfg(target_os = "windows")]` 的守卫段，
/// 不加门控会在 Linux/macOS 触发 `dead_code`（`#![deny(warnings)]` ⇒ CI 硬错）。
#[cfg(target_os = "windows")]
pub(crate) fn outbound_iface() -> Option<(u32, String)> {
    OUTBOUND_IFACE.read().clone()
}

/// 注册出站绑定 controller（幂等）。对应 Go `internet.RegisterDialerController`
/// （handler.go:145 同款忽略返回值——当前实现恒 `Ok`）。
pub(crate) fn ensure_outbound_controller_registered() {
    if !OUTBOUND_CONTROLLER_REGISTERED.swap(true, Ordering::Relaxed) {
        let _ =
            xray_transport::system_dialer::register_dialer_controller(outbound_iface_controller());
    }
}

/// 绑定决策（纯函数，测试面）：状态在位且目标非 loopback → 绑定该索引。
/// loopback 跳过 = Go handler.go:145-147（`addrPort.Addr().IsLoopback()` ||
/// `"localhost:"` 前缀；Rust 拨号前已解析为 IP，localhost 字符串形态不存在）。
fn iface_bind_decision(state: Option<u32>, dest: &SocketAddr) -> Option<u32> {
    if dest.ip().is_loopback() {
        return None;
    }
    state
}

/// 出站绑定 controller：读 [`OUTBOUND_IFACE`]，跳过 loopback，把 socket
/// 绑到物理网卡（freedom 出站不再绕回 TUN 自身）。Go 关闭后仍绑最后一次
/// 选中的 iface，此处清零后 no-op——语义差异（更干净）记录于报告。
fn outbound_iface_controller() -> xray_transport::system_dialer::DialerController {
    std::sync::Arc::new(move |socket, dest| {
        let state = OUTBOUND_IFACE.read().as_ref().map(|(index, _)| *index);
        match iface_bind_decision(state, dest) {
            None => Ok(()),
            Some(index) => {
                xray_transport::sockopt::bind_socket_to_interface(socket, index, dest.is_ipv4())
            },
        }
    })
}

/// 物理出口接口解析（Go `findOutboundInterface`，tun_windows.go:578 /
/// tun_linux.go:511）。`"auto"` 走 [`select_outbound_interface`]（排除回环/
/// 未 Up/TUN 自身/索引 0）；其余值 = 固定网卡名按名查找，命中 TUN 自身拒绝
/// （Go Linux 语义，tun_linux.go:519-521；Go Windows 缺该校验，Rust 从严）。
/// 返回 (名字, 索引)。
pub fn resolve_outbound_interface(
    interfaces: &[Interface],
    tun_index: u32,
    mode: &str,
) -> Result<(String, u32)> {
    if mode == "auto" {
        return select_outbound_interface(interfaces, tun_index)
            .map(|i| (i.name.clone(), i.index))
            .ok_or_else(|| TunError::DeviceNotFound("no usable outbound interface found".into()));
    }
    let iface = interfaces.iter().find(|i| i.name == mode).ok_or_else(|| {
        TunError::DeviceNotFound(format!("outbound interface {mode:?} not found"))
    })?;
    if iface.index == tun_index {
        return Err(TunError::InvalidConfig(
            "outbound interface cannot be the TUN interface".into(),
        ));
    }
    Ok((iface.name.clone(), iface.index))
}

/// A4：按平台生成 DNS 计划（见 `dns_wanted` 的平台分派）。
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
        // Go macOS 忽略 dns 字段；本仓平台层整体未接线 ⇒ 同 [`UNWIRED_PLATFORM`] 拒。
        Platform::Other => Err(TunError::InvalidConfig(UNWIRED_PLATFORM.into())),
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

/// DNS 接管计划的防环路验证门（Go `ConfigureSystemDNS` 内 verifyDNSRouting 调用点，
/// tun_linux.go:131 / tun_freebsd.go:360；本函数为判定分派，验证语义在
/// [`crate::dns_verify`]）。
///
/// - `LinuxTakeover`（指向 = TUN 内 gateway 后继）：全量验证；探针未注册（core 接线未落）=
///   无法证明安全 → fail-closed 拒启，不静默放行（Go 对 feature 缺失同款拒绝精神）。
/// - `WindowsAdapterServers`：指向真实上游、无「接管进 TUN」语义（Go build tag 不含
///   windows，本就无此验证；环路防护在 dial 点 `dns_skip`）→ 显式记日志跳过。
fn verify_dns_plan(
    inbound_tag: &str,
    plan: &DnsPlan,
    probe: Option<&dyn DnsRoutingProbe>,
) -> Result<()> {
    match &plan.target {
        DnsTarget::LinuxTakeover { source, dns } => {
            let Some(probe) = probe else {
                return Err(TunError::InvalidConfig(format!(
                    "cannot verify DNS routing for {dns}:53: no DNS routing probe registered \
                     (core wiring pending); refusing system DNS takeover to avoid a resolution loop"
                )));
            };
            verify_dns_routing(probe, inbound_tag, &source.to_string(), &dns.to_string())
                .map_err(|e| TunError::InvalidConfig(format!("no DNS path at {dns}:53: {e}")))
        },
        DnsTarget::WindowsAdapterServers { servers } => {
            crate::TUN_LOG.info(format!(
                "tun system dns: adapter servers set; loop verification not applicable on \
                 this platform (no takeover-into-TUN semantics; loop prevention via dial-point \
                 dns skip) servers={servers:?}"
            ));
            Ok(())
        },
    }
}

/// 启动侧接线：按配置门控 → 枚举真实接口 → 生成计划 → 防环路验证 → **真实执行**。
///
/// 默认关闭：直接 `Ok(None)`，**不枚举接口、不生成任何计划、不执行任何命令**。
/// 验证/执行失败（DNS 环路风险、任一命令 spawn 失败/非零退出，或平台无执行器）→
/// 错误上抛 → 调用方关设备拒启动（对齐 Go handler.go:196-205 "宁可无 TUN"）。
pub(crate) fn prepare(
    options: &StackOptions,
    inbound_tag: &str,
) -> Result<Option<AppliedSystemChanges>> {
    let Some(applied) =
        plan_changes(Platform::current(), &xray_common::net::interface::interfaces()?, options)?
    else {
        return Ok(None);
    };
    // 防环路验证先于任何系统变更落盘（Go ConfigureSystemDNS：verify → resolvectl）。
    if let Some(plan) = &applied.dns {
        let probe = crate::dns_verify::dns_probe();
        verify_dns_plan(inbound_tag, plan, probe.as_deref())?;
    }
    let (routes, dns) = default_executors();
    apply_changes_exec(&applied, routes.as_deref(), dns.as_deref())?;
    register_dns_skip(&applied);
    Ok(Some(applied))
}

/// Go startOver（tun_windows.go:141-152）的缩范围版：尝试 2 次、间隔 1s。
#[cfg(target_os = "windows")]
const ADAPTER_PROPS_ATTEMPTS: u32 = 2;
#[cfg(target_os = "windows")]
const ADAPTER_PROPS_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// Windows 适配器属性残余项的命令渲染（cv3w 纯函数面，测试断言命令行文本）。
///
/// Go `ipif.RouterDiscoveryBehavior = RouterDiscoveryDisabled` + `DadTransmits = 0`
/// （tun_windows.go:180-181），按族各下发一次；IP/`NLMTU`/`UseAutomaticMetric=false +
/// Metric=0` 已由 tun-rs builder（`ipv4`/`ipv6`/`mtu`/`metric`，
/// `CreateUnicastIpAddressEntry` / `SetIpInterfaceEntry` API 面）覆盖，无需 netsh 重复。
///
/// `ipv6` = 配置里真有 v6（[`ipv6_configured`]）：仅在此时下发 v6 命令——IPv6 被系统
/// 关掉的机器上 `netsh interface ipv6` 必败，无条件下发只是白发告警。
///
/// 结构化 args 直接传进程（无 shell 解析），接口名含空格也安全，不加引号
/// （与 [`executor`] 的 netsh 渲染约定一致）。
#[cfg(target_os = "windows")]
pub(crate) fn adapter_props_cmds(interface: &str, ipv6: bool) -> Vec<Cmd> {
    // netsh `set interface` 的接口是**位置参数**（`set interface [interface=]<string>`），
    // 没有 `name=` 参数——用 name= 会报 "name is not a valid argument"。
    let mut cmds = vec![executor::Cmd::new(
        "netsh",
        vec![
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "interface".into(),
            format!("interface={interface}"),
            "routerdiscovery=disabled".into(),
        ],
    )];
    if ipv6 {
        // 票 1qmer B-8：v6 侧同款关闭路由发现（否则 TUN 上跑 RA 会装出默认路由），
        // 并关掉 DAD（重复地址检测窗口内地址处于 tentative，路由不可用）。
        cmds.push(executor::Cmd::new(
            "netsh",
            vec![
                "interface".into(),
                "ipv6".into(),
                "set".into(),
                "interface".into(),
                format!("interface={interface}"),
                "routerdiscovery=disabled".into(),
                "dadtransmits=0".into(),
            ],
        ));
    }
    cmds
}

/// 重试循环（纯逻辑，[`std::thread::sleep`] 由参数注入以便测试）：至多
/// `attempts` 次调用 `try_once`，相邻尝试之间 sleep `backoff`；任一次成功即真。
/// 最后一次失败后不再 sleep。
///
/// 仅 Windows 适配器属性装配与测试使用；其它平台无条件本项会触发 dead_code。
#[cfg(any(target_os = "windows", test))]
pub(crate) fn retry_with_backoff(
    attempts: u32,
    backoff: std::time::Duration,
    mut try_once: impl FnMut() -> bool,
    mut sleep: impl FnMut(std::time::Duration),
) -> bool {
    for attempt in 0..attempts {
        if try_once() {
            return true;
        }
        if attempt + 1 < attempts {
            sleep(backoff);
        }
    }
    false
}

/// 启动侧接线：设 TUN 适配器属性（`adapter_props_cmds`）。失败不致命——
/// 适配器刚建时 IP 接口条目可能暂不可枚举，重试（`ADAPTER_PROPS_ATTEMPTS`）
/// 仍失败仅记 error 继续启动（完整 startOver 15×1s 致命重试留待后续票）。
#[cfg(target_os = "windows")]
pub(crate) fn apply_adapter_props(options: &StackOptions) {
    let cmds = adapter_props_cmds(&options.name, ipv6_configured(options));
    let ok = retry_with_backoff(
        ADAPTER_PROPS_ATTEMPTS,
        ADAPTER_PROPS_BACKOFF,
        || cmds.iter().all(|cmd| cmd.run().is_ok()),
        std::thread::sleep,
    );
    if !ok {
        crate::TUN_LOG.error(format!(
            "tun adapter props (routerdiscovery) failed after retries; continuing (non-fatal) \
             interface={}",
            options.name
        ));
    }
}

// ===== 票 1qmer B-8：Windows IPv6 双栈（地址 / 路由 / DNS / 清理）=====

/// 配置是否涉及 IPv6：`gateway` / `autoSystemRoutingTable` 的 v6 CIDR，或 `dns` 的 v6 地址。
///
/// 两个消费点：①能力门（配了 IPv6 而系统禁用它 ⇒ 拒启）；②v6 适配器属性只在真配了
/// v6 时下发。路由与 DNS 的 v6 命令面本身由 [`plan_routes`]/[`plan_dns`] 按内容自动覆盖
/// （v6 CIDR → `netsh interface ipv6`，v6 服务器 → v6 DNS 命令）。
#[cfg(any(target_os = "windows", test))]
fn ipv6_configured(options: &StackOptions) -> bool {
    options
        .gateway
        .iter()
        .chain(options.auto_system_routing_table.iter())
        .any(|cidr| matches!(parse_ip_cidr(cidr), Some((IpAddr::V6(_), _))))
        || options.dns.iter().any(|s| matches!(s.parse::<IpAddr>(), Ok(IpAddr::V6(_))))
}

/// 能力门失败文案（单测断言之；点名注册表位置与两条出路，用户才知道怎么救）。
#[cfg(any(target_os = "windows", test))]
const IPV6_DISABLED: &str = concat!(
    "IPv6 is configured (gateway/autoSystemRoutingTable/dns) but this system has IPv6 disabled ",
    "for non-tunnel interfaces (HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\",
    "DisabledComponents has bit 0x10): remove the IPv6 entries or re-enable IPv6 ",
    "(Windows applies that at boot)",
);

/// IPv6 能力门（纯函数，`ipv6_off` 由调用方探测，便于离线单测）。
///
/// Go 对 v6 失败只记日志继续（tun_windows.go:156-165）；**本仓按票 1qmer B-8 判 fail-loud**：
/// 配了双栈却只起来单栈是「沉默降级」，比拒启更难排查。
#[cfg(any(target_os = "windows", test))]
fn ipv6_gate(configured: bool, ipv6_off: bool) -> Result<()> {
    if !configured || !ipv6_off {
        return Ok(());
    }
    Err(TunError::InvalidConfig(IPV6_DISABLED.into()))
}

/// 启动侧能力门（Windows）：配置涉及 IPv6 而系统禁用 IPv6 ⇒ `Err`。
///
/// 必须在建适配器之前调用——否则 tun-rs 的 `CreateUnicastIpAddressEntry(AF_INET6)` 会先
/// 以含糊的 OS 错误失败，用户看不出根因是系统级 IPv6 被关掉。
#[cfg(target_os = "windows")]
pub(crate) fn ensure_ipv6_supported(options: &StackOptions) -> Result<()> {
    ipv6_gate(ipv6_configured(options), ipv6_off())
}

/// 读 `DisabledComponents`（`& 0x10` = 关掉非隧道接口的 IPv6，TUN 也在其中）。
/// Go `ipv6Off()`（tun_windows.go:105-111）。
///
/// 读不到 / 类型不对 ⇒ 视为「未禁用」：真禁用的话后续 v6 命令会以真实错误浮现（不吞）；
/// 读失败本身不足以断言禁用（Go 同款 fail-open）。
#[cfg(target_os = "windows")]
fn ipv6_off() -> bool {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_DWORD, RegCloseKey, RegOpenKeyExW,
            RegQueryValueExW,
        },
    };

    let subkey: Vec<u16> =
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\0".encode_utf16().collect();
    let value_name: Vec<u16> = "DisabledComponents\0".encode_utf16().collect();
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: subkey 以 NUL 结尾且存活到调用结束；成功时注册表 API 写入 key。
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_QUERY_VALUE, &mut key) }
        != ERROR_SUCCESS
    {
        return false;
    }
    let mut data: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    let mut ty: u32 = 0;
    // SAFETY: key 为上一步成功打开的句柄；data/size/ty 指向本栈帧有效内存，
    // size 声明 data 的容量 4 字节（REG_DWORD）。
    let code = unsafe {
        RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut ty,
            &mut data as *mut u32 as *mut u8,
            &mut size,
        )
    };
    // SAFETY: key 由 RegOpenKeyExW 成功返回，只关一次。
    unsafe { RegCloseKey(key) };
    code == ERROR_SUCCESS && ty == REG_DWORD && data & 0x10 != 0
}

/// 关闭侧地址清理命令（Go Close `FlushIPAddresses(AF_INET/AF_INET6)`，tun_windows.go:379-384）。
///
/// wintun 适配器在进程退出后仍然存在（下次启动按名复用）⇒ 地址不清就会跨配置叠加。
/// Go 按 LUID 整族清；CLI 面按地址逐条删。
///
/// ⚠️ 两族的接口参数名**不同**（netsh 实测）：v4 收 `name=<iface>`，v6 收
/// `interface=<iface>`（v6 写 `name=` 报「不是这个指令的有效参数」，v4 写 `interface=` 同理）。
#[cfg(any(target_os = "windows", test))]
pub(crate) fn flush_address_cmds(interface: &str, addrs: &[IpAddr]) -> Vec<Cmd> {
    addrs
        .iter()
        .map(|addr| {
            let (family, iface_arg) = if addr.is_ipv4() {
                ("ipv4", format!("name={interface}"))
            } else {
                ("ipv6", format!("interface={interface}"))
            };
            executor::Cmd::new(
                "netsh",
                vec![
                    "interface".into(),
                    family.into(),
                    "delete".into(),
                    "address".into(),
                    iface_arg,
                    format!("address={addr}"),
                ],
            )
        })
        .collect()
}

/// 把本次接管的 DNS 服务器登记进进程级 skip 集合（Go `internet.SkipDNSServers`，
/// tun_windows.go:222）：接管后这些服务器经系统路由指向 TUN，Xray 自身对它们的查询
/// 会绕回 TUN 内，拨号点据此拒拨（`xray_transport::dns_skip::is_skipped_dns_query`）。
///
/// 无 DNS 计划（未接管 DNS）→ 零调用，进程级集合保持原样（Go `if len(dns) > 0`）。
/// 整体替换语义，重复启动幂等（Go 每次 `SkipDNSServers` 覆盖上一轮）。
fn register_dns_skip(applied: &AppliedSystemChanges) {
    let Some(plan) = &applied.dns else { return };
    match &plan.target {
        // Windows：TUN 适配器 DNS 列表（= 配置 `dns`）。
        DnsTarget::WindowsAdapterServers { servers } => skip_dns_servers(servers),
        // Linux：接管指向的地址（gateway 后继，属 TUN 内部）。
        DnsTarget::LinuxTakeover { dns, .. } => skip_dns_servers(&[*dns]),
    }
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

/// 启动侧**真实执行**：路由先于 DNS。路由阶段失败时其自身已按条回滚
/// （[`RouteExecutor::apply_exec`]）；DNS 阶段失败则撤销**已下发的全部路由**——
/// 否则设备关闭后这些网段永久指向已关闭的 TUN（黑洞）。计划存在而执行器缺失
/// （平台未支持）→ 显式报错，绝不静默跳过。
///
/// # Errors
/// 任一命令 spawn 失败或非零退出（[`Cmd::run`]）；或对应平台无执行器。
/// 回滚动作自身的失败与原错误合并上报（不静默）。
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
        if let Err(e) = dx.apply_exec(plan) {
            return Err(rollback_routes_after_failure(&applied.routes, routes, e));
        }
    }
    Ok(())
}

/// DNS 接管失败后撤销已下发的路由，失败与原错误合并（不静默）。
fn rollback_routes_after_failure(
    routes_plan: &Option<RoutePlan>,
    routes: Option<&dyn RouteExecutor>,
    cause: std::io::Error,
) -> std::io::Error {
    let mut messages = vec![format!("dns apply failed after routes were installed: {cause}")];
    if let (Some(plan), Some(rx)) = (routes_plan, routes) {
        if let Err(e) = rx.rollback_exec(plan) {
            messages.push(format!("route rollback failed: {e}"));
        }
    }
    std::io::Error::other(messages.join("; "))
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
/// **两阶段都跑**：DNS 回滚失败不得连带跳过路由回滚（旧实现首错即返回，残留路由
/// 指向已关闭设备 = 黑洞）。错误逐条收集后合并上报。
///
/// # Errors
/// 任一命令 spawn 失败或非零退出；或对应平台无执行器。多错合并为一条消息。
pub fn revert_changes_exec(
    applied: &AppliedSystemChanges,
    routes: Option<&dyn RouteExecutor>,
    dns: Option<&dyn DnsExecutor>,
) -> std::io::Result<()> {
    let mut errors = Vec::new();
    if let Some(plan) = &applied.dns {
        match dns {
            Some(dx) => {
                if let Err(e) = dx.rollback_exec(plan) {
                    errors.push(format!("dns rollback: {e}"));
                }
            },
            None => errors.push(format!("no dns executor for platform {:?}", plan.platform)),
        }
    }
    if let Some(plan) = &applied.routes {
        match routes {
            Some(rx) => {
                if let Err(e) = rx.rollback_exec(plan) {
                    errors.push(format!("route rollback: {e}"));
                }
            },
            None => errors.push(format!("no route executor for platform {:?}", plan.platform)),
        }
    }
    if errors.is_empty() {
        return Ok(());
    }
    Err(std::io::Error::other(errors.join("; ")))
}

/// 关闭侧接线（[`prepare`] 的逆操作）。回滚失败显式 `TUN_LOG.error` 上报
/// （系统状态可能残留），但不阻塞设备关闭——对齐 Go Close 对 unset 错误的
/// 记日志不中止语义（tun_linux.go:353-367）。
///
/// 只管路由与 DNS；**适配器地址**由设备下线路径清（`flush_adapter_addresses`）——
/// 地址归设备、不归计划，且没配路由/DNS 时本函数根本不会被调用。
pub(crate) fn revert(applied: &AppliedSystemChanges) {
    let (routes, dns) = default_executors();
    if let Err(e) = revert_changes_exec(applied, routes.as_deref(), dns.as_deref()) {
        crate::TUN_LOG.error(format!(
            "tun system route/dns revert FAILED; system state may remain dirty error={e}"
        ));
    }
    // Go Close 无条件清除 skip 集合（tun_windows.go:360）：DNS 已不再指向 TUN，
    // 上一步 revert 失败也照样清（残留 skip 会让 Xray 的查询永久拒拨该服务器）。
    skip_dns_servers(&[]);
}

/// 删除本进程装到 TUN 适配器上的地址（Windows）。
///
/// 装的地址 = 设备 IPv4（`device_ipv4`：gateway 首个 v4，缺省 `10.0.0.1/24`）
/// ∪ gateway 全部 v6（[`crate::config::StackOptions::ipv6_gateways`]）——与
/// [`crate::device::TunDevice::create`] 下发的完全一致。
///
/// 调用点必须在设备关闭**之前**（适配器还活着才能删它的地址），且与「配没配路由/DNS」
/// 无关——只要适配器是本进程建的，地址就得清（Go Close 无条件 `FlushIPAddresses`）。
///
/// 失败只记 warn：Go 丢弃 `FlushIPAddresses` 返回值（地址残留不致死，
/// 下次 `CreateUnicastIpAddressEntry` 对已存在地址幂等），这里同样不阻塞关闭，
/// 但**不静默**。
#[cfg(target_os = "windows")]
pub(crate) fn flush_adapter_addresses(options: &StackOptions) {
    let (v4, _) = options.device_ipv4();
    let mut addrs = vec![IpAddr::V4(v4)];
    addrs.extend(options.ipv6_gateways().into_iter().map(|(a, _)| IpAddr::V6(a)));
    for cmd in flush_address_cmds(&options.name, &addrs) {
        if let Err(e) = cmd.run() {
            crate::TUN_LOG.warn(format!("tun adapter address cleanup failed: {cmd}: {e}"));
        }
    }
}

/// `dnsOutsideTUN` 的覆盖集合：gateway 全部 CIDR ∪ autoSystemRoutingTable 目的地
/// （Go `tun_windows.go:326-330` 的 `covered` = `addresses` + `routesData` 目的地）。
#[cfg(any(target_os = "windows", test))]
pub(crate) fn dns_covered_prefixes(
    options: &StackOptions,
    applied: Option<&AppliedSystemChanges>,
) -> Vec<(IpAddr, u8)> {
    let mut covered: Vec<(IpAddr, u8)> =
        options.gateway.iter().filter_map(|cidr| parse_ip_cidr(cidr)).collect();
    if let Some(routes) = applied.and_then(|a| a.routes.as_ref()) {
        covered.extend(routes.add.iter().map(|e| (e.destination, e.prefix)));
    }
    covered
}

/// 落在覆盖集合外的 DNS 服务器逐条告警：查询到不了 TUN，会被 WFP 阻断
/// （Go `tun_windows.go:326-330` 的 `dnsOutsideTUN` + `LogWarning`）。
///
/// 生产调用点 = `TunInboundHandler::start`（WFP 装好之后）；本节公开亦供真机自检
/// （`examples/tun_win_live.rs`）。
#[cfg(target_os = "windows")]
pub fn warn_dns_outside_tun(options: &StackOptions, applied: Option<&AppliedSystemChanges>) {
    let mut servers = Vec::with_capacity(options.dns.len());
    for entry in &options.dns {
        match entry.parse::<IpAddr>() {
            Ok(addr) => servers.push(addr),
            // 解析不了就无法判断覆盖关系——不静默丢弃。
            Err(e) => crate::TUN_LOG
                .warn(format!("[tun] dns entry {entry:?} is not an IP address, skipped: {e}")),
        }
    }
    let covered = dns_covered_prefixes(options, applied);
    for server in crate::wfp::spec::dns_outside_tun(&servers, &covered) {
        crate::TUN_LOG.warn(format!(
            "[tun] DNS server {server} is in neither gateway nor autoSystemRoutingTable, so \
             queries to it cannot go through the TUN and are blocked"
        ));
    }
}

/// 丢掉 Windows 已缓存的 DNS 应答（Go `flushDNSCache`，tun_windows_wfp.go:695-702）。
///
/// 返回 `Ok` = 系统已清缓存。失败**不致命**：Go 调用点只记日志（tun_windows.go:331-333
/// `LogInfoInner`、:404 直接丢弃），启动/停机都不因此中止。
#[cfg(target_os = "windows")]
pub fn flush_dns_cache() -> std::result::Result<(), String> {
    // SAFETY: 无参数、无返回值结构；`DnsFlushResolverCache` 是 dnsapi 的稳定导出
    // （Go 同样调它——`windows.NewLazySystemDLL("dnsapi.dll")`）。
    flush_result(unsafe { DnsFlushResolverCache() })
}

/// `DnsFlushResolverCache` 的返回值 → 结果（`FALSE` = 失败，Go 同判据）。
#[cfg(any(target_os = "windows", test))]
fn flush_result(ok: i32) -> std::result::Result<(), String> {
    if ok == 0 { Err("DnsFlushResolverCache returned FALSE".to_string()) } else { Ok(()) }
}

#[cfg(target_os = "windows")]
#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

#[cfg(test)]
mod tests {
    use xray_common::net::interface::{InterfaceAddr, InterfaceAddrV4};

    use super::*;
    use crate::sysroute::executor::{LinuxDns, LinuxRoutes, WindowsDns, WindowsRoutes};

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
        assert!(err.to_string().contains("not wired on this platform"), "{err}");
    }

    // ===== 平台门闸（bd bv98n）：macOS/FreeBSD 未接线 ⇒ 即使是默认配置也拒绝 =====

    /// 未接线平台**不得**因「配置全关」而静默放行：否则 TUN 会在 macOS/FreeBSD 上
    /// 起来却一条路由/DNS 都不配，流量永不经代理，而启动日志无任何异常。
    #[test]
    fn plan_changes_rejects_unwired_platform_even_when_disabled() {
        let disabled = StackOptions::default();
        let err = plan_changes(Platform::Other, &tun_and_eth(), &disabled).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not wired on this platform"), "{msg}");
        // 消息必须点名支持面，否则用户无从判断该怎么办。
        assert!(msg.contains("Linux/Windows"), "{msg}");

        // 配了路由 / DNS 接管同样拒（不是「没配才拒」）。
        let routed = opts(&["0.0.0.0/0"], &[], false);
        assert!(plan_changes(Platform::Other, &tun_and_eth(), &routed).is_err());
        let dns_takeover = opts(&[], &[], true);
        assert!(plan_changes(Platform::Other, &tun_and_eth(), &dns_takeover).is_err());
        // DNS 计划入口本身也拒（不留「单独调用时静默 Ok(None)」的口子）。
        assert!(plan_dns(Platform::Other, &dns_takeover).is_err());
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
                "netsh interface ipv6 delete route 2001:db8::/32 interface=xray0",
                "route delete 0.0.0.0 mask 0.0.0.0 if 24",
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

    /// 进程级 skip 集合是全局态：涉集合的测试必须持锁串行
    /// （`xray-transport/src/dns_skip.rs` TEST_LOCK 同款先例）。
    static DNS_SKIP_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// 测试退出即清集合，防串扰同进程其他用例。
    struct SkipClear;
    impl Drop for SkipClear {
        fn drop(&mut self) {
            skip_dns_servers(&[]);
        }
    }

    fn skip_hits(ip: &str) -> bool {
        let addr = std::net::SocketAddr::new(ip.parse().unwrap(), 53);
        xray_transport::dns_skip::is_skipped_dns_server(addr)
    }

    /// Windows 接管计划：TUN 适配器 DNS 列表（= 配置 `dns`）。
    fn windows_dns_applied(servers: &[&str]) -> AppliedSystemChanges {
        AppliedSystemChanges {
            routes: None,
            dns: Some(DnsPlan {
                platform: Platform::Windows,
                interface: "xray0".into(),
                target: DnsTarget::WindowsAdapterServers {
                    servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
                },
            }),
        }
    }

    /// 接管登记 → 命中（含 v4-mapped 归一化、端口无关）；清除（Go Close
    /// `SkipDNSServers(nil)`，`revert` 同语义）→ 不命中。
    #[test]
    fn dns_skip_registered_on_takeover_and_cleared_by_revert() {
        let _g = DNS_SKIP_TEST_LOCK.lock();
        let _clear = SkipClear;
        assert!(!skip_hits("1.1.1.1"));

        register_dns_skip(&windows_dns_applied(&["1.1.1.1", "::ffff:203.0.113.53"]));
        assert!(skip_hits("1.1.1.1"));
        assert!(skip_hits("203.0.113.53"), "v4-mapped 声明命中纯 v4 目标");
        assert!(!skip_hits("8.8.8.8"));

        // revert 的清除语义（Go Close tun_windows.go:360）。
        skip_dns_servers(&[]);
        assert!(!skip_hits("1.1.1.1"));
    }

    /// 整体替换语义：重复启动幂等、不叠加（Go 每次 `SkipDNSServers` 覆盖上一轮）。
    #[test]
    fn dns_skip_registration_replaces_and_does_not_accumulate() {
        let _g = DNS_SKIP_TEST_LOCK.lock();
        let _clear = SkipClear;

        register_dns_skip(&windows_dns_applied(&["1.1.1.1"]));
        register_dns_skip(&windows_dns_applied(&["1.1.1.1"]));
        assert!(skip_hits("1.1.1.1"), "两次同配置启动仍命中");

        // 换一组（模拟重启换了 dns 配置）：旧条目不得残留。
        register_dns_skip(&windows_dns_applied(&["8.8.8.8"]));
        assert!(skip_hits("8.8.8.8"));
        assert!(!skip_hits("1.1.1.1"), "上一轮的服务器必须已被替换掉");
    }

    /// 未接管 DNS（无 DNS 计划）→ 零调用：既有集合原样保留（Go `if len(dns) > 0`）。
    #[test]
    fn dns_skip_untouched_without_dns_plan() {
        let _g = DNS_SKIP_TEST_LOCK.lock();
        let _clear = SkipClear;

        skip_dns_servers(&["203.0.113.53".parse().unwrap()]);
        register_dns_skip(&AppliedSystemChanges {
            routes: Some(RoutePlan {
                platform: Platform::Windows,
                interface_index: 7,
                interface: "xray0".into(),
                add: Vec::new(),
                outbound_interface: None,
            }),
            dns: None,
        });
        assert!(skip_hits("203.0.113.53"), "无 DNS 计划时不得清空/改动集合");
        assert!(!skip_hits("1.1.1.1"));
    }

    /// Linux 接管：登记的是接管指向的地址（gateway 后继，属 TUN 内部）。
    #[test]
    fn dns_skip_linux_takeover_registers_gateway_next_hop() {
        let _g = DNS_SKIP_TEST_LOCK.lock();
        let _clear = SkipClear;

        register_dns_skip(&AppliedSystemChanges {
            routes: None,
            dns: Some(DnsPlan {
                platform: Platform::Linux,
                interface: "xray0".into(),
                target: DnsTarget::LinuxTakeover {
                    source: "192.168.100.1".parse().unwrap(),
                    dns: "192.168.100.2".parse().unwrap(),
                },
            }),
        });
        assert!(skip_hits("192.168.100.2"));
        assert!(!skip_hits("192.168.100.1"), "源地址不是解析器指向");
    }

    // ===== cv3w：适配器属性命令渲染 + 重试纯逻辑 =====

    /// 命令构造：netsh routerdiscovery=disabled，结构化 args 无引号（netsh 渲染约定）。
    /// 未配 IPv6 → 只下发 v4 一条（IPv6 被关掉的机器上 v6 命令必败，白打告警）。
    #[cfg(target_os = "windows")]
    #[test]
    fn adapter_props_commands_render_netsh_routerdiscovery() {
        let cmds = adapter_props_cmds("xray0", false);
        assert_eq!(
            render(&cmds),
            vec!["netsh interface ipv4 set interface interface=xray0 routerdiscovery=disabled"]
        );
    }

    /// 票 1qmer B-8：配了 IPv6 → 追加 v6 侧（routerdiscovery + dadtransmits）。
    #[cfg(target_os = "windows")]
    #[test]
    fn adapter_props_commands_add_ipv6_when_configured() {
        let cmds = adapter_props_cmds("xray0", true);
        assert_eq!(
            render(&cmds),
            vec![
                "netsh interface ipv4 set interface interface=xray0 routerdiscovery=disabled",
                "netsh interface ipv6 set interface interface=xray0 routerdiscovery=disabled \
                 dadtransmits=0",
            ]
        );
    }

    // ===== 票 1qmer B-8：Windows IPv6 双栈 =====

    /// `ipv6_configured` 覆盖面：gateway / autoSystemRoutingTable / dns 三处任一含 v6 即真。
    #[test]
    fn ipv6_configured_covers_gateway_routes_and_dns() {
        let parse = |json: &[u8]| StackOptions::parse_json(json).unwrap();
        assert!(!ipv6_configured(&parse(b"{}")), "全空配置不含 v6");
        assert!(!ipv6_configured(&parse(
            br#"{"gateway":["10.0.0.1/24"],"autoSystemRoutingTable":["0.0.0.0/0"],
                "dns":["1.1.1.1"]}"#
        )));
        assert!(ipv6_configured(&parse(br#"{"gateway":["10.0.0.1/24","fd00::1/64"]}"#)));
        assert!(ipv6_configured(&parse(br#"{"autoSystemRoutingTable":["::/0"]}"#)));
        assert!(ipv6_configured(&parse(br#"{"dns":["1.1.1.1","2606:4700:4700::1111"]}"#)));
    }

    /// 能力门：配了 v6 + 系统禁用 ⇒ Err（fail-loud，不静默降级成单栈）；
    /// 未配 v6 或系统未禁用 ⇒ Ok。
    #[test]
    fn ipv6_gate_rejects_configured_ipv6_when_system_disabled() {
        let err = ipv6_gate(true, true).expect_err("配了 v6 而系统禁用必须拒启");
        let msg = format!("{err}");
        assert!(msg.contains("DisabledComponents"), "必须点名注册表位置: {msg}");
        assert!(
            msg.contains("Tcpip6\\Parameters\\DisabledComponents"),
            "注册表路径必须完整（反斜杠不能丢）: {msg}"
        );
        assert!(msg.contains("0x10"), "必须点名禁用位: {msg}");
        assert!(ipv6_gate(false, true).is_ok(), "没配 v6 就不关本仓的事");
        assert!(ipv6_gate(true, false).is_ok(), "系统未禁用照常放行");
        assert!(ipv6_gate(false, false).is_ok());
    }

    /// 关闭侧地址清理：两族命令面（Go Close `FlushIPAddresses` 的 CLI 等价）。
    /// 接口参数名两族不同（v4 `name=` / v6 `interface=`）——已由 netsh 实测确认。
    #[test]
    fn flush_address_cmds_cover_both_families() {
        let cmds =
            flush_address_cmds("xray0", &["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        assert_eq!(
            render(&cmds),
            vec![
                "netsh interface ipv4 delete address name=xray0 address=10.0.0.1",
                "netsh interface ipv6 delete address interface=xray0 address=fd00::1",
            ]
        );
    }

    #[test]
    fn retry_with_backoff_stops_on_first_success_without_sleep() {
        let mut calls = 0u32;
        let mut sleeps = Vec::new();
        let ok = retry_with_backoff(
            2,
            std::time::Duration::from_secs(1),
            || {
                calls += 1;
                true
            },
            |d| sleeps.push(d),
        );
        assert!(ok);
        assert_eq!(calls, 1);
        assert!(sleeps.is_empty(), "首次成功不得 sleep");
    }

    #[test]
    fn retry_with_backoff_sleeps_between_attempts_then_succeeds() {
        let mut calls = 0u32;
        let mut sleeps = Vec::new();
        let ok = retry_with_backoff(
            3,
            std::time::Duration::from_secs(1),
            || {
                calls += 1;
                calls >= 2
            },
            |d| sleeps.push(d),
        );
        assert!(ok);
        assert_eq!(calls, 2);
        assert_eq!(sleeps, vec![std::time::Duration::from_secs(1)]);
    }

    #[test]
    fn retry_with_backoff_exhausts_attempts_without_final_sleep() {
        let mut calls = 0u32;
        let mut sleeps = Vec::new();
        let ok = retry_with_backoff(
            2,
            std::time::Duration::from_secs(1),
            || {
                calls += 1;
                false
            },
            |d| sleeps.push(d),
        );
        assert!(!ok);
        assert_eq!(calls, 2, "至多 attempts 次尝试");
        assert_eq!(sleeps, vec![std::time::Duration::from_secs(1)], "末次失败后不再 sleep");
    }

    // ===== AI4：出站接口绑定（Go handler.go:130-164）=====

    /// 验收⑤①（选择层）：auto 模式排除 TUN 自身，选出 Up 的物理网卡 index。
    #[test]
    fn resolve_auto_selects_physical_nic_excluding_tun() {
        let (name, index) =
            resolve_outbound_interface(&tun_and_eth(), 24, "auto").expect("resolve");
        assert_eq!((name.as_str(), index), ("eth0", 5));
    }

    /// auto 模式：除 TUN 外无候选（全回环/未 Up）→ 显式报错（宁可无 TUN）。
    #[test]
    fn resolve_auto_without_candidate_errors() {
        let only_tun = vec![iface(
            "xray0",
            24,
            UP | InterfaceFlags::POINT_TO_POINT,
            vec![v4_addr([10, 0, 0, 1], 24)],
        )];
        assert!(matches!(
            resolve_outbound_interface(&only_tun, 24, "auto"),
            Err(TunError::DeviceNotFound(_))
        ));
    }

    /// 固定名：按名解析出 index；命中 TUN 自身 / 名字不存在 → 显式报错
    /// （Go Linux tun_linux.go:519-521 语义；Go Windows 缺 TUN 自查，Rust 从严）。
    #[test]
    fn resolve_fixed_name_resolves_and_rejects_tun_self() {
        assert_eq!(
            resolve_outbound_interface(&tun_and_eth(), 24, "eth0").expect("resolve"),
            ("eth0".to_string(), 5)
        );
        assert!(matches!(
            resolve_outbound_interface(&tun_and_eth(), 24, "xray0"),
            Err(TunError::InvalidConfig(_))
        ));
        assert!(matches!(
            resolve_outbound_interface(&tun_and_eth(), 24, "nosuch"),
            Err(TunError::DeviceNotFound(_))
        ));
    }

    /// 验收⑤②：loopback 目标不绑（Go handler.go:145-147）；外部地址返回索引。
    #[test]
    fn bind_decision_skips_loopback_and_passes_external() {
        let v4: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let v6: SocketAddr = "[::1]:53".parse().unwrap();
        let ext: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert_eq!(iface_bind_decision(Some(5), &v4), None);
        assert_eq!(iface_bind_decision(Some(5), &v6), None);
        assert_eq!(iface_bind_decision(Some(5), &ext), Some(5));
    }

    /// 验收⑤④（前半）：状态清零（TUN 关闭）→ 决策恒 None（controller no-op，
    /// 拨号回归系统路由表）。
    #[test]
    fn bind_decision_cleared_state_is_noop() {
        let ext: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert_eq!(iface_bind_decision(None, &ext), None);
    }

    /// 验收⑤④（后半）：controller 注册幂等——重复 ensure 不再追加。
    #[test]
    fn outbound_controller_registration_is_idempotent() {
        ensure_outbound_controller_registered();
        let len = xray_transport::system_dialer::registered_controllers().len();
        ensure_outbound_controller_registered();
        assert_eq!(xray_transport::system_dialer::registered_controllers().len(), len);
    }

    // ===== bd uwt1：DNS 接管防环路验证门（verify_dns_plan）=====

    /// 恒报环路风险的假探针（验证门分派测试用；判定语义本体在 dns_verify 测试面）。
    struct RefusingProbe;

    impl crate::dns_verify::DnsRoutingProbe for RefusingProbe {
        fn system_resolver_use(&self) -> Option<crate::dns_verify::SystemResolverUse> {
            Some(crate::dns_verify::SystemResolverUse::DnsFeature)
        }

        fn route_for_dns(&self, _: &str, _: IpAddr, _: IpAddr) -> crate::dns_verify::RouteProbe {
            crate::dns_verify::RouteProbe::NoRoute
        }

        fn outbound_dns(&self, _: &str) -> crate::dns_verify::DnsCapability {
            crate::dns_verify::DnsCapability::NotDns
        }
    }

    /// Linux 接管计划标准形：gateway `10.0.0.1/30` → 接管地址 `10.0.0.2`（自身子树）。
    fn linux_takeover_plan() -> DnsPlan {
        DnsPlan {
            platform: Platform::Linux,
            interface: "xray0".into(),
            target: DnsTarget::LinuxTakeover {
                source: "10.0.0.1".parse().unwrap(),
                dns: "10.0.0.2".parse().unwrap(),
            },
        }
    }

    /// 探针未注册（core 接线未落）= 无法证明安全 → fail-closed 拒启，
    /// 错误明确说明接线缺口，不静默放行。
    #[test]
    fn takeover_without_probe_refuses_fail_closed() {
        let err = verify_dns_plan("tun-in", &linux_takeover_plan(), None)
            .expect_err("must refuse without probe");
        let msg = err.to_string();
        assert!(msg.contains("no DNS routing probe registered"), "{msg}");
        assert!(msg.contains("10.0.0.2:53"), "{msg}");
    }

    /// 验证不过（探针判定环路风险）→ 拒启，错误含 Go 包装文案 + 根因。
    #[test]
    fn takeover_with_failing_probe_refuses_wrapped() {
        let err = verify_dns_plan("tun-in", &linux_takeover_plan(), Some(&RefusingProbe))
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("no DNS path at 10.0.0.2:53"), "{msg}");
        assert!(msg.contains("system resolver"), "{msg}");
    }

    /// Windows 适配器 DNS：无接管进 TUN 语义（Go build tag 不含 windows）→
    /// 显式跳过验证（info 日志）不拒启。
    #[test]
    fn windows_adapter_plan_skips_verification() {
        let plan = DnsPlan {
            platform: Platform::Windows,
            interface: "xray0".into(),
            target: DnsTarget::WindowsAdapterServers { servers: vec!["1.1.1.1".parse().unwrap()] },
        };
        verify_dns_plan("tun-in", &plan, None).expect("windows plan skips verification");
    }

    // ===== bd mjbbg：部分应用必须可回滚（跨阶段）=====

    /// 必然失败的命令：程序不存在 ⇒ spawn 即 Err；名字带 tag ⇒ 可从错误消息辨别
    /// 「哪条命令真的跑过」（与 executor 测试面同一手法，绕开平台 shell 差异）。
    fn missing_cmd(tag: &str) -> Cmd {
        Cmd::new(format!("xray-sysrollback-missing-{tag}"), Vec::new())
    }

    /// 路由「成功」、DNS「必败」：路由撤销必须被执行（设备关闭后否则成黑洞）。
    struct OkRoutesBadDns;

    impl RouteExecutor for OkRoutesBadDns {
        fn apply(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            Vec::new()
        }

        fn rollback(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            vec![missing_cmd("route-rollback")]
        }
    }

    impl DnsExecutor for OkRoutesBadDns {
        fn apply(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            vec![missing_cmd("dns-apply")]
        }

        fn rollback(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            Vec::new()
        }
    }

    fn both_plans() -> AppliedSystemChanges {
        AppliedSystemChanges {
            routes: Some(RoutePlan {
                platform: Platform::current(),
                interface: "xray0".into(),
                interface_index: 7,
                add: Vec::new(),
                outbound_interface: None,
            }),
            dns: Some(linux_takeover_plan()),
        }
    }

    #[test]
    fn dns_failure_after_routes_rolls_routes_back() {
        let applied = both_plans();
        let ex = OkRoutesBadDns;
        let err = apply_changes_exec(&applied, Some(&ex), Some(&ex))
            .expect_err("dns apply must fail")
            .to_string();
        assert!(
            err.contains("dns apply failed after routes were installed"),
            "原错误必须上报：{err}"
        );
        assert!(
            err.contains("xray-sysrollback-missing-route-rollback"),
            "DNS 失败后已下发路由必须撤销：{err}"
        );
    }

    /// 两阶段回滚都要跑：DNS 回滚失败不得连带跳过路由回滚。
    struct BothRollbacksBad;

    impl RouteExecutor for BothRollbacksBad {
        fn apply(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            Vec::new()
        }

        fn rollback(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            vec![missing_cmd("route-rollback")]
        }
    }

    impl DnsExecutor for BothRollbacksBad {
        fn apply(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            Vec::new()
        }

        fn rollback(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            vec![missing_cmd("dns-rollback")]
        }
    }

    #[test]
    fn revert_runs_route_rollback_even_when_dns_rollback_fails() {
        let ex = BothRollbacksBad;
        let err = revert_changes_exec(&both_plans(), Some(&ex), Some(&ex))
            .expect_err("both rollbacks fail")
            .to_string();
        assert!(err.contains("dns rollback:"), "{err}");
        assert!(err.contains("route rollback:"), "DNS 首错不得跳过路由回滚：{err}");
        assert!(err.contains("xray-sysrollback-missing-route-rollback"), "{err}");
    }

    /// 覆盖集合 = gateway ∪ autoSystemRoutingTable 目的地（Go `covered`）。
    #[test]
    fn dns_covered_prefixes_union_of_gateway_and_routes() {
        let options = StackOptions {
            gateway: vec!["192.168.77.1/24".to_string(), "fd00::1/64".to_string()],
            ..StackOptions::default()
        };
        let applied = AppliedSystemChanges {
            routes: Some(RoutePlan {
                platform: Platform::Windows,
                interface: options.name.clone(),
                interface_index: 7,
                add: vec![RouteEntry {
                    destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix: 8,
                    metric: 0,
                }],
                outbound_interface: None,
            }),
            dns: None,
        };
        let covered = dns_covered_prefixes(&options, Some(&applied));
        assert_eq!(covered.len(), 3, "{covered:?}");
        assert!(covered.contains(&(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)));
        assert!(covered.contains(&(IpAddr::V4(Ipv4Addr::new(192, 168, 77, 1)), 24)));
        // 没有路由计划时只剩 gateway。
        assert_eq!(dns_covered_prefixes(&options, None).len(), 2);
    }

    /// 覆盖集合外的 DNS 会被 `dns_outside_tun` 挑出来（告警集合就是它）。
    #[test]
    fn dns_outside_covers_gateway_but_not_public_servers() {
        let options = StackOptions {
            gateway: vec!["192.168.77.1/24".to_string()],
            ..StackOptions::default()
        };
        let covered = dns_covered_prefixes(&options, None);
        let servers =
            [IpAddr::V4(Ipv4Addr::new(192, 168, 77, 53)), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        let outside = crate::wfp::spec::dns_outside_tun(&servers, &covered);
        assert_eq!(outside, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
    }

    /// ③ 真调 dnsapi：本机必然可清（清缓存不需管理员），且失败也只是一条 Err。
    #[cfg(target_os = "windows")]
    #[test]
    fn flush_dns_cache_really_runs_without_panicking() {
        match flush_dns_cache() {
            Ok(()) => {},
            Err(e) => assert!(e.contains("DnsFlushResolverCache"), "错误文本须可诊断：{e}"),
        }
    }

    /// `FALSE` 映射成 Err（调用点只记日志，不中断启动/停机）。
    #[test]
    fn flush_result_maps_false_to_err() {
        assert!(flush_result(0).is_err());
        assert!(flush_result(1).is_ok());
    }
}
