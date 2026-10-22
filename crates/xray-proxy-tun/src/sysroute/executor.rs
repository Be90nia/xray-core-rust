//! 执行器层：把 `sysroute` 的变更计划渲染成结构化命令，并提供真实执行。
//!
//! # 渲染与执行分离
//!
//! - **渲染面**（`apply`/`rollback` → `Vec<Cmd>`）：产出结构化命令 [`Cmd`]（program +
//!   args，不经字符串拆分），`Display` 即完整命令行。 测试与 Recording 走这里——**从不执行**。
//! - **执行面**（`apply_exec`/`rollback_exec` → trait 默认方法）：逐条 [`Cmd::run`] 真实
//!   spawn。**全模块唯一执行点**是 [`Cmd::run`]；每条命令 执行前
//!   `tracing::info!`（program+args），失败 `tracing::error!` 并上抛，
//!   不吞错——调用方（`sysroute::prepare`）把错误传给 TUN 启动流程， 接管失败宁可无 TUN（对齐 Go
//!   handler.go:196-205）。
//!
//! 测试**从不**调用执行面；唯一会真实执行的是配置开关显式开启后的实机路径。
//!
//! # 命令面与 Go 的映射（Go 走 API，此处为等价 CLI 形态）
//!
//! - Linux 路由：Go `netlink.RouteAdd{LinkIndex, Dst, Priority: 1}`（tun_linux.go:451-458） → `ip
//!   route add <dst>/<p> metric 1 dev <iface>`。
//! - Windows 路由：Go `LUID.SetRoutesForFamily{Destination, Metric: 0}`（tun_windows.go:126-149） →
//!   v4 `route add <dst> mask <mask> metric 0 if <idx>`；
//!
//!   v6 `netsh interface ipv6 add route <p>/<len> interface=<name> metric=0`。
//! - Linux DNS：Go `resolvectl dns/domain/default-route` + 失败 `revert` （tun_linux.go:105-160）→
//!   逐字同形。
//! - Windows DNS：Go `LUID.SetDNS(family, dns, nil)`（tun_windows.go:157） → `netsh interface
//!   {ipv4,ipv6} set/add dnsservers`；回滚 = `address=none` 清空（Go Close 的 `FlushDNS`
//!   等价命令面）。
//!
//! 结构化 args 直接传进程（无 shell 解析），接口名含空格也安全，故不再加引号。

use std::{fmt, process::Command, sync::Arc};

use parking_lot::Mutex as ParkMutex;

use super::{DnsPlan, DnsTarget, RouteEntry, RoutePlan, v4_mask};

/// 结构化命令（program + args）。`Display` 输出完整命令行（空格连接），
/// 与各平台测试断言的命令行文本一一对应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

impl Cmd {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self { program: program.into(), args }
    }

    /// 真实执行（全模块唯一执行点）。执行前 info 记录完整命令行；spawn 失败
    /// 或非零退出 → error 记录并上抛（不吞）。
    ///
    /// # Errors
    /// spawn 失败（程序不存在/权限不足）或退出码非 0。
    pub fn run(&self) -> std::io::Result<()> {
        tracing::info!(program = %self.program, args = ?self.args, "tun sysroute exec");
        let status = Command::new(&self.program).args(&self.args).status()?;
        if !status.success() {
            tracing::error!(
                program = %self.program, args = ?self.args, %status,
                "tun sysroute command failed"
            );
            return Err(std::io::Error::other(format!(
                "command failed ({status}): {} {}",
                self.program,
                self.args.join(" ")
            )));
        }
        Ok(())
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

/// 路由计划执行器：渲染命令（`apply`/`rollback`）+ 真实执行（`*_exec`）。
pub trait RouteExecutor: Send + Sync {
    /// 渲染新增命令（顺序同 [`RoutePlan::add`]）。不执行。
    fn apply(&self, plan: &RoutePlan) -> Vec<Cmd>;
    /// 渲染回滚命令（与 `apply` 一一对应、反序——对齐 Go `unsetSystemRoutes`）。不执行。
    fn rollback(&self, plan: &RoutePlan) -> Vec<Cmd>;

    /// 顺序真实执行 apply 的全部命令；任一失败即停并上抛。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn apply_exec(&self, plan: &RoutePlan) -> std::io::Result<()> {
        for cmd in self.apply(plan) {
            cmd.run()?;
        }
        Ok(())
    }

    /// 反序真实执行 rollback 的全部命令。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn rollback_exec(&self, plan: &RoutePlan) -> std::io::Result<()> {
        for cmd in self.rollback(plan) {
            cmd.run()?;
        }
        Ok(())
    }
}

/// DNS 计划执行器：渲染命令（`apply`/`rollback`）+ 真实执行（`*_exec`）。
pub trait DnsExecutor: Send + Sync {
    /// 渲染接管命令（Linux 三步序列 / Windows 按族 set+add）。不执行。
    fn apply(&self, plan: &DnsPlan) -> Vec<Cmd>;
    /// 渲染恢复命令（Linux `revert` / Windows 清空 TUN 适配器 DNS）。不执行。
    fn rollback(&self, plan: &DnsPlan) -> Vec<Cmd>;

    /// 顺序真实执行接管的全部命令。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn apply_exec(&self, plan: &DnsPlan) -> std::io::Result<()> {
        for cmd in self.apply(plan) {
            cmd.run()?;
        }
        Ok(())
    }

    /// 顺序真实执行恢复的全部命令。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn rollback_exec(&self, plan: &DnsPlan) -> std::io::Result<()> {
        for cmd in self.rollback(plan) {
            cmd.run()?;
        }
        Ok(())
    }
}

/// Linux 路由执行器（`ip route`）。
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxRoutes;

impl RouteExecutor for LinuxRoutes {
    fn apply(&self, plan: &RoutePlan) -> Vec<Cmd> {
        plan.add.iter().map(|e| linux_route_cmd("add", plan, e)).collect()
    }

    fn rollback(&self, plan: &RoutePlan) -> Vec<Cmd> {
        plan.add.iter().rev().map(|e| linux_route_cmd("del", plan, e)).collect()
    }
}

fn linux_route_cmd(verb: &str, plan: &RoutePlan, e: &RouteEntry) -> Cmd {
    Cmd::new(
        "ip",
        vec![
            "route".into(),
            verb.into(),
            format!("{}/{}", e.destination, e.prefix),
            "metric".into(),
            e.metric.to_string(),
            "dev".into(),
            plan.interface.clone(),
        ],
    )
}

/// Windows 路由执行器（v4 `route.exe` / v6 `netsh interface ipv6`）。
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsRoutes;

impl RouteExecutor for WindowsRoutes {
    fn apply(&self, plan: &RoutePlan) -> Vec<Cmd> {
        plan.add.iter().map(|e| windows_route_cmd("add", plan, e)).collect()
    }

    fn rollback(&self, plan: &RoutePlan) -> Vec<Cmd> {
        plan.add.iter().rev().map(|e| windows_route_cmd("delete", plan, e)).collect()
    }
}

fn windows_route_cmd(verb: &str, plan: &RoutePlan, e: &RouteEntry) -> Cmd {
    match e.destination {
        // route.exe 语法：route <verb> <dst> mask <mask> metric <m> if <idx>。
        std::net::IpAddr::V4(v4) => Cmd::new(
            "route",
            vec![
                verb.into(),
                v4.to_string(),
                "mask".into(),
                v4_mask(e.prefix).to_string(),
                "metric".into(),
                e.metric.to_string(),
                "if".into(),
                plan.interface_index.to_string(),
            ],
        ),
        // route.exe 不支持 v6：netsh route 按接口名挂。
        std::net::IpAddr::V6(_) => Cmd::new(
            "netsh",
            vec![
                "interface".into(),
                "ipv6".into(),
                verb.into(),
                "route".into(),
                format!("{}/{}", e.destination, e.prefix),
                format!("interface={}", plan.interface),
                format!("metric={}", e.metric),
            ],
        ),
    }
}

/// Linux DNS 执行器（`resolvectl`，命令面与 Go tun_linux.go 逐字同形）。
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxDns;

impl DnsExecutor for LinuxDns {
    fn apply(&self, plan: &DnsPlan) -> Vec<Cmd> {
        // 平台不匹配的分支不可达：plan_dns 按平台分派，接线保证执行器与计划同平台。
        let DnsTarget::LinuxTakeover { dns, .. } = &plan.target else { return Vec::new() };
        vec![
            resolvectl("dns", &plan.interface, Some(dns.to_string())),
            resolvectl("domain", &plan.interface, Some("~.".to_string())),
            resolvectl("default-route", &plan.interface, Some("true".to_string())),
        ]
    }

    fn rollback(&self, plan: &DnsPlan) -> Vec<Cmd> {
        if !matches!(plan.target, DnsTarget::LinuxTakeover { .. }) {
            return Vec::new();
        }
        vec![resolvectl("revert", &plan.interface, None)]
    }
}

/// Go `buildResolvectlArgs`（tun_linux.go:69-73）：`resolvectl <action> <iface> [extra]`。
fn resolvectl(action: &str, iface: &str, extra: Option<String>) -> Cmd {
    let mut args = vec![action.to_string(), iface.to_string()];
    if let Some(arg) = extra {
        args.push(arg);
    }
    Cmd::new("resolvectl", args)
}

/// Windows DNS 执行器（`netsh`，作用于 TUN 适配器自身——Go 只动 TUN 的 LUID，
/// 物理网卡状态从不触碰，故回滚即清空，无需外部备份）。
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDns;

impl DnsExecutor for WindowsDns {
    fn apply(&self, plan: &DnsPlan) -> Vec<Cmd> {
        let DnsTarget::WindowsAdapterServers { servers } = &plan.target else {
            return Vec::new();
        };
        let v4: Vec<_> = servers.iter().filter(|s| s.is_ipv4()).collect();
        let v6: Vec<_> = servers.iter().filter(|s| s.is_ipv6()).collect();
        let mut out = self.family_apply(plan, "ipv4", &v4);
        out.extend(self.family_apply(plan, "ipv6", &v6));
        out
    }

    fn rollback(&self, plan: &DnsPlan) -> Vec<Cmd> {
        if !matches!(plan.target, DnsTarget::WindowsAdapterServers { .. }) {
            return Vec::new();
        }
        // 按族清空：Go Close 的 luid.FlushDNS(family) 命令面。
        vec![
            netsh_dnsservers("ipv4", "set", &plan.interface, "address=none"),
            netsh_dnsservers("ipv6", "set", &plan.interface, "address=none"),
        ]
    }
}

impl WindowsDns {
    /// 单族命令：首个 `set`（netsh set 一次只收一个地址），其余 `add index=n`。
    fn family_apply(
        &self,
        plan: &DnsPlan,
        family: &str,
        servers: &[&std::net::IpAddr],
    ) -> Vec<Cmd> {
        if servers.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(servers.len());
        for (n, s) in servers.iter().enumerate() {
            if n == 0 {
                out.push(netsh_dnsservers(family, "set", &plan.interface, &format!("address={s}")));
            } else {
                out.push(netsh_dnsservers_add(family, &plan.interface, s, n + 1));
            }
        }
        out
    }
}

fn netsh_dnsservers(family: &str, verb: &str, iface: &str, address: &str) -> Cmd {
    Cmd::new(
        "netsh",
        vec![
            "interface".into(),
            family.into(),
            verb.into(),
            "dnsservers".into(),
            format!("name={iface}"),
            "source=static".into(),
            address.into(),
            "validate=no".into(),
        ],
    )
}

fn netsh_dnsservers_add(
    family: &str,
    iface: &str,
    address: &std::net::IpAddr,
    index: usize,
) -> Cmd {
    Cmd::new(
        "netsh",
        vec![
            "interface".into(),
            family.into(),
            "add".into(),
            "dnsservers".into(),
            format!("name={iface}"),
            format!("address={address}"),
            format!("index={index}"),
            "validate=no".into(),
        ],
    )
}

/// DryRun/Mock 装饰器：委托内层执行器**渲染**，并把每条命令行追加进共享日志供
/// 断言（绝不执行——测试专用；生产走 `default_executors()` 的真执行路径）。
pub struct Recording<E> {
    inner: E,
    log: Arc<ParkMutex<Vec<String>>>,
}

impl<E> Recording<E> {
    #[must_use]
    pub fn new(inner: E) -> Self {
        Self { inner, log: Arc::default() }
    }

    /// 已记录的全部命令行（apply + rollback 按调用序）。
    #[must_use]
    pub fn recorded(&self) -> Vec<String> {
        self.log.lock().clone()
    }

    fn record(&self, cmds: &[Cmd]) {
        self.log.lock().extend(cmds.iter().map(ToString::to_string));
    }
}

impl<E: RouteExecutor> RouteExecutor for Recording<E> {
    fn apply(&self, plan: &RoutePlan) -> Vec<Cmd> {
        let cmds = self.inner.apply(plan);
        self.record(&cmds);
        cmds
    }

    fn rollback(&self, plan: &RoutePlan) -> Vec<Cmd> {
        let cmds = self.inner.rollback(plan);
        self.record(&cmds);
        cmds
    }
}

impl<E: DnsExecutor> DnsExecutor for Recording<E> {
    fn apply(&self, plan: &DnsPlan) -> Vec<Cmd> {
        let cmds = self.inner.apply(plan);
        self.record(&cmds);
        cmds
    }

    fn rollback(&self, plan: &DnsPlan) -> Vec<Cmd> {
        let cmds = self.inner.rollback(plan);
        self.record(&cmds);
        cmds
    }
}

/// 运行时默认执行器对（routes, dns）。
type DefaultExecutors = (Option<Box<dyn RouteExecutor>>, Option<Box<dyn DnsExecutor>>);

/// 运行时默认执行器（按编译目标平台选择；具备渲染+真执行能力——
/// 生产路径 `apply_exec`/`rollback_exec` 只会拿到本平台渲染器，Windows 上
/// 不可能产出 `ip`/`resolvectl`，反之亦然）。
#[must_use]
pub fn default_executors() -> DefaultExecutors {
    #[cfg(target_os = "windows")]
    {
        (Some(Box::new(WindowsRoutes)), Some(Box::new(WindowsDns)))
    }
    #[cfg(target_os = "linux")]
    {
        (Some(Box::new(LinuxRoutes)), Some(Box::new(LinuxDns)))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        (None, None)
    }
}
