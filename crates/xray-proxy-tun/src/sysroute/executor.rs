//! 执行器层：把 `sysroute` 的变更计划渲染成结构化命令，并提供真实执行。
//!
//! # 渲染与执行分离
//!
//! - **渲染面**（`apply`/`rollback` → `Vec<Cmd>`）：产出结构化命令 [`Cmd`]（program +
//!   args，不经字符串拆分），`Display` 即完整命令行。 测试与 Recording 走这里——**从不执行**。
//! - **执行面**（`apply_exec`/`rollback_exec` → trait 默认方法）：逐条 [`Cmd::run`] 真实
//!   spawn。**全模块唯一执行点**是 [`Cmd::run`]；每条命令 执行前
//!   `TUN_LOG.info`（program+args），失败 `TUN_LOG.error` 并上抛，
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
//!   删除侧**不带 metric**（MS 文档的 `route delete` / `netsh delete route` 均无该参数，
//!   带上即整体失败 —— 票 yq6gv b）。
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
        crate::TUN_LOG
            .info(format!("tun sysroute exec program={} args={:?}", self.program, self.args));
        let status = Command::new(&self.program).args(&self.args).status()?;
        if !status.success() {
            crate::TUN_LOG.error(format!(
                "tun sysroute command failed program={} args={:?} status={status}",
                self.program, self.args
            ));
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

/// 顺序执行全部命令，错误逐条收集后合并上报（**首错不中断**——一条失败不得连带
/// 跳过其余回滚，否则残留系统状态更多；对齐 Go 逐条收集错误再合并）。
fn run_all_collect(cmds: &[Cmd]) -> std::io::Result<()> {
    let mut errors = Vec::new();
    for cmd in cmds {
        if let Err(e) = cmd.run() {
            errors.push(format!("`{cmd}`: {e}"));
        }
    }
    if errors.is_empty() {
        return Ok(());
    }
    Err(std::io::Error::other(errors.join("; ")))
}

/// 顺序执行到首个错误为止，返回（已成功条数, 首个错误）。
fn run_until_error(cmds: &[Cmd]) -> (usize, Option<std::io::Error>) {
    let mut applied = 0usize;
    for cmd in cmds {
        if let Err(e) = cmd.run() {
            return (applied, Some(e));
        }
        applied += 1;
    }
    (applied, None)
}

/// apply 中途失败时的收尾：执行 `rollback` 命令撤销已下发条目，并把回滚自身的
/// 失败与原错误**合并上报**（回滚首错绝不静默——静默会让残留路由无人知晓）。
fn cleanup_after_failure(rollback: &[Cmd], cause: std::io::Error) -> std::io::Error {
    let mut messages = vec![format!("apply failed after partial write: {cause}")];
    if let Err(e) = run_all_collect(rollback) {
        messages.push(format!("rollback failed: {e}"));
    }
    std::io::Error::other(messages.join("; "))
}

/// 路由计划执行器：渲染命令（`apply`/`rollback`）+ 真实执行（`*_exec`）。
pub trait RouteExecutor: Send + Sync {
    /// 渲染新增命令（顺序同 [`RoutePlan::add`]）。不执行。
    fn apply(&self, plan: &RoutePlan) -> Vec<Cmd>;
    /// 渲染回滚命令（与 `apply` 一一对应、反序——对齐 Go `unsetSystemRoutes`）。不执行。
    fn rollback(&self, plan: &RoutePlan) -> Vec<Cmd>;

    /// 顺序真实执行 apply 的全部命令；**任一失败即撤销已下发条目**再上抛。
    ///
    /// 逐条记账（`run_until_error`）而非「首错即停」：已写进系统路由表的条目若不
    /// 撤销，TUN 设备关闭后这些网段永久指向已关闭设备（流量黑洞）。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）；回滚自身失败时与原错误合并。
    fn apply_exec(&self, plan: &RoutePlan) -> std::io::Result<()> {
        let (applied, err) = run_until_error(&self.apply(plan));
        let Some(cause) = err else {
            return Ok(());
        };
        // `rollback` 与 `apply` 一一对应且反序 ⇒ 其尾部 `applied` 条正是已下发条目的
        // 撤销命令（逆序执行）。
        let rollback = self.rollback(plan);
        let skip = rollback.len().saturating_sub(applied);
        Err(cleanup_after_failure(&rollback[skip..], cause))
    }

    /// 反序真实执行 rollback 的全部命令；**逐条收集错误**（首错不中断）。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn rollback_exec(&self, plan: &RoutePlan) -> std::io::Result<()> {
        run_all_collect(&self.rollback(plan))
    }
}

/// DNS 计划执行器：渲染命令（`apply`/`rollback`）+ 真实执行（`*_exec`）。
pub trait DnsExecutor: Send + Sync {
    /// 渲染接管命令（Linux 三步序列 / Windows 按族 set+add）。不执行。
    fn apply(&self, plan: &DnsPlan) -> Vec<Cmd>;
    /// 渲染恢复命令（Linux `revert` / Windows 清空 TUN 适配器 DNS）。不执行。
    fn rollback(&self, plan: &DnsPlan) -> Vec<Cmd>;

    /// 顺序真实执行接管的全部命令；**任一失败即撤销已下发状态**再上抛。
    ///
    /// DNS 回滚是整计划幂等动作（Linux `resolvectl revert` / Windows
    /// `address=none`），故已执行任意一条即按整计划回滚——不按条数裁剪。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）；回滚自身失败时与原错误合并。
    fn apply_exec(&self, plan: &DnsPlan) -> std::io::Result<()> {
        let (applied, err) = run_until_error(&self.apply(plan));
        let Some(cause) = err else {
            return Ok(());
        };
        if applied == 0 {
            // 一条都没写下去 = 系统状态未变，无需回滚。
            return Err(cause);
        }
        Err(cleanup_after_failure(&self.rollback(plan), cause))
    }

    /// 顺序真实执行恢复的全部命令；**逐条收集错误**（首错不中断）。
    ///
    /// # Errors
    /// 任一命令 spawn 失败或非零退出（见 [`Cmd::run`]）。
    fn rollback_exec(&self, plan: &DnsPlan) -> std::io::Result<()> {
        run_all_collect(&self.rollback(plan))
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
    // MS 文档只给 `route add` / `netsh add route` 定义 metric：`route delete` 与
    // `netsh interface ipv6 delete route` 都不收该参数，带上会被判非法参数而整体
    // 失败 ⇒ 回滚失败、路由残留（票 yq6gv b）。删除按「目标 + 接口」定位，与 Go
    // `LUID.FlushRoutes`（按 LUID 整族清）语义等价。
    let metric = (verb == "add").then(|| e.metric.to_string());
    match e.destination {
        // route.exe 语法：route <verb> <dst> mask <mask> [metric <m>] if <idx>。
        std::net::IpAddr::V4(v4) => {
            let mut args =
                vec![verb.into(), v4.to_string(), "mask".into(), v4_mask(e.prefix).to_string()];
            if let Some(metric) = &metric {
                args.extend(["metric".to_string(), metric.clone()]);
            }
            args.extend(["if".to_string(), plan.interface_index.to_string()]);
            Cmd::new("route", args)
        },
        // route.exe 不支持 v6：netsh route 按接口名挂。
        std::net::IpAddr::V6(_) => {
            let mut args = vec![
                "interface".into(),
                "ipv6".into(),
                verb.into(),
                "route".into(),
                format!("{}/{}", e.destination, e.prefix),
                format!("interface={}", plan.interface),
            ];
            if let Some(metric) = &metric {
                args.push(format!("metric={metric}"));
            }
            Cmd::new("netsh", args)
        },
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::sysroute::Platform;

    /// 必然成功的命令：两平台各一条真实可执行程序（`Cmd` 结构化 args 直传进程）。
    #[cfg(target_os = "windows")]
    fn succeeding_cmd() -> Cmd {
        Cmd::new("cmd", vec!["/c".into(), "exit 0".into()])
    }
    #[cfg(not(target_os = "windows"))]
    fn succeeding_cmd() -> Cmd {
        Cmd::new("true", Vec::new())
    }

    /// 必然失败的命令：程序不存在 ⇒ spawn 即 `Err`，与平台 shell / 磁盘状态无关。
    /// 程序名带 tag ⇒ 「哪条回滚命令真的被执行」可从错误消息里读出来。
    fn missing_program(tag: &str) -> Cmd {
        Cmd::new(format!("xray-sysrollback-missing-{tag}"), Vec::new())
    }

    fn route_plan() -> RoutePlan {
        RoutePlan {
            platform: Platform::current(),
            interface: "xray-tun".into(),
            interface_index: 7,
            add: Vec::new(),
            outbound_interface: None,
        }
    }

    fn dns_plan() -> DnsPlan {
        DnsPlan {
            platform: Platform::current(),
            interface: "xray-tun".into(),
            target: DnsTarget::WindowsAdapterServers {
                servers: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
        }
    }

    /// apply 第 2 条必然失败、回滚命令全部指向不存在的程序。
    struct FailingRoutes;

    impl RouteExecutor for FailingRoutes {
        fn apply(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            vec![succeeding_cmd(), missing_program("apply-2")]
        }

        fn rollback(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            // 与 apply 一一对应且反序：第 0 项对第 2 条、第 1 项对第 1 条。
            vec![missing_program("rollback-for-2"), missing_program("rollback-for-1")]
        }
    }

    struct FailingDns;

    impl DnsExecutor for FailingDns {
        fn apply(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            vec![succeeding_cmd(), missing_program("dns-apply-2")]
        }

        fn rollback(&self, _plan: &DnsPlan) -> Vec<Cmd> {
            vec![missing_program("dns-rollback")]
        }
    }

    /// 全部命令成功的执行器（对照：不该产生任何回滚）。
    struct AllOkRoutes;

    impl RouteExecutor for AllOkRoutes {
        fn apply(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            vec![succeeding_cmd()]
        }

        fn rollback(&self, _plan: &RoutePlan) -> Vec<Cmd> {
            vec![missing_program("rollback-must-not-run")]
        }
    }

    /// 票 mjbbg 契约：第 2 条失败 ⇒ 第 1 条被撤销（且未下发的第 2 条不撤销）。
    #[test]
    fn route_apply_failure_rolls_back_only_written_entries() {
        let err = FailingRoutes.apply_exec(&route_plan()).unwrap_err().to_string();
        // spawn 失败的错误文本只有 "program not found"（不含程序名），故按阶段文案断言。
        assert!(err.contains("apply failed after partial write"), "原错误必须上报：{err}");
        assert!(
            err.contains("xray-sysrollback-missing-rollback-for-1"),
            "已下发的第 1 条必须被撤销：{err}"
        );
        assert!(
            !err.contains("xray-sysrollback-missing-rollback-for-2"),
            "未下发的第 2 条不得撤销：{err}"
        );
    }

    /// 回滚自身失败不静默：与原错误合并上报。
    #[test]
    fn route_apply_failure_reports_rollback_failure_too() {
        let err = FailingRoutes.apply_exec(&route_plan()).unwrap_err().to_string();
        assert!(err.contains("rollback failed"), "回滚失败须显式可见：{err}");
    }

    /// 全成功 ⇒ Ok，且绝不执行回滚命令。
    #[test]
    fn route_apply_all_success_runs_no_rollback() {
        AllOkRoutes.apply_exec(&route_plan()).expect("all commands succeed");
    }

    /// DNS 接管失败按整计划回滚（revert / address=none 是幂等整计划动作）。
    #[test]
    fn dns_apply_failure_runs_plan_rollback() {
        let err = FailingDns.apply_exec(&dns_plan()).unwrap_err().to_string();
        assert!(err.contains("apply failed after partial write"), "原错误必须上报：{err}");
        assert!(err.contains("xray-sysrollback-missing-dns-rollback"), "必须整计划回滚：{err}");
    }

    /// rollback_exec 逐条收集错误：首错之后的命令照跑（否则连带跳过余下回滚）。
    #[test]
    fn rollback_exec_collects_errors_without_stopping() {
        struct TwoBadRollbacks;
        impl RouteExecutor for TwoBadRollbacks {
            fn apply(&self, _plan: &RoutePlan) -> Vec<Cmd> {
                Vec::new()
            }

            fn rollback(&self, _plan: &RoutePlan) -> Vec<Cmd> {
                vec![missing_program("rb-a"), missing_program("rb-b")]
            }
        }

        let err = TwoBadRollbacks.rollback_exec(&route_plan()).unwrap_err().to_string();
        assert!(err.contains("xray-sysrollback-missing-rb-a"), "{err}");
        assert!(err.contains("xray-sysrollback-missing-rb-b"), "首错后必须继续：{err}");
    }
}
