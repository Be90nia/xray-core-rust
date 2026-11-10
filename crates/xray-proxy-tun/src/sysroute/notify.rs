//! 运行期路由/接口变化 → 重选出口网卡 + 重跑 weak host send 守卫。
//!
//! 对应 Go `proxy/tun/tun_windows.go:344-359` 的两个 iphlpapi 订阅
//! （`winipcfg.RegisterRouteChangeCallback` / `RegisterInterfaceChangeCallback`），
//! 回调体只有两步：`updater.Update()`（重选物理网卡）→ `t.guard.check()`（重跑
//! weak host send 守卫，换卡时先恢复旧卡）。
//!
//! 为什么必须有：启动时选一次是不够的——运行期插拔网卡、Wi-Fi↔有线切换、默认路由
//! 改变、用户开热点（forwarding）都会让绑定失效。失效后出站 socket 仍绑旧卡 ⇒ 包被
//! 路由进 TUN 卡死；新开的 weak host send 也无人关。
//!
//! ## 线程纪律（MSDN：同一次注册的回调被**串行**调用，跑在系统线程池的任意线程上）
//!
//! 回调里**只投递事件**（[`post`]：一次无边队列 `send`，不枚举、不写卡、不取锁）。
//! 枚举接口（几十毫秒）与 `SetIpInterfaceEntry`（等 NDIS）全部在托管任务里做：放
//! 回调线程会卡住整条系统通知队列，且在 NDIS 通知里做网络配置 IO 有反入风险。
//!
//! ## 反注册与上下文寿命
//!
//! `CancelMibChangeNotify2` 与在途回调同步（MSDN 备注：反注册线程持回调线程要等的
//! 资源即死锁 ⇒ 它会等回调返回），故 [`ChangeWatcher::drop`] 返回后不会再有回调读到
//! 投递上下文；本模块的回调不取任何共享资源，无死锁面。

use std::sync::Arc;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use windows_sys::Win32::{
    Foundation::{HANDLE, NO_ERROR, WIN32_ERROR},
    NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
        NotifyIpInterfaceChange, NotifyRouteChange2,
    },
    Networking::WinSock::AF_UNSPEC,
};

use super::guard::OutboundGuard;

/// 变化来源。只影响日志措辞——Go 两个回调体逐字相同（都是 Update + check），
/// 处置不分种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ChangeKind {
    /// 路由表变化（`NotifyRouteChange2`）：默认路由改变、网关换卡。
    Route,
    /// IP 接口变化（`NotifyIpInterfaceChange`）：网卡插拔、上下线、地址变化。
    Interface,
}

impl ChangeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Interface => "interface",
        }
    }
}

/// 一条通知的处置计划（[`plan`] 的产物）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// 换卡：绑定写新卡 + 重跑守卫（`OutboundGuard::check` 见索引变化先恢复旧卡）。
    Rebinding { name: String, index: u32 },
    /// 未换卡：只重跑守卫（Go 回调无条件 `guard.check()`）。
    Recheck { name: String, index: u32 },
    /// 重选失败：旧绑定与旧守卫状态都不动。
    ///
    /// Go 此时把 `updater.iface` 置 nil（config.go:33-40）再 `guard.check()`（恢复旧卡）；
    /// Rust 侧清空绑定 = controller 变 no-op ⇒ 拨号回落到系统路由表 = 重新落进 TUN，
    /// 正是本票要治的病。故保留旧绑定，只告警（失败可见，但不变差）。
    Keep { error: String },
}

/// 通知 → 处置计划（纯函数：输入全是纯数据，不枚举、不写卡 ⇒ 可离线单测）。
pub(crate) fn plan(
    current: &Option<(u32, String)>,
    resolved: &Result<(String, u32), String>,
) -> Plan {
    match resolved {
        Ok((name, index)) if current.as_ref().is_some_and(|(cur, _)| *cur == *index) => {
            Plan::Recheck { name: name.clone(), index: *index }
        },
        Ok((name, index)) => Plan::Rebinding { name: name.clone(), index: *index },
        Err(error) => Plan::Keep { error: error.clone() },
    }
}

/// 执行一条通知：重选出口网卡 → 按 [`plan`] 决定是否改绑 → 重跑守卫。
///
/// 阻塞（枚举 + 写卡）——只能在托管任务里跑，禁止在回调线程调用。
pub(crate) fn apply(kind: ChangeKind, tun_index: u32, mode: &str, guard: &OutboundGuard) {
    // 停机窗（`close` 已 restore 守卫）里在途/排队的通知一律丢弃：此时写绑定只会给
    // 停机后的进程留一个指向已失效网卡的错绑（`close` 在 drain 之后才清绑定）。
    if guard.is_stopped() {
        return;
    }
    let current = crate::sysroute::outbound_iface();
    let resolved =
        crate::sysroute::reselect_outbound_interface(tun_index, mode).map_err(|e| e.to_string());
    let was = current.as_ref().map_or("-", |(_, name)| name.as_str());
    match plan(&current, &resolved) {
        Plan::Rebinding { name, index } => {
            crate::TUN_LOG.info(format!(
                "[tun] {} change: outbound interface {was} -> {name} ({index})",
                kind.label()
            ));
            guard.check(Some((index, name.as_str())));
        },
        Plan::Recheck { name, index } => {
            // 卡没换，但它的地址族/转发状态可能刚变——Go 同样无条件重跑。
            guard.check(Some((index, name.as_str())));
        },
        Plan::Keep { error } => {
            crate::TUN_LOG.warn(format!(
                "[tun] {} change: unable to update interface: {error} (keeping {was})",
                kind.label()
            ));
        },
    }
}

/// 运行期出站维护会话：守卫 + 两个通知订阅 + 重选参数。
///
/// 生命周期挂在 `TunInboundHandler`（`start` 建、`close`/`rollback_start` 停）。
/// 守卫与订阅同寿命——否则会出现「回调还在投递而守卫已恢复」的窗口。
pub(crate) struct OutboundWatch {
    /// 通知订阅（`Drop` = 反注册）。
    watcher: ChangeWatcher,
    /// weak host send 守卫：托管任务持 `Arc` 克隆做重跑，本会话持原件负责停机恢复。
    guard: Arc<OutboundGuard>,
    /// TUN 自身索引（重选时排除，Go `InterfaceUpdater.tunIndex`）。
    tun_index: u32,
    /// `autoOutboundsInterface` 原值（`"auto"` 或固定网卡名，Go `fixedName`）。
    mode: String,
    /// 通知接收端——交给托管任务后置 None（只能取一次）。
    events: Option<UnboundedReceiver<ChangeKind>>,
}

impl OutboundWatch {
    /// 建会话：守卫首轮 check（Go 在注册回调**之前**就跑一次 check，
    /// tun_windows.go:335-359）→ 注册两个回调。
    ///
    /// 任一步失败即 Err，调用方按启动失败回滚（对齐 Go：Start 返回错误）。
    pub(crate) fn start(
        tun_index: u32,
        mode: String,
        guard: OutboundGuard,
    ) -> Result<Self, String> {
        let guard = Arc::new(guard);
        let bound = crate::sysroute::outbound_iface();
        guard.check(bound.as_ref().map(|(index, name)| (*index, name.as_str())));
        let (watcher, events) = ChangeWatcher::register(false)?;
        Ok(Self { watcher, guard, tun_index, mode, events: Some(events) })
    }

    /// 拆出托管任务侧参数（接收端只能取一次；再取 = None）。
    pub(crate) fn task_parts(
        &mut self,
    ) -> Option<(UnboundedReceiver<ChangeKind>, Arc<OutboundGuard>, u32, String)> {
        let events = self.events.take()?;
        Some((events, Arc::clone(&self.guard), self.tun_index, self.mode.clone()))
    }

    /// 停机：先反注册（不再投递）再恢复守卫（Go `Close`：`Unregister` → `guard.restore`）。
    ///
    /// 反注册同时释放投递端 ⇒ 托管任务的 `recv()` 返回 None 自行结束。
    pub(crate) fn stop(self) {
        drop(self.watcher);
        self.guard.restore();
    }
}

/// 两个通知注册的句柄集合。`Drop` = 反注册。
struct ChangeWatcher {
    /// 回调上下文的所有权（`Arc::as_ptr` 借给 iphlpapi 作 `CallerContext`）。
    /// 下划线前缀 = 只持有不读取；反注册完成后才随结构释放（见 `Drop`）。
    _context: Arc<UnboundedSender<ChangeKind>>,
    /// `NotifyRouteChange2` 的注册句柄。
    ///
    /// 按 `usize` 存而非 `HANDLE`（= `*mut c_void`）：句柄是 iphlpapi 的不透明内核
    /// 值、不指向 Rust 内存，存成指针类型会让整个会话 `!Send`，进不了 `TunInboundHandler`
    /// （它必须是 `Send`，回调任务跑在 tokio 线程上）。
    route: usize,
    /// `NotifyIpInterfaceChange` 的注册句柄（同上）。
    iface: usize,
}

impl ChangeWatcher {
    /// 注册两个回调（`AF_UNSPEC` = IPv4+IPv6 两族，MSDN 明示；与 Go
    /// `RegisterRouteChangeCallback` / `RegisterInterfaceChangeCallback` 同口径）。
    ///
    /// `initial_notification`：生产恒 `false`（Go 也不传——初始通知只表明注册成功、
    /// 不代表发生变化，没必要为它白跑一轮枚举）；测试传 `true`，借 Windows 的
    /// 「注册完成即回调一次」证明「回调 → 通道 → 消费端」链路真的通，且不改任何
    /// 系统状态。
    fn register(
        initial_notification: bool,
    ) -> Result<(Self, UnboundedReceiver<ChangeKind>), String> {
        let (tx, events) = unbounded_channel();
        let tx = Arc::new(tx);
        let context = Arc::as_ptr(&tx).cast::<core::ffi::c_void>();
        let initial = u8::from(initial_notification);

        let mut route: HANDLE = std::ptr::null_mut();
        // SAFETY: 句柄经 `&mut route` 交出；`context` 指向上一行的 `Arc`，本结构与
        // 注册同寿命（见 `Drop`）；回调与 `AF_UNSPEC`/`BOOLEAN` 实参均为合法值。
        let status =
            unsafe { NotifyRouteChange2(AF_UNSPEC, Some(on_route), context, initial, &mut route) };
        if status != NO_ERROR {
            return Err(format!("NotifyRouteChange2 failed: {}", os_error(status)));
        }

        let mut iface: HANDLE = std::ptr::null_mut();
        // SAFETY: 同上一处。
        let status = unsafe {
            NotifyIpInterfaceChange(AF_UNSPEC, Some(on_iface), context, initial, &mut iface)
        };
        if status != NO_ERROR {
            // 已注册的路由回调必须拆掉：句柄不交出 = 无人反注册 = 订阅泄漏。
            // SAFETY: `route` 是上面成功的注册句柄，只取消一次。
            unsafe { CancelMibChangeNotify2(route) };
            return Err(format!("NotifyIpInterfaceChange failed: {}", os_error(status)));
        }

        Ok((Self { _context: tx, route: route as usize, iface: iface as usize }, events))
    }
}

impl Drop for ChangeWatcher {
    fn drop(&mut self) {
        // 反注册。与在途回调同步（见模块文档）：返回后不会再有回调读 `_context`，
        // 故 `_context`（字段 drop 在本函数返回后）可安全释放。
        // SAFETY: 两个句柄各来自一次成功的注册（注册失败已在 `register` 里拆掉并
        // 返回 Err），且各只取消一次；`usize` 存的是注册函数原样返回的句柄值。
        unsafe {
            CancelMibChangeNotify2(self.route as HANDLE);
            CancelMibChangeNotify2(self.iface as HANDLE);
        }
    }
}

/// 路由表变化回调（`NotifyRouteChange2`）。
///
/// # Safety
///
/// 由 iphlpapi 调用：`context` 必须是注册时交出的 `Arc<UnboundedSender<_>>` 指针。
unsafe extern "system" fn on_route(
    context: *const core::ffi::c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _notification: MIB_NOTIFICATION_TYPE,
) {
    post(context, ChangeKind::Route);
}

/// IP 接口变化回调（`NotifyIpInterfaceChange`）。
///
/// # Safety
///
/// 同 [`on_route`]。
unsafe extern "system" fn on_iface(
    context: *const core::ffi::c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notification: MIB_NOTIFICATION_TYPE,
) {
    post(context, ChangeKind::Interface);
}

/// 回调线程唯一动作：投递一条通知。
///
/// 无界队列的 `send` 只写队列 + 唤醒消费者任务（可从任意线程调用），不阻塞、不取
/// 本模块任何锁——这是「回调不得做耗时操作」的落地方式。
fn post(context: *const core::ffi::c_void, kind: ChangeKind) {
    // SAFETY: `context` = `Arc::as_ptr(&ChangeWatcher::_context)`；所有权在会话结构里，
    // 反注册返回后（之后不会再有回调）才释放，故此处引用有效。
    let tx = unsafe { &*context.cast::<UnboundedSender<ChangeKind>>() };
    // 接收端已 drop ⇒ 停机窗口（`OutboundWatch::stop` 先反注册再放会话）：此时没有
    // 需要通知的对象，丢弃即正确。
    let _ = tx.send(kind);
}

/// `WIN32_ERROR` → 系统错误文本（`FormatMessage` 等价物）。
fn os_error(status: WIN32_ERROR) -> String {
    std::io::Error::from_raw_os_error(status as i32).to_string()
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::error::TryRecvError;

    use super::{ChangeKind, Plan, plan};

    fn bound(index: u32, name: &str) -> Option<(u32, String)> {
        Some((index, name.to_string()))
    }

    #[test]
    fn plan_rechecks_when_interface_unchanged() {
        assert_eq!(
            plan(&bound(7, "eth0"), &Ok(("eth0".into(), 7))),
            Plan::Recheck { name: "eth0".into(), index: 7 }
        );
    }

    #[test]
    fn plan_rebinds_when_interface_switched() {
        assert_eq!(
            plan(&bound(7, "eth0"), &Ok(("wlan0".into(), 9))),
            Plan::Rebinding { name: "wlan0".into(), index: 9 }
        );
    }

    #[test]
    fn plan_rebinds_when_nothing_bound_yet() {
        assert_eq!(
            plan(&None, &Ok(("eth0".into(), 7))),
            Plan::Rebinding { name: "eth0".into(), index: 7 }
        );
    }

    #[test]
    fn plan_keeps_binding_when_reselection_fails() {
        assert_eq!(
            plan(&bound(7, "eth0"), &Err("no cable".into())),
            Plan::Keep { error: "no cable".into() }
        );
    }

    #[test]
    fn kind_labels_are_distinct() {
        assert_ne!(ChangeKind::Route.label(), ChangeKind::Interface.label());
    }

    /// 真机：运行期重选路径（枚举 → 解析 → 写全局绑定）真实跑一遍——选出的网卡名
    /// 非空且写进了绑定状态。无可用物理网卡的环境（沙箱）跳过，与 guard 测试同口径。
    #[test]
    fn reselect_updates_binding_on_this_machine() {
        let previous = crate::sysroute::outbound_iface();
        let Ok((name, index)) = crate::sysroute::reselect_outbound_interface(0, "auto") else {
            return;
        };
        assert!(!name.is_empty(), "resolved interface name must not be empty");
        assert_eq!(crate::sysroute::outbound_iface(), Some((index, name)));
        crate::sysroute::set_outbound_iface(previous);
    }

    /// 真机证据（无需管理员、不改任何网络状态），两段：
    ///
    /// 1. 两个回调注册成功，且 `InitialNotification = TRUE` 让 Windows 立刻回调一次 ⇒ 「回调 → 通道
    ///    → 消费端」链路真的通（含 `CallerContext` 所有权正确）；
    /// 2. 会话 drop 之后通道关闭 ⇒ 反注册生效、投递端随会话释放（无悬垂上下文）。
    #[tokio::test]
    async fn callbacks_fire_and_cancel() {
        let (watch, mut events) = super::ChangeWatcher::register(true).expect("register callbacks");

        // 两条初始通知（路由 + 接口）先后到达；期间也可能夹进真实变化，故按种类收
        // 齐而不是按条数。
        let (mut route, mut iface) = (false, false);
        let arrived = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !(route && iface) {
                match events.recv().await.expect("channel must stay open while registered") {
                    ChangeKind::Route => route = true,
                    ChangeKind::Interface => iface = true,
                }
            }
        })
        .await;
        assert!(arrived.is_ok(), "initial notifications missing (route={route} iface={iface})");

        drop(watch);
        // 注册到 drop 之间可能确有真实变化，先排空再判断开。
        while events.try_recv().is_ok() {}
        assert!(
            matches!(events.try_recv(), Err(TryRecvError::Disconnected)),
            "channel must be closed after deregistration"
        );
    }
}
