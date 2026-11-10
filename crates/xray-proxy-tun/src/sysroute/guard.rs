//! weak host send 守卫（Go `proxy/tun/tun_windows_outbound.go` 的 `outboundGuard`）。
//!
//! 语义：`autoOutboundsInterface` 把 Xray 自己的 socket 绑到物理网卡，但网卡上
//! 若开着 weak host send（或 forwarding），Windows 会忽略绑定、把包按路由表
//! 送进 TUN——从该网卡地址发出，回来的包又被 TUN 侧丢掉，于是连接卡死。
//!
//! 处置（与 Go 一致）：
//! - 对被**路由到 TUN 的 IP 族**关掉绑定网卡的 weak host send，停机/换卡恢复；
//! - forwarding（移动热点 / ICS 需要它）**只告警**，不关。
//!
//! 关掉 weak host send 要管理员权限；失败**只告警**，不阻塞 TUN 启动（Go 同）。

use std::mem::zeroed;

use parking_lot::Mutex;
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceIndexToLuid, GetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
            SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6},
};

/// `SetIpInterfaceEntry` 失败的系统错误文本。
fn io_error(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// IP 族名（Go `familyName`）。
fn family_name(family: ADDRESS_FAMILY) -> &'static str {
    if family == AF_INET { "IPv4" } else { "IPv6" }
}

/// 接口索引 → LUID（Go `winipcfg.LUIDFromIndex`）。
fn luid_from_index(index: u32) -> Result<u64, String> {
    // SAFETY: 输出结构由本函数持有；`ConvertInterfaceIndexToLuid` 只写它。
    let mut luid = NET_LUID_LH { Value: 0 };
    let code = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    if code != ERROR_SUCCESS {
        return Err(io_error(code));
    }
    // SAFETY: 上一步成功后整块 union 已由系统写入，读 `Value` 分支合法。
    Ok(unsafe { luid.Value })
}

/// 读该接口某 IP 族的 `MIB_IPINTERFACE_ROW`（Go `luid.IPInterface(family)`）。
fn ip_interface(luid: u64, family: ADDRESS_FAMILY) -> Result<MIB_IPINTERFACE_ROW, String> {
    // SAFETY: 结构体全零 + 两个入参字段，GetIpInterfaceEntry 只读这两项、写其余。
    let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
    row.Family = family;
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code != ERROR_SUCCESS {
        return Err(io_error(code));
    }
    Ok(row)
}

/// 写回 weak host send 开关（Go `setWeakHostSend`）。
///
/// IPv4 必须把 `SitePrefixLength` 清 0，否则 `SetIpInterfaceEntry` 报参数错
/// （Go 同款注释：「as SetIpInterfaceEntry requires for IPv4」）。
fn set_weak_host_send(mut row: MIB_IPINTERFACE_ROW, on: bool) -> Result<(), String> {
    row.WeakHostSend = u8::from(on);
    if row.Family == AF_INET {
        row.SitePrefixLength = 0;
    }
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code != ERROR_SUCCESS {
        return Err(io_error(code));
    }
    Ok(())
}

#[derive(Default)]
struct GuardState {
    /// 被路由到 TUN 的 IP 族。
    families: Vec<ADDRESS_FAMILY>,
    /// 上次检查的网卡索引（换卡时先恢复旧卡）。
    index: Option<u32>,
    /// 该网卡索引对应的 LUID（恢复时用）。
    luid: u64,
    name: String,
    /// 已在哪些族上关掉过 weak host send（恢复用）。
    turned_off: Vec<ADDRESS_FAMILY>,
    /// 上次是否观测到 forwarding（`true → true` 不重复告警）。
    forwarding: bool,
    stopped: bool,
}

/// weak host send 守卫。`Drop` 即恢复（停机、启动失败回滚、换卡都走这里）。
pub struct OutboundGuard {
    state: Mutex<GuardState>,
}

impl OutboundGuard {
    /// `ipv4` / `ipv6` = 该族有路由指向 TUN（Go `t.guard.families`）。
    #[must_use]
    pub fn new(ipv4: bool, ipv6: bool) -> Self {
        let mut families = Vec::new();
        if ipv4 {
            families.push(AF_INET);
        }
        if ipv6 {
            families.push(AF_INET6);
        }
        Self { state: Mutex::new(GuardState { families, ..GuardState::default() }) }
    }

    /// 检查绑定网卡：关掉 weak host send，forwarding 只告警（Go `check`）。
    ///
    /// `bound` = 当前绑定的物理网卡（`sysroute::outbound_iface()`）；`None` = 未绑定，
    /// 此时只清旧卡状态。
    pub fn check(&self, bound: Option<(u32, &str)>) {
        let mut st = self.state.lock();
        if st.stopped {
            return;
        }
        let (index, name) = match bound {
            Some((index, name)) => (Some(index), name.to_string()),
            None => (None, String::new()),
        };
        if index != st.index {
            // 换网卡：旧卡先恢复，forwarding 记账清零（新卡也要告警）。
            restore_locked(&mut st);
            st.index = index;
            st.name = name.clone();
            st.forwarding = false;
        }
        let Some(index) = index else { return };
        let luid = match luid_from_index(index) {
            Ok(luid) => luid,
            Err(e) => {
                crate::TUN_LOG.warn(format!(
                    "[tun] unable to look up the interface {name} to check weak host send: {e}"
                ));
                return;
            },
        };
        st.luid = luid;
        let mut forwarding = Vec::new();
        for family in st.families.clone() {
            let row = match ip_interface(luid, family) {
                Ok(row) => row,
                // 该网卡没有这个 IP 族（Go 同：跳过）。
                Err(_) => continue,
            };
            if row.ForwardingEnabled != 0 {
                forwarding.push(family_name(family));
            }
            if row.WeakHostSend == 0 {
                continue;
            }
            if let Err(e) = set_weak_host_send(row, false) {
                warn_unable_off(&name, family, &e);
                continue;
            }
            if !st.turned_off.contains(&family) {
                st.turned_off.push(family);
                info_turned_off(&name, family);
            }
        }
        let was_on = st.forwarding;
        st.forwarding = !forwarding.is_empty();
        if st.forwarding && !was_on {
            crate::TUN_LOG.warn(format!(
                "[tun] forwarding is on for {} on {name} (Mobile Hotspot and Internet Connection \
                 Sharing turn it on), so Windows ignores autoOutboundsInterface there, and Xray's \
                 own connections go into the TUN and stall: turn the hotspot off, or have it share \
                 the TUN instead of {name}",
                forwarding.join(" and ")
            ));
        }
    }

    /// 真机自检（`examples/tun_win_live.rs`）：对给定网卡/族**强制**走一次「关 weak host
    /// send」，用的是与 [`Self::check`] 同一的写入函数与同一告警文本。
    ///
    /// 为什么需要：生产 `check` 只在网卡上 `WeakHostSend == 1` 时才写，而本机能拿到的
    /// 网卡都已经是 0（写得进去也不该写），于是「无管理员 ⇒ 被拒 ⇒ 只告警」这一降级
    /// 路径在真实启动里根本走不到。写入成功（管理员）时按读到的原值写回，不留副作用。
    pub fn probe_weak_host_send(&self, index: u32, name: &str, ipv6: bool) {
        let family = if ipv6 { AF_INET6 } else { AF_INET };
        let label = family_name(family);
        let luid = match luid_from_index(index) {
            Ok(luid) => luid,
            Err(e) => return crate::TUN_LOG.warn(format!("[tun] probe: no LUID for {name}: {e}")),
        };
        let row = match ip_interface(luid, family) {
            Ok(row) => row,
            Err(e) => {
                return crate::TUN_LOG.warn(format!("[tun] probe: no {label} row for {name}: {e}"));
            },
        };
        let was_on = row.WeakHostSend != 0;
        match set_weak_host_send(row, false) {
            Err(e) => warn_unable_off(name, family, &e),
            Ok(()) => {
                crate::TUN_LOG.info(format!(
                    "[tun] probe: weak host send writable for {label} on {name} (was on: {was_on})"
                ));
                if was_on {
                    let _ = ip_interface(luid, family)
                        .and_then(|row| set_weak_host_send(row, true).map(|()| row));
                }
            },
        }
    }

    /// 恢复（Go `restore`）：把关掉过的族逐个开回来，之后不再检查。
    ///
    /// 生产路径不需要显式调——`Drop` 已保证；公开供运行期换卡等场景复用。
    pub fn restore(&self) {
        let mut st = self.state.lock();
        restore_locked(&mut st);
        st.stopped = true;
    }
}

/// 关不掉一族的告警（Go `check` 的 `LogWarningInner`）。
fn warn_unable_off(name: &str, family: ADDRESS_FAMILY, e: &str) {
    crate::TUN_LOG.warn(format!(
        "[tun] unable to turn weak host send off for {} on {name}: {e}",
        family_name(family)
    ));
}

/// 关掉一族的记账日志（Go `check` 的 `LogInfo`）。
fn info_turned_off(name: &str, family: ADDRESS_FAMILY) {
    crate::TUN_LOG.info(format!(
        "[tun] weak host send turned off for {} on {name} while the TUN runs, as Windows would \
         ignore autoOutboundsInterface",
        family_name(family)
    ));
}

impl Drop for OutboundGuard {
    fn drop(&mut self) {
        restore_locked(&mut self.state.lock());
    }
}

/// 恢复已关掉的族（Go `restoreLocked`）。失败只告警——卡已经不用了。
fn restore_locked(st: &mut GuardState) {
    for family in st.turned_off.drain(..) {
        let name = st.name.clone();
        let result = ip_interface(st.luid, family)
            .and_then(|row| set_weak_host_send(row, true).map(|()| row));
        if let Err(e) = result {
            crate::TUN_LOG.warn(format!(
                "[tun] unable to turn weak host send on again for {} on {name}: {e}",
                family_name(family)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_name_matches_ip_version() {
        assert_eq!(family_name(AF_INET), "IPv4");
        assert_eq!(family_name(AF_INET6), "IPv6");
    }

    /// 本机（非管理员）真跑：`SetIpInterfaceEntry` 被拒 → `check` 只告警不 panic，
    /// 守卫仍可正常 Drop 恢复。需真接口索引，取系统枚举的第一个非回环接口。
    #[test]
    fn check_without_admin_degrades_to_warning() {
        let interfaces = xray_common::net::interface::interfaces().expect("interfaces");
        let Some(iface) = interfaces.iter().find(|i| {
            i.index != 0 && !i.flags.contains(xray_common::net::interface::InterfaceFlags::LOOPBACK)
        }) else {
            return; // 无网卡（离线 CI 容器）：无从检查，跳过。
        };
        let guard = OutboundGuard::new(true, true);
        guard.check(Some((iface.index, iface.name.as_str())));
        // 走到这里即证明失败路径未阻塞、未 panic。
        guard.restore();
    }

    /// 不存在的网卡：LUID 换算或 IP 接口查询失败 → 告警后返回（Go 同：跳过）。
    #[test]
    fn check_unknown_interface_does_not_panic() {
        let guard = OutboundGuard::new(true, false);
        guard.check(Some((u32::MAX, "nope")));
        guard.restore();
    }
}
