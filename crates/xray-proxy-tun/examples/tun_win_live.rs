//! 真机自检：TUN 的 Windows 侧三条「失败只告警、不阻塞」的路径（票 172ew ②③④）。
//!
//! 直接调用生产函数（不是替身）：输出就是 `TUN_LOG`（target `xray_frame::tun`）的真实
//! 日志——`tracing_subscriber` 把 WARN 打到 stderr。
//!
//! - ② `sysroute::warn_dns_outside_tun`：覆盖集合（gateway ∪ autoSystemRoutingTable）之外 的 DNS
//!   服务器逐条 WARN；
//! - ③ `sysroute::flush_dns_cache`：真调 `dnsapi!DnsFlushResolverCache`；
//! - ④ `sysroute::guard::OutboundGuard`：真调 `iphlpapi!SetIpInterfaceEntry`——非管理员
//!   必然被拒，WARN 后照常返回（关键判据：不 panic、不中断）。
//!
//! 用法（**无需管理员**，反过来：非管理员才测得到 ④ 的降级路径）：
//!
//! ```bat
//! cargo run --example tun_win_live -p xray-proxy-tun
//! ```

#![allow(
    clippy::disallowed_macros,
    reason = "手工诊断 example：进度直印 stdout 是其唯一输出通道（非生产代码路径）"
)]

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("tun_win_live is Windows-only");
}

#[cfg(target_os = "windows")]
fn main() {
    use xray_proxy_tun::{StackOptions, sysroute};

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .without_time()
        .init();

    // ② 覆盖集合内的 DNS 静默、集合外的 DNS 告警（gateway 只覆盖 192.168.77.0/24）。
    let options = StackOptions {
        gateway: vec!["192.168.77.1/24".to_string()],
        dns: vec![
            "192.168.77.53".to_string(), // 集合内 → 不告警
            "8.8.8.8".to_string(),       // 集合外 → 告警
            "not-an-ip".to_string(),     // 解析失败 → 告警（不静默丢弃）
        ],
        ..StackOptions::default()
    };
    println!("== ② dnsOutsideTUN: gateway=192.168.77.1/24, dns=192.168.77.53,8.8.8.8,not-an-ip ==");
    sysroute::warn_dns_outside_tun(&options, None);

    // ③ 真调 dnsapi。
    println!("== ③ flushDNSCache ==");
    match sysroute::flush_dns_cache() {
        Ok(()) => println!("flushDNSCache: ok"),
        Err(e) => println!("flushDNSCache: FAILED {e}"),
    }

    // ④ 用本机真实出口网卡（与 start() 同一选择函数）。
    println!("== ④ weak host send guard (real SetIpInterfaceEntry) ==");
    let interfaces = xray_common::net::interface::interfaces().expect("enumerate interfaces");
    let Some(iface) = sysroute::select_outbound_interface(&interfaces, 0) else {
        println!("no outbound interface found");
        return;
    };
    println!("bound interface: {} (index {})", iface.name, iface.index);
    let guard = sysroute::guard::OutboundGuard::new(true, true);
    guard.check(Some((iface.index, iface.name.as_str())));
    println!(
        "-- forced write (probe): 本机网卡 WeakHostSend 已是 Disabled，check 不会写 ⇒ 用同一生产函数强制写一次 --"
    );
    guard.probe_weak_host_send(iface.index, &iface.name, false);
    guard.probe_weak_host_send(iface.index, &iface.name, true);
    guard.restore();
    println!("guard: returned without blocking (TUN start would continue)");
}
