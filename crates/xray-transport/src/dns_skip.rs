//! DNS 上游查询 skip 判定。对应 Go `transport/internet/dns_skip.go:10-31`。
//!
//! TUN 接管系统 DNS 后，Xray 自身对「被 TUN 接管的 DNS 服务器」的查询（localdns
//! 及上游 NS 直连兜底）会经系统路由绕回 TUN 自身（环路或不通）。Go 侧由 TUN 模块
//! （`proxy/tun/tun_windows.go:222/232/360`）把接管的服务器声明进进程级 skip 集合；
//! localdns 拨号前查表拒拨（`features/dns/localdns/client.go:99-103`）。
//! Rust 侧等价三件：
//! - 进程级 skip 集合：[`skip_dns_servers`]（TUN 接管实现的接入点，xray-proxy-tun 侧）；
//! - task-local 上游查询标记：[`scope_dns_upstream_query`]（DNS 模块发起上游查询时打）；
//! - 拨号点合成判定：[`is_skipped_dns_query`]。
//!
//! 默认零影响：集合为空或当前 task 无标记时，[`is_skipped_dns_query`] 恒 `false`，
//! 拨号行为与未接入本模块时逐字相同；用户流量拨向 DNS 服务器的正常代理连接不受影响。

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
};

use parking_lot::RwLock;

/// 进程级 skip 集合（Go `skippedDNSServers`，dns_skip.go:7）。读多写少：
/// 写仅在 TUN 启停时发生，读随每次 DNS 上游拨号。
static SKIPPED_DNS_SERVERS: RwLock<Vec<IpAddr>> = RwLock::new(Vec::new());

/// 进程级声明 skip 的 DNS 服务器列表（Go `SkipDNSServers`，dns_skip.go:15-21）。
///
/// 整体替换现有列表；空切片 = 清除（Go `SkipDNSServers(nil)` 同义）。IPv4-mapped
/// IPv6 归一化为 IPv4（Go `Addr.Unmap`，dns_skip.go:17-19），使 `::ffff:203.0.113.53`
/// 与 `203.0.113.53` 视为同一服务器。
pub fn skip_dns_servers(servers: &[IpAddr]) {
    *SKIPPED_DNS_SERVERS.write() = servers.iter().map(|ip| unmap(*ip)).collect();
}

/// 拨号目标是否在 skip 集合（Go `IsSkippedDNSServer`，dns_skip.go:25-31）。
///
/// Go 侧 `host:port` 字符串解析（`netip.ParseAddrPort`）由 Rust 类型系统替代：
/// 调用方直接持 [`SocketAddr`]，解析失败分支不存在。
#[must_use]
pub fn is_skipped_dns_server(addr: SocketAddr) -> bool {
    let ip = unmap(addr.ip());
    SKIPPED_DNS_SERVERS.read().contains(&ip)
}

/// Go `netip.Addr.Unmap`（dns_skip.go:17-19）：IPv4-mapped IPv6 归一化为 IPv4。
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

tokio::task_local! {
    /// 当前 task 为 Xray 自身发起的 DNS 上游查询。消费点据此把 skip 拒拨限定在
    /// DNS 模块自身的查询拨号，不影响用户流量拨向 DNS 服务器的正常代理连接。
    static DNS_UPSTREAM_QUERY: ();
}

/// 标记当前 task 为 DNS 上游查询并在标记内执行 `f`（设置点包装，`DIAL_SRC` 同款
/// task-local scope 形态）。标记随 future 走：`tokio::spawn` 一个已被 scope 包装的
/// future，新 task 内 poll 时标记依然可见；未被包装的 future 永远无标记。
pub async fn scope_dns_upstream_query<F: Future>(f: F) -> F::Output {
    DNS_UPSTREAM_QUERY.scope((), f).await
}

/// 当前 task 是否处于 DNS 上游查询标记内。
#[must_use]
pub fn is_dns_upstream_query() -> bool {
    DNS_UPSTREAM_QUERY.try_with(|()| ()).is_ok()
}

/// 拨号点消费判定：当前 task 是 Xray 自身的 DNS 上游查询、且目标在进程级 skip
/// 集合 → 应拒拨。对应 Go `features/dns/localdns/client.go:99-103` 的拒拨语义
/// （错误消息同样含 "skipped DNS server" 字样，便于与 Go 日志对齐排查）。
#[must_use]
pub fn is_skipped_dns_query(addr: SocketAddr) -> bool {
    is_dns_upstream_query() && is_skipped_dns_server(addr)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        },
    };

    use super::*;

    /// 进程级 skip 集合是全局态：涉集合的测试必须持锁串行（DIALER_SLOT_LOCK
    /// 同款先例），否则 cargo test 并行线程互踩（全量跑实测竞态挂）。
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    /// Go dns_skip_test.go:10-26 直译：v4-mapped 归一化、v6 精确匹配、未列地址
    /// 不命中、清除（`SkipDNSServers(nil)` 等价）后不命中。
    #[test]
    fn skip_set_query_and_clear_roundtrip() {
        let _g = TEST_LOCK.lock();
        skip_dns_servers(&[
            // ::ffff:203.0.113.53（v4-mapped 声明，Go 测试样例 dns_skip_test.go:11）
            IpAddr::V6("::ffff:203.0.113.53".parse().unwrap()),
            IpAddr::V6("2001:db8::53".parse().unwrap()),
        ]);

        // v4-mapped 声明 ↔ 纯 v4 目标命中（Unmap 归一化）。
        assert!(is_skipped_dns_server(addr(v4([203, 0, 113, 53]), 53)));
        // 纯 v6 声明 ↔ v6 目标命中。
        assert!(is_skipped_dns_server(addr(IpAddr::V6("2001:db8::53".parse().unwrap()), 53)));
        // 未列地址不命中（Go 测试样例 dns_skip_test.go:16-17）。
        assert!(!is_skipped_dns_server(addr(v4([192, 0, 2, 1]), 53)));
        assert!(!is_skipped_dns_server(addr(IpAddr::V6("2001:db8::54".parse().unwrap()), 53)));

        // 端口不参与匹配（Go ParseAddrPort 后只取 Addr 判定，dns_skip.go:29-30）。
        assert!(is_skipped_dns_server(addr(v4([203, 0, 113, 53]), 5353)));

        // 空切片清除（Go SkipDNSServers(nil)，dns_skip_test.go:23-26）。
        skip_dns_servers(&[]);
        assert!(!is_skipped_dns_server(addr(v4([203, 0, 113, 53]), 53)));
    }

    /// 合成判定三态：有集合无标记不命中（用户流量不受影响）；有标记无集合不命中
    /// （未设置时零影响）；两者齐备才命中。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局集合锁刻意跨 await 串行化（无争用场景）
    async fn composed_query_requires_scope_and_set() {
        let _g = TEST_LOCK.lock();
        let target = addr(v4([203, 0, 113, 53]), 53);

        // 无标记 + 无集合。
        assert!(!is_skipped_dns_query(target));

        // 有集合 + 无标记 → 不命中（用户流量拨 DNS 服务器不受影响）。
        skip_dns_servers(&[target.ip()]);
        assert!(!is_skipped_dns_query(target));

        // 有标记 + 有集合 → 命中。
        let hit = scope_dns_upstream_query(async { is_skipped_dns_query(target) }).await;
        assert!(hit);

        // 有标记 + 空集合 → 不命中（默认零影响）。
        skip_dns_servers(&[]);
        let miss = scope_dns_upstream_query(async { is_skipped_dns_query(target) }).await;
        assert!(!miss);
    }

    /// task-local 隔离：scope 内外、嵌套 scope、并发 task 互不串味。
    #[tokio::test]
    async fn task_local_scope_isolation() {
        // scope 内 true / scope 外 false。
        let inside = scope_dns_upstream_query(async { is_dns_upstream_query() }).await;
        assert!(inside);
        assert!(!is_dns_upstream_query());

        // 嵌套 scope：内层 poll 期间标记可见，退出后外层 task 本身无残留标记。
        scope_dns_upstream_query(async {
            assert!(is_dns_upstream_query());
            let nested = scope_dns_upstream_query(async { is_dns_upstream_query() }).await;
            assert!(nested);
        })
        .await;
        assert!(!is_dns_upstream_query());

        // 并发 task 不串味：带标与不带标两个 task 并行，各自判定互不影响。
        let observed = Arc::new(AtomicU8::new(0));
        let o1 = Arc::clone(&observed);
        let marked = tokio::spawn(scope_dns_upstream_query(async move {
            let marked = is_dns_upstream_query();
            o1.store(u8::from(marked), Ordering::SeqCst);
        }));
        let o2 = Arc::clone(&observed);
        let plain = tokio::spawn(async move {
            assert!(!is_dns_upstream_query());
            o2.fetch_or(2, Ordering::SeqCst);
        });
        let (r1, r2) = tokio::join!(marked, plain);
        r1.unwrap();
        r2.unwrap();
        assert_eq!(
            observed.load(Ordering::SeqCst),
            3,
            "标记随 future 跨 task 可见，裸 task 不受污染"
        );
    }
}
