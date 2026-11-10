//! 本机网络接口枚举
//!
//! 对应 Go 版本 `net.InterfaceAddrs` / `net.Interfaces` / `net.InterfaceByName`
//! （`common/net/system.go:35,100,102` 别名转发至标准库；仓内调用点
//! `common/net/net.go` `IsLocal` 按 `*net.IPNet` 的 ip+掩码匹配本机地址）。
//!
//! 底层数据来自 `if-addrs` crate（POSIX getifaddrs / Windows GetAdaptersAddresses）。
//! 数据源不提供的信息（MTU、MAC、Broadcast/Multicast 标志）以哨兵值呈现：
//! [`Interface::mtu`] 恒 `0`、[`Interface::hardware_addr`] 恒 `None`、
//! `InterfaceFlags` 的 `BROADCAST` / `MULTICAST` 恒不置位；
//! 接线方（TUN 自动路由/系统 DNS）若需真实值须另扩数据源，不得消费哨兵值。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::RwLock,
    time::{Duration, Instant},
};

use if_addrs::{IfAddr, get_if_addrs};
use skeleton::clock::{Clock, SystemClock};

/// 接口单播地址（ip + 掩码），对应 Go `*net.IPNet`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceAddr {
    /// IPv4 地址。
    V4(InterfaceAddrV4),
    /// IPv6 地址。
    V6(InterfaceAddrV6),
}

/// IPv4 接口地址明细。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV4 {
    /// IP 地址。
    pub ip: Ipv4Addr,
    /// 网络掩码。
    pub netmask: Ipv4Addr,
    /// 掩码前缀长度（CIDR）。
    pub prefixlen: u8,
    /// 广播地址，接口无广播能力时为 `None`。
    pub broadcast: Option<Ipv4Addr>,
}

/// IPv6 接口地址明细。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV6 {
    /// IP 地址。
    pub ip: Ipv6Addr,
    /// 网络掩码。
    pub netmask: Ipv6Addr,
    /// 掩码前缀长度（CIDR）。
    pub prefixlen: u8,
    /// 广播地址，接口无广播能力时为 `None`。
    pub broadcast: Option<Ipv6Addr>,
}

impl InterfaceAddr {
    /// 获取 IP 地址。
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::V4(a) => IpAddr::V4(a.ip),
            Self::V6(a) => IpAddr::V6(a.ip),
        }
    }

    /// 是否为回环地址（127.0.0.0/8 或 ::1）。
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        match self {
            Self::V4(a) => a.ip.is_loopback(),
            Self::V6(a) => a.ip.is_loopback(),
        }
    }

    /// 是否为链路本地地址（169.254.0.0/16 或 fe80::/10）。
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        match self {
            Self::V4(a) => a.ip.is_link_local(),
            Self::V6(a) => a.ip.is_unicast_link_local(),
        }
    }
}

/// 接口标志，位定义对齐 Go `net.Flags`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InterfaceFlags(u16);

impl InterfaceFlags {
    /// 回环接口（对应 Go `FlagLoopback`，来自回环地址判定）。
    pub const LOOPBACK: Self = Self(1 << 2);
    /// 点对点接口（对应 Go `FlagPointToPoint`）。
    pub const POINT_TO_POINT: Self = Self(1 << 3);
    /// 接口在运行（对应 Go `FlagUp`，来自 oper_status=Up）。
    pub const UP: Self = Self(1 << 0);

    /// 全零标志集。
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 原始位值（位定义同 Go `net.Flags`）。
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// 是否包含 `other` 的全部位。
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// 是否为全零。
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for InterfaceFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for InterfaceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// 本机网络接口，字段对齐 Go `net.Interface`。
///
/// 与 Go 的差异：Go `net.Interface` 不含地址列表（需另调 `Addrs()`），
/// 本结构直接聚合 [`Interface::addresses`] 便于 TUN 路由/DNS 接线一次取全。
/// `mtu` / `hardware_addr` 数据源不提供（见模块文档哨兵值说明）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    /// 接口索引，`0` 表示数据源未提供（Go 语义：有效索引从 1 起）。
    pub index: u32,
    /// 最大传输单元；`0` 表示数据源未提供（Go 有效 MTU 不可能为 0）。
    pub mtu: i32,
    /// 接口名，如 `"Ethernet"` / `"eth0"` / `"Loopback Pseudo-Interface 1"`。
    pub name: String,
    /// 硬件地址（MAC），`None` 表示数据源未提供。
    pub hardware_addr: Option<Vec<u8>>,
    /// 接口标志（见 [`InterfaceFlags`] 数据源限制）。
    pub flags: InterfaceFlags,
    /// 该接口的全部单播地址。
    pub addresses: Vec<InterfaceAddr>,
}

impl Interface {
    /// 是否在运行（对应 Go `Flags&FlagUp`）。
    #[must_use]
    pub const fn is_up(&self) -> bool {
        self.flags.contains(InterfaceFlags::UP)
    }

    /// 是否回环接口（对应 Go `Flags&FlagLoopback`）。
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.flags.contains(InterfaceFlags::LOOPBACK)
    }

    /// 是否点对点接口（对应 Go `Flags&FlagPointToPoint`）。
    #[must_use]
    pub const fn is_point_to_point(&self) -> bool {
        self.flags.contains(InterfaceFlags::POINT_TO_POINT)
    }
}

/// 返回所有接口的全部单播地址，对应 Go `net.InterfaceAddrs`。
///
/// # Errors
/// 底层系统枚举（getifaddrs / GetAdaptersAddresses）失败时透传 `io::Error`。
pub fn interface_addrs() -> io::Result<Vec<InterfaceAddr>> {
    Ok(get_if_addrs()?.iter().map(|raw| convert_addr(&raw.addr)).collect())
}

/// 判断 IP 是否为本机接口地址，对应 Go `common/net/net.go` `IsLocal`。
///
/// Go 语义：遍历 `net.InterfaceAddrs()`，与每个 `*net.IPNet` 的 **IP 精确相等** 即判为
/// 本机（比的是 `ipnet.IP.Equal(ip)`，非「落在该网段内」的包含判定）。
/// 枚举失败 → `false`（Go 返回 error，调用方 `FindProcess` 即失败 → 进程不匹配）。
///
/// 缓存（Go `localIPCache` 等价，bd psbp1-A2）：枚举结果按 **1 分钟 TTL** 进程级缓存
/// （`net.go:24-52`：`atomic.Pointer` + `time.Since(lastUpdate) > time.Minute` 才重枚举）；
/// **枚举成功才写缓存**，失败不落盘 ⇒ 下次调用仍重试。消费面 = `xray-app-router`
/// 进程反查的 TCP/UDP 共同前置门——配了 `process` 路由规则时每连接的决策不再逐次
/// `getifaddrs`（Go 同款：每分钟至多一次枚举）。
#[must_use]
pub fn is_local_ip(ip: IpAddr) -> bool {
    // 取时走 `skeleton::clock` 端口（同 `protocol/time.rs` / `log` 的自由函数形态，
    // 禁裸 `Instant::now`）；枚举函数为内部实现细节，公开 API 与判定语义不变。
    is_local_ip_with(&LOCAL_IP_CACHE, ip, || SystemClock.now_instant(), interface_ips)
}

/// 枚举全部接口的单播地址（仅 IP 平铺；Go `IsLocal` 消费的正是 `ipnet.IP`）。
fn interface_ips() -> io::Result<Vec<IpAddr>> {
    Ok(get_if_addrs()?.iter().map(|raw| raw.addr.ip()).collect())
}

/// Go `localIPCacheEntry`（`common/net/net.go:19-23`）等价物：上次枚举的本机接口
/// 地址集 + 采集时刻（单调钟 `Instant`，只做相对比较，不受墙钟回拨影响）。
struct LocalIpCacheEntry {
    refreshed_at: Instant,
    ips: Vec<IpAddr>,
}

/// 缓存 TTL：对齐 Go `localIPCache` 的 1 分钟（`net.go:31`
/// `time.Since(entry.lastUpdate) > time.Minute` 才重枚举）。
const LOCAL_IP_TTL: Duration = Duration::from_secs(60);

/// 进程级缓存（Go `localIPCache` 的 `atomic.Pointer` 在本仓的 RwLock 等价形态）。
static LOCAL_IP_CACHE: RwLock<Option<LocalIpCacheEntry>> = RwLock::new(None);

/// `is_local_ip` 的可注入内核（同文件测试用，公开 API 不变）：`cache` / `now` /
/// `enumerate` 全注入。语义对齐 Go `IsLocal`（`net.go:31-52`）：
/// 缓存新鲜（`now - refreshed_at <= LOCAL_IP_TTL`）⇒ 直接比对；过期/缺失 ⇒ 重枚举，
/// 且**枚举成功才写缓存**——Go 枚举失败即返回 error（缓存保持原样），本仓同口径
/// 返回 `false` 且不更新 `refreshed_at`（下次调用仍会重试，不复用过期数据）。
fn is_local_ip_with<N, E>(
    cache: &RwLock<Option<LocalIpCacheEntry>>,
    ip: IpAddr,
    now: N,
    enumerate: E,
) -> bool
where
    N: Fn() -> Instant,
    E: Fn() -> io::Result<Vec<IpAddr>>,
{
    let is_fresh = |entry: &LocalIpCacheEntry| {
        now().saturating_duration_since(entry.refreshed_at) <= LOCAL_IP_TTL
    };
    let matches_ip = |entry: &LocalIpCacheEntry| entry.ips.contains(&ip);

    // 快路径：新鲜缓存 ⇒ 只读锁内判定（Go `localIPCache.Load()`）。
    let guard = cache.read().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = guard.as_ref() {
        if is_fresh(entry) {
            return matches_ip(entry);
        }
    }
    drop(guard);

    // 慢路径：过期/缺失 ⇒ 写锁内二次核对（并发下另一线程可能已刷新），仍过期才枚举。
    // 枚举期间持有写锁：并发调用串行收敛到单次 getifaddrs（每 TTL 至多一次），
    // 无锁内重入。锁毒化（持有线程 panic）⇒ 取余留数据继续，不让观测面永久卡死。
    let mut guard = cache.write().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = guard.as_ref() {
        if is_fresh(entry) {
            return matches_ip(entry);
        }
    }
    match enumerate() {
        Ok(ips) => {
            let hit = ips.contains(&ip);
            *guard = Some(LocalIpCacheEntry { refreshed_at: now(), ips });
            hit
        },
        Err(_) => false,
    }
}

/// 返回所有网络接口，对应 Go `net.Interfaces`（按名字+索引聚合多地址接口）。
///
/// # Errors
/// 底层系统枚举失败时透传 `io::Error`。
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut out: Vec<Interface> = Vec::new();
    for raw in get_if_addrs()? {
        let index = raw.index.unwrap_or(0);
        let addr = convert_addr(&raw.addr);
        let flags = flags_of(&raw);
        if let Some(existing) = out.iter_mut().find(|i| i.name == raw.name && i.index == index) {
            existing.addresses.push(addr);
            existing.flags |= flags;
        } else {
            out.push(Interface {
                index,
                mtu: 0,
                name: raw.name,
                hardware_addr: None,
                flags,
                addresses: vec![addr],
            });
        }
    }
    Ok(out)
}

/// 按名字查找接口，对应 Go `net.InterfaceByName`。
///
/// # Errors
/// 找不到时返回 `io::ErrorKind::NotFound`（对应 Go `errNoSuchInterface`，
/// 错误消息附接口名便于定位；非静默）。
pub fn interface_by_name(name: &str) -> io::Result<Interface> {
    interfaces()?.into_iter().find(|i| i.name == name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("route ip+net: no such network interface: {name}"),
        )
    })
}

fn convert_addr(addr: &IfAddr) -> InterfaceAddr {
    match addr {
        IfAddr::V4(v4) => InterfaceAddr::V4(InterfaceAddrV4 {
            ip: v4.ip,
            netmask: v4.netmask,
            prefixlen: v4.prefixlen,
            broadcast: v4.broadcast,
        }),
        IfAddr::V6(v6) => InterfaceAddr::V6(InterfaceAddrV6 {
            ip: v6.ip,
            netmask: v6.netmask,
            prefixlen: v6.prefixlen,
            broadcast: v6.broadcast,
        }),
    }
}

fn flags_of(raw: &if_addrs::Interface) -> InterfaceFlags {
    let mut flags = InterfaceFlags::empty();
    if raw.is_oper_up() {
        flags |= InterfaceFlags::UP;
    }
    if raw.is_loopback() {
        flags |= InterfaceFlags::LOOPBACK;
    }
    if raw.is_p2p() {
        flags |= InterfaceFlags::POINT_TO_POINT;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 单测 1：接口枚举非空且存在回环接口（Windows "Loopback..."，POSIX "lo..."）。
    #[test]
    fn interfaces_non_empty_and_has_loopback() {
        let ifs = interfaces().expect("interface enumeration should not fail");
        assert!(!ifs.is_empty(), "at least one interface expected");
        let loopback = ifs
            .iter()
            .find(|i| i.name.contains("Loopback") || i.name.starts_with("lo"))
            .or_else(|| ifs.iter().find(|i| i.is_loopback()))
            .expect("loopback interface expected on this host");
        assert!(!loopback.name.is_empty());
    }

    /// 单测 2：地址枚举非空且同时含 IPv4 与 IPv6（CI 无 IPv6 时允许跳过）。
    #[test]
    fn interface_addrs_has_ipv4_and_ipv6() {
        let addrs = interface_addrs().expect("address enumeration should not fail");
        assert!(!addrs.is_empty(), "at least one address expected");
        let has_v4 = addrs.iter().any(|a| matches!(a, InterfaceAddr::V4(_)));
        let has_v6 = addrs.iter().any(|a| matches!(a, InterfaceAddr::V6(_)));
        assert!(has_v4, "at least one IPv4 address expected");
        // CI 沙箱可能无 IPv6 栈：无 v6 时显式跳过并打印，不静默通过。
        if !has_v6 {
            #[allow(clippy::print_stderr)] // skip 必须在输出可见原因
            {
                eprintln!("SKIP: no IPv6 address on this host (CI sandbox)");
            }
        }
    }

    /// 单测 3：按真实接口名查找成功且 index > 0。
    #[test]
    fn interface_by_name_real_succeeds_with_positive_index() {
        let ifs = interfaces().expect("interface enumeration should not fail");
        let want = &ifs[0].name;
        let found = interface_by_name(want).expect("real interface should be found");
        assert_eq!(found.name, want.as_str());
        assert!(found.index > 0, "index must be positive, got {}", found.index);
    }

    /// 单测 4：不存在的接口名返回 NotFound 错误（非 panic）。
    #[test]
    fn interface_by_name_missing_is_error_not_panic() {
        let err = interface_by_name("definitely-not-exist").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("definitely-not-exist"));
    }

    /// 端到端取证：打印全部接口与地址（`cargo test -p xray-common interface -- --nocapture`）。
    #[test]
    #[allow(clippy::print_stderr)] // 本测试就是打印取证（--nocapture 手检工具）
    fn dump_all_interfaces_for_manual_inspection() {
        let ifs = interfaces().expect("interface enumeration should not fail");
        assert!(!ifs.is_empty());
        for i in &ifs {
            let flags = format!(
                "{}{}{}",
                if i.is_up() { "U" } else { "-" },
                if i.is_loopback() { "L" } else { "-" },
                if i.is_point_to_point() { "P" } else { "-" },
            );
            eprintln!(
                "#{:<3} flags[{}] mtu[{}:not-provided] mac[{:?}] {:?}",
                i.index, flags, i.mtu, i.hardware_addr, i.name
            );
            for a in &i.addresses {
                match a {
                    InterfaceAddr::V4(v4) => {
                        eprintln!("    v4 {}/{} broadcast {:?}", v4.ip, v4.prefixlen, v4.broadcast)
                    },
                    InterfaceAddr::V6(v6) => {
                        eprintln!("    v6 {}/{} broadcast {:?}", v6.ip, v6.prefixlen, v6.broadcast)
                    },
                }
            }
        }
    }

    // ── is_local_ip 缓存（Go localIPCache TTL 等价，bd psbp1-A2）──
    // 全走注入内核 `is_local_ip_with`：假枚举计数 + 冻结/可推进时钟，不依赖真实网卡。

    /// TTL 内重复查询必须命中缓存：同一 IP 连续两次调用只枚举一次。
    #[test]
    fn is_local_ip_cache_hits_within_ttl() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache: RwLock<Option<LocalIpCacheEntry>> = RwLock::new(None);
        let enumerations = AtomicUsize::new(0);
        let enumerate = || {
            enumerations.fetch_add(1, Ordering::Relaxed);
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))])
        };
        // 时钟冻结在采集时刻 ⇒ 缓存永远新鲜。
        let base = SystemClock.now_instant();
        let now = || base;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

        assert!(is_local_ip_with(&cache, ip, now, enumerate), "缓存地址必须命中");
        assert!(is_local_ip_with(&cache, ip, now, enumerate), "第二次调用仍须命中");
        assert_eq!(
            enumerations.load(Ordering::Relaxed),
            1,
            "TTL 内重复查询必须命中缓存（只枚举一次）"
        );
    }

    /// TTL 过期必须重枚举：把「上次更新时间」推进到 >60s 后第三次调用重新枚举，
    /// 且新结果在新的 TTL 窗口内继续命中（不再枚举）。
    #[test]
    fn is_local_ip_cache_refreshes_after_ttl_expiry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache: RwLock<Option<LocalIpCacheEntry>> = RwLock::new(None);
        let enumerations = AtomicUsize::new(0);
        let enumerate = || {
            enumerations.fetch_add(1, Ordering::Relaxed);
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))])
        };
        let base = SystemClock.now_instant();
        // 可推进时钟：翻旗后时钟跳到 base + TTL + 1s（越过过期线，不 sleep）。
        let past_ttl = std::cell::Cell::new(false);
        let now = || {
            if past_ttl.get() {
                base + Duration::from_secs(LOCAL_IP_TTL.as_secs() + 1)
            } else {
                base
            }
        };
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

        assert!(is_local_ip_with(&cache, ip, now, enumerate), "冷启动必须枚举并命中");
        assert!(is_local_ip_with(&cache, ip, now, enumerate), "TTL 内第二次调用命中缓存");
        assert_eq!(enumerations.load(Ordering::Relaxed), 1, "TTL 内不得重枚举");

        past_ttl.set(true);
        assert!(is_local_ip_with(&cache, ip, now, enumerate), "过期后必须重枚举再命中");
        assert_eq!(enumerations.load(Ordering::Relaxed), 2, "越过 TTL 必须重新枚举");
    }

    /// 枚举失败不入缓存：失败 ⇒ `false` 且下次调用仍重试（Go `InterfaceAddrs()`
    /// 失败即返回 err、缓存不落盘的同口径）；恢复成功后才落缓存并停止重试。
    #[test]
    fn is_local_ip_enumeration_failure_is_not_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache: RwLock<Option<LocalIpCacheEntry>> = RwLock::new(None);
        let enumerations = AtomicUsize::new(0);
        let fail = std::cell::Cell::new(true);
        let enumerate = || {
            enumerations.fetch_add(1, Ordering::Relaxed);
            if fail.get() {
                Err(io::Error::other("getifaddrs 注入失败"))
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))])
            }
        };
        let base = SystemClock.now_instant();
        let now = || base;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

        assert!(!is_local_ip_with(&cache, ip, now, enumerate), "枚举失败 ⇒ false");
        assert!(!is_local_ip_with(&cache, ip, now, enumerate), "失败不落缓存 ⇒ 仍是 false");
        assert_eq!(enumerations.load(Ordering::Relaxed), 2, "失败不入缓存：每次调用都必须重新枚举");

        fail.set(false);
        assert!(is_local_ip_with(&cache, ip, now, enumerate), "恢复后枚举成功 ⇒ 命中");
        assert_eq!(enumerations.load(Ordering::Relaxed), 3);
    }

    /// 公开口冒烟（走真实进程级缓存静态）：loopback 必判本机，TEST-NET-3 必非本机。
    /// 判定语义（IP 精确相等）未因缓存改动。
    #[test]
    fn is_local_ip_global_cache_resolves_loopback() {
        assert!(is_local_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), "127.0.0.1 必为本机地址");
        assert!(
            !is_local_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            "TEST-NET-3 保留段必非本机地址"
        );
    }
}
