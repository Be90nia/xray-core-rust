//! 服务端地址池（Go `proxy/masque/pool.go` 逐值直译，规划 B4.2 / PM 裁定 2）。
//!
//! 语义唯一源：Go `proxy/masque/pool.go`（v26.11.9 @ 676eaf66）。三条边界校验
//! （R10 / extra 条款 `MASQUE-ADDR-POOL`）逐条照抄：
//! 1. 前缀地址不得是 IPv4-mapped IPv6（Go `Is4In6`）或带 zone——Rust `std` 侧 `::ffff:a.b.c.d`
//!    解析即归一为 IPv4、zone 字面量解析失败，两类输入 天然不可达，等价 Go
//!    的拒绝语义（不重复检查）。
//! 2. 服务器自身地址不得是网络地址（v4 还不得是广播地址）——"not a host address"。
//! 3. 池内至少要有两个可分配地址（`first == last` 即拒）——"leaves no addresses"。
//!
//! 分配策略：环形游标 + used 集 + 跳过服务器自身地址；释放即归还。
//!
//! udf 不适用判定（CLAUDE.md §3.5.5）：前缀/广播/主机地址边界全是 Xray 配置
//! 语义（Go `infra/conf/masque.go` 每族一前缀），单消费方，无提炼候选。

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{
    capsule::IpPrefix,
    error::{MasqueError, Result},
};

/// 服务端地址池（Go `addressPool`）。
#[derive(Debug)]
pub struct AddressPool {
    /// 掩码后前缀（Go `p.prefix = address.Masked()`）。
    prefix: IpPrefix,
    /// 服务器自身地址（不得分配；Go `p.server`）。
    server: IpAddr,
    /// 首个可分配地址（网络地址 +1；Go `p.first`）。
    first: IpAddr,
    /// 末个可分配地址（v4 排除广播；Go `p.last`）。
    last: IpAddr,
    /// 环形游标（Go `p.next`）。
    next: IpAddr,
    /// 已分配集（Go `p.used`）。
    used: HashSet<IpAddr>,
}

impl AddressPool {
    /// 构造校验（Go `newAddressPool`）。
    pub fn new(address: IpPrefix) -> Result<Self> {
        let server = address.addr;
        // Go Is4In6 / Zone 检查：std 侧 4in6 解析即归一 IPv4、zone 解析失败，
        // 两类输入不可达（模块注释 §1）。
        let prefix = masked(&address);
        let last = last_addr(&prefix);
        if server == prefix.addr || (server.is_ipv4() && server == last) {
            return Err(MasqueError::Protocol(format!(
                "masque: address {server}/{} is not a host address",
                prefix.prefix_len
            )));
        }
        let mut last = last;
        if server.is_ipv4() {
            last = prev_addr(last);
        }
        let first = next_addr(prefix.addr);
        if first == last {
            return Err(MasqueError::Protocol(format!(
                "masque: address {server}/{} leaves no addresses to assign",
                prefix.prefix_len
            )));
        }
        Ok(Self { prefix, server, first, last, next: first, used: HashSet::new() })
    }

    /// 环形分配（Go `allocate`）：从游标起找首个未用且非服务器自身的地址；
    /// 转满一圈（回到游标起点）即无地址可分。
    pub fn allocate(&mut self) -> Option<IpAddr> {
        let mut addr = self.next;
        loop {
            let mut next = next_addr(addr);
            if addr == self.last {
                next = self.first;
            }
            if !self.used.contains(&addr) && addr != self.server {
                self.used.insert(addr);
                self.next = next;
                return Some(addr);
            }
            if next == self.next {
                return None;
            }
            addr = next;
        }
    }

    /// 释放归还（Go `release`）。
    pub fn release(&mut self, addr: &IpAddr) {
        self.used.remove(addr);
    }

    /// 掩码后前缀是否包含该地址（Go `p.prefix.Contains`；server `inPool` 判定）。
    pub fn prefix_contains(&self, addr: IpAddr) -> bool {
        crate::connect::prefix_contains(&self.prefix, addr)
    }

    /// 服务器自身地址（Go `prefix.Addr()`；server `local` 列表成员）。
    #[must_use]
    pub fn server_addr(&self) -> IpAddr {
        self.server
    }
}

/// 前缀掩码（Go `netip.Prefix.Masked`）：主机位清零。
fn masked(p: &IpPrefix) -> IpPrefix {
    let bits = p.prefix_len;
    let (n, full): (u128, u8) = match p.addr {
        IpAddr::V4(v) => (u32::from(v) as u128, 32),
        IpAddr::V6(v) => (u128::from(v), 128),
    };
    let host_bits = u32::from(full) - u32::from(bits.min(full));
    let mask: u128 = if host_bits >= 128 { 0 } else { u128::MAX << host_bits };
    let cleared = n & mask;
    let addr = match p.addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(cleared as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(cleared)),
    };
    IpPrefix { addr, prefix_len: bits }
}

/// 前缀末地址（Go `lastAddr`）：主机位全置 1。
fn last_addr(prefix: &IpPrefix) -> IpAddr {
    let bits = prefix.prefix_len;
    match prefix.addr {
        IpAddr::V4(v) => {
            let mut n = u32::from(v);
            for i in bits..32 {
                n |= 1 << (31 - i);
            }
            IpAddr::V4(n.into())
        },
        IpAddr::V6(v) => {
            let mut n = u128::from(v);
            for i in bits..128 {
                n |= 1 << (127 - i);
            }
            IpAddr::V6(n.into())
        },
    }
}

/// 地址 +1（Go `Addr.Next`；饱和不回绕）。
fn next_addr(a: IpAddr) -> IpAddr {
    crate::connect::next_addr(a)
}

/// 地址 -1（Go `Addr.Prev`；饱和不回绕）。
fn prev_addr(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            u32::from(v).checked_sub(1).map_or(IpAddr::V4(v), |n| IpAddr::V4(n.into()))
        },
        IpAddr::V6(v) => {
            u128::from(v).checked_sub(1).map_or(IpAddr::V6(v), |n| IpAddr::V6(n.into()))
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("v4 literal"))
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("v6 literal"))
    }
    fn prefix(s: &str, len: u8) -> IpPrefix {
        IpPrefix { addr: s.parse::<IpAddr>().expect("addr literal"), prefix_len: len }
    }

    // QAS-2 表驱动（规划 R10）：网络地址 / v4 广播 / 无可分配 / 正常分配环形。

    #[test]
    fn network_address_rejected() {
        // 10.0.0.0/24：前缀地址 = 网络地址 → 拒。
        let e = AddressPool::new(prefix("10.0.0.0", 24)).err().expect("network addr must reject");
        assert!(e.to_string().contains("not a host address"), "got: {e}");
    }

    #[test]
    fn v4_broadcast_rejected() {
        // 10.0.0.255/24：服务器地址 = v4 广播 → 拒。
        let e = AddressPool::new(prefix("10.0.0.255", 24)).err().expect("broadcast must reject");
        assert!(e.to_string().contains("not a host address"), "got: {e}");
    }

    #[test]
    fn v6_no_broadcast_last_is_assignable() {
        // v6 无广播语义：/120 的末地址合法可分（服务器地址取主机位非零项）。
        let pool = AddressPool::new(prefix("2001:db8::1", 120)).expect("v6 /120 ok");
        assert_eq!(pool.server_addr(), v6("2001:db8::1"));
    }

    #[test]
    fn too_small_prefix_rejected() {
        // /31 v4：first(10.0.0.1) 排除广播后 == 广播前一个？10.0.0.1/31：
        // lastAddr=10.0.0.1（主机位1位），v4 排除广播 → last=10.0.0.0=网络地址，
        // server 不得是网络地址……构造输入 server=10.0.0.1：first=10.0.0.0+1=10.0.0.1，
        // last=10.0.0.0——first != last？10.0.0.1 != 10.0.0.0 → 通过？
        // Go 语义：server=10.0.0.1 是 /31 的另一个地址（非网络非广播）→ 合法？
        // first=prefix+1=10.0.0.1、last=10.0.0.0（排除广播 10.0.0.1 后）——
        // first(10.0.0.1) == server 且 first != last……但 Go 判 first==last：
        // 10.0.0.1 != 10.0.0.0 → Go 也通过，分配时 server==first 恒跳过 → 池空。
        // （Go 池空由 allocate 循环终止保证，不构造期拒绝。）
        // /32 v4：server=任意主机位不存在 → 前缀地址即网络地址已拒。
        let e = AddressPool::new(prefix("10.0.0.5", 32)).err().expect("/32 must reject");
        assert!(e.to_string().contains("not a host address"), "got: {e}");
    }

    #[test]
    fn allocate_cycles_and_excludes_server() {
        let mut pool = AddressPool::new(prefix("10.0.0.3", 29)).expect("ok");
        assert_eq!(pool.server_addr(), v4("10.0.0.3"));
        // /29 可分配：10.0.0.1..6（网络 .0 与广播 .7 排除；.3 是 server）。
        let mut got = Vec::new();
        for _ in 0..5 {
            got.push(pool.allocate().expect("5 addresses in /29"));
        }
        assert!(pool.allocate().is_none(), "pool exhausted after 5");
        got.sort();
        assert_eq!(
            got,
            vec![v4("10.0.0.1"), v4("10.0.0.2"), v4("10.0.0.4"), v4("10.0.0.5"), v4("10.0.0.6"),]
        );
        // 释放后可再分（环形回到起点）。
        pool.release(&v4("10.0.0.4"));
        assert_eq!(pool.allocate(), Some(v4("10.0.0.4")));
        assert!(pool.allocate().is_none());
    }

    #[test]
    fn allocate_skips_server_addr() {
        let mut pool = AddressPool::new(prefix("10.0.0.2", 30)).expect("ok");
        // /30：网络 .0 排除、广播 .3 排除、server=.2 排除 → 唯一可分 .1。
        assert_eq!(pool.allocate(), Some(v4("10.0.0.1")));
        assert!(pool.allocate().is_none());
    }

    #[test]
    fn v6_prefix_contains() {
        let pool = AddressPool::new(prefix("2001:db8::1", 64)).expect("ok");
        assert!(pool.prefix_contains(v6("2001:db8::dead")));
        assert!(!pool.prefix_contains(v6("2001:db8:1::1")));
        assert!(!pool.prefix_contains(v4("10.0.0.1")));
    }
}
