//! `autoSystemWfpBlockLeak` 的值文法与展开（平台无关）。
//!
//! 对应 Go `proxy/tun/wfp_leak.go`（`parseLeak` / `ExpandWfpBlockLeak` /
//! `BlocksSystemDNS`）与 `proxy/tun/tun_windows_wfp.go` 的 `newLeakFilters`（:214-241）。
//!
//! 值文法（输入先小写）：
//! - `dns` = `53` + `853`（DNS over TLS/QUIC）+ `windnsclient`；
//! - `windnsclient`：Windows 的 DNS Client 服务（Windows 11 / Server 2022 起可能走
//!   DoH/DoT，故不限协议与端口）；
//! - `misconfigtun`：某个 IP 版本没有路由指向 TUN 时，该版本全部出站；
//! - `all` / `allexceptlan`（后者额外紧跟 `dns` 的三条——局域网里的解析器，如路由器， 会把查询转发到
//!   TUN 之外）；
//! - `icmp`；
//! - `tcp` / `udp`，可带 `/<port>` 或 `/<low>-<high>`（1-65535、下界不大于上界）， 端口单独写 =
//!   同时指 TCP 与 UDP；`tcp/1-65535` 与 `tcp` 同义。
//!
//! 任一值前可加 CIDR 限定地址，IPv6 的 CIDR 加方括号（`1.1.1.0/24:53`、
//! `[::/0]:all`）。不可识别的值一律 `Err`（fail-visible：配置写错即拒启）。

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::spec::{contains, mask_v4, mask_v6};

/// 一个已按掩码归一的 CIDR。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// 网络地址（已按 `bits` 归一）。
    pub addr: IpAddr,
    /// 前缀长度。
    pub bits: u8,
}

impl Prefix {
    /// 是否 IPv6。
    #[must_use]
    pub fn is_ipv6(self) -> bool {
        self.addr.is_ipv6()
    }

    /// 是否包含 `addr`（同族才算）。
    #[must_use]
    pub fn contains(self, addr: IpAddr) -> bool {
        contains(&self.addr, self.bits, addr)
    }
}

/// 一个解析后的 `autoSystemWfpBlockLeak` 值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    /// 限定的地址（`None` = 两个 IP 版本的全部地址）。
    pub prefix: Option<Prefix>,
    /// 名字（`""` = 只给端口，TCP 和 UDP 都算；否则是 `tcp`/`udp`/`dns`/… 字面量）。
    pub name: String,
    /// 端口下界（`0` = 全部端口）。
    pub low: u16,
    /// 端口上界。
    pub high: u16,
}

impl fmt::Display for Leak {
    /// 规范化写法（Go `leak.String`）：`[<cidr>:]<name>[/<low>[-<high>]]`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = self.name.clone();
        if self.low != 0 {
            if !text.is_empty() {
                text.push('/');
            }
            text.push_str(&self.low.to_string());
            if self.high != self.low {
                text.push('-');
                text.push_str(&self.high.to_string());
            }
        }
        match self.prefix {
            None => f.write_str(&text),
            Some(p) if p.is_ipv6() => write!(f, "[{}/{}]:{text}", p.addr, p.bits),
            Some(p) => write!(f, "{}/{}:{text}", p.addr, p.bits),
        }
    }
}

impl Leak {
    /// 该值在某个 IP 版本上的前缀；只属于另一版本则 `None`（Go `leak.over`）。
    #[must_use]
    pub fn over(&self, ipv6: bool) -> Option<Prefix> {
        match self.prefix {
            Some(p) if p.is_ipv6() != ipv6 => None,
            Some(p) => Some(p),
            None => Some(all_addresses(ipv6)),
        }
    }

    /// 是否覆盖 `tcp`/`udp` 到 `port` 的连接（Go `leak.covers`）。
    fn covers(&self, tcp: bool, port: u16) -> bool {
        match self.name.as_str() {
            "all" => true,
            "tcp" if tcp => self.in_ports(port),
            "udp" if !tcp => self.in_ports(port),
            "" => self.in_ports(port),
            _ => false,
        }
    }

    /// 端口是否落在该值的端口范围内（`low == 0` = 全部端口）。
    fn in_ports(&self, port: u16) -> bool {
        self.low == 0 || (self.low <= port && port <= self.high)
    }

    /// 是否把系统的 DNS（TCP/UDP 53 或 DNS Client 服务）留在 TUN 内
    /// （Go `leak.blocksDNS`）。
    #[must_use]
    pub fn blocks_dns(&self) -> bool {
        self.name == "windnsclient" || self.covers(true, 53) || self.covers(false, 53)
    }
}

/// `dns` 展开成的三条（Go `dnsLeaks`）。
const DNS_LEAKS: [&str; 3] = ["53", "853", "windnsclient"];

/// `allexceptlan` 留给局域网的地址（Go `lanPrefixes`）：私有、链路本地、组播与广播，
/// 局域网上的发现协议要用到它们。
fn lan_prefixes() -> [Prefix; 9] {
    let v4 = |octets: [u8; 4], bits| Prefix { addr: IpAddr::V4(Ipv4Addr::from(octets)), bits };
    let v6 = |octets: [u8; 16], bits| Prefix { addr: IpAddr::V6(Ipv6Addr::from(octets)), bits };
    [
        v4([10, 0, 0, 0], 8),
        v4([172, 16, 0, 0], 12),
        v4([192, 168, 0, 0], 16),
        v4([169, 254, 0, 0], 16),
        v4([224, 0, 0, 0], 4),
        v4([255, 255, 255, 255], 32),
        v6([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
        v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
        v6([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
    ]
}

/// 某个 IP 版本的全部地址（Go `allAddresses`）。
#[must_use]
pub fn all_addresses(ipv6: bool) -> Prefix {
    if ipv6 {
        Prefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), bits: 0 }
    } else {
        Prefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), bits: 0 }
    }
}

/// 落在任一给定前缀里的局域网前缀部分（Go `lanWithin`）。
#[must_use]
pub fn lan_within(prefixes: &[Prefix]) -> Vec<Prefix> {
    let mut parts: Vec<Prefix> = Vec::new();
    for lan in lan_prefixes() {
        for &prefix in prefixes {
            if !overlaps(prefix, lan) {
                continue;
            }
            // 两个前缀要么无交集，要么一族含另一族——取更具体的那个。
            let part = if prefix.bits > lan.bits { prefix } else { lan };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
    }
    parts
}

/// 两个前缀是否有交集（Go `netip.Prefix.Overlaps`）。
fn overlaps(a: Prefix, b: Prefix) -> bool {
    if a.is_ipv6() != b.is_ipv6() {
        return false;
    }
    let (small, large) = if a.bits <= b.bits { (a, b) } else { (b, a) };
    small.contains(large.addr)
}

/// 解析一个**已小写**的值；不可识别返回 `None`（Go `parseLeak`）。
#[must_use]
pub fn parse(value: &str) -> Option<Leak> {
    let mut leak = Leak { prefix: None, name: String::new(), low: 0, high: 0 };
    let mut rest = value;

    // 前缀化的写法：`<cidr>:<rest>`，IPv6 的 CIDR 带方括号（`[::/0]:all`）。
    let bracketed = value.starts_with('[');
    let cut = if bracketed { value[1..].split_once("]:") } else { value.split_once(':') };
    if let Some((cidr, after)) = cut {
        let (addr, bits) = cidr.split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        // IPv4-mapped IPv6 前缀匹配不到任何连接：Windows 把这类连接当 IPv4 检查。
        let mapped = matches!(addr, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some());
        if addr.is_ipv6() != bracketed || mapped {
            return None;
        }
        let bits = u8::try_from(decimal(bits)?).ok()?;
        leak.prefix = Some(Prefix { addr: masked(addr, bits)?, bits });
        rest = after;
    }

    let (name, ports) = match rest.split_once('/') {
        Some((name, ports)) => (name, Some(ports)),
        None => (rest, None),
    };
    let ports = match (name, ports) {
        // 只剩端口（如 `53`）：TCP 和 UDP 都指。
        ("", None) => return None,
        // 名字自带端口表的关键字不接受 `/<port>`。
        ("dns" | "windnsclient" | "misconfigtun" | "all" | "allexceptlan" | "icmp", None) => {
            leak.name = name.to_string();
            return Some(leak);
        },
        ("tcp" | "udp", None) => {
            leak.name = name.to_string();
            return Some(leak);
        },
        ("tcp" | "udp", Some(ports)) => {
            leak.name = name.to_string();
            ports
        },
        (_, Some(_)) => return None,
        // 端口单独写（如 `10-20`）。
        (ports, None) => ports,
    };

    let (low_text, high_text) = match ports.split_once('-') {
        Some((low, high)) => (low, Some(high)),
        None => (ports, None),
    };
    let low = decimal(low_text)?;
    if low == 0 {
        return None;
    }
    let high = match high_text {
        Some(text) => {
            let high = decimal(text)?;
            if high < low {
                return None;
            }
            high
        },
        None => low,
    };
    // `tcp/1-65535`（与 `tcp` 同义）不写端口；端口单独写时保留区间便于显示。
    if leak.name.is_empty() || low != 1 || high != 65535 {
        leak.low = low;
        leak.high = high;
    }
    Some(leak)
}

/// 校验并展开 `autoSystemWfpBlockLeak`（Go `ExpandWfpBlockLeak`）。
///
/// 返回小写、去重、保序的值：`dns` 换成它的三条，`allexceptlan` 后紧跟那三条，
/// CIDR 按掩码归一，`tcp/1-65535` 写作 `tcp`。
///
/// # Errors
///
/// 任一值不可识别即 `Err`，文案带**原值**（Go 同款），配置写错即拒启。
pub fn expand(values: &[String]) -> Result<Vec<String>, String> {
    let mut expanded: Vec<String> = Vec::new();
    for value in values {
        let leak = parse(&value.to_lowercase())
            .ok_or_else(|| format!("unknown autoSystemWfpBlockLeak value: {value}"))?;
        if leak.name != "dns" {
            push_unique(&mut expanded, &leak);
        }
        if leak.name == "dns" || leak.name == "allexceptlan" {
            for dns in DNS_LEAKS {
                let mut dns = parse(dns).expect("DNS_LEAKS 是合法的值文法");
                dns.prefix = leak.prefix;
                push_unique(&mut expanded, &dns);
            }
        }
    }
    Ok(expanded)
}

/// 按 `Display` 写法去重追加（Go `add`）。
fn push_unique(out: &mut Vec<String>, leak: &Leak) {
    let text = leak.to_string();
    if !out.contains(&text) {
        out.push(text);
    }
}

/// 展开后的值是否把系统的 DNS 留在 TUN 内（Go `BlocksSystemDNS`）。
#[must_use]
pub fn blocks_system_dns(leaks: &[String]) -> bool {
    leaks.iter().any(|value| parse(value).is_some_and(|leak| leak.blocks_dns()))
}

/// 把展开后的值变成实际要装的过滤器（Go `newLeakFilters`）。
///
/// `route4` / `route6` = 该 IP 版本是否有路由指向 TUN：`misconfigtun` 只对**没有**
/// 路由的版本生效（有路由的版本交给其它值）。
#[must_use]
pub fn new_leak_filters(leaks: &[String], route4: bool, route6: bool) -> Vec<Leak> {
    let mut block: Vec<Leak> = Vec::new();
    for value in leaks {
        let Some(mut leak) = parse(value) else { continue };
        if leak.name == "misconfigtun" {
            let mut unrouted4 = !route4;
            let mut unrouted6 = !route6;
            if let Some(prefix) = leak.prefix {
                unrouted4 &= !prefix.is_ipv6();
                unrouted6 &= prefix.is_ipv6();
            }
            if !unrouted4 && !unrouted6 {
                continue;
            }
            if leak.prefix.is_none() {
                // 只剩一个版本没有路由：把该值收窄到那个版本（另一个版本有路由，
                // 交给其它值）。
                if !unrouted4 {
                    leak.prefix = Some(all_addresses(true));
                } else if !unrouted6 {
                    leak.prefix = Some(all_addresses(false));
                }
            }
        }
        if !block.contains(&leak) {
            block.push(leak);
        }
    }
    block
}

/// 过滤器集合的规范化写法（Go `leakFilters.String`）：`, ` 分隔，空集合为空串。
#[must_use]
pub fn describe(block: &[Leak]) -> String {
    block.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// 十进制无符号数（Google `strconv.ParseUint(s, 10, 16)`）：只认 ASCII 数字，
/// 允许前导零，`+`/空格/十六进制一律不认。
fn decimal(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// 按前缀长度清零低位；长度越界返回 `None`。
fn masked(addr: IpAddr, bits: u8) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(v4) => {
            if bits > 32 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask_v4(bits))))
        },
        IpAddr::V6(v6) => {
            if bits > 128 {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask_v6(bits))))
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn values(list: &[&str]) -> Vec<String> {
        list.iter().map(|v| (*v).to_string()).collect()
    }

    fn expand_ok(list: &[&str]) -> Vec<String> {
        expand(&values(list)).expect("这些值是合法的")
    }

    fn prefix(cidr: &str) -> Prefix {
        let (addr, bits) = cidr.split_once('/').unwrap();
        Prefix { addr: addr.parse().unwrap(), bits: bits.parse().unwrap() }
    }

    /// Go `TestExpandWfpBlockLeak` 的展开表（值文法 + 去重保序 + dns 展开）。
    #[test]
    fn expand_table_matches_go() {
        let cases: [(&[&str], &[&str], bool); 30] = [
            (&[], &[], false),
            (&["dns"], &["53", "853", "windnsclient"], true),
            (&["DNS", "MisconfigTUN"], &["53", "853", "windnsclient", "misconfigtun"], true),
            (&["tcp/853", "dns", "TCP/0853"], &["tcp/853", "53", "853", "windnsclient"], true),
            (
                &["tcp/853", "udp/853", "misconfigtun"],
                &["tcp/853", "udp/853", "misconfigtun"],
                false,
            ),
            (&["udp/65535", "tcp/1"], &["udp/65535", "tcp/1"], false),
            (&["tcp/53"], &["tcp/53"], true),
            (&["windnsclient"], &["windnsclient"], true),
            (&["ALL"], &["all"], true),
            (&["tcp", "TCP", "UDP"], &["tcp", "udp"], true),
            (&["tcp/1-65535", "udp/1-65535"], &["tcp", "udp"], true),
            (&["udp/10-20", "udp/53-53", "tcp/50-60"], &["udp/10-20", "udp/53", "tcp/50-60"], true),
            (&["tcp/54-60", "udp/1-52"], &["tcp/54-60", "udp/1-52"], false),
            (&["ICMP", "icmp"], &["icmp"], false),
            (&["AllExceptLAN"], &["allexceptlan", "53", "853", "windnsclient"], true),
            (
                &["dns", "allexceptlan", "all"],
                &["53", "853", "windnsclient", "allexceptlan", "all"],
                true,
            ),
            // 端口单独写 = TCP + UDP。
            (&["53"], &["53"], true),
            (&["10-20", "0053", "853-853", "53"], &["10-20", "53", "853"], true),
            (&["54-60", "1-52", "65535"], &["54-60", "1-52", "65535"], false),
            (&["1-65535"], &["1-65535"], true),
            (&["853", "tcp/853"], &["853", "tcp/853"], false),
            // CIDR 限定地址。
            (&["1.1.1.0/24:53"], &["1.1.1.0/24:53"], true),
            (
                &["1.1.1.1/24:TCP/853", "[2001:DB8::1/32]:udp/10-20", "[::/0]:ICMP"],
                &["1.1.1.0/24:tcp/853", "[2001:db8::/32]:udp/10-20", "[::/0]:icmp"],
                false,
            ),
            (
                &["0.0.0.0/0:dns"],
                &["0.0.0.0/0:53", "0.0.0.0/0:853", "0.0.0.0/0:windnsclient"],
                true,
            ),
            (&["[::/0]:all"], &["[::/0]:all"], true),
            (&["10.0.0.1/32:windnsclient"], &["10.0.0.1/32:windnsclient"], true),
            (&["[2000::/3]:misconfigtun"], &["[2000::/3]:misconfigtun"], false),
            (
                &["1.1.1.0/24:tcp/1-65535", "1.1.1.0/24:udp/53-53"],
                &["1.1.1.0/24:tcp", "1.1.1.0/24:udp/53"],
                true,
            ),
            (&["1.1.1.0/24:20-30", "[::/0]:10-10"], &["1.1.1.0/24:20-30", "[::/0]:10"], false),
            (
                &["0.0.0.0/0:allexceptlan", "[::/0]:all"],
                &[
                    "0.0.0.0/0:allexceptlan",
                    "0.0.0.0/0:53",
                    "0.0.0.0/0:853",
                    "0.0.0.0/0:windnsclient",
                    "[::/0]:all",
                ],
                true,
            ),
        ];
        for (input, want, want_dns) in cases {
            let got = expand_ok(input);
            assert_eq!(got, want, "{input:?}");
            assert_eq!(blocks_system_dns(&got), want_dns, "{input:?}: BlocksSystemDNS");
        }
        // 表尾两条（重复 CIDR/端口写法归一）单独断言，避免数组长度写死。
        assert_eq!(
            expand_ok(&[
                "1.1.1.1/32:53",
                "1.1.1.1/32:0053",
                "1.1.1.1/24:53",
                "1.1.1.0/24:53",
                "53"
            ]),
            values(&["1.1.1.1/32:53", "1.1.1.0/24:53", "53"])
        );
        assert_eq!(
            expand_ok(&["1.2.3.4/0:icmp", "[::1/0]:icmp", "icmp"]),
            values(&["0.0.0.0/0:icmp", "[::/0]:icmp", "icmp"])
        );
    }

    /// Go `TestExpandWfpBlockLeak` 的非法值表：一个都不许放过（含越界、符号、
    /// 空白、非十进制、CIDR 写法错误、IPv4-mapped IPv6）。
    #[test]
    fn expand_rejects_invalid_values() {
        let invalid = [
            "",
            "ip",
            "tcp/",
            "udp/65536",
            "tcp/-1",
            "tcp/+53",
            "tcp/53/1",
            "udp/abc",
            "icmp/0",
            "icmp/8",
            "tcp:53",
            " dns",
            "tcp/0-10",
            "tcp/20-10",
            "tcp/5-",
            "tcp/-5",
            "tcp/1-2-3",
            "tcp/1-65536",
            "udp/ 53",
            "all/0",
            "dns/53",
            "windnsclient/53",
            "tcp/0",
            "udp/0",
            "tcp/00",
            "udp/0-0",
            "udp/65535-1", // 端口单独写
            "0",
            "00",
            "65536",
            "0-10",
            "20-10",
            "5-",
            "-5",
            "-",
            "1-2-3",
            "1-65536",
            "+53",
            " 53",
            "53 ",
            "53/1",
            "53/tcp",
            "0x35", // IP 版本现在是 CIDR
            "ipv4",
            "ipv6",
            "ipv4:udp",
            "ipv6:all",
            "ipv4:dns",
            "tcpv4",
            "udpv6",
            "icmpv4",
            "tcp4",
            "dnsv4", // CIDR：IPv6 要方括号，单地址与裸 CIDR 都不认
            "1.1.1.0/24",
            "[2001:db8::/32]",
            "1.1.1.0/24:",
            "[::/0]:",
            ":udp",
            "[]:udp",
            "[:udp",
            "[::/0]udp",
            "1.1.1.1:53",
            "[::1]:53",
            "[2001:db8::1]:tcp/53",
            "2001:db8::/32:53",
            "::/0:all",
            "[1.1.1.0/24]:53",
            "[2001:db8::]/32:53",
            "1.1.1.0/33:53",
            "[::/129]:53",
            "1.1.1.0/24:1.1.1.0/24:53",
            "[::/0]:[::/0]:53",
            "1.1.1.0/24 :53",
            "1.1.1.0/24: 53",
            " 1.1.1.0/24:53",
            "1.1.1.0/24::53",
            "[fe80::%1/64]:53",
            "geoip:cn:53",
            "1.1.1.0/24:udp/0",
            "[::/0]:icmp/8",
            "1.1.1.0/24:dns/53",
            "[::/0]:20-10",
            "1.1.1.0/24:ipv4:53",
            "1.1.1.0/24:geoip",
            "[::ffff:1.1.1.0/120]:53",
            "[::ffff:0:0/96]:all",
        ];
        for value in invalid {
            assert!(expand(&values(&[value])).is_err(), "{value:?} 必须被拒");
            assert!(
                expand(&values(&[value]))
                    .unwrap_err()
                    .contains(&format!("unknown autoSystemWfpBlockLeak value: {value}")),
                "{value:?}: 错误文案要带原值"
            );
        }
    }

    /// Go `TestLeakCovers`：`covers` 决定 DNS 是否留在 TUN 内。
    #[test]
    fn covers_table_matches_go() {
        let cases: [(&str, bool, u16, bool); 21] = [
            ("tcp", true, 1, true),
            ("tcp", false, 53, false),
            ("udp/53", false, 53, true),
            ("udp/53", false, 54, false),
            ("tcp/10-20", true, 10, true),
            ("tcp/10-20", true, 20, true),
            ("tcp/10-20", true, 21, false),
            ("tcp/10-20", true, 9, false),
            ("53", false, 53, true),
            ("53", true, 53, true),
            ("10-20", true, 15, true),
            ("10-20", false, 21, false),
            ("1.1.1.0/24:udp/53", false, 53, true),
            ("[::/0]:tcp", true, 443, true),
            ("[2001:db8::/32]:53", true, 53, true),
            ("0.0.0.0/0:icmp", false, 53, false),
            ("all", false, 53, true),
            ("1.1.1.1/32:all", true, 1, true),
            ("allexceptlan", false, 53, false),
            ("misconfigtun", false, 53, false),
            ("windnsclient", false, 53, false),
        ];
        for (value, tcp, port, want) in cases {
            let leak = parse(value).unwrap_or_else(|| panic!("{value} 必须能解析"));
            assert_eq!(leak.covers(tcp, port), want, "{value} covers tcp={tcp} {port}");
        }
    }

    /// Go `TestNewLeakFilters`：`misconfigtun` 只对没有路由的版本生效。
    #[test]
    fn new_leak_filters_table_matches_go() {
        let cases: [(&[&str], bool, bool, &str, bool); 20] = [
            (
                &["dns", "misconfigtun"],
                true,
                false,
                "53, 853, windnsclient, [::/0]:misconfigtun",
                true,
            ),
            (&["tcp/853", "udp/853", "misconfigtun"], true, true, "tcp/853, udp/853", false),
            (&["all"], true, true, "all", true),
            (&["all", "misconfigtun"], true, true, "all", true),
            (&["misconfigtun"], true, false, "[::/0]:misconfigtun", false),
            (&["misconfigtun"], false, true, "0.0.0.0/0:misconfigtun", false),
            (&["misconfigtun"], false, false, "misconfigtun", false),
            (&["tcp/10-20", "udp", "icmp"], true, true, "tcp/10-20, udp, icmp", true),
            (&["tcp/54-60", "icmp", "54-60"], true, true, "tcp/54-60, icmp, 54-60", false),
            (&["allexceptlan"], true, true, "allexceptlan, 53, 853, windnsclient", true),
            (
                &["allexceptlan", "all"],
                true,
                true,
                "allexceptlan, 53, 853, windnsclient, all",
                true,
            ),
            (
                &["misconfigtun", "allexceptlan"],
                true,
                false,
                "[::/0]:misconfigtun, allexceptlan, 53, 853, windnsclient",
                true,
            ),
            (
                &["0.0.0.0/0:TCP/10-20", "[::/0]:udp", "0.0.0.0/0:icmp"],
                true,
                true,
                "0.0.0.0/0:tcp/10-20, [::/0]:udp, 0.0.0.0/0:icmp",
                true,
            ),
            (
                &["[::/0]:tcp/54-60", "[::/0]:icmp"],
                true,
                true,
                "[::/0]:tcp/54-60, [::/0]:icmp",
                false,
            ),
            (&["0.0.0.0/0:windnsclient"], true, true, "0.0.0.0/0:windnsclient", true),
            (&["1.1.1.0/24:53"], true, true, "1.1.1.0/24:53", true),
            (&["[::/0]:all"], true, false, "[::/0]:all", true),
            (
                &["0.0.0.0/0:allexceptlan", "[::/0]:all"],
                true,
                true,
                "0.0.0.0/0:allexceptlan, 0.0.0.0/0:53, 0.0.0.0/0:853, 0.0.0.0/0:windnsclient, \
                 [::/0]:all",
                true,
            ),
            (&["0.0.0.0/0:misconfigtun"], true, false, "", false),
            (&["[::/0]:misconfigtun"], true, false, "[::/0]:misconfigtun", false),
        ];
        for (input, route4, route6, want, want_dns) in cases {
            let block = new_leak_filters(&expand_ok(input), route4, route6);
            assert_eq!(describe(&block), want, "{input:?} route4={route4} route6={route6}");
            assert_eq!(block.iter().any(Leak::blocks_dns), want_dns, "{input:?}: systemDNS");
        }
        // 表尾三条：CIDR 版 misconfigtun 的取舍。
        assert_eq!(
            describe(&new_leak_filters(
                &expand_ok(&["[2000::/3]:misconfigtun", "1.0.0.0/8:misconfigtun"]),
                true,
                false
            )),
            "[2000::/3]:misconfigtun"
        );
        assert_eq!(
            describe(&new_leak_filters(
                &expand_ok(&["misconfigtun", "[::/0]:misconfigtun"]),
                true,
                false
            )),
            "[::/0]:misconfigtun"
        );
        assert_eq!(
            describe(&new_leak_filters(
                &expand_ok(&["0.0.0.0/0:misconfigtun", "[::/0]:allexceptlan"]),
                false,
                true
            )),
            "0.0.0.0/0:misconfigtun, [::/0]:allexceptlan, [::/0]:53, [::/0]:853, \
             [::/0]:windnsclient"
        );
    }

    /// `allexceptlan` 自己（不带 dns 展开）不阻断系统 DNS：局域网里的解析器还通。
    #[test]
    fn allexceptlan_alone_keeps_local_resolver() {
        let block = [Leak { prefix: None, name: "allexceptlan".to_string(), low: 0, high: 0 }];
        assert!(!block[0].blocks_dns());
        assert!(!block.iter().any(Leak::blocks_dns));
    }

    /// Go `TestLanWithin`：局域网前缀的求交。
    #[test]
    fn lan_within_table_matches_go() {
        let cases: [(&[&str], &[&str]); 7] = [
            (&[], &[]),
            (
                &["0.0.0.0/0"],
                &[
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "255.255.255.255/32",
                ],
            ),
            (&["::/0"], &["fc00::/7", "fe80::/10", "ff00::/8"]),
            (&["1.0.0.0/8", "10.1.0.0/16"], &["10.1.0.0/16"]),
            (&["192.0.0.0/2"], &["192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32"]),
            (&["2000::/3", "fe80::/64", "fe80::/10"], &["fe80::/64", "fe80::/10"]),
            (&["8.8.8.8/32", "2001:db8::/32"], &[]),
        ];
        for (within, want) in cases {
            let within: Vec<Prefix> = within.iter().map(|c| prefix(c)).collect();
            let want: Vec<Prefix> = want.iter().map(|c| prefix(c)).collect();
            assert_eq!(lan_within(&within), want, "{within:?}");
        }
    }

    #[test]
    fn prefix_contains_and_masking() {
        let net = prefix("1.1.1.0/24");
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 200))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 2, 1))));
        // 跨族不算包含。
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // 未归一的地址在解析时被归一。
        assert_eq!(parse("1.1.1.99/24:53").unwrap().prefix, Some(net));
        // 0 长度前缀 = 全部地址。
        assert_eq!(parse("0.0.0.0/0:all").unwrap().prefix, Some(all_addresses(false)));
        assert_eq!(parse("[::/0]:all").unwrap().prefix, Some(all_addresses(true)));
    }
}
