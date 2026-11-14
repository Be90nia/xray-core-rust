//! WFP 泄漏阻断的**规格层**（平台无关）。
//!
//! 对应 Go `proxy/tun/tun_windows_wfp.go` 的 `addLeakFilters` 与
//! `dnsOutsideTUN`：把「装哪些过滤器、什么条件、什么动作、什么权重」表达成
//! 纯数据，本层不碰任何 Windows API，便于在任意平台单测。
//!
//! ## 语义（照抄 Go v26.11.9，勿自行发挥）
//!
//! 目的：把「本该走 TUN 却从别的网卡漏出去」的流量挡住。挡什么由
//! `autoSystemWfpBlockLeak` 的展开值决定（值文法与展开见 [`super::leak`]），
//! 每个值可以只作用于某个 CIDR 的地址。
//!
//! 无论挡什么，回环与 Windows 在本地链路上必需的流量（DHCP、IPv6 邻居/组播
//! 发现）都放行；经 TUN 的连接也放行。
//!
//! 过滤器装在**动态 WFP 会话**里：关掉 engine 即删除，进程退出 Windows 也会删。

use std::net::IpAddr;

use super::leak::{Leak, Prefix, all_addresses, lan_within};

/// WFP 过滤层（对应 Go 的 `fwpmLayerALEAuth*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// 出站连接授权（IPv4）。
    AuthConnectV4,
    /// 入站连接接受授权（IPv4）。
    AuthRecvAcceptV4,
    /// 出站连接授权（IPv6）。
    AuthConnectV6,
    /// 入站连接接受授权（IPv6）。
    AuthRecvAcceptV6,
}

impl Layer {
    /// 该层是否出站（出站层带 `ClearActionRight` 硬许可）。
    #[must_use]
    pub fn is_outbound(self) -> bool {
        matches!(self, Self::AuthConnectV4 | Self::AuthConnectV6)
    }

    /// 该层是否 IPv4。
    #[must_use]
    pub fn is_ipv4(self) -> bool {
        matches!(self, Self::AuthConnectV4 | Self::AuthRecvAcceptV4)
    }
}

/// 条件字段（对应 Go 的 `fwpmCondition*` GUID 集合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// 应用 AppID（`FwpmGetAppIdFromFileName0` 取得）。
    AleAppId,
    /// 用户/服务 SID（DNS Client 服务用安全描述符匹配）。
    AleUserId,
    /// 远端端口。
    IpRemotePort,
    /// 本地端口。
    IpLocalPort,
    /// 本地接口 LUID。
    IpLocalInterface,
    /// 下一跳接口 LUID。
    IpNexthopInterface,
    /// 到达接口 LUID。
    IpArrivalInterface,
    /// IP 协议号。
    IpProtocol,
    /// 远端地址（地址 + 掩码）。
    IpRemoteAddress,
    /// 条件标志集合（如回环）。
    Flags,
}

/// 条件匹配方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// 等值。
    Equal,
    /// 标志全命中（`FWP_MATCH_FLAGS_ALL_SET`）。
    FlagsAllSet,
    /// 落在区间内（`FWP_MATCH_RANGE`，值为 [`Value::PortRange`]）。
    Range,
}

/// 条件值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// 字节串（AppID / 安全描述符）。
    Bytes(Vec<u8>),
    /// 8 位无符号。
    U8(u8),
    /// 16 位无符号。
    U16(u16),
    /// 32 位无符号。
    U32(u32),
    /// 64 位无符号（接口 LUID）。
    U64(u64),
    /// 16 字节地址。
    Addr16([u8; 16]),
    /// 16 位无符号的区间（`FWP_RANGE0`，配 `MatchType::Range`）。
    PortRange {
        /// 下界（含）。
        low: u16,
        /// 上界（含）。
        high: u16,
    },
    /// IPv4 地址 + 掩码（`FWP_V4_ADDR_AND_MASK`，网络字节序语义由 WFP 解释）。
    V4AddrMask {
        /// 网络地址。
        addr: u32,
        /// 掩码。
        mask: u32,
    },
    /// IPv6 地址 + 前缀长度（`FWP_V6_ADDR_AND_MASK`）。
    V6AddrMask {
        /// 网络地址。
        addr: [u8; 16],
        /// 前缀长度。
        prefix_length: u8,
    },
}

/// 单条过滤条件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// 字段。
    pub field: Field,
    /// 匹配方式。
    pub match_type: MatchType,
    /// 值。
    pub value: Value,
}

impl Condition {
    /// 等值条件。
    #[must_use]
    pub fn equal(field: Field, value: Value) -> Self {
        Self { field, match_type: MatchType::Equal, value }
    }

    /// 标志全命中条件。
    #[must_use]
    pub fn flags_all_set(field: Field, value: Value) -> Self {
        Self { field, match_type: MatchType::FlagsAllSet, value }
    }
}

/// 过滤动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 放行。
    Permit,
    /// 阻断。
    Block,
}

/// 一条过滤器的完整规格（对应 Go 的 `fwpmFilter0`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    /// 显示名（Go 形如 `"Xray TUN: block 53"`）。
    pub name: String,
    /// 所属层。
    pub layer: Layer,
    /// 过滤器标志（`FWP_FILTER_FLAG_CLEAR_ACTION_RIGHT` 等）。
    pub flags: u32,
    /// 动作。
    pub action: Action,
    /// 权重（子层内最重的匹配过滤器决定结果）。
    pub weight: u8,
    /// 条件集合（空 = 无条件匹配）。
    pub conditions: Vec<Condition>,
}

/// `FWP_FILTER_FLAG_CLEAR_ACTION_RIGHT`：放行时清掉动作权利，
/// 下层子层（含 Windows 防火墙规则）不再能推翻（Go 注释「heaviest matching
/// filter ... unless the permit is hard」）。
pub const FILTER_FLAG_CLEAR_ACTION_RIGHT: u32 = 0x0000_0008;

/// `FWP_CONDITION_FLAG_IS_LOOPBACK`。
pub const CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;

/// IP 协议号：ICMP。
pub const IPPROTO_ICMP: u8 = 1;
/// IP 协议号：TCP。
pub const IPPROTO_TCP: u8 = 6;
/// IP 协议号：UDP。
pub const IPPROTO_UDP: u8 = 17;
/// IP 协议号：ICMPv6。
pub const IPPROTO_ICMPV6: u8 = 58;

/// DNS 客户端服务 SID（Go `dnsClientSID`）：NT SERVICE\Dnscache。
pub const DNS_CLIENT_SID: &str = "S-1-5-80-859482183-879914841-863379149-1145462774-2388618682";

/// Windows 11 / Server 2022（build 20348）起 DNS Client 服务可能走 DoH/DoT。
pub const WINDOWS_DOH_DNS_BUILD: u32 = 20348;

// 过滤器权重（Go `weightAllExceptLAN` … `weightXray`，七档）：同一子层里最重的
// 匹配过滤器决定结果，所以「放行 Xray」压过一切，`allexceptlan` 的阻断压不过
// 局域网的放行。
const WEIGHT_ALL_EXCEPT_LAN: u8 = 0;
const WEIGHT_LAN: u8 = 1;
const WEIGHT_DNS_CLIENT: u8 = 2;
const WEIGHT_LOCAL_LINK: u8 = 3;
const WEIGHT_BLOCK: u8 = 4;
const WEIGHT_PERMIT: u8 = 5;
const WEIGHT_XRAY: u8 = 6;

/// 生成泄漏阻断过滤器集合所需的输入。
#[derive(Debug, Clone)]
pub struct LeakFilterInput {
    /// TUN 接口的 LUID（接口索引经 `ConvertInterfaceIndexToLuid` 得到）。
    pub tun_luid: u64,
    /// 本进程 AppID（`FwpmGetAppIdFromFileName0` 的输出）。
    pub app_id: Vec<u8>,
    /// 要挡在 TUN 之外的连接（[`super::leak::new_leak_filters`] 的输出）。
    pub block: Vec<Leak>,
    /// DNS Client 服务的匹配用安全描述符（SDDL 转换后的字节）。
    ///
    /// `None` = 不生成 DNS Client 服务那一族过滤器（`block` 里没有
    /// `windnsclient`，或该版本 Windows 只查 53 端口）。
    pub dns_client_sd: Option<Vec<u8>>,
}

/// 组装全部泄漏阻断过滤器（对应 Go `addLeakFilters`）。
///
/// 每个层先放行 Xray 自己，再放行回环/系统必需流量与「经 TUN」的连接，
/// 最后按 `block` 逐值阻断；`allexceptlan` 的局域网放行比其它值轻，
/// 所以局域网上的 DNS 仍然被挡。
#[must_use]
pub fn leak_filter_specs(input: &LeakFilterInput) -> Vec<FilterSpec> {
    let mut out = Vec::new();
    let tun = Value::U64(input.tun_luid);
    let self_cond = Condition::equal(Field::AleAppId, Value::Bytes(input.app_id.clone()));

    let loopback = Condition::flags_all_set(Field::Flags, Value::U32(CONDITION_FLAG_IS_LOOPBACK));
    // DHCP（客户端 68 → 服务器 67）：其它网卡的地址靠它，Xray 自己也要用。
    let dhcp = vec![
        Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_UDP)),
        Condition::equal(Field::IpLocalPort, Value::U16(68)),
        Condition::equal(Field::IpRemotePort, Value::U16(67)),
    ];
    // 邻居/组播监听发现：ICMPv6 130-137 与 143（类型/码占端口位）。
    let mut discovery = vec![Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_ICMPV6))];
    for typ in [130u16, 131, 132, 133, 134, 135, 136, 137, 143] {
        discovery.push(Condition::equal(Field::IpLocalPort, Value::U16(typ)));
    }
    discovery.push(Condition::equal(Field::IpRemotePort, Value::U16(0)));
    let dhcpv6 = vec![
        Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_UDP)),
        Condition::equal(Field::IpLocalPort, Value::U16(546)),
        Condition::equal(Field::IpRemotePort, Value::U16(547)),
    ];
    let dhcpv6_out = {
        let mut conditions = dhcpv6.clone();
        // DHCPv6 客户端发往服务器的组播地址。
        conditions.push(Condition::equal(
            Field::IpRemoteAddress,
            Value::Addr16(multicast_dhcpv6_server()),
        ));
        conditions
    };

    for layer in [
        Layer::AuthConnectV4,
        Layer::AuthRecvAcceptV4,
        Layer::AuthConnectV6,
        Layer::AuthRecvAcceptV6,
    ] {
        let ipv6 = !layer.is_ipv4();

        // 放行 Xray 自己的连接：出站层带 CLEAR_ACTION_RIGHT = 硬许可；入站层是
        // 普通放行，防火墙继续守着入站。
        out.push(FilterSpec {
            name: "Xray TUN: permit Xray".to_string(),
            layer,
            flags: if layer.is_outbound() { FILTER_FLAG_CLEAR_ACTION_RIGHT } else { 0 },
            action: Action::Permit,
            weight: WEIGHT_XRAY,
            conditions: vec![self_cond.clone()],
        });

        let mut permits: Vec<(&str, Vec<Condition>)> = vec![("loopback", vec![loopback.clone()])];
        if ipv6 {
            permits.push(("IPv6 neighbor and multicast listener discovery", discovery.clone()));
            permits.push((
                "DHCPv6",
                if layer.is_outbound() { dhcpv6_out.clone() } else { dhcpv6.clone() },
            ));
        } else {
            permits.push(("DHCP", dhcp.clone()));
        }
        // 一条连接经 TUN：本地接口是 TUN，且从/向 TUN 出去（包可能因 weak host
        // send/recv 用别的网卡，故两个条件都要）。
        let via =
            if layer.is_outbound() { Field::IpNexthopInterface } else { Field::IpArrivalInterface };
        permits.push((
            "through the TUN",
            vec![
                Condition::equal(Field::IpLocalInterface, tun.clone()),
                Condition::equal(via, tun.clone()),
            ],
        ));
        for (name, conditions) in permits {
            out.push(FilterSpec {
                name: format!("Xray TUN: permit {name}"),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: WEIGHT_PERMIT,
                conditions,
            });
        }

        for leak in &input.block {
            let Some(prefix) = leak.over(ipv6) else {
                continue; // 只对另一个 IP 版本生效
            };
            let protocols: &[u8] = match leak.name.as_str() {
                "tcp" => &[IPPROTO_TCP],
                "udp" => &[IPPROTO_UDP],
                "" => &[IPPROTO_TCP, IPPROTO_UDP],
                "icmp" => {
                    if ipv6 {
                        &[IPPROTO_ICMPV6]
                    } else {
                        &[IPPROTO_ICMP]
                    }
                },
                // 每一个协议。
                "all" | "misconfigtun" => &[],
                // allexceptlan 与 windnsclient 的过滤器在下面单独装。
                _ => continue,
            };
            let mut conditions: Vec<Condition> = protocols
                .iter()
                .map(|protocol| Condition::equal(Field::IpProtocol, Value::U8(*protocol)))
                .collect();
            conditions.extend(port_conditions(leak));
            conditions.extend(remote(&[prefix]));
            out.push(FilterSpec {
                name: format!("Xray TUN: block {leak}"),
                layer,
                flags: 0,
                action: Action::Block,
                weight: WEIGHT_BLOCK,
                conditions,
            });
        }

        let all_except_lan: Vec<Prefix> = input
            .block
            .iter()
            .filter(|leak| leak.name == "allexceptlan")
            .filter_map(|leak| leak.over(ipv6))
            .collect();
        if !all_except_lan.is_empty() {
            let lan = lan_within(&all_except_lan);
            if !lan.is_empty() {
                out.push(FilterSpec {
                    name: "Xray TUN: permit the local network".to_string(),
                    layer,
                    flags: 0,
                    action: Action::Permit,
                    weight: WEIGHT_LAN,
                    conditions: remote(&lan),
                });
            }
            out.push(FilterSpec {
                name: "Xray TUN: block allexceptlan".to_string(),
                layer,
                flags: 0,
                action: Action::Block,
                weight: WEIGHT_ALL_EXCEPT_LAN,
                conditions: remote(&all_except_lan),
            });
        }
    }

    // Windows 11 / Server 2022 起 DNS Client 服务可能用 DoH/DoT 走任意端口，故它
    // 只能经 TUN 连接，例外是局域网上的名字解析（mDNS、LLMNR）。与 Windows
    // 防火墙对它的规则一样，按服务 SID 识别（安全描述符授予该 SID 匹配权）。
    if let Some(sd) = &input.dns_client_sd {
        let dns_client = Condition::equal(Field::AleUserId, Value::Bytes(sd.clone()));
        // 同字段的多条件 = 任一命中。
        let mdns_llmnr = vec![
            dns_client.clone(),
            Condition::equal(Field::IpRemotePort, Value::U16(5353)),
            Condition::equal(Field::IpRemotePort, Value::U16(5355)),
        ];
        for layer in [Layer::AuthConnectV4, Layer::AuthConnectV6] {
            let ipv6 = !layer.is_ipv4();
            let prefixes: Vec<Prefix> = input
                .block
                .iter()
                .filter(|leak| leak.name == "windnsclient")
                .filter_map(|leak| leak.over(ipv6))
                .collect();
            if prefixes.is_empty() {
                continue;
            }
            let mut conditions = mdns_llmnr.clone();
            conditions.extend(remote(&lan_within(&[all_addresses(ipv6)])));
            out.push(FilterSpec {
                name: "Xray TUN: permit the DNS Client service's mDNS and LLMNR".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: WEIGHT_LOCAL_LINK,
                conditions,
            });
            let mut conditions = vec![dns_client.clone()];
            conditions.extend(remote(&prefixes));
            out.push(FilterSpec {
                name: "Xray TUN: block the DNS Client service".to_string(),
                layer,
                flags: 0,
                action: Action::Block,
                weight: WEIGHT_DNS_CLIENT,
                conditions,
            });
        }
    }

    out
}

/// 远端地址条件：同一字段的多条件 = 任一命中；含全部地址（`/0`）时不需要条件。
fn remote(prefixes: &[Prefix]) -> Vec<Condition> {
    if prefixes.iter().any(|prefix| prefix.bits == 0) {
        return Vec::new();
    }
    prefixes
        .iter()
        .map(|prefix| Condition::equal(Field::IpRemoteAddress, addr_mask(*prefix)))
        .collect()
}

/// 前缀 → WFP 的「地址 + 掩码」值。
fn addr_mask(prefix: Prefix) -> Value {
    match prefix.addr {
        IpAddr::V4(v4) => Value::V4AddrMask { addr: u32::from(v4), mask: mask_v4(prefix.bits) },
        IpAddr::V6(v6) => Value::V6AddrMask { addr: v6.octets(), prefix_length: prefix.bits },
    }
}

/// 端口条件（Go `toPorts`）：全部端口不加条件，单端口等值，区间用 `FWP_MATCH_RANGE`。
fn port_conditions(leak: &Leak) -> Vec<Condition> {
    if leak.low == 0 {
        return Vec::new();
    }
    if leak.low == leak.high {
        return vec![Condition::equal(Field::IpRemotePort, Value::U16(leak.low))];
    }
    vec![Condition {
        field: Field::IpRemotePort,
        match_type: MatchType::Range,
        value: Value::PortRange { low: leak.low, high: leak.high },
    }]
}

/// DHCPv6 服务器组播地址 `ff02::1:2`（Go `ipv6AllDHCPv6Servers`）。
fn multicast_dhcpv6_server() -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[12] = 0x00;
    a[13] = 0x01;
    a[15] = 0x02;
    a
}

/// 返回「查询到不了 TUN 且会被阻断」的 DNS 服务器（对应 Go `tun_windows_wfp.go` 的
/// `dnsOutsideTUN`）。
///
/// 三条判据缺一不可（少任何一条就是过度告警）：
/// - 回环服务器跳过——本地解析器走回环，而回环保留在 TUN 内被放行；
/// - 落在 `prefixes`（gateway ∪ autoSystemRoutingTable）内的跳过——查询本来就走 TUN；
/// - 必须落在某个「阻断系统 DNS」的值（[`Leak::blocks_dns`]）或 `misconfigtun` 的 CIDR 内，
///   否则那些查询根本不会被 WFP 挡掉。
#[must_use]
pub fn dns_outside_tun(
    servers: &[IpAddr],
    prefixes: &[(IpAddr, u8)],
    block: &[Leak],
) -> Vec<IpAddr> {
    servers
        .iter()
        .copied()
        .filter_map(|server| {
            let server = match server {
                IpAddr::V4(v4) => IpAddr::V4(v4),
                IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => IpAddr::V6(v6),
                },
            };
            let covered = prefixes.iter().any(|(net, len)| contains(net, *len, server));
            if server.is_loopback() || covered {
                return None;
            }
            let blocked = block.iter().any(|leak| {
                leak.over(server.is_ipv6()).is_some_and(|prefix| {
                    prefix.contains(server) && (leak.blocks_dns() || leak.name == "misconfigtun")
                })
            });
            blocked.then_some(server)
        })
        .collect()
}

/// 前缀包含判定（`net/len` 含 `addr`）。
pub(crate) fn contains(net: &IpAddr, len: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = mask_v4(len);
            u32::from_be_bytes(n.octets()) & mask == u32::from_be_bytes(a.octets()) & mask
        },
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = mask_v6(len);
            u128::from_be_bytes(n.octets()) & mask == u128::from_be_bytes(a.octets()) & mask
        },
        _ => false,
    }
}

/// IPv4 掩码。
pub(crate) fn mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len).min(32)) }
}

/// IPv6 掩码。
pub(crate) fn mask_v6(len: u8) -> u128 {
    if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len).min(128)) }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::wfp::leak;

    fn input(block: &[&str]) -> LeakFilterInput {
        let values: Vec<String> = block.iter().map(|v| (*v).to_string()).collect();
        LeakFilterInput {
            tun_luid: 0x1122_3344_5566_7788,
            app_id: vec![1, 2, 3, 4],
            block: leak::new_leak_filters(&leak::expand(&values).expect("合法值"), true, true),
            dns_client_sd: None,
        }
    }

    fn named<'a>(specs: &'a [FilterSpec], name: &str) -> Vec<&'a FilterSpec> {
        specs.iter().filter(|spec| spec.name == name).collect()
    }

    /// 同一组值，但指定两个 IP 版本是否有路由（`misconfigtun` 的取舍看它）。
    fn input_routes(block: &[&str], route4: bool, route6: bool) -> LeakFilterInput {
        let values: Vec<String> = block.iter().map(|v| (*v).to_string()).collect();
        LeakFilterInput {
            block: leak::new_leak_filters(&leak::expand(&values).expect("合法值"), route4, route6),
            ..input(block)
        }
    }

    /// 常量必须与 fwptypes.h / Go `tun_windows_wfp.go` 逐值一致——写错一位就是
    /// 「过滤器装上了但不阻断/阻断过头」，只有真机才看得出来。
    #[test]
    fn constants_match_go() {
        assert_eq!(FILTER_FLAG_CLEAR_ACTION_RIGHT, 8, "fwpmFilterFlagClearActionRight");
        assert_eq!(CONDITION_FLAG_IS_LOOPBACK, 1, "fwpConditionFlagIsLoopback");
        assert_eq!(IPPROTO_ICMP, 1);
        assert_eq!(IPPROTO_TCP, 6);
        assert_eq!(IPPROTO_UDP, 17);
        assert_eq!(IPPROTO_ICMPV6, 58);
        assert_eq!(WINDOWS_DOH_DNS_BUILD, 20348);
        // 七档权重：0..=6，最重的是「放行 Xray」。
        assert_eq!(
            [
                WEIGHT_ALL_EXCEPT_LAN,
                WEIGHT_LAN,
                WEIGHT_DNS_CLIENT,
                WEIGHT_LOCAL_LINK,
                WEIGHT_BLOCK,
                WEIGHT_PERMIT,
                WEIGHT_XRAY,
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
        // ff02::1:2
        let m = multicast_dhcpv6_server();
        assert_eq!((m[0], m[1], m[13], m[15]), (0xff, 0x02, 0x01, 0x02));
    }

    /// 什么都不挡：每层放行 Xray + 回环 + 该族的系统必需流量 + 经 TUN。
    #[test]
    fn empty_block_permits_xray_system_traffic_and_tun() {
        let specs = leak_filter_specs(&input(&[]));
        // 4 层 × (1 Xray + 1 回环 + 1 经 TUN) + v4 两层 DHCP + v6 两层 (discovery + DHCPv6)
        assert_eq!(specs.len(), 18, "空 block 的过滤器数量");
        assert!(specs.iter().all(|spec| spec.action == Action::Permit));

        let xray = named(&specs, "Xray TUN: permit Xray");
        assert_eq!(xray.len(), 4);
        // 出站层带 CLEAR_ACTION_RIGHT（硬许可），入站层不带。
        for spec in &xray {
            assert_eq!(
                spec.flags,
                if spec.layer.is_outbound() { FILTER_FLAG_CLEAR_ACTION_RIGHT } else { 0 }
            );
            assert_eq!(spec.weight, WEIGHT_XRAY);
            assert_eq!(
                spec.conditions,
                vec![Condition::equal(Field::AleAppId, Value::Bytes(vec![1, 2, 3, 4]))]
            );
        }

        // 经 TUN：出站层看下一跳接口，入站层看到达接口。
        for spec in named(&specs, "Xray TUN: permit through the TUN") {
            let fields: Vec<Field> = spec.conditions.iter().map(|c| c.field).collect();
            let want = if spec.layer.is_outbound() {
                vec![Field::IpLocalInterface, Field::IpNexthopInterface]
            } else {
                vec![Field::IpLocalInterface, Field::IpArrivalInterface]
            };
            assert_eq!(fields, want);
            assert!(spec.conditions.iter().all(|c| c.value == Value::U64(0x1122_3344_5566_7788)));
        }

        // DHCP 只在 IPv4 层，DHCPv6 只在 IPv6 层。
        let dhcp = named(&specs, "Xray TUN: permit DHCP");
        assert_eq!(dhcp.len(), 2);
        assert!(dhcp.iter().all(|spec| spec.layer.is_ipv4()));
        assert!(dhcp[0].conditions.iter().any(|c| c.value == Value::U16(68)));
        assert!(dhcp[0].conditions.iter().any(|c| c.value == Value::U16(67)));
        let dhcpv6 = named(&specs, "Xray TUN: permit DHCPv6");
        assert_eq!(dhcpv6.len(), 2);
        assert!(dhcpv6.iter().all(|spec| !spec.layer.is_ipv4()));
        // 出站的 DHCPv6 还带组播目标地址。
        let out = dhcpv6.iter().find(|spec| spec.layer == Layer::AuthConnectV6).unwrap();
        assert!(out.conditions.iter().any(|c| c.value == Value::Addr16(multicast_dhcpv6_server())));
        let inbound = dhcpv6.iter().find(|spec| spec.layer == Layer::AuthRecvAcceptV6).unwrap();
        assert!(!inbound.conditions.iter().any(|c| matches!(c.value, Value::Addr16(_))));

        let discovery =
            named(&specs, "Xray TUN: permit IPv6 neighbor and multicast listener discovery");
        assert_eq!(discovery.len(), 2);
        assert!(discovery[0].conditions.iter().any(|c| c.value == Value::U8(IPPROTO_ICMPV6)));
        for typ in [130u16, 137, 143] {
            assert!(discovery[0].conditions.iter().any(|c| c.value == Value::U16(typ)));
        }
    }

    /// 端口与 CIDR 都翻成条件：单端口等值、区间 `FWP_MATCH_RANGE`、CIDR 地址+掩码。
    #[test]
    fn block_leak_becomes_protocol_port_and_address_conditions() {
        let specs = leak_filter_specs(&input(&["tcp/853", "1.1.1.0/24:udp/10-20"]));

        let single = named(&specs, "Xray TUN: block tcp/853");
        assert_eq!(single.len(), 4, "四层各一条");
        assert_eq!(single[0].action, Action::Block);
        assert_eq!(single[0].weight, WEIGHT_BLOCK);
        assert_eq!(
            single[0].conditions,
            vec![
                Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_TCP)),
                Condition::equal(Field::IpRemotePort, Value::U16(853)),
            ]
        );

        let range = named(&specs, "Xray TUN: block 1.1.1.0/24:udp/10-20");
        assert_eq!(range.len(), 2, "只落在 IPv4 层");
        assert!(range.iter().all(|spec| spec.layer.is_ipv4()));
        assert_eq!(
            range[0].conditions,
            vec![
                Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_UDP)),
                Condition {
                    field: Field::IpRemotePort,
                    match_type: MatchType::Range,
                    value: Value::PortRange { low: 10, high: 20 },
                },
                Condition::equal(
                    Field::IpRemoteAddress,
                    Value::V4AddrMask {
                        addr: u32::from(Ipv4Addr::new(1, 1, 1, 0)),
                        mask: mask_v4(24),
                    },
                ),
            ]
        );
    }

    /// 端口单独写 = TCP 和 UDP 各一条协议条件；`all` 不加协议条件。
    #[test]
    fn port_only_and_all_leaks_become_protocol_conditions() {
        let specs = leak_filter_specs(&input(&["53"]));
        let port = named(&specs, "Xray TUN: block 53");
        assert_eq!(port.len(), 4);
        assert_eq!(
            port[0].conditions,
            vec![
                Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_TCP)),
                Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_UDP)),
                Condition::equal(Field::IpRemotePort, Value::U16(53)),
            ]
        );

        // all：没有任何条件 = 每一个协议、每一个地址都阻断。
        let specs = leak_filter_specs(&input(&["all"]));
        let all = named(&specs, "Xray TUN: block all");
        assert_eq!(all.len(), 4);
        assert!(all.iter().all(|spec| spec.conditions.is_empty()));
        assert!(all.iter().all(|spec| spec.action == Action::Block));
    }

    /// `/0` 前缀 = 全部地址：不再生成地址条件。
    #[test]
    fn zero_prefix_omits_address_condition() {
        let specs = leak_filter_specs(&input(&["0.0.0.0/0:tcp/80", "[::/0]:icmp"]));
        let v4 = named(&specs, "Xray TUN: block 0.0.0.0/0:tcp/80");
        assert_eq!(v4.len(), 2, "只在 IPv4 层");
        assert!(v4.iter().all(|spec| spec.layer.is_ipv4()));
        assert!(!v4[0].conditions.iter().any(|c| c.field == Field::IpRemoteAddress));

        let v6 = named(&specs, "Xray TUN: block [::/0]:icmp");
        assert_eq!(v6.len(), 2, "只在 IPv6 层");
        assert!(v6.iter().all(|spec| !spec.layer.is_ipv4()));
        // IPv6 层用 ICMPv6。
        assert!(v6[0].conditions.iter().any(|c| c.value == Value::U8(IPPROTO_ICMPV6)));
    }

    /// IPv6 CIDR 用 `V6AddrMask`，且只落在 IPv6 层（IPv6 没有路由时 `misconfigtun`
    /// 才收窄到它）。
    #[test]
    fn ipv6_prefix_uses_v6_addr_and_mask() {
        let specs = leak_filter_specs(&input_routes(&["[2000::/3]:misconfigtun"], true, false));
        let block = named(&specs, "Xray TUN: block [2000::/3]:misconfigtun");
        assert_eq!(block.len(), 2);
        assert!(block.iter().all(|spec| !spec.layer.is_ipv4()));
        assert_eq!(
            block[0].conditions,
            vec![Condition::equal(
                Field::IpRemoteAddress,
                Value::V6AddrMask {
                    addr: Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0).octets(),
                    prefix_length: 3
                },
            )]
        );
    }

    /// `allexceptlan`：局域网放行比其它值轻（DNS 的 53/853 仍被挡）。
    #[test]
    fn all_except_lan_permits_local_network_lighter_than_blocks() {
        let specs = leak_filter_specs(&input(&["allexceptlan"]));
        let permit_lan = named(&specs, "Xray TUN: permit the local network");
        assert_eq!(permit_lan.len(), 4, "两个版本各两层");
        assert!(permit_lan.iter().all(|spec| spec.weight == WEIGHT_LAN));
        assert!(permit_lan.iter().all(|spec| {
            spec.conditions
                .iter()
                .any(|c| matches!(c.value, Value::V4AddrMask { .. } | Value::V6AddrMask { .. }))
        }));

        let block_lan = named(&specs, "Xray TUN: block allexceptlan");
        assert_eq!(block_lan.len(), 4);
        assert!(block_lan.iter().all(|spec| spec.weight == WEIGHT_ALL_EXCEPT_LAN));

        // 局域网 DNS 仍被挡（allexceptlan 展开带 53/853）。
        assert_eq!(named(&specs, "Xray TUN: block 53").len(), 4);
        assert_eq!(named(&specs, "Xray TUN: block 853").len(), 4);
    }

    /// DNS Client 服务那一族：只在给了安全描述符时生成，只进出站层。
    #[test]
    fn dns_client_filters_need_the_security_descriptor() {
        // 没有描述符：即使 block 里有 windnsclient 也不生成（避免半截条件）。
        let specs = leak_filter_specs(&input(&["windnsclient"]));
        assert!(!specs.iter().any(|spec| spec.name.contains("DNS Client service")));

        let values = vec!["windnsclient".to_string()];
        let mut with_sd = LeakFilterInput {
            tun_luid: 7,
            app_id: vec![1],
            block: leak::new_leak_filters(&leak::expand(&values).unwrap(), true, true),
            dns_client_sd: Some(vec![9, 9]),
        };
        let specs = leak_filter_specs(&with_sd);
        let permit_mdns: Vec<_> = specs
            .iter()
            .filter(|s| s.name == "Xray TUN: permit the DNS Client service's mDNS and LLMNR")
            .collect();
        assert_eq!(permit_mdns.len(), 2, "两个出站层");
        assert!(permit_mdns.iter().all(|spec| spec.layer.is_outbound()));
        assert_eq!(permit_mdns[0].weight, WEIGHT_LOCAL_LINK);
        // 限在局域网：5353/5355 + 该族的局域网前缀。
        assert!(permit_mdns[0].conditions.iter().any(|c| c.value == Value::U16(5353)));
        assert!(permit_mdns[0].conditions.iter().any(|c| c.value == Value::U16(5355)));
        assert!(
            permit_mdns[0].conditions.iter().any(|c| matches!(c.value, Value::V4AddrMask { .. }))
        );
        assert!(
            permit_mdns[1].conditions.iter().any(|c| matches!(c.value, Value::V6AddrMask { .. }))
        );

        let block_client: Vec<_> =
            specs.iter().filter(|s| s.name == "Xray TUN: block the DNS Client service").collect();
        assert_eq!(block_client.len(), 2);
        assert_eq!(block_client[0].weight, WEIGHT_DNS_CLIENT);
        assert_eq!(
            block_client[0].conditions[0],
            Condition::equal(Field::AleUserId, Value::Bytes(vec![9, 9]))
        );

        // 只限某个版本的 CIDR：只在该版本的出站层生成。
        with_sd.block = leak::new_leak_filters(
            &leak::expand(&["1.0.0.0/8:windnsclient".to_string()]).unwrap(),
            true,
            true,
        );
        let specs = leak_filter_specs(&with_sd);
        let block_client = named(&specs, "Xray TUN: block the DNS Client service");
        assert_eq!(block_client.len(), 1);
        assert!(block_client[0].layer.is_ipv4());
    }

    /// 七档权重全用上：最重的放行 Xray 压过一切，`allexceptlan` 的阻断压不过
    /// 局域网的放行。
    #[test]
    fn weights_use_all_seven_tiers() {
        let mut input = LeakFilterInput {
            tun_luid: 1,
            app_id: vec![1],
            block: leak::new_leak_filters(
                &leak::expand(&[
                    "all".to_string(),
                    "allexceptlan".to_string(),
                    "windnsclient".to_string(),
                ])
                .unwrap(),
                true,
                true,
            ),
            dns_client_sd: Some(vec![2]),
        };
        let specs = leak_filter_specs(&input);
        let mut weights: Vec<u8> = specs.iter().map(|spec| spec.weight).collect();
        weights.sort_unstable();
        weights.dedup();
        assert_eq!(weights, vec![0, 1, 2, 3, 4, 5, 6]);

        // 同一层里「放行 Xray」最重；「allexceptlan」最轻。
        let per_layer = |layer: Layer| {
            specs.iter().filter(|spec| spec.layer == layer).map(|spec| spec.weight).max().unwrap()
        };
        assert_eq!(per_layer(Layer::AuthConnectV4), WEIGHT_XRAY);

        // 描述符为空时不生成 DNS Client 族（这里只验证不会 panic 且权重仍齐）。
        input.dns_client_sd = None;
        assert!(!leak_filter_specs(&input).iter().any(|spec| spec.weight == WEIGHT_DNS_CLIENT));
    }

    /// 阻断值的构造入口（`new_leak_filters` 就是生产用的那个）。
    fn leak_block(values: &[&str]) -> Vec<leak::Leak> {
        let values: Vec<String> = values.iter().map(|v| (*v).to_string()).collect();
        leak::new_leak_filters(&leak::expand(&values).expect("合法值"), true, true)
    }

    /// F-02（bd 4af7e）：对齐 Go `dnsOutsideTUN` 的两条前置过滤。
    ///
    /// 旧断言把 `::1`（回环）算作「在外面」——那正是被否掉的过度告警，故此处改判：
    /// 回环跳过，且只有落在阻断值 CIDR 内的服务器才告警。
    #[test]
    fn dns_outside_tun_skips_loopback_and_requires_block_cidr() {
        let servers = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // 覆盖前缀内 → 不告警
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),     // 前缀外 + 落在阻断 CIDR 内 → 告警
            IpAddr::V4(Ipv4Addr::LOCALHOST),           // 回环 → 跳过（旧实现误报）
            IpAddr::V6(Ipv6Addr::LOCALHOST),           // 回环（v6）→ 跳过（旧实现误报）
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),    // 前缀外但不在阻断 CIDR 内 → 不告警
        ];
        let prefixes = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
        let block = leak_block(&["8.8.8.0/24:53"]);
        assert_eq!(
            dns_outside_tun(&servers, &prefixes, &block),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );

        // 没有阻断系统 DNS 的值（`icmp`）⇒ 那几条查询不会被挡 ⇒ 一条都不告警。
        assert!(dns_outside_tun(&servers, &prefixes, &leak_block(&["icmp"])).is_empty());
    }

    #[test]
    fn dns_outside_tun_empty_inputs() {
        let one = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        assert!(dns_outside_tun(&[], &[], &leak_block(&["dns"])).is_empty());
        assert!(dns_outside_tun(&one, &[], &[]).is_empty(), "没有阻断值 ⇒ 不告警");
        assert_eq!(
            dns_outside_tun(&one, &[], &leak_block(&["dns"])).len(),
            1,
            "全地址阻断 + 空前缀 ⇒ 在外面"
        );
    }
}
