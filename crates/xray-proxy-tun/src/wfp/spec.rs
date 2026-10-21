//! WFP 泄漏阻断的**规格层**（平台无关）。
//!
//! 对应 Go `proxy/tun/tun_windows_wfp.go` 的 `addLeakFilters`（:245-427）与
//! `dnsOutsideTUN`（:450-459）：把「装哪些过滤器、什么条件、什么动作」表达成
//! 纯数据，本层不碰任何 Windows API，便于在任意平台单测。
//!
//! ## 语义（照抄 Go，勿自行发挥）
//!
//! 目的：把「本该走 TUN 却从别的网卡漏出去」的流量挡住——
//! - `dns`：DNS 只允许走 TUN（Windows 11/Server 2022 起 DNS Client 服务还可能
//!   用 DoH/DoT，故按服务 SID 单独处理）；
//! - `misconfigtun`：某个 IP 版本没有任何路由指向 TUN 时，禁掉该版本的出站
//!   （回环、DHCP、IPv6 邻居/组播发现放行）。
//!
//! 过滤器装在**动态 WFP 会话**里：关掉 engine 即删除，进程退出 Windows 也会删。

use std::net::IpAddr;

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
    /// 该层是否出站（出站层带 `ClearActionRight` 硬许可，见 Go :304-307）。
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
    /// 远端地址（16 字节）。
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
    /// 显示名（Go 形如 `"Xray TUN: block DNS"`）。
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
/// 下层子层（含 Windows 防火墙规则）不再能推翻（Go :304-307）。
pub const FILTER_FLAG_CLEAR_ACTION_RIGHT: u32 = 0x0000_0008;

/// `FWP_CONDITION_FLAG_IS_LOOPBACK`（Go :367-369）。
pub const CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;

/// IP 协议号：UDP。
pub const IPPROTO_UDP: u8 = 17;
/// IP 协议号：ICMPv6。
pub const IPPROTO_ICMPV6: u8 = 58;

/// DNS 客户端服务 SID（Go `dnsClientSID`，:78）。
pub const DNS_CLIENT_SID: &str = "S-1-5-80-859482183-879914841-863379149-1145462774-2388618682";

/// Windows 11 / Server 2022（build 20348）起 DNS Client 服务可能走 DoH/DoT。
pub const WINDOWS_DOH_DNS_BUILD: u32 = 20348;

/// 生成泄漏阻断过滤器集合所需的输入。
#[derive(Debug, Clone)]
pub struct LeakFilterInput {
    /// TUN 接口的 LUID（接口索引经 `ConvertInterfaceIndexToLuid` 得到）。
    pub tun_luid: u64,
    /// 本进程 AppID（`FwpmGetAppIdFromFileName0` 的输出）。
    pub app_id: Vec<u8>,
    /// 是否阻断 DNS 泄漏。
    pub dns: bool,
    /// 是否阻断 IPv4 泄漏。
    pub ipv4: bool,
    /// 是否阻断 IPv6 泄漏。
    pub ipv6: bool,
    /// Windows build 号（`RtlGetNtVersionNumbers` 的第三返回值）。
    pub windows_build: u32,
    /// DNS Client 服务的匹配用安全描述符（SDDL 转换后的字节）。
    ///
    /// `None` = 未提供（则不生成 DNS Client 服务过滤器）。
    pub dns_client_sd: Option<Vec<u8>>,
}

/// 组装全部泄漏阻断过滤器（对应 Go `addLeakFilters`，:245-427）。
///
/// 顺序与 Go 一致：每个层先放行 Xray 自己，再（按需）放行/阻断 DNS，
/// 最后按 IP 版本放行回环与系统必需流量、阻断其余。
#[must_use]
pub fn leak_filter_specs(input: &LeakFilterInput) -> Vec<FilterSpec> {
    let mut out = Vec::new();
    let tun = Value::U64(input.tun_luid);
    let self_cond = Condition::equal(Field::AleAppId, Value::Bytes(input.app_id.clone()));
    let dns53 = Condition::equal(Field::IpRemotePort, Value::U16(53));

    for layer in [
        Layer::AuthConnectV4,
        Layer::AuthRecvAcceptV4,
        Layer::AuthConnectV6,
        Layer::AuthRecvAcceptV6,
    ] {
        // 放行 Xray 自己的出站连接（DNS 等走其它网卡是故意的）。
        // 出站层带 CLEAR_ACTION_RIGHT = 硬许可。
        out.push(FilterSpec {
            name: "Xray TUN: permit Xray".to_string(),
            layer,
            flags: if layer.is_outbound() { FILTER_FLAG_CLEAR_ACTION_RIGHT } else { 0 },
            action: Action::Permit,
            weight: 4,
            conditions: vec![self_cond.clone()],
        });

        if input.dns {
            // DNS 走 TUN：本地接口或下一跳/到达接口是 TUN。
            let through_tun = if layer.is_outbound() {
                vec![
                    dns53.clone(),
                    Condition::equal(Field::IpLocalInterface, tun.clone()),
                    Condition::equal(Field::IpNexthopInterface, tun.clone()),
                ]
            } else {
                vec![
                    dns53.clone(),
                    Condition::equal(Field::IpLocalInterface, tun.clone()),
                    Condition::equal(Field::IpArrivalInterface, tun.clone()),
                ]
            };
            out.push(FilterSpec {
                name: "Xray TUN: permit DNS through the TUN".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 3,
                conditions: through_tun,
            });
            out.push(FilterSpec {
                name: "Xray TUN: block DNS".to_string(),
                layer,
                flags: 0,
                action: Action::Block,
                weight: 2,
                conditions: vec![dns53.clone()],
            });
        }
    }

    // Windows 11 / Server 2022 起 DNS Client 服务可能用 DoH/DoT 走任意端口。
    if input.dns && input.windows_build >= WINDOWS_DOH_DNS_BUILD {
        if let Some(sd) = &input.dns_client_sd {
            let dns_client = Condition::equal(Field::AleUserId, Value::Bytes(sd.clone()));
            // mDNS(5353) 与 LLMNR(5355) 留在本地链路。
            let mdns_llmnr = vec![
                dns_client.clone(),
                Condition::equal(Field::IpRemotePort, Value::U16(5353)),
                Condition::equal(Field::IpRemotePort, Value::U16(5355)),
            ];
            for layer in [Layer::AuthConnectV4, Layer::AuthConnectV6] {
                // 另一版本被整体禁掉时，本版本才需要放行本地链路的 mDNS/LLMNR。
                let local_link = if layer.is_ipv4() { !input.ipv6 } else { !input.ipv4 };
                out.push(FilterSpec {
                    name: "Xray TUN: permit the DNS Client service through the TUN".to_string(),
                    layer,
                    flags: 0,
                    action: Action::Permit,
                    weight: 3,
                    conditions: vec![
                        dns_client.clone(),
                        Condition::equal(Field::IpLocalInterface, Value::U64(input.tun_luid)),
                        Condition::equal(Field::IpNexthopInterface, Value::U64(input.tun_luid)),
                    ],
                });
                if local_link {
                    out.push(FilterSpec {
                        name: "Xray TUN: permit the DNS Client service's mDNS and LLMNR"
                            .to_string(),
                        layer,
                        flags: 0,
                        action: Action::Permit,
                        weight: 3,
                        conditions: mdns_llmnr.clone(),
                    });
                }
                out.push(FilterSpec {
                    name: "Xray TUN: block the DNS Client service".to_string(),
                    layer,
                    flags: 0,
                    action: Action::Block,
                    weight: 2,
                    conditions: vec![dns_client.clone()],
                });
            }
        }
    }

    let loopback = Condition::flags_all_set(Field::Flags, Value::U32(CONDITION_FLAG_IS_LOOPBACK));

    if input.ipv4 {
        // DHCP（客户端 68 → 服务器 67）：其它网卡的地址靠它，Xray 自己要用。
        let dhcp = vec![
            Condition::equal(Field::IpProtocol, Value::U8(IPPROTO_UDP)),
            Condition::equal(Field::IpLocalPort, Value::U16(68)),
            Condition::equal(Field::IpRemotePort, Value::U16(67)),
        ];
        for layer in [Layer::AuthConnectV4, Layer::AuthRecvAcceptV4] {
            out.push(FilterSpec {
                name: "Xray TUN: permit IPv4 loopback".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 1,
                conditions: vec![loopback.clone()],
            });
            out.push(FilterSpec {
                name: "Xray TUN: permit DHCP".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 1,
                conditions: dhcp.clone(),
            });
            out.push(FilterSpec {
                name: "Xray TUN: block IPv4".to_string(),
                layer,
                flags: 0,
                action: Action::Block,
                weight: 0,
                conditions: Vec::new(),
            });
        }
    }

    if input.ipv6 {
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
        let dhcpv6_connect = {
            let mut c = dhcpv6.clone();
            // 客户端发往服务器的组播地址。
            c.push(Condition::equal(
                Field::IpRemoteAddress,
                Value::Addr16(multicast_dhcpv6_server()),
            ));
            c
        };
        for (layer, d) in
            [(Layer::AuthConnectV6, dhcpv6_connect), (Layer::AuthRecvAcceptV6, dhcpv6)]
        {
            out.push(FilterSpec {
                name: "Xray TUN: permit IPv6 loopback".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 1,
                conditions: vec![loopback.clone()],
            });
            out.push(FilterSpec {
                name: "Xray TUN: permit IPv6 neighbor and multicast listener discovery".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 1,
                conditions: discovery.clone(),
            });
            out.push(FilterSpec {
                name: "Xray TUN: permit DHCPv6".to_string(),
                layer,
                flags: 0,
                action: Action::Permit,
                weight: 1,
                conditions: d,
            });
            out.push(FilterSpec {
                name: "Xray TUN: block IPv6".to_string(),
                layer,
                flags: 0,
                action: Action::Block,
                weight: 0,
                conditions: Vec::new(),
            });
        }
    }

    out
}

/// DHCPv6 服务器组播地址 `ff02::1:2`（Go tun_windows_wfp.go:409 的 unicast 目标）。
fn multicast_dhcpv6_server() -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[12] = 0x00;
    a[13] = 0x01;
    a[15] = 0x02;
    a
}

/// 返回落在所有给定前缀**之外**的 DNS 服务器（对应 Go `dnsOutsideTUN`，:450-459）。
///
/// 这些服务器的查询无法走 TUN（Windows 会按各网卡的首个服务器发查询）。
#[must_use]
pub fn dns_outside_tun(servers: &[IpAddr], prefixes: &[(IpAddr, u8)]) -> Vec<IpAddr> {
    servers
        .iter()
        .copied()
        .filter(|server| {
            let server = match server {
                IpAddr::V4(v4) => IpAddr::V4(*v4),
                IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => IpAddr::V6(*v6),
                },
            };
            !prefixes.iter().any(|(net, len)| contains(net, *len, server))
        })
        .collect()
}

/// 前缀包含判定（`net/len` 含 `addr`）。
fn contains(net: &IpAddr, len: u8, addr: IpAddr) -> bool {
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
fn mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len).min(32)) }
}

/// IPv6 掩码。
fn mask_v6(len: u8) -> u128 {
    if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len).min(128)) }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn input(dns: bool, ipv4: bool, ipv6: bool) -> LeakFilterInput {
        LeakFilterInput {
            tun_luid: 0x1122_3344_5566_7788,
            app_id: vec![1, 2, 3, 4],
            dns,
            ipv4,
            ipv6,
            windows_build: 22621,
            dns_client_sd: None,
        }
    }

    /// 常量必须与 Go `tun_windows_wfp.go:34-54` 逐值一致——写错一位就是
    /// 「过滤器装上了但不阻断/阻断过头」，只有真机才看得出来。
    #[test]
    fn constants_match_go() {
        assert_eq!(FILTER_FLAG_CLEAR_ACTION_RIGHT, 8, "fwpmFilterFlagClearActionRight");
        assert_eq!(CONDITION_FLAG_IS_LOOPBACK, 1, "fwpConditionFlagIsLoopback");
        assert_eq!(IPPROTO_UDP, 17);
        assert_eq!(IPPROTO_ICMPV6, 58);
        assert_eq!(WINDOWS_DOH_DNS_BUILD, 20348);
        // ff02::1:2（Go ipv6AllDHCPv6Servers：bytes[13]=1, bytes[15]=2）
        let m = multicast_dhcpv6_server();
        assert_eq!(m[0], 0xff);
        assert_eq!(m[1], 0x02);
        assert_eq!(m[13], 0x01);
        assert_eq!(m[15], 0x02);
    }

    #[test]
    fn no_flags_means_only_permit_xray() {
        let specs = leak_filter_specs(&input(false, false, false));
        assert_eq!(specs.len(), 4, "每层一条 permit Xray");
        assert!(specs.iter().all(|s| s.name == "Xray TUN: permit Xray"));
        // 出站层带 CLEAR_ACTION_RIGHT（硬许可），入站层不带。
        assert_eq!(specs[0].flags, FILTER_FLAG_CLEAR_ACTION_RIGHT);
        assert_eq!(specs[1].flags, 0);
        // 条件 = 本进程 AppID。
        assert_eq!(
            specs[0].conditions,
            vec![Condition::equal(Field::AleAppId, Value::Bytes(vec![1, 2, 3, 4]))]
        );
    }

    #[test]
    fn dns_adds_permit_through_tun_and_block_per_layer() {
        let specs = leak_filter_specs(&input(true, false, false));
        let block_dns: Vec<_> = specs.iter().filter(|s| s.name == "Xray TUN: block DNS").collect();
        assert_eq!(block_dns.len(), 4, "四层各一条 block DNS");
        assert_eq!(block_dns[0].action, Action::Block);
        assert_eq!(
            block_dns[0].conditions,
            vec![Condition::equal(Field::IpRemotePort, Value::U16(53))]
        );
        let permit_tun: Vec<_> =
            specs.iter().filter(|s| s.name == "Xray TUN: permit DNS through the TUN").collect();
        assert_eq!(permit_tun.len(), 4);
        // 出站层用 nexthop 接口，入站层用 arrival 接口。
        assert!(permit_tun[0].conditions.iter().any(|c| c.field == Field::IpNexthopInterface));
        assert!(permit_tun[1].conditions.iter().any(|c| c.field == Field::IpArrivalInterface));
        // 条件里带 TUN 的 LUID。
        assert!(
            permit_tun[0].conditions.iter().any(|c| c.value == Value::U64(0x1122_3344_5566_7788))
        );
    }

    #[test]
    fn ipv4_branch_permits_loopback_and_dhcp_then_blocks() {
        let specs = leak_filter_specs(&input(false, true, false));
        assert!(specs.iter().any(|s| s.name == "Xray TUN: permit IPv4 loopback"));
        let dhcp = specs.iter().find(|s| s.name == "Xray TUN: permit DHCP").unwrap();
        assert_eq!(dhcp.conditions.len(), 3);
        assert!(dhcp.conditions.iter().any(|c| c.value == Value::U16(68)));
        assert!(dhcp.conditions.iter().any(|c| c.value == Value::U16(67)));
        let block = specs.iter().find(|s| s.name == "Xray TUN: block IPv4").unwrap();
        assert_eq!(block.action, Action::Block);
        assert!(block.conditions.is_empty(), "block IPv4 是无条件阻断");
        assert_eq!(block.weight, 0);
        // 只在 IPv4 层。
        assert!(block.layer.is_ipv4());
    }

    #[test]
    fn ipv6_branch_has_discovery_ports_and_dhcpv6() {
        let specs = leak_filter_specs(&input(false, false, true));
        let discovery = specs
            .iter()
            .find(|s| s.name == "Xray TUN: permit IPv6 neighbor and multicast listener discovery")
            .unwrap();
        // ICMPv6 + 130..137/143 + 远端端口 0
        assert!(discovery.conditions.iter().any(|c| c.value == Value::U8(IPPROTO_ICMPV6)));
        for typ in [130u16, 137, 143] {
            assert!(discovery.conditions.iter().any(|c| c.value == Value::U16(typ)));
        }
        let dhcpv6 = specs.iter().find(|s| s.name == "Xray TUN: permit DHCPv6").unwrap();
        assert!(dhcpv6.conditions.iter().any(|c| c.value == Value::U16(546)));
        assert!(dhcpv6.conditions.iter().any(|c| c.value == Value::U16(547)));
    }

    #[test]
    fn dns_client_filters_only_on_new_windows_and_with_sd() {
        // 老版本：即使给了 SD 也不生成（Go :332 build>=20348）。
        let mut old = input(true, false, false);
        old.windows_build = 19045;
        old.dns_client_sd = Some(vec![9, 9]);
        assert!(!leak_filter_specs(&old).iter().any(|s| s.name.contains("DNS Client service")));

        // 新版本 + 有 SD：生成。
        let mut new = input(true, false, false);
        new.windows_build = 22621;
        new.dns_client_sd = Some(vec![9, 9]);
        let specs = leak_filter_specs(&new);
        assert!(specs.iter().any(|s| s.name == "Xray TUN: block the DNS Client service"));
        // 新版本但无 SD：不生成（避免半截条件）。
        let mut nosd = input(true, false, false);
        nosd.windows_build = 22621;
        assert!(!leak_filter_specs(&nosd).iter().any(|s| s.name.contains("DNS Client service")));
    }

    #[test]
    fn dns_client_mdns_permit_only_when_other_family_blocked() {
        let mut i = input(true, true, true);
        i.windows_build = 22621;
        i.dns_client_sd = Some(vec![7]);
        // 两族都被阻断 → 不放行本地链路 mDNS/LLMNR。
        let specs = leak_filter_specs(&i);
        assert!(!specs.iter().any(|s| s.name.contains("mDNS and LLMNR")));

        // 只阻断 IPv4（ipv6 未阻断）→ IPv4 层需要放行 mDNS/LLMNR。
        let mut i2 = input(true, true, false);
        i2.windows_build = 22621;
        i2.dns_client_sd = Some(vec![7]);
        assert!(leak_filter_specs(&i2).iter().any(|s| s.name.contains("mDNS and LLMNR")));
    }

    #[test]
    fn dns_outside_tun_filters_by_prefix() {
        let servers = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // 前缀内
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),     // 前缀外
            IpAddr::V6(Ipv6Addr::LOCALHOST),           // 前缀外
        ];
        let prefixes = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
        let outside = dns_outside_tun(&servers, &prefixes);
        assert_eq!(outside.len(), 2);
        assert!(outside.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(outside.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn dns_outside_tun_empty_inputs() {
        assert!(dns_outside_tun(&[], &[]).is_empty());
        let one = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        assert_eq!(dns_outside_tun(&one, &[]).len(), 1, "空前缀 = 全部在外面");
    }
}
