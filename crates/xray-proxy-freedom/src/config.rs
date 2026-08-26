//! Freedom 配置与规则匹配。
//!
//! 对应 Go `proxy/freedom/freedom.go` + `config.proto`。
//!
//! ## 协议本质
//!
//! Freedom 出站代理直接连接目标地址（不走任何上游代理），是 Xray 的"直连"出口。
//! 配置层支持：
//!
//! - **DomainStrategy**：DNS 解析策略（AS_IS / USE_IP / USE_IP4 / USE_IP6 / USE_IP46 / USE_IP64）
//! - **DestinationOverride**：强制覆盖目标地址（用于透明代理重定向）
//! - **Fragment**：TCP 分片（绕过 SNI 审查）
//! - **Noise**：填充噪声（绕过流量分析）
//! - **FinalRules**：最终规则（Allow/Block 匹配 network + port + IP CIDR）
//!
//! 默认规则：`defaultBlockPrivateRule`（阻止 RFC 1918 私有地址 + 保留段）+
//! `defaultBlockAllRule`（阻止所有，用于 vless-reverse）。
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 实现配置层 + FinalRule 逻辑匹配（network + port + IP CIDR）+ 默认 CIDR 常量。
//! IP CIDR 匹配通过 `xray_geodata::matcher::ip::HeuristicIPMatcher` 实现。
//! 默认 `defaultBlockPrivateRule` 使用 [`DEFAULT_BLOCK_PRIVATE_CIDRS`] 构建的
//! 缓存 matcher（[`private_ip_matcher`]）。Handler/Process/dial 见 `handler.rs`。

/// DNS 解析策略。对应 Go `proxy/freedom/config.proto` DomainStrategy。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum DomainStrategy {
    /// AS_IS: 直接拨号，让 OS 解析域名（默认）
    #[default]
    AsIs = 0,
    /// USE_IP: 解析域名到 IP（IPv4 或 IPv6）
    UseIP = 1,
    /// USE_IP4: 解析域名到 IPv4
    UseIPv4 = 2,
    /// USE_IP6: 解析域名到 IPv6
    UseIPv6 = 3,
    /// USE_IP46: 优先 IPv4，回退 IPv6
    UseIPv4v6 = 4,
    /// USE_IP64: 优先 IPv6，回退 IPv4
    UseIPv6v4 = 5,
    /// FORCE_IP: 解析失败即失败（IPv4 或 IPv6）
    ForceIP = 6,
    /// FORCE_IP4: 强制 IPv4，解析失败即失败
    ForceIPv4 = 7,
    /// FORCE_IP6: 强制 IPv6，解析失败即失败
    ForceIPv6 = 8,
    /// FORCE_IP46: 强制 IPv4，回退 IPv6
    ForceIPv4v6 = 9,
    /// FORCE_IP64: 强制 IPv6，回退 IPv4
    ForceIPv6v4 = 10,
}

impl DomainStrategy {
    #[must_use]
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::UseIP,
            2 => Self::UseIPv4,
            3 => Self::UseIPv6,
            4 => Self::UseIPv4v6,
            5 => Self::UseIPv6v4,
            6 => Self::ForceIP,
            7 => Self::ForceIPv4,
            8 => Self::ForceIPv6,
            9 => Self::ForceIPv4v6,
            10 => Self::ForceIPv6v4,
            _ => Self::AsIs,
        }
    }

    /// Go `transport/internet/config.go` strategy 表：`[mode, prefer, fallback]`。
    ///
    /// mode：0=AsIs，1=Use，2=Force；prefer/fallback：0=任意，4=IPv4，6=IPv6。
    #[must_use]
    pub fn strategy_table(self) -> [u8; 3] {
        match self {
            Self::AsIs => [0, 0, 0],
            Self::UseIP => [1, 0, 0],
            Self::UseIPv4 => [1, 4, 0],
            Self::UseIPv6 => [1, 6, 0],
            Self::UseIPv4v6 => [1, 4, 6],
            Self::UseIPv6v4 => [1, 6, 4],
            Self::ForceIP => [2, 0, 0],
            Self::ForceIPv4 => [2, 4, 0],
            Self::ForceIPv6 => [2, 6, 0],
            Self::ForceIPv4v6 => [2, 4, 6],
            Self::ForceIPv6v4 => [2, 6, 4],
        }
    }

    /// 解析失败时是否必须报错（Go `ForceIP()`：`strategy[s][0] == 2`）。
    #[must_use]
    pub fn force_ip(self) -> bool {
        self.strategy_table()[0] == 2
    }

    /// 是否带解析策略（Go `HasStrategy()`：`strategy[s][0] != 0`）。
    #[must_use]
    pub fn has_strategy(self) -> bool {
        self.strategy_table()[0] != 0
    }

    /// 优先 IPv4（Go `PreferIP4()`）。
    #[must_use]
    pub fn prefer_ipv4(self) -> bool {
        self.strategy_table()[1] == 4
    }

    /// 优先 IPv6（Go `PreferIP6()`）。
    #[must_use]
    pub fn prefer_ipv6(self) -> bool {
        self.strategy_table()[1] == 6
    }

    /// 有回退家族（Go `HasFallback()`）。
    #[must_use]
    pub fn has_fallback(self) -> bool {
        self.strategy_table()[2] != 0
    }

    /// 回退到 IPv4（Go `FallbackIP4()`）。
    #[must_use]
    pub fn fallback_ipv4(self) -> bool {
        self.strategy_table()[2] == 4
    }

    /// 回退到 IPv6（Go `FallbackIP6()`）。
    #[must_use]
    pub fn fallback_ipv6(self) -> bool {
        self.strategy_table()[2] == 6
    }

    /// 是否需要 DNS 解析
    #[must_use]
    pub fn needs_resolution(self) -> bool {
        self.has_strategy()
    }

    /// 解析后是否只接受 IPv4
    #[must_use]
    pub fn ipv4_only(self) -> bool {
        self.prefer_ipv4() && !self.has_fallback()
    }

    /// 解析后是否只接受 IPv6
    #[must_use]
    pub fn ipv6_only(self) -> bool {
        self.prefer_ipv6() && !self.has_fallback()
    }
}

use crate::error::Result;

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use xray_common::net::port::{MemoryPortList, Port, PortRange};
use xray_geodata::matcher::ip::{HeuristicIPMatcher, IPMatcher};
use xray_proto::xray::common::geodata::ip_rule;

/// RuleAction 枚举。对应 proto `RuleAction`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum RuleAction {
    #[default]
    Allow = 0,
    Block = 1,
}

impl RuleAction {
    #[must_use]
    pub fn from_proto_value(v: i32) -> Self {
        match v {
            1 => Self::Block,
            _ => Self::Allow,
        }
    }

    #[must_use]
    pub fn to_proto_value(self) -> i32 {
        self as i32
    }
}

/// 数值范围。对应 proto `Range`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range {
    pub min: u64,
    pub max: u64,
}

/// 目标地址覆盖。对应 proto `DestinationOverride`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DestinationOverride {
    pub server: Option<xray_proto::xray::common::protocol::ServerEndpoint>,
}

/// TCP 分片配置。对应 proto `Fragment`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fragment {
    pub packets_from: u64,
    pub packets_to: u64,
    pub length_min: u64,
    pub length_max: u64,
    pub interval_min: u64,
    pub interval_max: u64,
    pub max_split_min: u64,
    pub max_split_max: u64,
}

/// 噪声配置。对应 proto `Noise`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Noise {
    pub length_min: u64,
    pub length_max: u64,
    pub delay_min: u64,
    pub delay_max: u64,
    pub packet: Vec<u8>,
    pub apply_to: String,
}

/// 最终规则配置。对应 proto `FinalRuleConfig`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FinalRuleConfig {
    pub action: RuleAction,
    /// 允许的网络类型（proto repeated enum → Vec<i32>）。
    pub networks: Vec<i32>,
    pub port_list: Option<xray_proto::xray::common::net::PortList>,
    /// IP CIDR 规则（prost repeated message）。
    pub ip: Vec<xray_proto::xray::common::geodata::IpRule>,
    pub block_delay: Option<Range>,
}

/// Freedom 主配置。对应 proto `xray.proxy.freedom.Config`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    /// DNS 解析策略（proto enum → i32）。
    pub domain_strategy: i32,
    pub destination_override: Option<DestinationOverride>,
    pub user_level: u32,
    pub fragment: Option<Fragment>,
    pub proxy_protocol: u32,
    pub noises: Vec<Noise>,
    pub final_rules: Vec<FinalRuleConfig>,
}

impl Config {
    /// 从 prost Config 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::freedom::Config) -> Result<Self> {
        Ok(Self {
            domain_strategy: p.domain_strategy,
            destination_override: p.destination_override.map(|d| DestinationOverride {
                server: d.server,
            }),
            user_level: p.user_level,
            fragment: p.fragment.map(|f| Fragment {
                packets_from: f.packets_from,
                packets_to: f.packets_to,
                length_min: f.length_min,
                length_max: f.length_max,
                interval_min: f.interval_min,
                interval_max: f.interval_max,
                max_split_min: f.max_split_min,
                max_split_max: f.max_split_max,
            }),
            proxy_protocol: p.proxy_protocol,
            noises: p
                .noises
                .into_iter()
                .map(|n| Noise {
                    length_min: n.length_min,
                    length_max: n.length_max,
                    delay_min: n.delay_min,
                    delay_max: n.delay_max,
                    packet: n.packet,
                    apply_to: n.apply_to,
                })
                .collect(),
            final_rules: p
                .final_rules
                .into_iter()
                .map(|r| FinalRuleConfig {
                    action: RuleAction::from_proto_value(r.action),
                    networks: r.networks,
                    port_list: r.port_list,
                    ip: r.ip,
                    block_delay: r.block_delay.map(|b| Range {
                        min: b.min,
                        max: b.max,
                    }),
                })
                .collect(),
        })
    }

    /// 转换为 prost Config。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::freedom::Config {
        xray_proto::xray::proxy::freedom::Config {
            domain_strategy: self.domain_strategy,
            destination_override: self.destination_override.as_ref().map(|d| {
                xray_proto::xray::proxy::freedom::DestinationOverride {
                    server: d.server.clone(),
                }
            }),
            user_level: self.user_level,
            fragment: self.fragment.as_ref().map(|f| {
                xray_proto::xray::proxy::freedom::Fragment {
                    packets_from: f.packets_from,
                    packets_to: f.packets_to,
                    length_min: f.length_min,
                    length_max: f.length_max,
                    interval_min: f.interval_min,
                    interval_max: f.interval_max,
                    max_split_min: f.max_split_min,
                    max_split_max: f.max_split_max,
                }
            }),
            proxy_protocol: self.proxy_protocol,
            noises: self
                .noises
                .iter()
                .map(|n| xray_proto::xray::proxy::freedom::Noise {
                    length_min: n.length_min,
                    length_max: n.length_max,
                    delay_min: n.delay_min,
                    delay_max: n.delay_max,
                    packet: n.packet.clone(),
                    apply_to: n.apply_to.clone(),
                })
                .collect(),
            final_rules: self
                .final_rules
                .iter()
                .map(|r| xray_proto::xray::proxy::freedom::FinalRuleConfig {
                    action: r.action.to_proto_value(),
                    networks: r.networks.clone(),
                    port_list: r.port_list.clone(),
                    ip: r.ip.clone(),
                    block_delay: r.block_delay.map(|b| {
                        xray_proto::xray::proxy::freedom::Range {
                            min: b.min,
                            max: b.max,
                        }
                    }),
                })
                .collect(),
        }
    }
}

/// 运行时最终规则（从 FinalRuleConfig 构建）。对应 Go `FinalRule` struct。
impl std::fmt::Debug for FinalRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalRule")
            .field("action", &self.action)
            .field("network", &self.network)
            .field("port", &self.port.is_some())
            .field("has_ip_matcher", &self.ip.is_some())
            .field("block_delay", &self.block_delay)
            .finish()
    }
}

pub struct FinalRule {
    pub action: RuleAction,
    /// 允许的网络类型（bool 数组索引 0=TCP 1=UDP 等，与 Go [8]bool 一致）。
    pub network: [bool; 8],
    /// 端口列表（None 表示匹配所有端口）。对应 Go `matchPort` 的 `len==0` 语义。
    pub port: Option<MemoryPortList>,
    /// IP CIDR 匹配器（None 表示无 IP 限制 → 匹配所有地址）。
    pub ip: Option<Arc<dyn IPMatcher>>,
    pub block_delay: Option<Range>,
}

impl Clone for FinalRule {
    fn clone(&self) -> Self {
        Self {
            action: self.action,
            network: self.network,
            port: self.port.clone(),
            ip: self.ip.clone(),
            block_delay: self.block_delay,
        }
    }
}

/// 默认允许所有网络（与 Go `allNetworks` 一致）。
pub const ALL_NETWORKS: [bool; 8] = [true; 8];

/// 默认阻止私有地址的 CIDR 列表（与 Go `defaultBlockPrivateRule` 一致）。
///
/// 包含 RFC 1918 私有地址 + 保留段 + 链路本地 + 多播等。
pub const DEFAULT_BLOCK_PRIVATE_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/127",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

impl FinalRule {
    /// 从 FinalRuleConfig 构造运行时规则。对应 Go `buildFinalRule`。
    pub fn build(config: &FinalRuleConfig) -> Result<Self> {
        let network = if config.networks.is_empty() {
            ALL_NETWORKS
        } else {
            let mut net = [false; 8];
            for &n in &config.networks {
                let idx = n as usize;
                if idx < 8 {
                    net[idx] = true;
                }
            }
            net
        };

        let port = config.port_list.as_ref().map(to_mem_port_list);

        Ok(Self {
            action: config.action,
            network,
            port,
            ip: build_ip_matcher_from_rules(&config.ip),
            block_delay: config.block_delay,
        })
    }

    /// 构造默认规则。对应 Go `init()` 中的 `defaultBlockPrivateRule` /
    /// `defaultBlockAllRule`，以及 `getDefaultFinalRule` 的选择结果。
    ///
    /// - [`DefaultRuleType::BlockPrivate`]：action=Block，network=all，ip=私有 CIDR matcher。
    /// - [`DefaultRuleType::BlockAll`]：action=Block，network=all，ip=None（匹配所有）。
    #[must_use]
    pub fn build_default_rule(kind: DefaultRuleType) -> Self {
        match kind {
            DefaultRuleType::BlockPrivate => Self {
                action: RuleAction::Block,
                network: ALL_NETWORKS,
                port: None,
                ip: Some(private_ip_matcher()),
                block_delay: None,
            },
            DefaultRuleType::BlockAll => Self {
                action: RuleAction::Block,
                network: ALL_NETWORKS,
                port: None,
                ip: None,
                block_delay: None,
            },
        }
    }

    /// 网络类型是否匹配。对应 Go `matchNetwork`。
    #[must_use]
    pub fn match_network(&self, network_index: usize) -> bool {
        if network_index >= 8 {
            return false;
        }
        self.network[network_index]
    }

    /// 端口是否匹配。None 表示匹配所有端口。对应 Go `matchPort`。
    #[must_use]
    pub fn match_port(&self, port: u16) -> bool {
        match &self.port {
            None => true,
            Some(list) => list.contains(Port::new(port)),
        }
    }

    /// IP 是否匹配。None ip matcher 表示匹配所有。对应 Go `matchIP`。
    ///
    /// `ip` 为 `None`（域名目标，但规则有 IP 限制）时返回 `false`——
    /// 与 Go `addr != nil && addr.Family().IsIP()` 一致。
    #[must_use]
    pub fn match_ip(&self, ip: Option<IpAddr>) -> bool {
        match (&self.ip, ip) {
            (None, _) => true,
            (Some(m), Some(addr)) => m.match_ip(addr),
            (Some(_), None) => false,
        }
    }

    /// 完整匹配。对应 Go `Apply`。
    #[must_use]
    pub fn apply(&self, network_index: usize, port: u16, ip: Option<IpAddr>) -> bool {
        if !self.match_network(network_index) {
            return false;
        }
        if !self.match_port(port) {
            return false;
        }
        self.match_ip(ip)
    }
}

/// 把 proto `PortList` 转为 `MemoryPortList`。对应 Go `net.PortListFromProto`。
fn to_mem_port_list(pl: &xray_proto::xray::common::net::PortList) -> MemoryPortList {
    let ranges: Vec<PortRange> = pl
        .range
        .iter()
        .map(|r| PortRange::new(Port::new(r.from as u16), Port::new(r.to as u16)))
        .collect();
    MemoryPortList::new(ranges)
}

/// 从 proto `IpRule` 列表构建 IP matcher（仅消费 Custom CIDR 变体）。
///
/// ponytail: Geoip 变体需要 geodata loader，freedom 直连出口通常用 Custom CIDR；
/// geoip 规则被忽略（None=不限制）。需要 geoip 时升级为 build_optimized_ip_matcher。
fn build_ip_matcher_from_rules(
    rules: &[xray_proto::xray::common::geodata::IpRule],
) -> Option<Arc<dyn IPMatcher>> {
    let cidrs: Vec<xray_geodata::pb::Cidr> = rules
        .iter()
        .filter_map(|r| match &r.value {
            Some(ip_rule::Value::Custom(c)) => {
                c.cidr.as_ref().map(|cidr| xray_geodata::pb::Cidr::new(cidr.ip.clone(), cidr.prefix))
            }
            _ => None,
        })
        .collect();
    if cidrs.is_empty() {
        None
    } else {
        Some(Arc::new(HeuristicIPMatcher::from_cidrs(&cidrs)))
    }
}

/// 缓存的私有 IP matcher（从 [`DEFAULT_BLOCK_PRIVATE_CIDRS`] 构建）。
///
/// 对应 Go `geodata.GetPrivateIPMatcher()`——进程级单例，惰性构建一次。
#[must_use]
pub fn private_ip_matcher() -> Arc<dyn IPMatcher> {
    static MATCHER: LazyLock<Arc<dyn IPMatcher>> = LazyLock::new(|| {
        let cidrs: Vec<xray_geodata::pb::Cidr> = DEFAULT_BLOCK_PRIVATE_CIDRS
            .iter()
            .filter_map(|s| xray_geodata::rule_parser::parse_cidr(s).ok())
            .collect();
        Arc::new(HeuristicIPMatcher::from_cidrs(&cidrs))
    });
    MATCHER.clone()
}

/// 根据入站协议名返回默认 final rule 类型。
///
/// 对应 Go `getDefaultFinalRule`：
/// - `"vless-reverse"` → 阻止所有
/// - `"vless"` / `"vmess"` / `"trojan"` / `"hysteria"` / `"wireguard"` / `"shadowsocks*"` → 阻止私有
/// - 其他 → None（不应用默认规则）
#[must_use]
pub fn get_default_rule_type(inbound_name: &str) -> Option<DefaultRuleType> {
    match inbound_name {
        "vless-reverse" => Some(DefaultRuleType::BlockAll),
        "vless" | "vmess" | "trojan" | "hysteria" | "wireguard" => {
            Some(DefaultRuleType::BlockPrivate)
        }
        other if other.starts_with("shadowsocks") => Some(DefaultRuleType::BlockPrivate),
        _ => None,
    }
}

/// 默认规则类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultRuleType {
    /// 阻止 RFC 1918 私有地址（DEFAULT_BLOCK_PRIVATE_CIDRS）。
    BlockPrivate,
    /// 阻止所有地址。
    BlockAll,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== RuleAction =====

    #[test]
    fn rule_action_roundtrip() {
        assert_eq!(RuleAction::from_proto_value(0), RuleAction::Allow);
        assert_eq!(RuleAction::from_proto_value(1), RuleAction::Block);
        assert_eq!(RuleAction::Allow.to_proto_value(), 0);
        assert_eq!(RuleAction::Block.to_proto_value(), 1);
    }

    // ===== DomainStrategy FORCE_* (v2q) =====

    #[test]
    fn domain_strategy_force_variants_from_i32() {
        // Go transport/internet/config.pb.go: DomainStrategy_FORCE_IP=6..FORCE_IP64=10
        assert_eq!(DomainStrategy::from_i32(6), DomainStrategy::ForceIP);
        assert_eq!(DomainStrategy::from_i32(7), DomainStrategy::ForceIPv4);
        assert_eq!(DomainStrategy::from_i32(8), DomainStrategy::ForceIPv6);
        assert_eq!(DomainStrategy::from_i32(9), DomainStrategy::ForceIPv4v6);
        assert_eq!(DomainStrategy::from_i32(10), DomainStrategy::ForceIPv6v4);
        assert_eq!(DomainStrategy::ForceIP as i32, 6);
        assert_eq!(DomainStrategy::ForceIPv6v4 as i32, 10);
    }

    /// Go config.go `strategy` 表第 0 列 == 2 → ForceIP()。
    #[test]
    fn domain_strategy_force_ip_flag() {
        for s in [
            DomainStrategy::AsIs,
            DomainStrategy::UseIP,
            DomainStrategy::UseIPv4,
            DomainStrategy::UseIPv6,
            DomainStrategy::UseIPv4v6,
            DomainStrategy::UseIPv6v4,
        ] {
            assert!(!s.force_ip(), "{s:?} is not force");
        }
        for s in [
            DomainStrategy::ForceIP,
            DomainStrategy::ForceIPv4,
            DomainStrategy::ForceIPv6,
            DomainStrategy::ForceIPv4v6,
            DomainStrategy::ForceIPv6v4,
        ] {
            assert!(s.force_ip(), "{s:?} is force");
            assert!(s.has_strategy(), "{s:?} has strategy");
        }
    }

    /// Go LookupForIP 的家族选择：PreferIP4/6 + FallbackIP4/6。
    #[test]
    fn domain_strategy_family_preference() {
        use DomainStrategy::*;
        // (strategy, prefer4, prefer6, fb4, fb6)
        let cases = [
            (UseIP, false, false, false, false),
            (UseIPv4, true, false, false, false),
            (UseIPv6, false, true, false, false),
            (UseIPv4v6, true, false, false, true),
            (UseIPv6v4, false, true, true, false),
            (ForceIP, false, false, false, false),
            (ForceIPv4, true, false, false, false),
            (ForceIPv6, false, true, false, false),
            (ForceIPv4v6, true, false, false, true),
            (ForceIPv6v4, false, true, true, false),
        ];
        for (s, p4, p6, f4, f6) in cases {
            assert_eq!(s.prefer_ipv4(), p4, "{s:?}.prefer_ipv4");
            assert_eq!(s.prefer_ipv6(), p6, "{s:?}.prefer_ipv6");
            assert_eq!(s.fallback_ipv4(), f4, "{s:?}.fallback_ipv4");
            assert_eq!(s.fallback_ipv6(), f6, "{s:?}.fallback_ipv6");
            assert_eq!(s.has_fallback(), f4 || f6, "{s:?}.has_fallback");
        }
        assert!(!AsIs.has_strategy());
    }

    // ===== FinalRule::build =====

    #[test]
    fn build_rule_empty_networks_allows_all() {
        let cfg = FinalRuleConfig {
            action: RuleAction::Block,
            networks: vec![],
            ..Default::default()
        };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.network.iter().all(|&v| v));
    }

    #[test]
    fn build_rule_specific_networks() {
        let cfg = FinalRuleConfig {
            action: RuleAction::Allow,
            networks: vec![0, 1], // TCP + UDP
            ..Default::default()
        };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.network[0]); // TCP
        assert!(rule.network[1]); // UDP
        assert!(!rule.network[2]); // 其他
    }

    // ===== FinalRule::match_network =====

    #[test]
    fn match_network_in_range() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: [true, false, false, false, false, false, false, false],
            port: None,
            ip: None,
            block_delay: None,
        };
        assert!(rule.match_network(0)); // TCP
        assert!(!rule.match_network(1)); // UDP
        assert!(!rule.match_network(99)); // 越界
    }

    // ===== FinalRule::match_port =====

    #[test]
    fn match_port_none_matches_all() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: None,
            ip: None,
            block_delay: None,
        };
        assert!(rule.match_port(80));
        assert!(rule.match_port(443));
    }

    #[test]
    fn match_port_list_restricts() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: Some(MemoryPortList::new(vec![
                PortRange::new(Port::new(80), Port::new(80)),
            ])),
            ip: None,
            block_delay: None,
        };
        assert!(rule.match_port(80));
        assert!(!rule.match_port(443));
    }

    // ===== FinalRule::match_ip / apply =====

    #[test]
    fn match_ip_none_matches_all_addresses() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: None,
            ip: None,
            block_delay: None,
        };
        assert!(rule.match_ip(Some("8.8.8.8".parse().unwrap())));
        assert!(rule.match_ip(Some("::1".parse().unwrap())));
        assert!(rule.match_ip(None)); // 无 IP 限制时域名也匹配
    }

    #[test]
    fn apply_full_match_no_ip_restriction() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: [true, true, false, false, false, false, false, false],
            port: None,
            ip: None,
            block_delay: None,
        };
        assert!(rule.apply(0, 80, Some("1.2.3.4".parse().unwrap()))); // TCP:80
        assert!(rule.apply(1, 443, Some("1.2.3.4".parse().unwrap()))); // UDP:443
        assert!(!rule.apply(2, 80, Some("1.2.3.4".parse().unwrap()))); // 网络 2 不允许
    }

    // ===== build_default_rule / private IP blocking =====

    #[test]
    fn build_default_rule_block_private_blocks_rfc1918() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.network.iter().all(|&v| v));
        // TCP:80
        let priv4: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        assert!(rule.apply(0, 80, priv4), "10.0.0.1 should be blocked");
        assert!(
            rule.apply(0, 80, Some("192.168.1.1".parse().unwrap())),
            "192.168.1.1 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("172.16.5.4".parse().unwrap())),
            "172.16.5.4 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("127.0.0.1".parse().unwrap())),
            "127.0.0.1 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("169.254.1.1".parse().unwrap())),
            "169.254.1.1 link-local should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("::1".parse().unwrap())),
            "::1 should be blocked"
        );
    }

    #[test]
    fn build_default_rule_block_private_allows_public() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        assert!(
            !rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())),
            "8.8.8.8 should NOT be blocked"
        );
        assert!(
            !rule.apply(0, 443, Some("1.1.1.1".parse().unwrap())),
            "1.1.1.1 should NOT be blocked"
        );
        assert!(
            !rule.apply(0, 80, Some("2001:4860:4860::8888".parse().unwrap())),
            "public IPv6 should NOT be blocked"
        );
    }

    #[test]
    fn build_default_rule_block_all_blocks_everything() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockAll);
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.ip.is_none(), "BlockAll has no IP matcher → matches all");
        assert!(rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())));
        assert!(rule.apply(0, 80, Some("10.0.0.1".parse().unwrap())));
        assert!(rule.apply(0, 80, None), "BlockAll matches even non-IP");
    }

    #[test]
    fn config_rule_with_custom_cidr_blocks_matching_ip() {
        // 用户配置：Allow 除 8.8.8.0/24 外的所有 → 用 Block 规则覆盖。
        use xray_proto::xray::common::geodata::{Cidr, CidrRule, IpRule};
        let cfg = FinalRuleConfig {
            action: RuleAction::Block,
            networks: vec![],
            ip: vec![IpRule {
                value: Some(ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr {
                        ip: vec![8, 8, 8, 0],
                        prefix: 24,
                    }),
                    reverse_match: false,
                })),
            }],
            ..Default::default()
        };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.ip.is_some(), "custom CIDR rule builds a matcher");
        assert!(rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())), "8.8.8.8 matches");
        assert!(!rule.apply(0, 80, Some("1.2.3.4".parse().unwrap())), "1.2.3.4 no match");
    }

    // ===== get_default_rule_type =====

    #[test]
    fn default_rule_for_known_protocols() {
        assert_eq!(
            get_default_rule_type("vless-reverse"),
            Some(DefaultRuleType::BlockAll)
        );
        assert_eq!(
            get_default_rule_type("vless"),
            Some(DefaultRuleType::BlockPrivate)
        );
        assert_eq!(
            get_default_rule_type("vmess"),
            Some(DefaultRuleType::BlockPrivate)
        );
        assert_eq!(
            get_default_rule_type("trojan"),
            Some(DefaultRuleType::BlockPrivate)
        );
        assert_eq!(
            get_default_rule_type("shadowsocks-aes-256-gcm"),
            Some(DefaultRuleType::BlockPrivate)
        );
    }

    #[test]
    fn default_rule_for_unknown_protocol_is_none() {
        assert_eq!(get_default_rule_type("socks"), None);
        assert_eq!(get_default_rule_type("http"), None);
        assert_eq!(get_default_rule_type(""), None);
    }

    // ===== 常量 =====

    #[test]
    fn default_block_private_cidrs_not_empty() {
        assert!(!DEFAULT_BLOCK_PRIVATE_CIDRS.is_empty());
        // 关键私有地址段必须包含
        assert!(DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&"10.0.0.0/8"));
        assert!(DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&"192.168.0.0/16"));
        assert!(DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&"172.16.0.0/12"));
        assert!(DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&"127.0.0.0/8"));
    }

    #[test]
    fn all_networks_constant() {
        assert!(ALL_NETWORKS.iter().all(|&v| v));
    }

    // ===== proto roundtrip =====

    #[test]
    fn proto_roundtrip_minimal() {
        let cfg = Config {
            user_level: 3,
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn proto_roundtrip_with_fragment() {
        let cfg = Config {
            fragment: Some(Fragment {
                packets_from: 1,
                packets_to: 100,
                length_min: 100,
                length_max: 500,
                interval_min: 0,
                interval_max: 10,
                max_split_min: 2,
                max_split_max: 8,
            }),
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
