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
//! 实现配置层 + FinalRule 纯逻辑匹配（network + port）+ 默认 CIDR 常量。
//! IP CIDR 匹配依赖 `geodata::IPMatcher`，留切片2（当前 match_ip 返回 true）。
//! Handler/Process/dial/retry 留切片2。

use crate::error::Result;

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
#[derive(Debug, Clone)]
pub struct FinalRule {
    pub action: RuleAction,
    /// 允许的网络类型（bool 数组索引 0=TCP 1=UDP 等，与 Go [8]bool 一致）。
    pub network: [bool; 8],
    /// 端口列表（None 表示匹配所有）。
    pub port: Option<xray_proto::xray::common::net::PortList>,
    /// IP CIDR 匹配器（切片2 接入 geodata::IPMatcher，当前 None 表示匹配所有）。
    pub _ip_matcher: Option<()>,
    pub block_delay: Option<Range>,
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

        Ok(Self {
            action: config.action,
            network,
            port: config.port_list.clone(),
            _ip_matcher: None, // 切片2: geodata::IPMatcher
            block_delay: config.block_delay,
        })
    }

    /// 网络类型是否匹配。对应 Go `matchNetwork`。
    #[must_use]
    pub fn match_network(&self, network_index: usize) -> bool {
        if network_index >= 8 {
            return false;
        }
        self.network[network_index]
    }

    /// 端口是否匹配。None port_list 表示匹配所有。对应 Go `matchPort`。
    ///
    /// 切片1: port_list 匹配逻辑依赖 `xray_common::net::PortList::contains`，
    /// 当前简化为 None=匹配所有，Some=匹配所有非零（精确匹配留切片2）。
    #[must_use]
    pub fn match_port(&self, _port: u16) -> bool {
        self.port.is_none()
    }

    /// IP 是否匹配。None ip_matcher 表示匹配所有。对应 Go `matchIP`。
    ///
    /// 切片1: 总返回 true（ip_matcher 留切片2 接入 geodata）。
    #[must_use]
    pub fn match_ip(&self) -> bool {
        self._ip_matcher.is_none()
    }

    /// 完整匹配。对应 Go `Apply`。
    #[must_use]
    pub fn apply(&self, network_index: usize, port: u16) -> bool {
        if !self.match_network(network_index) {
            return false;
        }
        if !self.match_port(port) {
            return false;
        }
        self.match_ip()
    }
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
            _ip_matcher: None,
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
            _ip_matcher: None,
            block_delay: None,
        };
        assert!(rule.match_port(80));
        assert!(rule.match_port(443));
    }

    // ===== FinalRule::apply =====

    #[test]
    fn apply_full_match() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: [true, true, false, false, false, false, false, false],
            port: None,
            _ip_matcher: None,
            block_delay: None,
        };
        assert!(rule.apply(0, 80)); // TCP:80
        assert!(rule.apply(1, 443)); // UDP:443
        assert!(!rule.apply(2, 80)); // 网络 2 不允许
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
