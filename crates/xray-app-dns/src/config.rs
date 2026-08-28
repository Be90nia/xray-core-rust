//! DNS 配置辅助：查询策略、IP 选项、本地 TLD 规则、随机 tag 生成。
//!
//! 对应 Go `app/dns/config.go`。proto 生成的 `Config` 结构未在 Rust 端启用
//! （`protos/app/dns/` 暂未纳入 build），上层用本模块提供的 enum + helpers
//! 构造配置，避免依赖 prost 生成。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use xray_common::net::address::Address;
use xray_features::dns::DnsError as FeaturesDnsError;

use crate::error::DnsError;

/// DNS 查询策略。对应 Go `QueryStrategy` enum。
///
/// proto 字段值（来自 `app/dns/config.proto`）：
/// - `USE_IP = 0`：返回 IPv4 + IPv6
/// - `USE_SYS = 4`：跟随系统偏好（业务层置 `check_system = true`）
/// - `USE_IP4 = 1`：仅返回 IPv4
/// - `USE_IP6 = 2`：仅返回 IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum QueryStrategy {
    /// 同时查询 IPv4 + IPv6。
    UseIp,
    /// 跟随系统 DNS 偏好。
    UseSys,
    /// 仅查询 IPv4。
    UseIp4,
    /// 仅查询 IPv6。
    UseIp6,
}

impl QueryStrategy {
    /// proto 字段值（与 Go enum 编号一致）。
    #[must_use]
    pub const fn to_proto_i32(self) -> i32 {
        match self {
            Self::UseIp => 0,
            Self::UseIp4 => 1,
            Self::UseIp6 => 2,
            Self::UseSys => 4,
        }
    }

    /// 从 proto i32 反解（未知值返回 `None`）。
    #[must_use]
    pub const fn from_proto_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::UseIp),
            1 => Some(Self::UseIp4),
            2 => Some(Self::UseIp6),
            4 => Some(Self::UseSys),
            _ => None,
        }
    }

    /// 推导 IP 选项：是否启用 IPv4 / IPv6。
    ///
    /// 对应 Go `dns.go::New` 中 switch `config.QueryStrategy` 的 `ipOption` 分支。
    /// 返回 `(ipv4_enable, ipv6_enable)`；`UseSys` 时额外标记 `check_system`。
    #[must_use]
    pub const fn ip_enables(self) -> (bool, bool) {
        match self {
            Self::UseIp | Self::UseSys => (true, true),
            Self::UseIp4 => (true, false),
            Self::UseIp6 => (false, true),
        }
    }
}

/// DNS 查询的 IP 过滤选项。对应 Go `features/dns.IPOption`（client.go:10-15）。
///
/// 类型本体在 `xray-features::dns`（Go 同样定义于 features/dns，app/dns 引用之）；
/// 此处 re-export 保持 `crate::config::IpOption` 路径兼容。
pub use xray_features::dns::IpOption;

/// 从查询策略推导默认 IPOption（不含 `UseSys` 的系统探测）。
/// `fake_enable` 默认 false，对应 Go `New()` 中初始 `ipOption`（dns.go:52-82）。
#[must_use]
pub const fn ip_option_from_strategy(s: QueryStrategy) -> IpOption {
    let (v4, v6) = s.ip_enables();
    IpOption {
        ipv4_enable: v4,
        ipv6_enable: v6,
        fake_enable: false,
    }
}

/// 按 `override_strategy` 覆盖基线 `IpOption`。
///
/// 对应 Go `app/dns/nameserver.go::ResolveIpOptionOverride`：
/// 子 ns 的 `QueryStrategy` 若为 `nil`（这里用 `Option<QueryStrategy>`）则保持基线，
/// 否则按子 ns 策略重算。
#[must_use]
pub fn resolve_ip_option_override(
    base: IpOption,
    override_strategy: Option<QueryStrategy>,
) -> IpOption {
    match override_strategy {
        Some(s) => {
            let (v4, v6) = s.ip_enables();
            IpOption {
                ipv4_enable: v4 && base.ipv4_enable,
                ipv6_enable: v6 && base.ipv6_enable,
                fake_enable: base.fake_enable,
            }
        }
        None => base,
    }
}

/// 将 `Address` 列表转为 `IpAddr` 列表。任一非 IP 则失败。
///
/// 对应 Go `app/dns/config.go::toNetIP`。
pub fn to_net_ip(addrs: &[Address]) -> Result<Vec<IpAddr>, DnsError> {
    let mut ips = Vec::with_capacity(addrs.len());
    for addr in addrs {
        match addr {
            Address::IPv4(v) => ips.push(IpAddr::V4(*v)),
            Address::IPv6(v) => ips.push(IpAddr::V6(*v)),
            other => {
                return Err(FeaturesDnsError::Other(format!(
                    "not an ip address: {other:?}"
                ))
                .into());
            }
        }
    }
    Ok(ips)
}

/// 生成默认 DNS 服务 tag（带随机后缀）。
///
/// 对应 Go `app/dns/config.go::generateRandomTag`，
/// 格式：`xray.system.<uuid>`。
#[must_use]
pub fn generate_random_tag() -> String {
    format!("xray.system.{}", uuid::Uuid::new_v4())
}

/// 校验 `ClientIp` 字节长度（合法：0 / 4 / 16）。
///
/// 对应 Go `dns.go::New` 顶部对 `config.ClientIp` 的 switch。
pub fn validate_client_ip_len(len: usize) -> Result<(), DnsError> {
    match len {
        0 | 4 | 16 => Ok(()),
        other => Err(DnsError::InvalidClientIpLength(other)),
    }
}

/// 将 4 字节 IPv4 数据包装为 `IpAddr`。
#[must_use]
pub fn ipv4_from_bytes(b: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(b))
}

/// 将 16 字节 IPv6 数据包装为 `IpAddr`。
#[must_use]
pub fn ipv6_from_bytes(b: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strategy_proto_roundtrip() {
        for s in [
            QueryStrategy::UseIp,
            QueryStrategy::UseIp4,
            QueryStrategy::UseIp6,
            QueryStrategy::UseSys,
        ] {
            assert_eq!(QueryStrategy::from_proto_i32(s.to_proto_i32()), Some(s));
        }
        assert_eq!(QueryStrategy::from_proto_i32(99), None);
    }

    #[test]
    fn ip_enables_match_go_switch() {
        assert_eq!(QueryStrategy::UseIp.ip_enables(), (true, true));
        assert_eq!(QueryStrategy::UseSys.ip_enables(), (true, true));
        assert_eq!(QueryStrategy::UseIp4.ip_enables(), (true, false));
        assert_eq!(QueryStrategy::UseIp6.ip_enables(), (false, true));
    }

    #[test]
    fn ip_option_from_strategy_has_fake_disabled() {
        let o = ip_option_from_strategy(QueryStrategy::UseIp);
        assert!(o.ipv4_enable && o.ipv6_enable);
        assert!(!o.fake_enable);
    }

    #[test]
    fn ip_option_is_empty_when_both_disabled() {
        let o = IpOption {
            ipv4_enable: false,
            ipv6_enable: false,
            fake_enable: true,
        };
        assert!(o.is_empty());
    }

    #[test]
    fn override_strategy_changes_enables() {
        let base = IpOption::all();
        let o = resolve_ip_option_override(base, Some(QueryStrategy::UseIp4));
        assert!(o.ipv4_enable);
        assert!(!o.ipv6_enable);
        assert!(o.fake_enable);
    }

    #[test]
    fn override_none_keeps_base() {
        let base = IpOption::all();
        let o = resolve_ip_option_override(base, None);
        assert_eq!(o, base);
    }

    #[test]
    fn override_intersect_with_base_when_v6_disabled_in_base() {
        let base = IpOption {
            ipv4_enable: true,
            ipv6_enable: false,
            fake_enable: false,
        };
        // 子 ns 想查 IPv6，但基线已禁用，结果 IPv6 仍禁用。
        let o = resolve_ip_option_override(base, Some(QueryStrategy::UseIp6));
        assert!(!o.ipv4_enable);
        assert!(!o.ipv6_enable);
    }

    #[test]
    fn to_net_ip_returns_addresses_in_order() {
        let addrs = vec![
            Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)),
            Address::IPv6(Ipv6Addr::LOCALHOST),
        ];
        let ips = to_net_ip(&addrs).unwrap();
        assert_eq!(ips.len(), 2);
        assert!(matches!(ips[0], IpAddr::V4(_)));
        assert!(matches!(ips[1], IpAddr::V6(_)));
    }

    #[test]
    fn to_net_ip_fails_on_domain() {
        let addrs = vec![Address::Domain("example.com".to_string())];
        assert!(to_net_ip(&addrs).is_err());
    }

    #[test]
    fn generate_random_tag_has_prefix() {
        let tag = generate_random_tag();
        assert!(tag.starts_with("xray.system."));
        assert_ne!(generate_random_tag(), generate_random_tag());
    }

    #[test]
    fn validate_client_ip_len_accepts_canonical_lengths() {
        assert!(validate_client_ip_len(0).is_ok());
        assert!(validate_client_ip_len(4).is_ok());
        assert!(validate_client_ip_len(16).is_ok());
        assert!(validate_client_ip_len(7).is_err());
    }
}
