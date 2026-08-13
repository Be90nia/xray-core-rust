//! Dokodemo-door 配置。
//!
//! 对应 Go `proxy/dokodemo/config.go` + `config.proto`。
//!
//! ## 协议本质
//!
//! Dokodemo（"どこでも"=任意地址）入站把所有连接重定向到一个固定的目标地址
//! （`rewrite_address` + `rewrite_port`），相当于反向代理的"透明转发"。常用于：
//!
//! - 把任意端口的流量转发到上游固定服务器
//! - 配合 `follow_redirect` + iptables REDIRECT 实现透明代理（Linux SO_ORIGINAL_DST）
//! - 通过 `port_map` 实现端口映射
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 切片1 实现配置层 + [`Config::predefined_address`]（对应 Go `GetPredefinedAddress`）+
//! 网络类型校验（[`Config::allows_network`]）。Handler/Process/fakeudp 留切片2
//! （依赖 transport/session/policy + Linux SO_ORIGINAL_DST syscall）。

use std::collections::HashMap;
use std::net::IpAddr;

use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;
use xray_proto::xray::common::net::IpOrDomain as ProtoIpOrDomain;
use xray_proto::xray::proxy::dokodemo::Config as ProtoConfig;

use crate::error::Result;

/// 预定义地址解析结果。对应 Go `GetPredefinedAddress` 返回的 `net.Address`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredefinedAddress {
    /// IPv4 或 IPv6 地址。
    Ip(IpAddr),
    /// 域名（DNS 解析由上层处理）。
    Domain(String),
}

/// 网络类型枚举。对应 proto `xray.common.net.Network`。
///
/// Go 端用 `Network_TCP = 0` / `Network_UDP = 1`，Rust 端 prost 生成模块嵌套。
/// 这里强类型化为枚举便于匹配。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum Network {
    #[default]
    Tcp = 0,
    Udp = 1,
}

impl Network {
    /// 从 prost 原始 i32 值构造。非法值返回 `None`。
    #[must_use]
    pub fn from_proto_value(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Tcp),
            1 => Some(Self::Udp),
            _ => None,
        }
    }

    /// 转换为 prost i32 值。
    #[must_use]
    pub fn to_proto_value(self) -> i32 {
        self as i32
    }

}

/// Dokodemo 配置。对应 proto `xray.proxy.dokodemo.Config`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    /// 允许的网络类型列表。空列表表示允许所有。
    pub allowed_networks: Vec<Network>,
    /// 重写目标地址。`follow_redirect=false` 时必填。
    pub rewrite_address: Option<ProtoIpOrDomain>,
    /// 重写目标端口。
    pub rewrite_port: u32,
    /// 端口映射：原始端口（字符串）→ 目标端口（字符串）。
    pub port_map: HashMap<String, String>,
    /// 是否跟随 iptables REDIRECT 的原始目标地址（Linux SO_ORIGINAL_DST）。
    pub follow_redirect: bool,
    /// 用户级别（用于 policy 匹配）。
    pub user_level: u32,
}

impl Config {
    /// 返回预定义地址。对应 Go `GetPredefinedAddress`。
    ///
    /// 当 `rewrite_address` 为空或无法解析时返回 `None`。
    /// 调用方应处理 `None` 情况（如 `follow_redirect=true` 时可降级到 SO_ORIGINAL_DST）。
    #[must_use]
    pub fn predefined_address(&self) -> Option<PredefinedAddress> {
        let addr = self.rewrite_address.as_ref()?;
        let inner = addr.address.as_ref()?;
        match inner {
            ProtoAddress::Ip(bytes) => {
                let ip = match bytes.len() {
                    4 => IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(bytes);
                        IpAddr::from(arr)
                    }
                    _ => return None,
                };
                Some(PredefinedAddress::Ip(ip))
            }
            ProtoAddress::Domain(s) => Some(PredefinedAddress::Domain(s.clone())),
        }
    }

    /// 判断网络类型是否被允许。空 `allowed_networks` 列表表示允许所有。
    #[must_use]
    pub fn allows_network(&self, net: Network) -> bool {
        if self.allowed_networks.is_empty() {
            return true;
        }
        self.allowed_networks.contains(&net)
    }

    /// 应用端口映射。对应 Go `Process()` 第 101-109 行 `portMap` 逻辑。
    ///
    /// 当 `local_port`（监听端口的字符串形式）匹配 `port_map` 中的 key 时，
    /// 解析 value（`"host:port"` 格式）并返回覆盖值。
    ///
    /// - value 格式 `"host:port"`：同时覆盖地址和端口
    /// - value 格式 `":port"`：仅覆盖端口
    /// - value 格式 `"host:"`：仅覆盖地址
    /// - 无冒号或不匹配：返回 `None`（与 Go `SplitHostPort` 忽略错误一致）
    #[must_use]
    pub fn apply_port_map(&self, local_port: &str) -> Option<(Option<String>, Option<u16>)> {
        let mapping = self.port_map.get(local_port)?;
        let (host, port_str) = mapping.rsplit_once(':')?;
        let host = if host.is_empty() {
            None
        } else {
            // 去除 IPv6 方括号："[::1]" → "::1"
            let h = host.trim_start_matches('[').trim_end_matches(']');
            if h.is_empty() { None } else { Some(h.to_string()) }
        };
        let port = port_str.parse::<u16>().ok();
        if host.is_none() && port.is_none() {
            return None;
        }
        Some((host, port))
    }

    /// 从 prost Config 构造。
    pub fn from_proto(p: ProtoConfig) -> Result<Self> {
        Ok(Self {
            allowed_networks: p
                .allowed_networks
                .into_iter()
                .filter_map(Network::from_proto_value)
                .collect(),
            rewrite_address: p.rewrite_address,
            rewrite_port: p.rewrite_port,
            port_map: p.port_map.into_iter().collect(),
            follow_redirect: p.follow_redirect,
            user_level: p.user_level,
        })
    }

    /// 转换为 prost Config。
    #[must_use]
    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            allowed_networks: self
                .allowed_networks
                .iter().copied().map(Network::to_proto_value)
                .collect(),
            rewrite_address: self.rewrite_address.clone(),
            rewrite_port: self.rewrite_port,
            port_map: self.port_map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            follow_redirect: self.follow_redirect,
            user_level: self.user_level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;

    fn make_ip_or_domain_ip(bytes: &[u8]) -> ProtoIpOrDomain {
        ProtoIpOrDomain {
            address: Some(ProtoAddress::Ip(bytes.to_vec())),
        }
    }

    fn make_ip_or_domain_domain(s: &str) -> ProtoIpOrDomain {
        ProtoIpOrDomain {
            address: Some(ProtoAddress::Domain(s.to_string())),
        }
    }

    // ===== Network =====

    #[test]
    fn network_roundtrip() {
        for n in [Network::Tcp, Network::Udp] {
            assert_eq!(Network::from_proto_value(n.to_proto_value()), Some(n));
        }
    }

    #[test]
    fn network_invalid_value_returns_none() {
        assert_eq!(Network::from_proto_value(99), None);
    }

    // ===== predefined_address =====

    #[test]
    fn predefined_address_none_when_unset() {
        let cfg = Config::default();
        assert!(cfg.predefined_address().is_none());
    }

    #[test]
    fn predefined_address_ipv4() {
        let cfg = Config {
            rewrite_address: Some(make_ip_or_domain_ip(&[192, 168, 1, 1])),
            ..Default::default()
        };
        match cfg.predefined_address() {
            Some(PredefinedAddress::Ip(IpAddr::V4(v4))) => {
                assert_eq!(v4.octets(), [192, 168, 1, 1]);
            }
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn predefined_address_ipv6() {
        let cfg = Config {
            rewrite_address: Some(make_ip_or_domain_ip(&[
                0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            ..Default::default()
        };
        match cfg.predefined_address() {
            Some(PredefinedAddress::Ip(IpAddr::V6(v6))) => {
                assert_eq!(v6.segments()[0], 0xfd00);
            }
            other => panic!("expected IPv6, got {other:?}"),
        }
    }

    #[test]
    fn predefined_address_invalid_ip_length_returns_none() {
        let cfg = Config {
            rewrite_address: Some(make_ip_or_domain_ip(&[1, 2, 3])), // 非法长度
            ..Default::default()
        };
        assert!(cfg.predefined_address().is_none());
    }

    #[test]
    fn predefined_address_domain() {
        let cfg = Config {
            rewrite_address: Some(make_ip_or_domain_domain("example.com")),
            ..Default::default()
        };
        match cfg.predefined_address() {
            Some(PredefinedAddress::Domain(s)) => assert_eq!(s, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    // ===== allows_network =====

    #[test]
    fn allows_network_empty_list_allows_all() {
        let cfg = Config::default();
        assert!(cfg.allows_network(Network::Tcp));
        assert!(cfg.allows_network(Network::Udp));
    }

    #[test]
    fn allows_network_specific_list() {
        let cfg = Config {
            allowed_networks: vec![Network::Tcp],
            ..Default::default()
        };
        assert!(cfg.allows_network(Network::Tcp));
        assert!(!cfg.allows_network(Network::Udp));
    }

    // ===== proto roundtrip =====

    #[test]
    fn proto_roundtrip_minimal() {
        let cfg = Config {
            follow_redirect: true,
            user_level: 5,
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn proto_roundtrip_full() {
        let cfg = Config {
            allowed_networks: vec![Network::Tcp, Network::Udp],
            rewrite_address: Some(make_ip_or_domain_domain("target.example.com")),
            rewrite_port: 8443,
            port_map: [
                ("80".to_string(), "8080".to_string()),
                ("443".to_string(), "8443".to_string()),
            ]
            .into_iter()
            .collect(),
            follow_redirect: false,
            user_level: 1,
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    // ===== apply_port_map =====

    fn make_port_map_cfg(entries: &[(&str, &str)]) -> Config {
        Config {
            port_map: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn port_map_host_port() {
        let cfg = make_port_map_cfg(&[("80", "192.168.1.1:8080")]);
        let (host, port) = cfg.apply_port_map("80").expect("should map");
        assert_eq!(host.as_deref(), Some("192.168.1.1"));
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn port_map_port_only() {
        let cfg = make_port_map_cfg(&[("80", ":8080")]);
        let (host, port) = cfg.apply_port_map("80").expect("should map");
        assert_eq!(host, None);
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn port_map_host_only() {
        let cfg = make_port_map_cfg(&[("80", "example.com:")]);
        let (host, port) = cfg.apply_port_map("80").expect("should map");
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(port, None);
    }

    #[test]
    fn port_map_ipv6() {
        let cfg = make_port_map_cfg(&[("80", "[::1]:9090")]);
        let (host, port) = cfg.apply_port_map("80").expect("should map");
        assert_eq!(host.as_deref(), Some("::1"));
        assert_eq!(port, Some(9090));
    }

    #[test]
    fn port_map_no_match_returns_none() {
        let cfg = make_port_map_cfg(&[("80", "192.168.1.1:8080")]);
        assert!(cfg.apply_port_map("443").is_none());
    }

    #[test]
    fn port_map_no_colon_returns_none() {
        // Go SplitHostPort silently fails on bare port; we match.
        let cfg = make_port_map_cfg(&[("80", "8080")]);
        assert!(cfg.apply_port_map("80").is_none());
    }

    #[test]
    fn port_map_empty_map_returns_none() {
        let cfg = Config::default();
        assert!(cfg.apply_port_map("80").is_none());
    }
}
