//! Dokodemo-door 出站 → DialBridge 适配器。
//!
//! Dokodemo outbound 语义：忽略 dispatcher 传入的 dest，始终拨号到
//! 配置的 `rewrite_address:rewrite_port`（"任意地址"→固定目标的反向代理）。
//!
//! 对应 Go `proxy/dokodemo/dokodemo.go` 的 `Process` 方法中 dial 逻辑。
//! Go 中 dokodemo 是 inbound-only，但 Rust 为对称性提供 outbound dial_fn。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::sync::Arc;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::{Config, PredefinedAddress};

/// Dokodemo 出站配置（从 Config 提取的拨号目标）。
///
/// 仅保留 outbound 所需的 `rewrite_address` + `rewrite_port`，
/// 不含 inbound 用的 `allowed_networks` / `follow_redirect` 等。
#[derive(Debug, Clone)]
pub struct DokodemoOutboundConfig {
    /// 目标地址（从 Config::predefined_address 提取）。
    address: Address,
    /// 目标端口。
    port: Port,
    /// 网络类型（TCP 或 UDP）。
    network: Network,
}

impl DokodemoOutboundConfig {
    /// 从 Config 构造出站配置。
    ///
    /// 返回 `None` 表示 Config 缺少 `rewrite_address` 或端口非法
    /// （对应 Go `Process` 中 `!dest.IsValid()` 的错误路径）。
    #[must_use]
    pub fn from_config(config: &Config) -> Option<Self> {
        let addr = config.predefined_address()?;
        let port = u16::try_from(config.rewrite_port).ok()?;
        let address = match addr {
            PredefinedAddress::Ip(ip) => match ip {
                std::net::IpAddr::V4(v4) => Address::IPv4(v4),
                std::net::IpAddr::V6(v6) => Address::IPv6(v6),
            },
            PredefinedAddress::Domain(s) => Address::Domain(s),
        };
        // 默认 TCP；将 dokodemo config Network 映射到 xray_common Network
        let network = if config.allows_network(crate::config::Network::Tcp) {
            Network::TCP
        } else {
            Network::UDP
        };
        Some(Self {
            address,
            port: Port::new(port),
            network,
        })
    }

    /// 直接从地址/端口/网络类型构造。
    #[must_use]
    pub fn new(address: Address, port: Port, network: Network) -> Self {
        Self {
            address,
            port,
            network,
        }
    }

    /// 返回目标 Destination。
    #[must_use]
    pub fn destination(&self) -> Destination {
        match self.network {
            Network::TCP => Destination::tcp(self.address.clone(), self.port),
            Network::UDP => Destination::udp(self.address.clone(), self.port),
            // dokodemo 不支持 Unix socket outbound，降级为 TCP
            Network::Unix => Destination::tcp(self.address.clone(), self.port),
        }
    }
}

/// 构造 Dokodemo 的 DialFn 闭包。
///
/// 闭包捕获 [`DokodemoOutboundConfig`]——每次调用忽略传入的 dest，
/// 始终拨号到配置的 rewrite_address:rewrite_port。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_dokodemo_dial_fn(config: DokodemoOutboundConfig) -> DialFn {
    Arc::new(move |_dest: &Destination| {
        let target = config.destination();
        Box::pin(async move {
            let sockopt = SocketOptions::default();
            let conn: Box<dyn Connection> = dial_system(&target, &sockopt)
                .await
                .map_err(|e| format!("dokodemo dial: {e}"))?;
            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;
    use xray_proto::xray::common::net::IpOrDomain as ProtoIpOrDomain;

    fn make_ipv4_config(ip: [u8; 4], port: u32) -> Config {
        Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(ip.to_vec())),
            }),
            rewrite_port: port,
            allowed_networks: vec![crate::config::Network::Tcp],
            ..Default::default()
        }
    }
    #[test]
    fn from_config_extracts_ipv4() {
        let cfg = make_ipv4_config([192, 168, 1, 1], 8080);
        let out = DokodemoOutboundConfig::from_config(&cfg).expect("should extract");
        assert_eq!(out.port.value(), 8080);
        match out.address {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [192, 168, 1, 1]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn from_config_none_when_no_address() {
        let cfg = Config::default();
        assert!(DokodemoOutboundConfig::from_config(&cfg).is_none());
    }

    #[test]
    fn from_config_none_when_port_overflow() {
        let cfg = Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(vec![192, 168, 1, 1])),
            }),
            rewrite_port: 70_000,
            ..Default::default()
        };
        assert!(DokodemoOutboundConfig::from_config(&cfg).is_none());
    }

    #[test]
    fn destination_tcp() {
        let out = DokodemoOutboundConfig::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
            Network::TCP,
        );
        let dest = out.destination();
        assert_eq!(dest.port().value(), 443);
    }
}
