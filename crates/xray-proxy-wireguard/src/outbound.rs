//! WireGuard 出站 Handler——将用户 TCP/UDP 流量通过 WireGuard tunnel 转发。
//!
//! 对应 Go `proxy/wireguard/client.go` 的 `Handler.Process`。
//!
//! ## 流程
//!
//! 1. 拨号时在 smoltcp netstack 上创建 TCP/UDP socket
//! 2. socket 由 driver task 驱动——通过 WireGuard tunnel 与远端 peer 通信
//! 3. 用户读写 socket 的数据被封装为 IP 包送入 smoltcp
//!
//! ## 当前限制（与 freedom 切片2 一致）
//!
//! `dial` 建立 socket 后立即返回——上层桥接（Link ↔ smoltcp socket）留待后续切片。

use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::session::Session;
use xray_features::outbound::{OutboundError, OutboundHandler};

use crate::config::DeviceConfig;
use crate::driver::{bind_udp_socket, WgDriver};
use crate::error::{Result, WgError};
use crate::netstack::WgNetStack;
use crate::peer::{shared_peer, SharedPeer};

/// WireGuard 出站 Handler。
///
/// 持有 driver + smoltcp 网栈句柄。dial 在 netstack 上建 socket。
pub struct WireguardOutboundHandler {
    tag: String,
    /// driver task 句柄。
    driver: Arc<WgDriver>,
    /// 共享的 smoltcp 网栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
}

impl WireguardOutboundHandler {
    /// 从 DeviceConfig 构造出站 Handler 并启动 driver。
    ///
    /// - 解析 peer endpoint
    /// - 绑定 UDP socket（本地随机端口）
    /// - 创建 smoltcp 网栈（从 config.endpoint 派生 interface 地址）
    /// - spawn driver task
    pub async fn new(tag: impl Into<String>, config: &DeviceConfig) -> Result<Self> {
        let tag = tag.into();
        if config.peers.is_empty() {
            return Err(WgError::InvalidConfig("wireguard outbound requires at least one peer".into()));
        }
        let peer_cfg = &config.peers[0];

        // peer session
        let peer: SharedPeer = shared_peer(config, peer_cfg)?;

        // 远端 endpoint（必须是 IP:port，DNS 解析由上层负责）
        let remote_addr = crate::peer::parse_endpoint_addr(&peer_cfg.endpoint)?;

        // 绑定本地 UDP（与远端同族）
        let bind_addr = if remote_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = bind_udp_socket(bind_addr).await?;

        // smoltcp 网栈——从 config.endpoint 解析 interface 地址
        let local_cidrs = parse_local_cidrs(config)?;
        let mtu = config.effective_mtu() as usize;
        let netstack = Arc::new(AsyncMutex::new(WgNetStack::new(&local_cidrs, mtu)));

        // driver
        let driver = Arc::new(WgDriver::new(Arc::clone(&peer), sock, Arc::clone(&netstack)));
        driver.set_remote(remote_addr);
        Arc::clone(&driver).spawn().await?;

        Ok(Self { tag, driver, netstack })
    }

    /// 暴露共享 netstack 句柄（高级用法——上层桥接用）。
    #[must_use]
    pub fn netstack(&self) -> &Arc<AsyncMutex<WgNetStack>> {
        &self.netstack
    }
}

#[async_trait]
impl OutboundHandler for WireguardOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 在 smoltcp 网栈上创建 socket，发起到 destination 的连接。
    ///
    /// 当前实现：建立 socket 后立即返回 Ok——实际的 Link 桥接待后续切片。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> std::result::Result<(), OutboundError> {
        // 解析目标 IP（Domain 暂不支持——DNS 留待接入上层）
        let ip = match destination.address() {
            Address::IPv4(v4) => IpAddr::V4(*v4),
            Address::IPv6(v6) => IpAddr::V6(*v6),
            Address::Domain(_) => {
                return Err(OutboundError::ConnectionFailed(
                    "wireguard outbound 暂不支持 Domain（DNS 解析由上层负责）".into(),
                ));
            }
        };
        let port = destination.port().value();

        let mut stack = self.netstack.lock().await;
        let handle = match destination.network() {
            xray_common::net::network::Network::TCP => {
                let handle = stack.add_tcp_socket();
                let remote_addr = match ip {
                    IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets())),
                    IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets())),
                };
                stack
                    .tcp_connect(handle, remote_addr, port)
                    .map_err(|e| OutboundError::ConnectionFailed(format!("smoltcp tcp_connect: {e}")))?;
                tracing::debug!(tag = %self.tag, %ip, port, "wireguard outbound tcp_connect initiated");
                handle
            }
            xray_common::net::network::Network::UDP => {
                let handle = stack.add_udp_socket();
                stack.with_udp_socket(handle, |s| {
                    // ponytail: 简化——bind 到 0.0.0.0:0
                    let _ = s.bind(0);
                });
                tracing::debug!(tag = %self.tag, %ip, port, "wireguard outbound udp socket created");
                handle
            }
            xray_common::net::network::Network::Unix => {
                return Err(OutboundError::ConnectionFailed(
                    "wireguard outbound 不支持 Unix socket".into(),
                ));
            }
        };
        // ponytail: socket handle 立即移除——实际桥接（Link ↔ socket）留待后续切片
        // 当前仅验证 dial 流程（socket 创建 + connect 发起）可用
        stack.remove_socket(handle);
        Ok(())
    }

    /// 可以处理 TCP/UDP 目标（IP 优先；Domain 暂不支持）。
    fn can_handle(&self, destination: &Destination) -> bool {
        matches!(
            destination.address(),
            Address::IPv4(_) | Address::IPv6(_)
        ) && matches!(
            destination.network(),
            xray_common::net::network::Network::TCP | xray_common::net::network::Network::UDP
        )
    }
}

/// 从 DeviceConfig.endpoint 解析为 smoltcp IpCidr。
///
/// 复用 [`crate::wireguard::parse_endpoints`] 的解析逻辑。
fn parse_local_cidrs(config: &DeviceConfig) -> Result<Vec<smoltcp::wire::IpCidr>> {
    let parsed = crate::wireguard::parse_endpoints(config)?;
    parsed
        .addrs
        .into_iter()
        .map(|addr| {
            let cidr_prefix = if addr.is_ipv4() { 32 } else { 128 };
            let smoltcp_addr = match addr {
                IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets())),
                IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets())),
            };
            Ok(smoltcp::wire::IpCidr::new(smoltcp_addr, cidr_prefix))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, PeerConfig};

    fn make_keypair(seed: u8) -> (String, String) {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes: [u8; 32] = [seed; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
    }

    #[test]
    fn parse_local_cidrs_handles_ipv4() {
        let (sec, _) = make_keypair(0x11);
        let cfg = DeviceConfig {
            secret_key: sec,
            endpoint: vec!["10.0.0.2/32".into()],
            ..Default::default()
        };
        let cidrs = parse_local_cidrs(&cfg).expect("parse");
        assert_eq!(cidrs.len(), 1);
    }

    #[test]
    fn parse_local_cidrs_dual_stack() {
        let (sec, _) = make_keypair(0x22);
        let cfg = DeviceConfig {
            secret_key: sec,
            endpoint: vec!["10.0.0.2/32".into(), "fd00::1/128".into()],
            ..Default::default()
        };
        let cidrs = parse_local_cidrs(&cfg).expect("parse");
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn parse_local_cidrs_empty_config_ok() {
        // 空 endpoint——返回空 cidr 列表（构造 handler 时会失败，但解析本身通过）
        let (sec, _) = make_keypair(0x33);
        let cfg = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let cidrs = parse_local_cidrs(&cfg).expect("parse");
        assert!(cidrs.is_empty());
    }

    #[tokio::test]
    async fn new_rejects_config_without_peers() {
        let (sec, _) = make_keypair(0x44);
        let cfg = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let result = WireguardOutboundHandler::new("test", &cfg).await;
        assert!(result.is_err(), "should reject empty peers");
    }

    #[tokio::test]
    async fn new_rejects_invalid_endpoint() {
        let (sec, pub_) = make_keypair(0x55);
        let cfg = DeviceConfig {
            secret_key: sec,
            peers: vec![PeerConfig {
                public_key: pub_,
                endpoint: "not-a-valid-endpoint".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = WireguardOutboundHandler::new("test", &cfg).await;
        assert!(result.is_err(), "should reject invalid endpoint");
    }
}
