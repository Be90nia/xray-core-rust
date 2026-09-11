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
//! 生产出站路径走 [`crate::dispatcher::make_wireguard_dial_fn`]（DialBridge）；
//! 本 handler 仅作为 driver/netstack 的 lazy-init 容器（bd 7v0k⑤：原 stub
//! `impl OutboundHandler`（dial 建 socket 后返 Ok 无数据流动的公共 API 陷阱）
//! 已删除）。

use std::net::SocketAddr;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;

use crate::config::DeviceConfig;
use crate::driver::{bind_udp_socket, WgDriver, WgTransport, DialedUdp};
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
    /// 从 DeviceConfig 构造出站 Handler 并启动 driver（直连 UDP）。
    pub async fn new(
        tag: impl Into<String>,
        config: &DeviceConfig,
        dns: Option<&Arc<xray_app_dns::DnsService>>,
    ) -> Result<Self> {
        Self::new_with_dialer(tag, config, dns, None).await
    }

    /// 从 DeviceConfig 构造出站 Handler，WG 自身 UDP 可经 system dialer 出站。
    ///
    /// 对应 Go `client.go:94-143 processWireGuard(ctx, dialer)`——`dialer`
    /// 为 `internet.Dialer`（Rust 侧 `DialFn`）：
    /// - `Some`：WG peer endpoint 以 UDP dest 经出站链拨号（可经 socks 等），
    ///   惰性连接（Go `netBindClient.connectTo` 在首次 Send 时拨）
    /// - `None`：绑定本地直连 UDP socket（与远端同族，随机端口）
    ///
    /// 其余步骤：
    /// - 解析 peer endpoint（域名经 `dns` 解析，Go `client.go:298-329`）
    /// - 创建 smoltcp 网栈（从 config.endpoint 派生 interface 地址）
    /// - spawn driver task（`reserved` 写 WG 包头 + `num_workers` worker 池）
    pub async fn new_with_dialer(
        tag: impl Into<String>,
        config: &DeviceConfig,
        dns: Option<&Arc<xray_app_dns::DnsService>>,
        system_dialer: Option<xray_app_dispatcher::default::DialFn>,
    ) -> Result<Self> {
        let tag = tag.into();
        if config.peers.is_empty() {
            return Err(WgError::InvalidConfig("wireguard outbound requires at least one peer".into()));
        }
        let peer_cfg = &config.peers[0];

        // peer session
        let peer: SharedPeer = shared_peer(config, peer_cfg, 0)?;

        // 远端 endpoint（IP:port；域名经 DNS 解析——Go client.go:298-329）
        let remote_addr = resolve_endpoint_addr(&peer_cfg.endpoint, config, dns).await?;

        // WG UDP 传输：system dialer（代理链，Go netBindClient.connectTo）或直连 socket
        let transport = match &system_dialer {
            Some(dialer) => {
                let addr = match remote_addr.ip() {
                    std::net::IpAddr::V4(v4) => Address::IPv4(v4),
                    std::net::IpAddr::V6(v6) => Address::IPv6(v6),
                };
                let dest = Destination::new(
                    addr,
                    xray_common::net::port::Port::new(remote_addr.port()),
                    xray_common::net::network::Network::UDP,
                );
                WgTransport::Dialed(Arc::new(DialedUdp::new(Arc::clone(dialer), dest)))
            }
            None => {
                // 绑定本地 UDP（与远端同族）
                let bind_addr = if remote_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                WgTransport::Direct(bind_udp_socket(bind_addr).await?)
            }
        };

        // smoltcp 网栈——从 config.endpoint 解析 interface 地址
        let local_cidrs = parse_local_cidrs(config)?;
        let mtu = config.effective_mtu() as usize;
        let netstack = Arc::new(AsyncMutex::new(WgNetStack::new(&local_cidrs, mtu)));

        // driver（reserved → WG 包头；num_workers → worker 池，Go bind.go:94-104）
        let driver = Arc::new(
            WgDriver::with_transport(vec![peer], vec![vec![]], transport, Arc::clone(&netstack))
                .with_num_workers(config.num_workers),
        );
        driver.set_reserved(config.reserved.clone());
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

/// 解析 peer endpoint（`host:port`）。
///
/// IP 直连；域名经 `dns` + WireGuard `domainStrategy` 解析（Go `client.go:298-329`
/// 的 createIPCRequest endpoint 分支，dice.Roll 随机选 IP）。
async fn resolve_endpoint_addr(
    endpoint: &str,
    config: &DeviceConfig,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
) -> Result<SocketAddr> {
    if let Ok(addr) = crate::peer::parse_endpoint_addr(endpoint) {
        return Ok(addr);
    }
    // host:port 拆分（Go net.SplitHostPort）
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| WgError::InvalidEndpoint(format!("peer endpoint not host:port: {endpoint}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| WgError::InvalidEndpoint(format!("peer endpoint bad port: {endpoint}")))?;
    let Some(dns) = dns else {
        return Err(WgError::InvalidEndpoint(format!(
            "peer endpoint is domain but no DNS service: {endpoint}"
        )));
    };
    let (has_v4, has_v6) = crate::dispatcher::endpoint_families(config);
    let ip = crate::dispatcher::resolve_dest_domain(
        host,
        config.domain_strategy,
        has_v4,
        has_v6,
        dns,
    )
    .await
    .map_err(|e| WgError::InvalidEndpoint(format!("peer endpoint DNS resolve: {e}")))?;
    Ok(SocketAddr::new(ip, port))
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
        let result = WireguardOutboundHandler::new("test", &cfg, None).await;
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
        let result = WireguardOutboundHandler::new("test", &cfg, None).await;
        assert!(result.is_err(), "should reject invalid endpoint");
    }
}
