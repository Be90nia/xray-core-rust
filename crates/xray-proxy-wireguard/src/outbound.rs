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

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::sync::Mutex as AsyncMutex;
use xray_common::net::{address::Address, destination::Destination};

use crate::{
    config::DeviceConfig,
    driver::{DialedUdp, WgDriver, WgTransport, bind_udp_socket},
    error::{Result, WgError},
    netstack::WgNetStack,
    peer::{SharedPeer, shared_peer},
};

/// WireGuard 出站 Handler。
///
/// 持有 driver + smoltcp 网栈句柄。dial 在 netstack 上建 socket。
pub struct WireguardOutboundHandler {
    #[allow(dead_code)] // 存量清零批次
    tag: String,
    /// driver task 句柄。
    #[allow(dead_code)] // 句柄由 worker task 持有，字段保留生命周期
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
        Self::new_with_dialer(tag, config, dns, None, None).await
    }

    /// 从 DeviceConfig 构造出站 Handler，WG 自身 UDP 可经 system dialer 出站。
    ///
    /// 对应 Go `client.go:94-143 processWireGuard(ctx, dialer)`——`dialer`
    /// 为 `internet.Dialer`（Rust 侧 `DialFn`）：
    /// - `Some`：WG peer endpoint 以 UDP dest 经出站链拨号（可经 socks 等）， 惰性连接（Go
    ///   `netBindClient.connectTo` 在首次 Send 时拨）
    /// - `None`：绑定本地直连 UDP socket（与远端同族，随机端口）
    ///
    /// 其余步骤：
    /// - 解析 peer endpoint（域名经 `dns` 解析，Go `client.go:298-329`）
    /// - 创建 smoltcp 网栈（从 config.endpoint 派生 interface 地址）
    /// - spawn driver task（`reserved` 写 WG 包头 + `num_workers` worker 池）
    #[allow(private_bounds)] // TtlDnsCache 为 wireguard crate 内网栈实现细节
    #[allow(private_interfaces)] // TtlDnsCache 为 wireguard crate 内网栈实现细节
    pub async fn new_with_dialer(
        tag: impl Into<String>,
        config: &DeviceConfig,
        dns: Option<&Arc<xray_app_dns::DnsService>>,
        system_dialer: Option<xray_app_dispatcher::default::DialFn>,
        // c7e569b0：endpoint 域名解析 TTL 缓存（Go Handler.cache）。None = 不缓存。
        dns_cache: Option<Arc<crate::dispatcher::TtlDnsCache>>,
    ) -> Result<Self> {
        let tag = tag.into();
        if config.peers.is_empty() {
            return Err(WgError::InvalidConfig(
                "wireguard outbound requires at least one peer".into(),
            ));
        }
        let peer_cfg = &config.peers[0];

        // peer session
        let peer: SharedPeer = shared_peer(config, peer_cfg, 0)?;

        // 远端 endpoint（IP:port；域名经 DNS 解析——Go client.go:298-329）
        let remote_addr =
            resolve_endpoint_addr(&peer_cfg.endpoint, config, dns, dns_cache.as_deref()).await?;

        // WG UDP 传输：system dialer（代理链，Go netBindClient.connectTo）或直连 socket。
        // Go 7d214f8b：Process 入口 `dialer.SetOutboundGateway(ctx, ob)` → sendThrough
        // （ob.Gateway）对 WG 自身 UDP 生效。Rust 等价：本 handler 的惰性初始化运行
        // 在外层 wrap_dial_with_send_through 的 DIAL_SRC scope 内，此处读取快照并
        // 应用到 WG 传输 socket（代理链分支同 Go dialer.go:233——dialer_proxy 存在
        // 时不消费源地址，链式 dispatch 天然忽略 DIAL_SRC）。
        let src_ip = xray_transport::system_dialer::DIAL_SRC.try_with(|v| *v).ok().flatten();
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
                // DialedUdp 实际拨号发生在 driver task 上下文（scope 外）——把
                // sendThrough 源地址重新包进 DIAL_SRC scope（dial_system 绑定源 IP）。
                let dialer: xray_app_dispatcher::default::DialFn = match src_ip {
                    Some(ip) => {
                        let inner = Arc::clone(dialer);
                        Arc::new(move |dest: &Destination| {
                            let inner = Arc::clone(&inner);
                            let dest = dest.clone();
                            Box::pin(async move {
                                xray_transport::system_dialer::DIAL_SRC
                                    .scope(Some(ip), inner(&dest))
                                    .await
                            })
                        })
                    },
                    None => Arc::clone(dialer),
                };
                WgTransport::Dialed(Arc::new(DialedUdp::new(dialer, dest)))
            },
            None => {
                // 绑定本地 UDP：sendThrough 源地址（与远端同族时）优先，否则通配。
                let bind_addr = match src_ip {
                    Some(ip) if ip.is_ipv4() && remote_addr.is_ipv4() => format!("{ip}:0"),
                    Some(ip) if ip.is_ipv6() && !remote_addr.is_ipv4() => format!("[{ip}]:0"),
                    _ if remote_addr.is_ipv4() => "0.0.0.0:0".to_string(),
                    _ => "[::]:0".to_string(),
                };
                WgTransport::Direct(bind_udp_socket(&bind_addr).await?)
            },
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
/// 的 createIPCRequest endpoint 分支 / `resolveLocal`，dice.Roll 随机选 IP），
/// 结果进 TTL 缓存（Go `Handler.cache`，c7e569b0；缓存键 = endpoint host）。
async fn resolve_endpoint_addr(
    endpoint: &str,
    config: &DeviceConfig,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    dns_cache: Option<&crate::dispatcher::TtlDnsCache>,
) -> Result<SocketAddr> {
    if let Ok(addr) = crate::peer::parse_endpoint_addr(endpoint) {
        return Ok(addr);
    }
    // host:port 拆分（Go net.SplitHostPort）
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| {
        WgError::InvalidEndpoint(format!("peer endpoint not host:port: {endpoint}"))
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| WgError::InvalidEndpoint(format!("peer endpoint bad port: {endpoint}")))?;
    let Some(dns) = dns else {
        return Err(WgError::InvalidEndpoint(format!(
            "peer endpoint is domain but no DNS service: {endpoint}"
        )));
    };
    if let Some(cache) = dns_cache {
        if let Some(ip) = cache.get(host) {
            return Ok(SocketAddr::new(ip, port));
        }
    }
    let (has_v4, has_v6) = crate::dispatcher::endpoint_families(config);
    let ip =
        crate::dispatcher::resolve_dest_domain(host, config.domain_strategy, has_v4, has_v6, dns)
            .await
            .map_err(|e| WgError::InvalidEndpoint(format!("peer endpoint DNS resolve: {e}")))?;
    // 本地 app DNS 不暴露记录 TTL → 缺省 300（Go netstack 默认，c7e569b0）。
    if let Some(cache) = dns_cache {
        cache.put(host, vec![ip], crate::dispatcher::DEFAULT_DNS_TTL_SECS);
    }
    Ok(SocketAddr::new(ip, port))
}

/// 从 DeviceConfig.endpoint 解析为 smoltcp IpCidr。
///
/// 复用 [`crate::wireguard::parse_endpoints`] 的解析逻辑。
#[allow(clippy::incompatible_msrv)] // 存量清零批次：incompatible_msrv
fn parse_local_cidrs(config: &DeviceConfig) -> Result<Vec<smoltcp::wire::IpCidr>> {
    let parsed = crate::wireguard::parse_endpoints(config)?;
    parsed
        .addrs
        .into_iter()
        .map(|addr| {
            let cidr_prefix = if addr.is_ipv4() { 32 } else { 128 };
            let smoltcp_addr = match addr {
                IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
                ),
                IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(
                    smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
                ),
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
        let cfg = DeviceConfig { secret_key: sec, ..Default::default() };
        let cidrs = parse_local_cidrs(&cfg).expect("parse");
        assert!(cidrs.is_empty());
    }

    #[tokio::test]
    async fn new_rejects_config_without_peers() {
        let (sec, _) = make_keypair(0x44);
        let cfg = DeviceConfig { secret_key: sec, ..Default::default() };
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
