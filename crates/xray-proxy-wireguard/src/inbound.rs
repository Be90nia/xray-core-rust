//! WireGuard 入站 Handler——接收 WireGuard 流量并注入本地。
//!
//! 对应 Go `proxy/wireguard/server.go` 的 `Server.Process`。
//!
//! ## 流程
//!
//! 1. 监听 UDP 端口
//! 2. 接收 WG 数据报 → Tunnel.decapsulate → smoltcp netstack
//! 3. smoltcp 把入站 TCP/UDP 流通过 dispatcher 注入本地（留待接入上层）
//!
//! ## 当前限制
//!
//! 与 outbound 一致——driver 与 netstack 集成已完成，但 dispatcher 桥接（smoltcp
//! socket → router）留待后续切片。

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex as ParkMutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::config::DeviceConfig;
use crate::driver::{bind_udp_socket, WgDriver};
use crate::error::Result;
use crate::netstack::WgNetStack;
use crate::peer::{shared_peer, SharedPeer};

/// WireGuard 入站 Handler。
///
/// 持有 driver + 监听状态 + 监听端口。
pub struct WireguardInboundHandler {
    tag: String,
    port: u16,
    started: AtomicBool,
    /// driver 句柄——start() 后填充。
    driver: ParkMutex<Option<Arc<WgDriver>>>,
    /// join handle——close() 用以终止 task。
    join: ParkMutex<Option<JoinHandle<()>>>,
    /// smoltcp 网栈句柄（与 driver 共享）。
    netstack: Arc<AsyncMutex<WgNetStack>>,
}

impl WireguardInboundHandler {
    /// 从 DeviceConfig 构造入站 Handler。
    ///
    /// 不在此 spawn driver——构造仅做参数校验。`start()` 时启动。
    ///
    /// # 参数
    ///
    /// - `tag`：handler 唯一标识
    /// - `config`：DeviceConfig（is_client 应为 false）
    /// - `listen_port`：UDP 监听端口
    pub async fn new(
        tag: impl Into<String>,
        config: &DeviceConfig,
        listen_port: u16,
    ) -> Result<Self> {
        let tag = tag.into();
        if config.peers.is_empty() {
            return Err(crate::error::WgError::InvalidConfig(
                "wireguard inbound requires at least one peer".into(),
            ));
        }
        let peer_cfg = &config.peers[0];

        // peer session（server 模式不预先设置 endpoint——从首包学习）
        let peer: SharedPeer = shared_peer(config, peer_cfg)?;

        // 绑定监听 UDP
        let bind_addr = format!("0.0.0.0:{listen_port}");
        let sock = bind_udp_socket(&bind_addr).await?;

        // smoltcp 网栈
        let local_cidrs = parse_local_cidrs(config)?;
        let mtu = config.effective_mtu() as usize;
        let netstack = Arc::new(AsyncMutex::new(WgNetStack::new(&local_cidrs, mtu)));

        // driver（server 模式不设 remote——从首包学习）
        let driver = Arc::new(WgDriver::new(peer, sock, Arc::clone(&netstack)));

        Ok(Self {
            tag,
            port: listen_port,
            started: AtomicBool::new(false),
            driver: ParkMutex::new(Some(driver)),
            join: ParkMutex::new(None),
            netstack,
        })
    }

    /// 共享 smoltcp 网栈句柄（dispatcher 桥接用）。
    #[must_use]
    pub fn netstack(&self) -> &Arc<AsyncMutex<WgNetStack>> {
        &self.netstack
    }
}

#[async_trait]
impl InboundHandler for WireguardInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 启动 driver task。
    async fn start(&self) -> std::result::Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        let driver = self
            .driver
            .lock()
            .clone()
            .ok_or_else(|| InboundError::Closed(self.tag.clone()))?;

        let handle = driver
            .spawn()
            .await
            .map_err(|e| InboundError::ListenError(format!("wg driver spawn: {e}")))?;
        *self.join.lock() = Some(handle);
        tracing::info!(tag = %self.tag, port = self.port, "wireguard inbound started");
        Ok(())
    }

    /// 关闭 driver task。
    async fn close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        if let Some(handle) = self.join.lock().take() {
            handle.abort();
        }
        tracing::info!(tag = %self.tag, "wireguard inbound closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

/// 从 DeviceConfig.endpoint 解析为 smoltcp IpCidr（与 outbound 共用逻辑）。
fn parse_local_cidrs(config: &DeviceConfig) -> Result<Vec<smoltcp::wire::IpCidr>> {
    let parsed = crate::wireguard::parse_endpoints(config)?;
    parsed
        .addrs
        .into_iter()
        .map(|addr| {
            let cidr_prefix = if addr.is_ipv4() { 32 } else { 128 };
            let smoltcp_addr = match addr {
                std::net::IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets())),
                std::net::IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets())),
            };
            Ok(smoltcp::wire::IpCidr::new(smoltcp_addr, cidr_prefix))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair(seed: u8) -> (String, String) {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes: [u8; 32] = [seed; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
    }

    #[tokio::test]
    async fn construct_inbound_handler() {
        let (sec, pub_) = make_keypair(0x66);
        let cfg = DeviceConfig {
            secret_key: sec,
            peers: vec![PeerConfig {
                public_key: pub_,
                ..Default::default()
            }],
            ..Default::default()
        };
        // 使用随机端口避免冲突
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let h = WireguardInboundHandler::new("test", &cfg, port).await;
        assert!(h.is_ok(), "construct failed: {:?}", h.err());
    }

    #[tokio::test]
    async fn construct_rejects_no_peers() {
        let (sec, _) = make_keypair(0x77);
        let cfg = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let result = WireguardInboundHandler::new("test", &cfg, 0).await;
        assert!(result.is_err());
    }

    use crate::config::PeerConfig;

    #[tokio::test]
    async fn start_close_lifecycle() {
        let (sec, pub_) = make_keypair(0x88);
        let cfg = DeviceConfig {
            secret_key: sec,
            peers: vec![PeerConfig {
                public_key: pub_,
                ..Default::default()
            }],
            ..Default::default()
        };
        // 绑定一个临时端口
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let h = WireguardInboundHandler::new("test", &cfg, port).await.expect("construct");
        assert_eq!(h.port(), port);
        assert_eq!(h.tag(), "test");

        // start
        h.start().await.expect("start");
        // double start 应失败
        let result = h.start().await;
        assert!(result.is_err(), "double start should fail");

        // close
        h.close().await.expect("close");
        // close 后可再次 start
        // 但 driver 已 take，再次 start 会失败——这是预期（一个 handler 只能 start 一次有效周期）
    }
}
