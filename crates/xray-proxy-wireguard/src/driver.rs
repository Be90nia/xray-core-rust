//! WireGuard UDP driver——协调 UDP socket + Tunnel + smoltcp 网络栈。
//!
//! 对应 Go `proxy/wireguard/bind.go` 的 conn.Bind 实现。
//!
//! ## 架构
//!
//! ```text
//! [User TCP/UDP] ←→ [smoltcp Interface] ←IP pkts→ [VirtualDevice]
//!                                                            ↓ (rx→tun, tx←tun)
//!                                                     [WgDriver task]
//!                                                            ↓
//!                                              [UdpSocket] ↔ [Tunnel] ↔ [WG peer]
//! ```
//!
//! driver task 驱动三个循环：
//! 1. UDP recv → Tunnel.decapsulate → netstack.ingest_rx（每个 WG 数据报）
//! 2. netstack.drain_tx → Tunnel.encapsulate → UDP send（每 100ms + 每次 rx 后）
//! 3. Tunnel.update_timers → UDP send（每 100ms keepalive/rekey）
//!
//! ## 注意
//!
//! - Tunnel 是同步的（`&mut self`），用 [`parking_lot::Mutex`] 保护
//! - smoltcp Interface 不 Sync，整个 [`WgNetStack`] 也在 Mutex 内
//! - driver task 单独持有 Mutex 锁，保证顺序一致

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::interval;

use crate::error::{Result, WgError};
use crate::netstack::WgNetStack;
use crate::peer::SharedPeer;
use crate::tunnel::Output;

/// 定时器驱动间隔（boringtun 推荐 ~100ms）。
const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/// UDP socket 接收缓冲。
const UDP_RECV_BUF_SIZE: usize = 65535;

/// WireGuard driver——协调 UDP socket + Tunnel + netstack。
///
/// 一个 driver 对应一个 peer + 一个 UdpSocket。
/// 由 [`WireguardOutboundHandler`](crate::outbound::WireguardOutboundHandler) 或
/// [`WireguardInboundHandler`](crate::inbound::WireguardInboundHandler) 创建并 spawn。
pub struct WgDriver {
    /// peer 会话列表（单 peer=client；多 peer=server multi-peer）。
    peers: Vec<SharedPeer>,
    /// UDP socket——与远端 peer 通信。
    sock: Arc<UdpSocket>,
    /// smoltcp 网络栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// 远端 endpoint（client 模式固定；server 模式从首包学习）。
    remote: Mutex<Option<SocketAddr>>,
    /// server 模式 addr→peer index 路由缓存。
    addr_route: Mutex<HashMap<SocketAddr, usize>>,
    /// 每 peer 的 allowed_ips CIDR（出站 IP 包路由）。
    allowed_cidrs: Vec<Vec<smoltcp::wire::IpCidr>>,
}

impl WgDriver {
    /// 构造单 peer driver（client/outbound 模式）。
    pub fn new(peer: SharedPeer, sock: Arc<UdpSocket>, netstack: Arc<AsyncMutex<WgNetStack>>) -> Self {
        Self::new_multi(vec![peer], vec![vec![]], sock, netstack)
    }

    /// 构造多 peer driver（server/inbound 模式）。
    ///
    /// # 参数
    ///
    /// - `peers`：所有配置的 peer 会话
    /// - `allowed_cidrs`：每 peer 的 allowed_ips CIDR（与 peers 等长，用于出站路由）
    /// - `sock`：已绑定的 UDP socket
    /// - `netstack`：smoltcp 网络栈
    pub fn new_multi(
        peers: Vec<SharedPeer>,
        allowed_cidrs: Vec<Vec<smoltcp::wire::IpCidr>>,
        sock: Arc<UdpSocket>,
        netstack: Arc<AsyncMutex<WgNetStack>>,
    ) -> Self {
        Self {
            peers,
            allowed_cidrs,
            sock,
            netstack,
            remote: Mutex::new(None),
            addr_route: Mutex::new(HashMap::new()),
        }
    }

    /// 设置远端 endpoint（client 模式启动时）。
    pub fn set_remote(&self, addr: SocketAddr) {
        *self.remote.lock() = Some(addr);
        self.peers[0].set_endpoint(addr);
    }

    /// 尝试解封装入站包，返回 (peer_idx, outputs)。
    ///
    /// 单 peer：直接解封装。
    /// 多 peer：先查 addr_route 缓存，miss 时遍历所有 peer。
    fn decapsulate_incoming(&self, data: &[u8], src: SocketAddr) -> Option<(usize, Vec<Output>)> {
        if self.peers.len() == 1 {
            self.peers[0].set_endpoint(src);
            *self.remote.lock() = Some(src);
            self.peers[0].with_tunnel(|t| t.decapsulate(data)).ok().map(|outs| (0, outs))
        } else {
            // 查缓存
            let cached = self.addr_route.lock().get(&src).copied();
            if let Some(idx) = cached {
                if idx < self.peers.len() {
                    self.peers[idx].set_endpoint(src);
                    if let Ok(outs) = self.peers[idx].with_tunnel(|t| t.decapsulate(data)) {
                        if !outs.is_empty() {
                            return Some((idx, outs));
                        }
                    }
                }
            }
            // 遍历所有 peer（WG MAC 验证确保只有正确 peer 产生输出）
            for (idx, peer) in self.peers.iter().enumerate() {
                peer.set_endpoint(src);
                if let Ok(outs) = peer.with_tunnel(|t| t.decapsulate(data)) {
                    if !outs.is_empty() {
                        self.addr_route.lock().insert(src, idx);
                        return Some((idx, outs));
                    }
                }
            }
            None
        }
    }

    /// 根据出站 IP 包目的地址路由到正确 peer。
    fn route_outgoing(&self, ip_pkt: &[u8]) -> usize {
        if self.peers.len() == 1 {
            return 0;
        }
        let dest = match ip_pkt.first() {
            Some(&b) if b >> 4 == 4 && ip_pkt.len() >= 20 => {
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]))
            }
            Some(&b) if b >> 4 == 6 && ip_pkt.len() >= 40 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&ip_pkt[24..40]);
                smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(
                    u16::from_be_bytes([o[0], o[1]]),
                    u16::from_be_bytes([o[2], o[3]]),
                    u16::from_be_bytes([o[4], o[5]]),
                    u16::from_be_bytes([o[6], o[7]]),
                    u16::from_be_bytes([o[8], o[9]]),
                    u16::from_be_bytes([o[10], o[11]]),
                    u16::from_be_bytes([o[12], o[13]]),
                    u16::from_be_bytes([o[14], o[15]]),
                ))
            }
            _ => return 0,
        };
        for (idx, cidrs) in self.allowed_cidrs.iter().enumerate() {
            for cidr in cidrs {
                if cidr.contains_addr(&dest) {
                    return idx;
                }
            }
        }
        0 // fallback
    }


    /// 启动 driver。返回三个 JoinHandle——调用方可丢弃以停止。
    ///
    /// 内部 spawn 三个 tokio task：
    /// - rx_loop：UDP recv → decapsulate → netstack.ingest_rx
    /// - tx_loop：netstack.drain_tx → encapsulate → UDP send + timer
    /// - timer_loop：update_timers → UDP send
    pub async fn spawn(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        // 主循环：rx + tx + timer 三合一，简化锁竞争
        let driver = Arc::clone(&self);
        let handle = tokio::spawn(async move {
            driver.main_loop().await;
        });
        Ok(handle)
    }

    /// 主循环——驱动所有 IO。
    ///
    /// 合并为单循环避免多任务争抢 Mutex：
    /// - select! 上 UDP recv（80% 时间等待）
    /// - 每 100ms 触发 timer + drain_tx
    pub async fn main_loop(&self) {
        let mut timer = interval(TIMER_INTERVAL);
        let mut recv_buf = vec![0u8; UDP_RECV_BUF_SIZE];
        let multi = self.peers.len() > 1;
        let mut last_keepalive = std::time::Instant::now();
        let keepalive_interval = self.peers[0].with_tunnel(|t| t.keepalive_interval());
        tracing::debug!(peer_count = self.peers.len(), "wg driver main loop started");

        loop {
            tokio::select! {
                result = self.sock.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, src)) => {
                            if n == 0 { continue; }
                            let (peer_idx, outputs) = match self.decapsulate_incoming(&recv_buf[..n], src) {
                                Some(v) => v,
                                None => continue,
                            };
                            let mut stack = self.netstack.lock().await;
                            let peer_endpoint = self.peers[peer_idx].endpoint();
                            for out in outputs {
                                match out {
                                    Output::Ip(ip) => stack.ingest_rx(ip),
                                    Output::Network(wg) => {
                                        let target = if multi { peer_endpoint } else { *self.remote.lock() };
                                        if let Some(t) = target {
                                            let _ = self.sock.send_to(&wg, t).await;
                                        }
                                    }
                                }
                            }
                            stack.poll(smoltcp::time::Instant::now());
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "wg udp recv error");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                _ = timer.tick() => {
                    for peer in &self.peers {
                        let timer_outputs = peer.with_tunnel(|t| t.update_timers());
                        if let Ok(outs) = timer_outputs {
                            let ep = if multi { peer.endpoint() } else { *self.remote.lock() };
                            if let Some(ep) = ep {
                                for out in outs {
                                    if let Output::Network(wg) = out {
                                        let _ = self.sock.send_to(&wg, ep).await;
                                    }
                                }
                            }
                        }
                    }
                    if !multi {
                        if let Some(interval_secs) = keepalive_interval {
                            if last_keepalive.elapsed().as_secs() >= u64::from(interval_secs) {
                                last_keepalive = std::time::Instant::now();
                                let ka_outputs = self.peers[0].with_tunnel(|t| t.encapsulate(&[]));
                                if let Ok(outs) = ka_outputs {
                                    let remote = *self.remote.lock();
                                    if let Some(r) = remote {
                                        for out in outs {
                                            if let Output::Network(wg) = out {
                                                let _ = self.sock.send_to(&wg, r).await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let tx_pkts: Vec<Vec<u8>> = {
                        let mut stack = self.netstack.lock().await;
                        stack.poll(smoltcp::time::Instant::now());
                        stack.drain_tx()
                    };
                    if tx_pkts.is_empty() { continue; }
                    for pkt in &tx_pkts {
                        let peer_idx = self.route_outgoing(pkt);
                        let endpoint = if multi { self.peers[peer_idx].endpoint() } else { *self.remote.lock() };
                        if endpoint.is_none() { continue; }
                        let enc_outputs = self.peers[peer_idx].with_tunnel(|t| t.encapsulate(pkt));
                        match enc_outputs {
                            Ok(outs) => {
                                if let Some(ep) = endpoint {
                                    for out in outs {
                                        if let Output::Network(wg) = out {
                                            let _ = self.sock.send_to(&wg, ep).await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "wg encapsulate failed");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 绑定 UDP socket（双栈 / v4-only / v6-only）。
///
/// `bind_addr` 形如 `"0.0.0.0:0"`（client 随机端口）或 `"0.0.0.0:51820"`（server 固定端口）。
pub async fn bind_udp_socket(bind_addr: &str) -> Result<Arc<UdpSocket>> {
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| WgError::Io(e))?;
    Ok(Arc::new(sock))
}

