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
    /// peer 会话（Tunnel + endpoint）。
    peer: SharedPeer,
    /// UDP socket——与远端 peer 通信。
    sock: Arc<UdpSocket>,
    /// smoltcp 网络栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// 远端 endpoint（client 模式固定；server 模式从首包学习）。
    remote: Mutex<Option<SocketAddr>>,
}

impl WgDriver {
    /// 构造 driver（不启动）。
    ///
    /// # 参数
    ///
    /// - `peer`：peer 会话
    /// - `sock`：已绑定的 UDP socket
    /// - `netstack`：smoltcp 网络栈
    pub fn new(peer: SharedPeer, sock: Arc<UdpSocket>, netstack: Arc<AsyncMutex<WgNetStack>>) -> Self {
        Self {
            peer,
            sock,
            netstack,
            remote: Mutex::new(None),
        }
    }

    /// 设置远端 endpoint（client 模式启动时）。
    pub fn set_remote(&self, addr: SocketAddr) {
        *self.remote.lock() = Some(addr);
        self.peer.set_endpoint(addr);
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
    async fn main_loop(&self) {
        let mut timer = interval(TIMER_INTERVAL);
        let mut recv_buf = vec![0u8; UDP_RECV_BUF_SIZE];
        let mut last_keepalive = std::time::Instant::now();
        let keepalive_interval = self.peer.with_tunnel(|t| t.keepalive_interval());
        tracing::debug!(key = %self.peer.public_key_hex(), "wg driver main loop started");

        loop {
            tokio::select! {
                // 收到 UDP 数据报
                result = self.sock.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, src)) => {
                            if n == 0 { continue; }
                            // server 模式 roaming：更新 remote
                            {
                                let mut remote = self.remote.lock();
                                if *remote != Some(src) {
                                    *remote = Some(src);
                                    self.peer.set_endpoint(src);
                                    tracing::debug!(peer = %src, "wg peer endpoint updated (roaming)");
                                }
                            }
                            // decapsulate → netstack.ingest_rx
                            let outputs = self.peer.with_tunnel(|t| t.decapsulate(&recv_buf[..n]));
                            match outputs {
                                Ok(outs) => {
                                    let mut stack = self.netstack.lock().await;
                                    for out in outs {
                                        match out {
                                            Output::Ip(ip) => stack.ingest_rx(ip),
                                            Output::Network(wg) => {
                                                // handshake reply 等——立即发出
                                                let remote = *self.remote.lock();
                                                if let Some(r) = remote {
                                                    let _ = self.sock.send_to(&wg, r).await;
                                                }
                                            }
                                        }
                                    }
                                    // poll netstack 处理刚到的包
                                    stack.poll(smoltcp::time::Instant::now());
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "wg decapsulate failed");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "wg udp recv error");
                            // ponytail: 不退出循环——socket 可能临时错误
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                // 每 100ms 触发：timer + drain_tx
                _ = timer.tick() => {
                    // 1. update_timers（keepalive / session key 轮换）
                    let timer_outputs = self.peer.with_tunnel(|t| t.update_timers());
                    match timer_outputs {
                        Ok(outs) => {
                            let remote = *self.remote.lock();
                            if let Some(r) = remote {
                                for out in outs {
                                    if let Output::Network(wg) = out {
                                        let _ = self.sock.send_to(&wg, r).await;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "wg timer failed");
                        }
                    }

                    // 2. 检查 keepalive 间隔——如果配置了 keepalive 且超时，触发握手
                    if let Some(interval_secs) = keepalive_interval {
                        if last_keepalive.elapsed().as_secs() >= u64::from(interval_secs) {
                            last_keepalive = std::time::Instant::now();
                            // 发送一个空的 keepalive 包（encapsulate 空 IP 包）
                            let keepalive_pkt = vec![0u8; 0];
                            let ka_outputs = self.peer.with_tunnel(|t| t.encapsulate(&keepalive_pkt));
                            match ka_outputs {
                                Ok(outs) => {
                                    let remote = *self.remote.lock();
                                    if let Some(r) = remote {
                                        for out in outs {
                                            if let Output::Network(wg) = out {
                                                let _ = self.sock.send_to(&wg, r).await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "wg keepalive encapsulate failed");
                                }
                            }
                        }
                    }

                    // 2. drain_tx → encapsulate → UDP send
                    let tx_pkts: Vec<Vec<u8>> = {
                        let mut stack = self.netstack.lock().await;
                        stack.poll(smoltcp::time::Instant::now());
                        stack.drain_tx()
                    };
                    if tx_pkts.is_empty() { continue; }
                    let enc_outputs: Vec<Output> = self.peer.with_tunnel(|t| {
                        let mut all = Vec::new();
                        for pkt in &tx_pkts {
                            match t.encapsulate(pkt) {
                                Ok(o) => all.extend(o),
                                Err(e) => {
                                    tracing::warn!(error = %e, "wg encapsulate failed");
                                    break;
                                }
                            }
                        }
                        all
                    });
                    for out in enc_outputs {
                        if let Output::Network(wg) = out {
                            let remote = *self.remote.lock();
                            if let Some(r) = remote {
                                let _ = self.sock.send_to(&wg, r).await;
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

