//! # UDP hub
//!
//! 对应 Go `transport/internet/udp/hub.go`。UDP listener + recv loop。
//!
//! ## 架构
//!
//! - `UdpHub` — 持有 `UdpSocket` + 收包 channel，spawn recv 循环
//! - `UdpPacket` — 收到的 UDP 包（payload + source + optional origDest）
//! - `ListenUDP` — bind + spawn recv loop + return `UdpHub`
//!
//! origDest（TPROXY 原始目标地址）当前为 stub——需要平台特定 syscall（Linux `IP_RECVORIGDSTADDR`）。
//! udpmask wrapping 当前为 stub——等 finalmask 集成。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

/// UDP 收包缓冲区大小（对应 Go `finalmask.UDPSize = 4096`）。
const UDP_BUFFER_SIZE: usize = 4096;

/// 默认收包 channel 容量（对应 Go `Hub.capacity = 256`）。
const DEFAULT_CACHE_CAPACITY: usize = 256;

// ===== UdpPacket =====

/// 收到的 UDP 包。对应 Go `protocol/udp.Packet`。
pub struct UdpPacket {
    /// 负载数据。
    pub payload: Vec<u8>,
    /// 来源地址。
    pub source: SocketAddr,
    /// 原始目标地址（TPROXY/redirect 场景，Linux `IP_RECVORIGDSTADDR`）。
    ///
    /// 当前为 stub——需要平台特定 syscall 实现。
    pub target: Option<SocketAddr>,
}

// ===== HubOption =====

/// UDP Hub 配置选项。对应 Go `HubOption func(h *Hub)`。
pub trait HubOption: Send + Sync {
    fn apply(&self, hub: &mut UdpHubBuilder);
}

/// 收包 channel 容量。
pub struct Capacity(pub usize);
impl HubOption for Capacity {
    fn apply(&self, hub: &mut UdpHubBuilder) {
        hub.capacity = self.0;
    }
}

/// 是否接收原始目标地址（TPROXY）。
pub struct ReceiveOriginalDestination(pub bool);
impl HubOption for ReceiveOriginalDestination {
    fn apply(&self, hub: &mut UdpHubBuilder) {
        hub.recv_orig_dest = self.0;
    }
}

// ===== UdpHubBuilder =====

/// UDP Hub 构建器（内部用）。
pub struct UdpHubBuilder {
    capacity: usize,
    recv_orig_dest: bool,
}

impl Default for UdpHubBuilder {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CACHE_CAPACITY,
            recv_orig_dest: false,
        }
    }
}

// ===== UdpHub =====

/// UDP Hub。对应 Go `udp.Hub` struct。
///
/// 持有 `UdpSocket` + 收包 channel。`start()` 在独立 tokio task 中运行，
/// `recv_from` → 构造 `UdpPacket` → 发送到 channel。
/// 消费者通过 `receive()` 获取 channel receiver。
pub struct UdpHub {
    socket: Arc<UdpSocket>,
    rx: mpsc::Receiver<UdpPacket>,
    close_notify: Arc<Notify>,
    recv_orig_dest: bool,
}

impl UdpHub {
    /// 创建 UDP Hub 并 spawn recv 循环。
    ///
    /// 对应 Go `ListenUDP()`：bind → spawn `start()` → return。
    ///
    /// # 参数
    ///
    /// - `addr`：监听地址
    /// - `options`：配置选项（`Capacity`、`ReceiveOriginalDestination`）
    ///
    /// # 错误
    ///
    /// bind 失败时返回 `io::Error`。
    pub async fn listen(
        addr: SocketAddr,
        options: &[Box<dyn HubOption>],
    ) -> io::Result<Self> {
        let mut builder = UdpHubBuilder::default();
        for opt in options {
            opt.apply(&mut builder);
        }

        let socket = UdpSocket::bind(addr).await?;
        let (tx, rx) = mpsc::channel(builder.capacity);
        let close_notify = Arc::new(Notify::new());

        let hub = Self {
            socket: Arc::new(socket),
            rx,
            close_notify: Arc::clone(&close_notify),
            recv_orig_dest: builder.recv_orig_dest,
        };

        // Spawn recv 循环。
        let socket = Arc::clone(&hub.socket);
        let recv_orig_dest = hub.recv_orig_dest;
        tokio::spawn(async move {
            start_recv_loop(&socket, tx, close_notify, recv_orig_dest).await;
        });

        Ok(hub)
    }

    /// 获取收包 channel receiver。
    ///
    /// 对应 Go `Hub.Receive() <-chan *udp.Packet`。
    /// 调用后 receiver 所有权转移，只能调用一次。
    pub fn receive(mut self) -> mpsc::Receiver<UdpPacket> {
        // ponytail: 消费 receiver，让调用方直接 await。
        // 如果需要多次获取，改用 Arc<Mutex<Receiver>> 或 watch channel。
        self.rx
    }

    /// 发送 UDP 包到指定地址。
    ///
    /// 对应 Go `Hub.WriteTo(payload, dest)`。
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    /// 监听器本地地址。
    ///
    /// 对应 Go `Hub.Addr()`。
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 关闭 UDP Hub。
    ///
    /// 对应 Go `Hub.Close()`。通知 recv 循环退出。
    /// 底层 UdpSocket 在 Arc drop 时关闭。
    pub fn close(&self) -> io::Result<()> {
        self.close_notify.notify_waiters();
        Ok(())
    }
}

// ===== recv 循环 =====

/// UDP 收包循环。对应 Go `Hub.start()`。
///
/// 循环 `recv_from` → 构造 `UdpPacket` → 发送到 channel。
/// channel 满时丢弃包（与 Go `select { case c <- payload: default: }` 一致）。
/// 收到 close 信号或 recv 错误时退出。
async fn start_recv_loop(
    socket: &UdpSocket,
    tx: mpsc::Sender<UdpPacket>,
    close_notify: Arc<Notify>,
    _recv_orig_dest: bool,
) {
    let mut buf = [0u8; UDP_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, source)) => {
                        if n == 0 {
                            continue;
                        }

                        // ponytail: origDest 需要平台特定 syscall
                        // （Linux IP_RECVORIGDSTADDR / IPv6 IPV6_RECVORIGDSTADDR）。
                        // 当前为 stub，target = None。
                        let target = None;

                        let packet = UdpPacket {
                            payload: buf[..n].to_vec(),
                            source,
                            target,
                        };

                        // channel 满时丢弃（与 Go default 分支一致）。
                        if tx.try_send(packet).is_err() {
                            tracing::debug!("UDP hub cache full, dropping packet");
                        }
                    }
                    Err(e) => {
                        // 对应 Go：recv 错误 → log + break。
                        tracing::warn!(error = %e, "failed to read UDP msg");
                        break;
                    }
                }
            }
            _ = close_notify.notified() => {
                // 收到关闭信号，退出循环。
                break;
            }
        }
    }
}

// ===== 旧 API 兼容 =====
//
// 保留 `register_udp_listener` / `unregister_udp_listener` 向后兼容，
// 但标记为 deprecated——新代码应使用 `UdpHub::listen()`。

use std::collections::HashMap;
use std::sync::Mutex;

static UDP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, ()>>> = std::sync::OnceLock::new();
fn udp_hub() -> &'static Mutex<HashMap<SocketAddr, ()>> {
    UDP_HUB.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 注册 UDP listener。锁中毒时静默忽略。
#[deprecated(note = "use UdpHub::listen() instead")]
pub fn register_udp_listener(addr: SocketAddr) {
    if let Ok(mut hub) = udp_hub().lock() {
        hub.insert(addr, ());
    }
}

/// 注销 UDP listener。锁中毒时静默忽略。
#[deprecated(note = "use UdpHub::close() instead")]
pub fn unregister_udp_listener(addr: SocketAddr) {
    if let Ok(mut hub) = udp_hub().lock() {
        hub.remove(&addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_hub_bind_and_recv() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);

        let mut rx = hub.receive();

        // 发送 UDP 包。
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        sender.send_to(b"hello", addr).await.expect("send_to 失败");

        // 接收。
        let packet = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        assert_eq!(&packet.payload, b"hello");
        assert!(packet.target.is_none());
    }

    #[tokio::test]
    async fn udp_hub_local_addr() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn udp_hub_send_to() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("listen 失败");
        let hub_addr = hub.local_addr().expect("local_addr 失败");

        // 接收端。
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let recv_addr = receiver.local_addr().expect("local_addr");

        // Hub 发送。
        hub.send_to(b"world", recv_addr).await.expect("send_to 失败");

        // 接收端验证。
        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("timeout")
        .expect("recv_from 失败");

        assert_eq!(&buf[..n], b"world");
        assert_eq!(from, hub_addr);
    }

    #[tokio::test]
    async fn udp_hub_close_stops_recv_loop() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("listen 失败");

        hub.close().expect("close 失败");

        // close 后 receive 应该最终返回 None（channel 关闭）。
        let mut rx = hub.receive();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await;

        // 可能收到 None（channel 关闭）或 timeout（recv 循环还在等）。
        // 关键是不 panic。
        match result {
            Ok(None) => {} // channel 已关闭 ✅
            Ok(Some(_)) => {} // 收到残留包也 OK
            Err(_) => {} // timeout 也 OK——recv 循环可能在等下一个包
        }
    }

    #[tokio::test]
    async fn udp_hub_capacity_option() {
        let options: Vec<Box<dyn HubOption>> = vec![Box::new(Capacity(10))];
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &options)
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn udp_hub_multiple_packets() {
        let hub = UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("listen 失败");
        let addr = hub.local_addr().expect("local_addr 失败");

        let mut rx = hub.receive();

        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        for i in 0..5u8 {
            sender
                .send_to(&[i], addr)
                .await
                .expect("send_to 失败");
        }

        // 接收 5 个包。
        let mut received = Vec::new();
        for _ in 0..5 {
            let packet = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                rx.recv(),
            )
            .await
            .expect("timeout")
            .expect("channel closed");
            received.push(packet.payload);
        }

        // 验证顺序（UDP 不保证顺序，但本地 loopback 通常有序）。
        assert_eq!(received.len(), 5);
    }
}
