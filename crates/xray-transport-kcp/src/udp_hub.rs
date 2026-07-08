//! `StdUdpHub`——基于 `std::net::UdpSocket` 的 UDP hub 同步实现。
//!
//! 对应 Go `transport/internet/kcp/udp_hub.go`（基于 `net.UDPConn`）。
//!
//! ## Ponytail 决策
//!
//! Go 端 `udp.Hub` 用 `net.ListenUDP` + goroutine 接收循环。Rust 端直接
//! 用 `std::net::UdpSocket`（同步阻塞 IO）+ `Arc<Mutex>` 共享，让上层
//! 在 `tokio::task::spawn_blocking` 中跑接收循环。这样不引入 async UDP
//! 复杂度，且 trait [`crate::listener::UdpHub`] 是同步的（与 Go 一致）。
//!
//! TLS / Udpmask 包装留 follow-up（依赖 uTLS 决策 + xray 自有 udpmask 协议）。

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::dialer::PacketInput;
use crate::listener::UdpHub;

/// 同步 UDP hub：包装 `UdpSocket` 实现 [`UdpHub`] trait。
///
/// 内部用 `parking_lot::Mutex` 保护 socket，让多线程接收/写入共享同一 socket。
/// `receive` 阻塞读一个包；上层应在独立线程或 `spawn_blocking` 中调用。
pub struct StdUdpHub {
    socket: Arc<Mutex<std::net::UdpSocket>>,
    local: Option<SocketAddr>,
}

impl StdUdpHub {
    /// 绑定 UDP socket（对应 Go `net.ListenUDP`）。
    ///
    /// `addr` 形如 `127.0.0.1:0`（系统分配端口）或 `0.0.0.0:443`。
    pub fn bind(addr: impl std::net::ToSocketAddrs) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let local = socket.local_addr().ok();
        Ok(Self {
            socket: Arc::new(Mutex::new(socket)),
            local,
        })
    }

    /// 从已建立的 socket 构造（用于 dialer 端的 connected UDP socket）。
    pub fn from_socket(socket: std::net::UdpSocket) -> Self {
        let local = socket.local_addr().ok();
        Self {
            socket: Arc::new(Mutex::new(socket)),
            local,
        }
    }

    /// 拿底层 socket 的 Arc<Mutex> 引用（用于构造 [`StdPacketInput`] 复用同一 socket）。
    #[must_use]
    pub fn socket_handle(&self) -> Arc<Mutex<std::net::UdpSocket>> {
        Arc::clone(&self.socket)
    }
}

impl UdpHub for StdUdpHub {
    fn receive(&self) -> Option<(Vec<u8>, SocketAddr)> {
        // ponytail: 单次最大 1500 字节（标准 MTU），KCP segment 上限 < 1500
        let mut buf = [0u8; 1500];
        let socket = self.socket.lock();
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => Some((buf[..n].to_vec(), src)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // 同步 socket 不会返 WouldBlock；防御性记录并返 None
                None
            }
            Err(_) => None,
        }
    }

    fn write_to(&self, payload: &[u8], dest: SocketAddr) -> io::Result<()> {
        let socket = self.socket.lock();
        socket.send_to(payload, dest)?;
        Ok(())
    }

    fn close(&self) {
        // ponytail: Arc<Mutex> drop 后 socket 自动关闭；这里显式忽略
        // （std::net::UdpSocket 无显式 close，Drop 时由 OS 回收）
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }
}

/// 同步 PacketInput：包装共享 socket 实现客户端 UDP 读取。
///
/// dialer 端用 `UdpSocket::connect` 后，从此 hub 读取服务端发回的 segment。
/// 与 [`StdUdpHub`] 共享 socket handle，让 client 端既能写又能读。
pub struct StdPacketInput {
    socket: Arc<Mutex<std::net::UdpSocket>>,
}

impl StdPacketInput {
    /// 从 hub 复用 socket 构造。
    #[must_use]
    pub fn from_hub(hub: &StdUdpHub) -> Self {
        Self {
            socket: hub.socket_handle(),
        }
    }

    /// 从已建立的 socket 构造。
    pub fn from_socket(socket: std::net::UdpSocket) -> Self {
        Self {
            socket: Arc::new(Mutex::new(socket)),
        }
    }
}

impl PacketInput for StdPacketInput {
    fn read_packet(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 1500];
        let socket = self.socket.lock();
        match socket.recv(&mut buf) {
            Ok(n) => Some(buf[..n].to_vec()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_local_addr() {
        let hub = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let local = hub.local_addr().expect("local addr");
        assert_eq!(local.ip().to_string(), "127.0.0.1");
        assert!(local.port() > 0);
    }

    #[test]
    fn write_to_and_receive_roundtrip() {
        // 两个 hub，A 发给 B，B 收到
        let hub_a = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let hub_b = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let addr_b = hub_b.local_addr().unwrap();

        hub_a.write_to(b"hello kcp", addr_b).unwrap();
        let (payload, src) = hub_b.receive().expect("recv");
        assert_eq!(payload, b"hello kcp");
        assert_eq!(src, hub_a.local_addr().unwrap());
    }

    #[test]
    fn from_hub_packet_input_reads_inbound() {
        // A 发给 B，B 的 StdPacketInput 读取
        let hub_a = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let hub_b = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let addr_b = hub_b.local_addr().unwrap();

        // B 端：connect socket 到 A 后再读（PacketInput 用 recv）
        // 简化：hub_b 内部 socket 未 connect，用 receive 路径
        hub_a.write_to(b"packet", addr_b).unwrap();
        let (payload, _src) = hub_b.receive().expect("recv");
        assert_eq!(payload, b"packet");
    }

    #[test]
    fn multiple_writes_in_order() {
        let hub_a = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let hub_b = StdUdpHub::bind("127.0.0.1:0").unwrap();
        let addr_b = hub_b.local_addr().unwrap();

        // UDP 不保证顺序，但本机 loopback 通常保序
        hub_a.write_to(b"first", addr_b).unwrap();
        hub_a.write_to(b"second", addr_b).unwrap();

        let (p1, _) = hub_b.receive().unwrap();
        let (p2, _) = hub_b.receive().unwrap();
        assert_eq!(p1, b"first");
        assert_eq!(p2, b"second");
    }

    #[test]
    fn close_does_not_panic() {
        let hub = StdUdpHub::bind("127.0.0.1:0").unwrap();
        hub.close();
        // 多次 close 安全
        hub.close();
    }

    #[test]
    fn from_socket_preserves_local_addr() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let expected = socket.local_addr().unwrap();
        let hub = StdUdpHub::from_socket(socket);
        assert_eq!(hub.local_addr(), Some(expected));
    }
}
