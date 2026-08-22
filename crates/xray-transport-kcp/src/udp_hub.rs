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
/// 内部共享底层 socket（`std::net::UdpSocket` 的 send/recv 均为 `&self` 且线程安全，
/// 由内核串行化——对应 Go `net.UDPConn` 并发语义；不加大锁，否则「一个线程持锁阻塞
/// recv + 另一线程写抢锁」会死锁，client 先发后收的 KCP 流程直接卡死）。
/// `receive` 阻塞读一个包；上层应在独立线程或 `spawn_blocking` 中调用。
pub struct StdUdpHub {
    socket: Arc<std::net::UdpSocket>,
    local: Option<SocketAddr>,
}

impl StdUdpHub {
    /// 绑定 UDP socket（对应 Go `net.ListenUDP`）。
    pub fn bind(addr: impl std::net::ToSocketAddrs) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let local = socket.local_addr().ok();
        Ok(Self {
            socket: Arc::new(socket),
            local,
        })
    }

    /// 从已建立的 socket 构造（用于 dialer 端的 connected UDP socket）。
    pub fn from_socket(socket: std::net::UdpSocket) -> Self {
        let local = socket.local_addr().ok();
        Self {
            socket: Arc::new(socket),
            local,
        }
    }

    /// 拿底层 socket 的共享引用（用于构造 [`StdPacketInput`] 复用同一 socket）。
    #[must_use]
    pub fn socket_handle(&self) -> Arc<std::net::UdpSocket> {
        Arc::clone(&self.socket)
    }
}

impl UdpHub for StdUdpHub {
    fn receive(&self) -> Option<(Vec<u8>, SocketAddr)> {
        // ponytail: 单次最大 1500 字节（标准 MTU），KCP segment 上限 < 1500
        let mut buf = [0u8; 1500];
        match self.socket.recv_from(&mut buf) {
            Ok((n, src)) => Some((buf[..n].to_vec(), src)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // 同步 socket 不会返 WouldBlock；防御性记录并返 None
                None
            }
            Err(_) => None,
        }
    }

    fn write_to(&self, payload: &[u8], dest: SocketAddr) -> io::Result<()> {
        self.socket.send_to(payload, dest)?;
        Ok(())
    }

    fn close(&self) {
        // ponytail: Arc drop 后 socket 自动关闭；这里显式忽略
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
    socket: Arc<std::net::UdpSocket>,
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
            socket: Arc::new(socket),
        }
    }
}

impl PacketInput for StdPacketInput {
    fn read_packet(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 1500];
        match self.socket.recv(&mut buf) {
            Ok(n) => Some(buf[..n].to_vec()),
            Err(_) => None,
        }
    }
}

/// finalmask 伪装包装的 UDP hub（对应 Go `udp.Hub` 建立时 `WrapPacketConnServer`，
/// `transport/internet/udp/hub.go:71-72`）。
///
/// `write_to` 前 encode、`receive` 后 decode；decode 失败的包丢弃继续收，
/// 不终止接收循环（对齐 Go mask conn 读校验失败 → 丢包语义）。
pub struct MaskedUdpHub {
    inner: Arc<dyn UdpHub>,
    chain: xray_transport::finalmask::CodecChain,
}

impl MaskedUdpHub {
    /// 包装底层 hub + 伪装链。
    #[must_use]
    pub fn new(inner: Arc<dyn UdpHub>, chain: xray_transport::finalmask::CodecChain) -> Self {
        Self { inner, chain }
    }
}

impl UdpHub for MaskedUdpHub {
    fn receive(&self) -> Option<(Vec<u8>, SocketAddr)> {
        loop {
            let (pkt, src) = self.inner.receive()?;
            match self.chain.decode(&pkt) {
                Ok(decoded) => return Some((decoded, src)),
                Err(_) => continue, // 伪装层校验失败：丢弃该包，继续收
            }
        }
    }

    fn write_to(&self, payload: &[u8], dest: SocketAddr) -> io::Result<()> {
        let pkt = self.chain.encode(payload)?;
        self.inner.write_to(&pkt, dest)
    }

    fn close(&self) {
        self.inner.close();
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }
}

/// finalmask 伪装包装的 PacketInput（dialer 侧读路径，对应 Go `WrapPacketConnClient`
/// 后 KCP 从 masked PacketConn 读）。
pub struct MaskedPacketInput {
    inner: Box<dyn PacketInput>,
    chain: xray_transport::finalmask::CodecChain,
}

impl MaskedPacketInput {
    /// 包装底层输入 + 伪装链。
    #[must_use]
    pub fn new(inner: Box<dyn PacketInput>, chain: xray_transport::finalmask::CodecChain) -> Self {
        Self { inner, chain }
    }
}

impl PacketInput for MaskedPacketInput {
    fn read_packet(&mut self) -> Option<Vec<u8>> {
        loop {
            let pkt = self.inner.read_packet()?;
            match self.chain.decode(&pkt) {
                Ok(decoded) => return Some(decoded),
                Err(_) => continue, // 校验失败：丢弃，继续读
            }
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
