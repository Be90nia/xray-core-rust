//! SOCKS5 UDP ASSOCIATE relay——对齐 Go `proxy/socks/temp_udp_listen.go` 的
//! `TempUDPConn`。
//!
//! ## 来源过滤（4ers，Go protocol.go:211-219 + temp_udp_listen.go:30-51）
//!
//! `expectedRemote` 初始化语义（Go `handshake5`）：
//! - ASSOCIATE 请求目标是**域名或未指定 IP** → expected = (TCP 对端 IP, port 0)；
//! - 否则 expected = (请求 IP, 请求端口)——端口 0 表示来源端口待首包锁定。
//!
//! [`TempUdpRelay::recv_filtered`]（对齐 `TempUDPConn.Read`）丢弃来源不匹配的
//! 数据报（第三方注入/抢收防护）；expected 端口为 0 时以首个 IP 匹配的来源
//! 锁定（对齐 `c.ExpectedRemote.Store(remote)`）。
//! [`TempUdpRelay::send_to_expected`]（对齐 `TempUDPConn.Write`）固定发往
//! expected 地址。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use tokio::net::UdpSocket;

use crate::protocol::Host;

/// UDP ASSOCIATE relay socket：带来源过滤的 `UdpSocket` 包装。
pub struct TempUdpRelay {
    socket: UdpSocket,
    /// Go `ExpectedRemote atomic.Pointer[net.UDPAddr]`。端口 0 = 未锁定。
    expected: Mutex<SocketAddr>,
}

impl TempUdpRelay {
    /// 从已绑定的 UDP socket + expectedRemote 构造。
    pub fn new(socket: UdpSocket, expected: SocketAddr) -> Self {
        Self {
            socket,
            expected: Mutex::new(expected),
        }
    }

    /// 按 Go `handshake5`（protocol.go:211-219）语义计算 expectedRemote。
    ///
    /// - 请求地址为域名或未指定 IP → (peer IP, 0)；
    /// - 否则 → (请求 IP, 请求端口)；peer 未知时回退未指定地址（近乎全拒，
    ///   对齐 Go `expectedRemote.IP == nil` 时 `Equal` 恒 false 的丢弃语义）。
    pub fn expected_remote(
        request_host: &Host,
        request_port: u16,
        peer_ip: Option<IpAddr>,
    ) -> SocketAddr {
        let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        match request_host {
            Host::Domain(_) => SocketAddr::new(peer_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0),
            Host::Ipv4(ip) if ip.is_unspecified() => unspec.max_peer(peer_ip),
            Host::Ipv6(ip) if ip.is_unspecified() => unspec.max_peer(peer_ip),
            Host::Ipv4(ip) => SocketAddr::new(IpAddr::V4(*ip), request_port),
            Host::Ipv6(ip) => SocketAddr::new(IpAddr::V6(*ip), request_port),
        }
    }

    /// 读一个来源匹配的数据报。对齐 `TempUDPConn.Read`
    /// （temp_udp_listen.go:30-51）：来源 IP 不匹配直接丢弃继续读；
    /// expected 端口为 0 时以首个 IP 匹配的来源锁定端口。
    ///
    /// Windows `WSAECONNRESET`（UDP 上一次 send 触发的 ICMP unreachable 被
    /// 回报给本 socket）按 Go runtime 禁用 `SIO_UDP_CONNRESET` 的效果处理：
    /// 视为噪音忽略继续读。
    pub async fn recv_filtered(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let (n, from) = match self.socket.recv_from(buf).await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            let expected = self.expected();
            // Go net.IP.Equal 归一化 4-in-6 映射；Rust 用 to_canonical 等价
            if from.ip().to_canonical() != expected.ip().to_canonical() {
                continue;
            }
            if from.port() == expected.port() {
                return Ok(n);
            }
            if expected.port() == 0 {
                drop(expected);
                *self.expected() = from;
                return Ok(n);
            }
        }
    }

    /// 发数据报到 expectedRemote。对齐 `TempUDPConn.Write`（temp_udp_listen.go:53-56）。
    /// `ConnectionReset` 噪音重试一次（Windows SIO_UDP_CONNRESET 语义，见上）。
    pub async fn send_to_expected(&self, data: &[u8]) -> std::io::Result<usize> {
        let addr = *self.expected();
        match self.socket.send_to(data, addr).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                self.socket.send_to(data, addr).await
            }
            r => r,
        }
    }

    /// relay socket 本地地址（BND.PORT 来源）。
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn expected(&self) -> std::sync::MutexGuard<'_, SocketAddr> {
        // 临界区无 await、无 panic 路径——poison 恢复即可（锁内仅读取/赋值）
        self.expected.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// peer 未知时保持未指定地址（近乎全拒）的小助手。
trait MaxPeer {
    fn max_peer(self, peer_ip: Option<IpAddr>) -> SocketAddr;
}

impl MaxPeer for SocketAddr {
    fn max_peer(self, peer_ip: Option<IpAddr>) -> SocketAddr {
        match peer_ip {
            Some(ip) => SocketAddr::new(ip, 0),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 冒名者 bind 在同主机的另一个回环 IP 上（127.0.0.2 ≠ 127.0.0.1）。
    async fn impostor_socket() -> UdpSocket {
        match UdpSocket::bind(("127.0.0.2", 0)).await {
            Ok(s) => s,
            Err(_) => UdpSocket::bind(("127.0.0.3", 0)).await.expect("bind 127.0.0.2/3"),
        }
    }

    #[test]
    fn expected_remote_domain_falls_back_to_peer() {
        let peer: IpAddr = "10.1.2.3".parse().unwrap();
        let e = TempUdpRelay::expected_remote(&Host::Domain("cdn.example.com".into()), 9999, Some(peer));
        assert_eq!(e.ip(), peer);
        assert_eq!(e.port(), 0); // 域名 → 端口待首包锁定
    }

    #[test]
    fn expected_remote_ip_keeps_request_port() {
        let ip: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let e = TempUdpRelay::expected_remote(&Host::Ipv4(ip), 5353, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(e.ip(), IpAddr::from(ip));
        assert_eq!(e.port(), 5353);
    }

    #[test]
    fn expected_remote_unspecified_ip_uses_peer() {
        let peer: IpAddr = "192.168.1.7".parse().unwrap();
        let e = TempUdpRelay::expected_remote(&Host::Ipv4(std::net::Ipv4Addr::UNSPECIFIED), 0, Some(peer));
        assert_eq!(e.ip(), peer);
        assert_eq!(e.port(), 0);
    }

    /// e2e：来源过滤——不同源 IP 的数据报被丢弃（4ers 防注入语义），
    /// 合法来源正常收发，send_to_expected 落到 expected 地址。
    #[tokio::test]
    async fn relay_filters_foreign_sources() {
        let relay_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        // 客户端（合法来源，127.0.0.1）+ 冒名者（不同回环 IP）
        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let impostor = impostor_socket().await;
        // expected = client 的具体地址（对齐 ASSOCIATE 指定 IP:port 分支）
        let expected = client.local_addr().unwrap();
        let relay = TempUdpRelay::new(relay_sock, expected);

        // 1. 冒名包（IP 不匹配）必须被丢弃
        impostor.send_to(b"evil", relay.local_addr().unwrap()).await.unwrap();
        // 2. 合法客户端包 → 通过
        client.send_to(b"hello", relay.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), relay.recv_filtered(&mut buf))
            .await
            .expect("relay should accept legit packet")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");

        // 3. 冒名者继续被过滤；合法来源可继续通信
        impostor.send_to(b"evil2", relay.local_addr().unwrap()).await.unwrap();
        client.send_to(b"second", relay.local_addr().unwrap()).await.unwrap();
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), relay.recv_filtered(&mut buf))
            .await
            .expect("relay should accept second legit packet")
            .unwrap();
        assert_eq!(&buf[..n], b"second");

        // 4. send_to_expected 落到 expected（client）地址
        let sent = relay.send_to_expected(b"resp").await.unwrap();
        assert_eq!(sent, 4);
        let mut rbuf = [0u8; 64];
        let (rn, from) = client.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..rn], b"resp");
        assert_eq!(from, relay.local_addr().unwrap());
    }

    /// expected 端口 0（ASSOCIATE 域名/未指定 IP 分支）：首个 IP 匹配来源锁定，
    /// IP 不匹配的来源既不被接受也不触发锁定。
    #[tokio::test]
    async fn relay_port_zero_locks_first_matching_source() {
        let relay_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let relay = TempUdpRelay::new(relay_sock, "127.0.0.1:0".parse().unwrap());
        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let impostor = impostor_socket().await;

        // 冒名包先到（IP 不匹配）——不得锁定，必须丢弃
        impostor.send_to(b"evil", relay.local_addr().unwrap()).await.unwrap();
        client.send_to(b"first", relay.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), relay.recv_filtered(&mut buf))
            .await
            .expect("first matching source should be accepted")
            .unwrap();
        assert_eq!(&buf[..n], b"first");
        // 锁定后 expected = client 实际地址
        assert_eq!(*relay.expected(), client.local_addr().unwrap());
    }
}
