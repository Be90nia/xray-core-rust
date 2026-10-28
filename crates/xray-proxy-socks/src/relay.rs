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

use parking_lot::Mutex;
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
        Self { socket, expected: Mutex::new(expected) }
    }

    /// 按 Go `handshake5`（protocol.go:211-219）语义计算 expectedRemote。
    ///
    /// - 请求地址为域名或未指定 IP → (peer IP, 0)；
    /// - 否则 → (请求 IP, 请求端口)；peer 未知时回退未指定地址（近乎全拒， 对齐 Go
    ///   `expectedRemote.IP == nil` 时 `Equal` 恒 false 的丢弃语义）。
    pub fn expected_remote(
        request_host: &Host,
        request_port: u16,
        peer_ip: Option<IpAddr>,
    ) -> SocketAddr {
        let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        match request_host {
            Host::Domain(_) => {
                SocketAddr::new(peer_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0)
            },
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
            },
            r => r,
        }
    }

    /// relay socket 本地地址（BND.PORT 来源）。
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn expected(&self) -> parking_lot::MutexGuard<'_, SocketAddr> {
        self.expected.lock()
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

    /// 断言 `recv_filtered` 在 `ms` 内拿不到包（负向断言；与 core 侧同名助手同形）。
    ///
    /// 不绑二级回环 IP：macOS CI 的 lo0 默认只有 127.0.0.1，
    /// `bind(127.0.0.2)` 会 EADDRNOTAVAIL（CI run 40710670210 实证）。
    async fn assert_dropped(relay: &TempUdpRelay, ms: u64, why: &str) {
        let mut buf = [0u8; 64];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(ms),
            relay.recv_filtered(&mut buf),
        )
        .await;
        assert!(got.is_err(), "{why}");
    }

    #[test]
    fn expected_remote_domain_falls_back_to_peer() {
        let peer: IpAddr = "10.1.2.3".parse().unwrap();
        let e = TempUdpRelay::expected_remote(
            &Host::Domain("cdn.example.com".into()),
            9999,
            Some(peer),
        );
        assert_eq!(e.ip(), peer);
        assert_eq!(e.port(), 0); // 域名 → 端口待首包锁定
    }

    #[test]
    fn expected_remote_ip_keeps_request_port() {
        let ip: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let e =
            TempUdpRelay::expected_remote(&Host::Ipv4(ip), 5353, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(e.ip(), IpAddr::from(ip));
        assert_eq!(e.port(), 5353);
    }

    #[test]
    fn expected_remote_unspecified_ip_uses_peer() {
        let peer: IpAddr = "192.168.1.7".parse().unwrap();
        let e = TempUdpRelay::expected_remote(
            &Host::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
            Some(peer),
        );
        assert_eq!(e.ip(), peer);
        assert_eq!(e.port(), 0);
    }

    /// e2e：来源过滤——与 expected 不符的来源被丢弃（防注入语义），
    /// 合法来源正常收发，send_to_expected 落到 expected 地址。
    ///
    /// 跨平台写法：第一阶段用「expected 指向本机未绑定的 127.0.0.2」制造来源 IP 不符
    /// （不实际 bind 127.0.0.2）；第二阶段用两个 127.0.0.1 socket 验合法路径。
    #[tokio::test]
    async fn relay_filters_foreign_sources() {
        // 1) expected 是 127.0.0.2，来自 127.0.0.1 的包即「来源 IP 不符」→ 丢弃
        let relay_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let relay = TempUdpRelay::new(relay_sock, "127.0.0.2:1234".parse().unwrap());
        let foreign = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        foreign.send_to(b"evil", relay_addr).await.unwrap();
        assert_dropped(&relay, 300, "来源 IP 与 expected 不符必须被丢弃").await;

        // 2) expected = 客户端真实地址 → 合法收发 + send_to_expected 落点
        let relay_sock2 = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_addr2 = relay_sock2.local_addr().unwrap();
        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let expected = client.local_addr().unwrap();
        let relay2 = TempUdpRelay::new(relay_sock2, expected);

        client.send_to(b"hello", relay_addr2).await.unwrap();
        let mut buf = [0u8; 64];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(2), relay2.recv_filtered(&mut buf))
                .await
                .expect("relay should accept legit packet")
                .unwrap();
        assert_eq!(&buf[..n], b"hello");

        // 同 IP、不同端口（另一个 socket）→ 与 expected 端口不符 → 丢弃
        let other_port = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        other_port.send_to(b"evil2", relay_addr2).await.unwrap();
        assert_dropped(&relay2, 300, "来源端口与 expected 不符必须被丢弃").await;

        // send_to_expected 落到 expected（client）地址
        let sent = relay2.send_to_expected(b"resp").await.unwrap();
        assert_eq!(sent, 4);
        let mut rbuf = [0u8; 64];
        let (rn, from) = client.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..rn], b"resp");
        assert_eq!(from, relay_addr2);
    }

    /// expected 端口 0（ASSOCIATE 域名/未指定 IP 分支）：首个 IP 匹配来源锁定，
    /// IP 不匹配的来源既不被接受也不触发锁定；锁定后其它端口被拒。
    #[tokio::test]
    async fn relay_port_zero_locks_first_matching_source() {
        // 1) IP 不匹配 → 丢弃且不改写 expected（expected 仍为 127.0.0.2:0）
        let relay_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let relay = TempUdpRelay::new(relay_sock, "127.0.0.2:0".parse().unwrap());
        let foreign = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        foreign.send_to(b"evil", relay_addr).await.unwrap();
        assert_dropped(&relay, 300, "IP 不符的来源不得被接受").await;
        assert_eq!(*relay.expected(), "127.0.0.2:0".parse().unwrap(), "IP 不符不得抢占端口锁定");

        // 2) IP 匹配（127.0.0.1）+ 端口 0 → 首包锁定到该来源的实际端口
        let relay_sock2 = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_addr2 = relay_sock2.local_addr().unwrap();
        let relay2 = TempUdpRelay::new(relay_sock2, "127.0.0.1:0".parse().unwrap());
        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client.send_to(b"first", relay_addr2).await.unwrap();
        let mut buf = [0u8; 64];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(2), relay2.recv_filtered(&mut buf))
                .await
                .expect("first matching source should be accepted")
                .unwrap();
        assert_eq!(&buf[..n], b"first");
        assert_eq!(*relay2.expected(), client.local_addr().unwrap(), "首包锁定到实际来源");

        // 3) 锁定后，同 IP 另一端口 → 丢弃
        let other_port = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        other_port.send_to(b"evil", relay_addr2).await.unwrap();
        assert_dropped(&relay2, 300, "锁定后其它端口必须被丢弃").await;
    }
}
