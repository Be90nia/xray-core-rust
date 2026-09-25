//! SOCKS outbound → DialBridge 适配器。
//!
//! 把 [`SocksClient`] 接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_dial_fn`] 闭包，内部把 [`Destination`] 转 [`SocksAddr`] 后调
//! [`SocksClient::dial`]，再用 [`TcpConnection`] 包装为 `Box<dyn Connection>`。
//!
//! 模式完全照搬 [`xray-proxy-anytls::dispatcher`]（已验证的拨号型 outbound adapter）。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::sync::Arc;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::{address::Address, destination::Destination};
use xray_transport::connection::{Connection, TcpConnection};

use crate::{client::SocksClient, protocol::SocksAddr};

/// 构造 [`DialBridge`] 用的 [`DialFn`] 闭包。
///
/// 闭包捕获 `Arc<SocksClient>`，每次调用：
/// 1. 把 [`Destination`] 转 [`SocksAddr`]（同步）
/// 2. `client.dial(&socks)` 拨号到 SOCKS 服务端（内部完成 SOCKS5 handshake）
/// 3. 包装返回 [`TcpConnection`]（impl [`Connection`]）
///
/// # Panics
///
/// 不会 panic；任何错误（dial 失败）以 `Err(String)` 返回。
pub fn make_dial_fn(client: Arc<SocksClient>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let client = Arc::clone(&client);
        let socks = dest_to_socks(dest);
        Box::pin(async move {
            let stream = client.dial(&socks).await.map_err(|e| format!("socks dial: {e}"))?;
            Ok(Box::new(TcpConnection::new(stream)) as Box<dyn Connection>)
        })
    })
}

/// Destination → SocksAddr 转换（IPv4 / IPv6 / Domain）。
fn dest_to_socks(dest: &Destination) -> SocksAddr {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => SocksAddr::ipv4(*ip, port),
        Address::IPv6(ip) => SocksAddr::ipv6(*ip, port),
        Address::Domain(d) => SocksAddr::domain(d.clone(), port),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use xray_common::net::{network::Network, port::Port};

    use super::*;

    #[test]
    fn dest_to_socks_ipv4() {
        let d = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(8080),
            Network::TCP,
        );
        let s = dest_to_socks(&d);
        match s.host {
            crate::protocol::Host::Ipv4(ip) => {
                assert_eq!(ip.octets(), [127, 0, 0, 1]);
            },
            _ => panic!("expected Ipv4"),
        }
        assert_eq!(s.port, 8080);
    }

    #[test]
    fn dest_to_socks_ipv6() {
        let d = Destination::new(
            Address::from_ipv6_bytes(Ipv6Addr::LOCALHOST.octets()),
            Port::new(443),
            Network::TCP,
        );
        let s = dest_to_socks(&d);
        match s.host {
            crate::protocol::Host::Ipv6(ip) => {
                assert_eq!(ip, Ipv6Addr::LOCALHOST);
            },
            _ => panic!("expected Ipv6"),
        }
        assert_eq!(s.port, 443);
    }

    #[test]
    fn dest_to_socks_domain() {
        let d = Destination::new(Address::new_domain("example.com"), Port::new(443), Network::TCP);
        let s = dest_to_socks(&d);
        match s.host {
            crate::protocol::Host::Domain(d) => {
                assert_eq!(d, "example.com");
            },
            _ => panic!("expected Domain"),
        }
        assert_eq!(s.port, 443);
    }

    /// e2e：DialFn 闭包→ SocksClient dial → 通过 mock socks server 转 echo → 读回。
    #[tokio::test]
    async fn make_dial_fn_e2e_through_mock_socks_server() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        use crate::{client::ClientConfig, config::ServerConfig, server::socks5_server_handshake};

        // 启动 echo socks server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let _target =
                            socks5_server_handshake(&mut sock, &ServerConfig::default()).await;
                        // echo
                        let mut buf = [0u8; 256];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                },
                            }
                        }
                        let _ = sock;
                    });
                } else {
                    break;
                }
            }
        });

        // 构造 DialFn
        let client = Arc::new(SocksClient::new(ClientConfig::new_noauth(server_addr.to_string())));
        let dial_fn = make_dial_fn(client);

        // 调用 DialFn 拨到一个 dummy target（mock 不真连）
        let dest = Destination::new(
            Address::new_domain("dummy.example.com"),
            Port::new(443),
            Network::TCP,
        );
        let mut conn = dial_fn(&dest).await.expect("dial_fn should succeed");

        // AsyncWrite for Box<dyn Connection> 由 blanket impl 提供
        let payload = b"socks dial fn e2e";
        conn.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload);

        server.abort();
    }
}
