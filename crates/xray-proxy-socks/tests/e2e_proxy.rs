//! E2E: socks5 inbound → dial_system → bridge_connections → echo target
//!
//! 验证完整代理链路：客户端通过 SOCKS5 代理连接 echo 服务器，数据双向流通。
//! 这是 SystemDialer/SystemListener/bridge_connections/freedom/socks 协同工作的端到端证明。

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::InboundHandler;
use xray_proxy_socks::{
    config::{AuthType, ServerConfig},
    protocol::Host,
    server::{SocksServer, socks5_server_handshake},
};
use xray_transport::{
    bridge::bridge_connections, connection::TcpConnection, sockopt::SocketOptions,
    system_dialer::dial_system,
};

/// 手动组装 socks proxy → dial_system → bridge 链路，验证 echo 往返。
#[tokio::test]
async fn socks5_proxy_to_echo_target_e2e() {
    // ===== 1. 启动 echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        // 简单 echo：把读到的数据原样写回
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // ===== 2. 启动 socks proxy（手动组装，不用 SocksServer::start）=====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        // SOCKS5 handshake（NoAuth）
        let config = ServerConfig { auth_type: AuthType::NoAuth, ..Default::default() };
        let dest = socks5_server_handshake(&mut client_stream, &config).await.expect("handshake");
        // SocksRequest::TcpConnect(SocksAddr) → Destination
        let dest_addr = match dest {
            xray_proxy_socks::server::SocksRequest::TcpConnect(addr) => addr,
            _ => panic!("expected TcpConnect"),
        };
        let address = match dest_addr.host {
            Host::Ipv4(ip) => Address::IPv4(ip),
            Host::Ipv6(ip) => Address::IPv6(ip),
            Host::Domain(_) => panic!("expected IP address from handshake"),
        };
        let destination = Destination::new(address, Port::new(dest_addr.port), Network::TCP);
        // dial target
        let target_conn =
            dial_system(&destination, &SocketOptions::default()).await.expect("dial target");
        // bridge client ↔ target
        let client_conn: Box<dyn xray_transport::connection::Connection> =
            Box::new(TcpConnection::new(client_stream));
        let _ = bridge_connections(client_conn, target_conn).await;
    });

    // ===== 3. 客户端：SOCKS5 CONNECT → 发数据 → 收 echo =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // 3a. 发 SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=NoAuth(0x00)
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_resp = [0u8; 2];
    client.read_exact(&mut method_resp).await.unwrap();
    assert_eq!(method_resp[0], 0x05, "SOCKS version");
    assert_eq!(method_resp[1], 0x00, "selected method = NoAuth");

    // 3b. 发 CONNECT 请求: VER=5, CMD=1(CONNECT), RSV=0, ATYP=1(IPv4), IP, PORT
    client.write_all(&[0x05, 0x01, 0x00, 0x01]).await.unwrap();
    match echo_ip {
        std::net::IpAddr::V4(v4) => client.write_all(&v4.octets()).await.unwrap(),
        std::net::IpAddr::V6(v6) => client.write_all(&v6.octets()).await.unwrap(),
    }
    client.write_all(&echo_port.to_be_bytes()).await.unwrap();

    // 3c. 读 CONNECT 响应: VER, REP, RSV, ATYP=1, 4B IP, 2B PORT = 10 bytes
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "reply SOCKS version");
    assert_eq!(reply[1], 0x00, "reply REP = success");

    // 3d. 通过代理隧道发数据，收 echo 回来
    let payload = b"hello socks5 e2e!";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..], payload, "echo should match sent data");
}

/// 验证 SocksServer::start + accept loop 模式可以工作（不 dispatch，仅 handshake）。
/// 这是 SocksServer lifecycle 端到端验证。
#[tokio::test]
async fn socks_server_start_and_handshake_lifecycle() {
    let server = SocksServer::new(
        "test-socks",
        ServerConfig { auth_type: AuthType::NoAuth, ..Default::default() },
    );
    server.start().await.unwrap();
    let port = server.bound_port().await;
    assert!(port > 0, "bound port should be non-zero after start");

    // 客户端连接，做 greeting + method negotiation
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    server.close().await.unwrap();
    // close 后 bound_port 应为 0
    let port_after = server.bound_port().await;
    assert_eq!(port_after, 0, "port should be 0 after close");
}
