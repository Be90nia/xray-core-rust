//! E2E: Trojan proxy → dial_system → bridge_connections → echo target
//!
//! 验证 Trojan 代理完整链路：客户端通过 Trojan 协议连接 echo 服务器。

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_trojan::hex_sha224;
use xray_proxy_trojan::config::MemoryAccount;
use xray_proxy_trojan::server::trojan_server_handshake;
use xray_proxy_trojan::validator::{MemoryUser, Validator};
use xray_transport::bridge::bridge_connections;
use xray_transport::connection::TcpConnection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

/// Trojan 代理 → freedom → echo 端到端验证。
#[tokio::test]
async fn trojan_proxy_to_echo_target_e2e() {
    let password = "test_trojan_password";

    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // ===== 2. Trojan proxy =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();

    // 创建 validator 注册测试用户
    let validator = Arc::new(Validator::new());
    let account = MemoryAccount::new(password.to_string());
    let user = MemoryUser::new("test@example.com", 0, account);
    validator.add(user).expect("add user");

    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        let (network, addr, port, _user) =
            trojan_server_handshake(&mut client_stream, &validator_clone)
                .await
                .expect("handshake");
        let dest_network = match network {
            xray_proxy_trojan::Network::Tcp => Network::TCP,
            xray_proxy_trojan::Network::Udp => Network::UDP,
        };
        let destination = Destination::new(addr, Port::new(port), dest_network);
        let target_conn = dial_system(&destination, &SocketOptions::default())
            .await
            .expect("dial target");
        let client_conn: Box<dyn xray_transport::connection::Connection> =
            Box::new(TcpConnection::new(client_stream));
        let _ = bridge_connections(client_conn, target_conn).await;
    });

    // ===== 3. 客户端: Trojan 协议 =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // 构造 Trojan 请求头: hex(sha224(password)) + CRLF + CMD + ATYP + addr + port + CRLF
    let key_hex = hex_sha224(password); // 56 hex chars
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(&key_hex); // 56 bytes hex key
    header.extend_from_slice(b"\r\n"); // CRLF
    header.push(0x01); // CMD = TCP
    header.push(0x01); // ATYP = IPv4
    let echo_v4 = match echo_ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 echo addr"),
    };
    header.extend_from_slice(&echo_v4.octets()); // 4 bytes IP
    header.extend_from_slice(&echo_port.to_be_bytes()); // 2 bytes port
    header.extend_from_slice(b"\r\n"); // CRLF

    client.write_all(&header).await.unwrap();

    // Trojan 握手无服务端响应，直接发送数据
    let payload = b"hello trojan e2e!";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..], payload, "echo should match sent data");
}

/// Trojan 无效用户被拒绝。
#[tokio::test]
async fn trojan_invalid_user_rejected_e2e() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();

    // validator 只注册正确密码
    let validator = Arc::new(Validator::new());
    let account = MemoryAccount::new("correct_password".to_string());
    let user = MemoryUser::new("legit@example.com", 0, account);
    validator.add(user).unwrap();

    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        // 用错误密码握手 → 应失败
        let result = trojan_server_handshake(&mut client_stream, &validator_clone).await;
        assert!(result.is_err(), "handshake should fail with wrong key");
    });

    // 客户端用错误密码
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let wrong_key = hex_sha224("wrong_password");
    let mut header = Vec::new();
    header.extend_from_slice(&wrong_key);
    header.extend_from_slice(b"\r\n");
    header.push(0x01); // TCP
    header.push(0x01); // IPv4
    if let std::net::IpAddr::V4(v4) = echo_ip {
        header.extend_from_slice(&v4.octets());
    }
    header.extend_from_slice(&echo_port.to_be_bytes());
    header.extend_from_slice(b"\r\n");
    client.write_all(&header).await.unwrap();

    // 服务端关闭连接，client 写或读应失败
    let mut buf = vec![0u8; 16];
    let _ = client.read(&mut buf).await;
}
