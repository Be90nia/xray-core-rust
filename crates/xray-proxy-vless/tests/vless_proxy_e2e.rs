//! E2E: VLESS proxy → dial_system → bridge_connections → echo target
//!
//! 验证 VLESS 协议完整链路（无加密层，FLOW_NONE 模式）：
//! 客户端 encode_request_header → 服务端 decode_request_header → dial → bridge → echo。

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    uuid::UUID,
};
use xray_proto::xray::proxy::vless::encoding::Addons;
use xray_proxy_vless::{
    Validator,
    account::MemoryAccount,
    encoding::{
        VlessCommand,
        client::encode_request_header,
        server::{decode_request_header, encode_response_header},
    },
    validator::MemoryValidator,
};
use xray_transport::{
    bridge::bridge_connections, connection::TcpConnection, sockopt::SocketOptions,
    system_dialer::dial_system,
};

/// VLESS 协议版本（对应 Go `encoding` 包常量）。
const VLESS_VERSION: u8 = 0;

/// VLESS proxy → freedom → echo 端到端验证（无加密模式）。
#[tokio::test]
async fn vless_proxy_to_echo_target_e2e() {
    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // ===== 2. 创建 UUID + validator =====
    let uuid = UUID::new();
    let validator = MemoryValidator::new();
    let account = MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
        id: uuid.to_string(),
        ..Default::default()
    })
    .unwrap();
    let user = xray_proxy_vless::validator::MemoryUser {
        level: 0,
        email: "test@example.com".to_string(),
        account,
    };
    validator.add(user).unwrap();

    // ===== 3. proxy server =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();

    let validator = std::sync::Arc::new(validator);
    let validator_clone = std::sync::Arc::clone(&validator);
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();

        // 解码 VLESS 请求头
        let decoded =
            decode_request_header(false, &mut None, &mut client_stream, &*validator_clone)
                .await
                .expect("decode request header");

        // 发送 VLESS 响应头
        let addons = Addons::default();
        encode_response_header(&mut client_stream, VLESS_VERSION, &addons)
            .await
            .expect("encode response header");

        // 拨号目标
        let addr = decoded.address.expect("address");
        let port = decoded.port.expect("port");
        let dest = Destination::new(addr, Port::new(port), Network::TCP);
        let target_conn = dial_system(&dest, &SocketOptions::default()).await.expect("dial target");

        // 桥接 client ↔ target
        let client_conn: Box<dyn xray_transport::connection::Connection> =
            Box::new(TcpConnection::new(client_stream));
        let _ = bridge_connections(client_conn, target_conn).await;
    });

    // ===== 4. 客户端: VLESS 请求 =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // 构造目标地址
    let echo_v4 = match echo_ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 echo addr"),
    };
    let dest_addr = Address::IPv4(echo_v4);

    // 编码并发送 VLESS 请求头
    let addons = Addons::default();
    encode_request_header(
        &mut client,
        VLESS_VERSION,
        &uuid,
        VlessCommand::Tcp,
        Some(&dest_addr),
        Some(echo_port),
        &addons,
    )
    .await
    .expect("encode request header");

    // 读 VLESS 响应头（version 1B + addons_len 1B = 2B 最小）
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // 通过隧道发数据，收 echo
    let payload = b"hello vless e2e!";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..], payload, "echo should match sent data");
}

/// VLESS 无效 UUID 被拒绝。
#[tokio::test]
async fn vless_invalid_uuid_rejected_e2e() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // validator 只注册正确 UUID
    let valid_uuid = UUID::new();
    let validator = MemoryValidator::new();
    let account = MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
        id: valid_uuid.to_string(),
        ..Default::default()
    })
    .unwrap();
    let user = xray_proxy_vless::validator::MemoryUser {
        level: 0,
        email: "legit@example.com".to_string(),
        account,
    };
    validator.add(user).unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();

    let validator = std::sync::Arc::new(validator);
    let validator_clone = std::sync::Arc::clone(&validator);
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        let result =
            decode_request_header(false, &mut None, &mut client_stream, &*validator_clone).await;
        assert!(result.is_err(), "decode should fail with unknown UUID");
    });

    // 客户端用不同 UUID
    let wrong_uuid = UUID::new();
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let echo_v4 = match echo_ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4"),
    };
    let addons = Addons::default();
    encode_request_header(
        &mut client,
        VLESS_VERSION,
        &wrong_uuid,
        VlessCommand::Tcp,
        Some(&Address::IPv4(echo_v4)),
        Some(echo_port),
        &addons,
    )
    .await
    .unwrap();

    // 服务端关闭连接
    let mut buf = vec![0u8; 16];
    let _ = client.read(&mut buf).await;
}
