//! TUIC UDP relay 端到端 loopback 测试（切片2）。
//!
//! 拓扑：
//! ```text
//! TuicClient.dial_udp → QUIC bi-stream → TuicMockServer
//!                                          ↓ UDP send_to
//!                                      UdpEchoServer
//!                                          ↓ UDP recv → echo back
//! TuicClient ← Packet 帧 ← bi-stream ← server recv_from
//! ```

#![cfg(test)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::net::UdpSocket;
use uuid::Uuid;
use xray_proxy_tuic::{
    client::TuicClient, pool::QuinnConnectionPool, protocol::Address, server::TuicMockServer,
};

/// 启动简单 UDP echo server：收到什么就回什么。
async fn start_udp_echo_server() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// 构造 rustls ClientConfig，信任 mock server 自签 cert。
fn make_client_config(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.to_vec().into()).expect("add cert");
    Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
    )
}

#[tokio::test]
async fn udp_loopback_echo_works() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // 2. mock TUIC server
    let uuid = Uuid::new_v4();
    let password = "udp-loopback-test";
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().expect("parse addr"),
        "localhost",
        uuid,
        password.to_string(),
    )
    .await
    .expect("mock server bind");
    let server_addr = server.local_addr();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 3. client connect
    let client_cfg = make_client_config(&cert_der);
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        TuicClient::connect(
            server_addr,
            "localhost",
            uuid,
            password,
            client_cfg,
            QuinnConnectionPool::new(),
        ),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    // 4. dial_udp + send_recv
    let assoc = client.dial_udp(0x0001);
    assert_eq!(assoc.assoc_id(), 0x0001);

    let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let payload = b"hello tuic udp!";
    let resp =
        tokio::time::timeout(Duration::from_secs(15), assoc.send_recv(target, payload, None))
            .await
            .expect("udp send_recv timed out")
            .expect("udp send_recv failed");

    assert_eq!(resp, payload);

    client.close(0u32.into(), b"");
}

#[tokio::test]
async fn udp_loopback_multiple_packets() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let echo_addr = start_udp_echo_server().await;

    let uuid = Uuid::new_v4();
    let password = "udp-multi-pkt-test";
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().expect("parse addr"),
        "localhost",
        uuid,
        password.to_string(),
    )
    .await
    .expect("mock server bind");
    let server_addr = server.local_addr();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_cfg = make_client_config(&cert_der);
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        TuicClient::connect(
            server_addr,
            "localhost",
            uuid,
            password,
            client_cfg,
            QuinnConnectionPool::new(),
        ),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    // 同一 assoc 内发多个包，验证 pkt_id 递增 + 每包独立 bi-stream
    let assoc = client.dial_udp(0xABCD);
    let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());

    for i in 0..5u8 {
        let payload = vec![i; (i as usize + 1) * 10]; // 10, 20, 30, 40, 50 字节
        let resp = tokio::time::timeout(
            Duration::from_secs(15),
            assoc.send_recv(target.clone(), &payload, None),
        )
        .await
        .expect("udp send_recv timed out")
        .expect("udp send_recv failed");
        assert_eq!(resp, payload);
    }

    client.close(0u32.into(), b"");
}
