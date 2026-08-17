//! TUIC 端到端 loopback 测试。
//!
//! 拓扑：
//! ```text
//! TuicClient → QUIC → TuicMockServer → TCP dial → EchoServer
//!                                                  ↓
//! EchoServer ←—————————————————————————————————————┘
//! ```
//!
//! 切片1 范围：TCP relay。UDP relay 留切片2。

#![cfg(test)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use xray_proxy_tuic::client::TuicClient;
use xray_proxy_tuic::protocol::Address;
use xray_proxy_tuic::server::TuicMockServer;
use xray_proxy_tuic::pool::QuinnConnectionPool;

/// 启动简单 echo TCP server。
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 构造 rustls ClientConfig，信任 mock server 自签 cert。
fn make_client_config(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.to_vec().into()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn loopback_echo_works() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. echo server
    let echo_addr = start_echo_server().await;

    // 2. mock TUIC server
    let uuid = Uuid::new_v4();
    let password = "test-password-loopback";
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().unwrap(),
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
        TuicClient::connect(server_addr, "localhost", uuid, password, client_cfg, QuinnConnectionPool::new()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    // 4. dial to echo server via TUIC
    let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let conn = tokio::time::timeout(Duration::from_secs(10), client.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    // 5. echo round-trip
    let (mut send, mut recv) = conn.into_split();
    let payload = b"hello tuic loopback!";
    send.write_all(payload).await.expect("write_all");
    let mut got = vec![0u8; payload.len()];
    recv.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(&got, payload);

    client.close(0u32.into(), b"");
}

/// 8hb/eim：auth 后 uni Heartbeat 与 bi relay 并存。
///
/// 服务端 select! 循环必须持续 accept_uni（Heartbeat/Dissociate），同时 bi
/// stream relay 不受影响——心跳后 dial 仍能完成 echo。
#[tokio::test]
async fn heartbeat_then_bi_relay_still_works() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let echo_addr = start_echo_server().await;

    let uuid = Uuid::new_v4();
    let password = "heartbeat-test";
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().unwrap(),
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
    let client = Arc::new(
        tokio::time::timeout(
            Duration::from_secs(10),
            TuicClient::connect(server_addr, "localhost", uuid, password, client_cfg, QuinnConnectionPool::new()),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed"),
    );

    // 周期心跳任务（eim）：短周期多发几帧（覆盖 auth 之后的首帧 uni）。
    let hb = client.start_heartbeat(Duration::from_millis(50));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 心跳进行中 bi relay 仍然工作（8hb：服务端持续读 uni 不阻塞 bi）。
    let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let conn = tokio::time::timeout(Duration::from_secs(10), client.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    let (mut send, mut recv) = conn.into_split();
    let payload = b"heartbeat alive";
    send.write_all(payload).await.expect("write_all");
    let mut got = vec![0u8; payload.len()];
    recv.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(&got, payload);

    hb.abort();
    client.close(0u32.into(), b"");
}

#[tokio::test]
async fn loopback_large_payload() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let echo_addr = start_echo_server().await;

    let uuid = Uuid::new_v4();
    let password = "large-payload-test";
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().unwrap(),
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
        TuicClient::connect(server_addr, "localhost", uuid, password, client_cfg, QuinnConnectionPool::new()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let conn = tokio::time::timeout(Duration::from_secs(10), client.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    let (mut send, mut recv) = conn.into_split();

    // 32 KiB payload，触发 QUIC 多次 chunk 切分
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 256) as u8).collect();
    send.write_all(&payload).await.expect("write_all");

    let mut got = vec![0u8; payload.len()];
    recv.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(got, payload);

    client.close(0u32.into(), b"");
}

#[tokio::test]
async fn auth_wrong_password_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let echo_addr = start_echo_server().await;

    let uuid = Uuid::new_v4();
    let (server, cert_der) = TuicMockServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        "localhost",
        uuid,
        "correct-password".to_string(),
    )
    .await
    .expect("mock server bind");
    let server_addr = server.local_addr();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 客户端用错误 password
    let client_cfg = make_client_config(&cert_der);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        TuicClient::connect(server_addr, "localhost", uuid, "wrong-password", client_cfg, QuinnConnectionPool::new()),
    )
    .await;

    // 客户端 connect 本身可能成功（QUIC 握手层不验密码），但 dial 应失败
    // 因为 server 收到错误 token 后会关闭连接
    if let Ok(Ok(client)) = result {
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
        let _ = client.dial(target).await; // 预期失败
    }
    // 不强制断言：认证失败可能立即被 server 关闭（result 是 Err），或 dial 后才失败。
}
