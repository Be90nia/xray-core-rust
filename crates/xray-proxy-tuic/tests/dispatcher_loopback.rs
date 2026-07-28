//! TUIC outbound → dispatcher → DialBridge 端到端测试（切片 1b）。
//!
//! 拓扑：
//! ```text
//! DefaultDispatcher
//!   ↓ dispatch
//! inbound Link（writer/reader）
//!   ↓ DialBridge → TuicClient::dial → TuicConnection（duplex pump）
//! TuicMockServer
//!   ↓ 解 Connect + dial TCP
//! EchoServer
//! ```

#![cfg(test)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm, SniffingRequest};
use xray_buf::io::{Reader, Writer};
use xray_buf::multi::MultiBuffer;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_tuic::client::TuicClient;
use xray_proxy_tuic::dispatcher::make_dial_fn;
use xray_proxy_tuic::server::TuicMockServer;
use xray_proxy_tuic::pool::QuinnConnectionPool;

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
async fn dispatcher_e2e_tuic_loopback_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. echo server
    let echo_addr = start_echo_server().await;

    // 2. TUIC mock server
    let uuid = Uuid::new_v4();
    let password = "dispatcher-test-password";
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

    // 3. TUIC client connect + auth
    let client_cfg = make_client_config(&cert_der);
    let client_inner = tokio::time::timeout(
        Duration::from_secs(15),
        TuicClient::connect(server_addr, "localhost", uuid, password, client_cfg, QuinnConnectionPool::new()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    let client = Arc::new(client_inner);

    // 4. dispatcher + DialBridge(TuicClient)
    let ohm = SimpleOhm::new();
    ohm.set_default(Arc::new(DialBridge::new(
        "tuic-out",
        make_dial_fn(Arc::clone(&client)),
    )));
    let mut dispatcher = DefaultDispatcher::new();
    dispatcher.ohm = Some(Arc::new(ohm));

    // 5. dispatch 目标 = echo server
    let dest = Destination::new(
        Address::ipv4(Ipv4Addr::new(127, 0, 0, 1)),
        Port::new(echo_addr.port()),
        Network::TCP,
    );
    let inbound = dispatcher
        .dispatch(&dest, &SniffingRequest::default())
        .expect("dispatch returns inbound Link");

    let mut w = inbound.writer;
    let mut r = inbound.reader;

    // 6. 写 payload → TUIC → mock server → dial echo → echo 回流
    let payload = b"hello tuic via dispatcher";
    let mut mb = MultiBuffer::new();
    mb.merge_bytes(payload);
    w.write_multi_buffer(mb).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(30), r.read_multi_buffer())
        .await
        .expect("timeout waiting for echo response")
        .unwrap();

    assert_eq!(resp.to_vec(), payload);

    w.shutdown();
    drop(w);
    drop(r);
    // 给 QUIC 一点时间清理
    tokio::time::sleep(Duration::from_millis(100)).await;
}
