//! TUIC inbound → dispatcher/router e2e（bd f0m）。
//!
//! 拓扑：
//! ```text
//! TuicClient::dial(echo_addr)
//!   ↓ Connect 帧
//! TuicInboundHandler（with_dispatch）
//!   ↓ handler.dispatch(dest, link)
//! DialBridge(freedom) → echo server
//! ```

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use xray_app_dispatcher::OutboundHandlerManager as _;
use xray_features::inbound::InboundHandler as _;
use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_proxy_tuic::client::TuicClient;
use xray_proxy_tuic::inbound::{TuicInboundConfig, TuicInboundHandler};
use xray_proxy_tuic::pool::QuinnConnectionPool;
use xray_proxy_tuic::protocol::Address;

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
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

#[tokio::test]
async fn tuic_inbound_dispatches_via_router() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. echo server
    let echo_addr = start_echo_server().await;

    // 2. TUIC inbound（dispatch 注入 freedom DialBridge）
    let uuid = Uuid::new_v4();
    let password = "inbound-dispatch-test";
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(Arc::new(DialBridge::new(
        "freedom",
        xray_proxy_freedom::make_freedom_dial_fn(),
    )) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
    let dispatch = ohm.get_default_handler().unwrap();

    let handler = xray_proxy_tuic::TuicInboundHandler::new(
        "tuic-in",
        TuicInboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server_name: "localhost".to_string(),
            uuid,
            password: password.to_string(),
            cert_der: None,
            key_der: None,
        },
    )
    .unwrap()
    .with_dispatch(dispatch);
    handler.start().await.expect("tuic inbound start");
    let server_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        handler.port(),
    );

    // 3. TUIC client connect（trust 自签证书）+ dial echo
    let cert_der = handler.cert_der().expect("cert after start");
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.as_slice().into()).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let client = tokio::time::timeout(
        Duration::from_secs(15),
        TuicClient::connect(server_addr, "localhost", uuid, password, client_cfg, QuinnConnectionPool::new()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let mut conn = tokio::time::timeout(
        Duration::from_secs(10),
        client.dial(Address::Ipv4(
            std::net::Ipv4Addr::LOCALHOST,
            echo_addr.port(),
        )),
    )
    .await
    .expect("dial timed out")
    .expect("dial failed");

    let (mut send, mut recv) = conn.into_split();

    // 4. 写 payload → TUIC inbound → dispatch → freedom → echo → 回读
    let payload = b"hello tuic via dispatcher";
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    recv.read_exact(&mut got).await.expect("echo read");
    assert_eq!(&got, payload, "tuic inbound must relay via dispatcher");
}
