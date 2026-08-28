//! AnyTLS inbound → dispatcher/router e2e（bd Xray-core-rust-dax）。
//!
//! 拓扑：
//! ```text
//! AnytlsClient → TLS → AnytlsInboundHandler（with_dispatch = DialBridge(freedom)）
//!                                       ↓ handler.dispatch(dest, link)
//!                                       DialBridge → freedom → echo server
//! ```
//!
//! 关键改动：AnytlsMockServer 的 handle_session 从直连 `TcpStream::connect` 改为
//! 走 `dispatch.dispatch(&dest, link)`，inbound 流量经 router 分发。

#![cfg(test)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_app_dispatcher::OutboundHandlerManager;
use xray_features::inbound::InboundHandler;
use xray_proxy_anytls::client::{AnytlsClient, ClientConfig};
use xray_proxy_anytls::inbound::AnytlsInboundHandler;
use xray_proxy_anytls::socks::SocksAddr;
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

/// rcgen 自签证书 → rustls server config + cert_der。
fn make_server_config() -> (RustlsServerConfig, Vec<u8>) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().clone();
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let server_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], key_der.into())
        .unwrap();
    (server_config, cert_der.to_vec())
}

fn make_client_config(server_cert_der: &[u8]) -> Arc<RustlsClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(server_cert_der.to_vec().into()).unwrap();
    Arc::new(
        RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn inbound_dispatches_via_router() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. echo server（远端目标）
    let echo_addr = start_echo_server().await;

    // 2. TLS acceptor（自签证书）
    let (server_config, cert_der) = make_server_config();
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 3. dispatcher + DialBridge(freedom) —— 模拟生产 router
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(Arc::new(DialBridge::new(
        "freedom",
        xray_proxy_freedom::make_freedom_dial_fn(),
    )));
    let dispatch: Arc<dyn xray_app_dispatcher::DispatchHandler> =
        ohm.get_default_handler().unwrap();

    // 4. AnyTLS inbound（with_dispatch）
    let handler = AnytlsInboundHandler::new(
        "anytls-in",
        "127.0.0.1:0".parse().unwrap(),
        tls_acceptor,
    )
    .with_dispatch(dispatch);
    handler.start().await.expect("anytls inbound start");
    let inbound_port = handler.port();
    assert!(inbound_port > 0, "inbound must bind ephemeral port");

    // 5. AnyTLS client → inbound → dispatch → freedom → echo
    let client_config = ClientConfig::new(
        format!("127.0.0.1:{inbound_port}"),
        "localhost",
        make_client_config(&cert_der),
    );
    let client = AnytlsClient::new(client_config);

    let target = SocksAddr::ipv4(Ipv4Addr::LOCALHOST, echo_addr.port());
    let mut conn = tokio::time::timeout(Duration::from_secs(10), client.dial(&target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    let payload = b"hello anytls via inbound dispatcher";
    conn.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .await
        .expect("read_exact should succeed via dispatcher→freedom→echo");
    assert_eq!(&got, payload, "inbound must relay via dispatcher/router");

    drop(conn);
    let _ = client.close().await;
    handler.close().await.expect("inbound close");
}