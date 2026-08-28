//! AnyTLS outbound → dispatcher → DialBridge 端到端测试（切片 1a）。
//!
//! 拓扑：
//! ```text
//! DefaultDispatcher
//!   ↓ dispatch
//! inbound Link（writer/reader）
//!   ↓ DialBridge → AnytlsClient::dial → AnytlsConnection
//! AnytlsMockServer
//!   ↓ 解 SOCKS5 + dial
//! EchoServer
//! ```
//!
//! 测试场景：通过 dispatcher 写入 payload → 经 anytls 协议层 → mock server 解码目标 →
//! 拨号到 echo server → echo 返回 → 经 anytls 反向 → 回到 reader。

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm};
use xray_app_dispatcher::default::SniffingRequest;
use xray_buf::io::{Reader, Writer};
use xray_buf::multi::MultiBuffer;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_anytls::client::{AnytlsClient, ClientConfig};
use xray_proxy_anytls::dispatcher::make_dial_fn;
use xray_proxy_anytls::server::AnytlsMockServer;

/// 起简单 echo TCP server。
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// rcgen 自签证书 → rustls server config + cert_der（供 client trust）。
fn make_server_config() -> (RustlsServerConfig, Vec<u8>) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "localhost");
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
async fn dispatcher_e2e_anytls_loopback_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. echo server
    let echo_addr = start_echo_server().await;

    // 2. anytls mock server
    let (server_config, cert_der) = make_server_config();
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let anytls_server = AnytlsMockServer::start("127.0.0.1:0".parse().unwrap(), tls_acceptor, None)
        .await
        .unwrap();
    let anytls_addr = anytls_server.local_addr;

    // 3. anytls client
    let client_config = ClientConfig::new(
        format!("127.0.0.1:{}", anytls_addr.port()),
        "localhost",
        make_client_config(&cert_der),
    );
    let client = Arc::new(AnytlsClient::new(client_config));

    // 4. dispatcher + DialBridge(AnytlsClient)
    let ohm = SimpleOhm::new();
    ohm.set_default(Arc::new(DialBridge::new(
        "anytls-out",
        make_dial_fn(Arc::clone(&client)),
    )));
    let mut dispatcher = DefaultDispatcher::new();
    dispatcher.ohm = Some(Arc::new(ohm));

    // 5. dispatch 目标 = echo server（IPv4 127.0.0.1:port）
    let dest = Destination::new(
        Address::from_ipv4_bytes([127, 0, 0, 1]),
        Port::new(echo_addr.port()),
        Network::TCP,
    );
    let inbound = dispatcher
        .dispatch(&dest, &SniffingRequest::default(), None, None)
        .expect("dispatch returns inbound Link");

    let mut w = inbound.writer;
    let mut r = inbound.reader;

    // 6. 写 payload → anytls → mock server → dial echo → echo 回流
    let payload = b"hello anytls via dispatcher";
    let mut mb = MultiBuffer::new();
    mb.merge_bytes(payload);
    w.write_multi_buffer(mb).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(15), r.read_multi_buffer())
        .await
        .expect("timeout waiting for echo response")
        .unwrap();

    assert_eq!(resp.to_vec(), payload);

    // 7. shutdown 通知 bridge 结束
    w.shutdown();

    // 8. 清理
    drop(w);
    drop(r);
    let _ = client.close().await;
    anytls_server.stop().await;
}

#[tokio::test]
async fn dispatcher_e2e_anytls_loopback_large_payload() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let echo_addr = start_echo_server().await;
    let (server_config, cert_der) = make_server_config();
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let anytls_server = AnytlsMockServer::start("127.0.0.1:0".parse().unwrap(), tls_acceptor, None)
        .await
        .unwrap();
    let anytls_addr = anytls_server.local_addr;

    let client_config = ClientConfig::new(
        format!("127.0.0.1:{}", anytls_addr.port()),
        "localhost",
        make_client_config(&cert_der),
    );
    let client = Arc::new(AnytlsClient::new(client_config));

    let ohm = SimpleOhm::new();
    ohm.set_default(Arc::new(DialBridge::new(
        "anytls-out-large",
        make_dial_fn(Arc::clone(&client)),
    )));
    let mut dispatcher = DefaultDispatcher::new();
    dispatcher.ohm = Some(Arc::new(ohm));

    let dest = Destination::new(
        Address::from_ipv4_bytes([127, 0, 0, 1]),
        Port::new(echo_addr.port()),
        Network::TCP,
    );
    let inbound = dispatcher
        .dispatch(&dest, &SniffingRequest::default(), None, None)
        .expect("dispatch returns inbound Link");

    let mut w = inbound.writer;
    let mut r = inbound.reader;

    // 32 KiB payload：触发 anytls session pump + dispatcher bridge 多次循环
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 256) as u8).collect();
    let mut mb = MultiBuffer::new();
    mb.merge_bytes(&payload);
    w.write_multi_buffer(mb).await.unwrap();

    // 大 payload 分多次读，累积到完整长度
    let mut got = Vec::with_capacity(payload.len());
    while got.len() < payload.len() {
        let chunk = tokio::time::timeout(Duration::from_secs(30), r.read_multi_buffer())
            .await
            .expect("timeout waiting for chunk")
            .unwrap();
        if chunk.is_empty() {
            break;
        }
        got.extend_from_slice(&chunk.to_vec());
    }
    assert_eq!(got, payload);

    w.shutdown();
    drop(w);
    drop(r);
    let _ = client.close().await;
    anytls_server.stop().await;
}
