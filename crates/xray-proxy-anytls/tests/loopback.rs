//! AnyTLS 端到端 loopback 测试。
//!
//! 拓扑：
//! ```text
//! AnytlsClient → TLS → AnytlsMockServer → dial TCP → EchoServer
//!                                              ↓
//! EchoServer ←———————————————————————————————┘
//! ```
//!
//! 测试场景：
//! 1. 起 echo TCP server
//! 2. 自签证书 + 起 AnytlsMockServer
//! 3. AnytlsClient dial 到 echo server
//! 4. 客户端 write → server echo → 客户端 read，验证数据一致

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use xray_proxy_anytls::client::{AnytlsClient, ClientConfig};
use xray_proxy_anytls::server::AnytlsMockServer;
use xray_proxy_anytls::socks::SocksAddr;

/// 简单 echo TCP server，返回收到的字节。
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

/// 用 rcgen 自签证书生成 rustls server config。
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

/// 客户端 TLS config：信任自签证书（dangerous，测试专用）。
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
async fn loopback_echo_works() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // 1. 起 echo server
    let echo_addr = start_echo_server().await;

    // 2. 自签证书 + server config
    let (server_config, cert_der) = make_server_config();
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 3. 起 anytls mock server
    let anytls_server = AnytlsMockServer::start("127.0.0.1:0".parse().unwrap(), tls_acceptor, None)
        .await
        .unwrap();
    let anytls_addr = anytls_server.local_addr;

    // 4. 构造 client config
    let client_config = ClientConfig::new(
        format!("127.0.0.1:{}", anytls_addr.port()),
        "localhost",
        "test-password",
        make_client_config(&cert_der),
    );
    let client = AnytlsClient::new(client_config);

    // 5. dial 到 echo server
    let target = SocksAddr::ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let mut conn = tokio::time::timeout(Duration::from_secs(10), client.dial(&target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    // 6. write + read echo
    let payload = b"hello anytls loopback!";
    conn.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .await
        .expect("read_exact should succeed");
    assert_eq!(&got, payload);

    let _ = client.close().await;
    anytls_server.stop().await;
}

#[tokio::test]
async fn loopback_large_payload() {
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
        "test-password",
        make_client_config(&cert_der),
    );
    let client = AnytlsClient::new(client_config);
    let target = SocksAddr::ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
    let mut conn = tokio::time::timeout(Duration::from_secs(10), client.dial(&target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    // 32 KiB payload，触发 duplex pump 多次循环
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 256) as u8).collect();
    conn.write_all(&payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.expect("read_exact failed");
    assert_eq!(got, payload);

    let _ = client.close().await;
    anytls_server.stop().await;
}
