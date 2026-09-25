//! 契约测试：anytls 客户端拨号必须经 dial_system（bd n65u）。
//!
//! 断言面：server_addr 用 `.test` 保留 TLD 域名 + 注入 FakeDns。直连路径
//! （`TcpStream::connect`）用系统 resolver 查 `.test` 必失败；只有拨号走
//! dial_system 且 sockopt（domain_strategy）被透传时，FakeDns 才被查询并
//! 返回 127.0.0.1 完成真实建链——fake.seen 记录即 sockopt 可观测证据。

#![cfg(test)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use parking_lot::Mutex;
use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use xray_features::dns::{DnsClient, DnsError, IpOption};
use xray_proxy_anytls::{
    client::{AnytlsClient, ClientConfig},
    server::AnytlsMockServer,
    socks::SocksAddr,
};
use xray_transport::{
    sockopt::{DomainStrategy, SocketOptions},
    system_dialer::set_dns_client,
};

/// FakeDns：固定返回 127.0.0.1，记录 (domain, ipv4_enable, ipv6_enable) 供断言。
#[derive(Clone, Default)]
struct FakeDns {
    seen: Arc<Mutex<Vec<(String, bool, bool)>>>,
}

#[async_trait]
impl DnsClient for FakeDns {
    async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<std::net::IpAddr>, u32), DnsError> {
        self.seen.lock().push((domain.to_string(), option.ipv4_enable, option.ipv6_enable));
        Ok((vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)], 300))
    }
}

/// 简单 echo TCP server。
async fn start_echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                        },
                    }
                }
            });
        }
    });
    addr
}

/// 用 rcgen 自签证书生成 rustls server config（SAN = `san_name`），返回
/// (server config, 证书 DER)——DER 供客户端信任锚使用。
fn make_server_config(san_name: &str) -> (RustlsServerConfig, Vec<u8>) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut params = CertificateParams::new(vec![san_name.to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, san_name);
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
    Arc::new(RustlsClientConfig::builder().with_root_certificates(root_store).with_no_client_auth())
}

/// 主契约：anytls 拨号经 dial_system（FakeDns 命中）+ sockopt.domain_strategy
/// 透传生效（seen 记录 UseIPv4 的族过滤）+ 真实建链 echo 往返。
#[tokio::test]
async fn dial_routes_through_dial_system_and_carries_sockopt() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let echo_addr = start_echo_server().await;

    let (server_config, cert_der) = make_server_config("anytls.test");
    let anytls_server = AnytlsMockServer::start(
        "127.0.0.1:0".parse().unwrap(),
        TlsAcceptor::from(Arc::new(server_config)),
        None,
    )
    .await
    .unwrap();
    let port = anytls_server.local_addr.port();

    let fake = FakeDns::default();
    set_dns_client(Some(Arc::new(fake.clone()) as Arc<dyn DnsClient>));

    let sockopt = SocketOptions { domain_strategy: DomainStrategy::UseIPv4, ..Default::default() };
    let client_config = ClientConfig::new(
        format!("anytls.test:{port}"),
        "anytls.test",
        "test-password",
        make_client_config(&cert_der),
    )
    .with_sockopt(sockopt);
    let client = AnytlsClient::new(client_config);

    let target = SocksAddr::ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
    let mut conn = tokio::time::timeout(Duration::from_secs(10), client.dial(&target))
        .await
        .expect("dial timed out")
        .expect("dial failed");

    let payload = b"hello dial_system contract!";
    conn.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.expect("echo read");
    assert_eq!(&got, payload);

    let seen = fake.seen.lock().clone();
    set_dns_client(None);
    let _ = client.close().await;
    anytls_server.stop().await;

    assert!(
        seen.iter().any(|(d, v4, v6)| d == "anytls.test" && *v4 && !*v6),
        "dial must resolve server domain via dial_system DNS with sockopt domain_strategy, seen: {seen:?}"
    );
}
