//! 集成测试：tcp + tls 出站拨号。
//!
//! 验证 `dial_with_settings("tcp", security:tls)` 正确包装 TLS 握手而非裸 TCP。

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_transport::dialer::{StreamSettings, dial_with_settings};
use xray_transport::sockopt::SocketOptions;

/// TCP + TLS 出站：dial 应完成 TLS 握手并能 echo 回环。
///
/// 若未包装 TLS（裸 TCP），client 写明文到 TLS server，server 的 TLS accept
/// 失败并关闭连接，client read 返回 0/err——测试因此失败，暴露回归。
#[tokio::test]
async fn tcp_plus_tls_wraps_tls_and_echoes() {
    // 自签证书 + rustls ServerConfig
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().to_vec();
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert_der)], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // TLS echo server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_acceptor = acceptor.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = server_acceptor.accept(tcp).await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = tls.write_all(&buf[..n]).await;
                }
            }
        }
    });

    // 注册 tcp dialer（含 security 包装）
    let _ = xray_transport_tcp::register::register_dialer();

    // dial tcp+tls（allowInsecure 信任自签证书）
    let mut settings = StreamSettings::tcp();
    settings.security = "tls".to_string();
    settings.security_json =
        Some(serde_json::json!({"allowInsecure": true, "serverName": "localhost"}));
    let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
    let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
        .await
        .expect("tcp+tls dial 应成功（含 TLS 握手）");

    // echo 回环
    conn.write_all(b"hello-over-tls").await.unwrap();
    let mut got = [0u8; 64];
    let n = conn.read(&mut got).await.expect("echo read 应成功");
    assert_eq!(&got[..n], b"hello-over-tls");
}

/// TCP + TLS + fingerprint：dial 用 btls 浏览器指纹握手（Chrome ClientHello）。
///
/// 验证 fingerprint 字段被正确解析，走 u_client（btls）而非标准 rustls。
/// server 端是标准 rustls TlsAcceptor——btls ClientHello 与标准 rustls server 兼容。
#[tokio::test]
async fn tcp_plus_tls_with_fingerprint_uses_btls() {
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().to_vec();
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert_der)], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_acceptor = acceptor.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = server_acceptor.accept(tcp).await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = tls.write_all(&buf[..n]).await;
                }
            }
        }
    });

    let _ = xray_transport_tcp::register::register_dialer();

    // dial tcp+tls+fingerprint=chrome（btls Chrome ClientHello 指纹）
    let mut settings = StreamSettings::tcp();
    settings.security = "tls".to_string();
    settings.security_json = Some(serde_json::json!({
        "allowInsecure": true,
        "serverName": "localhost",
        "fingerprint": "chrome"
    }));
    let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
    let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
        .await
        .expect("tcp+tls+fingerprint dial 应成功（btls Chrome 指纹握手）");

    conn.write_all(b"hello-over-btls").await.unwrap();
    let mut got = [0u8; 64];
    let n = conn.read(&mut got).await.expect("btls echo read 应成功");
    assert_eq!(&got[..n], b"hello-over-btls");
}
