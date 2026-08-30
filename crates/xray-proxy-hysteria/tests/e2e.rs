//! Hysteria 真实 QUIC 回环 e2e（bd ghp0）。
//!
//! 拓扑：
//! ```text
//! QuinnHysteriaTransport (client)
//!   ↓ QUIC dial + h3 /auth (token=test-secret)
//! QuinnListenerFactory (server, h3 + on_new_conn → echo)
//!   ↓ server InterStreamConn 自闭环 echo
//! client InterStreamConn 写 → server 读 → server 写回 → client 读
//! ```
//!
//! 对应 Go `proxy/hysteria/client.go::Client.Process`(TCP) — 在 QUIC bidi stream 上
//! 透明双向转发。当前测试聚焦 QUIC 全链路（dial + auth + bidi stream + handler），
//! 与 `dispatcher.rs::udp_dial_fn_relays_xudp_frames_through_interconn` 互补：
//! 那个测 UDP/XUDP 桥（mock HysteriaTransport），本测测真 QUIC 全链路。

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use xray_transport_hysteria::hub::HysteriaListenerFactory as _;

use tokio::sync::mpsc;
use xray_transport_hysteria::conn::InterStreamConn;
use xray_transport_hysteria::dialer::{DialDestination, HysteriaTransport, QuicConfig};
use xray_transport_hysteria::hub::{AuthValidator, MasqType};
use xray_transport_hysteria::hysteria_transport::QuinnHysteriaTransport;
use xray_transport_hysteria::proto_config::Config as ProtoConfig;
use xray_transport_hysteria::quinn_adapter::QuinnListenerFactory;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 自签证书（CN=localhost）
fn self_signed() -> (Vec<rustls_pki_types::CertificateDer<'static>>, rustls_pki_types::PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();
    (
        vec![cert_der.into()],
        rustls_pki_types::PrivateKeyDer::try_from(key_der).unwrap(),
    )
}

/// 接受任意服务端证书的 verifier（仅测试用）。
#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct TestValidator;
impl AuthValidator for TestValidator {
    fn validate(&self, auth: &str) -> Option<String> {
        if auth == "test-secret" { Some("user".into()) } else { None }
    }
    fn count(&self) -> usize { 1 }
}

#[tokio::test]
async fn hysteria_quic_loopback_dial_auth_bidi_roundtrip() {
    ensure_crypto_provider();

    // 1. server 证书 + listener
    let (cert_chain, key_der) = self_signed();
    let server_tls = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .unwrap();
    let factory = QuinnListenerFactory::new(Arc::new(server_tls));
    let proto_cfg = Arc::new(ProtoConfig::default());
    let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
    let validator: Option<Arc<dyn AuthValidator>> = Some(Arc::new(TestValidator));

    // 2. on_new_conn 把 server-side InterStreamConn 投递给回环 task
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<Arc<InterStreamConn>>();
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> =
        Arc::new(move |s| { let _ = stream_tx.send(s); });
    let listener = factory
        .listen(
            "127.0.0.1:0".parse().unwrap(),
            proto_cfg,
            quic_params,
            MasqType::NotFound,
            validator,
            on_new_conn,
        )
        .await
        .expect("factory listen should succeed");
    let server_addr: SocketAddr = listener.local_addr();

    // 3. client 端：trust 自签证书 + udp bind
    let client_tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let transport = Arc::new(
        QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport"),
    );

    // 4. dial + auth（实际 QUIC 握手 + h3 /auth 状态码 233）
    let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
    let qc = QuicConfig::default_for_hysteria();
    let conn = tokio::time::timeout(
        Duration::from_secs(15),
        transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
    )
    .await
    .expect("dial+auth timeout (15s)")
    .expect("dial+auth should succeed");
    // 5. 开 bidi data stream（client=false 等价 server-perspective enabled 后 client=true，
    // quinn 0.11 open_bi 是 lazy：必须先 write 让 STREAM frame 落地，server accept_bi 才会返回）。
    let quinn_conn = conn
        .as_quinn_connection()
        .expect("QuicConn 必须暴露 as_quinn_connection")
        .clone();
    let (send, recv) = tokio::time::timeout(
        Duration::from_secs(10),
        quinn_conn.open_bi(),
    )
    .await
    .expect("open_bi timeout")
    .expect("open_bi");
    let qs = xray_transport_hysteria::quinn_adapter::QuinnQuicStream::new(
        send, recv,
        conn.local_addr(), conn.remote_addr(),
    );
    let client_isc = Arc::new(InterStreamConn::new(
        Arc::new(qs),
        conn.local_addr(), conn.remote_addr(), false,
    ));

    // quinn 0.11 open_bi 是 lazy：必须先 write 让 STREAM frame 落地，
    // server accept_bi 才会返回。
    let payload = b"hello hysteria e2e";
    client_isc.write(payload).await.expect("client write");

    // 6. server-side 收到 stream 后做 echo
    let server_isc = tokio::time::timeout(Duration::from_secs(10), stream_rx.recv())
        .await
        .expect("server should receive stream")
        .expect("channel not empty");
    let server_isc_clone = Arc::clone(&server_isc);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match server_isc_clone.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if server_isc_clone.write(&buf[..n]).await.is_err() { break; }
                }
            }
        }
    });

    // 7. 验证 echo 回环
    let mut got = vec![0u8; payload.len()];
    client_isc.read(&mut got).await.expect("client read echo");
    assert_eq!(&got, payload, "QUIC echo round-trip via real quinn+h3+hysteria");

    let _ = listener.close().await;
}
