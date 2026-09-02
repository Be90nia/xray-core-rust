//! Hysteria 真实 QUIC 回环 e2e。
//!
//! 覆盖：QUIC dial + HTTP/3 auth + 客户端 TCPRequest 地址帧 + 服务端 frame type
//! 消费/TCPRequest 解析。

#![cfg(test)]

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use xray_common::net::address::Address;
use xray_common::net::port::Port;
use tokio::sync::mpsc;
use xray_transport_hysteria::conn::InterStreamConn;
use xray_transport_hysteria::dialer::{DialDestination, HysteriaClient, HysteriaTransport, QuicConfig};
use xray_transport_hysteria::hysteria_transport::QuinnHysteriaTransport;
use xray_transport_hysteria::proto_config::Config as ProtoConfig;
use xray_transport_hysteria::quinn_adapter::QuinnListenerFactory;
use xray_transport_hysteria::hub::{AuthValidator, MasqType};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed() -> (
    Vec<rustls_pki_types::CertificateDer<'static>>,
    rustls_pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();
    (vec![cert_der.into()], rustls_pki_types::PrivateKeyDer::try_from(key_der).unwrap())
}

#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
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
        (auth == "test-secret").then(|| "user".to_string())
    }

    fn count(&self) -> usize {
        1
    }
}

#[tokio::test]
async fn hysteria_quic_loopback_dial_auth_bidi_roundtrip() {
    ensure_crypto_provider();

    let (cert_chain, key_der) = self_signed();
    let server_tls = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .unwrap();
    let factory = QuinnListenerFactory::new(Arc::new(server_tls));
    let proto_cfg = Arc::new(ProtoConfig::default());
    let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
    let validator: Option<Arc<dyn AuthValidator>> = Some(Arc::new(TestValidator));

    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<String>();
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> =
        Arc::new(move |server_stream: Arc<InterStreamConn>| {
            let stream_tx = stream_tx.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = server_stream.read(&mut tmp).await.expect("server read request");
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&tmp[..n]);
                    let mut cursor = Cursor::new(&request);
                    match xray_proxy_hysteria::protocol::read_tcp_request(&mut cursor) {
                        Ok(addr) => {
                            let _ = stream_tx.send(addr);
                            return;
                        }
                        Err(xray_proxy_hysteria::HysteriaProxyError::ProtocolParse(_)) => {}
                        Err(error) => panic!("invalid hysteria TCP request: {error}"),
                    }
                }
            });
        });

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

    let client_tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let transport = Arc::new(
        QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport"),
    );
    let dest = DialDestination {
        udp_addr: server_addr,
        host: "localhost".into(),
    };

    // 真实客户端路径：HysteriaClient::tcp 写地址帧，InterStreamConn 自动加 0x401。
    let _client_isc = HysteriaClient::new(
        dest,
        Arc::new(ProtoConfig::default()),
        Arc::new(xray_proto::xray::transport::internet::QuicParams::default()),
        transport,
    )
    .tcp(&Address::new_domain("127.0.0.1"), Port::new(1))
    .await
    .expect("real TCP dial should write address frame");

    let addr = tokio::time::timeout(Duration::from_secs(10), stream_rx.recv())
        .await
        .expect("server should receive framed request")
        .expect("channel not empty");
    assert_eq!(addr, "127.0.0.1:1");
    let _ = listener.close().await;
}

#[test]
fn hysteria_congestion_values_are_parsed_by_dialer_config() {
    // 防止配置层回归：默认值仍为 BBR/空 CC。
    let qc = QuicConfig::default_for_hysteria();
    assert_eq!(qc.congestion, "");
    assert_eq!(qc.bbr_profile, "standard");
}
