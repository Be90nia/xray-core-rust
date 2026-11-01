//! bd ctiwx：hysteria 入站 `users[]` 多用户面端到端（真实 QUIC 回环）。
//!
//! 验证生产装配形态（`HysteriaInboundHandler::new` + `with_multi_validator`，
//! 即 xray-core `build_hysteria_inbound` 的接线）：
//! 1. seed 用户连上 + TCP request/response + 数据往返；
//! 2. `MultiUserValidator::add`（= `api adu` 落点）后**新用户立刻能连**；
//! 3. `remove`（= `api rmu`）后**立刻被拒**（新 QUIC 连接 auth 失败）；
//! 4. 单 auth 形态回归（无 multi_validator，`StaticAuthValidator` 路径）。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use xray_common::net::{address::Address, port::Port};
use xray_features::inbound::InboundHandler as _;
use xray_proxy_hysteria::{
    HysteriaConfig, HysteriaInboundHandler, HysteriaUser, MultiUserValidator,
};
use xray_transport_hysteria::{
    conn::InterStreamConn,
    dialer::{DialDestination, HysteriaClient},
    hub::HysteriaListenerFactory,
    hysteria_transport::QuinnHysteriaTransport,
    quinn_adapter::QuinnListenerFactory,
};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed()
-> (Vec<rustls_pki_types::CertificateDer<'static>>, rustls_pki_types::PrivateKeyDer<'static>) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self signed");
    (
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("private key der"),
    )
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

/// TCP 中继 echo：读侧字节原样写回（模拟目标站回显）。
#[derive(Debug)]
struct EchoTcpDispatcher;

impl xray_proxy_hysteria::TcpDispatcher for EchoTcpDispatcher {
    fn dispatch_tcp(
        &self,
        _dest_addr: &str,
        stream: std::sync::Arc<InterStreamConn>,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                stream.write(&buf[..n]).await?;
            }
        })
    }
}

fn client_transport() -> Arc<QuinnHysteriaTransport> {
    let client_tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(
        QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("client transport"),
    )
}

/// 一个完整的"用 auth 连上来并发数据"往返；auth 被拒时返回 Err。
async fn connect_roundtrip(
    server_addr: SocketAddr,
    auth: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let transport = client_transport();
    let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
    let client = HysteriaClient::new(
        dest,
        Arc::new(xray_proto::xray::transport::internet::hysteria::Config {
            auth: auth.to_string(),
            ..xray_proto::xray::transport::internet::hysteria::Config::default()
        }),
        Arc::new(xray_proto::xray::transport::internet::QuicParams::default()),
        transport,
    );
    let stream = tokio::time::timeout(Duration::from_secs(8), async {
        client.tcp(&Address::new_domain("127.0.0.1"), Port::new(1)).await
    })
    .await
    .expect("tcp() within 8s")
    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    // TCPResponse 帧（status=ok）已在升级路径被客户端消费；直接收中继负载。
    stream.write(b"ping").await?;
    let mut tmp = [0u8; 256];
    let mut echo = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
        .await
        .expect("echo within 5s")
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    echo.extend_from_slice(&tmp[..n]);
    Ok(String::from_utf8_lossy(&echo).into_owned())
}

/// seed 用户 + `api adu`（validator.add）后新用户立刻能连 + `rmu` 后立刻被拒。
#[tokio::test]
async fn multi_user_add_remove_takes_effect_on_next_connection() {
    let validator = Arc::new(MultiUserValidator::new());
    validator.add(&HysteriaUser::new("seed@um.test", "seed-token")).expect("seed user");

    // :0 由 OS 分配——server addr 从 QUIC listener 拿不到（handler 不暴露），
    // 改为显式自由端口（TOCTOU 由重试兜底；测试环境可接受）。
    let port = xray_common::testing::pick_free_ports(1).await[0];
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let bind = server_addr;
    ensure_crypto_provider();
    let (cert_chain, key_der) = self_signed();
    let server_tls = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .expect("server cert");
    let factory: Arc<dyn HysteriaListenerFactory> =
        Arc::new(QuinnListenerFactory::new(Arc::new(server_tls)));
    let handler = HysteriaInboundHandler::new(
        "hyst-um",
        HysteriaConfig::new(bind.to_string(), ""),
        bind,
        factory,
    )
    .expect("handler")
    .with_multi_validator(Some(Arc::clone(&validator)))
    .with_dispatcher(Some(Arc::new(EchoTcpDispatcher)));
    handler.start().await.expect("start");

    // 1. seed 用户：连接 + 数据往返。
    let echo =
        tokio::time::timeout(Duration::from_secs(10), connect_roundtrip(server_addr, "seed-token"))
            .await
            .expect("seed roundtrip within 10s")
            .expect("seed roundtrip ok");
    assert_eq!(echo, "ping", "seed 数据必须往返");

    // 2. `api adu` 落点：validator.add → 新用户立刻能连。
    validator.add(&HysteriaUser::new("u2@um.test", "tok-2")).expect("add u2");
    let echo =
        tokio::time::timeout(Duration::from_secs(10), connect_roundtrip(server_addr, "tok-2"))
            .await
            .expect("u2 roundtrip within 10s")
            .expect("u2 (adu'd) roundtrip ok");
    assert_eq!(echo, "ping", "adu 后新用户数据必须往返");

    // 3. `api rmu` 落点：validator.remove → 立刻被拒（新 QUIC 连接）。
    validator.remove("u2@um.test").expect("remove u2");
    let rejected =
        tokio::time::timeout(Duration::from_secs(10), connect_roundtrip(server_addr, "tok-2"))
            .await
            .expect("rejected attempt within 10s");
    assert!(rejected.is_err(), "rmu 后 tok-2 必须被拒，实得 {rejected:?}");
}

/// 单 auth 形态回归：无 multi_validator 时 `config.auth` 走 `StaticAuthValidator`。
#[tokio::test]
async fn single_auth_still_works_without_validator() {
    ensure_crypto_provider();
    let (cert_chain, key_der) = self_signed();
    let server_tls = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .expect("server cert");
    let factory: Arc<dyn HysteriaListenerFactory> =
        Arc::new(QuinnListenerFactory::new(Arc::new(server_tls)));
    let port = xray_common::testing::pick_free_ports(1).await[0];
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handler = HysteriaInboundHandler::new(
        "hyst-single",
        HysteriaConfig::new(bind.to_string(), "single-auth-token"),
        bind,
        factory,
    )
    .expect("handler")
    .with_dispatcher(Some(Arc::new(EchoTcpDispatcher)));
    assert!(handler.multi_validator().is_none(), "单 auth 形态不得带 multi_validator");
    handler.start().await.expect("start");

    let echo = tokio::time::timeout(
        Duration::from_secs(10),
        connect_roundtrip(handler.bind_addr(), "single-auth-token"),
    )
    .await
    .expect("single-auth roundtrip within 10s")
    .expect("single-auth roundtrip ok");
    assert_eq!(echo, "ping");
}
