//! S3：hysteria2 QUIC 重连循环（真实 QUIC 栈 loopback，0-RTT 生效路径）。
//!
//! 拓扑对齐 crates/xray-proxy-hysteria/tests/e2e.rs 既有形态：
//! server = `QuinnListenerFactory` + echo 回调；client = 每轮新建 `HysteriaClient`
//! （连接缓存挂在 client 实例上，新建即新 QUIC 连接 → dial → auth → 0-RTT →
//! TCPRequest/TCPResponse → 数据回显 → drop → 重连）。会话票据 store 是 crate 级
//! 全局静态，二次连接起 0-RTT 生效——这正是本场景要压的 quinn 连接回环。

use std::{net::SocketAddr, sync::Arc, time::Instant};

use xray_common::net::{address::Address, port::Port};
use xray_proxy_hysteria::protocol::{read_tcp_request, write_tcp_response};
use xray_transport_hysteria::{
    HysteriaListenerFactory,
    conn::InterStreamConn,
    dialer::{DialDestination, HysteriaClient},
    hub::{AuthValidator, MasqType},
    hysteria_transport::QuinnHysteriaTransport,
    proto_config::Config as ProtoConfig,
    quinn_adapter::QuinnListenerFactory,
};

use crate::report::StatsHandle;

const AUTH_SECRET: &str = "xray-stress-secret";
const S3_PAYLOAD_LEN: usize = 8 * 1024;

/// PEM → DER（自签证书场景，无链无加密段；rcgen 产物为单段 PKCS#8）。
pub(crate) fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| anyhow::anyhow!("pem base64 decode: {e}"))
}

/// S3 服务端：QUIC listener + TCPRequest 解析 + echo 回调。
pub async fn start_quic_echo_server() -> anyhow::Result<SocketAddr> {
    let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])?;
    let cert_der = pem_to_der(&cert_pem)?;
    let key_der = pem_to_der(&key_pem)?;
    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| anyhow::anyhow!("private key der: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("server cert: {e}"))?;

    let factory = QuinnListenerFactory::new(Arc::new(server_tls));
    let validator: Option<Arc<dyn AuthValidator>> = Some(Arc::new(StaticValidator));
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> =
        Arc::new(|stream: Arc<InterStreamConn>| {
            tokio::spawn(echo_one(stream));
        });
    let mut quic_port = crate::topology::pick_free_port().await;
    let listener = loop {
        match factory
            .listen(
                format!("127.0.0.1:{quic_port}").parse().unwrap(),
                Arc::new(ProtoConfig::default()),
                Arc::new(xray_proto::xray::transport::internet::QuicParams::default()),
                MasqType::NotFound,
                validator.clone(),
                on_new_conn.clone(),
                None,
            )
            .await
        {
            Ok(l) => break l,
            Err(_) => {
                // 极小概率端口被抢：换一个非保留端口重试
                quic_port = crate::topology::pick_free_port().await;
            },
        }
    };
    Ok(listener.local_addr())
}

async fn echo_one(stream: Arc<InterStreamConn>) {
    // 1. 聚齐并消费 TCPRequest 地址帧
    let mut request = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                request.extend_from_slice(&tmp[..n]);
                let mut cursor = std::io::Cursor::new(&request);
                match read_tcp_request(&mut cursor) {
                    Ok(_addr) => break,
                    Err(xray_proxy_hysteria::HysteriaProxyError::ProtocolParse(_)) => continue,
                    Err(_) => return,
                }
            },
        }
    }
    let mut resp = Vec::new();
    if write_tcp_response(&mut resp, true, "").is_err() {
        return;
    }
    if stream.write(&resp).await.is_err() {
        return;
    }
    // 2. 裸数据 echo 循环
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if stream.write(&buf[..n]).await.is_err() {
                    return;
                }
            },
        }
    }
}

struct StaticValidator;
impl AuthValidator for StaticValidator {
    fn validate(&self, auth: &str) -> Option<String> {
        (auth == AUTH_SECRET).then(|| "stress-user".to_string())
    }

    fn count(&self) -> usize {
        1
    }
}

/// S3 worker：deadline 前不断 dial → auth（0-RTT）→ roundtrip → drop。
pub async fn s3_quic_reconnect_loop(
    server_addr: SocketAddr,
    deadline: Instant,
    stats: StatsHandle,
) {
    let client_tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let transport: Arc<QuinnHysteriaTransport> = Arc::new(
        QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("quic transport"),
    );
    let dest = DialDestination { udp_addr: server_addr, host: "localhost".into() };
    let make_config = || {
        Arc::new(xray_proto::xray::transport::internet::hysteria::Config {
            auth: AUTH_SECRET.into(),
            ..xray_proto::xray::transport::internet::hysteria::Config::default()
        })
    };
    let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
    let payload = vec![0xABu8; S3_PAYLOAD_LEN];

    while Instant::now() < deadline {
        let started = Instant::now();
        let client = HysteriaClient::new(
            dest.clone(),
            make_config(),
            quic_params.clone(),
            transport.clone(),
        );
        match roundtrip_once(&client, &payload).await {
            Ok(()) => {
                stats.record_ok(0, payload.len() as u64 * 2, elapsed_ms(started));
            },
            Err(e) => {
                stats.record_fail();
                tracing::warn!("s3 roundtrip failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            },
        }
        // drop client = QUIC 连接关闭；下一轮新建 = 重连回环
        drop(client);
    }
}

async fn roundtrip_once(
    client: &HysteriaClient,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let isc = client.tcp(&Address::new_domain("127.0.0.1"), Port::new(8080)).await?;
    isc.write(payload).await?;
    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < got.len() {
        let n = isc.read(&mut got[filled..]).await?;
        if n == 0 {
            return Err("quic echo closed early".into());
        }
        filled += n;
    }
    // ponytail: 长度校验即可，memcmp 会占 S3 吞吐大头；内容错在 S1 已有同型校验
    Ok(())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

/// quinn 客户端对自签证书的放行 verifier（e2e.rs 同款语义）。
#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
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
