//! 切片 G 端到端集成测试：mock H3 server + dial_h3_packet_up。
//!
//! 测试覆盖：
//! 1. quinn + h3 server 启动（自签证书 + ALPN h3）
//! 2. H3Conn::connect → dial_h3_packet_up：GET 下载 + POST 上传
//! 3. server 端验证 POST 收到字节数

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

use xray_transport_splithttp::config::{Config, RangeConfig};
use xray_transport_splithttp::dialer::{build_request_url, dial_h3_packet_up};
use xray_transport_splithttp::h3_client::H3Conn;

/// 生成自签证书（SAN = 127.0.0.1）+ rustls ServerConfig。
fn make_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params
        .self_signed(&key_pair)
        .expect("rcgen self_signed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    (cert_der, key_der)
}

/// 客户端 rustls ClientConfig：信任自签证书。
fn make_client_tls(cert_der: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add cert to roots");
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// 服务端 quinn ServerConfig（自签证书 + ALPN h3）。
fn make_server_crypto(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tns_config_to_arc(tls))
        .expect("QuicServerConfig");
    quinn::ServerConfig::with_crypto(Arc::new(quic))
}

fn tns_config_to_arc(cfg: rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
    Arc::new(cfg)
}

#[derive(Debug, Default)]
struct ServerStats {
    post_count: AtomicU64,
    bytes_received: AtomicUsize,
    get_count: AtomicU64,
}

/// H3 mock server：接受连接 → 接受请求 → 处理 GET/POST。
async fn mock_h3_server(
    endpoint: quinn::Endpoint,
    stats: Arc<ServerStats>,
    download_payload: Vec<u8>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let stats = stats.clone();
        let dl = download_payload.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            let quinn_conn = h3_quinn::Connection::new(conn);
            let mut h3_conn = match h3::server::Connection::new(quinn_conn).await {
                Ok(c) => c,
                Err(_) => return,
            };
            while let Ok(Some(req_resolver)) = h3_conn.accept().await {
                let stats = stats.clone();
                let dl = dl.clone();
                let (req, mut stream) = match req_resolver.resolve_request().await {
                    Ok(rs) => rs,
                    Err(_) => continue,
                };
                let method = req.method().clone();
                tokio::spawn(async move {
                    if method == Method::GET {
                        // 下载流：发送 payload + finish
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from(dl)).await;
                        let _ = stream.finish().await;
                        stats.get_count.fetch_add(1, Ordering::Relaxed);
                    } else if method == Method::POST {
                        // 上传流：读 body 统计字节
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            let len = chunk.remaining();
                            let _ = chunk.copy_to_bytes(len);
                            stats.bytes_received.fetch_add(len, Ordering::Relaxed);
                        }
                        stats.post_count.fetch_add(1, Ordering::Relaxed);
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.finish().await;
                    }
                });
            }
        });
    }
}

#[tokio::test]
async fn dial_h3_packet_up_end_to_end() {
    // 确保 rustls CryptoProvider 在并行测试中只初始化一次
    static CRYPTO_ONCE: std::sync::Once = std::sync::Once::new();
    CRYPTO_ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });

    // 1. 自签证书 + quinn server
    let (cert_der, key_der) = make_self_signed_cert();
    let server_crypto = make_server_crypto(cert_der.clone(), key_der);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = socket.local_addr().expect("local addr");
    drop(socket); // 释放端口给 quinn 用
    let endpoint = quinn::Endpoint::server(server_crypto, server_addr).expect("server endpoint");

    let stats = Arc::new(ServerStats::default());
    let download_payload = b"hello-h3-splithttp".to_vec();
    let server_task = tokio::spawn(mock_h3_server(
        endpoint.clone(),
        stats.clone(),
        download_payload.clone(),
    ));

    // 2. H3Conn::connect
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client_tls = make_client_tls(cert_der);
    // quic_params=None：CC 走默认 BBR（Go dialer.go:161-164 语义）
    let h3_conn = H3Conn::connect_with_quic_params(
        config.clone(),
        server_addr,
        "127.0.0.1",
        client_tls,
        None,
        &xray_transport::sockopt::SocketOptions::default(),
    )
    .await
    .expect("H3Conn::connect_with_quic_params");

    // 3. dial_h3_packet_up
    let session_id = uuid::Uuid::new_v4().to_string();
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let sc_max = 1_000_000usize;
    let mut conn = dial_h3_packet_up(h3_conn, base_uri, session_id, sc_max, RangeConfig::new(0, 0))
        .await
        .expect("dial_h3_packet_up");

    // 4. 验证下载内容
    let mut buf = vec![0u8; download_payload.len()];
    conn.reader
        .read_exact(&mut buf)
        .await
        .expect("read download");
    assert_eq!(buf, download_payload);

    // 5. 上传数据
    let upload_data = b"upload-payload-h3";
    {
        use tokio::io::AsyncWriteExt;
        let _ = conn.writer.write_all(upload_data).await;
        // 关 writer 让 server 收到 EOF
    }
    // 给 server 一点时间处理 POST
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    assert!(
        stats.post_count.load(Ordering::Relaxed) >= 1,
        "至少收到 1 个 POST，实际 {}",
        stats.post_count.load(Ordering::Relaxed)
    );
    assert!(
        stats.bytes_received.load(Ordering::Relaxed) >= upload_data.len(),
        "POST 收到字节数应 >= {}, 实际 {}",
        upload_data.len(),
        stats.bytes_received.load(Ordering::Relaxed)
    );

    // 关闭
    drop(conn);
    drop(endpoint);
    server_task.abort();
}
