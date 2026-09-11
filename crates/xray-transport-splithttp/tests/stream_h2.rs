//! 切片 D H2 集成测试：dial_stream_up + dial_stream_one via mock H2 server.
//!
//! 补 co1 切片 C 遗留：stream-up/stream-one 在 H1.1 下 deadlock（协议设计），
//! 必须走 H2 全双工。本测试用 mock H2 server（自签 TLS + ALPN h2 + hyper h2）
//! 覆盖两个 stream 模式。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use xray_transport_splithttp::client::{DefaultDialerClient, DialTarget};
use xray_transport_splithttp::config::Config;
use xray_transport_splithttp::dialer::{build_request_url, dial_stream_one, dial_stream_up};

fn make_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
    )
}

fn make_server_tls(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> rustls::ServerConfig {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg
}

fn make_client_tls(cert: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add cert");
    // ponytail: 不预设 ALPN, hyper-rustls HttpsConnectorBuilder 自动设置 (预设会 panic)
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[derive(Default)]
struct ServerStats {
    post_count: AtomicU64,
    post_bytes: AtomicUsize,
    get_count: AtomicU64,
}

/// mock H2 splithttp server：
/// - GET：返 download_payload（stream-up/stream-one 下载流）
/// - POST：drain body 统计字节数 + 返 200（stream-up 上传 / stream-one 上传）
async fn mock_h2_splithttp_server(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    stats: Arc<ServerStats>,
    download_payload: Vec<u8>,
) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => break,
        };
        let tls_acceptor = tls_acceptor.clone();
        let stats = stats.clone();
        let dl = download_payload.clone();
        tokio::spawn(async move {
            let tls = match tls_acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let io = TokioIo::new(tls);
            let stats_inner = stats.clone();
            let dl_inner = dl.clone();
            let svc = service_fn(move |req: Request<Incoming>| {
                let stats = stats_inner.clone();
                let dl = dl_inner.clone();
                async move {
                    let method = req.method().clone();
                    if method == Method::GET {
                        // 下载流：返 download_payload
                        stats.get_count.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(dl)))
                                .unwrap(),
                        )
                    } else if method == Method::POST {
                        // 上传流：spawn drain body (避免与 client streaming upload 互锁) + 立即返 200
                        let (_, body) = req.into_parts();
                        tokio::spawn(async move {
                            let collected = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                            stats.post_bytes.fetch_add(collected.len(), Ordering::Relaxed);
                            stats.post_count.fetch_add(1, Ordering::Relaxed);
                        });
                        Ok(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    } else {
                        Ok(
                            Response::builder()
                                .status(StatusCode::METHOD_NOT_ALLOWED)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                }
            });
            let _ = http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

#[tokio::test]
async fn dial_stream_up_via_h2_mock_server() {
    // 确保 rustls CryptoProvider 在并行测试中只初始化一次
    static CRYPTO_ONCE: std::sync::Once = std::sync::Once::new();
    CRYPTO_ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });

    // 1. 自签证书 + H2 server
    let (cert_der, key_der) = make_self_signed_cert();
    let server_tls = make_server_tls(cert_der.clone(), key_der);
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local addr");
    let stats = Arc::new(ServerStats::default());
    let download_payload = b"hello-stream-up-download-via-h2".to_vec();
    let server_task = tokio::spawn(mock_h2_splithttp_server(
        listener,
        tls_acceptor,
        stats.clone(),
        download_payload.clone(),
    ));

    // 2. 客户端 DefaultDialerClient（hyper-rustls + ALPN h2）
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client_tls = make_client_tls(cert_der);
    let client = Arc::new(DefaultDialerClient::new(config.clone(), client_tls.into(), DialTarget { host: server_addr.ip().to_string(), port: server_addr.port(), sni: String::new() }, None, None));

    // 3. dial_stream_up
    let session_id = uuid::Uuid::new_v4().to_string();
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let mut conn = dial_stream_up(client, base_uri, session_id)
        .await
        .expect("dial_stream_up");

    // 4. 验证下载内容
    let mut buf = vec![0u8; download_payload.len()];
    conn.reader
        .read_exact(&mut buf)
        .await
        .expect("read download");
    assert_eq!(buf, download_payload);

    // 5. 上传数据
    let upload_data = b"stream-up-upload-payload-h2";
    conn.writer
        .write_all(upload_data)
        .await
        .expect("write upload");
    conn.writer.shutdown().await.expect("close writer");

    // 给 server 时间处理 POST
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        stats.post_count.load(Ordering::Relaxed) >= 1,
        "stream-up 应触发至少 1 个 POST，实际 {}",
        stats.post_count.load(Ordering::Relaxed)
    );
    assert!(
        stats.post_bytes.load(Ordering::Relaxed) >= upload_data.len(),
        "POST 收到字节数应 >= {}, 实际 {}",
        upload_data.len(),
        stats.post_bytes.load(Ordering::Relaxed)
    );

    drop(conn);
    server_task.abort();
}

#[tokio::test]
async fn dial_stream_one_via_h2_mock_server() {
    // 确保 rustls CryptoProvider 在并行测试中只初始化一次
    static CRYPTO_ONCE2: std::sync::Once = std::sync::Once::new();
    CRYPTO_ONCE2.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });

    // 1. 自签证书 + H2 server（POST 返 download_payload）
    let (cert_der, key_der) = make_self_signed_cert();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local addr");
    let download_payload = b"hello-stream-one-response-via-h2".to_vec();
    let dl_clone = download_payload.clone();
    let server_task = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let tls_acceptor = tls_acceptor.clone();
            let dl = dl_clone.clone();
            tokio::spawn(async move {
                let tls = match tls_acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let dl_inner = dl.clone();
                let svc = service_fn(move |req: Request<Incoming>| {
                    let dl = dl_inner.clone();
                    async move {
                        // ponytail: stream-one 用 POST + 同连接响应
                        // 不读 body（H2 全双工允许 server 先发响应）
                        drop(req.into_body());
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(dl)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    // 2. 客户端
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client_tls = make_client_tls(cert_der);
    let client = Arc::new(DefaultDialerClient::new(config.clone(), client_tls.into(), DialTarget { host: server_addr.ip().to_string(), port: server_addr.port(), sni: String::new() }, None, None));

    // 3. dial_stream_one
    let session_id = String::new(); // stream-one session_id 空
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let mut conn = dial_stream_one(client, base_uri, session_id)
        .await
        .expect("dial_stream_one");

    // 4. 验证下载（server 在 POST 上返 download_payload）
    let mut buf = vec![0u8; download_payload.len()];
    let n = tokio::time::timeout(Duration::from_secs(3), conn.reader.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf[..n], download_payload, "应收到 download_payload");

    drop(conn);
    server_task.abort();
}
