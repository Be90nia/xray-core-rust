//! 切片 A 端到端集成测试：mock HTTP server + dial_packet_up。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use webpki_roots::TLS_SERVER_ROOTS;

use xray_transport_splithttp::client::DefaultDialerClient;
use xray_transport_splithttp::config::Config;
use xray_transport_splithttp::dialer::dial_packet_up;
use xray_transport_splithttp::error::SplitHttpError;


/// 确保 rustls CryptoProvider 在并行测试中只初始化一次
static CRYPTO_ONCE: std::sync::Once = std::sync::Once::new();
fn ensure_crypto_provider() {
    CRYPTO_ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
}

fn make_tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[derive(Debug, Default)]
struct ServerStats {
    post_count: AtomicU64,
    bytes_received: AtomicUsize,
}

async fn mock_splithttp_server(
    listener: TcpListener,
    stats: Arc<ServerStats>,
    download_payload: Vec<u8>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };
        let io = TokioIo::new(stream);
        let stats_clone = stats.clone();
        let dl_payload = download_payload.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let stats = stats_clone.clone();
                let dl = dl_payload.clone();
                async move {
                    let method = req.method().clone();
                    if method == Method::GET {
                        let body = Full::new(Bytes::from(dl));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder().status(StatusCode::OK).body(body).unwrap(),
                        )
                    } else if method == Method::POST {
                        let (_, body) = req.into_parts();
                        let bytes = match body.collect().await {
                            Ok(b) => b.to_bytes(),
                            Err(_) => Bytes::new(),
                        };
                        stats.post_count.fetch_add(1, Ordering::Relaxed);
                        stats.bytes_received.fetch_add(bytes.len(), Ordering::Relaxed);
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::new()))
                            .unwrap())
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Full::new(Bytes::new()))
                            .unwrap())
                    }
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

#[tokio::test]
async fn dial_packet_up_end_to_end_via_mock_http1_server() {
    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let stats = Arc::new(ServerStats::default());
    let download_payload = b"hello-splithttp-download".to_vec();
    let server_task = tokio::spawn(mock_splithttp_server(
        listener,
        stats.clone(),
        download_payload.clone(),
    ));

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let tls_config = make_tls_config();
    let client = Arc::new(DefaultDialerClient::new(config, tls_config));

    let base_uri = format!("http://127.0.0.1:{}/", server_addr.port());
    let session_id = "test-session-1".to_string();

    let conn = dial_packet_up(client, base_uri, session_id, 1024, 0).await.unwrap();

    let mut conn = conn;
    let mut read_buf = vec![0u8; download_payload.len()];
    conn.read_exact(&mut read_buf).await.unwrap();
    assert_eq!(&read_buf, &download_payload[..]);

    conn.write_all(b"upload-chunk-1").await.unwrap();
    conn.write_all(b"upload-chunk-2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let posts = stats.post_count.load(Ordering::Relaxed);
    assert!(posts >= 1, "expected at least 1 POST, got {posts}");
    let total = stats.bytes_received.load(Ordering::Relaxed);
    assert!(
        total >= "upload-chunk-1".len() + "upload-chunk-2".len(),
        "expected >= 24 bytes received, got {total}"
    );

    drop(conn);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server_task.abort();
}

#[tokio::test]
async fn post_packet_returns_bad_status_on_500() {
    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let config = Arc::new(Config::default());
    let tls_config = make_tls_config();
    let client = Arc::new(DefaultDialerClient::new(config, tls_config));
    let base_uri = format!("http://127.0.0.1:{}/", addr.port());

    let result = client.post_packet(&base_uri, "sess", "0", b"x".to_vec()).await;
    let err = result.unwrap_err();
    assert!(
        matches!(err, SplitHttpError::BadStatus(500)),
        "expected BadStatus(500), got {err:?}"
    );
}

#[tokio::test]
async fn open_stream_returns_bad_status_on_non_200() {
    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let config = Arc::new(Config::default());
    let tls_config = make_tls_config();
    let client = Arc::new(DefaultDialerClient::new(config, tls_config));
    let base_uri = format!("http://127.0.0.1:{}/", addr.port());

    let result = client.open_stream(&base_uri, "sess", None).await;
    let err = result.unwrap_err();
    assert!(
        matches!(err, SplitHttpError::BadStatus(404)),
        "expected BadStatus(404), got {err:?}"
    );
}
