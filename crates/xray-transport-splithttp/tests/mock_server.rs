//! 切片 A 端到端集成测试：mock HTTP server + dial_packet_up。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

use xray_transport_splithttp::client::{DefaultDialerClient, DialTarget, Fingerprint};
use xray_transport_splithttp::config::{Config, RangeConfig};
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
    let client = Arc::new(DefaultDialerClient::new(config, tls_config, DialTarget { host: "127.0.0.1".into(), port: server_addr.port(), sni: String::new() }, None, None));

    let base_uri = format!("http://127.0.0.1:{}/", server_addr.port());
    let session_id = "test-session-1".to_string();

    let conn = dial_packet_up(client, base_uri, session_id, 1024, RangeConfig::new(0, 0)).await.unwrap();

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
    let client = Arc::new(DefaultDialerClient::new(config, tls_config, DialTarget { host: "127.0.0.1".into(), port: addr.port(), sni: String::new() }, None, None));
    let base_uri = format!("http://127.0.0.1:{}/", addr.port());

    let result = client.post_packet(&base_uri, "sess", "0", b"x".to_vec()).await;
    let err = result.unwrap_err();
    assert!(
        matches!(err, SplitHttpError::BadStatus(500)),
        "expected BadStatus(500), got {err:?}"
    );
}

/// GET 分支 lazy 契约：非 200 不再从 `open_stream` 返回 `BadStatus`，
/// dial 立即返回、读端呈现 EOF（对齐 Go `"unexpected status"` 分支）。
#[tokio::test]
async fn open_stream_get_non_200_yields_eof() {
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
    let client = Arc::new(DefaultDialerClient::new(config, tls_config, DialTarget { host: "127.0.0.1".into(), port: addr.port(), sni: String::new() }, None, None));
    let base_uri = format!("http://127.0.0.1:{}/", addr.port());

    // lazy：open_stream 立即返回，非 200 在读端以 EOF 呈现
    let (mut reader, _, _) = client
        .open_stream(&base_uri, "sess", None, None)
        .await
        .expect("lazy GET must not fail dial");
    let mut buf = [0u8; 16];
    let n = reader.read(&mut buf).await.expect("read must not error");
    assert_eq!(n, 0, "non-200 GET must surface as EOF, got {n} bytes");
}

// ===== tlsSettings.fingerprint 出站（btls u_client connector）端到端 =====

/// 自签证书 TLS mock server：ALPN 可配，h1/h2 双协议 serve。
async fn mock_splithttp_tls_server(
    listener: TcpListener,
    server_cfg: std::sync::Arc<rustls::ServerConfig>,
    use_http2: bool,
    download_payload: Vec<u8>,
    got_get: std::sync::Arc<AtomicBool>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    loop {
        let Ok((stream, _)) = listener.accept().await else { break };
        let acceptor = acceptor.clone();
        let dl = download_payload.clone();
        let got_get = got_get.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else { return };
            let svc = service_fn(move |req: Request<Incoming>| {
                let dl = dl.clone();
                let got_get = got_get.clone();
                async move {
                    if req.method() == Method::GET {
                        got_get.store(true, Ordering::Relaxed);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder().status(StatusCode::OK)
                                .body(Full::new(Bytes::from(dl))).unwrap(),
                        )
                    } else {
                        Ok(Response::builder().status(StatusCode::OK)
                            .body(Full::new(Bytes::new())).unwrap())
                    }
                }
            });
            if use_http2 {
                let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            } else {
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
            }
        });
    }
}

/// 自签证书 server config（ALPN 决定协商结果 → hyper 的 HTTP 版本判定）。
fn self_signed_server_config(alpn: Vec<Vec<u8>>) -> std::sync::Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = alpn;
    std::sync::Arc::new(cfg)
}

async fn spawn_fingerprint_test(
    use_http2: bool,
    alpn: Vec<Vec<u8>>,
) -> (Arc<AtomicBool>, tokio::task::JoinHandle<()>, u16) {
    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let payload = if use_http2 { b"fp-download-h2" } else { b"fp-download-h1" }.to_vec();
    let got_get = Arc::new(AtomicBool::new(false));
    let server = tokio::spawn(mock_splithttp_tls_server(
        listener,
        self_signed_server_config(alpn),
        use_http2,
        payload,
        got_get.clone(),
    ));
    let _ = payload;
    (got_get, server, addr.port())
}

/// fingerprint=chrome 出站：btls 指纹握手 + ALPN 协商 http/1.1 → hyper h1 roundtrip。
#[tokio::test]
async fn fingerprint_btls_end_to_end_http1() {
    let (got_get, server, port) = spawn_fingerprint_test(false, vec![b"http/1.1".to_vec()]).await;
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{port}"),
        path: "/".into(),
        ..Default::default()
    });
    // mock 自签证书：走 crate 自身 allowInsecure 语义跳过 btls 证书验证
    // （本测试对象是指纹握手 + ALPN roundtrip，不是证书链）。
    let client = Arc::new(DefaultDialerClient::new(config, make_tls_config(), DialTarget { host: "127.0.0.1".into(), port, sni: String::new() }, Some(Fingerprint::Chrome), Some(serde_json::json!({"allowInsecure": true}))));

    let mut conn = dial_packet_up(
        client,
        format!("https://127.0.0.1:{port}/"),
        "fp-sess".into(),
        1024,
        RangeConfig::new(0, 0),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; b"fp-download-h1".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"fp-download-h1");
    assert!(got_get.load(Ordering::Relaxed), "server must see the GET");

    drop(conn);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.abort();
}

/// fingerprint=chrome 出站：ALPN 协商 h2 → connector 标记 negotiated_h2 → hyper h2。
#[tokio::test]
async fn fingerprint_btls_end_to_end_http2() {
    let (got_get, server, port) = spawn_fingerprint_test(true, vec![b"h2".to_vec()]).await;
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{port}"),
        path: "/".into(),
        ..Default::default()
    });
    let client = Arc::new(DefaultDialerClient::new(config, make_tls_config(), DialTarget { host: "127.0.0.1".into(), port, sni: String::new() }, Some(Fingerprint::Chrome), Some(serde_json::json!({"allowInsecure": true}))));

    let mut conn = dial_packet_up(
        client,
        format!("https://127.0.0.1:{port}/"),
        "fp-sess".into(),
        1024,
        RangeConfig::new(0, 0),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; b"fp-download-h2".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"fp-download-h2");
    assert!(got_get.load(Ordering::Relaxed), "server must see the GET");

    drop(conn);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.abort();
}

/// 连接 drop 必须终止客户端所有 HTTP 连接（bd s10 泄漏回归测试）。
///
/// SplitConn drop → on_close → lazy reader 终止 → hyper Client drop →
/// 池内 TCP 关闭 → 服务端 `serve_connection` 全部返回。缺失断连传播时
/// （修复前），GET lazy reader 永挂，server 侧连接永不关闭。
#[tokio::test]
async fn conn_drop_terminates_all_http_connections() {
    use std::sync::atomic::AtomicUsize;

    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // server：统计 accept 数与 serve_connection 完成数（完成 = 对端关闭）。
    let accepted = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let server_task = {
        let accepted = Arc::clone(&accepted);
        let finished = Arc::clone(&finished);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                accepted.fetch_add(1, Ordering::Relaxed);
                let finished = Arc::clone(&finished);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let body = if req.method() == Method::GET {
                            Full::new(Bytes::from_static(b"dl"))
                        } else {
                            Full::new(Bytes::new())
                        };
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder().status(StatusCode::OK).body(body).unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                    finished.fetch_add(1, Ordering::Relaxed);
                });
            }
        })
    };

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client = Arc::new(DefaultDialerClient::new(
        config,
        make_tls_config(),
        DialTarget { host: "127.0.0.1".into(), port: server_addr.port(), sni: String::new() },
        None,
        None,
    ));
    let base_uri = format!("http://127.0.0.1:{}/", server_addr.port());

    let mut conn = dial_packet_up(
        client,
        base_uri,
        "drop-sess".into(),
        1024,
        RangeConfig::new(0, 0),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 2];
    conn.read_exact(&mut buf).await.unwrap();
    conn.write_all(b"x").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let accepted_before = accepted.load(Ordering::Relaxed);
    assert!(accepted_before >= 1, "server must accept connections, got {accepted_before}");

    // 连接关闭：客户端所有 TCP 必须终结（泄漏回归断言）。
    drop(conn);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let finished_after = finished.load(Ordering::Relaxed);
    assert_eq!(
        finished_after, accepted_before,
        "all server connections must finish after client conn drop (accepted={accepted_before}, finished={finished_after})"
    );

    server_task.abort();
}

/// 桥级 EOF 传播测试（bd s10 残余泄漏定位）。
///
/// dispatcher 桥（`bridge_link_with_stream_full`）桥接 dispatch link 与
/// splithttp packet-up 连接：inbound 侧 shutdown（SOCKS FIN 等价）后，桥必须
/// 在 half-close 窗口（uplinkOnly/downlinkOnly=1s）内返回并释放 conn——
/// 生产默认 connIdle=300s 兜底会把挂起的 SplitConn/HTTP 连接钉住 5 分钟，
/// 表现为 fd/RSS 线性增长。本测试用生产同款默认 policy（connIdle=300s），
/// 断言桥不依赖 connIdle 即可退出。
#[tokio::test]
async fn bridge_eof_propagates_without_conn_idle() {
    use std::sync::atomic::AtomicUsize;

    use futures_util::{StreamExt, TryStreamExt};
    use xray_features::policy::TimeoutPolicy;
    use xray_transport::bridge::bridge_link_with_stream_full;
    use xray_transport::link::Link;

    ensure_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // mock server：GET 响应头已发但 body 长挂（真实 stream-down 形态），
    // 客户端断开时 hyper 检测到并结束 serve_connection。
    let accepted = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let server_task = {
        let accepted = Arc::clone(&accepted);
        let finished = Arc::clone(&finished);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                accepted.fetch_add(1, Ordering::Relaxed);
                let finished = Arc::clone(&finished);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let dl = req.method() == Method::GET;
                        async move {
                            if dl {
                                // 长挂下载流：60s 后才结束（测试会在其之前断开）
                                let body = tokio_stream::wrappers::UnboundedReceiverStream::new({
                                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                                    tokio::spawn(async move {
                                        tx.send(Ok::<Bytes, std::convert::Infallible>(
                                            Bytes::from_static(b"head"),
                                        ))
                                        .ok();
                                        tokio::time::sleep(Duration::from_secs(60)).await;
                                        tx.send(Ok(Bytes::from_static(b"tail"))).ok();
                                    });
                                    rx
                                });
                                let body: http_body_util::combinators::BoxBody<
                                    Bytes,
                                    std::convert::Infallible,
                                > = http_body_util::BodyExt::boxed(
                                    http_body_util::StreamBody::new(body.map_ok(|b| {
                                        hyper::body::Frame::data(b)
                                    })),
                                );
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder().status(StatusCode::OK).body(body).unwrap(),
                                )
                            } else {
                                let body: http_body_util::combinators::BoxBody<
                                    Bytes,
                                    std::convert::Infallible,
                                > = http_body_util::BodyExt::boxed(
                                    http_body_util::StreamBody::new(
                                        tokio_stream::wrappers::UnboundedReceiverStream::new({
                                            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                                            tx.send(Ok(hyper::body::Frame::data(Bytes::new())))
                                                .ok();
                                            rx
                                        }),
                                    ),
                                );
                                Ok(Response::builder().status(StatusCode::OK).body(body).unwrap())
                            }
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                    finished.fetch_add(1, Ordering::Relaxed);
                });
            }
        })
    };

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client = Arc::new(DefaultDialerClient::new(
        config,
        make_tls_config(),
        DialTarget { host: "127.0.0.1".into(), port: server_addr.port(), sni: String::new() },
        None,
        None,
    ));

    let conn = dial_packet_up(
        client,
        format!("http://127.0.0.1:{}/", server_addr.port()),
        "bridge-eof-sess".into(),
        1024,
        RangeConfig::new(0, 0),
    )
    .await
    .unwrap();
    // 生产同款包装（register.rs：Sync bound）
    let mut conn = conn.into_sync_reader();

    // 模拟 inbound 侧：up 管道写 payload 后 shutdown（SOCKS FIN 等价）；
    // down 管道读端由本测试持有（客户端收下行）。
    let (up_r, mut up_w) = xray_buf::pipe::new();
    let (_dn_r, dn_w) = xray_buf::pipe::new();
    let link = Link::new(
        Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
        Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
    );
    tokio::spawn(async move {
        use xray_buf::io::Writer as _;
        let _ = up_w.write_multi_buffer({
            let mut mb = xray_buf::multi::MultiBuffer::new();
            mb.merge_bytes(b"payload");
            mb
        }).await;
        up_w.shutdown(); // inbound EOF：触发桥 half-close 窗口
    });

    // 生产默认 policy：connIdle=300s（挂起时的兜底）。桥必须不依赖它退出。
    let policy = TimeoutPolicy::default();
    let started = std::time::Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(5), async move {
        bridge_link_with_stream_full(link, conn, &policy).await
    })
    .await;
    let elapsed = started.elapsed();
    assert!(res.is_ok(), "bridge must return via half-close window (1s), not connIdle=300s; elapsed {elapsed:?}");
    let _ = res.unwrap().expect("bridge io ok");
    assert!(
        elapsed < Duration::from_secs(4),
        "bridge must exit within half-close window, elapsed {elapsed:?}"
    );

    // 桥返回后 SplitConn 已 drop → 客户端 HTTP 连接关闭 → server 全部终结。
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let accepted_n = accepted.load(Ordering::Relaxed);
    let finished_n = finished.load(Ordering::Relaxed);
    assert_eq!(
        finished_n, accepted_n,
        "all server connections must finish after bridge EOF (accepted={accepted_n}, finished={finished_n})"
    );

    server_task.abort();
}

// ===== r2lq：serve_http_conn 全栈（TLS + 默认 ALPN=[h2,http/1.1]）packet-up 冒烟 =====

/// rcgen 自签证书（SAN 127.0.0.1）→ (cert PEM, key PEM, cert DER 供客户端信任)。
fn self_signed_tls() -> (String, String, rustls::pki_types::CertificateDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    (cert.pem(), key_pair.serialize_pem(), der)
}

/// 生产入口端到端：listen_splithttp（TLS acceptor → serve_http_conn auto h1/h2）
/// → handle_request → handle_packet_up/handle_stream_down → add_conn 桥 → echo
/// dispatcher。tlsSettings 缺省 ALPN=["h2","http/1.1"]（xray-tls server_config.rs:246），
/// 客户端 hyper-rustls enable_http2 同 ALPN——协商必为 h2（CI #25/#26 真实路径）。
/// 断言：上行 POST → dispatcher echo → 下行 GET body 双向可达。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_up_end_to_end_tls_h2_via_serve_http_conn() {
    use xray_transport::dialer::StreamSettings;
    use xray_transport::listener_registry::ConnHandler;
    use xray_transport::sockopt::SocketOptions;
    use xray_transport_splithttp::transport::listen_splithttp;

    ensure_crypto_provider();
    let (cert_pem, key_pem, cert_der) = self_signed_tls();

    // 预占随机端口（TransportListener 不暴露 local_addr）。
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = probe.local_addr().unwrap();
    drop(probe);

    // echo dispatcher：读多少回多少（interop echo 语义的最小等价物）。
    let handler: ConnHandler = Arc::new(|conn| {
        tokio::spawn(async move {
            let mut conn = conn;
            let mut buf = vec![0u8; 8192];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    });

    // 服务端：生产配置形状（transport_json 直接是 splithttpSettings 对象；
    // cert/key 顶层键走 build_server_config 既有解析，见 server_config.rs 测试）。
    let settings = StreamSettings {
        protocol: "splithttp".into(),
        security: "tls".into(),
        transport_json: Some(serde_json::json!({ "path": "/", "mode": "packet-up" })),
        security_json: Some(serde_json::json!({ "cert": cert_pem, "key": key_pem })),
        ..Default::default()
    };
    let listener = listen_splithttp(server_addr, &settings, &SocketOptions::default(), handler)
        .await
        .expect("listen_splithttp");

    // 客户端：rustls 信任自签证书；DefaultDialerClient rustls 分支
    // enable_http1+enable_http2 注入 [h2, http/1.1]（client.rs bd 3ze9 注释）。
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add root");
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let client = Arc::new(DefaultDialerClient::new(
        config,
        tls_config,
        DialTarget {
            host: "127.0.0.1".into(),
            port: server_addr.port(),
            sni: "127.0.0.1".into(),
        },
        None,
        None,
    ));

    let mut conn = tokio::time::timeout(
        Duration::from_secs(15),
        dial_packet_up(
            client,
            format!("https://127.0.0.1:{}/", server_addr.port()),
            "r2lq-h2-echo-sess".into(),
            1024,
            RangeConfig::new(0, 0),
        ),
    )
    .await
    .expect("dial timeout (GET stream-down never established)")
    .expect("dial_packet_up");

    // 双向可达：上行 POST(seq) → upload_queue → 桥 → echo → dl_tx → GET body。
    conn.write_all(b"r2lq-echo-h2").await.expect("upload write");
    let mut got = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut got))
        .await
        .expect("echo round-trip timeout (h2 server data path broken)")
        .expect("download read");
    assert_eq!(&got, b"r2lq-echo-h2");

    let _ = listener.close();
}
