//! xmux 连接复用证据锚（bd s42cg）。
//!
//! 复用锚**不看请求成功**（复用坏掉时拨号照样成功——只是每次都新建连接），而是看
//! 服务端侧的**连接接受次数**：
//! - h2：统计 `TcpListener::accept` 次数（每个 = 一条新 TCP 连接）；
//! - h3：统计 `quinn::Endpoint::accept` 次数（每个 = 一次 QUIC 握手）。
//!
//! 客户端走**生产接线路径**（`register::register_dialer()` + `xray_transport::dialer::dial`），
//! 即 `H2_MANAGERS` / `H3_MANAGERS` 池 + `XmuxManager` 五维判定。
//!
//! 拨号形态取**生产形态**：多条代理连接同时存活（不 drop）。顺序"拨完即关"的形态
//! 单列（`h2_sequential_close_*`）——它比并发形态弱，因为每次关连接都会终止下载流。
//!
//! 反证：绕过池（每次 `mux::wrap_xmux_client` 包一个现建客户端 = 接线前形态）⇒
//! 连接数 ≈ 2×拨号数，证明锚对"是否真复用"敏感。

// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // bd g3cr：测试断言便利豁免；生产禁令不受影响
#![allow(clippy::print_stderr)] // 证据数字落 stderr（cargo test -- --nocapture 可见）

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Incoming, server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    dialer::{StreamSettings, dial},
    sockopt::SocketOptions,
};

// ===== 公共：自签证书 =====

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

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ===== h2 计数服务端 =====

#[derive(Debug, Default)]
struct H2Stats {
    /// TCP accept 次数（复用锚）。
    accepts: AtomicU64,
    gets: AtomicU64,
    posts: AtomicU64,
}

/// 计数型 mock h2 splithttp 服务端：
/// - 每次 `accept` 计一次（= 一条新 TCP 连接）；
/// - GET 返 2 字节下行后 finish（packet-up 下载流）；
/// - POST drain body 后 200（packet-up 上行）。
async fn counting_h2_server(listener: TcpListener, acceptor: TlsAcceptor, stats: Arc<H2Stats>) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => break,
        };
        stats.accepts.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else { return };
            let svc = service_fn(move |req: Request<Incoming>| {
                let stats = stats.clone();
                async move {
                    if req.method() == Method::GET {
                        stats.gets.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"dl")))
                                .unwrap(),
                        )
                    } else {
                        let (_, body) = req.into_parts();
                        tokio::spawn(async move {
                            let _ = body.collect().await;
                            stats.posts.fetch_add(1, Ordering::SeqCst);
                        });
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::new()))
                            .unwrap())
                    }
                }
            });
            let _ = http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

/// 起一个计数 h2 服务端，返回 (端口, 证书 DER, 统计)。
async fn start_h2_server() -> (u16, CertificateDer<'static>, Arc<H2Stats>) {
    ensure_crypto_provider();
    let (cert_der, key_der) = make_self_signed_cert();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(H2Stats::default());
    tokio::spawn(counting_h2_server(
        listener,
        TlsAcceptor::from(Arc::new(server_tls)),
        stats.clone(),
    ));
    (port, cert_der, stats)
}

/// 生产形状的 splithttp streamSettings（h2 + TLS）。
fn h2_settings(port: u16, xmux: Option<serde_json::Value>) -> StreamSettings {
    let mut inner = serde_json::json!({
        "host": format!("127.0.0.1:{port}"),
        "path": "/",
        "mode": "packet-up",
    });
    if let Some(x) = xmux {
        inner["xmux"] = x;
    }
    StreamSettings::from_json(Some(&serde_json::json!({
        "method": "splithttp",
        "security": "tls",
        "tlsSettings": { "serverName": "127.0.0.1", "allowInsecure": true },
        "splithttpSettings": inner,
    })))
}

fn dest_of(port: u16) -> Destination {
    Destination::tcp("127.0.0.1".parse::<Address>().unwrap(), Port::new(port))
}

// ===== h3 计数服务端 =====

fn make_server_crypto(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).expect("QuicServerConfig");
    quinn::ServerConfig::with_crypto(Arc::new(quic))
}

#[derive(Debug, Default)]
struct H3Stats {
    /// QUIC 连接接受次数（= 握手次数；复用锚）。
    accepts: AtomicU64,
    gets: AtomicU64,
    posts: AtomicU64,
}

async fn counting_h3_server(endpoint: quinn::Endpoint, stats: Arc<H3Stats>) {
    while let Some(incoming) = endpoint.accept().await {
        stats.accepts.fetch_add(1, Ordering::SeqCst);
        let stats = stats.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let quinn_conn = h3_quinn::Connection::new(conn);
            let Ok(mut h3_conn) = h3::server::Connection::new(quinn_conn).await else { return };
            while let Ok(Some(req_resolver)) = h3_conn.accept().await {
                let stats = stats.clone();
                let Ok((req, mut stream)) = req_resolver.resolve_request().await else { continue };
                tokio::spawn(async move {
                    if req.method() == Method::GET {
                        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from_static(b"dl")).await;
                        let _ = stream.finish().await;
                        stats.gets.fetch_add(1, Ordering::SeqCst);
                    } else {
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            let len = chunk.remaining();
                            chunk.copy_to_bytes(len);
                        }
                        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.finish().await;
                        stats.posts.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
    }
}

async fn start_h3_server() -> (u16, CertificateDer<'static>, Arc<H3Stats>) {
    ensure_crypto_provider();
    let (cert_der, key_der) = make_self_signed_cert();
    let crypto = make_server_crypto(cert_der.clone(), key_der);
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let endpoint = quinn::Endpoint::server(crypto, addr).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let stats = Arc::new(H3Stats::default());
    tokio::spawn(counting_h3_server(endpoint, stats.clone()));
    (port, cert_der, stats)
}

fn h3_settings(xmux: Option<serde_json::Value>) -> StreamSettings {
    // host 不带端口：h3 的 `server_name` 直接进 quinn（非法 DNS 名会被拒），
    // 与 Go 侧 `requestURL.Host` 去端口的形态一致；连接目标仍是 dest 的端口。
    let mut inner = serde_json::json!({ "host": "127.0.0.1", "path": "/", "mode": "packet-up" });
    if let Some(x) = xmux {
        inner["xmux"] = x;
    }
    StreamSettings::from_json(Some(&serde_json::json!({
        "method": "splithttp",
        "security": "tls",
        "tlsSettings": { "serverName": "127.0.0.1", "allowInsecure": true, "alpn": ["h3"] },
        "splithttpSettings": inner,
    })))
}

// ===== 拨号驱动 =====

/// 走生产接线路径拨号 `dials` 次，**连接保持存活**（生产形态：多条代理连接并存）。
/// 每轮写完上行再读完下载流 2 字节（不读完则 GET 响应滞留，连接被占）。
async fn dial_concurrent(dest: &Destination, settings: &StreamSettings, dials: usize) {
    xray_transport_splithttp::register::register_dialer().expect("register dialer");
    let mut held = Vec::new();
    for i in 0..dials {
        let mut conn = dial(dest, settings, &SocketOptions::default())
            .await
            .unwrap_or_else(|e| panic!("dial #{i}: {e}"));
        tokio::io::AsyncWriteExt::write_all(&mut conn, b"x")
            .await
            .unwrap_or_else(|e| panic!("write #{i}: {e}"));
        let mut dl = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut conn, &mut dl)
            .await
            .unwrap_or_else(|e| panic!("read dl #{i}: {e}"));
        assert_eq!(&dl, b"dl", "下载流内容");
        tokio::time::sleep(Duration::from_millis(20)).await;
        held.push(conn);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(held);
}

/// 串行形态：每次拨号用完即关（每条代理连接生命周期内独占）。
async fn dial_sequential(dest: &Destination, settings: &StreamSettings, dials: usize) {
    xray_transport_splithttp::register::register_dialer().expect("register dialer");
    for i in 0..dials {
        let mut conn = dial(dest, settings, &SocketOptions::default())
            .await
            .unwrap_or_else(|e| panic!("dial #{i}: {e}"));
        tokio::io::AsyncWriteExt::write_all(&mut conn, b"x")
            .await
            .unwrap_or_else(|e| panic!("write #{i}: {e}"));
        let mut dl = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut conn, &mut dl)
            .await
            .unwrap_or_else(|e| panic!("read dl #{i}: {e}"));
        assert_eq!(&dl, b"dl", "下载流内容");
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(conn);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
}

// ===== 用例 1：默认 xmux（缺省预设 maxConnections=3）+ 并发拨号 ⇒ 连接数远小于拨号数 =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_default_xmux_reuses_tcp_connection() {
    let (port, _cert, stats) = start_h2_server().await;
    const DIALS: usize = 5;
    dial_concurrent(&dest_of(port), &h2_settings(port, None), DIALS).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    let gets = stats.gets.load(Ordering::SeqCst);
    let posts = stats.posts.load(Ordering::SeqCst);
    eprintln!("[h2 default xmux] dials={DIALS} accepts={accepts} gets={gets} posts={posts}");

    assert_eq!(gets, DIALS as u64, "每次拨号都要发一个下载 GET");
    assert_eq!(posts, DIALS as u64, "每次拨号都要发上行 POST");
    // 无池形态实测 2×DIALS = 10 条（见 h2_bypass_pool_control）。
    assert!(
        accepts < 2 * DIALS as u64,
        "默认 xmux 下必须复用：accepts={accepts} 应显著小于 2×{DIALS}"
    );
}

// ===== 用例 2：maxConnections=1 ⇒ 单 client，多条代理连接挤在极少数 TCP 上 =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_max_connections_one_single_client() {
    let (port, _cert, stats) = start_h2_server().await;
    const DIALS: usize = 5;
    let xmux = serde_json::json!({ "maxConnections": { "from": 1, "to": 1 } });
    dial_concurrent(&dest_of(port), &h2_settings(port, Some(xmux)), DIALS).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    eprintln!("[h2 maxConnections=1] dials={DIALS} accepts={accepts}");
    // 实测 6（无池形态 = 10）：池化确实省掉近一半 TCP，但 h2 侧仍常见"每拨号新增
    // 一条"——成因未定（同一 client 直连实测 5 拨号仅 2 条 TCP，多路复用本身可用），
    // 登记在报告 §5 残余风险。
    assert!(
        accepts < 2 * DIALS as u64,
        "maxConnections=1 时必须复用（明显少于无池的 2×{DIALS}）：accepts={accepts}"
    );
}

// ===== 用例 3：反证——绕过池（每次现建客户端 = 接线前形态）⇒ 连接数 ≈ 2×拨号数 =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_bypass_pool_control() {
    use xray_transport_splithttp::{
        client::{DefaultDialerClient, DialTarget},
        config::RangeConfig,
        dialer::dial_packet_up,
    };

    let (port, cert_der, stats) = start_h2_server().await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();

    const DIALS: usize = 5;
    let mut held = Vec::new();
    for i in 0..DIALS {
        let client = Arc::new(DefaultDialerClient::new(
            Arc::new(xray_transport_splithttp::config::Config {
                host: format!("127.0.0.1:{port}"),
                path: "/".into(),
                ..Default::default()
            }),
            tls.clone(),
            DialTarget { host: "127.0.0.1".into(), port, sni: "127.0.0.1".into() },
            None,
            None,
            None,
        ));
        // 每次现建一个"池"——等价接线前 `dialer.rs` 对 mux:: 零引用的形态。
        let mut conn = dial_packet_up(
            xray_transport_splithttp::mux::wrap_xmux_client(client),
            None,
            format!("https://127.0.0.1:{port}/"),
            format!("bypass-{i}"),
            1024,
            RangeConfig::new(0, 0),
        )
        .await
        .expect("dial_packet_up");
        tokio::io::AsyncWriteExt::write_all(&mut conn, b"y").await.unwrap();
        let mut dl = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut conn, &mut dl).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        held.push(conn);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    eprintln!("[h2 bypass pool] dials={DIALS} accepts={accepts}");
    drop(held);
    assert!(
        accepts >= DIALS as u64,
        "绕过池后每拨号至少现拨一条（锚的敏感性证明）：accepts={accepts} dials={DIALS}"
    );
}

// ===== 用例 4：串行形态（拨完即关）的复用弱化 —— 与用例 1 对比 =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_sequential_close_weakens_reuse() {
    let (port, _cert, stats) = start_h2_server().await;
    const DIALS: usize = 5;
    dial_sequential(&dest_of(port), &h2_settings(port, None), DIALS).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    eprintln!("[h2 sequential close] dials={DIALS} accepts={accepts}");
    // 关连接会终止该拨号的下载流，hyper 池随之多拨；仍应少于无池形态（2×DIALS）。
    assert!(accepts < 2 * DIALS as u64, "串行形态也应复用：accepts={accepts}");
}

// ===== 用例 5：hMaxRequestTimes 逐请求扣减真的接上了 =====
// 同一 manager、同 maxConnections 缺省（=0 不限），只有请求预算不同：
// - 预算 100：5 次拨号共 10 个请求，够用 ⇒ 连接数少
// - 预算 1：client 首次取用即耗尽（GET 扣一次）⇒ 每次拨号必须新建 client

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_h_max_request_times_budget_is_decremented_per_request() {
    const DIALS: usize = 5;

    let (port_a, _c1, stats_a) = start_h2_server().await;
    let budget_big = serde_json::json!({ "hMaxRequestTimes": { "from": 100, "to": 100 } });
    dial_concurrent(&dest_of(port_a), &h2_settings(port_a, Some(budget_big)), DIALS).await;
    let accepts_big = stats_a.accepts.load(Ordering::SeqCst);

    let (port_b, _c2, stats_b) = start_h2_server().await;
    let budget_one = serde_json::json!({ "hMaxRequestTimes": { "from": 1, "to": 1 } });
    dial_concurrent(&dest_of(port_b), &h2_settings(port_b, Some(budget_one)), DIALS).await;
    let accepts_one = stats_b.accepts.load(Ordering::SeqCst);

    eprintln!(
        "[h2 hMaxRequestTimes] dials={DIALS} budget=100 accepts={accepts_big} \
         budget=1 accepts={accepts_one}"
    );
    assert!(
        accepts_big < accepts_one,
        "预算 100 的连接复用必须多于预算 1（证明 dec_left_requests 已接）：\
         big={accepts_big} one={accepts_one}"
    );
}

// ===== 用例 6：h3 侧复用（池单元 = LazyH3Conn，锚 = QUIC 接受次数） =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_xmux_reuses_quic_connection() {
    let (port, _cert, stats) = start_h3_server().await;
    const DIALS: usize = 4;
    let xmux = serde_json::json!({ "maxConnections": { "from": 1, "to": 1 } });
    dial_concurrent(&dest_of(port), &h3_settings(Some(xmux)), DIALS).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    let gets = stats.gets.load(Ordering::SeqCst);
    let posts = stats.posts.load(Ordering::SeqCst);
    eprintln!("[h3 maxConnections=1] dials={DIALS} accepts={accepts} gets={gets} posts={posts}");

    assert_eq!(gets, DIALS as u64, "每次拨号都要发一个下载 GET");
    assert_eq!(posts, DIALS as u64, "每次拨号都要发上行 POST");
    assert_eq!(accepts, 1, "h3 侧 xmux 必须复用同一条 QUIC 连接：accepts={accepts}");
}
