//! XMUX 连接复用证据锚（规划 §6 门 B2，bd hjtlk B2 验收②）。
//!
//! 复用锚**不看请求成功**（复用坏掉时拨号照样成功——只是每次都新建连接），而是看
//! 服务端侧的 **TCP accept 次数**：xmux `maxConnections {1,1}` ⇒ 5 次 dial 全部
//! 挤在 1 条 h2 连接上，accept 数必须远小于 2×dial（反证阈；splithttp
//! `tests/xmux_reuse.rs` 同款口径——绕池形态 accept ≈ 2×dial）。
//!
//! 客户端走**生产接线路径**（`dial()` → 共享 template 后端 → XMUX 池五维判定）；
//! TLS + ALPN h2（明文 http 无多路复用，accept 数没有锚定力）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)] // 证据数字落 stderr（--nocapture 可见）

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::{io::AsyncWriteExt as _, net::TcpListener, sync::Mutex};
use tokio_rustls::TlsAcceptor;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{connection::Connection, dialer::StreamSettings};
use xray_transport_xdrive::{dial, storage::reset_shared_storage};

// ── 计数 TLS/h2 mock 对象存储 ───────────────────────────────────────────────

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, Vec<u8>>,
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();

    let mut st = state.lock().await;
    let route = path.split('?').next().unwrap_or_default();
    let Some(key) = route.strip_prefix("/folder/") else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    };
    match method.as_str() {
        "PUT" => {
            st.objects.insert(key.to_string(), body.to_vec());
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(Full::new(Bytes::new()))
                .unwrap())
        },
        "GET" => match st.objects.get(key) {
            Some(data) => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::copy_from_slice(data)))
                .unwrap()),
            None => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap()),
        },
        "DELETE" => {
            st.objects.remove(key);
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap())
        },
        "PROPFIND" => {
            let mut listing = String::new();
            for name in st.objects.keys() {
                listing.push_str(&format!("<d:href>/folder/{name}</d:href>\n"));
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(listing.into_bytes().into()))
                .unwrap())
        },
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
}

struct MockStats {
    accepts: AtomicU64,
}

async fn start_tls_h2_mock() -> (Arc<Mutex<MockState>>, Arc<MockStats>, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert_pem, key_pem) =
        xray_tls::certificate::generate_self_signed_cert(&["127.0.0.1"]).unwrap();
    let (certs, key) = xray_tls::certificate::entry_certs_and_key(&json!({
        "certificate": cert_pem,
        "key": key_pem
    }))
    .unwrap();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.expect("self-signed key must parse"))
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("https://{addr}");
    let state = Arc::new(Mutex::new(MockState::default()));
    let stats = Arc::new(MockStats { accepts: AtomicU64::new(0) });
    let (server_state, server_stats, server_acceptor) =
        (Arc::clone(&state), Arc::clone(&stats), acceptor.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            server_stats.accepts.fetch_add(1, Ordering::SeqCst);
            let (state, acceptor) = (Arc::clone(&server_state), server_acceptor.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move { handle(req, state).await }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (state, stats, base)
}

fn xmux_settings(base: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "security": "tls",
        "tlsSettings": {"allowInsecure": true, "alpn": ["h2"], "serverName": "127.0.0.1"},
        "xdriveSettings": {
            "service": "template",
            "remoteFolder": "folder",
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 30,
            "segmentBytes": 16384,
            "eagerWindowMs": 200,
            "template": {
                "flatten": true,
                "auth": {"type": "none"},
                "put": {"method": "PUT", "url": format!("{base}/folder/{{name}}")},
                "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
                "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
                "list": {
                    "method": "PROPFIND",
                    "url": format!("{base}/folder/?prefix={{prefix}}"),
                    "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
                },
                "retry": {"status": [500, 502, 503]}
            },
            "xmux": {"maxConnections": {"from": 1, "to": 1}}
        }
    })))
}

/// 5 次 dial（生产接线：共享 template 后端 → XMUX 池）+ 每会话写 64KiB
/// ⇒ accept 数必须远小于 2×dial（反证阈），实测应为 1。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xmux_max_connections_one_shares_single_h2_conn() {
    reset_shared_storage();

    let (_state, stats, base) = start_tls_h2_mock().await;
    let settings = xmux_settings(&base);
    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);

    const DIALS: usize = 5;
    // 连接保持存活（生产形态：多条代理连接并存）。
    let mut conns: Vec<Box<dyn Connection>> = Vec::with_capacity(DIALS);
    for _ in 0..DIALS {
        let mut conn = dial(&dest, &Default::default(), &settings).await.unwrap();
        // 写一小段上行，逼 WAL writer 产生真实 PUT 分段请求。
        let payload = vec![7u8; 64 * 1024];
        conn.write_all(&payload).await.unwrap();
        conns.push(conn);
    }

    // 等写侧 flush + 读侧轮询在唯一 h2 连接上跑起来。
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let accepts = stats.accepts.load(Ordering::SeqCst);
    eprintln!("xmux reuse: {DIALS} dials → {accepts} TCP accepts");
    assert!(
        accepts < 2 * DIALS as u64,
        "xmux maxConnections=1 must reuse one h2 conn: {DIALS} dials made {accepts} accepts"
    );
    assert!(accepts >= 1, "at least one connection must have been accepted");

    drop(conns);
    reset_shared_storage();
}
