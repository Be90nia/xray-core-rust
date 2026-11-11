//! h3 面证据锚（规划 §5 B6②：ALPN `["h3"]` 触发 + 与 h2 同款语义）。
//!
//! ① **ALPN 触发判据**（Go `client.go:235`：只有 `tlsSettings.alpn` 恰好是
//!    `["h3"]` 才走 QUIC；`["h2","h3"]` 不算——TCP 上没有服务端会用 h3 ALPN 应答）；
//! ② **真跑**：QUIC + h3 mock 对象存储上 `serve()` → `dial()` → 128KiB 双向往返
//!    逐字节相等，且服务端握手数据里协商出的 ALPN 必须是 `h3`；
//! ③ **与 h2 同款语义**：xmux `maxConnections {1,1}` ⇒ 5 次 dial 复用同一池单元，
//!    QUIC 连接数远小于 2×dial（同 `tests/xmux_reuse_xdrive.rs` 的 h2 反证锚口径）。
//!
//! h3 是 Go 对齐面：`xdrive` 的 storage 后端（template/S3/drive）由本传输自己发
//! HTTP 请求，Go 在 `tlsSettings.alpn == ["h3"]` 时改走 `http3.Transport`。

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::{Buf as _, Bytes};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Mutex, mpsc},
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_frame::scope::ComponentScope;
use xray_transport::{
    connection::Connection, dialer::StreamSettings, listener_registry::ConnHandler,
};
use xray_transport_xdrive::{Config, dial, serve, storage::reset_shared_storage};

// ── h3 mock 对象存储（QUIC + h3 server）────────────────────────────────────

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct MockStats {
    /// 每条 QUIC 连接一次。
    connections: AtomicU64,
    /// 服务端握手数据里记录到的 ALPN（`None` = 对端未发 ALPN）。
    alpns: Mutex<Vec<Option<Vec<u8>>>>,
    /// 收到的 PUT body 总字节（证明数据真的经由 h3 到达服务端）。
    put_bytes: AtomicU64,
}

fn udp_transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.stream_receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
    tc.receive_window(quinn::VarInt::from_u32(32 * 1024 * 1024));
    tc
}

/// 启动 h3 mock（`PUT/GET/DELETE/PROPFIND /folder/<name>`，同 xmux h2 mock 的路由
/// 口径），返回 `(state, stats, base_url)`。
///
/// 任务全挂 [`ComponentScope`]（§3.5.6 ①类；测试代码不留裸 spawn）。
async fn start_h3_mock(
    scope: &Arc<ComponentScope>,
) -> (Arc<Mutex<MockState>>, Arc<MockStats>, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert_pem, key_pem) =
        xray_tls::certificate::generate_self_signed_cert(&["127.0.0.1"]).expect("self-signed cert");
    let (certs, key) = xray_tls::certificate::entry_certs_and_key(&json!({
        "certificate": cert_pem,
        "key": key_pem
    }))
    .expect("certs and key");
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.expect("self-signed key must parse"))
        .expect("server TLS config");
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("rustls → quic server");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(udp_transport_config()));

    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp bind");
    let addr = sock.local_addr().expect("local addr");
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        sock,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("quic endpoint");

    let state = Arc::new(Mutex::new(MockState::default()));
    let stats = Arc::new(MockStats::default());
    let (server_state, server_stats, tasks) =
        (Arc::clone(&state), Arc::clone(&stats), Arc::clone(scope));
    scope
        .spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                server_stats.connections.fetch_add(1, Ordering::SeqCst);
                let alpn = conn
                    .handshake_data()
                    .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|h| h.protocol.clone());
                server_stats.alpns.lock().await.push(alpn);
                let (state, stats) = (Arc::clone(&server_state), Arc::clone(&server_stats));
                let _ = tasks.spawn(serve_h3_conn(conn, state, stats, Arc::clone(&tasks)));
            }
        })
        .expect("mock accept task");
    (state, stats, format!("https://{addr}"))
}

async fn serve_h3_conn(
    conn: quinn::Connection,
    state: Arc<Mutex<MockState>>,
    stats: Arc<MockStats>,
    tasks: Arc<ComponentScope>,
) {
    let Ok(mut h3_conn) =
        h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await
    else {
        return;
    };
    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let (state, stats, tasks) = (Arc::clone(&state), Arc::clone(&stats), Arc::clone(&tasks));
        let _ = tasks.spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else { return };
            let (send, recv) = stream.split();
            handle_h3_request(req, send, recv, state, stats).await;
        });
    }
}

async fn handle_h3_request(
    req: http::Request<()>,
    mut send: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    state: Arc<Mutex<MockState>>,
    stats: Arc<MockStats>,
) {
    let mut body = Vec::new();
    loop {
        match recv.recv_data().await {
            Ok(Some(chunk)) => body.extend_from_slice(chunk.chunk()),
            Ok(None) => break,
            Err(_) => return,
        }
    }
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let route = path.split('?').next().unwrap_or_default();
    let mut status = http::StatusCode::NOT_FOUND;
    let mut payload = Vec::new();
    if let Some(key) = route.strip_prefix("/folder/") {
        let mut st = state.lock().await;
        match req.method().as_str() {
            "PUT" => {
                stats.put_bytes.fetch_add(body.len() as u64, Ordering::SeqCst);
                st.objects.insert(key.to_string(), body);
                status = http::StatusCode::CREATED;
            },
            "GET" => {
                status = http::StatusCode::OK;
                payload = st.objects.get(key).cloned().unwrap_or_default();
            },
            "DELETE" => {
                st.objects.remove(key);
                status = http::StatusCode::NO_CONTENT;
            },
            "PROPFIND" => {
                status = http::StatusCode::OK;
                let mut listing = String::new();
                for name in st.objects.keys() {
                    listing.push_str(&format!("<d:href>/folder/{name}</d:href>\n"));
                }
                payload = listing.into_bytes();
            },
            _ => status = http::StatusCode::METHOD_NOT_ALLOWED,
        }
    }
    if send
        .send_response(http::Response::builder().status(status).body(()).expect("response builder"))
        .await
        .is_err()
    {
        return;
    }
    if !payload.is_empty() && send.send_data(Bytes::from(payload)).await.is_err() {
        return;
    }
    let _ = send.finish().await;
}

// ── 配置面 ─────────────────────────────────────────────────────────────────

fn settings_with_alpn(base: &str, alpn: serde_json::Value) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "security": "tls",
        "tlsSettings": {"allowInsecure": true, "alpn": alpn, "serverName": "127.0.0.1"},
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

// ── ① ALPN 触发判据 ────────────────────────────────────────────────────────

#[test]
fn h3_derives_only_when_alpn_is_h3_alone() {
    let h3 = settings_with_alpn("https://127.0.0.1:1", json!(["h3"]));
    assert!(Config::from_settings(&h3).expect("h3 settings").h3, "alpn [\"h3\"] must select h3");
    for alpn in [json!(["h2", "h3"]), json!(["h2"]), json!(["http/1.1"])] {
        let settings = settings_with_alpn("https://127.0.0.1:1", alpn.clone());
        assert!(
            !Config::from_settings(&settings).expect("settings").h3,
            "alpn {alpn} must stay on h2/h1（Go client.go:234：TCP 上没有服务端用 h3 应答）"
        );
    }
}

// ── ② + ③ h3 真跑：往返传输 + 连接复用 ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_dial_serve_roundtrip_uses_quic_and_reuses_conn() {
    reset_shared_storage();
    let tasks = Arc::new(ComponentScope::new("xdrive-h3-test"));
    let (_state, stats, base) = start_h3_mock(&tasks).await;
    let settings = settings_with_alpn(&base, json!(["h3"]));

    let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn Connection>>(8);
    let handler: ConnHandler = Arc::new(move |conn| {
        let tx = conn_tx.clone();
        tx.try_send(conn).expect("handler channel must have room");
    });
    let listener = serve(
        "127.0.0.1:0".parse().expect("listen addr"),
        settings.clone(),
        Default::default(),
        handler,
    )
    .await
    .expect("serve over template backend");

    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    {
        let mut client = tokio::time::timeout(
            Duration::from_secs(30),
            dial(&dest, &Default::default(), &settings),
        )
        .await
        .expect("dial over h3 must complete in time")
        .expect("dial over h3");

        let mut server = tokio::time::timeout(Duration::from_secs(30), conn_rx.recv())
            .await
            .expect("listener must accept the announced session")
            .expect("handler channel closed");

        // 128KiB 上行：客户端 → 服务端，逐字节相等（数据真经 h3 传输）。
        let payload: Vec<u8> = (0..128 * 1024usize).map(|i| (i * 31 % 251) as u8).collect();
        client.write_all(&payload).await.expect("write uplink");
        let mut received = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(30), server.read_exact(&mut received))
            .await
            .expect("uplink must arrive")
            .expect("uplink bytes");
        assert_eq!(received, payload, "128KiB uplink over h3 must be byte-equal");

        // 128KiB 下行：服务端回写 → 客户端读。
        server.write_all(&received).await.expect("write downlink");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(30), client.read_exact(&mut echoed))
            .await
            .expect("downlink must arrive")
            .expect("downlink bytes");
        assert_eq!(echoed, payload, "128KiB downlink over h3 must be byte-equal");

        let _ = client.shutdown().await;
        let _ = server.shutdown().await;
    }

    // ③ 与 h2 同款语义：后续 dial 复用同一客户端池单元（不再新建 QUIC 连接；
    // `tests/xmux_reuse_xdrive.rs` 的 h2 反证锚同口径：绕池形态 = 每次 dial 一条）。
    const DIALS: usize = 5;
    for _ in 1..DIALS {
        let conn = tokio::time::timeout(
            Duration::from_secs(30),
            dial(&dest, &Default::default(), &settings),
        )
        .await
        .expect("dial over h3 must complete in time")
        .expect("dial over h3");
        drop(conn);
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let connections = stats.connections.load(Ordering::SeqCst);
    let put_bytes = stats.put_bytes.load(Ordering::SeqCst);
    let alpns = stats.alpns.lock().await.clone();
    eprintln!("h3 anchor: connections={connections} put_bytes={put_bytes} alpns={alpns:?}");
    assert!(!alpns.is_empty(), "h3 client must have opened at least one QUIC connection");
    assert!(
        alpns.iter().all(|a| a.as_deref() == Some(b"h3")),
        "every QUIC connection must negotiate ALPN h3（触发与协商双证）: {alpns:?}"
    );
    assert!(
        connections < 2 * DIALS as u64,
        "xmux maxConnections=1 must reuse QUIC conns: {DIALS} dials made {connections} connections"
    );
    assert!(put_bytes > 0, "storage PUT bodies must have crossed the h3 connection");

    listener.close().expect("listener close");
    reset_shared_storage();
}
