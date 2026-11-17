//! 切片 C / Q3：H3 持续全双工矩阵（GitHub issue #22 疑问 3）。
//!
//! 与 `full_duplex_matrix_h2.rs` 同构的四个场景（upload-only / download-only /
//! 并发 upload+download / 慢消费消费者），但传输层换成 H3 over QUIC
//! （`quinn` + `h3`），覆盖 [`xray_transport_splithttp::dialer::dial_h3_stream_up`] /
//! [`xray_transport_splithttp::dialer::dial_h3_stream_one`] 两条路径。
//!
//! H3 侧的收发并发靠 h3 官方 `RequestStream::split()`（客户端 `open_stream_uploading`
//! 拆收发两半 + 两个 task；服务端本文件同样拆），因此「同一 stream 上同时收发」
//! 在 H3 上是**设计内**的形态，与 H2 侧 hyper 的隐式并发路径不同。
//!
//! 观测点与 H2 文件一致：方向吞吐（字节数 + 耗时）、背压等待（poll 返回 `Pending`
//! 的次数）、服务端收发时刻交错。
//!
//! 进程隔离说明：本仓 h3 端到端用例的 rustls 进程级 `ClientConfig` 缓存按
//! **server name** 分键（`xray_transport_quic::zero_rtt::shared_client_config`），
//! 故每个用例用**互不相同的 server name + 各自的自签证书**，避免同进程多 h3 用例
//! 互相污染证书（历史症状：`invalid peer certificate: BadSignature`）。
//!
//! 结论边界（明示局限）：本文件结论**只覆盖被测 mock 传输**（quinn + `h3` server +
//! 本仓客户端），未覆盖真实对端。QUIC 流级/连接级流窗事件（MAX_STREAM_DATA /
//! MAX_DATA）**无埋点**——窗口背压只能由「该方向 pending 计数 + 服务端下发停滞」
//! 间接证明，不能精确归因到具体窗口帧。

// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // bd g3cr：测试断言便利豁免（allow-unwrap-in-tests 对 tests/ 目录失效，clippy#13981）；生产禁令不受影响

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
};
use xray_transport_splithttp::{
    config::Config,
    dialer::{build_request_url, dial_h3_stream_one, dial_h3_stream_up},
    h3_client::H3Conn,
    mux::wrap_xmux_client,
};

/// 上行/下行块大小（与生产上行块 `UPLINK_CHUNK` 同值）。
const CHUNK: usize = 64 * 1024;
/// 上行字节数（8 MiB）。
const UPLOAD_BYTES: usize = 8 * 1024 * 1024;
/// 并发场景下行字节数（8 MiB）。
const CONCURRENT_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// 下载独占场景下行字节数（16 MiB）。
const DOWNLOAD_ONLY_BYTES: u64 = 16 * 1024 * 1024;
/// upload-only 场景服务端下推字节数（48 MiB；H3 流收窗 1.25 MiB ⇒ 下行必然背压）。
const UPLOAD_ONLY_DOWNLOAD_BYTES: u64 = 48 * 1024 * 1024;
/// slow consumer 场景下行字节数（40 MiB ⇒ 下行必然背压）。
const SLOW_DOWNLOAD_BYTES: u64 = 40 * 1024 * 1024;
/// slow consumer 每读一块的间隔。
const SLOW_READ_DELAY: Duration = Duration::from_millis(5);
/// 单次方向操作的超时上限。
const OP_TIMEOUT: Duration = Duration::from_secs(60);

// ===== 计量工具 =====

/// 计量包装：统计 future 被 poll 返回 `Pending` 的次数（该方向遇到的背压等待）。
struct PendingMeter<F> {
    inner: Pin<Box<F>>,
    pending: u64,
}

impl<F: Future> PendingMeter<F> {
    fn new(inner: F) -> Self {
        Self { inner: Box::pin(inner), pending: 0 }
    }
}

impl<F: Future> Future for PendingMeter<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.inner.as_mut().poll(cx) {
            Poll::Ready(v) => Poll::Ready(v),
            Poll::Pending => {
                this.pending += 1;
                Poll::Pending
            },
        }
    }
}

/// 单方向指标。
#[derive(Debug, Clone, Copy, Default)]
struct DirMetrics {
    bytes: u64,
    elapsed: Duration,
    pending_polls: u64,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl DirMetrics {
    fn mib_per_sec(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.bytes as f64 / (1024.0 * 1024.0) / self.elapsed.as_secs_f64()
    }
}

/// 上行泵：写满 `total` 字节。
async fn pump_upload(writer: &mut DuplexStream, total: usize) -> DirMetrics {
    let start = Instant::now();
    let mut m = DirMetrics { start: Some(start), ..DirMetrics::default() };
    let buf = vec![b'u'; CHUNK];
    while (m.bytes as usize) < total {
        let n = CHUNK.min(total - m.bytes as usize);
        let mut meter = PendingMeter::new(writer.write_all(&buf[..n]));
        let res = tokio::time::timeout(OP_TIMEOUT, &mut meter).await.expect("upload write timeout");
        m.pending_polls += meter.pending;
        res.expect("upload write failed");
        m.bytes += n as u64;
    }
    m.elapsed = start.elapsed();
    m.end = Some(Instant::now());
    m
}

/// 下行泵：读满 `total` 字节（`None` = 读到 EOF）。
async fn pump_download(
    reader: &mut Box<dyn AsyncRead + Send + Unpin>,
    total: Option<u64>,
    slow: Option<Duration>,
) -> DirMetrics {
    let start = Instant::now();
    let mut m = DirMetrics { start: Some(start), ..DirMetrics::default() };
    let mut buf = vec![0u8; CHUNK];
    loop {
        if let Some(t) = total {
            if m.bytes >= t {
                break;
            }
        }
        let mut meter = PendingMeter::new(reader.read(&mut buf));
        let res =
            tokio::time::timeout(OP_TIMEOUT, &mut meter).await.expect("download read timeout");
        m.pending_polls += meter.pending;
        let n = res.expect("download read failed");
        if n == 0 {
            break;
        }
        m.bytes += n as u64;
        if let Some(d) = slow {
            tokio::time::sleep(d).await;
        }
    }
    m.elapsed = start.elapsed();
    m.end = Some(Instant::now());
    m
}

// ===== mock H3 server =====

/// mock server 的服务端侧观测点。
#[derive(Default)]
struct ServerCounters {
    recv_bytes: AtomicU64,
    recv_count: AtomicU64,
    sent_bytes: AtomicU64,
    recv_last_at: std::sync::Mutex<Option<Instant>>,
    recv_first_at: std::sync::Mutex<Option<Instant>>,
    sent_last_at: std::sync::Mutex<Option<Instant>>,
}

/// mock server 行为配置。
#[derive(Clone, Copy)]
struct MockSpec {
    get_bytes: u64,
    post_bytes: u64,
    chunk: usize,
    delay: Duration,
}

/// mock H3 splithttp server：GET → 下行载荷；POST → 计量上行 + 下行载荷（响应体）。
///
/// 收发两半用 h3 官方 `RequestStream::split()` 拆开，**同一 task 内 `join!`**：
/// 上行计量与下行下发并发（与客户端 `open_stream_uploading` 的 split 对称）。
/// 用具体类型（不写泛型 helper）⇒ 编译器可直接判定 `Send`（`tokio::spawn` 要求）。
async fn mock_h3_server(endpoint: quinn::Endpoint, spec: MockSpec, counters: Arc<ServerCounters>) {
    while let Some(incoming) = endpoint.accept().await {
        let counters = counters.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                return;
            };
            let quinn_conn = h3_quinn::Connection::new(conn);
            let Ok(mut h3_conn) = h3::server::Connection::new(quinn_conn).await else {
                return;
            };
            while let Ok(Some(resolver)) = h3_conn.accept().await {
                let counters = counters.clone();
                tokio::spawn(async move {
                    let Ok((req, stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    // 下行载荷长度按方法取（GET 走独立下载流，POST 走响应体）。
                    let payload_bytes = match *req.method() {
                        Method::POST => spec.post_bytes,
                        Method::GET => spec.get_bytes,
                        _ => 0,
                    };
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    // 收发两半拆开（h3 官方 split）：上行计量与下行下发并发。
                    let (mut send_half, mut recv_half) = stream.split();
                    let recv_counters = counters.clone();
                    let recv_task = async move {
                        let mut first = true;
                        while let Ok(Some(mut chunk)) = recv_half.recv_data().await {
                            let len = chunk.remaining();
                            let _ = chunk.copy_to_bytes(len);
                            recv_counters.recv_bytes.fetch_add(len as u64, Ordering::Relaxed);
                            let now = Instant::now();
                            *recv_counters.recv_last_at.lock().unwrap() = Some(now);
                            if first {
                                *recv_counters.recv_first_at.lock().unwrap() = Some(now);
                                first = false;
                            }
                        }
                        recv_counters.recv_count.fetch_add(1, Ordering::Relaxed);
                    };
                    let send_counters = counters.clone();
                    let send_task = async move {
                        let _ = send_half.send_response(resp).await;
                        let mut sent = 0u64;
                        while sent < payload_bytes {
                            let n = spec.chunk.min((payload_bytes - sent) as usize);
                            let buf = Bytes::from(vec![b'd'; n]);
                            if send_half.send_data(buf).await.is_err() {
                                break;
                            }
                            sent += n as u64;
                            send_counters.sent_bytes.fetch_add(n as u64, Ordering::Relaxed);
                            if !spec.delay.is_zero() {
                                tokio::time::sleep(spec.delay).await;
                            }
                        }
                        *send_counters.sent_last_at.lock().unwrap() = Some(Instant::now());
                        let _ = send_half.finish().await;
                    };
                    tokio::join!(recv_task, send_task);
                });
            }
        });
    }
}

// ===== 测试脚手架 =====

fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 自签证书（SAN = `name`）。
fn make_self_signed_cert(name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
    )
}

/// 服务端 quinn 配置（ALPN = h3）。
fn make_server_crypto(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).expect("QuicServerConfig");
    quinn::ServerConfig::with_crypto(Arc::new(quic))
}

/// 客户端 rustls 配置（信任自签证书）。
fn make_client_tls(cert: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add cert to roots");
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// 一套 mock server + 客户端（每个场景/每轮独立 ⇒ 计数互不污染）。
struct H3Mock {
    base_uri: String,
    h3: Arc<H3Conn>,
    counters: Arc<ServerCounters>,
    task: tokio::task::JoinHandle<()>,
}

/// 起一套 H3 mock server + 对应客户端。
///
/// `server_name` 必须**逐用例唯一**：rustls 进程级 `ClientConfig` 缓存按 server name
/// 分键（`xray_transport_quic::zero_rtt::shared_client_config`），同名会复用上一个
/// 用例的证书 ⇒ `invalid peer certificate: BadSignature`。
async fn start_mock(server_name: &str, spec: MockSpec) -> H3Mock {
    let (cert, key) = make_self_signed_cert(server_name);
    let server_crypto = make_server_crypto(cert.clone(), key);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = socket.local_addr().expect("local addr");
    drop(socket);
    let endpoint = quinn::Endpoint::server(server_crypto, server_addr).expect("server endpoint");
    let counters = Arc::new(ServerCounters::default());
    let task = tokio::spawn(mock_h3_server(endpoint.clone(), spec, counters.clone()));

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let h3 = H3Conn::connect_with_quic_params(
        config.clone(),
        server_addr,
        server_name,
        make_client_tls(cert),
        None,
        &xray_transport::sockopt::SocketOptions::default(),
    )
    .await
    .expect("H3Conn::connect_with_quic_params");
    H3Mock { base_uri, h3, counters, task }
}

/// 等服务端收满上行字节。
async fn wait_for_recv_bytes(
    counters: &Arc<ServerCounters>,
    target: u64,
    timeout: Duration,
) -> u64 {
    let start = Instant::now();
    loop {
        let got = counters.recv_bytes.load(Ordering::Relaxed);
        if got >= target || start.elapsed() > timeout {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 打印方向指标（可复现证据）。
fn report(label: &str, up: &DirMetrics, down: &DirMetrics, counters: &ServerCounters) {
    // 服务端视角的**双向重叠**：上行第一字节到达时刻早于下行最后一字节下发时刻
    // ⇒ 服务端「还在下发下行」时就已经开始「收上行」⇒ 两方向同时在途。
    let overlap =
        match (*counters.recv_first_at.lock().unwrap(), *counters.sent_last_at.lock().unwrap()) {
            (Some(f), Some(s)) => Some(f < s),
            _ => None,
        };
    println!(
        "[{label}] up={} B/{:?} ({:.2} MiB/s, pending={}) | down={} B/{:?} ({:.2} MiB/s, pending={}) \
         | server recv={} B sent={} B server_overlap={:?}",
        up.bytes,
        up.elapsed,
        up.mib_per_sec(),
        up.pending_polls,
        down.bytes,
        down.elapsed,
        down.mib_per_sec(),
        down.pending_polls,
        counters.recv_bytes.load(Ordering::Relaxed),
        counters.sent_bytes.load(Ordering::Relaxed),
        overlap,
    );
}

/// 两个方向的时间窗是否重叠（真并发证据）。
fn windows_overlap(a: &DirMetrics, b: &DirMetrics) -> bool {
    match (a.start, a.end, b.start, b.end) {
        (Some(as_), Some(ae), Some(bs), Some(be)) => as_ < be && bs < ae,
        _ => false,
    }
}

// ===== 场景 1：upload-only =====

/// upload-only：服务端持续下推（客户端不读 ⇒ 下行背压），上行仍须写满并被收满。
#[tokio::test]
async fn h3_upload_only_survives_unread_download() {
    ensure_crypto_provider();
    let mock = start_mock(
        "h3-s1-upload-only.test",
        MockSpec {
            get_bytes: UPLOAD_ONLY_DOWNLOAD_BYTES,
            post_bytes: 0,
            chunk: CHUNK,
            delay: Duration::ZERO,
        },
    )
    .await;

    let mut conn = dial_h3_stream_up(
        wrap_xmux_client(mock.h3.clone()),
        None,
        mock.base_uri.clone(),
        uuid::Uuid::new_v4().to_string(),
    )
    .await
    .expect("dial_h3_stream_up");

    let up = pump_upload(&mut conn.writer, UPLOAD_BYTES).await;
    let server_got = wait_for_recv_bytes(&mock.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    let down = DirMetrics::default();
    report("h3/upload-only", &up, &down, &mock.counters);

    assert_eq!(up.bytes, UPLOAD_BYTES as u64, "上行应写满");
    assert_eq!(server_got, UPLOAD_BYTES as u64, "服务端应收满上行字节（下行背压不得拖死上行）");
    assert!(
        mock.counters.sent_bytes.load(Ordering::Relaxed) > 0,
        "服务端应已下推下行字节（证明下行方向确实在制造背压）"
    );
    mock.task.abort();
}

// ===== 场景 2：download-only =====

/// download-only：服务端持续下发，客户端读到 EOF。
#[tokio::test]
async fn h3_download_only_transfers_full_payload() {
    ensure_crypto_provider();
    let mock = start_mock(
        "h3-s2-download-only.test",
        MockSpec {
            get_bytes: DOWNLOAD_ONLY_BYTES,
            post_bytes: 0,
            chunk: CHUNK,
            delay: Duration::ZERO,
        },
    )
    .await;

    let mut conn = dial_h3_stream_up(
        wrap_xmux_client(mock.h3.clone()),
        None,
        mock.base_uri.clone(),
        uuid::Uuid::new_v4().to_string(),
    )
    .await
    .expect("dial_h3_stream_up");

    let down = pump_download(&mut conn.reader, None, None).await;
    let up = DirMetrics::default();
    report("h3/download-only", &up, &down, &mock.counters);

    assert_eq!(down.bytes, DOWNLOAD_ONLY_BYTES, "下行应读满服务端下发字节");
    assert!(down.mib_per_sec() > 0.0, "下行吞吐应可测（实测 {:.2} MiB/s）", down.mib_per_sec());
    mock.task.abort();
}

// ===== 场景 3：并发 upload + download =====

/// 并发 upload+download：同一 QUIC stream 上同时收发（时间窗必须重叠）。
#[tokio::test]
async fn h3_concurrent_upload_and_download_overlap() {
    ensure_crypto_provider();
    let mock = start_mock(
        "h3-s3-concurrent.test",
        MockSpec {
            get_bytes: 0,
            post_bytes: CONCURRENT_DOWNLOAD_BYTES,
            chunk: CHUNK,
            delay: Duration::ZERO,
        },
    )
    .await;

    let mut conn =
        dial_h3_stream_one(wrap_xmux_client(mock.h3.clone()), mock.base_uri.clone(), String::new())
            .await
            .expect("dial_h3_stream_one");

    let reader = &mut conn.reader;
    let writer = &mut conn.writer;
    let (up, down) = tokio::join!(
        pump_upload(writer, UPLOAD_BYTES),
        pump_download(reader, Some(CONCURRENT_DOWNLOAD_BYTES), None),
    );
    let server_got = wait_for_recv_bytes(&mock.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    report("h3/concurrent", &up, &down, &mock.counters);

    assert_eq!(up.bytes, UPLOAD_BYTES as u64, "上行应写满");
    assert_eq!(down.bytes, CONCURRENT_DOWNLOAD_BYTES, "下行应读满服务端下发字节");
    assert_eq!(server_got, UPLOAD_BYTES as u64, "服务端应收满上行字节（下行在途时上行未被饿死）");
    assert!(
        windows_overlap(&up, &down),
        "上下行时间窗必须重叠（真并发，而非先上传完再下载）：up={:?} down={:?}",
        (up.start, up.end),
        (down.start, down.end)
    );
    mock.task.abort();
}

// ===== 场景 4：慢消费消费者 =====

/// slow consumer：下行消费者刻意慢读时，上行仍须写满并被服务端收满。
///
/// 两轮各自一套 mock server（server name 与计数都独立 ⇒ 互不污染）。
#[tokio::test]
async fn h3_slow_consumer_does_not_stall_upload() {
    ensure_crypto_provider();
    let spec = MockSpec {
        get_bytes: 0,
        post_bytes: SLOW_DOWNLOAD_BYTES,
        chunk: CHUNK,
        delay: Duration::ZERO,
    };

    // 轮 1：快消费基线。
    let fast = start_mock("h3-s4a-slow-consumer-fast.test", spec).await;
    let mut conn =
        dial_h3_stream_one(wrap_xmux_client(fast.h3.clone()), fast.base_uri.clone(), String::new())
            .await
            .expect("dial_h3_stream_one (fast)");
    {
        let reader = &mut conn.reader;
        let writer = &mut conn.writer;
        let (up, down) = tokio::join!(
            pump_upload(writer, UPLOAD_BYTES),
            pump_download(reader, Some(SLOW_DOWNLOAD_BYTES), None),
        );
        report("h3/slow-consumer[fast]", &up, &down, &fast.counters);
        assert_eq!(up.bytes, UPLOAD_BYTES as u64, "基线轮上行应写满");
        assert_eq!(down.bytes, SLOW_DOWNLOAD_BYTES, "基线轮下行应读满");
        drop(conn);
    }
    fast.task.abort();

    // 轮 2：慢消费（下行每读一块停 5 ms ⇒ 下行方向持续背压）。
    let slow = start_mock("h3-s4b-slow-consumer-slow.test", spec).await;
    let mut conn =
        dial_h3_stream_one(wrap_xmux_client(slow.h3.clone()), slow.base_uri.clone(), String::new())
            .await
            .expect("dial_h3_stream_one (slow)");
    let (up_slow, down_slow) = {
        let reader = &mut conn.reader;
        let writer = &mut conn.writer;
        tokio::join!(
            pump_upload(writer, UPLOAD_BYTES),
            pump_download(reader, Some(SLOW_DOWNLOAD_BYTES), Some(SLOW_READ_DELAY)),
        )
    };
    let server_got = wait_for_recv_bytes(&slow.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    report("h3/slow-consumer[slow]", &up_slow, &down_slow, &slow.counters);

    assert_eq!(up_slow.bytes, UPLOAD_BYTES as u64, "慢消费轮上行仍应写满");
    assert_eq!(
        server_got, UPLOAD_BYTES as u64,
        "慢消费轮服务端应收满上行字节（下行背压不得拖死上行）"
    );
    assert!(windows_overlap(&up_slow, &down_slow), "慢消费轮上下行时间窗必须重叠");
    slow.task.abort();
}
