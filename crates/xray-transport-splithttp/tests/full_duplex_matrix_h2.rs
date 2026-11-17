//! 切片 C / Q3：H2 持续全双工矩阵（GitHub issue #22 疑问 3）。
//!
//! 背景：现有 splithttp 集成测试的读写流程是**串行**的（先写后读 / 先读后写），
//! 不能证明「持续全双工」行为。本文件按四场景矩阵补测，并把**方向吞吐**与
//! **背压等待次数**作为可复现的观测量记录下来。
//!
//! | 场景 | 客户端模式 | 断言目标 |
//! |---|---|---|
//! | upload-only | stream-up（POST 上行 + 独立 GET 下行） | 下行读端全程不消费（制造下行背压）时，上行仍能写满并被服务端收满 |
//! | download-only | stream-up | 下行读满服务端下发字节（读到 EOF），方向吞吐可测 |
//! | 并发 upload+download | stream-one（同一 HTTP/2 stream 收发） | 上下行时间窗重叠（真并发，非先上传完再下载） |
//! | slow consumer | stream-one | 下行消费者刻意慢读时，上行字节仍全部送达（方向不耦合） |
//!
//! 观测点：
//! - **方向吞吐**：上/下行各自字节数 + 耗时（MiB/s）。
//! - **背压等待**：上传 `write_all` / 下行 `read` 被 poll 返回 `Pending` 的次数 （=
//!   该方向在传输层等窗口 / 等管道空位的次数）。
//! - **服务端侧交错**：服务端收到上行最后一字节的时刻 vs 服务端下发下行最后一字节的
//!   时刻——两者交错即证明服务端视角下双向同时在跑。
//!
//! 结论边界（明示局限）：本文件结论**只覆盖被测 mock 传输**（hyper `http2` server +
//! 本仓客户端），未覆盖真实对端（CDN/浏览器）。h2 流级/连接级 `WINDOW_UPDATE` 事件
//! **无埋点**——窗口背压只能由「该方向 pending 计数 + 服务端下发停滞」间接证明，
//! 不能精确归因到具体窗口事件。

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

use bytes::Bytes;
use futures_util::TryStreamExt as _;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    server::conn::http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use xray_transport_splithttp::{
    client::{DefaultDialerClient, DialTarget},
    config::Config,
    dialer::{build_request_url, dial_stream_one, dial_stream_up},
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
/// upload-only 场景服务端下推字节数（48 MiB > 客户端 32 MiB 收窗 ⇒ 下行必然背压）。
const UPLOAD_ONLY_DOWNLOAD_BYTES: u64 = 48 * 1024 * 1024;
/// slow consumer 场景下行字节数（40 MiB > 客户端 32 MiB 收窗 ⇒ 下行必然背压）。
const SLOW_DOWNLOAD_BYTES: u64 = 40 * 1024 * 1024;
/// slow consumer 每读一块的间隔。
const SLOW_READ_DELAY: Duration = Duration::from_millis(5);
/// 单次方向操作的超时上限（背压真发生时也不应超过）。
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
    /// 传输字节数。
    bytes: u64,
    /// 该方向耗时。
    elapsed: Duration,
    /// 该方向被 poll 返回 `Pending` 的次数（背压等待观测点）。
    pending_polls: u64,
    /// 方向起始时刻（与 `end` 一起给出时间窗，用于证明重叠）。
    start: Option<Instant>,
    /// 方向结束时刻。
    end: Option<Instant>,
}

impl DirMetrics {
    /// 方向吞吐（MiB/s）。
    fn mib_per_sec(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.bytes as f64 / (1024.0 * 1024.0) / self.elapsed.as_secs_f64()
    }
}

/// 上行泵：写满 `total` 字节，计量字节数 / 耗时 / 背压等待次数。
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

/// 下行泵：读满 `total` 字节（`None` = 读到 EOF），计量字节数 / 耗时 / 背压等待次数。
///
/// `slow` = 每读一块后的额外停顿（慢消费者）。
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
            // EOF
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

// ===== mock H2 server =====

/// mock server 的服务端侧观测点。
#[derive(Default)]
struct ServerCounters {
    /// 服务端收到的上行字节数。
    recv_bytes: AtomicU64,
    /// 服务端收到的上行请求数。
    recv_count: AtomicU64,
    /// 服务端下发到下行的字节数。
    sent_bytes: AtomicU64,
    /// 服务端收到上行最后一字节的时刻。
    recv_last_at: std::sync::Mutex<Option<Instant>>,
    /// 服务端收到上行**第一**字节的时刻（服务端视角的双向重叠判据）。
    recv_first_at: std::sync::Mutex<Option<Instant>>,
    /// 服务端下发下行最后一字节的时刻。
    sent_last_at: std::sync::Mutex<Option<Instant>>,
}

/// mock server 行为配置。
#[derive(Clone, Copy)]
struct MockSpec {
    /// GET 响应体下发字节数（stream-up 的下行）。
    get_bytes: u64,
    /// POST 响应体下发字节数（stream-one 的下行）。
    post_bytes: u64,
    /// 每块字节数。
    chunk: usize,
    /// 每块之间的间隔（`Duration::ZERO` = 不限速）。
    delay: Duration,
}

/// 下行载荷体：按块下发 `total` 字节（可限速）。
fn download_body(
    total: u64,
    chunk: usize,
    delay: Duration,
    counters: Arc<ServerCounters>,
) -> BoxBody<Bytes, std::convert::Infallible> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(8);
    tokio::spawn(async move {
        let mut sent = 0u64;
        while sent < total {
            let n = chunk.min((total - sent) as usize);
            let buf = Bytes::from(vec![b'd'; n]);
            if tx.send(Ok(buf)).await.is_err() {
                return;
            }
            sent += n as u64;
            counters.sent_bytes.fetch_add(n as u64, Ordering::Relaxed);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        *counters.sent_last_at.lock().unwrap() = Some(Instant::now());
    });
    StreamBody::new(ReceiverStream::new(rx).map_ok(Frame::data)).boxed()
}

/// 后台计量上行请求体字节数（同时记录最后一字节到达时刻）。
fn spawn_body_counter(body: Incoming, counters: Arc<ServerCounters>) {
    tokio::spawn(async move {
        let mut body = body;
        let mut first = true;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { break };
            if let Ok(data) = frame.into_data() {
                let n = data.len() as u64;
                counters.recv_bytes.fetch_add(n, Ordering::Relaxed);
                // 每块记录到达时刻（用于与下行下发时刻比对 ⇒ 服务端视角的双向交错）。
                let now = Instant::now();
                *counters.recv_last_at.lock().unwrap() = Some(now);
                if first {
                    *counters.recv_first_at.lock().unwrap() = Some(now);
                    first = false;
                }
            }
        }
        counters.recv_count.fetch_add(1, Ordering::Relaxed);
    });
}

/// mock H2 splithttp server：GET → 下行载荷；POST → 计量上行 + 下行载荷（响应体）。
async fn mock_h2_server(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    spec: MockSpec,
    counters: Arc<ServerCounters>,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            break;
        };
        let tls_acceptor = tls_acceptor.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            let Ok(tls) = tls_acceptor.accept(tcp).await else {
                return;
            };
            let io = TokioIo::new(tls);
            let svc = service_fn(move |req: Request<Incoming>| {
                let counters = counters.clone();
                async move {
                    let resp = match *req.method() {
                        Method::GET => Response::builder()
                            .status(StatusCode::OK)
                            .body(download_body(
                                spec.get_bytes,
                                spec.chunk,
                                spec.delay,
                                counters.clone(),
                            ))
                            .unwrap(),
                        Method::POST => {
                            let (_, body) = req.into_parts();
                            // 上行计量独立任务：响应头先回（客户端不等上行结束），
                            // 上行 body 由后台任务持续消费。
                            spawn_body_counter(body, counters.clone());
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(download_body(
                                    spec.post_bytes,
                                    spec.chunk,
                                    spec.delay,
                                    counters.clone(),
                                ))
                                .unwrap()
                        },
                        _ => Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Full::new(Bytes::new()).boxed())
                            .unwrap(),
                    };
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            let _ = http2::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
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

/// 自签证书（SAN = 127.0.0.1）。
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

/// 服务端 TLS（ALPN = h2）。
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

/// 客户端 TLS（信任自签证书）。
fn make_client_tls(cert: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add cert");
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// 一套 mock server + 客户端（每个场景/每轮独立 ⇒ 计数互不污染）。
struct H2Mock {
    client: Arc<DefaultDialerClient>,
    base_uri: String,
    counters: Arc<ServerCounters>,
    task: tokio::task::JoinHandle<()>,
}

/// 起一套 mock H2 server + 对应客户端。
async fn start_mock(spec: MockSpec) -> H2Mock {
    let (cert, key) = make_self_signed_cert();
    let tls_acceptor = TlsAcceptor::from(Arc::new(make_server_tls(cert.clone(), key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counters = Arc::new(ServerCounters::default());
    let task = tokio::spawn(mock_h2_server(listener, tls_acceptor, spec, counters.clone()));

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let client = Arc::new(DefaultDialerClient::new(
        config,
        make_client_tls(cert),
        DialTarget {
            host: addr.ip().to_string(),
            port: addr.port(),
            sni: String::new(),
            sockopt: Default::default(),
        },
        None,
        None,
        None,
    ));
    H2Mock { client, base_uri, counters, task }
}

/// 等服务端收满上行字节（返回实际收到字节数）。
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

/// 打印本场景的方向指标（可复现证据）。
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

// ===== 场景 1：upload-only（下行读端全程不消费） =====

/// upload-only：服务端持续下推（客户端不读 ⇒ 下行方向处于背压），上行仍须写满并被收满。
#[tokio::test]
async fn h2_upload_only_survives_unread_download() {
    ensure_crypto_provider();
    let mock = start_mock(MockSpec {
        get_bytes: UPLOAD_ONLY_DOWNLOAD_BYTES,
        post_bytes: 0,
        chunk: CHUNK,
        delay: Duration::ZERO,
    })
    .await;

    let mut conn = dial_stream_up(
        wrap_xmux_client(mock.client.clone()),
        None,
        mock.base_uri.clone(),
        uuid::Uuid::new_v4().to_string(),
    )
    .await
    .expect("dial_stream_up");

    // 上行写满；下行读端全程不消费 ⇒ 下行方向存在背压。
    let up = pump_upload(&mut conn.writer, UPLOAD_BYTES).await;
    let server_got = wait_for_recv_bytes(&mock.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    let down = DirMetrics::default();
    report("h2/upload-only", &up, &down, &mock.counters);

    assert_eq!(up.bytes, UPLOAD_BYTES as u64, "上行应写满");
    assert_eq!(server_got, UPLOAD_BYTES as u64, "服务端应收满上行字节（下行背压不得拖死上行）");
    assert!(
        mock.counters.sent_bytes.load(Ordering::Relaxed) > 0,
        "服务端应已下推下行字节（证明下行方向确实在制造背压）"
    );
    mock.task.abort();
}

// ===== 场景 2：download-only =====

/// download-only：服务端持续下发，客户端持续读到 EOF。
#[tokio::test]
async fn h2_download_only_transfers_full_payload() {
    ensure_crypto_provider();
    let mock = start_mock(MockSpec {
        get_bytes: DOWNLOAD_ONLY_BYTES,
        post_bytes: 0,
        chunk: CHUNK,
        delay: Duration::ZERO,
    })
    .await;

    let mut conn = dial_stream_up(
        wrap_xmux_client(mock.client.clone()),
        None,
        mock.base_uri.clone(),
        uuid::Uuid::new_v4().to_string(),
    )
    .await
    .expect("dial_stream_up");

    // 上行不写数据（download-only），下行读到 EOF。
    let down = pump_download(&mut conn.reader, None, None).await;
    let up = DirMetrics::default();
    report("h2/download-only", &up, &down, &mock.counters);

    assert_eq!(down.bytes, DOWNLOAD_ONLY_BYTES, "下行应读满服务端下发字节");
    assert!(down.mib_per_sec() > 0.0, "下行吞吐应可测（实测 {:.2} MiB/s）", down.mib_per_sec());
    mock.task.abort();
}

// ===== 场景 3：并发 upload + download（同一 stream） =====

/// 并发 upload+download：同一 HTTP/2 stream 上同时收发（时间窗必须重叠）。
#[tokio::test]
async fn h2_concurrent_upload_and_download_overlap() {
    ensure_crypto_provider();
    let mock = start_mock(MockSpec {
        get_bytes: 0,
        post_bytes: CONCURRENT_DOWNLOAD_BYTES,
        chunk: CHUNK,
        delay: Duration::ZERO,
    })
    .await;

    let mut conn = dial_stream_one(
        wrap_xmux_client(mock.client.clone()),
        mock.base_uri.clone(),
        String::new(),
    )
    .await
    .expect("dial_stream_one");

    // 同一连接上同时跑上行与下行（join! = 两个方向同时在途）。
    let reader = &mut conn.reader;
    let writer = &mut conn.writer;
    let (up, down) = tokio::join!(
        pump_upload(writer, UPLOAD_BYTES),
        pump_download(reader, Some(CONCURRENT_DOWNLOAD_BYTES), None),
    );
    let server_got = wait_for_recv_bytes(&mock.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    report("h2/concurrent", &up, &down, &mock.counters);

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

// ===== 场景 4：慢消费消费者（方向耦合检查） =====

/// slow consumer：下行消费者刻意慢读时，上行仍须写满并被服务端收满。
///
/// 同测试内跑两轮（快消费基线 + 慢消费），两轮各自一套 mock server（计数互不污染），
/// 对比上行吞吐 ⇒ 直接回答「下行背压是否串扰上行方向」。
#[tokio::test]
async fn h2_slow_consumer_does_not_stall_upload() {
    ensure_crypto_provider();
    let spec = MockSpec {
        get_bytes: 0,
        post_bytes: SLOW_DOWNLOAD_BYTES,
        chunk: CHUNK,
        delay: Duration::ZERO,
    };

    // 轮 1：快消费基线。
    let fast = start_mock(spec).await;
    let mut conn = dial_stream_one(
        wrap_xmux_client(fast.client.clone()),
        fast.base_uri.clone(),
        String::new(),
    )
    .await
    .expect("dial_stream_one (fast)");
    {
        let reader = &mut conn.reader;
        let writer = &mut conn.writer;
        let (up, down) = tokio::join!(
            pump_upload(writer, UPLOAD_BYTES),
            pump_download(reader, Some(SLOW_DOWNLOAD_BYTES), None),
        );
        report("h2/slow-consumer[fast]", &up, &down, &fast.counters);
        assert_eq!(up.bytes, UPLOAD_BYTES as u64, "基线轮上行应写满");
        assert_eq!(down.bytes, SLOW_DOWNLOAD_BYTES, "基线轮下行应读满");
        drop(conn);
    }
    fast.task.abort();

    // 轮 2：慢消费（下行每读一块停 5 ms ⇒ 下行方向持续背压）。
    let slow = start_mock(spec).await;
    let mut conn = dial_stream_one(
        wrap_xmux_client(slow.client.clone()),
        slow.base_uri.clone(),
        String::new(),
    )
    .await
    .expect("dial_stream_one (slow)");
    let (up_slow, down_slow) = {
        let reader = &mut conn.reader;
        let writer = &mut conn.writer;
        tokio::join!(
            pump_upload(writer, UPLOAD_BYTES),
            pump_download(reader, Some(SLOW_DOWNLOAD_BYTES), Some(SLOW_READ_DELAY)),
        )
    };
    let server_got = wait_for_recv_bytes(&slow.counters, UPLOAD_BYTES as u64, OP_TIMEOUT).await;
    report("h2/slow-consumer[slow]", &up_slow, &down_slow, &slow.counters);

    assert_eq!(up_slow.bytes, UPLOAD_BYTES as u64, "慢消费轮上行仍应写满");
    assert_eq!(
        server_got, UPLOAD_BYTES as u64,
        "慢消费轮服务端应收满上行字节（下行背压不得拖死上行）"
    );
    assert!(windows_overlap(&up_slow, &down_slow), "慢消费轮上下行时间窗必须重叠");
    slow.task.abort();
}
