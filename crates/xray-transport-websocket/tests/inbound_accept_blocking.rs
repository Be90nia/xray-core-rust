//! ws inbound：accept 循环**不被单条坏连接独占**的实测探针（E1）。
//!
//! 场景（对齐 argo 明文 ws 入站 39007/39009/39011/39016 的真实流量形态）：
//!   1. 客户端 A 连上后**不发任何字节**（扫描器 / 半开连接形态）；
//!   2. 客户端 B 立刻连上并完成完整 WS 握手；
//!   3. 测 B 从 connect 到握手完成的耗时，以及 A 被服务端持有的时长。
//!
//! 走**生产同款 accept 循环**：`register_listener()` → `listener_registry::listen_tcp()`
//! ⇒ 命中 `xray-transport-websocket/src/register.rs::spawn_ws_accept_loop`（循环内
//! 只 accept，握手在 spawn 出的每连接任务里，bd 0wvne）。
//!
//! 判定契约（修复后，禁放宽）：
//!   - 坏连接在场时好连接 < 500ms 完成          ⇒ ✅ accept 循环未被独占
//!   - 坏连接仍在有界窗内被清理（不泄漏不无界）  ⇒ ✅ 单连接仍受 4s/8s 窗约束
//!
//! 修复前实测（同一探针，bd 0wvne）：好连接 3706ms（明文）/ 3708ms（TLS）/
//! 7013ms（慢 TLS 两窗串行），PROXY 档 6s 内永不被 accept（无界）。
//!
//! 复现：`cargo test --release -p xray-transport-websocket --test inbound_accept_blocking --
//! --nocapture --test-threads=1`

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::disallowed_methods,
    reason = "测试：打印实测数据 + 探针必须取墙钟（测服务端持有时长/握手耗时）"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    handshake_gate::MAX_INFLIGHT_HANDSHAKES,
    listener_registry::{ConnHandler, listen_tcp},
    proxy_protocol::build_proxy_header,
    sockopt::SocketOptions,
};
use xray_transport_websocket::register::register_listener;

// ---- 堆增量测量：本文件是独立测试二进制，可自带计数 allocator（只用 std）----
// 只用于「256 并发坏连接」用例的前后差值；不为测量引入任何依赖。

/// 转发到 `System` 的计数 allocator（alloc/dealloc 累计字节数）。
struct CountingAlloc;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: 纯转发 `System`；计数用 Relaxed（只做度量，不参与任何同步语义）。
// `realloc`/`alloc_zeroed` 走 GlobalAlloc 缺省实现（alloc+copy+dealloc），同样被计到。
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 调用方保证 layout 合法（GlobalAlloc 契约）。
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREED.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: ptr/layout 来自本 allocator 的 alloc（GlobalAlloc 契约）。
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// 当前在用堆字节（alloc − free），用于用例内的增量断言。
fn heap_in_use() -> usize {
    ALLOCATED.load(Ordering::Relaxed).saturating_sub(FREED.load(Ordering::Relaxed))
}

/// 判据 2（好连接端到端上界）。
const FAST_LIMIT: Duration = Duration::from_millis(500);
/// 判据 1（accept 循环零阻塞：坏连接在场时新连接必须在 50ms 内能被 accept）。
const ACCEPT_LIMIT: Duration = Duration::from_millis(50);
/// 两段式超时的首字节窗（`xray_transport::handshake_gate::FIRST_BYTE_TIMEOUT`）。
const FIRST_BYTE_WINDOW: Duration = Duration::from_secs(1);
/// 坏连接被清理的上界：首字节窗 1s + loopback 抖动（明显早于 4s 握手窗 ⇒ 探测流量
/// 比 Go 单一 4s 头超时清得更快，在途数因此极低）。
const BAD_RELEASE_LIMIT: Duration = Duration::from_millis(2000);
/// 坏连接被服务端接受后的让位时间（确保服务端先取到坏连接，再放好连接进 backlog）。
const ACCEPT_SETTLE: Duration = Duration::from_millis(300);
/// 并发坏连接数（判据 3 证据；< 握手闸上界 512 ⇒ 好连接仍应被接纳）。
const CONCURRENT_BAD: usize = 256;

/// 服务端 TLS 配置（自签 + ALPN=http/1.1）。
///
/// ALPN 必须显式收敛到 http/1.1：ws 服务端在 `accept_tls` 里把协商出 h2 的连接
/// 判为「h2 拒绝服务」直接报错（server.rs:310-315），默认 ALPN 是 [h2, http/1.1]。
fn tls_server_json() -> serde_json::Value {
    let (cert_pem, key_pem) =
        xray_tls::certificate::generate_self_signed_cert(&["localhost"]).expect("self-signed cert");
    serde_json::json!({"cert": cert_pem, "key": key_pem, "alpn": ["http/1.1"]})
}

/// 客户端 TLS 配置（allowInsecure：探针只关心时序，不校验证书链）。
fn tls_client_cfg() -> Arc<tokio_rustls::rustls::ClientConfig> {
    xray_tls::client_config::build_client_config(
        "tls",
        Some(&serde_json::json!({"allowInsecure": true, "alpn": ["http/1.1"]})),
        "localhost",
    )
    .expect("client tls config")
    .expect("tls config present")
}

/// 起一个 ws listener（走生产同款注册表入口 → `spawn_ws_accept_loop`）。
async fn start_ws_listener(
    security: &str,
    transport_json: Option<serde_json::Value>,
) -> SocketAddr {
    let _ = register_listener();
    let security_json = if security == "tls" { Some(tls_server_json()) } else { None };
    let settings = StreamSettings {
        protocol: "ws".into(),
        security: security.into(),
        transport_json,
        security_json,
        ..StreamSettings::default()
    };
    let handler: ConnHandler = Arc::new(|_conn: Box<dyn Connection>| {});
    let listener = listen_tcp(
        "127.0.0.1:0".parse().expect("bind addr"),
        settings,
        SocketOptions::default(),
        handler,
    )
    .await
    .expect("ws listener starts");
    // listener 句柄 Drop 兜底会终止 accept 循环（register.rs Drop impl / v7nqa）——
    // 探针需监听存活到用例结束，forget 之（进程退出即回收）。
    let addr = listener.local_addr().expect("ws local_addr");
    std::mem::forget(listener);
    addr
}

/// 坏连接：只连不写（服务端卡在握手读上，直到超时才释放）。
///
/// 返回连接；调用方持有它直到服务端释放（读到 EOF / RST）。
async fn open_bad_conn(addr: SocketAddr) -> TcpStream {
    let sock = TcpStream::connect(addr).await.expect("bad conn connect");
    // 让服务端先把这条连接取走（accept 顺序 = 建连顺序），好连接随后才进 backlog。
    tokio::time::sleep(ACCEPT_SETTLE).await;
    sock
}

/// 服务端释放坏连接的时刻（读到 EOF / RST 为止）。
///
/// 返回服务端持有该连接的时长。
#[allow(clippy::disallowed_methods, reason = "测试：实测服务端持有时长（探针需要墙钟）")]
async fn wait_released(mut sock: TcpStream, opened_at: std::time::Instant) -> Duration {
    let mut buf = [0u8; 1];
    // 服务端超时丢弃连接 → 本端读回 EOF / RST。持有时长从坏连接建连起算
    // （good 握手先跑完时释放事件已发生 ⇒ 从调用时刻起算会得 ≈0）。
    let _ = sock.read(&mut buf).await;
    opened_at.elapsed()
}

/// ws 客户端握手（明文或 TLS；可选 PROXY protocol 前缀）。
///
/// 返回从 connect 到握手完成的耗时。
#[allow(clippy::disallowed_methods, reason = "测试：实测握手耗时（探针需要墙钟）")]
async fn ws_handshake(addr: SocketAddr, tls: bool, proxy: bool) -> Result<Duration, String> {
    let t0 = std::time::Instant::now();
    let mut tcp = TcpStream::connect(addr).await.map_err(|e| format!("connect: {e}"))?;
    // PROXY protocol 头在裸 TCP 上（TLS 之前）——服务端 accept_conn 先读它。
    if proxy {
        let header = build_proxy_header(1, "127.0.0.1:12345".parse().expect("src addr"), addr);
        tcp.write_all(&header).await.map_err(|e| format!("proxy header: {e}"))?;
        tcp.flush().await.map_err(|e| format!("proxy flush: {e}"))?;
    }
    let req = format!("ws://127.0.0.1:{}/", addr.port())
        .into_client_request()
        .map_err(|e| format!("request: {e}"))?;
    if tls {
        let connector = tokio_rustls::TlsConnector::from(tls_client_cfg());
        let sni = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|e| format!("server name: {e}"))?;
        let stream = connector.connect(sni, tcp).await.map_err(|e| format!("tls: {e}"))?;
        tokio_tungstenite::client_async(req, stream).await.map_err(|e| format!("ws: {e}"))?;
    } else {
        tokio_tungstenite::client_async(req, tcp).await.map_err(|e| format!("ws: {e}"))?;
    }
    Ok(t0.elapsed())
}

/// 单条用例结果。
struct Probe {
    /// 好连接从 connect 到握手完成的耗时。
    good: Option<Duration>,
    /// 好连接基线（无坏连接同时存在）耗时。
    baseline: Duration,
    /// 服务端持有坏连接的时长（None = 观察上限内仍未释放 ⇒ 无界）。
    bad_hold: Option<Duration>,
    /// 结论。
    verdict: String,
}

/// 打印一行结果（报告口径：坏连接占用时长 / 好连接耗时 / 结论）。
fn report(case: &str, p: &Probe) {
    println!(
        "[{case}] baseline={}ms good={}ms bad_hold={} verdict={}",
        p.baseline.as_millis(),
        p.good.map(|d| d.as_millis()).map(|v| v.to_string()).unwrap_or_else(|| "never".into()),
        p.bad_hold.map(|d| d.as_millis()).map(|v| v.to_string()).unwrap_or_else(|| ">cap".into()),
        p.verdict
    );
}

/// 判定：好连接耗时（判据 1 = <50ms；判据 2 = <500ms）。
fn judge(baseline: Duration, good: Duration) -> String {
    let induced = good.saturating_sub(baseline);
    if good < ACCEPT_LIMIT {
        format!(
            "✅ accept 循环零阻塞（好连接 {}ms，增量 {}ms）",
            good.as_millis(),
            induced.as_millis()
        )
    } else if good < FAST_LIMIT {
        format!(
            "⚠️ 未达 <{}ms 判据（好连接 {}ms，增量 {}ms），但 <{}ms",
            ACCEPT_LIMIT.as_millis(),
            good.as_millis(),
            induced.as_millis(),
            FAST_LIMIT.as_millis()
        )
    } else {
        format!("❌ 好连接被延迟 {}ms（≥ {}ms）", induced.as_millis(), FAST_LIMIT.as_millis())
    }
}

/// ws 明文（security=none）：坏连接只连不写 ⇒ 好连接仍须 <500ms 完成。
///
/// 命中面：argo 明文 ws 39007/39009/39011/39016。
/// 修复前实测：好连接 3706ms（独占一个 WS 4s 窗）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_plaintext_bad_connection_does_not_block_accept_loop() {
    let addr = start_ws_listener("none", Some(serde_json::json!({"path": "/"}))).await;

    // 基线：好连接单独跑。
    let baseline = ws_handshake(addr, false, false).await.expect("baseline handshake");

    // 坏连接 + 好连接并发。
    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = ws_handshake(addr, false, false).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("ws 明文（security=none）", &probe);

    // 判据 1/2：accept 循环零阻塞 ⇒ 好连接 50ms 内完成（修复前 3706ms）。
    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );
    // 坏连接仍在有界窗内被清理（首字节窗 2s ⇒ 比 Go 的单一 4s 头超时清得更快）。
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "坏连接应在 {:?} 内被清理（首字节窗 2s），实测 {:?}",
        BAD_RELEASE_LIMIT,
        bad_hold
    );
    assert!(
        bad_hold >= FIRST_BYTE_WINDOW - Duration::from_millis(500),
        "坏连接应在首字节窗（{:?}）到期前保持（不提前误杀真实慢客户端），实测 {:?}",
        FIRST_BYTE_WINDOW,
        bad_hold
    );
}

/// ws + TLS：坏连接只连不写 ⇒ 好连接仍须 <500ms 完成。
///
/// 命中面：443/2083/2096/39003/39004。
/// 修复前实测：好连接 3708ms（独占 TLS 4s 窗）；生产 4528 次/60min accept timeout。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_tls_bad_connection_does_not_block_accept_loop() {
    let addr = start_ws_listener("tls", Some(serde_json::json!({"path": "/"}))).await;

    let baseline = ws_handshake(addr, true, false).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = ws_handshake(addr, true, false).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("ws + TLS", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "坏连接应在 {:?} 内被清理（首字节窗 2s），实测 {:?}",
        BAD_RELEASE_LIMIT,
        bad_hold
    );
    assert!(
        bad_hold >= FIRST_BYTE_WINDOW - Duration::from_millis(500),
        "坏连接应在首字节窗（{:?}）到期前保持，实测 {:?}",
        FIRST_BYTE_WINDOW,
        bad_hold
    );
}

/// 两段式超时：坏连接连上后不发首字节 ⇒ 首字节窗（1s）先到期，连接被清掉，
/// **不必等 4s 协议窗**——比 Go 的单一 4s `ReadHeaderTimeout` 清得更快，且不阻塞
/// accept 循环。
///
/// 修复前实测：同类「慢」连接（3s 后完成 TLS、不发升级）让好连接等 7013ms
/// （TLS 4s 窗 + WS 4s 窗在 accept 循环内串行）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_slow_first_byte_cleared_by_first_byte_window() {
    let addr = start_ws_listener("none", Some(serde_json::json!({"path": "/"}))).await;

    let baseline = ws_handshake(addr, false, false).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = ws_handshake(addr, false, false).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("ws 两段式：沉默坏连接（首字节窗 1s）", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "沉默坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );
    // 首字节窗 2s 到期即清 ⇒ 明显早于 4s 协议窗，且仍有界。
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "沉默坏连接应在首字节窗（{:?}）附近被清理，实测 {:?}",
        FIRST_BYTE_WINDOW,
        bad_hold
    );
}

/// 「裸 socket 双方」基线：256 条连接到只 accept-不握手的哑监听，量出客户端 socket +
/// 服务端 accepted socket 的进程内堆成本（不含任何握手态）。
async fn measure_bare_256() -> usize {
    let dummy = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("dummy bind");
    let dummy_addr = dummy.local_addr().expect("dummy addr");
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        for _ in 0..CONCURRENT_BAD {
            match dummy.accept().await {
                Ok((s, _)) => held.push(s),
                Err(_) => break,
            }
        }
        held
    });
    let h0 = heap_in_use();
    let mut conns = Vec::with_capacity(CONCURRENT_BAD);
    for _ in 0..CONCURRENT_BAD {
        conns.push(TcpStream::connect(dummy_addr).await.expect("dummy connect"));
    }
    let delta = heap_in_use().saturating_sub(h0);
    drop(conns);
    let _ = holder.await;
    delta
}

/// 判据 3（96MB xray 预算）：并发坏连接 × 256 时内存有界、进程不崩、accept 循环不堵。
///
/// 语义（闸上界 `MAX_INFLIGHT_HANDSHAKES = 64`，**fail-fast 不排队**）：
/// - 前 64 条被接纳并各占一个 permit，其余 192 条**立即被丢弃**（对端毫秒级见 FIN）
///   ——这同时是「accept 循环零阻塞」+「fail-fast 不排队」的证据；
/// - 首字节窗 1s 到期 ⇒ 接纳的那批被清理，permit 归还；
/// - 之后好连接毫秒级完成。
///
/// 内存证据 = 进程内堆增量（本文件自带计数 allocator）。注意本用例客户端与服务端
/// 同进程，故先对「哑监听（只 accept 不握手）」量一遍 256 连接的**客户端侧成本**，
/// 再从总量里扣除 ⇒ 得到**服务端握手**的可归因增量（生产上只有这一侧）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_accept_loop_survives_256_bad_connections() {
    // ① 裸 socket 双方基线（无握手态）——用于扣除 256 连接的 socket 固有成本。
    let bare = measure_bare_256().await;

    let addr = start_ws_listener("none", Some(serde_json::json!({"path": "/"}))).await;
    let baseline = ws_handshake(addr, false, false).await.expect("baseline handshake");

    // ② ws 监听：同样 256 条沉默连接（含服务端握手任务与 192 条 fail-fast 丢弃）。
    let heap_before = heap_in_use();
    let mut bad = Vec::with_capacity(CONCURRENT_BAD);
    for _ in 0..CONCURRENT_BAD {
        bad.push(TcpStream::connect(addr).await.expect("bad conn connect"));
    }
    let total_delta = heap_in_use().saturating_sub(heap_before);
    // 扣除裸 socket 基线 ⇒ 握手路径（任务/permit/缓冲）的可归因增量。
    let handshake_extra = total_delta.saturating_sub(bare);

    // ③ accept 循环未堵 + fail-fast：溢出闸的连接必须毫秒级被服务端关闭。
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut closed_fast = 0usize;
    for s in &bad {
        let mut b = [0u8; 1];
        if matches!(s.try_read(&mut b), Ok(0)) {
            closed_fast += 1;
        }
    }
    let overflow = CONCURRENT_BAD.saturating_sub(MAX_INFLIGHT_HANDSHAKES);
    println!(
        "[ws 判据3] bad_conns={CONCURRENT_BAD} closed_fast={closed_fast} (闸上界 {MAX_INFLIGHT_HANDSHAKES} ⇒ 期望 ≥{overflow}) total_delta={}KiB bare_baseline={}KiB handshake_extra={}KiB",
        total_delta / 1024,
        bare / 1024,
        handshake_extra / 1024
    );

    // ② 内存红线：握手路径可归因堆增量 <4MB（`MEMORY-BUDGET-256MB.md` 本轮新增池
    // 硬顶；64 × 实测 55KiB/conn ≈ 3.4MiB，PM 复核后取 64 以容纳真实 burst，
    // 3MB 曾是压测阈值而非预算上限）。
    assert!(
        handshake_extra < 4 * 1024 * 1024,
        "256 并发坏连接的握手路径堆增量应 <4MB，实测 {handshake_extra} 字节（总 {total_delta}，裸 socket 基线 {bare}）"
    );
    // ③ fail-fast 证据：超出闸上界的连接被立即丢弃（不等 1s 首字节窗）。
    assert!(
        closed_fast >= overflow,
        "闸满应 fail-fast：期望 ≥{overflow} 条在 300ms 内被关闭，实测 {closed_fast}"
    );

    // ④ 首字节窗到期 → permit 归还 → 好连接毫秒级完成。
    tokio::time::sleep(FIRST_BYTE_WINDOW + Duration::from_millis(300)).await;
    let good = ws_handshake(addr, false, false).await.expect("good handshake");
    println!(
        "[ws 判据3] 洪峰后 good={}ms baseline={}ms verdict=✅ 进程存活/好连接可用",
        good.as_millis(),
        baseline.as_millis()
    );
    assert!(
        good < ACCEPT_LIMIT,
        "洪峰后好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );

    // ⑤ 全部坏连接最终被清理（无泄漏）。
    let mut released = 0usize;
    for sock in bad {
        let _ = wait_released(sock, std::time::Instant::now()).await;
        released += 1;
    }
    assert_eq!(released, CONCURRENT_BAD, "所有坏连接都应被清理");
}

/// ws 明文 + PROXY protocol：坏连接不发 PROXY 头 ⇒ 有界（PROXY 读 4s 窗），好连接不受影响。
///
/// 命中面：`wsSettings.acceptProxyProtocol=true` 的明文 ws 入站。
/// 修复前实测：**无界**——好连接 6s 观察上限内永不被 accept，坏连接永不被释放
/// （裸 `read_exact` 无超时）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_plaintext_proxy_protocol_does_not_block_accept_loop() {
    let addr = start_ws_listener(
        "none",
        Some(serde_json::json!({"path": "/", "acceptProxyProtocol": true})),
    )
    .await;

    let baseline = ws_handshake(addr, false, true).await.expect("baseline handshake");

    // 坏连接只连不发 PROXY 头 ⇒ 服务端卡在读 PROXY 头（4s 窗后丢弃）。
    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = ws_handshake(addr, false, true).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("ws 明文 + PROXY protocol", &probe);

    assert!(
        good < FAST_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        FAST_LIMIT,
        good,
        baseline
    );
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "PROXY 头读取必须有界：坏连接应在 {:?} 内被清理，实测 {:?}",
        BAD_RELEASE_LIMIT,
        bad_hold
    );
}

/// ws TLS + PROXY protocol：坏连接不发 PROXY 头 ⇒ 好连接仍须 <500ms 完成。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_tls_proxy_protocol_does_not_block_accept_loop() {
    let addr = start_ws_listener(
        "tls",
        Some(serde_json::json!({"path": "/", "acceptProxyProtocol": true})),
    )
    .await;

    let baseline = ws_handshake(addr, true, true).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = ws_handshake(addr, true, true).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("ws + TLS + PROXY protocol", &probe);

    assert!(
        good < FAST_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        FAST_LIMIT,
        good,
        baseline
    );
    // PROXY 头读取在 TLS 4s 窗内 ⇒ 坏连接有界释放。
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "坏连接应在 {:?} 内被清理（4s 窗），实测 {:?}",
        BAD_RELEASE_LIMIT,
        bad_hold
    );
}
