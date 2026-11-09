//! httpupgrade inbound：accept 循环**不被单条坏连接独占**的实测探针（E1）。
//!
//! 场景（对齐 argo 明文 httpupgrade 入站 39010/39012/39013 的真实流量形态）：
//!   1. 客户端 A 连上后**不发任何字节**（扫描器 / 半开连接形态）；
//!   2. 客户端 B 立刻连上并完成完整 HTTP Upgrade 握手；
//!   3. 测 B 从 connect 到握手完成的耗时，以及 A 被服务端持有的时长。
//!
//! 走**生产同款 accept 循环**：`register_listener()` → `listener_registry::listen_tcp()`
//! ⇒ 命中 `xray-transport-httpupgrade/src/register.rs::listen_httpupgrade`（循环内只
//! accept，PROXY/TLS/upgrade 全在 spawn 出的每连接任务里，bd 0wvne）。
//!
//! 判定契约（修复后，禁放宽）：
//!   - 坏连接在场时好连接 < 500ms 完成          ⇒ ✅ accept 循环未被独占
//!   - 坏连接仍在有界窗内被清理（不泄漏不无界）  ⇒ ✅ 单连接仍受 4s 窗约束
//!
//! 修复前实测（同一探针，bd 0wvne）：好连接 3696ms（明文）/ 3704ms（TLS），
//! PROXY 档（明文与 TLS 两档）6s 内永不被 accept（无界）。
//!
//! 复现：`cargo test --release -p xray-transport-httpupgrade --test inbound_accept_blocking --
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

// ---- 堆增量测量：本文件是独立测试二进制，自带计数 allocator（只用 std）----
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

/// 当前在用堆字节（alloc − free），用于诊断用例内的增量测量。
fn heap_in_use() -> usize {
    ALLOCATED.load(Ordering::Relaxed).saturating_sub(FREED.load(Ordering::Relaxed))
}

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    listener_registry::{ConnHandler, listen_tcp},
    proxy_protocol::build_proxy_header,
    sockopt::SocketOptions,
};
use xray_transport_httpupgrade::register::register_listener;

/// 判据 2（好连接端到端上界）。
const FAST_LIMIT: Duration = Duration::from_millis(500);
/// 判据 1（accept 循环零阻塞：坏连接在场时新连接必须在 50ms 内能被 accept）。
const ACCEPT_LIMIT: Duration = Duration::from_millis(50);
/// 两段式超时的首字节窗（`xray_transport::handshake_gate::FIRST_BYTE_TIMEOUT`）。
const FIRST_BYTE_WINDOW: Duration = Duration::from_secs(1);
/// 坏连接被服务端接受后的让位时间（确保服务端先取到坏连接，再放好连接进 backlog）。
const ACCEPT_SETTLE: Duration = Duration::from_millis(300);
/// 坏连接被清理的上界：首字节窗 1s + loopback 抖动（早于 4s 合并窗 ⇒ 探测流量清得更快）。
const BAD_RELEASE_LIMIT: Duration = Duration::from_millis(2000);

/// 服务端 TLS 配置（自签 + ALPN=http/1.1）。
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

/// 起一个 httpupgrade listener（走生产同款注册表入口 → `listen_httpupgrade`）。
async fn start_hu_listener(
    security: &str,
    transport_json: Option<serde_json::Value>,
) -> SocketAddr {
    let _ = register_listener();
    let security_json = if security == "tls" { Some(tls_server_json()) } else { None };
    let settings = StreamSettings {
        protocol: "httpupgrade".into(),
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
    .expect("httpupgrade listener starts");
    // listener 句柄 Drop 会触发 close（register.rs Drop impl / v7nqa）取消 accept
    // task——探针需监听存活到用例结束，forget 之（进程退出即回收）。
    let addr = listener.local_addr().expect("httpupgrade local_addr");
    std::mem::forget(listener);
    addr
}

/// HTTP Upgrade 请求字节（裸 HTTP/1.1，与 `build_upgrade_request` 的关键头同形）。
const UPGRADE_REQ: &[u8] =
    b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

/// 坏连接：只连不写（服务端卡在握手读上，直到超时才释放）。
async fn open_bad_conn(addr: SocketAddr) -> TcpStream {
    let sock = TcpStream::connect(addr).await.expect("bad conn connect");
    // 让服务端先把这条连接取走（accept 顺序 = 建连顺序），好连接随后才进 backlog。
    tokio::time::sleep(ACCEPT_SETTLE).await;
    sock
}

/// 服务端释放坏连接的时刻（读到 EOF / RST 为止）。
#[allow(clippy::disallowed_methods, reason = "测试：实测服务端持有时长（探针需要墙钟）")]
async fn wait_released(mut sock: TcpStream, opened_at: std::time::Instant) -> Duration {
    let mut buf = [0u8; 1];
    // 服务端超时丢弃连接 → 本端读回 EOF / RST。持有时长从坏连接建连起算
    // （good 握手先跑完时释放事件已发生 ⇒ 从调用时刻起算会得 ≈0）。
    let _ = sock.read(&mut buf).await;
    opened_at.elapsed()
}

/// httpupgrade 客户端握手（明文或 TLS；可选 PROXY protocol 前缀）。
///
/// 返回从 connect 到握手完成的耗时。
#[allow(clippy::disallowed_methods, reason = "测试：实测握手耗时（探针需要墙钟）")]
async fn hu_handshake(addr: SocketAddr, tls: bool, proxy: bool) -> Result<Duration, String> {
    let t0 = std::time::Instant::now();
    let mut tcp = TcpStream::connect(addr).await.map_err(|e| format!("connect: {e}"))?;
    // PROXY protocol 头在裸 TCP 上（TLS 之前）——服务端 RawUpgradeConn::into_transport 先读它。
    if proxy {
        let header = build_proxy_header(1, "127.0.0.1:12345".parse().expect("src addr"), addr);
        tcp.write_all(&header).await.map_err(|e| format!("proxy header: {e}"))?;
        tcp.flush().await.map_err(|e| format!("proxy flush: {e}"))?;
    }
    if tls {
        let connector = tokio_rustls::TlsConnector::from(tls_client_cfg());
        let sni = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|e| format!("server name: {e}"))?;
        let mut stream = connector.connect(sni, tcp).await.map_err(|e| format!("tls: {e}"))?;
        stream.write_all(UPGRADE_REQ).await.map_err(|e| format!("write: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;
        let resp = read_http_head(&mut stream).await.map_err(|e| format!("read: {e}"))?;
        if !resp.starts_with("HTTP/1.1 101") {
            return Err(format!("upgrade rejected: {}", resp.lines().next().unwrap_or("")));
        }
    } else {
        tcp.write_all(UPGRADE_REQ).await.map_err(|e| format!("write: {e}"))?;
        tcp.flush().await.map_err(|e| format!("flush: {e}"))?;
        let resp = read_http_head(&mut tcp).await.map_err(|e| format!("read: {e}"))?;
        if !resp.starts_with("HTTP/1.1 101") {
            return Err(format!("upgrade rejected: {}", resp.lines().next().unwrap_or("")));
        }
    }
    Ok(t0.elapsed())
}

/// 读到 HTTP 响应头结束（`\r\n\r\n`）为止。
async fn read_http_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before \\r\\n\\r\\n",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// 单条用例结果。
struct Probe {
    good: Option<Duration>,
    baseline: Duration,
    bad_hold: Option<Duration>,
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

/// httpupgrade 明文（security=none）：坏连接只连不写 ⇒ 好连接仍须 <500ms 完成。
///
/// 命中面：argo 明文 httpupgrade 39010/39012/39013。
/// 修复前实测：好连接 3696ms（独占一个 4s 合并窗）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn httpupgrade_plaintext_bad_connection_does_not_block_accept_loop() {
    let addr = start_hu_listener("none", Some(serde_json::json!({"path": "/ws"}))).await;

    let baseline = hu_handshake(addr, false, false).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = hu_handshake(addr, false, false).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("httpupgrade 明文（security=none）", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "坏连接应在 {:?} 内被清理（4s 合并窗），实测 {:?}",
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

/// httpupgrade + TLS：坏连接只连不写 ⇒ 好连接仍须 <500ms 完成。
///
/// 命中面：2087/8443/39000。
/// 修复前实测：好连接 3704ms（独占 4s 合并窗）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn httpupgrade_tls_bad_connection_does_not_block_accept_loop() {
    let addr = start_hu_listener("tls", Some(serde_json::json!({"path": "/ws"}))).await;

    let baseline = hu_handshake(addr, true, false).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = hu_handshake(addr, true, false).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("httpupgrade + TLS", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
        good,
        baseline
    );
    assert!(
        bad_hold <= BAD_RELEASE_LIMIT,
        "坏连接应在 {:?} 内被清理（4s 合并窗），实测 {:?}",
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

/// httpupgrade + PROXY protocol：坏连接不发 PROXY 头 ⇒ 有界（4s 窗内），好连接不受影响。
///
/// 修复前实测：**无界**——PROXY 解析在 accept 循环内、握手窗之外（连 TLS 都没护栏），
/// 好连接 6s 观察上限内永不被 accept。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn httpupgrade_plaintext_proxy_protocol_does_not_block_accept_loop() {
    let addr = start_hu_listener(
        "none",
        Some(serde_json::json!({"path": "/ws", "acceptProxyProtocol": true})),
    )
    .await;

    let baseline = hu_handshake(addr, false, true).await.expect("baseline handshake");

    // 坏连接只连不发 PROXY 头 ⇒ 服务端卡在读 PROXY 头（4s 窗后丢弃）。
    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = hu_handshake(addr, false, true).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("httpupgrade 明文 + PROXY protocol", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
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

/// httpupgrade + TLS + PROXY protocol：坏连接不发 PROXY 头 ⇒ 有界，好连接不受影响。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn httpupgrade_tls_proxy_protocol_does_not_block_accept_loop() {
    let addr = start_hu_listener(
        "tls",
        Some(serde_json::json!({"path": "/ws", "acceptProxyProtocol": true})),
    )
    .await;

    let baseline = hu_handshake(addr, true, true).await.expect("baseline handshake");

    let bad_t0 = std::time::Instant::now();
    let bad = open_bad_conn(addr).await;
    let good = hu_handshake(addr, true, true).await;
    let bad_hold = wait_released(bad, bad_t0).await;

    let good = good.expect("good handshake must succeed");
    let probe = Probe {
        good: Some(good),
        baseline,
        bad_hold: Some(bad_hold),
        verdict: judge(baseline, good),
    };
    report("httpupgrade + TLS + PROXY protocol", &probe);

    assert!(
        good < ACCEPT_LIMIT,
        "坏连接在场时好连接应 <{:?} 完成，实测 {:?} / 基线 {:?}",
        ACCEPT_LIMIT,
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

/// 单连接「握手期在途」堆成本诊断：逐 8 条连接测堆增量斜率（临时证据用例）。
///
/// httpupgrade 明文档在首字节窗（peek）即挂起——**不含 tungstenite/rustls 状态**，
/// 对照 ws 档的斜率即可拆出「tokio 任务 + 握手闸 + 首字节等待」与「ws 握手库内部
/// 缓冲」各自占比（bd 0wvne 55KiB/conn 构成说明）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn httpupgrade_per_conn_handshake_heap_slope() {
    let addr = start_hu_listener("none", Some(serde_json::json!({"path": "/ws"}))).await;
    hu_handshake(addr, false, false).await.expect("warm handshake");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let h0 = heap_in_use();
    let mut conns = Vec::new();
    for i in 1..=64 {
        conns.push(TcpStream::connect(addr).await.expect("conn"));
        if i % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let d = heap_in_use().saturating_sub(h0);
            println!("[diag] conns={i} heap_delta={}KiB per_conn={}B", d / 1024, d / i);
        }
    }
    drop(conns);
    tokio::time::sleep(FIRST_BYTE_WINDOW + Duration::from_millis(300)).await;
}
