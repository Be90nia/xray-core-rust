//! 审计探针（audit-2026-11-06 / reviewer）—— **u0pe2 反转后形态**。
//!
//! # 本文件测什么（2026-11-07 反转）
//!
//! 原探针 1 断言「`hot_log!(DEBUG, "error=…")` 在生产默认 `warn` 门下**不可见**」
//! ——那是**缺陷指纹**（bd u0pe2 ①：26 处失败留痕在默认 loglevel 下零痕迹）。
//! 修复（xdns DoH / xdns send / PacketIoConn send 等代表功能失效的站点提级为
//! WARN + 限频）落地后，本探针按 PM 验收**反转**为行为断言：
//!
//! > **失败必须在默认 `warn` 门下可见**：同一生产事件在 `LevelFilter::WARN`
//! > 过滤器下捕获 ≥1 行。
//!
//! 三个探针全部走**真实生产路径**（不用 mock 回声、不测源码文本）——生产码若把
//! 留痕改回 DEBUG，对应断言必红（反向自检表见各测试 doc）：
//!
//! | 探针 | 生产路径 | 反向自检（改回 DEBUG 必红的原因） |
//! |---|---|---|
//! | `doh_request_failure_visible_under_default_warn_gate` | `xdns/doh.rs` DoH worker（`endpoint.post` 失败 → WARN 限频） | DEBUG 行被 WARN 门丢弃 ⇒ 捕获 0 行 |
//! | `xdns_send_failure_visible_under_default_warn_gate` | `xdns/client.rs::send_loop`（`send_once` 失败 → WARN 限频） | 同上 |
//! | `packet_io_conn_send_failure_visible_under_default_warn_gate` | `finalmask/mod.rs` PacketIoConn send worker（WARN 限频） | 同上 |
//!
//! 其余提级站点（splithttp dialer/client/h3/batched_upload、xmc/conn 各一次性
//! WARN）与本探针同一修法、同一门语义，判定表见
//! `reports/audit-2026-11-06/impl-u0pe2.md`；splithttp/xmc 的可注入探针面不在
//! 本 crate 依赖方向内，未逐一入探针（残余风险已登记）。
//!
//! # 过滤器语义来源
//!
//! `tracing::level_filters::LevelFilter` 是 `tracing` 自带的等级门，生产
//! `xray-cli/src/run.rs::loglevel_directive`：`loglevel` 未配 ⇒ `EnvFilter::new("warn")`
//! ≙ `LevelFilter::WARN`（只放行 ERROR/WARN；tracing `Level` 序：ERROR=0 < WARN=1
//! < INFO=2 < DEBUG=3 < TRACE=4）。探针 subscriber 的 `enabled` 用同一判定做全局
//! 门——**泵任务跑在 runtime worker 线程，线程局部 `with_default` 捕不到**，故走
//! 进程级 `set_global_default`（`audit_perfmemaudit_probe.rs` 同教训）。
//!
//! # 历史注记
//!
//! 原探针 2（`Err(_) => continue` 紧循环形态复刻）已删除：其回归网早已移至
//! `audit_perfmemaudit_probe.rs::persistent_recv_error_warns_once_and_stops`
//! （真实 `XdnsConnClient` 行为断言），复刻体随生产修复变成无守护对象的过时
//! 重演（旧「Rust 现行形态=continue」注释已失真）。2026-11-07 u0pe2。

#![allow(clippy::print_stdout)] // 取证输出（--nocapture 人眼核对）

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tracing::level_filters::LevelFilter;
use xray_transport::finalmask::{UdpIo, build_udpmask_manager_from_json};

// ===========================================================================
// WARN 门捕获：subscriber 的 enabled 按 LevelFilter::WARN 判（生产默认门同源），
// 泵任务在 runtime worker 线程 ⇒ 进程级 set_global_default（log_single_entry /
// audit_perfmemaudit_probe 同教训）；HotLog 每次 emit 经 dispatch.enabled 现判，
// 无 callsite 兴趣缓存陷阱。
// ===========================================================================

type Events = Arc<Mutex<Vec<(String, String, String)>>>; // (level, target, message)

static EVENTS: LazyLock<Events> = LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));
static CAPTURE_INSTALL: LazyLock<()> = LazyLock::new(|| {
    let _ = tracing::subscriber::set_global_default(CaptureSubscriber(Arc::clone(&EVENTS)));
});

struct CaptureSubscriber(Events);

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        // 生产默认（loglevel 未配 ⇒ "warn"，xray-cli run.rs）：只放行 ERROR/WARN。
        *meta.level() <= LevelFilter::WARN
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Fmt(String);
        impl tracing::field::Visit for Fmt {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.push_str(&format!("{}={value} ", field.name()));
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut v = Fmt(String::new());
        event.record(&mut v);
        self.0.lock().expect("events poisoned").push((
            event.metadata().level().to_string(),
            event.metadata().target().to_string(),
            v.0,
        ));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// 幂等安装捕获订阅器（多测试并发：败者拿 Err，同一订阅器无影响）。
fn install_capture() {
    LazyLock::force(&CAPTURE_INSTALL);
}

/// 统计含指定消息片段的 WARN 事件数（默认 warn 门下的失败可见性判据）。
fn warn_count(message_needle: &str) -> usize {
    EVENTS
        .lock()
        .expect("events poisoned")
        .iter()
        .filter(|(lvl, _tgt, msg)| lvl == "WARN" && msg.contains(message_needle))
        .count()
}

/// 让 spawn 出去的泵任务真正被调度起来（并给失败路径留时间）。
async fn settle(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ===========================================================================
// 探针 1：DoH 请求失败在默认 warn 门下可见（xdns/doh.rs worker WARN 限频）
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_request_failure_visible_under_default_warn_gate() {
    install_capture();

    // 假 DoH 服务端：接受 TCP 后立即断开 ⇒ rustls 握手 EOF ⇒ endpoint.post
    // 快速失败（连接拒绝路径在本机 WSL/Hyper-V 网络栈下 SYN 可能被静默丢弃，
    // 不可确定性；EOF 握手失败同为 Go `do err` 错误族，等价代表）。
    let killer = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let killer_addr = killer.local_addr().expect("local_addr");
    #[allow(
        clippy::disallowed_methods,
        reason = "探针本地假服务端（进程内 helper 任务），寿命随本测试，句柄显式 abort"
    )]
    let killer_task = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = killer.accept().await else { break };
            drop(sock); // 立即断开 ⇒ 客户端 TLS 握手 EOF
        }
    });

    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                // 指向握手必败的假端点：POST 必失败 ⇒ worker WARN（首条限频放行）
                "resolvers": [{ "addrs": [format!("https://{killer_addr}/dns-query")] }]
            }
        }]
    })))
    .expect("xdns DoH manager 必须可构造");

    let inner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let wrapped = mgr.wrap_packet_conn_client(Box::new(inner)).expect("wrap 必须成功");

    // 一条真实上行包：write_tx → send_loop → send_once → send_msg → DoH worker
    // → endpoint.post（TLS EOF）→ WARN。
    wrapped
        .send_to(&[0xC0, 0x01, b'A'], "127.0.0.1:53".parse::<SocketAddr>().unwrap())
        .await
        .expect("send");

    settle(2000).await;
    let hits = warn_count("xdns: DoH request failed");
    println!("[探针1-DoH] warn 门下捕获 'xdns: DoH request failed' 行数 = {hits}");

    drop(wrapped);
    killer_task.abort();
    settle(200).await;

    assert!(
        hits >= 1,
        "u0pe2 反转断言：DoH 请求失败必须在生产默认 warn 门下捕获 ≥1 行 \
         （若生产码把该留痕改回 DEBUG ⇒ 被 WARN 门丢弃 ⇒ hits=0 本断言红）"
    );
}

// ===========================================================================
// 探针 2：DNS 查询发送失败在默认 warn 门下可见（xdns/client.rs send_loop WARN）
// ===========================================================================

/// 发送恒失败的内层 `UdpIo`（recv 永挂 = 不干扰泵）。
struct SendErrInner {
    sends: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UdpIo for SendErrInner {
    async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("probe: send refused"))
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_send_failure_visible_under_default_warn_gate() {
    install_capture();

    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                "resolvers": [{ "addrs": ["127.0.0.1:53"] }]
            }
        }]
    })))
    .expect("xdns manager 必须可构造");

    let inner = SendErrInner { sends: Arc::new(AtomicUsize::new(0)) };
    let wrapped = mgr.wrap_packet_conn_client(Box::new(inner)).expect("wrap 必须成功");

    // 一条真实上行包：send_loop → send_once → inner.send_to（恒 Err）⇒ WARN。
    wrapped.send_to(&[1, 2, 3], "127.0.0.1:53".parse::<SocketAddr>().unwrap()).await.expect("send");

    settle(800).await;
    let hits = warn_count("xdns client: send failed");
    println!("[探针2-xdns send] warn 门下捕获 'xdns client: send failed' 行数 = {hits}");

    drop(wrapped);
    settle(200).await;

    assert!(
        hits >= 1,
        "u0pe2 反转断言：DNS 查询发送失败（查询发不出去 = DNS 全断）必须在 \
         生产默认 warn 门下捕获 ≥1 行（改回 DEBUG ⇒ hits=0 本断言红）"
    );
}

// ===========================================================================
// 探针 3：PacketIoConn send 失败在默认 warn 门下可见（finalmask send worker WARN）
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_io_conn_send_failure_visible_under_default_warn_gate() {
    install_capture();
    use tokio::io::AsyncWriteExt;
    use xray_transport::finalmask::wrap_packet_conn_client_into_connection;

    let inner = SendErrInner { sends: Arc::new(AtomicUsize::new(0)) };
    let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let conn: Box<dyn xray_transport::connection::Connection> =
        wrap_packet_conn_client_into_connection(Box::new(inner), remote).expect("wrap 必须成功");

    // poll_write 入队即 Ok ⇒ worker 异步 send_to（恒 Err）⇒ WARN（首条限频放行）。
    let mut conn = conn;
    conn.write_all(&[1, 2, 3]).await.expect("poll_write 入队必须成功");

    settle(500).await;
    let hits = warn_count("PacketIoConn send_to failed");
    println!("[探针3-PacketIoConn] warn 门下捕获 'PacketIoConn send_to failed' 行数 = {hits}");

    drop(conn);
    settle(200).await;

    assert!(
        hits >= 1,
        "u0pe2 反转断言：PacketIoConn send 失败必须在生产默认 warn 门下捕获 ≥1 行 \
         （改回 DEBUG ⇒ hits=0 本断言红）"
    );
}
