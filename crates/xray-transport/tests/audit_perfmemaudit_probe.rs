//! 审计探针（2026-11-06 perf-memory 轮，PM-01/PM-03 取证；**修复后反转**，bd
//! ar3tf / i86yo 验收）：xdns client 的**资源闭环**与**帧语义**实测。
//!
//! # 被测对象与修复后契约
//!
//! `crates/xray-transport/src/finalmask/xdns/client.rs` 的 `XdnsConnClient`：
//! - 三泵（`recv_loop` / `doh_recv_loop` / `send_loop`）改走 `FxScope::spawn_tracked` 进
//!   JoinSet（server.rs 同款），conn drop ⇒ scope drop ⇒ abort 全组；
//! - `impl Drop`：`closed.store(true)`（Go `Close` 的 close(closeCh) 对应物）；
//! - DoH worker 在 doh.rs 内部 spawn（句柄本层不可达），随 `state` drop ⇒ `DohResolver.tx` drop ⇒
//!   worker `rx.recv()` 返 None **级联退出**；
//! - `recv_loop` 的 recv 错误分支 = closed 短路 + **WARN 留痕 + 退出泵** （对齐 Go
//!   `client.go:308-314`，不再 `Err(_) => continue` 紧循环）；
//! - 帧拆包对 0 长度帧**跳过不投递**（Go `client.go:265-267` 的空条目在其 PacketConn
//!   语义下无害；Rust `Ok(0)` 会被 AsyncRead 消费方读成 EOF）。
//!
//! # 断言（修复后应为绿；反向自检 = 把对应改动改回去 ⇒ 各断言必红，红值见表）
//!
//! | 测试 | 断言 | 改回去必红的原因（旧指纹） |
//! |---|---|---|
//! | `xdns_client_drop_releases_all_tasks` | drop 后 `alive == base` | 无 Drop/无托管 ⇒ `recv_loop` 永活（`base+1`） |
//! | `xdns_client_drop_releases_doh_workers` | drop 后 `alive == base` | worker 级联断 ⇒ 32 worker 永活（`base+34`） |
//! | `persistent_recv_error_warns_once_and_stops` | `recv_from` 恰 poll **1** 次 + WARN 留痕恰 **1** 条 | `continue` ⇒ poll 数无界（实测 9999+）且零日志 |
//! | `xdns_client_zero_length_frame_is_not_eof` | 0 长度帧不产生任何投递（无 EOF 语义），后续真帧照常投递 | 空 payload 投递 ⇒ `recv_from` 返 `Ok(0)` = 上层 EOF |
//!
//! # 跑法
//!
//! ```text
//! cargo test -p xray-transport --test audit_perfmemaudit_probe -- --nocapture
//! ```

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use xray_transport::finalmask::{UdpIo, build_udpmask_manager_from_json};

/// 存活任务数（tokio runtime 指标；`Handle::metrics()` 返回 owned `RuntimeMetrics`）。
fn alive_tasks() -> usize {
    tokio::runtime::Handle::current().metrics().num_alive_tasks()
}

/// 让 spawn 出去的任务真正被调度起来（并给退出/级联退出留时间）。
async fn settle(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ===========================================================================
// WARN 留痕捕获：泵任务跑在 runtime worker 线程 ⇒ 线程局部 with_default 捕不到，
// 用进程级 set_global_default（log_single_entry.rs 同教训）；HotLog 每次 emit 经
// `dispatch.enabled` 现判，无 tracing callsite 兴趣缓存陷阱。
// ===========================================================================

type Events = Arc<Mutex<Vec<(String, String, String)>>>; // (level, target, message)

static EVENTS: LazyLock<Events> = LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));
static CAPTURE_INSTALL: LazyLock<()> = LazyLock::new(|| {
    let _ = tracing::subscriber::set_global_default(CaptureSubscriber(Arc::clone(&EVENTS)));
});

struct CaptureSubscriber(Events);

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
        true
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

/// 统计含指定消息片段的 WARN 事件数。
fn warn_count(message_needle: &str) -> usize {
    EVENTS
        .lock()
        .expect("events poisoned")
        .iter()
        .filter(|(lvl, _tgt, msg)| lvl == "WARN" && msg.contains(message_needle))
        .count()
}

// ===========================================================================
// 测试 1/2：drop 后任务全回收（ar3tf）
// ===========================================================================

/// xdns 客户端（UDP resolver 形态）：drop 后泵任务与底层 fd 必须全回收。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_client_drop_releases_all_tasks() {
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

    // 真 UDP socket（`impl UdpIo for tokio::net::UdpSocket` 已存在，finalmask/mod.rs:77）
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    let base = alive_tasks();
    let wrapped = mgr.wrap_packet_conn_client(Box::new(sock)).expect("wrap 必须成功");
    settle(120).await;
    let after_wrap = alive_tasks();
    drop(wrapped);
    settle(300).await;
    let after_drop = alive_tasks();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "xdns(udp resolver) alive_tasks: base={base} after_wrap={after_wrap} after_drop={after_drop} \
             (leaked={})",
            after_drop.saturating_sub(base)
        );
    }

    assert!(after_wrap > base, "wrap 必须起 pump 任务（after_wrap={after_wrap} base={base}）");
    assert_eq!(
        after_drop, base,
        "ar3tf：drop 后必须全回收（泵 abort + fd 释放）；旧指纹 after_drop == base+1 \
         （recv_loop 持 inner 永不退）"
    );
}

/// xdns 客户端（**DoH resolver** 形态）：worker(缺省 32) + 三泵；drop 后必须全部
/// 退出（pump 经 fx abort；worker 经 `state`→`DohResolver.tx` drop 级联）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_client_drop_releases_doh_workers() {
    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                // Go 形态 https resolver（worker 缺省 32，见 infra/conf/transport_finalmask.go:860-862）
                "resolvers": [{ "addrs": ["https://127.0.0.1:8443/dns-query"] }]
            }
        }]
    })))
    .expect("xdns manager 必须可构造");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    let base = alive_tasks();
    let wrapped = mgr.wrap_packet_conn_client(Box::new(sock)).expect("wrap 必须成功");
    settle(120).await;
    let after_wrap = alive_tasks();
    drop(wrapped);
    // 级联退出两跳（泵 abort → tx drop → worker recv None），多留一拍
    settle(300).await;
    settle(300).await;
    let after_drop = alive_tasks();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "xdns(doh resolver) alive_tasks: base={base} after_wrap={after_wrap} \
             after_drop={after_drop} (leaked={})",
            after_drop.saturating_sub(base)
        );
    }

    assert!(
        after_wrap >= base + 32,
        "DoH resolver 必须起 worker(缺省 32) 个任务（after_wrap={after_wrap} base={base}）"
    );
    assert_eq!(
        after_drop, base,
        "ar3tf：drop 后 DoH worker(32) 必须经 tx-drop 级联全退；旧指纹 after_drop == base+34"
    );
}

// ===========================================================================
// 测试 3：持续 recv 错误 ⇒ WARN 一次 + 泵即退（ar3tf ③ / CQ-02 / B-06）
// ===========================================================================

/// 永久 recv 错误的内层 `UdpIo`（带 poll 计数）。
#[derive(Clone)]
struct ErrInner {
    polls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UdpIo for ErrInner {
    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("probe: persistent recv error"))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_recv_error_warns_once_and_stops() {
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

    let inner = ErrInner { polls: Arc::new(AtomicUsize::new(0)) };
    let base = alive_tasks();
    let wrapped = mgr.wrap_packet_conn_client(Box::new(inner.clone())).expect("wrap 必须成功");

    settle(300).await;
    let polls = inner.polls.load(Ordering::SeqCst);
    let warns = warn_count("xdns client: recv failed");
    let after_err = alive_tasks();

    // 紧循环判据：再等一拍，poll 数与 WARN 数都不得增长
    settle(200).await;
    let polls_later = inner.polls.load(Ordering::SeqCst);
    let warns_later = warn_count("xdns client: recv failed");

    drop(wrapped);
    settle(300).await;
    let after_drop = alive_tasks();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "recv-error probe: polls={polls} polls_later={polls_later} warns={warns} \
             warns_later={warns_later} after_err={after_err} after_drop={after_drop} base={base}"
        );
    }

    assert_eq!(polls, 1, "持续 recv 错误下 recv_from 必须恰 poll 1 次即退泵（旧指纹：无界增长）");
    assert_eq!(polls_later, 1, "等待期 poll 数不得增长 ⇒ 无紧循环");
    assert_eq!(warns, 1, "失败必须留痕且恰一条（WARN 级，默认 loglevel=warn 可见；旧指纹：0 条）");
    assert_eq!(warns_later, 1, "等待期 WARN 数不得增长 ⇒ 非重复刷屏");
    assert_eq!(
        after_err,
        base + 1,
        "recv/doh 两泵已退、send 泵存活（write_rx 未关）；旧指纹 base+2（recv_loop 永活）"
    );
    assert_eq!(after_drop, base, "drop 后错误路径也不得残留任务");
}

// ===========================================================================
// 测试 4：0 长度帧不得产生 EOF 语义（i86yo / B-11）
// ===========================================================================

/// 构造最小 DNS TXT 响应（question = x.example.com TXT，answer 单条 TXT，
/// rdata = [len][payload...] ⇒ `Resp::decode` 还原出 payload），query name 为
/// 域名后缀且严格更长（`Domain::is_domain` 契约）。
fn dns_txt_response(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 255, "探针 payload 走单 string");
    let qname: [u8; 15] = [
        0x01, b'x', // "x"
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00,
    ];
    let mut m = Vec::with_capacity(12 + qname.len() * 2 + 10 + 1 + payload.len());
    m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1 RA=1 rcode=0 非 TC
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&1u16.to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes()); // nscount
    m.extend_from_slice(&0u16.to_be_bytes()); // arcount
    m.extend_from_slice(&qname);
    m.extend_from_slice(&16u16.to_be_bytes()); // qtype TXT
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    m.extend_from_slice(&qname); // answer name
    m.extend_from_slice(&16u16.to_be_bytes()); // type TXT
    m.extend_from_slice(&1u16.to_be_bytes()); // class IN
    m.extend_from_slice(&60u32.to_be_bytes()); // ttl
    m.extend_from_slice(&((payload.len() + 1) as u16).to_be_bytes()); // rdlength
    m.push(payload.len() as u8); // TXT string len
    m.extend_from_slice(payload);
    m
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_client_zero_length_frame_is_not_eof() {
    // 假 resolver：端口进配置（客户端只信来自 resolver 地址的包）
    let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let resolver_addr = resolver.local_addr().expect("local_addr");

    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                "resolvers": [{ "addrs": [resolver_addr.to_string()] }]
            }
        }]
    })))
    .expect("xdns manager 必须可构造");

    let inner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let inner_addr = inner.local_addr().expect("local_addr");
    let wrapped = mgr.wrap_packet_conn_client(Box::new(inner)).expect("wrap 必须成功");
    settle(120).await;

    // 响应 1：decode 后 payload = [0xC0, 0x00]（0 长度终帧）
    resolver.send_to(&dns_txt_response(&[0xC0, 0x00]), inner_addr).await.expect("send");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(500), wrapped.recv_from(&mut buf)).await {
        Err(_elapsed) => {
            // 预期：0 长度帧被跳过，无任何投递
        },
        Ok(result) => {
            panic!(
                "i86yo：0 长度帧不得投递（Ok(0) = 上层 EOF 语义 / Ok(n>0) / Err 均不符）: {result:?}"
            );
        },
    }

    // 连接仍活：随后一条真帧（1 字节 'A'）必须照常投递
    resolver.send_to(&dns_txt_response(&[0xC0, 0x01, b'A']), inner_addr).await.expect("send");
    let (n, addr) = tokio::time::timeout(Duration::from_millis(2000), wrapped.recv_from(&mut buf))
        .await
        .expect("真帧必须照常投递（跳过 0 长度帧不得卡死连接）")
        .expect("recv_from 必须成功");
    assert_eq!(n, 1, "真帧 payload 长度");
    assert_eq!(buf[..n], [b'A'], "真帧 payload 内容");
    assert_eq!(addr, resolver_addr, "来源必须是 resolver 地址");

    drop(wrapped);
    settle(300).await;
}
