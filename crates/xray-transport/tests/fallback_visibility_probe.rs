//! C 组实测探针：fallback 路径的「失败可见性」与客户端可见行为。
//!
//! 审计 2026-11-04 · outbound/dns/fallback 三侧逐路径。
//!
//! **只读探针**：不改任何产品代码。
//!
//! 覆盖（每条给「客户端可见行为」实测）：
//! - C-1 VLESS fallback：`xray_transport::fallback::fallback_to_dest` 直调（VLESS `do_fallback`
//!   的唯一实现，`crates/xray-proxy-vless/src/inbound/server.rs:456`）。 fallback dest 不可达 ⇒
//!   客户端看到什么？（连接被断开 / 挂到 idle 超时 / 无声）
//! - C-2 Trojan fallback：同一实现（`xray-proxy-trojan/src/server.rs:453`）。
//! - C-3 REALITY fallback：同一实现（`xray-core/src/inbound.rs:4232` / `:4398`）。
//! - C-4 splithttp reality fallback：同一实现（`xray-transport-splithttp/src/transport.rs:803`）。
//!   ⇒ 四处共用 `xray_transport::fallback::fallback_to_dest` ⇒ **耗时/可见行为同构**，
//!   差异只在**调用方是否吞错误**（`let _ =` vs `if let Err(e) => warn`）。
//! - C-5 fallback dest 是域名 ⇒ 每次重试**重新解析**（×5）。
//! - C-6 PROXY protocol 解析无 timeout（裸 `read_exact`）⇒ 只连不发 ⇒ 挂多久？
//!
//! 复现（**必须 release**）：
//! ```text
//! cargo test --release -p xray-transport --test fallback_visibility_probe -- --nocapture --test-threads=1
//! ```
//!
//! 纪律：探针产物只读；不改 src。
//!
//! **lint 豁免理由**：本文件是**计时探针**，必须读系统单调钟测墙钟耗时；
//! 生产代码的 `Instant::now` 禁令（L3：时钟唯一源 = udf `skeleton::clock`）针对的是
//! 数据面/业务逻辑，不适用于测墙钟的测试夹具（同 `inbound_accept_blocking.rs`）。
#![allow(clippy::disallowed_methods, reason = "计时探针：需系统单调钟测墙钟耗时，非数据面时钟使用")]

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_transport::fallback::fallback_to_dest;

/// 打印一行探针结果（`[PROBE]` 前缀便于 grep）。
fn probe(label: &str, detail: impl std::fmt::Display) {
    println!("[PROBE] {label:<52} {detail}");
}

/// 最小 `Subscriber`：捕获 `(级别, message)`（xray-transport 无 tracing-subscriber
/// dev-dep，手写捕获足够断言 warn 留痕；同 `src/accept_policy.rs` 测试内实现）。
///
/// 全局安装而非 `set_default`：fallback 的 future 在 multi_thread runtime 上可跨线程
/// 恢复，thread-local 的 guard 会丢。
struct CaptureLogs(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for CaptureLogs {
    fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _a: &tracing::span::Id, _b: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct MsgVisitor(String);
        impl tracing::field::Visit for MsgVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0.push_str(value);
                }
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0.push_str(&format!("{value:?}"));
                }
            }
        }
        let mut v = MsgVisitor(String::new());
        event.record(&mut v);
        let line = format!("{} {}", event.metadata().level(), v.0);
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// 本机保留端口（连接立即被拒 ⇒ 快速失败）。
/// 用一个「先监听再 drop」的端口拿一个大概率空闲端口。
async fn closed_port() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr");
    drop(l);
    addr
}

/// 全二进制的日志汇聚槽：`set_global_default` 只能装一次，故所有用例共用一份槽，
/// 各用例用「下标边界」只看自己那段的日志。
static LOG_SINK: std::sync::LazyLock<Arc<Mutex<Vec<String>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// 装上（或复用已装的）日志捕获，返回汇聚槽。
fn install_capture() -> Arc<Mutex<Vec<String>>> {
    let logs = Arc::clone(&LOG_SINK);
    // 已装过就复用（同二进制内多用例共用）；装不上说明别人先装了同一个槽。
    let _ = tracing::subscriber::set_global_default(CaptureLogs(Arc::clone(&logs)));
    logs
}

/// C-1/C-2/C-3/C-4 共用实现：`fallback_to_dest` 在 dest 不可达时的行为。
///
/// 客户端可见行为判定（用 duplex 模拟客户端↔服务端）：
/// - `fallback_to_dest` 返回 `Err` ⇒ **失败可见**（调用方可观测）。
/// - 四处调用方中三处用 `let _ =`（VLESS `server.rs:459`、REALITY
///   `inbound.rs:4232`/`:4398`、splithttp `transport.rs:803`），只有 Trojan 用 `if let Err(e) =>
///   warn`（`server.rs:465`）——**bd wue5s** 起拨号失败在 `fallback_to_dest` 内 warn
///   留痕，故吞错不再等于静默。
/// - **对客户端**：dest 不可达 ⇒ 服务端既不转发也不回错误 ⇒ 客户端只看到 「连接被关闭」（读到 0
///   字节/EOF），**没有任何错误信息**。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1_fallback_to_dest_unreachable_dest_fails_visible_to_caller() {
    let dest = closed_port().await;
    // bd wue5s：修复后契约要求拨号失败留痕（修复前三处调用方 `let _ =` 吞错 ⇒ 静默）。
    let logs = install_capture();

    // 客户端侧：duplex 的一端当客户端。
    let (mut client, mut server) = tokio::io::duplex(4096);
    let first = b"GET / HTTP/1.1\r\n";

    let dest_str = format!("{}:{}", dest.ip(), dest.port());
    let t0 = Instant::now();
    let result = fallback_to_dest(
        &mut server,
        first,
        &dest_str,
        "127.0.0.1:1234".parse().expect("peer"),
        "127.0.0.1:443".parse().expect("local"),
        0,
    )
    .await;
    let elapsed = t0.elapsed();

    probe(
        "C-1 fallback_to_dest dest 不可达 → 返回值",
        format!(
            "{elapsed:?} is_err={} err={:?}",
            result.is_err(),
            result.as_ref().err().map(io::Error::to_string)
        ),
    );
    probe("C-1 错误 Debug（kind 判别）", format!("{:?}", result.as_ref().err()));

    // 判据（PM 2026-11-04 定调：效果最优，不要求与 Go 一致）：`ECONNREFUSED` 是
    // **确定性失败**，重试不可能改变结果 ⇒ 一次尝试即返回。
    // 修复前：裸 `TcpStream::connect` 每次等一次 SYN 重传（2.04s）× 5 + 600ms 退避
    // = 10.816s。修复后：SIO_TCP_INITIAL_RTO 快速失败 + 不重试 ⇒ 毫秒级。
    assert!(
        elapsed < Duration::from_millis(200),
        "refused 必须快速失败（确定性失败不重试），实测 {elapsed:?}"
    );

    // 失败**可见**（返回 Err）——修复后不得再被调用方静默吞掉：拨号失败必须 warn 留痕。
    assert!(result.is_err(), "dest 不可达必须返回 Err");
    let err = result.as_ref().expect_err("dest 不可达应返回 Err");
    let msg = err.to_string();
    probe("C-1 错误文本（分类依据）", &msg);
    // 错误文本须含「所有重试失败」语义（`RetryError` 的 Display 前缀）。
    assert!(msg.contains("all retry attempts failed"), "错误应表明是重试耗尽，实测: {msg}");
    // 错误类别必须透传（refused 不能被压成 Other）：调用方可据此分流。
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "错误类别须透传 refused");
    // 留痕断言按**本用例的 dest** 过滤：日志槽是全二进制共享的，并行跑的其他用例
    // 也会往里写（`warn` 级别由共享的 60s/5 条限频闸决定，故此处不钉级别——
    // 「有 warn 输出」由 C-1d 按全局口径断言）。
    let mine: Vec<String> = logs
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains(&format!("fallback dest={dest_str} ")))
        .cloned()
        .collect();
    probe("C-1 拨号失败留痕", format!("{mine:?}"));
    assert!(!mine.is_empty(), "失败必须留痕（不许静默），实测 {mine:?}");
    for line in &mine {
        assert!(line.contains("class=refused"), "留痕行须带错误分类，实测: {line}");
        assert!(line.contains("elapsed="), "留痕行须带耗时，实测: {line}");
        assert!(line.contains(&dest_str), "留痕行须带 dest，实测: {line}");
    }

    // 客户端可见行为：服务端既没转发数据也没回错误 ⇒ 客户端读到 EOF（0 字节）。
    // （真实 VLESS 路径：`do_fallback` 拿到 read_half/write_half 后调用
    //   `fallback_to_dest`；失败返回 ⇒ 两半随函数返回被 drop ⇒ 客户端见 EOF。
    //   这里同样在 fallback 失败后 drop 服务端半边以复现该语义。）
    drop(server);
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => probe("C-1 客户端可见行为", "EOF（连接被关闭，无错误信息、无数据）"),
        Ok(Ok(n)) => panic!("客户端不应收到数据，实测 {n} 字节"),
        Ok(Err(e)) => probe("C-1 客户端可见行为", format!("连接错误（reset）：{e}")),
        Err(_) => panic!("客户端不应挂住：dest 不可达时应快速收场"),
    }
}

/// C-1c：黑洞 dest（SYN 无应答、无 RST）⇒ 总耗时必须被**总预算**封顶。
///
/// 判据（PM 2026-11-04）：黑洞总耗时 < 6s。修复前每次尝试的上界是 OS SYN 重传超时
/// （Windows ~21s）× 5 次 ≈ 105s（E2 推导；环回 refused 档实测 10.816s）。
/// 修复后：整次重试受 `FALLBACK_DIAL_BUDGET`(5s) 约束，单次尝试按剩余预算切成 ≤2s，
/// 故重试真实发生且总耗时封在 5s + 一层退避内。
///
/// 用 RFC 5737 TEST-NET-1（192.0.2.1）保证不可路由——注意个别网络会回 ICMP
/// unreachable（那就变成快速失败，仍满足 <6s，故类别不作硬钉）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1c_blackhole_dest_capped_by_total_budget() {
    let (_client, mut server) = tokio::io::duplex(4096);
    let t0 = Instant::now();
    let result = fallback_to_dest(
        &mut server,
        b"x",
        "192.0.2.1:443",
        "127.0.0.1:1234".parse().expect("peer"),
        "127.0.0.1:443".parse().expect("local"),
        0,
    )
    .await;
    let elapsed = t0.elapsed();
    let kind = result.as_ref().err().map(io::Error::kind);
    probe("C-1c 黑洞 dest（192.0.2.1:443）→ 总耗时", format!("{elapsed:?} kind={kind:?}"));

    assert!(result.is_err(), "黑洞 dest 必须 Err");
    assert!(elapsed < Duration::from_secs(6), "黑洞总耗时须 <6s（总预算封顶），实测 {elapsed:?}");
    assert!(
        matches!(
            kind,
            Some(
                io::ErrorKind::TimedOut
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            )
        ),
        "黑洞须归入 timeout/unreachable 类别，实测 {kind:?}"
    );
}

/// C-1d：失败日志**节流但不静默**。
///
/// 判据（PM 2026-11-04）：日志可见且不刷屏。fallback dest 配错时每连接都失败，
/// 逐条 warn 会淹掉日志；实现按「60s 窗口 / 至多 5 条 warn」限频，超出的降级 debug
/// ⇒ 每次失败仍有一条留痕（`RUST_LOG` 打开可见），但 warn 有硬上限；窗口滚动时补
/// 一条 `suppressed=N` 汇总。
///
/// 断言分两层：
///
/// 1. **本 dest 的 10 次失败**：留痕恰 10 条（节流不许等于静默）、其中 warn < 10；
/// 2. **全局**：整个二进制（含 C-1/C-1c 的失败）至少产出一条 warn 且带分类字段 —— `warn`
///    级别由共享限频闸决定，按 dest 钉会随并行调度摇摆。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1d_failure_logging_is_throttled_not_silent() {
    const N: usize = 10;
    let logs = install_capture();
    let dest = closed_port().await;
    let dest_str = format!("{}:{}", dest.ip(), dest.port());
    let key = format!("fallback dest={dest_str} ");

    for _ in 0..N {
        let (_client, mut server) = tokio::io::duplex(64);
        let r = fallback_to_dest(
            &mut server,
            b"x",
            &dest_str,
            "127.0.0.1:1234".parse().expect("peer"),
            "127.0.0.1:443".parse().expect("local"),
            0,
        )
        .await;
        assert!(r.is_err(), "refused dest 必须 Err");
    }

    let captured = logs.lock().unwrap().clone();
    let mine: Vec<&String> = captured.iter().filter(|l| l.contains(&key)).collect();
    let warns = mine.iter().filter(|l| l.starts_with("WARN")).count();
    probe("C-1d 10 次失败 → 留痕条数 / 其中 warn", format!("lines={} warns={warns}", mine.len()));
    assert!(mine.len() >= N, "每次失败都必须留痕（节流不许等于静默），实测 {mine:?}");
    assert!(warns < N, "warn 必须节流（实测 {warns} 条 warn / {N} 次失败）");

    // 全局：限频不等于全静默——本二进制内的失败里必须有 warn 输出且带分类。
    let all_warns: Vec<&String> =
        captured.iter().filter(|l| l.starts_with("WARN") && l.contains("fallback dest=")).collect();
    probe(
        "C-1d 全局 warn 留痕",
        format!("count={} sample={:?}", all_warns.len(), all_warns.first()),
    );
    assert!(!all_warns.is_empty(), "全局必须有 warn 留痕（限频不许等于静默）");
    assert!(
        all_warns.iter().any(|l| l.contains("class=") && l.contains("elapsed=")),
        "warn 行须带分类与耗时，实测: {all_warns:?}"
    );
    assert!(all_warns.len() <= N, "全局 warn 数不该超过本用例的失败数（限频生效）");
}

/// C-1b：fallback dest **可达**时，客户端应收到首字节回放（对照面）。
///
/// 注意：`fallback_to_dest` 末尾是 `copy_bidirectional(conn, dest_conn)` ⇒ **双向**
/// 拷贝 ⇒ 只有**两端都关闭**才返回 ⇒ 直调会挂住（除非 dest 侧先断）。
/// ⇒ 本用例把 `fallback_to_dest` 放在后台任务里跑，客户端侧读到首字节回声后
/// 主动关闭客户端端，驱动双向拷贝收场。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1b_fallback_to_dest_reachable_dest_replays_first_bytes() {
    // 起一个 echo-ish 服务端：读首字节 → 回写。
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr");
    xray_common::testing::spawn("c1b-fallback-echo", async move {
        while let Ok((mut sock, _)) = l.accept().await {
            let mut buf = [0u8; 64];
            let Ok(n) = sock.read(&mut buf).await else { continue };
            let _ = sock.write_all(&buf[..n]).await;
        }
    });

    let (mut client, mut server) = tokio::io::duplex(4096);
    let first = b"GET / HTTP/1.1\r\n";
    let dest_str = format!("{}:{}", addr.ip(), addr.port());

    let t0 = Instant::now();
    let fb = xray_common::testing::spawn("c1b-fallback-task", async move {
        fallback_to_dest(
            &mut server,
            first,
            &dest_str,
            "127.0.0.1:1234".parse().expect("peer"),
            "127.0.0.1:443".parse().expect("local"),
            0,
        )
        .await
    });

    // 客户端侧应收到首字节回声（dest 侧 echo 回来的 first）。
    let mut back = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut back))
        .await
        .expect("回放超时")
        .expect("read");
    let elapsed = t0.elapsed();
    probe(
        "C-1b fallback_to_dest dest 可达 → 首字节回放",
        format!("{n} 字节：{:?} total={elapsed:?}", String::from_utf8_lossy(&back[..n])),
    );
    assert_eq!(&back[..n], first, "首字节应原样回放（dest 收到并 echo 回来）");

    // 关闭客户端端 ⇒ 双向拷贝收场 ⇒ fallback 任务返回。
    drop(client);
    let r = tokio::time::timeout(Duration::from_secs(3), fb).await.expect("fallback 收场超时");
    probe("C-1b fallback_to_dest 返回值（客户端关闭后）", format!("is_err={}", r.is_err()));
}

/// C-5：fallback dest 是**域名** ⇒ 每次重试**重新解析**（×5）。
///
/// `fallback_to_dest` 用 `TcpStream::connect(dest)`（`&str` 形式）⇒ 每次调用
/// 都触发一次系统解析（tokio `ToSocketAddrs`）。`exponential_backoff(5, 100)`
/// ⇒ 最多 5 次尝试 ⇒ **最多 5 次解析**。
///
/// 实测方法：dest 用一个**每次解析都要走一次真实 DNS 查询**的域名
/// （本机用 `localhost.` 不行——hosts 命中；改用 RFC 6761 保证 NXDOMAIN 的
/// `.invalid` 顶级域 ⇒ 每次都真发一次 DNS 查询到上游）。
/// 计数方式：用一个**自带 DNS 计数**的 mock 上游不可行（系统 resolver 不听我们的
/// mock）⇒ 改用**耗时侧证**：5 次解析的耗时 ≈ 5× 单次解析耗时。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c5_fallback_domain_dest_resolves_on_every_retry() {
    // 单次系统解析耗时（`.invalid` ⇒ NXDOMAIN，每次真发查询）。
    let host = "fallback-probe-does-not-exist.invalid";
    let t0 = Instant::now();
    let single = tokio::net::lookup_host((host, 443)).await;
    let single_elapsed = t0.elapsed();
    probe(
        "C-5 单次系统解析耗时（.invalid ⇒ NXDOMAIN）",
        format!("{single_elapsed:?} is_err={}", single.is_err()),
    );
    assert!(single.is_err(), ".invalid 顶级域必须解析失败");

    // fallback 到该域名 ⇒ 5 次尝试 ⇒ 5 次解析。
    let dest_str = format!("{host}:443");
    let (mut _client, mut server) = tokio::io::duplex(4096);
    let t0 = Instant::now();
    let result = fallback_to_dest(
        &mut server,
        b"x",
        &dest_str,
        "127.0.0.1:1234".parse().expect("peer"),
        "127.0.0.1:443".parse().expect("local"),
        0,
    )
    .await;
    let elapsed = t0.elapsed();
    probe(
        "C-5 fallback dest=域名 → 总耗时（含 5 次重解析）",
        format!("{elapsed:?} is_err={}", result.is_err()),
    );
    probe("C-5 错误 Debug（kind 判别）", format!("{:?}", result.as_ref().err()));
    assert!(result.is_err(), "域名不可解析 ⇒ 必须 Err");

    // 判据：总耗时 ≥ 1× 单次解析（证明至少解析过一次），且**回退阶梯**
    // （0+100+200+300=600ms）叠加在上面 ⇒ 总耗时 ≥ 600ms + 1×解析。
    assert!(
        elapsed >= Duration::from_millis(600) + single_elapsed,
        "总耗时 {elapsed:?} 应 ≥ 退避阶梯 600ms + 单次解析 {single_elapsed:?}"
    );
    // 上界宽松（5 次解析 + 阶梯）。
    assert!(elapsed < Duration::from_secs(30), "总耗时 {elapsed:?} 应 <30s（5 次解析上界）");
}

/// C-6：PROXY protocol 解析**无 timeout**（裸 `read_exact`）⇒ 只连不发 ⇒ 挂多久？
///
/// `xray_transport::proxy_protocol::read_proxy_protocol` 用裸 `reader.read_exact`
/// ⇒ 无 deadline ⇒ **无界等待**（直到对端关闭或 OS 层报错）。
///
/// 实测：客户端连上后**不发任何字节** ⇒ 服务端读阻塞；用一个 3s 的观察窗口
/// 证明「3s 内不返回」⇒ 无界（非某个固定超时）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c6_proxy_protocol_parse_has_no_timeout() {
    use xray_transport::read_proxy_protocol;

    // 起一个「accept 后永不发送」的 TCP 服务端。
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr");
    xray_common::testing::spawn("c6-silent-peer", async move {
        let mut held = Vec::new();
        loop {
            let Ok((sock, _)) = l.accept().await else { return };
            held.push(sock);
        }
    });

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let t0 = Instant::now();
    // 观察窗口 3s：若 read_proxy_protocol 有 3s 内会返回的超时/错误 ⇒ 返回。
    let observed =
        tokio::time::timeout(Duration::from_secs(3), read_proxy_protocol(&mut sock)).await;
    let elapsed = t0.elapsed();
    match observed {
        Err(_elapsed_to) => {
            probe(
                "C-6 PROXY protocol 解析（只连不发）",
                format!("{elapsed:?} ⇒ 3s 观察窗口内**未返回** ⇒ 无 timeout（无界等待）"),
            );
            // 判据成立：观察窗口到期仍未返回 ⇒ 无内部超时。
        },
        Ok(Ok(v)) => panic!("不应在 3s 内返回 Ok({v:?})：PROXY 解析应有 timeout"),
        Ok(Err(e)) => panic!("不应在 3s 内返回 Err({e})：PROXY 解析应有 timeout"),
    }
}

/// 附：常量与语义打印（报告引用）。
#[test]
fn c0_probe_constants() {
    probe("fallback 重试参数", "exponential_backoff(5, 100) ⇒ 最多 5 次尝试，但…");
    probe("…确定性失败（refused/addr-unavailable）", "立即停：1 次尝试、零退避 sleep");
    probe("…非确定性失败（timeout/unreachable/dns）", "保留重试，退避阶梯 0+100+200+300 = 600ms");
    probe("fallback 总预算", "FALLBACK_DIAL_BUDGET = 5s（黑洞封顶 <6s 判据）");
    probe("fallback 单次尝试上限", "FALLBACK_ATTEMPT_TIMEOUT = 2s（按剩余预算取 min）");
    probe("失败日志限频", "60s 窗 / 至多 5 条 warn，其余 debug + 窗滚动汇总 suppressed=N");
    probe("PROXY protocol 解析", "裸 read_exact ⇒ 无 timeout");
    probe(
        "四处 fallback 调用方的错误处理",
        "VLESS/REALITY×2/splithttp = `let _ =`；Trojan = `if let Err(e) => warn`（源头已留痕）",
    );
}
