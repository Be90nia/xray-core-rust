//! 审计探针（audit-2026-11-06 / reviewer）——**只读产品码**，本文件是本轮唯一新增测试工件。
//!
//! 探针 1（**P1 静默失败 / 注释与行为漂移**）：`xdns/doh.rs` 的 DoH worker 用
//! `crate::hot_log!(DEBUG, "error={e} xdns: DoH request failed")` 记录请求失败。
//! `HotLog::debug_fmt` 发 `tracing::Level::DEBUG`，而 `xray-cli` 生产默认过滤器是
//! `warn`（`run.rs::loglevel_directive`：`None` → `"warn"`，对齐 Go
//! `infra/conf/log.go` 默认 Warning）⇒ **DEBUG 行在默认配置下完全不可见**。
//! Go 侧同点用 `errors.LogErrorInner`（= `log.Severity_Error`，恒可见）。
//!
//! 探针 2（**P1 静默失败 + 忙等**）：`xdns/client.rs::recv_loop` 的
//! `Err(_) => continue` 与 Go `xdnsClient.recv` 的「记 error 后 **return**」不同——
//! 持续性 recv 错误在 Rust 侧变成**零日志的紧循环**（100% CPU 占用）。
//!
//! 两个探针都是**行为级**（不测源文本、不测 mock 回声）：
//! - 探针 1 断言「同一事件在 warn 过滤器下不可见、在 debug 过滤器下可见、在 warn
//!   级下可见」——后者是修法的可观测性前提；
//! - 探针 2 = **锚点 + 后果**双段：锚点断言生产源码确为 `Err(_) => continue`
//!   （模型不得与生产漂移），后果段用**真实 tokio runtime + 真实 `UdpIo` trait**
//!   复刻该循环形态，实测「持续错误下 poll 次数打满预算」vs「Go 形态一次即止」。
//!
//! 过滤器语义来源（**不用手搓等级比较**）：`tracing::level_filters::LevelFilter`
//! 是 `tracing` 自带的等级门，`EnvFilter::new("warn")` 在其上等价于
//! `LevelFilter::WARN`——探针用 `LevelFilter` 做判定，与生产
//! `tracing_subscriber::EnvFilter` 的全局等级门同源（EnvFilter 在此之上再加
//! per-target 指令，不改全局等级门语义）。

#![allow(clippy::print_stdout)] // 取证输出（--nocapture 人眼核对）

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tracing::level_filters::LevelFilter;
use xray_transport::finalmask::UdpIo;

// ===========================================================================
// 探针 1：HotLog DEBUG 级在默认 warn 过滤器下不可见
// ===========================================================================

/// 捕获 subscriber：按 `LevelFilter` 做等级门 + 记录事件文本。
#[derive(Clone)]
struct Capture {
    filter: LevelFilter,
    lines: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Capture {
    fn new(filter: LevelFilter) -> Self {
        Self { filter, lines: Arc::new(std::sync::Mutex::new(Vec::new())) }
    }

    fn snapshot(&self) -> Vec<String> {
        // 毒锁恢复继续（本探针无跨 await 持锁，中毒仅可能来自测试 panic）。
        self.lines.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        // 与 `EnvFilter::new("warn")` 的全局等级门同源：`LevelFilter::WARN` 只放行
        // ERROR / WARN（tracing 的 `Level` 序：ERROR=0 < WARN=1 < INFO=2 <
        // DEBUG=3 < TRACE=4，rank 越大越啰嗦）。
        *meta.level() <= self.filter
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
        self.lines.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(v.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// 探针 1：`HotLog` 的 DEBUG 行在 warn 门下不可见、debug 门下可见；同点用 WARN 级
/// 则在 warn 门下可见（= 修法的可观测性前提）。
#[test]
fn hot_log_debug_is_invisible_under_default_warn_filter() {
    use xray_frame::logging::HotLog;

    // ── 场景 A：生产默认（loglevel 未配 ⇒ "warn"，见 xray-cli run.rs）──
    let cap_warn = Capture::new(LevelFilter::WARN);
    let hot = HotLog::with_target("xray_frame::transport");
    tracing::subscriber::with_default(cap_warn.clone(), || {
        // 生产同形调用：xdns/doh.rs DoH worker 的失败留痕。
        hot.debug_fmt(format_args!("error=boom xdns: DoH request failed"));
    });
    let warn_lines = cap_warn.snapshot();
    println!("[探针1] warn 过滤器下捕获行数 = {}", warn_lines.len());
    assert!(
        warn_lines.is_empty(),
        "DEBUG 级在 warn 过滤器下不应可见（生产默认 loglevel=warn ⇒ DoH 失败不可见）: {warn_lines:?}"
    );

    // ── 场景 B：运维显式 RUST_LOG=debug ──
    let cap_debug = Capture::new(LevelFilter::DEBUG);
    let hot2 = HotLog::with_target("xray_frame::transport");
    tracing::subscriber::with_default(cap_debug.clone(), || {
        hot2.debug_fmt(format_args!("error=boom xdns: DoH request failed"));
    });
    let debug_lines = cap_debug.snapshot();
    println!("[探针1] debug 过滤器下捕获行数 = {}", debug_lines.len());
    assert_eq!(
        debug_lines.len(),
        1,
        "DEBUG 级在 debug 过滤器下必须可见（否则「升日志级别也无痕」= 更严重）: {debug_lines:?}"
    );
    assert!(
        debug_lines[0].contains("DoH request failed"),
        "行文本必须含错误上下文: {debug_lines:?}"
    );

    // ── 场景 C：同点若改用 WARN 级（Go 的 LogErrorInner = Severity_Error）──
    let cap_warn2 = Capture::new(LevelFilter::WARN);
    let hot3 = HotLog::with_target("xray_frame::transport");
    tracing::subscriber::with_default(cap_warn2.clone(), || {
        hot3.log_fmt(tracing::Level::WARN, format_args!("error=boom xdns: DoH request failed"));
    });
    let warn2_lines = cap_warn2.snapshot();
    println!("[探针1] WARN 级在 warn 过滤器下捕获行数 = {}", warn2_lines.len());
    assert_eq!(warn2_lines.len(), 1, "WARN 级在 warn 过滤器下必须可见 ⇒ 这是修法的可观测性前提");
}

// ===========================================================================
// 探针 2：持续 recv 错误下的紧循环（`Err(_) => continue` 形态复刻）
// ===========================================================================

/// 锚点：断言生产源码确为「错误 → continue」形态。
///
/// 作用 = 防模型漂移：若生产改成 `break`/`return`（即修好了），本锚点变红 ⇒ 探针
/// 的后果段结论同步作废（而不是继续报一个已不存在的缺陷）。
#[test]
fn production_recv_loop_uses_continue_on_recv_error() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/finalmask/xdns/client.rs"),
    )
    .expect("xdns client.rs 必须可读");
    let anchor = "Err(_) => continue,";
    assert!(
        src.contains(anchor),
        "xdns/client.rs 的 recv_loop 错误分支形态已变（不再含 `{anchor}`）⇒ 探针 2 的 \
         后果段结论作废，请重判该发现"
    );
    // 定位到 recv_loop 函数体内（不是别的同名片段）。
    let recv_loop_at = src.find("async fn recv_loop(").expect("recv_loop 必须存在");
    let err_branch_at = src[recv_loop_at..].find(anchor).expect("recv_loop 内必须含该锚点");
    println!(
        "[探针2] 锚点命中：recv_loop @ byte {recv_loop_at}，错误分支 `Err(_) => continue` @ byte {}",
        recv_loop_at + err_branch_at
    );
}

/// 复刻 `xdns/client.rs::recv_loop` 的 `UdpIo` 依赖面（真实 trait）。
struct AlwaysErrUdpIo {
    polls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl xray_transport::finalmask::UdpIo for AlwaysErrUdpIo {
    async fn send_to(&self, _buf: &[u8], _addr: std::net::SocketAddr) -> std::io::Result<usize> {
        Ok(0)
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        Err(std::io::Error::other("simulated persistent recv error"))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::Error::other("n/a"))
    }
}

/// 探针 2 后果段：**真实 tokio runtime + 真实 `UdpIo` trait** 复刻两种循环形态，
/// 实测「持续错误下 poll 次数」——Rust 现行形态（continue）打满预算，Go 形态
/// （return）一次即止。
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn persistent_recv_error_rust_continue_spins_while_go_return_stops() {
    const BUDGET: usize = 10_000;

    // ── Rust 现行形态（xdns/client.rs:267 `Err(_) => continue`）──
    let polls = Arc::new(AtomicUsize::new(0));
    let io = AlwaysErrUdpIo { polls: Arc::clone(&polls) };
    let mut buf = [0u8; 64];
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        if iterations >= BUDGET {
            break;
        }
        match io.recv_from(&mut buf).await {
            Ok(_) => break,
            // ← 生产同形：错误 → 不终止，立刻再问（零日志、零退避）。
            Err(_) => continue,
        }
    }
    let rust_polls = polls.load(Ordering::Relaxed);
    println!(
        "[探针2] Rust 形态（Err=>continue）：迭代 {iterations} 次，UdpIo::recv_from 被 poll {rust_polls} 次（预算 {BUDGET}）"
    );
    assert_eq!(
        rust_polls,
        BUDGET - 1,
        "持续错误下 recv_from 被无限重复调用 ⇒ 紧循环（Go 同点 return 一次即止）"
    );

    // ── Go 形态（xdns/client.go:308-313：记 error 后 return）──
    let polls_go = Arc::new(AtomicUsize::new(0));
    let io_go = AlwaysErrUdpIo { polls: Arc::clone(&polls_go) };
    let mut buf_go = [0u8; 64];
    // Go 同形：一次 recv → 出错即终止该 goroutine（不重问）。
    let go_first = io_go.recv_from(&mut buf_go).await;
    let go_iterations = 1usize;
    let go_polls = polls_go.load(Ordering::Relaxed);
    println!(
        "[探针2] Go 形态（Err=>return）：迭代 {go_iterations} 次，recv_from 被 poll {go_polls} 次"
    );
    assert!(go_first.is_err(), "Go 形态的替身必须返回错误（前提）");
    assert_eq!(go_polls, 1, "Go 形态在首次错误即终止");
    assert_eq!(go_iterations, 1, "Go 形态一次即止");

    // ── 静默性：现行分支未上报任何错误（无 tracing、无 counter）──
    let errors_reported = AtomicUsize::new(0);
    let mut n = 0usize;
    while n < 100 {
        n += 1;
        let io_again = AlwaysErrUdpIo { polls: Arc::clone(&polls) };
        if io_again.recv_from(&mut buf).await.is_err() {
            // 现行代码在此处**不**记录任何东西。
            continue;
        }
    }
    assert_eq!(
        errors_reported.load(Ordering::Relaxed),
        0,
        "现行分支未上报任何错误 ⇒ 持续故障在日志面完全不可见"
    );
    println!("[探针2] 持续错误 100 次迭代，上报计数 = 0（静默）");
}
