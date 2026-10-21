//! `/debug/vars`（Go expvar 等价）与 `/debug/pprof`（诚实快照等价）端点实现。
//!
//! 对应 Go DefaultServeMux 上 `expvar` 与 `net/http/pprof` 自动注册的 debug 端点：
//! - [`expvars_json`]: JSON 计数器。保留 Go expvar 默认 var 名骨架（`cmdline`/`memstats`）
//!   以免客户端按同名 key 解析失败；Rust 无 `runtime.MemStats`，仅输出 OS 可得的近似
//!   等价字段（Linux `/proc`），无等价物的字段一律不给。
//! - [`pprof_goroutine_snapshot`]: 当前进程可得的运行时快照。Rust 无 goroutine， 非 Go pprof
//!   格式，body 首行显式注明。
//! - [`pprof_index`]: index 页，列出可用端点。

use std::{
    sync::LazyLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// 进程（近似）启动时刻：首次访问时初始化。
///
/// Rust 标准库没有进程启动时间 API；metrics server 是常驻服务，
/// 服务构造后首个 debug 请求与真实启动的偏差在秒级以下。
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

fn uptime() -> Duration {
    PROCESS_START.elapsed()
}

/// OS 线程数与常驻内存字节数，仅 Linux（`/proc/self/status`）可读；
/// 其他平台返回 `(None, None)`——对应字段省略，诚实优于编造。
#[cfg(target_os = "linux")]
fn os_threads_and_rss() -> (Option<u64>, Option<u64>) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let mut threads = None;
    let mut rss = None;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Threads:") {
            threads = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("VmRSS:") {
            // 形如 "  1234 kB"
            rss = v
                .trim()
                .strip_suffix("kB")
                .and_then(|n| n.trim().parse::<u64>().ok())
                .map(|kib| kib * 1024);
        }
    }
    (threads, rss)
}

#[cfg(not(target_os = "linux"))]
fn os_threads_and_rss() -> (Option<u64>, Option<u64>) {
    (None, None)
}

/// JSON 字符串转义：`"`、`\` 与 <0x20 控制字符。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_string_array<I: IntoIterator<Item = String>>(items: I) -> String {
    let parts: Vec<String> =
        items.into_iter().map(|a| format!("\"{}\"", json_escape(&a))).collect();
    format!("[{}]", parts.join(","))
}

/// `/debug/vars` 响应体：Go expvar 形态的 JSON。
///
/// 顶层 key 按 Go expvar handler 的字母序输出；`cmdline`/`memstats` 是 Go
/// 默认注册的 var 名，`start_time_unix`/`uptime_seconds` 是 Rust 侧补充。
/// `memstats.Sys` 为进程 RSS 近似（非 Go 堆语义），`memstats.Goroutines`
/// 为 OS 线程数近似（tokio 任务数 stable API 不可得）；两者仅 Linux 可得。
pub fn expvars_json() -> String {
    let (threads, rss) = os_threads_and_rss();
    let mut memstats = String::new();
    if let Some(rss) = rss {
        memstats.push_str(&format!("\"Sys\":{rss},"));
    }
    if let Some(threads) = threads {
        memstats.push_str(&format!("\"Goroutines\":{threads},"));
    }
    let uptime_secs = uptime().as_secs();
    let start_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .unwrap_or(0)
        .saturating_sub(uptime_secs);
    format!(
        "{{\"cmdline\":{},\"memstats\":{{{}}},\"start_time_unix\":{start_unix},\"uptime_seconds\":{uptime_secs}}}",
        json_string_array(std::env::args()),
        memstats.trim_end_matches(','),
    )
}

/// `/debug/pprof/` 响应体：index 页，列出可用端点（Go pprof index 等价）。
pub fn pprof_index() -> String {
    concat!(
        "<html><head><title>/debug/pprof/ (rust-native)</title></head><body>\n",
        "<pre>/debug/pprof/ — rust-native snapshot, not Go pprof format\n\n",
        "<a href=\"/debug/pprof/goroutine?debug=1\">goroutine</a>\n",
        "allocs, block, heap, mutex, profile, threadcreate, trace: unavailable on Rust\n",
        "</pre></body></html>\n"
    )
    .to_string()
}

/// `/debug/pprof/goroutine?debug=1` 响应体。
///
/// 诚实的 rust-native 快照：当前可得的运行时量（uptime/OS 线程/RSS/CPU 并行度）
/// 加当前 worker 线程栈。tokio 任务列表在 stable tokio 上不可得（runtime metrics
/// 需要 tokio_unstable），不伪造；非 Go pprof 格式，首行注明。
pub fn pprof_goroutine_snapshot() -> String {
    let (threads, rss) = os_threads_and_rss();
    let mut out = String::from("rust-native snapshot, not Go pprof format\n");
    out.push_str(&format!("uptime_seconds: {}\n", uptime().as_secs()));
    if let Some(t) = threads {
        out.push_str(&format!("os_threads: {t}\n"));
    }
    if let Some(r) = rss {
        out.push_str(&format!("rss_bytes: {r}\n"));
    }
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    out.push_str(&format!("cpu_parallelism: {cpus}\n"));
    out.push_str(
        "tokio task list: unavailable on stable tokio (runtime metrics require tokio_unstable)\n",
    );
    out.push_str("goroutine count equivalent: /debug/vars memstats.Goroutines (OS threads)\n");
    out.push_str("current worker backtrace (this request only):\n");
    out.push_str(&format!("{:?}", std::backtrace::Backtrace::force_capture()));
    out
}
