//! `/debug/vars`（Go expvar 等价）与 `/debug/pprof`（诚实快照等价）端点实现。
//!
//! 对应 Go DefaultServeMux 上 `expvar` 与 `net/http/pprof` 自动注册的 debug 端点：
//! - [`expvars_json`]: JSON 计数器，完整对应 Go `MetricsHandler.handleDebugVars`
//!   （app/metrics/metrics.go:128-146）：Go expvar 默认 var 骨架（`cmdline`/`memstats`） 加 `stats`
//!   与 `observatory` 两个 key，顶层 key 按字母序（Go map marshal 语义）。 Rust 无
//!   `runtime.MemStats`，仅输出 OS 可得的近似等价字段（Linux `/proc`）， 无等价物的字段一律不给。
//! - [`pprof_goroutine_snapshot`]: 当前进程可得的运行时快照。Rust 无 goroutine， 非 Go pprof
//!   格式，body 首行显式注明。
//! - [`pprof_index`]: index 页，列出可用端点。

use std::{
    collections::HashMap,
    sync::LazyLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::metrics::{ObservationSnapshot, StatsSnapshot, TrafficCount};

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

/// `/debug/vars` 响应体：Go `MetricsHandler.handleDebugVars` 完整形态
/// （app/metrics/metrics.go:128-146）。
///
/// 顶层 key 按 Go expvar handler 的字母序输出（Go `json.Marshal(map)` 语义）：
/// `cmdline`/`memstats` 是 Go expvar 默认注册的 var 名，`observatory`/`stats`
/// 是 handleDebugVars 追加的两个 key（metrics.go:143-144），
/// `start_time_unix`/`uptime_seconds` 是 Rust 侧补充。
/// `memstats.Sys` 为进程 RSS 近似（非 Go 堆语义），`memstats.Goroutines`
/// 为 OS 线程数近似（tokio 任务数 stable API 不可得）；两者仅 Linux 可得。
pub fn expvars_json(stats: &StatsSnapshot, obs: Option<&ObservationSnapshot>) -> String {
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
        "{{\"cmdline\":{},\"memstats\":{{{}}},\"observatory\":{},\"start_time_unix\":{start_unix},\"stats\":{},\"uptime_seconds\":{uptime_secs}}}",
        json_string_array(std::env::args()),
        memstats.trim_end_matches(','),
        observatory_json(obs),
        stats_json(stats),
    )
}

/// `stats` key：Go `MetricsHandler.stats()` 形态
/// （app/metrics/metrics.go:159-183）。
///
/// `inbound`/`outbound`/`user` 三个 key **始终存在**（无数据时为空对象，
/// metrics.go:160-164）；每项 `{tag: {downlink: n, uplink: m}}`，direction
/// 取计数器名第 4 段（metrics.go:169），tag 取第 2 段。快照内不存在的
/// direction（解析面已过滤，见 [`crate::metrics::parse_counter_name`]）不输出。
pub fn stats_json(stats: &StatsSnapshot) -> String {
    format!(
        "{{\"inbound\":{},\"outbound\":{},\"user\":{}}}",
        traffic_map_json(&stats.inbound),
        traffic_map_json(&stats.outbound),
        traffic_map_json(&stats.user),
    )
}

/// 单类计数 map → `{"tag":{"downlink":n,"uplink":m},...}`，tag 按字母序
/// （Go map marshal 语义）。
fn traffic_map_json(counts: &HashMap<String, TrafficCount>) -> String {
    let mut tags: Vec<(&String, &TrafficCount)> = counts.iter().collect();
    tags.sort_by(|a, b| a.0.cmp(b.0));
    let parts: Vec<String> = tags
        .iter()
        .map(|(tag, c)| {
            format!(
                "\"{}\":{{\"downlink\":{},\"uplink\":{}}}",
                json_escape(tag),
                c.downlink,
                c.uplink
            )
        })
        .collect();
    format!("{{{}}}", parts.join(","))
}

/// `observatory` key：Go `MetricsHandler.observatoryStatus()` 的 marshalJSON 形态
/// （app/metrics/metrics.go:148-153/206-219）。
///
/// 无 observatory 时输出 `null`（Go feature == nil → marshalJSON(nil)，metrics.go:207-209）；
/// 有数据时 `{outbound_tag: {extra...}}`。与 Go 的形状差异：Go `OutboundStatus`
/// 字段是类型化的（alive bool / delay int64 等），本 crate 的
/// [`ObservationSnapshot`] 把 extras 建模为字符串，此处按字符串原样输出——
/// 不做类型猜测，避免静默类型强制。
pub fn observatory_json(obs: Option<&ObservationSnapshot>) -> String {
    let Some(obs) = obs else {
        return "null".to_string();
    };
    let mut tags: Vec<&crate::metrics::ObservationEntry> = obs.entries.iter().collect();
    tags.sort_by(|a, b| a.outbound_tag.cmp(&b.outbound_tag));
    let parts: Vec<String> = tags
        .iter()
        .map(|e| {
            let kvs: Vec<String> = e
                .extra
                .iter()
                .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
                .collect();
            format!("\"{}\":{{{}}}", json_escape(&e.outbound_tag), kvs.join(","))
        })
        .collect();
    format!("{{{}}}", parts.join(","))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{ObservationEntry, aggregate_counters};

    /// 验收①：注册计数器后导出 JSON，key 名与 Go handleDebugVars 一致。
    ///
    /// Go 证据（app/metrics/metrics.go）：
    /// - :128-146 handleDebugVars = expvar 默认 var（cmdline/memstats）+ "stats" + "observatory"
    /// - :143-144 `vars["stats"]` / `vars["observatory"]` 追加
    /// - :160-164 stats() 始终含 inbound/outbound/user 三 key（空数据也是空对象）
    /// - :169-181 type=parts[0] tag=parts[1] direction=parts[3]，值 = counter.Value()
    #[test]
    fn expvars_key_shape_matches_go_handle_debug_vars() {
        let snapshot = aggregate_counters([
            ("inbound>>>tag_a>>>traffic>>>uplink", 11),
            ("inbound>>>tag_a>>>traffic>>>downlink", 22),
            ("outbound>>>tag_b>>>traffic>>>uplink", 33),
            ("outbound>>>tag_b>>>traffic>>>downlink", 44),
            ("user>>>u@x.com>>>traffic>>>uplink", 55),
        ]);
        let parsed: serde_json::Value =
            serde_json::from_str(&expvars_json(&snapshot, None)).expect("valid json");

        let top_keys: Vec<&str> =
            parsed.as_object().expect("top-level object").keys().map(String::as_str).collect();
        // Go json.Marshal(map) 按字母序输出 key
        assert_eq!(
            top_keys,
            ["cmdline", "memstats", "observatory", "start_time_unix", "stats", "uptime_seconds"]
        );

        // observatory：无 feature → null（metrics.go:207-209 nil → marshalJSON(nil)）
        assert!(parsed["observatory"].is_null(), "observatory must be null: {parsed}");

        // stats 恰好三类 key（metrics.go:160-164）
        let stats = &parsed["stats"];
        let stat_keys: Vec<&str> =
            stats.as_object().expect("stats object").keys().map(String::as_str).collect();
        assert_eq!(stat_keys, ["inbound", "outbound", "user"]);

        // 计数值落位：type/tag/direction 三层嵌套（metrics.go:169-181）
        assert_eq!(stats["inbound"]["tag_a"]["uplink"], 11);
        assert_eq!(stats["inbound"]["tag_a"]["downlink"], 22);
        assert_eq!(stats["outbound"]["tag_b"]["uplink"], 33);
        assert_eq!(stats["outbound"]["tag_b"]["downlink"], 44);
        assert_eq!(stats["user"]["u@x.com"]["uplink"], 55);
        assert_eq!(stats["user"]["u@x.com"]["downlink"], 0);
    }

    /// 空 stats 仍输出 inbound/outbound/user 三空对象（Go metrics.go:160-164
    /// 预置三空 map，marshal 后为 `{}`）。
    #[test]
    fn empty_stats_still_emits_three_sections() {
        let parsed: serde_json::Value =
            serde_json::from_str(&expvars_json(&StatsSnapshot::default(), None))
                .expect("valid json");
        assert_eq!(parsed["stats"]["inbound"], serde_json::json!({}));
        assert_eq!(parsed["stats"]["outbound"], serde_json::json!({}));
        assert_eq!(parsed["stats"]["user"], serde_json::json!({}));
    }

    /// 短名计数器（<4 段）跳过——Go `len(nameSplit) < 4` 跳过（metrics.go:166-168）。
    #[test]
    fn short_counter_names_are_skipped() {
        let snapshot = aggregate_counters([
            ("user>>>u@x.com>>>ip", 7),
            ("badname", 8),
            ("inbound>>>ok_tag>>>traffic>>>uplink", 9),
        ]);
        let parsed: serde_json::Value =
            serde_json::from_str(&stats_json(&snapshot)).expect("valid json");
        assert!(parsed["user"].as_object().expect("user object").is_empty());
        assert_eq!(parsed["inbound"]["ok_tag"]["uplink"], 9);
    }

    /// observatory 有数据时按 outbound_tag 索引（Go metrics.go:211-217
    /// `resp[x.OutboundTag] = x`）。
    #[test]
    fn observatory_present_keyed_by_outbound_tag() {
        let obs = ObservationSnapshot {
            entries: vec![ObservationEntry {
                outbound_tag: "proxy_a".to_string(),
                extra: vec![("alive".to_string(), "true".to_string())],
            }],
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&expvars_json(&StatsSnapshot::default(), Some(&obs)))
                .expect("valid json");
        assert_eq!(parsed["observatory"]["proxy_a"]["alive"], "true");
    }
}
