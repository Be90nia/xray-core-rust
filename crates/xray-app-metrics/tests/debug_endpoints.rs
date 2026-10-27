//! `/debug/vars` 与 `/debug/pprof` 端点 E2E 验收测试（dofk G-13）。
//!
//! 对应 Go `testing/scenarios/metrics_test.go` 的 debug 端点验收：
//! 1. `GET /debug/vars` 返回合法 JSON（含 Go expvar 默认 var 骨架 cmdline/memstats）
//! 2. `GET /debug/pprof/goroutine?debug=1` 返回非空文本且带 rust-native 说明
//! 3. `GET /debug/pprof/` index 页列出可用端点
//! 4. 未知路径（含 /debug/pprof 未知子路径）仍 404

use std::sync::Arc;

use xray_app_metrics::{MetricsHttpServer, StatsCollector, StatsSnapshot, TokioHttpServer};

struct EmptyStats;
impl StatsCollector for EmptyStats {
    fn collect(&self) -> StatsSnapshot {
        StatsSnapshot::default()
    }
}

/// TOCTOU 加固：bind(:0)→drop→被测 server 再 bind 之间端口可能被并行测试/
/// 其他进程抢占（Windows 10048 / Unix EADDRINUSE）——占用时换端口重试至多 5 次。
async fn start_server_retrying(
    stats: Arc<dyn StatsCollector>,
    obs: Option<Arc<dyn xray_app_metrics::ObservationCollector>>,
) -> (std::net::SocketAddr, TokioHttpServer) {
    for _ in 0..5 {
        let port = xray_common::testing::pick_free_ports(1).await[0];
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = TokioHttpServer::new();
        match server.start_http_listen(&addr.to_string(), Arc::clone(&stats), obs.clone()) {
            Ok(()) => return (addr, server),
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
            Err(e) => panic!("start_http_listen: {e}"),
        }
    }
    panic!("start_http_listen: EADDRINUSE persisted across 5 port retries");
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8(buf).expect("utf8")
}

async fn start_server() -> (std::net::SocketAddr, TokioHttpServer) {
    let (addr, server) = start_server_retrying(Arc::new(EmptyStats), None).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, server)
}

/// 带计数数据的 StatsCollector stub：模拟 xray-core `AppStatsFeature`（register.rs
/// impl StatsCollector）经 visit_counters 聚合现有 stats manager 后喂给的快照。
struct PopulatedStats;
impl StatsCollector for PopulatedStats {
    fn collect(&self) -> StatsSnapshot {
        xray_app_metrics::aggregate_counters([
            ("inbound>>>in_tag>>>traffic>>>uplink", 100),
            ("inbound>>>in_tag>>>traffic>>>downlink", 200),
        ])
    }
}

/// bd chnz 验收：`/debug/vars` 携带 Go handleDebugVars 形态的 stats/observatory key
/// （Go app/metrics/metrics.go:128-146；stats 三类 key 恒在 :160-164）。
#[tokio::test]
async fn get_debug_vars_serves_go_shaped_stats_and_observatory() {
    let (addr, server) = start_server_retrying(Arc::new(PopulatedStats), None).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = http_get(addr, "/debug/vars").await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected 200 OK, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );
    let parsed: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("valid json body");
    assert_eq!(
        parsed["stats"]["inbound"]["in_tag"]["uplink"], 100,
        "stats.inbound[tag].uplink missing: {parsed}"
    );
    assert_eq!(parsed["stats"]["inbound"]["in_tag"]["downlink"], 200);
    assert!(
        parsed["stats"].get("outbound").and_then(|v| v.as_object()).is_some(),
        "stats.outbound must exist even when empty: {parsed}"
    );
    assert!(
        parsed["stats"].get("user").and_then(|v| v.as_object()).is_some(),
        "stats.user must exist even when empty: {parsed}"
    );
    assert!(parsed["observatory"].is_null(), "observatory null without feature: {parsed}");

    server.shutdown().await;
}

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

#[tokio::test]
async fn get_debug_vars_returns_valid_json_with_go_skeleton() {
    let (addr, server) = start_server().await;

    let resp = http_get(addr, "/debug/vars").await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected 200 OK, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );
    assert!(resp.contains("Content-Type: application/json"), "missing json content-type");

    let parsed: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("valid json body");
    // Go expvar 默认 var 骨架：客户端按同名顶层 key 解析不失败
    assert!(
        parsed.get("cmdline").and_then(|v| v.as_array()).is_some(),
        "cmdline array missing: {parsed}"
    );
    assert!(
        parsed.get("memstats").map(|v| v.is_object()).unwrap_or(false),
        "memstats object missing: {parsed}"
    );
    assert!(parsed.get("uptime_seconds").and_then(|v| v.as_u64()).is_some(), "uptime missing");
    assert!(parsed.get("start_time_unix").and_then(|v| v.as_u64()).is_some(), "start_time missing");

    server.shutdown().await;
}

#[tokio::test]
async fn get_debug_pprof_goroutine_returns_snapshot_with_disclaimer() {
    let (addr, server) = start_server().await;

    let resp = http_get(addr, "/debug/pprof/goroutine?debug=1").await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected 200 OK, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );
    let body = body_of(&resp);
    assert!(!body.is_empty(), "snapshot body must be non-empty");
    assert!(
        body.contains("rust-native snapshot, not Go pprof format"),
        "disclaimer missing in body: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn get_debug_pprof_index_lists_available_endpoints() {
    let (addr, server) = start_server().await;

    let resp = http_get(addr, "/debug/pprof/").await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected 200 OK, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );
    assert!(
        body_of(&resp).contains("/debug/pprof/goroutine"),
        "index must list goroutine endpoint: {}",
        body_of(&resp)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn get_debug_unknown_paths_still_404() {
    let (addr, server) = start_server().await;

    // pprof 前缀下不可用的 Go 子路径必须 404（不伪造空 profile）
    let heap = http_get(addr, "/debug/pprof/heap?debug=1").await;
    assert!(
        heap.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "expected 404 for /debug/pprof/heap, got: {}",
        heap.split("\r\n").next().unwrap_or("")
    );
    // 完全未知路径
    let nope = http_get(addr, "/nope").await;
    assert!(
        nope.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "expected 404 for /nope, got: {}",
        nope.split("\r\n").next().unwrap_or("")
    );

    server.shutdown().await;
}
