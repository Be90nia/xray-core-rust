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

/// 取一个临时空闲端口：bind 127.0.0.1:0 拿系统分配的端口，drop 后让被测 server 重新 bind。
fn pick_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp");
    let a = l.local_addr().expect("local_addr");
    drop(l);
    a
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
    let addr = pick_port();
    let server = TokioHttpServer::new();
    let stats: Arc<dyn StatsCollector> = Arc::new(EmptyStats);
    server.start_http_listen(&addr.to_string(), stats, None).expect("start_http_listen");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, server)
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
