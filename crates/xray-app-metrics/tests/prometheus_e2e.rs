//! Prometheus endpoint E2E 验收测试。
//!
//! 对应任务 5ec 验收标准：「能通过 curl /metrics 获取 Prometheus 格式指标」。
//! 本测试用纯 tokio TCP 客户端模拟 curl 行为，验证：
//! 1. `GET /metrics` 返回 200 + `text/plain; version=0.0.4` Content-Type
//! 2. 响应体含 Prometheus exposition format（# HELP / # TYPE / xray_traffic_bytes{...}）
//! 3. 未知路径返回 404

use std::sync::Arc;

use xray_app_metrics::{
    MetricsHttpServer, ObservationSnapshot, StatsCollector, StatsSnapshot, TokioHttpServer,
    TrafficCount,
};

/// 测试用常量 stats：固定 inbound tag=e2e_in uplink=1234 downlink=5678。
struct ConstStats;
impl StatsCollector for ConstStats {
    fn collect(&self) -> StatsSnapshot {
        let mut snap = StatsSnapshot::default();
        snap.inbound.insert(
            "e2e_in".into(),
            TrafficCount {
                uplink: 1234,
                downlink: 5678,
            },
        );
        snap
    }
}

/// 取一个临时空闲端口：bind 127.0.0.1:0 拿系统分配的端口，drop 后让被测 server 重新 bind。
/// 测试场景下窗口很小（localhost 无竞争），可接受。
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

#[tokio::test]
async fn get_metrics_returns_prometheus_exposition_format() {
    let addr = pick_port();
    let server = TokioHttpServer::new();
    let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats);

    server
        .start_http_listen(&addr.to_string(), stats, None)
        .expect("start_http_listen");

    // 给 accept loop 一点时间进入 select!（实际 race window 极小）
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = http_get(addr, "/metrics").await;

    // 状态行
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected 200 OK, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );
    // Content-Type 是 Prometheus exposition format 标准 MIME
    assert!(
        resp.contains("Content-Type: text/plain; version=0.0.4"),
        "missing prometheus content-type"
    );
    // HELP / TYPE 头
    assert!(resp.contains("# HELP xray_traffic_bytes"));
    assert!(resp.contains("# TYPE xray_traffic_bytes counter"));
    // 实际指标行（标签顺序与 format_prometheus 实现一致）
    assert!(resp.contains("xray_traffic_bytes{type=\"inbound\",tag=\"e2e_in\",direction=\"uplink\"} 1234"));
    assert!(resp.contains("xray_traffic_bytes{type=\"inbound\",tag=\"e2e_in\",direction=\"downlink\"} 5678"));

    server.shutdown().await;
}

#[tokio::test]
async fn get_unknown_path_returns_404() {
    let addr = pick_port();
    let server = TokioHttpServer::new();
    let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats);

    server
        .start_http_listen(&addr.to_string(), stats, None)
        .expect("start_http_listen");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = http_get(addr, "/nope").await;
    assert!(
        resp.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "expected 404, got: {}",
        resp.split("\r\n").next().unwrap_or("")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn get_metrics_includes_observation_when_collector_provided() {
    struct WithObs;
    impl StatsCollector for WithObs {
        fn collect(&self) -> StatsSnapshot {
            StatsSnapshot::default()
        }
    }
    impl xray_app_metrics::ObservationCollector for WithObs {
        fn collect(&self) -> Option<ObservationSnapshot> {
            let mut s = ObservationSnapshot::default();
            s.entries.push(xray_app_metrics::ObservationEntry {
                outbound_tag: "out_e2e".into(),
                extra: vec![("alive".into(), "true".into())],
            });
            Some(s)
        }
    }

    let addr = pick_port();
    let server = TokioHttpServer::new();
    let stats: Arc<dyn StatsCollector> = Arc::new(WithObs);
    let obs: Arc<dyn xray_app_metrics::ObservationCollector> = Arc::new(WithObs);

    server
        .start_http_listen(&addr.to_string(), stats, Some(obs))
        .expect("start_http_listen");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = http_get(addr, "/metrics").await;
    assert!(resp.contains("# TYPE xray_observation_extra gauge"));
    assert!(resp.contains("xray_observation_extra{outbound=\"out_e2e\",key=\"alive\"} true"));

    server.shutdown().await;
}
