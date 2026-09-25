//! Feature::start 真实启动 HTTP listener 验收测试。
//!
//! 对应任务 0sy 验收标准：
//! 1. `MetricsFeature::start` 启动后 `curl /metrics` 能拿到 Prometheus exposition format
//! 2. `close` 关闭后端口不可达
//! 3. `start` 无 listen 配置时不报错、返回 Ok
//! 4. `start` 幂等

use std::sync::Arc;

use xray_app_metrics::{
    MetricsFeature, ObservationCollector, ObservationSnapshot, StatsCollector, StatsSnapshot,
};
use xray_features::Feature;

/// 测试用 stats：固定 inbound tag=test_in uplink=42 downlink=7。
struct FixedStats;
impl StatsCollector for FixedStats {
    fn collect(&self) -> StatsSnapshot {
        let mut s = StatsSnapshot::default();
        s.inbound.insert(
            "test_in".to_string(),
            xray_app_metrics::TrafficCount { uplink: 42, downlink: 7 },
        );
        s
    }
}

/// 拿到一个本机空闲端口（drop 后被测 server 重新 bind 同端口）。
fn pick_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp");
    let a = l.local_addr().expect("local_addr");
    drop(l);
    a
}

/// 微型 HTTP/1.1 GET 客户端：发送请求、读至 EOF，返回完整响应。
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8(buf).expect("utf8")
}

/// `tokio::time::timeout` 包裹的 connect：close 后应超时/失败。
async fn try_connect(addr: std::net::SocketAddr) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// 等待若干毫秒让 listener task 接到 shutdown 通知并退出。
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn feature_start_listens_on_configured_addr_and_serves_metrics() {
    let addr = pick_port();
    let cfg =
        xray_app_metrics::MetricsConfig { tag: "metrics_out".into(), listen: addr.to_string() };
    let feature = MetricsFeature::new(cfg).with_stats_collector(Arc::new(FixedStats));

    feature.start().expect("start ok");

    let resp = http_get(addr, "/metrics").await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "expected 200 OK, got: {resp}");
    assert!(resp.contains("text/plain; version=0.0.4"), "missing Prometheus content-type: {resp}");
    assert!(resp.contains("# HELP xray_traffic_bytes"), "missing HELP line: {resp}");
    assert!(resp.contains("# TYPE xray_traffic_bytes counter"), "missing TYPE line: {resp}");
    assert!(
        resp.contains(r#"xray_traffic_bytes{type="inbound",tag="test_in",direction="uplink"} 42"#),
        "missing uplink sample: {resp}"
    );
    assert!(
        resp.contains(r#"xray_traffic_bytes{type="inbound",tag="test_in",direction="downlink"} 7"#),
        "missing downlink sample: {resp}"
    );

    feature.close().expect("close ok");
}

#[tokio::test]
async fn feature_close_stops_http_listener() {
    let addr = pick_port();
    let cfg = xray_app_metrics::MetricsConfig { tag: "t".into(), listen: addr.to_string() };
    let feature = MetricsFeature::new(cfg);
    feature.start().expect("start ok");
    // 先确认启动后能连。
    assert!(try_connect(addr).await, "should connect before close");

    feature.close().expect("close ok");
    settle().await;

    // close 后端口不再接收连接。
    assert!(!try_connect(addr).await, "should not connect after close");
}

#[tokio::test]
async fn feature_start_without_listen_is_ok() {
    let cfg = xray_app_metrics::MetricsConfig { tag: "t".into(), listen: String::new() };
    let feature = MetricsFeature::new(cfg);
    feature.start().expect("start ok");
    feature.close().expect("close ok");
}

#[tokio::test]
async fn feature_start_is_idempotent() {
    let addr = pick_port();
    let cfg = xray_app_metrics::MetricsConfig { tag: "idem".into(), listen: addr.to_string() };
    let feature = MetricsFeature::new(cfg);
    feature.start().expect("first start ok");
    feature.start().expect("second start ok (no error)");
    feature.close().expect("close ok");
}

#[tokio::test]
async fn feature_serves_metrics_with_injected_obs_collector() {
    use xray_app_metrics::ObservationEntry;
    struct WithObs;
    impl ObservationCollector for WithObs {
        fn collect(&self) -> Option<ObservationSnapshot> {
            let mut s = ObservationSnapshot::default();
            s.entries.push(ObservationEntry {
                outbound_tag: "out_obs".into(),
                extra: vec![("alive".into(), "true".into())],
            });
            Some(s)
        }
    }

    let addr = pick_port();
    let cfg = xray_app_metrics::MetricsConfig { tag: "t".into(), listen: addr.to_string() };
    let feature = MetricsFeature::new(cfg).with_obs_collector(Arc::new(WithObs));
    feature.start().expect("start ok");

    let resp = http_get(addr, "/metrics").await;
    assert!(resp.contains("# HELP xray_observation_extra"));
    assert!(resp.contains(r#"xray_observation_extra{outbound="out_obs",key="alive"} true"#));

    feature.close().expect("close ok");
}
