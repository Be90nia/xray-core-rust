//! bd 0z7zt：metrics **tag 形态**端到端验收。
//!
//! Go `app/metrics/metrics.go:63-94`：`tag` 非空 → `OutboundListener` +
//! `ohm.AddHandler(&Outbound{tag, listener})`——路由规则 `outboundTag` 命中该 tag
//! 的连接被灌进 metrics HTTP server。本文件在 crate 内复刻整条链路：
//!
//! 1. `SimpleOhmOutboundRegistrar` 把 `Outbound` 注册进真 `SimpleOhm`；
//! 2. 从 `ohm.get_handler(tag)` 取回 handler，`dispatch` 一条 duplex `Link` （dispatcher
//!    投递路径：`Link → cnc Conn → listener → HTTP server`）；
//! 3. 客户端半边发 `GET /metrics`，断言收到 200 + Prometheus 文本。
//!
//! 反证（`tag_mode_without_registrar_is_dead`）：默认 `RecordingOutboundRegistrar`
//! 只记账不注册 → ohm 表内无该 tag → 路由不可达（接线前的生产形态）。

use std::sync::Arc;

use xray_app_dispatcher::{OutboundHandlerManager, SimpleOhm};
use xray_app_metrics::{
    MetricsConfig, MetricsHandler, ObservationCollector, ObservationSnapshot,
    RecordingOutboundRegistrar, SimpleOhmOutboundRegistrar, StatsCollector, StatsSnapshot,
    TokioHttpServer, TrafficCount,
};

/// 测试用常量 stats：固定 inbound tag=e2e_in uplink=1234 downlink=5678。
struct ConstStats;
impl StatsCollector for ConstStats {
    fn collect(&self) -> StatsSnapshot {
        StatsSnapshot {
            inbound: [("e2e_in".to_string(), TrafficCount { uplink: 1234, downlink: 5678 })]
                .into_iter()
                .collect(),
            ..StatsSnapshot::default()
        }
    }
}

struct NoneObs;
impl ObservationCollector for NoneObs {
    fn collect(&self) -> Option<ObservationSnapshot> {
        None
    }
}

const TAG: &str = "metrics-out";

/// 路由命中后的 dispatcher 侧：duplex server 半边打包成 Link，交给 ohm 里的 handler。
/// 返回 dispatch 完成信号（连接被消费/关闭后触发）。
async fn dispatch_link_through_ohm(
    ohm: &Arc<SimpleOhm>,
    server_half: tokio::io::DuplexStream,
) -> tokio::sync::oneshot::Receiver<()> {
    let dispatch_handler = ohm.get_handler(TAG).expect("metrics outbound registered in ohm");
    assert_eq!(dispatch_handler.tag(), TAG);

    let (s_r, s_w) = tokio::io::split(server_half);
    let link = xray_transport::link::Link::new(
        xray_buf::io::new_reader(s_r),
        xray_buf::io::new_writer(s_w),
    );
    let dest = xray_common::net::destination::Destination::new(
        xray_common::net::address::Address::new_domain("metrics.internal"),
        xray_common::net::port::Port::new(80),
        xray_common::net::network::Network::TCP,
    );
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    // 对应 dispatcher 投递：spawn 使连接任务与会话任务同生命周期形态。
    #[allow(clippy::disallowed_methods, reason = "测试：模拟 dispatcher 的连接级投递任务")]
    tokio::spawn(async move {
        dispatch_handler.dispatch(&dest, link).await;
        let _ = done_tx.send(());
    });
    done_rx
}

/// 正向：tag 形态全链路——注册 → 路由命中 → Link 灌入 → GET /metrics 拿 Prometheus 文本。
#[tokio::test]
async fn tag_mode_dispatch_serves_prometheus_over_link() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let ohm = Arc::new(SimpleOhm::new());
    let registrar = SimpleOhmOutboundRegistrar(Arc::clone(&ohm));
    let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats);
    let obs: Option<Arc<dyn ObservationCollector>> = Some(Arc::new(NoneObs));
    let server = TokioHttpServer::new();
    let handler = MetricsHandler::new(MetricsConfig {
        tag: TAG.to_string(),
        listen: String::new(), // tag 形态：无 listen
    });
    handler.start(&server, stats, obs, &registrar).expect("metrics start");

    let (mut client, server_half) = tokio::io::duplex(4096);
    let mut dispatch_done = dispatch_link_through_ohm(&ohm, server_half).await;

    // 客户端经"代理"访问 metrics 端点。
    client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics.internal\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    // 连接被 HTTP server 消费并关闭（Go `<-closeSignal.Wait()` 语义）后 dispatch 才返回。
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut dispatch_done)
        .await
        .expect("dispatch must complete once the conn is served")
        .expect("dispatch ok");
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
        .await
        .expect("e2e within 5s")
        .expect("read response");

    // 关停：listener.close 唤醒 spawn_blocking 的 accept（否则 runtime drop 会等
    // 这个永不返回的阻塞任务）。对应 Go metrics Close（metrics.go:105-119）。
    handler.close();
    server.shutdown().await;

    let response = String::from_utf8_lossy(&buf);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response:?}");
    assert!(
        response.contains("text/plain; version=0.0.4"),
        "content-type must be Prometheus exposition: {response:?}"
    );
    assert!(
        response.contains("# HELP xray_traffic_bytes"),
        "body must be Prometheus format: {response:?}"
    );
    assert!(
        response
            .contains(r#"xray_traffic_bytes{type="inbound",tag="e2e_in",direction="uplink"} 1234"#),
        "stats values must round-trip: {response:?}"
    );
}

/// 反证：默认 `RecordingOutboundRegistrar` 只记账不注册（= 本票修复前的生产形态）
/// ⇒ ohm 表内无该 tag ⇒ 路由不可达（连接无从灌入 metrics HTTP server）。
#[tokio::test]
async fn tag_mode_without_registrar_is_dead() {
    let ohm = Arc::new(SimpleOhm::new());
    let registrar = RecordingOutboundRegistrar::new();
    let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats);
    let obs: Option<Arc<dyn ObservationCollector>> = Some(Arc::new(NoneObs));
    let server = TokioHttpServer::new();
    let handler =
        MetricsHandler::new(MetricsConfig { tag: TAG.to_string(), listen: String::new() });
    handler.start(&server, stats, obs, &registrar).expect("metrics start");

    assert!(
        ohm.get_handler(TAG).is_none(),
        "recording registrar must NOT register into ohm (tag path stays dead)"
    );
    // 注册面确实"记账"了（形态保留，但无生产效果）。
    assert_eq!(registrar.last_added_tag().as_deref(), Some(TAG));

    // 关停 serve_outbound 的阻塞 accept（否则 runtime drop 挂死）。
    handler.close();
    server.shutdown().await;
}
