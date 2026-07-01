//! xray-app-metrics 主 handler + IO 边界注入 trait。
//!
//! 对应 Go `app/metrics/metrics.go`：`MetricsHandler` 在 `Start` 时
//!   1. 若配置了 `listen`，直接 listen TCP + http.Serve(DefaultServeMux)
//!   2. 创建 `OutboundListener`，再 http.Serve(listener)
//!   3. 通过 `outbound.Manager` 移除/注册 `Outbound` 作为 dialer
//!
//! HTTP server + expvar + outbound.Manager 在 Rust 端由上层注入 trait 实现，
//! 本 crate 只保留纯业务：counter name 解析、stats 快照结构、observation 快照结构、
//! 启动编排顺序。

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::MetricsConfig;
use crate::error::{at_error, at_warning, MetricsError};
use crate::outbound::{Outbound, OutboundListener};

/// 流量上下行计数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficCount {
    pub uplink: i64,
    pub downlink: i64,
}

/// Stats 快照：按 inbound/outbound/user 三类聚合的流量计数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub inbound: HashMap<String, TrafficCount>,
    pub outbound: HashMap<String, TrafficCount>,
    pub user: HashMap<String, TrafficCount>,
}

/// Observation 单条记录：outbound_tag + 灵活的 extra 键值对。
///
/// 上层 observatory 实现负责填充 extra 字段（alive/delay/last_seen 等），
/// metrics crate 只关心 outbound_tag 用于 map 索引。
#[derive(Debug, Clone, Default)]
pub struct ObservationEntry {
    pub outbound_tag: String,
    pub extra: Vec<(String, String)>,
}

/// Observation 快照。
#[derive(Debug, Clone, Default)]
pub struct ObservationSnapshot {
    pub entries: Vec<ObservationEntry>,
}

/// Counter name 解析。
///
/// 对应 Go `strings.Split(name, ">>>")`，提取 `type/tag_or_user/direction`。
/// name 格式必须为 4 段 `{type}>>>{tag_or_user}>>>traffic>>>{direction}`；
/// 3 段的 `user>>>{email}>>>ip` 在 Go 版会 panic，Rust 翻译稳健地跳过。
pub fn parse_counter_name(name: &str) -> Option<(&'static str, &str, &'static str)> {
    let parts: Vec<&str> = name.split(">>>").collect();
    if parts.len() != 4 {
        return None;
    }
    let type_name = match parts[0] {
        "inbound" => "inbound",
        "outbound" => "outbound",
        "user" => "user",
        _ => return None,
    };
    let direction = match parts[3] {
        "uplink" => "uplink",
        "downlink" => "downlink",
        _ => return None,
    };
    Some((type_name, parts[1], direction))
}

/// 把一组 (counter name, value) 聚合为 StatsSnapshot。
///
/// 跳过格式错误的 counter name（与 Go 版差异：Go 版会 panic，此处更稳健）。
pub fn aggregate_counters<'a, I>(entries: I) -> StatsSnapshot
where
    I: IntoIterator<Item = (&'a str, i64)>,
{
    let mut out = StatsSnapshot::default();
    for (name, value) in entries {
        let Some((type_name, tag, direction)) = parse_counter_name(name) else {
            continue;
        };
        let bucket = match type_name {
            "inbound" => &mut out.inbound,
            "outbound" => &mut out.outbound,
            "user" => &mut out.user,
            _ => continue,
        };
        let entry = bucket.entry(tag.to_string()).or_default();
        match direction {
            "uplink" => entry.uplink += value,
            "downlink" => entry.downlink += value,
            _ => {}
        }
    }
    out
}

/// Stats 采集 trait：上层实现，调用方应返回当前快照。
pub trait StatsCollector: Send + Sync {
    fn collect(&self) -> StatsSnapshot;
}

/// Observation 采集 trait：上层实现，无 observatory 时返回 None。
pub trait ObservationCollector: Send + Sync {
    fn collect(&self) -> Option<ObservationSnapshot>;
}

/// Metrics HTTP server 注入 trait。
///
/// 对应 Go 版的 `expvar.Publish("stats", ...)` + `expvar.Publish("observatory", ...)`
/// + `http.Serve(listener, http.DefaultServeMux)`。Rust 翻译把 HTTP server 实例
/// 与 expvar handler 注册的具体机制留给上层实现（hyper/axum/tonic 等）。
pub trait MetricsHttpServer: Send + Sync {
    /// 直接 listen TCP + http.Serve（对应 Go 版 `p.listen != ""` 分支）。
    fn start_http_listen(
        &self,
        listen: &str,
        stats: Arc<dyn StatsCollector>,
        obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError>;

    /// 通过 Outbound 路由 HTTP（对应 Go 版 `http.Serve(listener, ...)` 分支）。
    /// 实现应从 outbound.listener() 接受连接并处理。
    fn serve_outbound(
        &self,
        outbound: Arc<Outbound>,
        stats: Arc<dyn StatsCollector>,
        obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError>;
}

/// Outbound manager 注入 trait：对应 Go `outbound.Manager.AddHandler/RemoveHandler`。
pub trait OutboundRegistrar: Send + Sync {
    fn remove(&self, tag: &str) -> Result<(), MetricsError>;
    fn add(&self, outbound: Arc<Outbound>) -> Result<(), MetricsError>;
}

/// Noop 实现：测试用，所有方法都返回 Ok。
pub struct NoopHttpServer;
impl MetricsHttpServer for NoopHttpServer {
    fn start_http_listen(
        &self,
        _listen: &str,
        _stats: Arc<dyn StatsCollector>,
        _obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError> {
        Ok(())
    }
    fn serve_outbound(
        &self,
        _outbound: Arc<Outbound>,
        _stats: Arc<dyn StatsCollector>,
        _obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError> {
        Ok(())
    }
}

/// Noop 实现：测试用，记录最后一次 add/remove 的 tag。
pub struct RecordingOutboundRegistrar {
    last_remove: Mutex<Option<String>>,
    last_add: Mutex<Option<String>>,
}

impl RecordingOutboundRegistrar {
    pub fn new() -> Self {
        Self {
            last_remove: Mutex::new(None),
            last_add: Mutex::new(None),
        }
    }
    pub fn last_removed_tag(&self) -> Option<String> {
        self.last_remove.lock().clone()
    }
    pub fn last_added_tag(&self) -> Option<String> {
        self.last_add.lock().clone()
    }
}

impl Default for RecordingOutboundRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundRegistrar for RecordingOutboundRegistrar {
    fn remove(&self, tag: &str) -> Result<(), MetricsError> {
        *self.last_remove.lock() = Some(tag.to_string());
        Ok(())
    }
    fn add(&self, outbound: Arc<Outbound>) -> Result<(), MetricsError> {
        *self.last_add.lock() = Some(outbound.tag().to_string());
        Ok(())
    }
}

/// MetricsHandler：metrics crate 的主入口。
///
/// 不持有 stats/observability/http 实例的引用，而是把这些依赖作为 trait 参数
/// 在 `start()` 时注入，避免生命周期与循环依赖问题。
pub struct MetricsHandler {
    config: MetricsConfig,
    outbound: Mutex<Option<Arc<Outbound>>>,
}

impl MetricsHandler {
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            outbound: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// 已注册的 outbound（如果 start 已成功）。
    pub fn registered_outbound(&self) -> Option<Arc<Outbound>> {
        self.outbound.lock().clone()
    }

    /// 启动 metrics：编排 Go 版 Start 的 4 个步骤。
    ///
    /// 1. 若 listen 非空：调 `http_server.start_http_listen`
    /// 2. 创建 OutboundListener + Outbound（Arc 共享）
    /// 3. 调 `http_server.serve_outbound`
    /// 4. 调 `registrar.remove(tag)`（容忍失败）
    /// 5. 调 `registrar.add(outbound)`
    pub fn start(
        &self,
        http_server: &dyn MetricsHttpServer,
        stats: Arc<dyn StatsCollector>,
        obs: Option<Arc<dyn ObservationCollector>>,
        outbound_registrar: &dyn OutboundRegistrar,
    ) -> Result<(), MetricsError> {
        if !self.config.listen.is_empty() {
            http_server.start_http_listen(&self.config.listen, stats.clone(), obs.clone())?;
        }

        let listener = OutboundListener::new();
        let outbound = Arc::new(Outbound::new(self.config.tag.clone(), listener));
        outbound.start();

        http_server.serve_outbound(outbound.clone(), stats, obs)?;

        // 容忍 remove 失败（tag 可能本来就不存在，与 Go 版 `errors.LogInfo` 一致）
        if let Err(e) = outbound_registrar.remove(&self.config.tag) {
            at_warning(&MetricsError::ListenInvalid(format!(
                "failed to remove existing handler '{}': {e}",
                self.config.tag
            )));
        }

        outbound_registrar
            .add(outbound.clone())
            .map_err(|e| {
                at_error(&e);
                e
            })?;

        *self.outbound.lock() = Some(outbound);
        Ok(())
    }

    /// Close：与 Go 版一致，no-op（资源由注入的 http_server/registrar 自行管理）。
    pub fn close(&self) {
        if let Some(ob) = self.outbound.lock().take() {
            ob.close();
        }
    }
}

/// Prometheus 指标暴露格式（exposition format）。
///
/// 把 [`StatsSnapshot`] 与可选的 [`ObservationSnapshot`] 序列化为
/// Prometheus 文本格式（每个指标带 HELP/TYPE 头 + 标签行）。
///
/// 仅暴露 counter 类型指标，对应 Go 版 `expvar.Publish("stats", ...)` 的
/// 流量统计；observation 数据用 gauge 类型（与 Prometheus 习惯一致）。
///
/// 标签设计：`type`（inbound/outbound/user）+ `tag`（具体 handler 标签）。
pub fn format_prometheus(stats: &StatsSnapshot, obs: Option<&ObservationSnapshot>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("# HELP xray_traffic_bytes Total traffic in bytes by direction\n");
    out.push_str("# TYPE xray_traffic_bytes counter\n");
    emit_traffic(&mut out, "inbound", &stats.inbound);
    emit_traffic(&mut out, "outbound", &stats.outbound);
    emit_traffic(&mut out, "user", &stats.user);
    if let Some(obs) = obs {
        out.push_str("\n# HELP xray_observation_extra Per-outbound observation key/value pairs\n");
        out.push_str("# TYPE xray_observation_extra gauge\n");
        for entry in &obs.entries {
            for (k, v) in &entry.extra {
                out.push_str(&format!(
                    "xray_observation_extra{{outbound=\"{}\",key=\"{}\"}} {}\n",
                    escape_label(entry.outbound_tag.as_str()),
                    escape_label(k.as_str()),
                    escape_value(v.as_str()),
                ));
            }
        }
    }
    out
}

fn emit_traffic<'a, I>(out: &mut String, type_name: &str, iter: I)
where
    I: IntoIterator<Item = (&'a String, &'a TrafficCount)>,
{
    for (tag, count) in iter {
        if count.uplink > 0 {
            out.push_str(&format!(
                "xray_traffic_bytes{{type=\"{}\",tag=\"{}\",direction=\"uplink\"}} {}\n",
                type_name,
                escape_label(tag.as_str()),
                count.uplink
            ));
        }
        if count.downlink > 0 {
            out.push_str(&format!(
                "xray_traffic_bytes{{type=\"{}\",tag=\"{}\",direction=\"downlink\"}} {}\n",
                type_name,
                escape_label(tag.as_str()),
                count.downlink
            ));
        }
    }
}

/// 转义 Prometheus label 值：`\`、`\"`、`\n` 按 Prometheus 规范转义。
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// 转义 Prometheus 指标值（非引号/反斜杠/换行字符直接保留）。
fn escape_value(s: &str) -> String {
    escape_label(s)
}

/// 基于 tokio 的最小 Prometheus HTTP server 实现 [`MetricsHttpServer`]。
///
/// 设计目标：验收 `curl /metrics` 拿到 Prometheus exposition format 文本响应。
/// 不使用 hyper/axum 以避免额外依赖（ponytail ladder rung 4：tokio 已提供所需原语）。
///
/// ## 行为
/// - `start_http_listen`: 绑定 `listen` 地址，spawn accept loop，
///   每个 conn task 解析请求行后返回 `200 OK` + Prometheus 文本。
///   仅处理 `GET /metrics`；其他路径返回 `404 Not Found`。
/// - `serve_outbound`: 当前 stub（仅 log），真实实现需等 dispatcher 切片3
///   把 OutboundListener.accept 桥接到 tokio task。
///
/// ## 优雅关闭
/// `TokioHttpServer::shutdown()` 通过 Notify 唤醒所有 task，等待 5s 超时。
/// 未显式 shutdown 时随 tokio runtime drop 自动释放。
pub struct TokioHttpServer {
    inner: Arc<TokioHttpServerInner>,
}

struct TokioHttpServerInner {
    shutdown: Arc<tokio::sync::Notify>,
    join_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl TokioHttpServer {
    /// 创建一个新的 TokioHttpServer，未启动任何 listener。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TokioHttpServerInner {
                shutdown: Arc::new(tokio::sync::Notify::new()),
                join_handles: Mutex::new(Vec::new()),
            }),
        }
    }

    /// 优雅关闭：notify + 等待所有 task 退出（超时 5s/task）。
    pub async fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
        let handles: Vec<_> = self.inner.join_handles.lock().drain(..).collect();
        let timeout = std::time::Duration::from_secs(5);
        for h in handles {
            let _ = tokio::time::timeout(timeout, h).await;
        }
    }
}

impl Default for TokioHttpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsHttpServer for TokioHttpServer {
    fn start_http_listen(
        &self,
        listen: &str,
        stats: Arc<dyn StatsCollector>,
        obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError> {
        // trait 是 sync，但 tokio::TcpListener::bind 是 async。
        // 用 std::net::TcpListener::bind (sync) + set_nonblocking + tokio::net::TcpListener::from_std 转换。
        let std_listener = std::net::TcpListener::bind(listen)
            .map_err(|e| MetricsError::ListenInvalid(format!("bind {listen}: {e}")))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| MetricsError::ListenInvalid(format!("set_nonblocking: {e}")))?;
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|e| MetricsError::ListenInvalid(format!("from_std: {e}")))?;
        let shutdown = self.inner.shutdown.clone();
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.notified() => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else { continue; };
                        let stats = stats.clone();
                        let obs = obs.clone();
                        let shutdown = shutdown.clone();
                        let h = tokio::spawn(serve_one(stream, stats, obs, shutdown));
                        inner.join_handles.lock().push(h);
                    }
                }
            }
        });
        self.inner.join_handles.lock().push(handle);
        Ok(())
    }

    fn serve_outbound(
        &self,
        _outbound: Arc<Outbound>,
        _stats: Arc<dyn StatsCollector>,
        _obs: Option<Arc<dyn ObservationCollector>>,
    ) -> Result<(), MetricsError> {
        // 切片2 stub：完整实现需要桥接 OutboundListener.accept（同步 Condvar）到 tokio，
        // 推迟到 dispatcher 切片3 outbound 路径完成后再做。
        tracing::info!(
            target: "xray_app_metrics",
            "TokioHttpServer::serve_outbound: stub (postponed to dispatcher slice3)"
        );
        Ok(())
    }
}

/// 处理单个 HTTP/1.1 连接：解析请求行，返回 `/metrics` 响应或 404。
async fn serve_one(
    mut stream: tokio::net::TcpStream,
    stats: Arc<dyn StatsCollector>,
    obs: Option<Arc<dyn ObservationCollector>>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 1024];
    let body: &[u8] = tokio::select! {
        biased;
        _ = shutdown.notified() => return,
        r = stream.read(&mut buf) => match r {
            Ok(0) | Err(_) => return,
            Ok(n) => &buf[..n],
        },
    };
    let request_line = body
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or(&[]);
    let is_metrics = request_line.starts_with(b"GET /metrics ");
    let response = if is_metrics {
        let snapshot = stats.collect();
        let obs_snapshot = obs.as_ref().and_then(|o| o.collect());
        let body = format_prometheus(&snapshot, obs_snapshot.as_ref());
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}


#[cfg(test)]
mod tests {
    use super::*;

    struct ConstStats(i64);
    impl StatsCollector for ConstStats {
        fn collect(&self) -> StatsSnapshot {
            aggregate_counters([
                ("inbound>>>tag_a>>>traffic>>>uplink", self.0),
                ("inbound>>>tag_a>>>traffic>>>downlink", self.0 + 1),
            ])
        }
    }

    struct NoneObs;
    impl ObservationCollector for NoneObs {
        fn collect(&self) -> Option<ObservationSnapshot> {
            None
        }
    }

    #[test]
    fn parse_inbound_uplink() {
        let r = parse_counter_name("inbound>>>tag_a>>>traffic>>>uplink").unwrap();
        assert_eq!(r, ("inbound", "tag_a", "uplink"));
    }

    #[test]
    fn parse_outbound_downlink() {
        let r = parse_counter_name("outbound>>>tag_b>>>traffic>>>downlink").unwrap();
        assert_eq!(r, ("outbound", "tag_b", "downlink"));
    }

    #[test]
    fn parse_user_uplink() {
        let r = parse_counter_name("user>>>a@b.com>>>traffic>>>uplink").unwrap();
        assert_eq!(r, ("user", "a@b.com", "uplink"));
    }

    #[test]
    fn parse_invalid_3_segments_returns_none() {
        // user>>>{email}>>>ip 是 3 段，无法解析
        assert!(parse_counter_name("user>>>a@b.com>>>ip").is_none());
    }

    #[test]
    fn parse_invalid_unknown_type_returns_none() {
        assert!(parse_counter_name("unknown>>>x>>>traffic>>>uplink").is_none());
    }

    #[test]
    fn parse_invalid_unknown_direction_returns_none() {
        assert!(parse_counter_name("inbound>>>x>>>traffic>>>sideways").is_none());
    }

    #[test]
    fn parse_invalid_5_segments_returns_none() {
        assert!(parse_counter_name("a>>>b>>>c>>>d>>>e").is_none());
    }

    #[test]
    fn parse_empty_string_returns_none() {
        assert!(parse_counter_name("").is_none());
    }

    #[test]
    fn aggregate_single_inbound() {
        let snap = aggregate_counters([("inbound>>>tag>>>traffic>>>uplink", 100_i64)]);
        assert_eq!(snap.inbound["tag"].uplink, 100);
        assert_eq!(snap.inbound["tag"].downlink, 0);
    }

    #[test]
    fn aggregate_merges_two_entries() {
        let snap = aggregate_counters([
            ("inbound>>>tag>>>traffic>>>uplink", 100_i64),
            ("inbound>>>tag>>>traffic>>>downlink", 200),
            ("inbound>>>tag>>>traffic>>>uplink", 50), // 同 key 累加
        ]);
        assert_eq!(snap.inbound["tag"].uplink, 150);
        assert_eq!(snap.inbound["tag"].downlink, 200);
    }

    #[test]
    fn aggregate_splits_by_bucket() {
        let snap = aggregate_counters([
            ("inbound>>>i1>>>traffic>>>uplink", 1),
            ("outbound>>>o1>>>traffic>>>downlink", 2),
            ("user>>>u1>>>traffic>>>uplink", 3),
        ]);
        assert_eq!(snap.inbound.len(), 1);
        assert_eq!(snap.outbound.len(), 1);
        assert_eq!(snap.user.len(), 1);
        assert_eq!(snap.user["u1"].uplink, 3);
    }

    #[test]
    fn aggregate_skips_malformed() {
        let snap = aggregate_counters([
            ("malformed", 1),
            ("inbound>>>ok>>>traffic>>>uplink", 5),
            ("user>>>e>>>ip", 9), // 3 段
        ]);
        assert_eq!(snap.inbound.len(), 1);
        assert!(snap.user.is_empty());
    }

    #[test]
    fn aggregate_empty_input() {
        let snap = aggregate_counters(std::iter::empty::<(&str, i64)>());
        assert!(snap.inbound.is_empty());
    }

    #[test]
    fn traffic_count_default_zero() {
        let t = TrafficCount::default();
        assert_eq!(t.uplink, 0);
        assert_eq!(t.downlink, 0);
    }

    #[test]
    fn stats_snapshot_default_empty() {
        let s = StatsSnapshot::default();
        assert!(s.inbound.is_empty());
        assert!(s.outbound.is_empty());
        assert!(s.user.is_empty());
    }

    #[test]
    fn noop_http_server_listen_ok() {
        let s = NoopHttpServer;
        let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats(0));
        let r = s.start_http_listen("127.0.0.1:0", stats, None);
        assert!(r.is_ok());
    }

    #[test]
    fn noop_http_server_serve_outbound_ok() {
        let s = NoopHttpServer;
        let listener = OutboundListener::new();
        let outbound = Arc::new(Outbound::new("t", listener));
        let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats(0));
        let r = s.serve_outbound(outbound, stats, None);
        assert!(r.is_ok());
    }

    #[test]
    fn recording_registrar_records_remove() {
        let r = RecordingOutboundRegistrar::new();
        r.remove("foo").unwrap();
        assert_eq!(r.last_removed_tag().as_deref(), Some("foo"));
        assert!(r.last_added_tag().is_none());
    }

    #[test]
    fn recording_registrar_records_add_tag() {
        let r = RecordingOutboundRegistrar::new();
        let listener = OutboundListener::new();
        let outbound = Arc::new(Outbound::new("tag_x", listener));
        r.add(outbound).unwrap();
        assert_eq!(r.last_added_tag().as_deref(), Some("tag_x"));
    }

    #[test]
    fn metrics_handler_exposes_config() {
        let cfg = MetricsConfig {
            tag: "metrics_out".into(),
            listen: "127.0.0.1:9090".into(),
        };
        let h = MetricsHandler::new(cfg.clone());
        assert_eq!(h.config().tag, "metrics_out");
        assert_eq!(h.config().listen, "127.0.0.1:9090");
    }

    #[test]
    fn metrics_handler_start_registers_outbound() {
        let cfg = MetricsConfig {
            tag: "m".into(),
            listen: "".into(),
        };
        let h = MetricsHandler::new(cfg);
        let http = NoopHttpServer;
        let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats(0));
        let obs: Option<Arc<dyn ObservationCollector>> = Some(Arc::new(NoneObs));
        let reg = RecordingOutboundRegistrar::new();

        h.start(&http, stats, obs, &reg).unwrap();

        assert!(h.registered_outbound().is_some());
        assert_eq!(reg.last_removed_tag().as_deref(), Some("m"));
        assert_eq!(reg.last_added_tag().as_deref(), Some("m"));
    }

    #[test]
    fn metrics_handler_start_with_listen_calls_http_listen() {
        // 使用计数 registrar 验证 start_http_listen 被调用过：通过 NoopHttpServer 总返回 Ok
        // 这里仅验证带 listen 的 start 流程不报错
        let cfg = MetricsConfig {
            tag: "m".into(),
            listen: "127.0.0.1:0".into(),
        };
        let h = MetricsHandler::new(cfg);
        let http = NoopHttpServer;
        let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats(0));
        let reg = RecordingOutboundRegistrar::new();
        h.start(&http, stats, None, &reg).unwrap();
        assert!(h.registered_outbound().is_some());
    }

    #[test]
    fn metrics_handler_close_releases_outbound() {
        let cfg = MetricsConfig {
            tag: "m".into(),
            listen: "".into(),
        };
        let h = MetricsHandler::new(cfg);
        let http = NoopHttpServer;
        let stats: Arc<dyn StatsCollector> = Arc::new(ConstStats(0));
        let reg = RecordingOutboundRegistrar::new();
        h.start(&http, stats, None, &reg).unwrap();
        assert!(h.registered_outbound().is_some());
        h.close();
        assert!(h.registered_outbound().is_none());
    }

    #[test]
    fn metrics_handler_close_without_start_is_noop() {
        let cfg = MetricsConfig::default();
        let h = MetricsHandler::new(cfg);
        h.close();
        assert!(h.registered_outbound().is_none());
    }

    #[test]
    fn observation_entry_default_empty() {
        let e = ObservationEntry::default();
        assert!(e.outbound_tag.is_empty());
        assert!(e.extra.is_empty());
    }

    #[test]
    fn stats_snapshot_eq() {
        let mut s1 = StatsSnapshot::default();
        s1.inbound.insert(
            "a".into(),
            TrafficCount {
                uplink: 1,
                downlink: 2,
            },
        );
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    // 确保关键类型 Send + Sync
    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn types_are_send_sync() {
        _assert_send_sync::<Outbound>();
        _assert_send_sync::<OutboundListener>();
        _assert_send_sync::<MetricsHandler>();
        _assert_send_sync::<Arc<dyn StatsCollector>>();
        _assert_send_sync::<Arc<dyn ObservationCollector>>();
        _assert_send_sync::<Arc<Outbound>>();
    }

    // ===== format_prometheus 测试 =====

    #[test]
    fn format_prometheus_empty_stats_returns_only_headers() {
        let stats = StatsSnapshot::default();
        let out = format_prometheus(&stats, None);
        assert!(out.contains("# HELP xray_traffic_bytes"));
        assert!(out.contains("# TYPE xray_traffic_bytes counter"));
        assert!(!out.contains("xray_traffic_bytes{"));
    }

    #[test]
    fn format_prometheus_includes_nonzero_entries() {
        let mut stats = StatsSnapshot::default();
        stats.inbound.insert(
            "tag_a".into(),
            TrafficCount { uplink: 100, downlink: 0 },
        );
        stats.outbound.insert(
            "out_x".into(),
            TrafficCount { uplink: 0, downlink: 200 },
        );
        let out = format_prometheus(&stats, None);
        assert!(out.contains("xray_traffic_bytes{type=\"inbound\",tag=\"tag_a\",direction=\"uplink\"} 100"));
        assert!(out.contains("xray_traffic_bytes{type=\"outbound\",tag=\"out_x\",direction=\"downlink\"} 200"));
        // uplink=0 / downlink=0 不输出
        assert!(!out.contains("direction=\"downlink\"} 0\n"));
    }

    #[test]
    fn format_prometheus_escapes_special_chars_in_tag() {
        let mut stats = StatsSnapshot::default();
        stats.user.insert(
            "a\"b\\c\n".into(),
            TrafficCount { uplink: 1, downlink: 0 },
        );
        let out = format_prometheus(&stats, None);
        // 转义后应为 a\\\"b\\\\c\\n（前后会包双引号）
        assert!(out.contains("tag=\"a\\\"b\\\\c\\n\""));
    }

    #[test]
    fn format_prometheus_emits_observation_when_provided() {
        let stats = StatsSnapshot::default();
        let mut obs = ObservationSnapshot::default();
        obs.entries.push(ObservationEntry {
            outbound_tag: "out1".into(),
            extra: vec![("alive".into(), "true".into()), ("delay".into(), "42".into())],
        });
        let out = format_prometheus(&stats, Some(&obs));
        assert!(out.contains("# TYPE xray_observation_extra gauge"));
        assert!(out.contains("xray_observation_extra{outbound=\"out1\",key=\"alive\"} true"));
        assert!(out.contains("xray_observation_extra{outbound=\"out1\",key=\"delay\"} 42"));
    }

    #[test]
    fn format_prometheus_skips_observation_section_when_none() {
        let stats = StatsSnapshot::default();
        let out = format_prometheus(&stats, None);
        assert!(!out.contains("xray_observation_extra"));
    }
}
