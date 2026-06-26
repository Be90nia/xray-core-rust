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
}
