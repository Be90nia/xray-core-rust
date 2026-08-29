//! Feature 注册中心 —— 将 kind 字符串映射到 FeatureFactory。
//!
//! Go 用 `init()` 自注册（每个协议/应用在 init 中调用 `common.RegisterConfig`）。
//! Rust 没有 init，需要程序入口显式调用 [`register_all_features`]。
//!
//! 当前阶段：各 `xray-app-*` crate 尚未实现 `Feature` trait，因此注册 stub factory
//! （返回 `FeatureError::StartFailed` 提示 "not yet implemented"）。
//! 待各 crate 切片完成后，替换为真实 factory。

use std::path::PathBuf;
 use std::sync::Arc;

use xray_features::{Feature, FeatureError, FeatureFactory, registry};

/// 注册所有已知 kind 的 FeatureFactory（stub 版本）。
///
/// 必须在 `Instance::new_from_built` 之前调用，否则所有 kind 查找返回 `NotFound`。
///
/// # 注册的 kind 列表
///
/// App: log, routing, dns, policy, api, metrics, stats, fakeDns,
///      observatory, burstObservatory, version, geodata
///
/// Proxy inbound: socks, http, shadowsocks, vmess, vless, trojan,
///                dokodemo, blackhole, dns, hysteria2, tuic, wireguard, anytls, tun*, loopback
///
/// Proxy outbound: freedom, blackhole, dns, socks, http, shadowsocks,
///                 vmess, vless, trojan, hysteria2, tuic, wireguard, loopback, tun*
///
/// *tun 全平台注册（bd b8i，对齐 Go 无条件 init 注册）；支持平台
/// （Linux/Android/FreeBSD）真实构建在 inbound/outbound 构建层，
/// 不支持平台 factory/构建层明确拒绝。
pub fn register_all_features() {
    // --- App kinds ---
    // Real factories (construct actual Feature implementations)
    let _ = registry::register_feature("log", log_factory());
    let _ = registry::register_feature("dns", dns_factory());
    let _ = registry::register_feature("routing", default_feature_factory("routing"));
    let _ = registry::register_feature("policy", policy_factory());
    let _ = registry::register_feature("observatory", observatory_factory());
    let _ = registry::register_feature("metrics", metrics_factory());
    let _ = registry::register_feature("stats", default_feature_factory("stats"));
    let _ = registry::register_feature("api", commander_factory());
    let _ = registry::register_feature("fakeDns", fake_dns_factory());

    let _ = registry::register_feature("burstObservatory", burst_observatory_factory());
    let _ = registry::register_feature("version", simple_feature_factory("version"));
    let _ = registry::register_feature("geodata", geodata_factory());
    // Reverse：proto Config 程序化构造（Go v26 已移除 JSON 配置路径，见 reverse_factory）
    let _ = registry::register_feature("reverse", reverse_factory());

    // --- Proxy inbound kinds ---
    for &kind in PROXY_INBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }

    // --- Proxy outbound kinds ---
    for &kind in PROXY_OUTBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }

    // TUN（入站/出站同 kind "tun"）——全平台注册，平台差异在
    // factory/构建层拒绝（bd b8i，对齐 Go handler.go:186 无条件注册）。
    for &kind in TUN_KINDS {
        let _ = registry::register_feature(kind, tun_factory(kind));
    }
}

/// 注册所有传输层 dialer + listener。
///
/// 必须在 `register_outbounds` / `spawn_inbounds` 之前调用，
/// 否则传输注册表为空——除裸 TCP 外所有 dial/listen 返回 NotFound。
pub fn register_all_transports() {
    // TCP（系统传输）
    let _ = xray_transport::tcp::register_tcp_transport();

    // TCP dialer（出站 + security 包装：tls/reality）——独立 crate，
    // 因 xray-transport 核心不能依赖 xray-tls（循环依赖）。
    let _ = xray_transport_tcp::register::register_dialer();

    // WebSocket
    let _ = xray_transport_websocket::register::register_dialer();
    let _ = xray_transport_websocket::register::register_listener();

    // HTTPUpgrade
    let _ = xray_transport_httpupgrade::register::register_dialer();
    let _ = xray_transport_httpupgrade::register::register_listener();

    // gRPC
    let _ = xray_transport_grpc::register::register_dialer();
    let _ = xray_transport_grpc::register::register_listener();

    // SplitHTTP / XHTTP
    let _ = xray_transport_splithttp::register::register_dialer();
    let _ = xray_transport_splithttp::register::register_listener();

    // mKCP
    let _ = xray_transport_kcp::register::register_dialer();
    let _ = xray_transport_kcp::register::register_listener();

    // Hysteria transport
    let _ = xray_transport_hysteria::register::register_dialer();
    let _ = xray_transport_hysteria::register::register_listener();

    // QUIC
    let _ = xray_transport_quic::register::register_dialer();
    let _ = xray_transport_quic::register::register_listener();

    // REALITY
    let _ = xray_reality::register::register_dialer();

    tracing::info!("all transport dialers + listeners registered");
}

/// App kind 列表（与 `xray-conf/src/built.rs` push_app! 宏的 kind 一致）。
const APP_KINDS: &[&str] = &[
    "log",
    "routing",
    "dns",
    "policy",
    "api",
    "metrics",
    "stats",
    "fakeDns",
    "observatory",
    "burstObservatory",
    "version",
    "geodata",
];

/// 代理入站 kind 列表（与 `xray-conf` 解析的 protocol 值一致）。
/// TUN 单独注册（见 [`TUN_KINDS`]，全平台注册 + 平台感知 factory）。
const PROXY_INBOUND_KINDS: &[&str] = &[
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "dokodemo",
    "blackhole",
    "hysteria2",
    "tuic",
    "wireguard",
    "anytls",
    "loopback",
];

/// TUN 入站/出站 kind——**全平台注册**（bd b8i）。
///
/// 对齐 Go `proxy/tun/handler.go:186-194` init() 无条件 `RegisterConfig`：
/// 注册不挑平台，平台差异在设备创建层拒绝（Go 设备层支持五平台——
/// tun_windows.go/tun_darwin.go 均存在；tun_default.go:18-20 对五平台外
/// 在 NewTun 报 "Tun is not supported on your platform"）。
///
/// Rust 设备适配目前仅 Linux/Android/FreeBSD（Windows/macOS 留后，
/// bd b8i non-goal），不支持平台由 [`tun_factory`] 返回明确错误 +
/// 构建层拒绝（`spawn_one_inbound` 硬错 / `try_build_handler`
/// Unsupported→warn 跳过），而非不注册。
const TUN_KINDS: &[&str] = &["tun"];

/// 代理出站 kind 列表（与 `xray-conf` 解析的 protocol 值一致）。
/// TUN 单独注册（见 [`TUN_KINDS`]，全平台注册 + 平台感知 factory）。
const PROXY_OUTBOUND_KINDS: &[&str] = &[
    "freedom",
    "blackhole",
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "wireguard",
    "loopback",
];

/// TUN 平台感知 factory（bd b8i）。
///
/// - Linux/Android/FreeBSD：stub factory（"not yet implemented"）——真实
///   inbound/outbound 构建不经 registry（`spawn_one_inbound` /
///   `try_build_handler` 直连 `xray-proxy-tun`）。
/// - 其他平台（Windows/macOS 等）：明确 platform 错误。registry 消费方
///   （instance.rs）对 StartFailed 是 warn+跳过，非致命。
fn tun_factory(kind: &'static str) -> FeatureFactory {
    if cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd")) {
        stub_factory(kind)
    } else {
        Arc::new(move |_data: &[u8]| {
            Err(FeatureError::StartFailed {
                name: kind,
                message: format!(
                    "tun: not supported on {} (Rust port supports Linux/Android/FreeBSD; \
                     Windows/macOS device adaptation pending)",
                    std::env::consts::OS
                ),
            })
        })
    }
}

/// 创建 stub factory：返回 `StartFailed` 错误提示 "not yet implemented"。
fn stub_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        Err(FeatureError::StartFailed {
            name: kind,
            message: format!("{kind}: not yet implemented (stub factory registered)"),
        })
    })
}

/// Log app 真实 factory：解析 log JSON（`xray-conf` 的 `LogConfig` 字节）→
/// [`xray_app_log::LogConfig`] → [`LogFeature`]。
///
/// 对应 Go `infra/conf.LogConfig.Build()`（log.go:26-64）语义：
/// - `access`/`error`：`"none"` → LogType::None；非空 → File + path；缺省 → Console
///   （注意：Go 在 log 块存在时 access 默认 Console，与无 log 块的
///   `DefaultLogConfig`（access=None）不同，此处保持一致）
/// - `loglevel`：debug/info/error 映射级别，`none` 双双关闭，缺省 Warning
/// - `dnsLog`/`maskAddress` 直传；`format`（Rust 扩展）`"json"` → Json
fn log_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let json_cfg: xray_conf::app_config::LogConfig =
            serde_json::from_slice(data).map_err(|e| FeatureError::StartFailed {
                name: "log",
                message: format!("invalid log config: {e}"),
            })?;
        let config = build_log_config(&json_cfg);
        let feature = xray_app_log::LogFeature::new(config)?;
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

/// JSON `LogConfig` → [`xray_app_log::LogConfig`]（Go `infra/conf/log.go Build`）。
fn build_log_config(v: &xray_conf::app_config::LogConfig) -> xray_app_log::LogConfig {
    use xray_app_log::{LogConfig, LogFormat, LogType, SeverityLevel};

    let mut config = LogConfig {
        error_log_type: LogType::Console,
        access_log_type: LogType::Console,
        enable_dns_log: v.dns_log.unwrap_or(false),
        ..LogConfig::default()
    };

    match v.access.as_deref() {
        Some("none") => config.access_log_type = LogType::None,
        Some(p) if !p.is_empty() => {
            config.access_log_path = p.to_string();
            config.access_log_type = LogType::File;
        }
        _ => {}
    }
    match v.error.as_deref() {
        Some("none") => config.error_log_type = LogType::None,
        Some(p) if !p.is_empty() => {
            config.error_log_path = p.to_string();
            config.error_log_type = LogType::File;
        }
        _ => {}
    }

    match v.loglevel.as_deref().map(str::to_lowercase).as_deref() {
        Some("debug") => config.error_log_level = SeverityLevel::Debug,
        Some("info") => config.error_log_level = SeverityLevel::Info,
        Some("error") => config.error_log_level = SeverityLevel::Error,
        Some("none") => {
            config.error_log_type = LogType::None;
            config.access_log_type = LogType::None;
        }
        _ => config.error_log_level = SeverityLevel::Warning,
    }

    config.mask_address = v.mask_address.clone().unwrap_or_default();
    config.format = v
        .format
        .as_deref()
        .map(LogFormat::parse)
        .unwrap_or(LogFormat::Console);
    config
}

/// DNS app 真实 factory：解析顶层 dns JSON → [`DnsServiceConfig`] → [`DnsService`]。
///
/// 对应 Go `app/dns` 的 `init()` 注册 + `New(ctx, config)`。`xray-conf` 把顶层 dns
/// 配置作为 JSON 字节传入；本 factory 反序列化为 [`xray_app_dns::DnsAppConfig`]
/// 再 [`DnsAppConfig::build`] 构造（含真实 nameserver clients + 静态 hosts）。
///
/// 之前此处返回 no-op `DefaultDnsFeature`，丢弃整个配置（bd issue 9gu3）。
fn dns_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let cfg: xray_app_dns::DnsAppConfig = serde_json::from_slice(data).map_err(|e| {
            FeatureError::StartFailed {
                name: "dns",
                message: format!("invalid dns config: {e}"),
            }
        })?;
        let svc = cfg.build().map_err(|e| FeatureError::StartFailed {
            name: "dns",
            message: e.to_string(),
        })?;
        let dns = xray_app_dns::DnsService::new(svc);
        Ok(Arc::new(dns) as Arc<dyn Feature>)
    })
}

/// Policy app 真实 factory：解析 JSON → proto Config → [`xray_app_policy::PolicyFeature`]。
///
/// 对应 Go `app/policy` 的 `init()` + `New(ctx, config)`。JSON 来自
/// `xray-conf` 的 `PolicyConfig`（levels + system），转换为 proto
/// `xray.app.policy.Config` 后构造 [`PolicyFeature`](xray_app_policy::PolicyFeature)。
fn policy_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let json_cfg: xray_conf::app_config::PolicyConfig =
            serde_json::from_slice(data).unwrap_or_default();

        let mut proto = xray_proto::xray::app::policy::Config::default();
        for (lv_str, pl) in &json_cfg.levels {
            let lv = match lv_str.parse::<u32>() {
                Ok(n) => n,
                Err(_) => continue,
            };
            proto.level.insert(lv, policy_level_to_proto(pl));
        }
        if let Some(sys) = json_cfg.system.as_ref() {
            proto.system = Some(policy_system_to_proto(sys));
        }

        let feature = xray_app_policy::PolicyFeature::new(proto)?;
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

/// Observatory app 真实 factory：解析 JSON → [`xray_app_observatory::ObservatoryConfig`]
/// → [`ObservatoryFeature`](xray_app_observatory::ObservatoryFeature)。
///
/// 对应 Go `app/observatory` 的 `init()` + `New(ctx, config)`。
/// 探测循环：装配阶段 `set_io(selector, executor)` 后由 `Feature::start` 启动
/// （factory 时无 outbound.Manager/dispatcher 可取，对应 Go RequireFeatures）。
fn observatory_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let json_cfg: xray_conf::app_config::ObservatoryConfig =
            serde_json::from_slice(data).unwrap_or_default();

        let config = xray_app_observatory::ObservatoryConfig {
            subject_selector: json_cfg.subject_outbound.into_iter().collect(),
            probe_url: json_cfg.probe_url.unwrap_or_default(),
            probe_interval: json_cfg
                .probe_interval
                .as_deref()
                .and_then(parse_go_duration_ms)
                .unwrap_or(0),
            enable_concurrency: false,
        };

        let feature = xray_app_observatory::ObservatoryFeature::new(config);
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

/// Burst Observatory app 真实 factory：解析 `BurstObservatoryConfig` JSON →
/// [`BurstObservatoryFeature`](xray_app_observatory::BurstObservatoryFeature)。
///
/// 对应 Go `app/observatory/burst` 的 `init()` + `New(ctx, config)`。
/// 探测循环：装配阶段 `set_io(executor)` 后由 `Feature::start` 启动
/// scheduler（factory 时无 outbound.Manager/dispatcher 可取，
/// 对应 Go RequireFeatures）。
fn burst_observatory_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let json_cfg: xray_conf::app_config::BurstObservatoryConfig =
            serde_json::from_slice(data).unwrap_or_default();

        let subject_outbound = json_cfg.subject_outbound.unwrap_or_default();
        let ping_config = json_cfg.ping_config.as_ref();

        let feature = xray_app_observatory::BurstObservatoryFeature::new(
            subject_outbound,
            ping_config,
        );
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}
/// Metrics app 真实 factory：解析 JSON → proto Config →
/// [`xray_app_metrics::MetricsConfig`] → [`MetricsFeature`](xray_app_metrics::MetricsFeature)。
///
/// 对应 Go `app/metrics` 的 `init()` + `New(ctx, config)` + `Handler.Start()`。
/// `Feature::start` 调用时启动 [`xray_app_metrics::TokioHttpServer`] 绑 `MetricsConfig::listen`
/// 端口并 `tokio::spawn` accept loop，`GET /metrics` 返回 Prometheus exposition format。
fn metrics_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let json_cfg: xray_conf::app_config::MetricsConfig =
            serde_json::from_slice(data).unwrap_or_default();

        let proto = xray_proto::xray::app::metrics::Config {
            tag: String::new(),
            listen: json_cfg.listen.unwrap_or_default(),
        };

        let config = xray_app_metrics::MetricsConfig::from_proto(&proto);
        let feature = xray_app_metrics::MetricsFeature::new(config);
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

/// JSON `PolicyLevel` → proto `Policy`。
fn policy_level_to_proto(
    pl: &xray_conf::app_config::PolicyLevel,
) -> xray_proto::xray::app::policy::Policy {
    use xray_proto::xray::app::policy::{policy, Policy, Second};

    let mut p = Policy::default();
    p.timeout = Some(policy::Timeout {
        handshake: pl.handshake.map(|v| Second { value: v }),
        connection_idle: pl.conn_idle.map(|v| Second { value: v }),
        uplink_only: pl.uplink.map(|v| Second { value: v }),
        downlink_only: pl.downlink.map(|v| Second { value: v }),
    });

    if pl.stats_user_uplink.is_some()
        || pl.stats_user_downlink.is_some()
        || pl.stats_user_online.is_some()
    {
        p.stats = Some(policy::Stats {
            user_uplink: pl.stats_user_uplink.unwrap_or(false),
            user_downlink: pl.stats_user_downlink.unwrap_or(false),
            user_online: pl.stats_user_online.unwrap_or(false),
        });
    }

    if let Some(bs) = pl.buffer_size {
        p.buffer = Some(policy::Buffer {
            connection: bs as i32,
        });
    }
    p
}

/// JSON `PolicySystem` → proto `SystemPolicy`。
fn policy_system_to_proto(
    sys: &xray_conf::app_config::PolicySystem,
) -> xray_proto::xray::app::policy::SystemPolicy {
    use xray_proto::xray::app::policy::{system_policy, SystemPolicy};
    SystemPolicy {
        stats: Some(system_policy::Stats {
            inbound_uplink: sys.stats_inbound_uplink.unwrap_or(false),
            inbound_downlink: sys.stats_inbound_downlink.unwrap_or(false),
            outbound_uplink: sys.stats_outbound_uplink.unwrap_or(false),
            outbound_downlink: sys.stats_outbound_downlink.unwrap_or(false),
        }),
    }
}
/// 解析 Go duration 字符串（如 `"1m"`, `"30s"`, `"500ms"`）为毫秒。
/// 不支持复合形式（如 `"1m30s"`）；解析失败返回 `None`。
fn parse_go_duration_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let split_pos = s.bytes().rposition(|b| !b.is_ascii_alphabetic())?;
    let (num_part, unit) = (&s[..=split_pos], &s[split_pos + 1..]);
    let num: f64 = num_part.parse().ok()?;
     let ms = match unit {
        "ms" => num,
        "s" => num * 1_000.0,
        "m" => num * 60_000.0,
        "h" => num * 3_600_000.0,
        _ => return None,
    };
    Some(ms as i64)
}

/// 为 routing/stats 创建 Default*Feature 工厂。
///
/// routing 是 xray-features 占位实现（路由由 dispatcher 直接匹配）；
/// stats 是真实 [`AppStatsFeature`]（包 `xray_app_stats::Manager`，计数器可注册/查询）。
/// policy 走 [`policy_factory`]，dns 走 [`dns_factory`]。
fn default_feature_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        match kind {
            "routing" => Ok(Arc::new(xray_features::routing::DefaultRouterFeature) as Arc<dyn Feature>),
            "stats" => Ok(Arc::new(AppStatsFeature::new()) as Arc<dyn Feature>),
            _ => Err(FeatureError::StartFailed {
                name: kind,
                message: format!("{kind}: no Default*Feature available"),
            }),
        }
    })
}

/// 真实 stats Feature：包装 `xray_app_stats::Manager`（对应 Go `app/stats.Instance`）。
///
/// 替代 `DefaultStatsFeature`（NoopManager）——counter/online_map/channel 可真实注册与计数，
/// api/其它 feature 经 [`xray_features::stats::Manager`] trait 消费。
pub struct AppStatsFeature {
    manager: std::sync::Arc<xray_app_stats::Manager>,
}

impl AppStatsFeature {
    #[must_use]
    pub fn new() -> Self {
        Self { manager: std::sync::Arc::new(xray_app_stats::Manager::new_running()) }
    }

    /// 内部真实 Manager（供 commander/stats service 消费）。
    #[must_use]
    pub fn manager(&self) -> &std::sync::Arc<xray_app_stats::Manager> {
        &self.manager
    }
}

/// Reverse app factory：prost 解码 `xray.app.reverse.Config` → [`ReverseFeature`]。
///
/// 对应 Go `app/reverse` 的 `init()` + `New(ctx, config)`。Go v26 已移除 JSON
/// reverse 配置（`infra/conf/xray.go:569-571` PrintRemovedFeatureError，迁移至
/// VLESS Reverse Proxy），app/reverse 仅经 VLESS（`v1.rvs.cool`）程序化消费——
/// 故本 factory 不经 xray-conf（顶层 `reverse` 字段被 `ConfError::Removed` 拦截），
/// 消费方（VLESS 反向代理 / 程序化装配）直接以 proto 字节调用。
///
/// dispatcher/registrar 在 factory 时刻不可得（对应 Go `core.RequireFeatures`），
/// 经 [`ReverseFeature::set_deps`] 注入后 `Feature::start` 生效；未注入时
/// start 为 warn+跳过。
fn reverse_factory() -> FeatureFactory {
    use prost::Message as _;
    Arc::new(|data: &[u8]| {
        let proto = xray_proto::xray::app::reverse::Config::decode(data).map_err(|e| {
            FeatureError::StartFailed {
                name: "reverse",
                message: format!("config decode: {e}"),
            }
        })?;
        let feature = xray_app_reverse::ReverseFeature::new(
            xray_app_reverse::ReverseConfig::from_proto(&proto),
        );
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

impl Default for AppStatsFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl xray_features::Feature for AppStatsFeature {
    fn feature_name(&self) -> &'static str {
        "stats"
    }
}

impl xray_features::stats::Manager for AppStatsFeature {
    fn register_counter(&self, name: &str) -> Result<std::sync::Arc<dyn xray_features::stats::Counter>, xray_features::stats::ManagerError> {
        self.manager.register_counter(name)
    }
    fn unregister_counter(&self, name: &str) {
        self.manager.unregister_counter(name)
    }
    fn get_counter(&self, name: &str) -> Option<std::sync::Arc<dyn xray_features::stats::Counter>> {
        self.manager.get_counter(name)
    }
    fn visit_counters(&self, f: &mut dyn FnMut(&str, &dyn xray_features::stats::Counter) -> bool) {
        self.manager.visit_counters(f)
    }
    fn register_online_map(&self, name: &str) -> Result<std::sync::Arc<dyn xray_features::stats::OnlineMap>, xray_features::stats::ManagerError> {
        self.manager.register_online_map(name)
    }
    fn unregister_online_map(&self, name: &str) {
        self.manager.unregister_online_map(name)
    }
    fn get_online_map(&self, name: &str) -> Option<std::sync::Arc<dyn xray_features::stats::OnlineMap>> {
        self.manager.get_online_map(name)
    }
    fn visit_online_maps(&self, f: &mut dyn FnMut(&str, &dyn xray_features::stats::OnlineMap) -> bool) {
        self.manager.visit_online_maps(f)
    }
    fn register_channel(&self, name: &str) -> Result<std::sync::Arc<dyn xray_features::stats::Channel>, xray_features::stats::ManagerError> {
        self.manager.register_channel(name)
    }
    fn unregister_channel(&self, name: &str) {
        self.manager.unregister_channel(name)
    }
    fn get_channel(&self, name: &str) -> Option<std::sync::Arc<dyn xray_features::stats::Channel>> {
        self.manager.get_channel(name)
    }
    fn get_all_online_users(&self) -> Vec<String> {
        self.manager.get_all_online_users()
    }
}
/// Commander (api) 真实 factory：解析 JSON `ApiConfig` → [`Commander`]。
///
/// 对应 Go `app/commander` 的 `init()` + `New(ctx, config)`。`xray-conf` 把 `api`
/// 配置序列化为 [`ApiConfig`](xray_conf::app_config::ApiConfig) JSON 字节；本 factory
/// 反序列化后构造 [`Commander`]（携带 listen 地址），其 `Feature::start` 在 listen
/// 地址启动 tonic gRPC server（注册 HandlerService：add/remove/list outbound）。
///
/// services 列表中的 `HandlerService` / `ReflectionService` 记录到 Commander 的
/// service 容器（供编排校验）；listen 为空时走 outbound 模式（transport 全链路待接入）。
fn commander_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let cfg: xray_conf::app_config::ApiConfig = serde_json::from_slice(data).unwrap_or_default();
        let tag = cfg.tag.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| "api".to_string());
        let mut commander = xray_app_commander::Commander::new(tag, cfg.listen.clone());
        // 记录声明的 service（编排/诊断用）。实际 gRPC service 由 Feature::start 固定注册。
        if let Some(services) = &cfg.services {
            for svc in services {
                let marker: Option<std::sync::Arc<dyn xray_app_commander::Service>> = match svc.as_str() {
                    "HandlerService" => Some(std::sync::Arc::new(
                        xray_app_commander::HandlerServiceMarker,
                    )),
                    "ReflectionService" => Some(std::sync::Arc::new(
                        xray_app_commander::ReflectionService::new(),
                    )),
                    other => {
                        tracing::warn!(service = %other, "commander: unknown api service, ignored");
                        None
                    }
                };
                if let Some(m) = marker {
                    commander.add_service(m);
                }
            }
        }
        Ok(std::sync::Arc::new(commander) as std::sync::Arc<dyn Feature>)
    })
}

/// FakeDNS app 真实 factory：解析 `ipPool`/`poolSize` JSON → 初始化 [`Holder`]。
///
/// 对应 Go `app/dns/fakedns` 的 `init()` + `New(ctx, config)`。
/// 缺省池 `240.0.0.0/4` + LRU 65535（Go `FakeIPv4Pool` 同值）。
/// dispatcher 嗅探注入经 [`FakeDnsFeature::engine`] 取引擎视图。
fn fake_dns_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let cfg: xray_conf::app_config::FakeDnsConfig =
            serde_json::from_slice(data).map_err(|e| FeatureError::StartFailed {
                name: "fakeDns",
                message: format!("parse FakeDnsConfig: {e}"),
            })?;
        let holder = build_fake_dns_holder(&cfg)?;
        Ok(Arc::new(FakeDnsFeature { holder }) as Arc<dyn Feature>)
    })
}

/// FakeDnsConfig → 已初始化 Holder。缺省池 `240.0.0.0/4` + LRU 65535
/// （Go `FakeIPv4Pool` 同值）。
fn build_fake_dns_holder(cfg: &xray_conf::app_config::FakeDnsConfig) -> Result<Arc<xray_app_dns::fakedns::Holder>, FeatureError> {
    let pool = xray_app_dns::fakedns::FakeDnsPool {
        ip_pool: cfg
            .ip_pool
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "240.0.0.0/4".to_string()),
        lru_size: u64::from(cfg.pool_size.unwrap_or(65535)),
    };
    let mut holder = xray_app_dns::fakedns::Holder::with_config(pool);
    holder.initialize().map_err(|e| FeatureError::StartFailed {
        name: "fakeDns",
        message: format!("initialize fake dns pool: {e}"),
    })?;
    Ok(Arc::new(holder))
}

/// FakeDNS Feature：持有真实 [`Holder`]（LRU 域名↔Fake IP 双向映射引擎）。
struct FakeDnsFeature {
    holder: Arc<xray_app_dns::fakedns::Holder>,
}

impl Feature for FakeDnsFeature {
    fn feature_name(&self) -> &'static str {
        "fakeDns"
    }
}

impl FakeDnsFeature {
    /// 引擎视图：DNS app / dispatcher 嗅探共用同一 Holder。
    #[must_use]
    pub fn engine(&self) -> Arc<xray_app_dns::fakedns::Holder> {
        Arc::clone(&self.holder)
    }
}
/// Geodata app 真实 factory：解析 JSON → [`xray_app_geodata::GeodataConfig`]
/// → [`GeodataFeature`](xray_app_geodata::GeodataFeature)。
///
/// 对应 Go `app/geodata` 的 `init()` + `New(ctx, config)`。JSON 来自
/// `xray-conf` 的 `GeodataConfig`（当前 shape 为 `{code, dir}`，**对齐 Go
/// `{cron, outbound, assets}` 见 bd issue 待后续修复**）。本 batch 把
/// `dir`（如设置）作为 asset dir hint，其余字段若空则构造空 `GeodataConfig`，
/// 此时 `GeodataInstance.start_with_callback` 走 `if config.cron == ""` 早退
/// 分支不调度（与 Go 等价）。
///
/// 之前此处返回 no-op `SimpleFeature`，`GeodataInstance` 从不实例化，
/// cron 自动下载 + swap reload 全是死代码（bd issue Xray-core-rust-gpc）。
fn geodata_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        use xray_app_geodata::{
            CronScheduler, GeodataConfig, GeodataFeature, RealAssetDownloader,
            downloader::{AssetDownloader, GeodataReloader, ReloadBothRegistries},
            instance::Scheduler,
        };
        use std::path::PathBuf;

        // 解析 JSON（`xray_conf::app_config::GeodataConfig`：当前 `{code, dir}`）。
        // 失败回退默认空配置——保证 GeodataFeature 实例化成功。
        let json_cfg: xray_conf::app_config::GeodataConfig =
            serde_json::from_slice(data).unwrap_or_default();

        let asset_dir: Option<PathBuf> = json_cfg.dir.as_ref().map(PathBuf::from);
        let _code_hint: Option<String> = json_cfg.code.clone();

        // 当前 xray-conf shape 与 Go `{cron, outbound, assets}` 不对齐，
        // 走空 config；`GeodataInstance::start_with_callback` 在 cron 空时
        // 不调度（与 Go `if config.Cron == ""` 等价）。
        // 真正 cron/JSON 字段映射留给后续 batch。
        let config = GeodataConfig::default();

        // 真实实现替换之前的 stub。
        let scheduler: Arc<dyn Scheduler> = Arc::new(CronScheduler::new());
        let downloader: Arc<dyn AssetDownloader> = Arc::new(
            RealAssetDownloader::new(asset_dir.unwrap_or_else(default_asset_dir)),
        );
        let reloader: Arc<dyn GeodataReloader> = Arc::new(ReloadBothRegistries);

        let feature = GeodataFeature::new(config, scheduler, downloader, reloader);
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

/// 默认 asset 目录：`XRAY_LOCATION_ASSET` 或 std::env::temp_dir() + "xray-geodata"。
fn default_asset_dir() -> PathBuf {
    xray_common::platform::get_resource_path()
}

/// 为 api/metrics/version
/// 创建 SimpleFeature 工厂（实现 Feature trait 的最简 no-op）。
fn simple_feature_factory(kind: &'static str) -> FeatureFactory {
    let kind = kind.to_string();
    Arc::new(move |_data: &[u8]| {
        Ok(Arc::new(SimpleFeature { name: kind.clone() }) as Arc<dyn Feature>)
    })
}

/// 最简 Feature 实现（仅 feature_name + no-op）。
struct SimpleFeature {
    name: String,
}

impl Feature for SimpleFeature {
    fn feature_name(&self) -> &'static str {
        "simple"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_features_makes_all_kinds_findable() {
        register_all_features();

        for &kind in APP_KINDS
            .iter()
            .chain(PROXY_INBOUND_KINDS)
            .chain(TUN_KINDS)
            .chain(PROXY_OUTBOUND_KINDS)
        {
            // stub factory 应能被找到（不再返回 NotFound）
            let result = registry::create_feature(kind, b"{}");
            assert!(
                !matches!(result, Err(FeatureError::NotFound { .. })),
                "kind={kind} should be registered, got NotFound"
            );
            // stub factory 返回 StartFailed
            if let Err(FeatureError::StartFailed { name, .. }) = result {
                assert_eq!(name, kind);
            }
        }
    }

    /// bd issue Xray-core-rust-b8i：TUN kind **全平台注册**（对齐 Go
    /// `proxy/tun/handler.go:186-194` init() 无条件 `RegisterConfig`——
    /// 注册不挑平台，平台差异在设备创建层拒绝，tun_default.go:18-20）。
    /// 修复前 Windows/macOS 上 `create_feature("tun")` 返回 NotFound。
    #[test]
    fn tun_kind_registered_on_all_platforms() {
        register_all_features();

        let result = registry::create_feature("tun", b"{}");
        assert!(
            !matches!(result, Err(FeatureError::NotFound { .. })),
            "tun must be registered on all platforms (Go registers unconditionally)"
        );
        if let Err(FeatureError::StartFailed { name, message }) = result {
            assert_eq!(name, "tun");
            if cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd")) {
                assert!(message.contains("not yet implemented"), "got: {message}");
            } else {
                assert!(message.contains("not supported"), "got: {message}");
            }
        }
    }

    #[test]
    fn dns_factory_parses_config_and_returns_feature() {
        register_all_features();

        // 空 JSON → 默认 DnsServiceConfig，注册成功。
        let feat = registry::create_feature("dns", b"{}").expect("empty dns config should build");
        assert_eq!(feat.feature_name(), "dns");

        // 含 servers + hosts 的真实配置 → 构造含 nameserver clients 的 DnsService。
        let json = br#"{
            "servers": [{"address": "8.8.8.8", "port": 53}],
            "hosts": {"example.com": "1.2.3.4"},
            "queryStrategy": "UseIP4",
            "tag": "test_dns"
        }"#;
        let feat = registry::create_feature("dns", json).expect("real dns config should build");
        assert_eq!(feat.feature_name(), "dns");
    }

    #[test]
    fn dns_factory_rejects_malformed_json() {
        register_all_features();
        let result = registry::create_feature("dns", b"{not json");
        assert!(matches!(result, Err(FeatureError::StartFailed { name, .. }) if name == "dns"));
    }
    #[test]
    fn stats_factory_wires_real_manager() {
        register_all_features();

        // factory 路径：kind=stats 构建成功且 name 正确（原 DefaultStatsFeature 是 Noop）。
        let feat = registry::create_feature("stats", b"{}").expect("stats config should build");
        assert_eq!(feat.feature_name(), "stats");
    }

    /// bd issue Xray-core-rust-gpc 验收：geodata 注册为真实 factory，
    /// 不再是 SimpleFeature no-op。`create_feature("geodata", ...)` 应
    /// 返回 `feature_name() == "geodata"` 的真实 GeodataFeature。
    #[test]
    fn geodata_factory_returns_real_feature_not_simple_noop() {
        register_all_features();

        let feat = registry::create_feature("geodata", b"{}")
            .expect("geodata config should build");
        assert_eq!(
            feat.feature_name(),
            "geodata",
            "factory must return real GeodataFeature (was SimpleFeature name='simple' before fix)"
        );
    }
    #[test]
    fn app_stats_feature_counts_for_real() {
        use xray_features::stats::Manager as _;

        let mgr = AppStatsFeature::new();
        let name = "user>>>email[test@a.com]>>>traffic>>>uplink";
        let counter = mgr.register_counter(name).expect("counter should register");
        counter.add(1024);
        counter.add(23);
        assert_eq!(counter.value(), 1047, "counter must actually accumulate (Noop stays 0)");

        // 查询路径：get_counter 命中且值非零。
        let got = mgr.get_counter(name).expect("counter should be queryable");
        assert_eq!(got.value(), 1047);

        // 遍历路径：visit_counters 能看到注册的 counter。
        let mut seen = 0;
        mgr.visit_counters(&mut |n, c| {
            if n == name {
                seen += 1;
                assert_eq!(c.value(), 1047);
            }
            true
        });
        assert_eq!(seen, 1, "visit_counters should see the registered counter");

        // unregister 后查询为空。
        mgr.unregister_counter(name);
        assert!(mgr.get_counter(name).is_none());
    }

    #[test]
    fn fake_dns_factory_builds_working_engine() {
        register_all_features();

        let json = br#"{"ipPool":"198.18.0.0/15","poolSize":1024}"#;
        let feat = registry::create_feature("fakeDns", json).expect("fakeDns config should build");
        assert_eq!(feat.feature_name(), "fakeDns");
        assert_ne!(feat.feature_name(), "simple", "should not be SimpleFeature");

        // 直接验证引擎可做域名↔Fake IP 双向映射。
        let cfg: xray_conf::app_config::FakeDnsConfig = serde_json::from_slice(json).unwrap();
        let engine = build_fake_dns_holder(&cfg).expect("holder should initialize");
        use xray_app_dns::nameserver::fakedns::FakeDnsEngine as _;
        let ips = engine.get_fake_ip_for_domain("example.com");
        assert!(!ips.is_empty(), "engine should allocate fake IPs");
        let ip = ips[0];
        assert!(engine.is_ip_in_pool(ip));
        assert_eq!(
            engine.get_domain_from_fake_dns(ip).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn fake_dns_factory_uses_default_pool_when_config_empty() {
        let cfg: xray_conf::app_config::FakeDnsConfig = serde_json::from_slice(b"{}").unwrap();
        let engine = build_fake_dns_holder(&cfg).expect("default pool should initialize");
        use xray_app_dns::nameserver::fakedns::FakeDnsEngine as _;
        let ips = engine.get_fake_ip_for_domain("x.com");
        assert!(!ips.is_empty());
        // 缺省池 240.0.0.0/4——分配的 IP 必须落在池内。
        assert!(engine.is_ip_in_pool(ips[0]));
    }

    #[test]
    fn policy_factory_returns_real_policy_feature() {
        register_all_features();
        let feat =
            registry::create_feature("policy", b"{}").expect("empty policy config should build");
        assert_eq!(feat.feature_name(), "policy");
        assert_ne!(feat.feature_name(), "simple", "should not be SimpleFeature");
    }

    #[test]
    fn policy_factory_parses_levels() {
        register_all_features();
        let json = br#"{
            "levels": {
                "0": {"handshake": 5, "conn_idle": 300, "uplink": 120, "downlink": 120},
                "5": {"handshake": 10, "buffer_size": 4096, "stats_user_uplink": true}
            },
            "system": {"stats_inbound_uplink": true}
        }"#;
        let feat =
            registry::create_feature("policy", json).expect("policy with levels should build");
        assert_eq!(feat.feature_name(), "policy");
        assert_ne!(feat.feature_name(), "simple");
    }

    #[test]
    fn observatory_factory_returns_real_observatory_feature() {
        register_all_features();
        let feat = registry::create_feature("observatory", b"{}")
            .expect("empty observatory config should build");
        assert_eq!(feat.feature_name(), "observatory");
        assert_ne!(feat.feature_name(), "simple");
    }

    #[test]
    fn observatory_factory_parses_config() {
        register_all_features();
        let json = br#"{
            "subject_outbound": "proxy1",
            "probe_url": "https://example.com/generate_204",
            "probe_interval": "30s"
        }"#;
        let feat = registry::create_feature("observatory", json)
            .expect("observatory config should build");
        assert_eq!(feat.feature_name(), "observatory");
    }

    /// bd f23r：factory 阶段不注入 IO——`init_dependencies` 接到
    /// `DepBag` 后才注入；subject_selector 非空时 start 会 fail-fast（返
    /// StartFailed）直到 IO 就绪。
    #[test]
    fn observatory_factory_does_not_inject_io_at_construction() {
        register_all_features();
        let json =
            br#"{"subject_outbound": "proxy1", "probe_interval": "30s"}"#;
        let feat = registry::create_feature("observatory", json)
            .expect("observatory config should build");
        // factory 仅构造 ObservatoryFeature，IO 在 init_dependencies 阶段注入。
        // start 阶段（无 IO + subject_selector 非空）必返 StartFailed。
        let err = feat.start().expect_err("start must fail without IO injection");
        assert!(
            matches!(err, xray_features::FeatureError::StartFailed { name: "observatory", .. }),
            "expected StartFailed, got: {err:?}"
        );
    }

    /// bd f23r：Instance 装配路径——factory 创建的 ObservatoryFeature 经
    /// `init_dependencies(DepBag)` 注入 IO 后 start 成功。
    #[test]
    fn observatory_init_dependencies_wires_io_then_start_succeeds() {
        use std::sync::Arc;
        use xray_features::{DepBag, OutboundTagSelector};

        register_all_features();
        let json =
            br#"{"subject_outbound": "node1", "probe_url": "http://127.0.0.1:1/", "probe_interval": "60s"}"#;
        let feat = registry::create_feature("observatory", json)
            .expect("observatory config should build");

        // 构造一个简单 backend——返回固定 tag 列表。
        struct EchoBackend;
        impl OutboundTagSelector for EchoBackend {
            fn select_by_prefix(&self, p: &[String]) -> Vec<String> {
                p.to_vec()
            }
        }
        let bag = DepBag::new()
            .with_outbound_selector(Arc::new(EchoBackend) as Arc<dyn OutboundTagSelector>);
        feat.init_dependencies(&bag);
        // 注入后 start 不再 fail-fast（即使探测失败，start 本身 OK）。
        feat.start().expect("start should succeed after IO injected");
    }

    #[test]
    fn metrics_factory_returns_real_metrics_feature() {
        register_all_features();
        let feat =
            registry::create_feature("metrics", b"{}").expect("empty metrics config should build");
        assert_eq!(feat.feature_name(), "metrics");
        assert_ne!(feat.feature_name(), "simple");
    }

    #[test]
    fn metrics_factory_parses_config() {
        register_all_features();
        let json = br#"{"listen": "127.0.0.1:9100"}"#;
        let feat =
            registry::create_feature("metrics", json).expect("metrics config should build");
        assert_eq!(feat.feature_name(), "metrics");
    }

    #[test]
    fn parse_go_duration_ms_handles_common_units() {
        assert_eq!(parse_go_duration_ms("30s"), Some(30_000));
        assert_eq!(parse_go_duration_ms("1m"), Some(60_000));
        assert_eq!(parse_go_duration_ms("1h"), Some(3_600_000));
        assert_eq!(parse_go_duration_ms("500ms"), Some(500));
        assert_eq!(parse_go_duration_ms(""), None);
        assert_eq!(parse_go_duration_ms("invalid"), None);
    }

    /// log 配置块解析（bd 4uu，对齐 Go infra/conf/log.go Build 语义）。
    #[test]
    fn log_factory_parses_full_config() {
        use xray_app_log::{LogFormat, LogType, SeverityLevel};

        let json = br#"{
            "loglevel": "debug",
            "access": "/tmp/access.log",
            "error": "none",
            "dnsLog": true,
            "maskAddress": "half",
            "format": "json"
        }"#;
        let json_cfg: xray_conf::app_config::LogConfig =
            serde_json::from_slice(json).expect("log config should parse");
        let cfg = build_log_config(&json_cfg);
        assert_eq!(cfg.error_log_level, SeverityLevel::Debug);
        assert_eq!(cfg.access_log_type, LogType::File);
        assert_eq!(cfg.access_log_path, "/tmp/access.log");
        assert_eq!(cfg.error_log_type, LogType::None);
        assert!(cfg.enable_dns_log);
        assert_eq!(cfg.mask_address, "half");
        assert_eq!(cfg.format, LogFormat::Json);
    }

    /// 缺省 log 块字段：log 块存在时 access/error 缺省 Console（Go Build 语义），
    /// loglevel 缺省 Warning，format 缺省 Console。
    #[test]
    fn log_factory_defaults_when_log_block_present() {
        use xray_app_log::{LogFormat, LogType, SeverityLevel};

        let json_cfg: xray_conf::app_config::LogConfig =
            serde_json::from_slice(b"{}").unwrap();
        let cfg = build_log_config(&json_cfg);
        assert_eq!(cfg.access_log_type, LogType::Console);
        assert_eq!(cfg.error_log_type, LogType::Console);
        assert_eq!(cfg.error_log_level, SeverityLevel::Warning);
        assert_eq!(cfg.format, LogFormat::Console);
    }

    /// loglevel=none：error 与 access 双双关闭（Go log.go:57-59）。
    #[test]
    fn log_factory_loglevel_none_disables_both() {
        use xray_app_log::LogType;

        let json_cfg: xray_conf::app_config::LogConfig =
            serde_json::from_slice(br#"{"loglevel": "none"}"#).unwrap();
        let cfg = build_log_config(&json_cfg);
        assert_eq!(cfg.error_log_type, LogType::None);
        assert_eq!(cfg.access_log_type, LogType::None);
    }

    /// log factory 从 JSON 字节构建 LogFeature 并 start（log 块真实生效链路）。
    #[test]
    fn log_factory_builds_feature_from_json() {
        register_all_features();
        let feat = registry::create_feature("log", br#"{"loglevel": "warning"}"#)
            .expect("log config should build");
        assert_eq!(feat.feature_name(), "log");
    }

    #[test]
    fn all_kinds_are_unique() {
        let mut all: Vec<&str> = Vec::new();
        all.extend(APP_KINDS);
        all.extend(PROXY_INBOUND_KINDS);
        all.extend(TUN_KINDS);
        all.extend(PROXY_OUTBOUND_KINDS);
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        // "dns", "blackhole", "loopback" 出现在多个列表中是正常的（不同上下文）
        // 只检查同一个列表内无重复
        for list in &[APP_KINDS, PROXY_INBOUND_KINDS, PROXY_OUTBOUND_KINDS] {
            let mut seen = std::collections::HashSet::new();
            for &k in *list {
                assert!(seen.insert(k), "duplicate kind in same list: {k}");
            }
        }
    }
}
