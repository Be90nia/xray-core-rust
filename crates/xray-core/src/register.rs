//! Feature 注册中心 —— 将 kind 字符串映射到 FeatureFactory。
//!
//! Go 用 `init()` 自注册（每个协议/应用在 init 中调用 `common.RegisterConfig`）。
//! Rust 没有 init，需要程序入口显式调用 [`register_all_features`]。
//!
//! 当前阶段：各 `xray-app-*` crate 尚未实现 `Feature` trait，因此注册 stub factory
//! （返回 `FeatureError::StartFailed` 提示 "not yet implemented"）。
//! 待各 crate 切片完成后，替换为真实 factory。

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
///                 vmess, vless, trojan, hysteria2, tuic, wireguard, loopback
///
/// *tun 仅在 Linux/Android/FreeBSD 上注册。
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

    // SimpleFeature for apps without real Feature impl yet
    for &kind in &["fakeDns", "burstObservatory", "version", "geodata"] {
        let _ = registry::register_feature(kind, simple_feature_factory(kind));
    }

    // --- Proxy inbound kinds ---
    for &kind in PROXY_INBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
    // TUN inbound
    for &kind in TUN_INBOUND_KIND {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }

    // --- Proxy outbound kinds ---
    for &kind in PROXY_OUTBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
    // TUN outbound
    for &kind in TUN_OUTBOUND_KIND {
        let _ = registry::register_feature(kind, stub_factory(kind));
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
/// TUN 单独注册（平台门控）。
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

/// TUN 入站 kind——仅 Linux/Android/FreeBSD 可用。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_INBOUND_KIND: &[&str] = &["tun"];

/// TUN 入站 kind——非 Linux/Android/FreeBSD 不注册。
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
const TUN_INBOUND_KIND: &[&str] = &[];

/// 代理出站 kind 列表。TUN 单独注册（平台门控）。
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

/// TUN 出站 kind——仅 Linux/Android/FreeBSD 可用。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_OUTBOUND_KIND: &[&str] = &["tun"];

/// TUN 出站 kind——非 Linux/Android/FreeBSD 不注册。
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
const TUN_OUTBOUND_KIND: &[&str] = &[];

/// 创建 stub factory：返回 `StartFailed` 错误提示 "not yet implemented"。
fn stub_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        Err(FeatureError::StartFailed {
            name: kind,
            message: format!("{kind}: not yet implemented (stub factory registered)"),
        })
    })
}

/// Log app 真实 factory：从 proto 编码的配置字节创建 LogFeature。
fn log_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let proto: xray_proto::xray::app::log::Config =
            prost::Message::decode(data).unwrap_or_default();
        let config = xray_app_log::LogConfig::from_proto(&proto);
        let feature = xray_app_log::LogFeature::new(config)?;
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
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
/// 探测循环暂不启动（需 OutboundSelector + ProbeExecutor 注入）。
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

/// Metrics app 真实 factory：解析 JSON → proto Config →
/// [`xray_app_metrics::MetricsConfig`] → [`MetricsFeature`](xray_app_metrics::MetricsFeature)。
///
/// 对应 Go `app/metrics` 的 `init()` + `New(ctx, config)`。
/// HTTP listener 暂不启动（需 MetricsHttpServer + StatsCollector 注入）。
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
    if pl.stats_user_uplink.is_some() || pl.stats_user_downlink.is_some() {
        p.stats = Some(policy::Stats {
            user_uplink: pl.stats_user_uplink.unwrap_or(false),
            user_downlink: pl.stats_user_downlink.unwrap_or(false),
            user_online: false,
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
/// 这些 Default*Feature 是 xray-features 中的占位实现，提供 trait check 通过
/// + no-op 行为（路由由 dispatcher 直接匹配，统计为空容器）。
/// policy 走 [`policy_factory`]，dns 走 [`dns_factory`]。
fn default_feature_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        match kind {
            "routing" => Ok(Arc::new(xray_features::routing::DefaultRouterFeature) as Arc<dyn Feature>),
            "stats" => Ok(Arc::new(xray_features::stats::DefaultStatsFeature::new()) as Arc<dyn Feature>),
            _ => Err(FeatureError::StartFailed {
                name: kind,
                message: format!("{kind}: no Default*Feature available"),
            }),
        }
    })
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

/// 为 api/metrics/fakeDns/observatory/burstObservatory/version/geodata
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
            .chain(TUN_INBOUND_KIND)
            .chain(PROXY_OUTBOUND_KINDS)
            .chain(TUN_OUTBOUND_KIND)
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

    #[test]
    fn all_kinds_are_unique() {
        let mut all: Vec<&str> = Vec::new();
        all.extend(APP_KINDS);
        all.extend(PROXY_INBOUND_KINDS);
        all.extend(TUN_INBOUND_KIND);
        all.extend(PROXY_OUTBOUND_KINDS);
        all.extend(TUN_OUTBOUND_KIND);
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
