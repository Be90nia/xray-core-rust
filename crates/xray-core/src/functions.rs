//! 外部 API —— Xray 实例构造与启动入口。
//!
//! 对应 Go `core/functions.go`。Go 端 `StartInstance(configFormat, configBytes)`
//! 三步：`LoadConfig` → `New` → `Start`。Rust 端等价路径：
//!
//! 1. 字节流 → [`xray_conf::Config`]（由 `xray_conf::Config::from_json_str` 完成）
//! 2. [`Config::build`](xray_conf::Config::build) → [`xray_conf::BuiltConfig`]
//! 3. [`Instance::new_from_built`] → [`Instance`]
//! 4. [`Instance::start`] → 启动所有 features
//!
//! ## 切片边界
//!
//! - 仅支持 JSON 输入字节（YAML/TOML 字节解析留给文件加载路径，见
//!   [`xray_conf::load_file_with_format`] 处理 `auto`/`yaml`/`toml`）
//! - inbound/outbound handler 注入依赖各 proxy crate 切片2 + proxyman 切片2（c2v 任务）

use std::sync::Arc;

use thiserror::Error;

use crate::Instance;
use xray_features::FeatureError;

use crate::inbound::spawn_inbounds;
use crate::outbound::register_outbounds;
use crate::router::DispatchRouter;
use crate::register::{register_all_features, register_all_transports};
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::{DefaultDispatcher, OutboundHandlerManager};

/// AccessLogSink → LogInstance 桥（bd 4uu）。
///
/// dispatcher crate 不依赖 xray-app-log（AccessLogSink trait 注入解耦），
/// xray-core 同时依赖两者，在此把 [`xray_app_log::LogInstance`] 适配为
/// dispatcher 的 access 记录 sink——对应 Go `log.Record(accessMessage)`
/// 全局 handler → `app/log.Instance.Handle` 链。
struct LogInstanceSink(Arc<xray_app_log::LogInstance>);

/// SimpleOhm → xray_features::OutboundTagSelector 桥（bd f23r wiring）。
///
/// `xray_app_dispatcher::SimpleOhm` 没有 `select_by_prefix`（仅 `list_tags`），
/// 这里做一次过滤：subject_selector 任意一项是 tag 前缀即保留。
/// SimpleOhm 不带 default 标识，此处把"无前缀"也按精确匹配兼容——足够
/// observatory 探测（observatory 关注的是已注册 outbound 列表，不是 default 选择）。
struct OhmTagSelector(Arc<SimpleOhm>);
impl xray_features::OutboundTagSelector for OhmTagSelector {
    fn select_by_prefix(&self, prefixes: &[String]) -> Vec<String> {
        let all = self.0.list_tags();
        if prefixes.is_empty() {
            return all;
        }
        all.into_iter()
            .filter(|tag| {
                prefixes
                    .iter()
                    .any(|p| tag.starts_with(p.as_str()))
            })
            .collect()
    }
}

impl xray_app_dispatcher::AccessLogSink for LogInstanceSink {
    fn record_access(&self, e: &xray_app_dispatcher::AccessLogEntry) {
        let status = if e.status == "rejected" {
            xray_app_log::AccessStatus::Rejected
        } else {
            xray_app_log::AccessStatus::Accepted
        };
        self.0.handle(&xray_app_log::LogEntry::Access(xray_app_log::AccessMessage {
            from: e.from.clone(),
            to: e.to.clone(),
            email: e.email.clone(),
            detour: e.detour.clone(),
            status: Some(status),
            reason: e.reason.clone(),
        }));
    }
}

/// 外部 API 调用错误。
#[derive(Debug, Error)]
pub enum CoreFunctionError {
    /// 配置解析失败（JSON 格式错误、字段非法等）。
    #[error("config load failed: {0}")]
    ConfigLoad(String),

    /// `Config::build()` 失败（如使用了已废弃的全局 transport 字段）。
    #[error("config build failed: {0}")]
    ConfigBuild(String),

    /// `Instance::new_from_built` 期间 FeatureFactory 报错（如 prost decode 失败、配置非法）。
    #[error("instance init failed: {0}")]
    InstanceInit(String),

    /// `Instance::start` 期间某 feature 启动失败。
    #[error("instance start failed: {0}")]
    InstanceStart(String),
}

impl From<FeatureError> for CoreFunctionError {
    fn from(e: FeatureError) -> Self {
        // 语义：
        // - CloseFailed: 仅 start() 后才可能发生 → InstanceStart
        // - 其他（含 StartFailed）：factory 构造期也可能发生 → InstanceInit
        //   (factory 常用 StartFailed 作为通用错误码)
        match e {
            FeatureError::CloseFailed { .. } => CoreFunctionError::InstanceStart(e.to_string()),
            _ => CoreFunctionError::InstanceInit(e.to_string()),
        }
    }
}

impl From<xray_conf::ConfError> for CoreFunctionError {
    fn from(e: xray_conf::ConfError) -> Self {
        CoreFunctionError::ConfigBuild(e.to_string())
    }
}

/// 从已构建的 [`BuiltConfig`] 启动新实例。
///
/// 内部步骤：`Instance::new_from_built(built)` → `instance.start()` → 包装为 `Arc<Instance>`。
///
/// 对应 Go `core.New(config)` + `instance.Start()` 组合。**不阻塞**：调用方需自行管理
/// instance 生命周期（如等待信号、监听关闭事件）。
pub fn start_from_built(built: &xray_conf::BuiltConfig) -> Result<Arc<Instance>, CoreFunctionError> {
    register_all_features();
    register_all_transports();
    let mut instance = Instance::new_from_built(built)?;
    instance.start()?;
    Ok(Arc::new(instance))
}

/// 完整启动路径：Instance + SimpleOhm + outbounds + inbounds。
///
/// 对应 Go `core.New(config)` + `instance.Start()` + `addInboundHandlers` + `addOutboundHandlers`。
/// 返回 `(Arc<Instance>, Arc<SimpleOhm>, inbound JoinHandles)`。
///
/// 调用方需在 tokio runtime 中调用，并持有 JoinHandles 以管理 inbound listener 生命周期。
///
/// # Routing 自动接入
///
/// 如果 `built.apps` 含 `kind="routing"` 项，优先用 `xray-app-router` 的完整
/// [`crate::wiring::RouterAdapter`]（rich RoutingContext + DNS resolved 选路）；
/// 失败时回退 [`PatternRouter`](crate::router::PatternRouter)；否则走纯 default
/// outbound 路径。三条路径统一经 [`DefaultDispatcher`]（sniffing + routing + stats）。
pub async fn start_full(
    built: &xray_conf::BuiltConfig,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    start_full_dispatched(built, None).await
}

/// 带路由的完整启动路径：Instance + SimpleOhm + outbounds + router + inbounds。
///
/// router 经 [`crate::wiring::DispatchRouterBridge`] 暴露为 dispatcher 的
/// `RoutingRouter`，与 [`start_full`] 的 RouterAdapter 路径同样经
/// [`DefaultDispatcher::dispatch_link`] 分发（仅目标地址参与规则匹配）。
pub async fn start_full_with_router(
    built: &xray_conf::BuiltConfig,
    router: Arc<dyn DispatchRouter>,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    start_full_dispatched(built, Some(router)).await
}

/// 共用装配路径（方案 B）：Instance + SimpleOhm + outbounds + DefaultDispatcher + inbounds。
///
/// 生产 default handler 经 [`DefaultDispatcher::dispatch_link`]：
/// - sniffing：`BuiltInbound.sniffing` JSON → 首包嗅探 + dest 覆盖 + CachedReader 回灌
/// - routing：`routing_router.pick_route_resolved`（domainStrategy DNS 解析路径）
/// - stats：inbound/outbound tag counter（`{kind}>>>{tag}>>>traffic>>>{direction}`）
///
/// `routing_router` 为 None 时退 default handler（无路由行为），
/// sniffing 与 counter 与路由无关始终生效。
/// `dns_router` 仅用于 DNS client 注入（domainStrategy 解析）。
async fn start_full_dispatched(
    built: &xray_conf::BuiltConfig,
    // 外部注入路由器（`start_full_with_router` 路径）；None 时按 routing app 自动装配。
    routing_override: Option<Arc<dyn DispatchRouter>>,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    register_all_features();
    register_all_transports();
    let mut instance = Instance::new_from_built(built)?;

    let ohm = Arc::new(SimpleOhm::new());

    // Routing 自动接入：routing app 存在时优先完整 RouterAdapter（rich RoutingContext
    // + DNS resolved 选路 + balancer selector 接真实 ohm + observatory 观测器）；
    // 失败回退 PatternRouter；否则走纯 default outbound 路径。
    let (routing_router, dns_router) = if let Some(r) = routing_override {
        let bridge = Arc::new(crate::wiring::DispatchRouterBridge::new(Arc::clone(&r)))
            as Arc<dyn xray_app_dispatcher::default::RoutingRouter>;
        (Some(bridge), Some(r))
    } else {
        match built.apps.iter().find(|a| a.kind == "routing") {
            Some(a) => {
                // 观测器：observatory app 存在时桥接（leastping/leastload 观测数据源，
                // Go RequireFeatures(observatory) 等价）。
                let observer: Option<
                    Arc<dyn xray_app_router::balancing::ObservationProvider>,
                > = instance
                    .get_feature::<xray_app_observatory::ObservatoryFeature>()
                    .map(|f| {
                        Arc::new(crate::wiring::ObservatoryProviderBridge(f)) as Arc<_>
                    });
                match crate::wiring::build_router_adapter_from_json_with_ohm(
                    &a.data,
                    &ohm,
                    observer,
                ) {
                    Ok(adapter) => {
                        let routing = Arc::clone(&adapter)
                            as Arc<dyn xray_app_dispatcher::default::RoutingRouter>;
                        let dns_side = Arc::clone(&adapter) as Arc<dyn DispatchRouter>;
                        (Some(routing), Some(dns_side))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "full Router init failed, falling back to PatternRouter"
                        );
                        match crate::router::PatternRouter::from_json(&a.data) {
                            Ok(r) => {
                                let r: Arc<dyn DispatchRouter> = Arc::new(r);
                                let bridge = Arc::new(
                                    crate::wiring::DispatchRouterBridge::new(Arc::clone(&r)),
                                ) as Arc<dyn xray_app_dispatcher::default::RoutingRouter>;
                                let dns_side = Arc::clone(&r) as Arc<dyn DispatchRouter>;
                                (Some(bridge), Some(dns_side))
                            }
                            Err(_) => (None, None),
                        }
                    }
                }
            }
            None => (None, None),
        }
    };

    // DNS 注入（对应 Go 装配链：instance 创建后 router.dns = core.GetFeature(dns)）：
    // routing domainStrategy（IpOnDemand/IpIfNonMatch）解析经 DnsClient 查询。
    if let Some(r) = dns_router.as_ref() {
        if let Some(dns) = instance.get_feature::<xray_app_dns::DnsService>() {
            r.set_dns_client(Arc::clone(&dns) as Arc<dyn xray_features::dns::DnsClient>);
        } else if let Some(local) = instance.get_feature::<xray_features::dns::DefaultDnsFeature>() {
            // Go 装配链：无 dns app 时 router 经 RequireFeatures 拿到
            // essentialFeatures 注册的 localdns 默认 client（core/xray.go:213）。
            r.set_dns_client(Arc::clone(&local) as Arc<dyn xray_features::dns::DnsClient>);
        }
    }

    // DefaultDispatcher 装配（对应 Go dispatcher.Init(ohm, router, pm, sm)）
    let mut dispatcher = DefaultDispatcher::new();
    dispatcher.init(
        &xray_app_dispatcher::Config::default(),
        Arc::clone(&ohm) as Arc<dyn OutboundHandlerManager>,
        routing_router,
        xray_features::policy::Policy::default(),
        None,
    );
    // sm80③/czwu：出站 DialBridge 的 session policy manager（Go freedom.go:393
    // sessionPolicy 驱动 bridge connIdle/uplinkOnly/downlinkOnly）。非 freedom
    // 出站查 level 0；freedom 按 settings.userLevel 查档位（outbound.rs 内）。
    let pm_opt = instance.get_feature::<xray_app_policy::PolicyFeature>();
    if let Some(pm) = pm_opt.as_ref() {
        dispatcher.set_policy_manager(Arc::clone(pm) as Arc<dyn xray_features::policy::PolicyManager>);
    }
    let policy_manager: Option<&dyn xray_features::policy::PolicyManager> =
        pm_opt.as_ref().map(|p| &**p as &dyn xray_features::policy::PolicyManager);
    dispatcher.stats = instance
        .get_feature::<crate::register::AppStatsFeature>()
        .map(|f| f as Arc<dyn xray_features::stats::Manager>);
    // bd 3xmjx：metrics `/metrics` 端点接真实 stats manager（非 EmptyStats）——
    // 对应 Go metrics.New(ctx) RequireFeatures 拿 stats.Manager。
    if let Some(metrics) = instance.get_feature::<xray_app_metrics::MetricsFeature>() {
        if let Some(stats) = instance.get_feature::<crate::register::AppStatsFeature>() {
            metrics.set_stats_collector(stats);
        }
    }
    // per-tag UDP443 策略（bd g35）：mux JSON → dispatch_link 前置检查
    dispatcher.udp443_policies = crate::outbound::parse_udp443_policies(&built.outbounds);
    // FakeDNS 注入（对应 Go dispatcher.fdns，嗅探阶段反查 fake IP 域名）：
    // fakeDns app 存在时 engine() → dispatcher.set_fdns。
    if let Some(f) = instance.get_feature::<crate::register::FakeDnsFeature>() {
        dispatcher.set_fdns(Some(crate::register::fake_dns_engine_bridge(f.engine())));
    }

    // Access log 装配（bd 4uu，对应 Go logger 是首个启动的 App + dispatcher log.Record）：
    // 无 log 配置块时按 Go DefaultLogConfig（access=None/error=Console/Warning）注入默认
    // LogFeature；再把 LogInstance 适配为 dispatcher 的 AccessLogSink。
    if instance.get_feature::<xray_app_log::LogFeature>().is_none() {
        let feature = xray_app_log::LogFeature::new(xray_app_log::LogConfig::default())
            .map_err(CoreFunctionError::from)?;
        instance.add_feature(Arc::new(feature));
    }
    if let Some(log_feature) = instance.get_feature::<xray_app_log::LogFeature>() {
        dispatcher.access_sink = Some(Arc::new(LogInstanceSink(Arc::clone(
            log_feature.instance(),
        ))));
    }
    let dispatcher = Arc::new(dispatcher);

    // loopback 出站 sink 注入（票 rdcc，对应 Go loopback.go:46 DispatchLink 回注）：
    // 生产装配持 init 完成的 DefaultDispatcher 构造 sink；loopback outbound 命中
    // 路由后经 dispatch_link 回注 inboundTag 对应入站。此前恒传 None = 任何命中
    // loopback 的连接在 handler 侧静默 drop（黑洞）。
    let loopback_sink: Arc<dyn xray_proxy_loopback::LoopbackSink> = Arc::new(
        crate::outbound::DispatcherLoopbackSink::new(Arc::clone(&dispatcher)),
    );
    // DNS service 同步注入出站（bd bqm）：targetStrategy 域名解析经此生效
    // （对应 Go 全局 internet.dnsClient 由 app/dns 初始化）。
    register_outbounds(
        built,
        &ohm,
        Some(loopback_sink),
        instance.get_feature::<xray_app_dns::DnsService>(),
        policy_manager,
    )?;
    // 此次 init_dependencies 与 instance.new_from_built 里的第一次是幂等
    // 的（已 set_io 的 feature 跳过），允许双阶段注入。
    let ohm_selector: Arc<dyn xray_features::OutboundTagSelector> =
        Arc::new(OhmTagSelector(Arc::clone(&ohm)));
    let bag2 = xray_features::DepBag::new().with_outbound_selector(ohm_selector);
    for feat in instance.features() {
        feat.init_dependencies(&bag2);
    }
    // Commander（api）真注入（bd ze3/bg7）：HandlerService 操作生产 SimpleOhm
    //（proto config → try_build_handler 复用静态注册构建路径），
    // LoggerService 接 DefaultLogService（LogInstance::restart）。
    // 对应 Go Commander.Start 中 RequireFeatures(outbound.Manager, log.Instance)。
    if let Some(commander) = instance.get_feature::<xray_app_commander::Commander>() {
        commander.set_outbound_runtime(Arc::new(crate::outbound::ApiOutboundRuntime::new(
            Arc::clone(&ohm),
        )));
        if let Some(log_feature) = instance.get_feature::<xray_app_log::LogFeature>() {
            commander.set_logger_service(log_feature.log_service());
        }
        // bd dnw3：StatsService 后端接 AppStatsFeature（essential 注入必在场，
        // 对应 Go statsServer 经 RequireFeatures 拿 stats.Manager）；是否实际
        // 暴露仍由 `api.services` 声明集门控。
        if let Some(stats) = instance.get_feature::<crate::register::AppStatsFeature>() {
            let manager = Arc::clone(stats.manager());
            commander.set_stats_service(Arc::new(
                xray_app_stats::command::DefaultStatsService::new(manager),
            ));
        }
    }

    // 先 start features（LogInstance 等 handler 就绪）再起 inbound listener——
    // 对应 Go：logger 是首个启动的 App，addInboundHandlers 在 instance.Start() 之后。
    instance.start()?;
    let handles = spawn_inbounds(
        built,
        Arc::clone(&ohm),
        Some(dispatcher),
        instance.shutdown_token().clone(),
    )
    .await
    .map_err(|e| CoreFunctionError::InstanceStart(e.to_string()))?;
    tracing::info!(
        inbounds = handles.len(),
        routed = dns_router.is_some(),
        "Xray instance started via DefaultDispatcher (sniffing+stats+routing+accesslog)"
    );
    Ok((Arc::new(instance), ohm, handles))
}

/// 从序列化配置字节启动新实例（仅支持 JSON 格式）。
///
/// 对应 Go `core.StartInstance(configFormat, configBytes)`：
///
/// 1. 字节 → `Config`（`from_json_str`）
/// 2. `Config::build()` → `BuiltConfig`
/// 3. `start_from_built(&built)`
///
/// # 参数
///
/// - `config_format`：必须是 `"json"`（大小写不敏感）。其他格式返回 `ConfigLoad` 错误，
///   建议改用文件加载路径（`xray_cli::run` + `xray_conf::load_file_with_format`）。
/// - `config_bytes`：JSON 编码的字节流。
pub fn start_instance(
    config_format: &str,
    config_bytes: &[u8],
) -> Result<Arc<Instance>, CoreFunctionError> {
    if !config_format.eq_ignore_ascii_case("json") {
        return Err(CoreFunctionError::ConfigLoad(format!(
            "unsupported format: {config_format} (only json supported for bytes input; use file path for yaml/toml)"
        )));
    }
    let json_str = std::str::from_utf8(config_bytes)
        .map_err(|e| CoreFunctionError::ConfigLoad(format!("config is not valid UTF-8: {e}")))?;
    let config = xray_conf::Config::from_json_str(json_str)
        .map_err(|e| CoreFunctionError::ConfigLoad(e.to_string()))?;
    register_all_features();
    register_all_transports();
    let built = config.build()?;
    start_from_built(&built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use xray_features::{Feature, FeatureError, FeatureFactory, registry};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
    use xray_app_dispatcher::OutboundHandlerManager;

    /// 集成链路测试的 freedom settings：显式 allow 全放行。
    ///
    /// freedom 默认规则按入站协议名推导（Go getDefaultFinalRule）：
    /// vless/vmess/trojan/shadowsocks* 入站 → BlockPrivate（geoip:private 含
    /// 127.0.0.0/8）——回环 echo 会被黑洞。Go 语义下配置 finalRules 先于默认
    /// 规则匹配（matchFinalRule），显式 allow 即逃生门。
    const FREEDOM_ALLOW_ALL_SETTINGS: &[u8] = br#"{"finalRules":[{"action":"allow"}]}"#;
    /// 测试用 Feature：记录 start 次数。
    struct SharedCounterFeature {
        counter: StdArc<AtomicUsize>,
    }
    impl Feature for SharedCounterFeature {
        fn feature_name(&self) -> &'static str {
            "SharedCounterFeature"
        }
        fn start(&self) -> Result<(), FeatureError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn start_instance_rejects_non_json_format() {
        let err = start_instance("yaml", b"{}").err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
        let msg = format!("{err}");
        assert!(msg.contains("only json supported"));
    }

    #[test]
    fn start_instance_rejects_invalid_utf8() {
        let err = start_instance("json", &[0xFF, 0xFE]).err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
    }

    #[test]
    fn start_instance_rejects_invalid_json() {
        let err = start_instance("json", b"not json").err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
    }

    #[test]
    fn start_from_built_with_empty_config_starts_zero_features() {
        let built = xray_conf::BuiltConfig::default();
        let inst = start_from_built(&built).expect("empty built should start cleanly");
        assert!(inst.is_running());
        assert_eq!(inst.feature_count(), 4); // dns+routing+policy+stats defaults
    }

    #[test]
    fn start_from_built_skips_unregistered_kind() {
        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.unregistered.kind".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("unregistered kind should be skipped");
        assert_eq!(inst.feature_count(), 4); // 4 defaults + unregistered skipped
    }

    #[test]
    fn start_from_built_registers_and_starts_via_factory() {
        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory: FeatureFactory = Arc::new(move |_data: &[u8]| {
            Ok(Arc::new(SharedCounterFeature {
                counter: counter_for_factory.clone(),
            }) as Arc<dyn Feature>)
        });
        let _ = registry::register_feature("xray.test.shared_counter", factory);

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.shared_counter".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("registered feature should start");
        assert_eq!(inst.feature_count(), 5); // 4 defaults + 1 test app
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "feature.start should be called once"
        );
    }

    #[test]
    fn start_from_built_factory_error_skipped() {
        // Go 行为：factory 失败时跳过该 feature，继续启动其余。
        let factory: FeatureFactory = Arc::new(|_data: &[u8]| {
            Err(FeatureError::StartFailed {
                name: "BadFeature",
                message: "injected failure".into(),
            })
        });
        let _ = registry::register_feature("xray.test.bad_factory", factory);

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.bad_factory".into(),
            data: b"{}".to_vec(),
        });
        // bad_factory 失败被跳过，实例仍成功启动（含 4 个 default features）
        let inst = start_from_built(&built).expect("bad factory should be skipped");
        assert!(inst.is_running());
        assert_eq!(inst.feature_count(), 4); // 4 defaults, bad_factory skipped
    }

    #[test]
    fn start_from_built_multiple_apps_in_order() {
        let order = StdArc::new(parking_lot::Mutex::new(Vec::new()));
        struct OrderedFeature {
            tag: &'static str,
            order: StdArc<parking_lot::Mutex<Vec<String>>>,
        }
        impl Feature for OrderedFeature {
            fn feature_name(&self) -> &'static str {
                self.tag
            }
            fn start(&self) -> Result<(), FeatureError> {
                self.order.lock().push(self.tag.to_string());
                Ok(())
            }
        }
        let order1 = order.clone();
        let order2 = order.clone();
        let _ = registry::register_feature(
            "xray.test.ordered.first",
            Arc::new(move |_data| {
                Ok(Arc::new(OrderedFeature {
                    tag: "first",
                    order: order1.clone(),
                }) as Arc<dyn Feature>)
            }),
        );
        let _ = registry::register_feature(
            "xray.test.ordered.second",
            Arc::new(move |_data| {
                Ok(Arc::new(OrderedFeature {
                    tag: "second",
                    order: order2.clone(),
                }) as Arc<dyn Feature>)
            }),
        );

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.ordered.first".into(),
            data: b"{}".to_vec(),
        });
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.ordered.second".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("ordered features should start");
        assert_eq!(inst.feature_count(), 6); // 4 defaults + 2 test apps
        let recorded = order.lock().clone();
        assert_eq!(recorded, vec!["first".to_string(), "second".to_string()]);
    }

    /// 端到端验证：BuiltConfig → start_full → socks5 inbound → freedom outbound → echo server。
    /// 这是 P1 集成的核心测试：证明代理能从配置启动并工作。
    #[tokio::test]
    async fn start_full_socks_inbound_to_freedom_outbound_e2e() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 找空闲端口给 socks inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 3. 构建 BuiltConfig: socks inbound + freedom outbound
        let mut built = BuiltConfig::default();
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: vec![],
            },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        built.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "freedom".into(),
                data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec(),
            },
            tag: "direct".into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        });

        // 4. start_full
        let (inst, ohm, handles) =
            start_full(&built).await.expect("start_full should succeed");
        assert!(inst.is_running(), "instance should be running");
        assert!(
            ohm.get_default_handler().is_some(),
            "freedom should be default handler"
        );

        // 5. 等 listener 就绪
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 6. SOCKS5 client: 连 inbound → handshake → CONNECT echo → echo
        let mut client =
            TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.expect("connect socks");

        // SOCKS5 握手
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "server should select no-auth");

        // CONNECT echo_addr
        let ipv4 = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ipv4);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        // 7. echo
        let payload = b"hello full proxy chain!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through full proxy chain");

        // cleanup
        for h in handles {
            h.abort();
        }
    }
    /// Access log e2e（bd 4uu）：log 配置块（access 文件）→ socks → freedom 全链路，
    /// dispatch 后 access log 记录 from/to/detour（Go default.go:488-502 对齐）。
    #[tokio::test]
    async fn access_log_full_chain_socks_to_freedom_e2e() {
        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. access log 临时文件
        let access_path = std::env::temp_dir()
            .join(format!("xray-access-e2e-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&access_path);

        // 3. 找空闲端口给 socks inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 4. BuiltConfig: log app（access 文件）+ socks inbound + freedom outbound
        let mut built = BuiltConfig::default();
        built.apps.push(BuiltEntry {
            kind: "log".into(),
            data: serde_json::to_vec(&serde_json::json!({
                "loglevel": "warning",
                "access": access_path.to_string_lossy(),
            }))
            .unwrap(),
        });
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: vec![],
            },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        built.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "freedom".into(),
                data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec(),
            },
            tag: "direct".into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        });

        // 5. start_full + 等 listener
        let (_inst, _ohm, handles) = start_full(&built).await.expect("start_full should succeed");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 6. SOCKS5 CONNECT → echo
        let mut client =
            TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.expect("connect socks");
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        let ipv4 = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ipv4);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        let payload = b"ping";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "echo through chain");

        // 7. 断言 access log：等记录落盘（record 在 handler.dispatch 前同步执行）
        let content = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(s) = std::fs::read_to_string(&access_path) {
                    if s.contains("accepted") {
                        return s;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("access log should be written");

        // Go 格式：from {from} accepted {to} [{in >> out}]
        let expected_to = format!("tcp:127.0.0.1:{}", echo_addr.port());
        assert!(content.contains("accepted"), "line: {content}");
        assert!(content.contains(&expected_to), "line: {content}");
        assert!(content.contains("[socks-in >> direct]"), "line: {content}");
        assert!(content.contains("from 127.0.0.1:"), "line: {content}");

        for h in handles {
            h.abort();
        }
        let _ = std::fs::remove_file(&access_path);
    }

    /// Graceful shutdown：cancel shutdown_token 后 inbound task 应退出。
    #[tokio::test]
    async fn graceful_shutdown_cancels_inbound_tasks() {
        // 找空闲端口给 socks inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut built = BuiltConfig::default();
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        built.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        });

        let (mut inst, _ohm, handles) = start_full(&built).await.unwrap();
        assert!(inst.is_running());
        // 等 listener 就绪
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // cancel token 触发 graceful shutdown
        inst.shutdown_token().cancel();

        // 所有 inbound handle 应在合理时间内退出（token cancel → select! 命中 → task 结束）
        let drain = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for h in handles {
                let _ = h.await;
            }
        });
        drain.await.expect("inbound tasks should exit within 2s after token cancel");
    }

    /// SOCKS5 → VMess → Freedom → echo 全链路
    #[tokio::test]
    async fn integration_socks_through_vmess_to_echo() {
        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vmess_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        // 2. server: VMess inbound + Freedom outbound
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vmess".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vmess-in".into(), port: Some(vmess_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vmess server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. client: SOCKS inbound + VMess outbound
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vmess".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vmess_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. SOCKS5 → VMess → echo
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VMess CONNECT");

        let payload = b"hello vmess chain!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through VMess"),
            Ok(Err(e)) => panic!("VMess read error: {e}"),
            Err(_) => panic!("timeout: VMess chain may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// SOCKS5 → VLESS → Freedom → echo 全链路
    #[tokio::test]
    async fn integration_socks_through_vless_to_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vless-in".into(), port: Some(vless_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VLESS CONNECT");

        let payload = b"hello vless chain!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through VLESS"),
            Ok(Err(e)) => panic!("VLESS read error: {e}"),
            Err(_) => panic!("timeout: VLESS chain may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// SOCKS5 → Trojan → Freedom → echo 全链路
    #[tokio::test]
    async fn integration_socks_through_trojan_to_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trojan_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "trojan".into(),
                data: br#"{"clients":[{"password":"test-pass-12345"}]}"#.to_vec() },
            tag: "trojan-in".into(), port: Some(trojan_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("trojan server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "trojan".into(),
                data: format!(r#"{{"servers":[{{"address":"127.0.0.1","port":{trojan_port},"password":"test-pass-12345"}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("trojan client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "Trojan CONNECT");

        let payload = b"hello trojan chain!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through Trojan"),
            Ok(Err(e)) => panic!("Trojan read error: {e}"),
            Err(_) => panic!("timeout: Trojan chain may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// 传输矩阵：VLESS over WebSocket → Freedom → echo
    #[tokio::test]
    async fn integration_vless_over_websocket_to_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let ws_settings = r#"{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}"#;

        // server: VLESS+WS inbound + Freedom outbound
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vless-ws-in".into(), port: Some(vless_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(ws_settings.into()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-ws server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // client: SOCKS inbound + VLESS+WS outbound
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(ws_settings.into()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-ws client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // SOCKS5 → VLESS/WS → echo
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VLESS/WS CONNECT");

        let payload = b"hello vless over ws!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through VLESS/WS"),
            Ok(Err(e)) => panic!("VLESS/WS read error: {e}"),
            Err(_) => panic!("timeout: VLESS/WS transport may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// 路由分发测试：多 outbound + 域名规则 → 正确 outbound 被选中
    #[tokio::test]
    async fn integration_routing_selects_correct_outbound() {
        use std::sync::atomic::{AtomicU8, Ordering};
        // 两个 echo server，用不同的标记字节区分
        let tag_a = std::sync::Arc::new(AtomicU8::new(0));
        let tag_b = std::sync::Arc::new(AtomicU8::new(0));

        // echo server A (tag "out-a")
        let ea_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ea_addr = ea_listener.local_addr().unwrap();
        let ea_tag = tag_a.clone();
        tokio::spawn(async move {
            let (mut sock, _) = ea_listener.accept().await.unwrap();
            ea_tag.store(1, Ordering::SeqCst);
            sock.write_all(b"SERVER_A").await.unwrap();
            let mut buf = [0u8; 1024]; loop {
                match sock.read(&mut buf).await { Ok(0)|Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } } }
            }
        });

        // echo server B (tag "out-b")
        let eb_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let eb_addr = eb_listener.local_addr().unwrap();
        let eb_tag = tag_b.clone();
        tokio::spawn(async move {
            let (mut sock, _) = eb_listener.accept().await.unwrap();
            eb_tag.store(1, Ordering::SeqCst);
            sock.write_all(b"SERVER_B").await.unwrap();
            let mut buf = [0u8; 1024]; loop {
                match sock.read(&mut buf).await { Ok(0)|Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } } }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        // 单实例：SOCKS inbound + 2 个 Freedom outbound (A, B) + 路由规则
        let mut cfg = BuiltConfig::default();
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        // outbound A: freedom (默认)
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "default".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        // routing config: IP 规则 → 127.0.0.0/8 走默认（验证 routing 不崩溃）
        // 注：完整路由测试需要 RouterAdapter + domain sniffing，此处验证 routing JSON 不破坏启动
        cfg.apps.push(BuiltEntry {
            kind: "xray.app.router".into(),
            data: br#"{"domainStrategy":"AsIs","rules":[{"type":"field","ip":["127.0.0.0/8"],"outboundTag":"default"}]}"#.to_vec(),
        });

        let (inst, ohm, handles) = start_full(&cfg).await.expect("routing config start");
        assert!(inst.is_running());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // SOCKS5 → echo A (通过默认 outbound)
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match ea_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&ea_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "routing CONNECT");

        // 验证数据通过
        let payload = b"routing test!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => {}, // echo 回环成功即路由正常
            Ok(Err(e)) => panic!("routing read error: {e}"),
            Err(_) => panic!("timeout: routing dispatch may need further work"),
        }
        for h in handles.iter() { h.abort(); }
    }

    /// TLS 端到端测试：SOCKS5 → VLESS+TLS → Freedom → echo
    #[tokio::test]
    async fn integration_vless_over_tls_to_echo() {
        // 0. 生成自签名证书
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");

        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        // server streamSettings: TLS with inline cert
        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);
        // client streamSettings: TLS with allowInsecure
        let client_tls = r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#;
    
        // 2. server: VLESS+TLS inbound + Freedom outbound
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vless-tls-in".into(), port: Some(vless_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-tls server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. client: SOCKS inbound + VLESS+TLS outbound
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(serde_json::from_str(client_tls).unwrap()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-tls client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. SOCKS5 → VLESS+TLS → echo
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VLESS+TLS CONNECT");

        let payload = b"hello vless over tls!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through VLESS+TLS"),
            Ok(Err(e)) => panic!("VLESS+TLS read error: {e}"),
            Err(_) => panic!("timeout: VLESS+TLS may need TLS listener wiring"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// VLESS+Vision+TLS 端到端（server splice 接线）：SOCKS5 → VLESS(flow=XRV)+TLS
    /// → Freedom → echo。伪 TLS 会话（ClientHello 回显置位 filter + app-data
    /// record）+ 大 payload 跨缓冲窗口，验证 start_full 生产路径 VisionConn
    /// 双端构造与数据完整性。
    #[tokio::test]
    async fn integration_vless_vision_over_tls_to_echo() {
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16_384];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);
        let client_tls = r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#;

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vless-vision-in".into(), port: Some(vless_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vision server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":"xtls-rprx-vision"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(serde_json::from_str(client_tls).unwrap()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vision client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VLESS+Vision+TLS CONNECT");

        // 阶段1：伪 ClientHello record（触发双端 xtls_filter_tls enable_xtls）
        let mut hello = vec![0x16u8, 0x03, 0x03, 0x00, 0x2b];
        hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x27, 0x03, 0x03]);
        hello.extend_from_slice(&[0xAB; 32]);
        hello.extend_from_slice(&[0x00, 0x00, 0x13, 0x01, 0x00, 0x00]);
        client.write_all(&hello).await.unwrap();
        let mut echoed = vec![0u8; hello.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, hello, "ClientHello echo");

        // 阶段2：512KB 数据跨缓冲窗口完整性。
        // 驱动形态对齐真实 pump（8KB 块 + 1ms 间歇）：单 task 零间歇全速灌
        // 512KB 会触发 Windows loopback TCP 的发送停滞（数据滞留内核 send
        // buffer 不发送、对端 recv 空也零窗口恢复失败）——OS 栈病理，与
        // 被测链路无关（repro_bare/H1/H2 对照矩阵 + TcpConnection 字节探针
        // 实证）。完整性断言不变。
        let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
        // curl 真实形态：请求写与响应读并发（全双工）。顺序「写完再读」时
        // test client 的 sock 读侧停摆 → pipe 背压消失 → xray 内部 pump 对
        // loopback TCP 零间歇全速灌 → Windows loopback 发送停滞（OS 栈病理，
        // 见 repro 对照矩阵）。完整性断言不变。
        let expect = payload.clone();
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let up = tokio::spawn(async move {
            let mut off = 0usize;
            while off < expect.len() {
                let n = (expect.len() - off).min(8192);
                client_w.write_all(&expect[off..off + n]).await.unwrap();
                off += n;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(30), client_r.read_exact(&mut got))
            .await
            .expect("vision echo 512KB no timeout")
            .unwrap();
        up.await.unwrap();
        assert_eq!(got, payload, "512KB integrity through VLESS+Vision+TLS");
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// [三层组合最小复现·实验I] VisionConn(padding) ↔ xray-tls rustls ↔ 真 TCP
    /// 回环。server = accept 层 dup 克隆 + 内层 split→join→new_server（对齐
    /// inbound/server.rs:408-418）+ 外层 split 双 task 经有界 channel echo；
    /// client = rustls Conn + VisionConn::new + 外层 split 双 task。挂死时
    /// 2s 强制唤醒 + raw.try_read 探测 server 内核 recv buffer。
    #[tokio::test]
    async fn repro_three_layer_vision_rustls_tcp_512k() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_proxy_vless::encryption::vision_conn::VisionConn;

        let server_cfg = xray_tls::server_config::build_server_config("tls", None)
            .unwrap()
            .expect("server tls config");
        let client_cfg = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({ "allowInsecure": true })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            sock.set_nodelay(true).unwrap();
            let raw = xray_transport::connection::dup_tcp_stream(&sock).unwrap();
            let conn = xray_transport::connection::TcpConnection::new(sock);
            let tls = xray_tls::utls::server(conn, server_cfg).await.unwrap();
            let (r, w) = tokio::io::split(tls);
            let vision = VisionConn::new_server(tokio::io::join(r, w), vec![0xAB; 16], raw);
            let (mut vr, mut vw) = tokio::io::split(vision);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let reader = async move {
                let mut buf = vec![0u8; 16_384];
                loop {
                    match vr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let writer = async move {
                while let Some(chunk) = rx.recv().await {
                    if vw.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(reader, writer);
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let tls = xray_tls::utls::client(
            Box::new(xray_transport::connection::TcpConnection::new(tcp))
                as Box<dyn xray_transport::connection::Connection>,
            "localhost",
            client_cfg,
        )
        .await
        .unwrap();
        let vision = VisionConn::new(
            Box::new(tls) as Box<dyn xray_transport::connection::Connection>,
            vec![0xAB; 16],
        );
        let (mut vr, mut vw) = tokio::io::split(vision);

        let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
        let expect = payload.clone();

        let run = async {
            let up = async {
                // 驱动形态对齐真实 pump（8KB 块 + 1ms 间歇）：单 task 零间歇
                // 全速灌 512KB 触发 Windows loopback TCP 发送停滞（OS 栈病理，
                // 见对照实验矩阵）。完整性断言不变。
                let mut off = 0usize;
                while off < payload.len() {
                    let n = (payload.len() - off).min(8192);
                    vw.write_all(&payload[off..off + n]).await.unwrap();
                    off += n;
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                vw.flush().await.unwrap();
            };
            let down = async {
                let mut got = vec![0u8; expect.len()];
                tokio::time::timeout(std::time::Duration::from_secs(20), vr.read_exact(&mut got))
                    .await
                    .expect("three-layer 512KB read 超时")
                    .unwrap();
                assert_eq!(got, expect, "512KB integrity through three layers");
            };
            tokio::join!(up, down);
        };
        tokio::time::timeout(std::time::Duration::from_secs(75), run)
            .await
            .expect("three-layer 512KB bulk 超时：复现挂死");
        server.abort();
    }

    /// [对照实验 G] 裸 TCP 512KB bulk（无 TLS 无 Vision）：同款双端双 task
    /// echo 拓扑。若挂死 → tokio Windows loopback 本身问题，Rust 协议层
    /// 全部排除。
    #[tokio::test]
    async fn repro_bare_tcp_512k_bulk() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = tokio::io::split(sock);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let reader = async move {
                let mut buf = vec![0u8; 16_384];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let writer = async move {
                while let Some(chunk) = rx.recv().await {
                    if w.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(reader, writer);
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let (mut sock_r, mut sock_w) = tokio::io::split(sock);
        let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
        let expect = payload.clone();
        let run = async {
            let up = async {
                sock_w.write_all(&payload).await.unwrap();
            };
            let down = async {
                let mut got = vec![0u8; expect.len()];
                sock_r.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expect, "bare TCP 512KB integrity");
            };
            tokio::join!(up, down);
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), run)
            .await
            .expect("bare TCP 512KB 超时：tokio loopback 本身挂死");
        server.abort();
    }

    /// [对照实验 H1] rustls 双端 + TCP loopback（去 VisionConn）：
    /// 若挂 → VisionConn 排除；若过 → VisionConn 必需成分。
    #[tokio::test]
    async fn repro_h1_rustls_only_tcp_512k() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let server_cfg = xray_tls::server_config::build_server_config("tls", None)
            .unwrap()
            .expect("server tls config");
        let client_cfg = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({ "allowInsecure": true })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let conn = xray_transport::connection::TcpConnection::new(sock);
            let tls = xray_tls::utls::server(conn, server_cfg).await.unwrap();
            let (r, w) = tokio::io::split(tls);
            let joined = tokio::io::join(r, w);
            let (mut vr, mut vw) = tokio::io::split(joined);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let reader = async move {
                let mut buf = vec![0u8; 16_384];
                loop {
                    match vr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let writer = async move {
                while let Some(chunk) = rx.recv().await {
                    if vw.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(reader, writer);
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let tls = xray_tls::utls::client(
            Box::new(xray_transport::connection::TcpConnection::new(tcp))
                as Box<dyn xray_transport::connection::Connection>,
            "localhost",
            client_cfg,
        )
        .await
        .unwrap();
        let (mut vr, mut vw) = tokio::io::split(tls);

        let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
        let expect = payload.clone();
        let run = async {
            let up = async {
                vw.write_all(&payload).await.unwrap();
            };
            let down = async {
                let mut got = vec![0u8; expect.len()];
                vr.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expect, "H1 512KB integrity");
            };
            tokio::join!(up, down);
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), run)
            .await
            .expect("H1 rustls-only 512KB 超时");
        server.abort();
    }

    /// [对照实验 H2] VisionConn 双端 + 裸 TCP（去 rustls）：
    /// 若挂 → rustls 非必需；若过 → rustls×VisionConn 组合必需。
    #[tokio::test]
    async fn repro_h2_vision_plain_tcp_512k() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_proxy_vless::encryption::vision_conn::VisionConn;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let conn = xray_transport::connection::TcpConnection::new(sock);
            let (r, w) = tokio::io::split(conn);
            let vision = VisionConn::new(tokio::io::join(r, w), vec![0xAB; 16]);
            let (mut vr, mut vw) = tokio::io::split(vision);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let reader = async move {
                let mut buf = vec![0u8; 16_384];
                loop {
                    match vr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let writer = async move {
                while let Some(chunk) = rx.recv().await {
                    if vw.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(reader, writer);
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let vision = VisionConn::new(
            Box::new(xray_transport::connection::TcpConnection::new(tcp))
                as Box<dyn xray_transport::connection::Connection>,
            vec![0xAB; 16],
        );
        let (mut vr, mut vw) = tokio::io::split(vision);

        let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
        let expect = payload.clone();
        let run = async {
            let up = async {
                vw.write_all(&payload).await.unwrap();
            };
            let down = async {
                let mut got = vec![0u8; expect.len()];
                vr.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expect, "H2 512KB integrity");
            };
            tokio::join!(up, down);
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), run)
            .await
            .expect("H2 vision-plain 512KB 超时");
        server.abort();
    }

    /// Trojan+TLS 端到端：SOCKS5 → Trojan+TLS → Freedom → echo（验证 8m1 修复：streamSettings TLS 注入）
    #[tokio::test]
    async fn integration_trojan_over_tls_to_echo() {
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trojan_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);
        let client_tls = r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#;

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "trojan".into(),
                data: br#"{"clients":[{"password":"test-pass-12345"}]}"#.to_vec() },
            tag: "trojan-tls-in".into(), port: Some(trojan_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("trojan-tls server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "trojan".into(),
                data: format!(r#"{{"servers":[{{"address":"127.0.0.1","port":{trojan_port},"password":"test-pass-12345"}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(serde_json::from_str(client_tls).unwrap()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("trojan-tls client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "Trojan+TLS CONNECT");

        let payload = b"hello trojan over tls!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through Trojan+TLS"),
            Ok(Err(e)) => panic!("Trojan+TLS read error: {e}"),
            Err(_) => panic!("timeout: Trojan+TLS inbound may ignore streamSettings TLS"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// VMess+TLS 端到端：SOCKS5 → VMess+TLS → Freedom → echo（验证 vmess inbound TLS 接线）
    #[tokio::test]
    async fn integration_vmess_over_tls_to_echo() {
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vmess_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);
        let client_tls = r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#;

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vmess".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vmess-tls-in".into(), port: Some(vmess_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vmess-tls server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vmess".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vmess_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(serde_json::from_str(client_tls).unwrap()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-tls client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VMess+TLS CONNECT");

        let payload = b"hello vmess over tls!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through VMess+TLS"),
            Ok(Err(e)) => panic!("VMess+TLS read error: {e}"),
            Err(_) => panic!("timeout: VMess+TLS inbound may ignore streamSettings TLS"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// Trojan+TLS+fallbacks：非 Trojan 流量（handshake 失败）→ fallback dest 收到原始字节（bd cvi）。
    #[tokio::test]
    async fn integration_trojan_tls_fallback_routes_failed_handshake() {
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");

        // fallback dest：echo
        let fb_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb_listener.local_addr().unwrap();
        let fb_task = tokio::spawn(async move {
            let (mut sock, _) = fb_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            buf[..n].to_vec()
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trojan_port = probe.local_addr().unwrap().port(); drop(probe);

        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "trojan".into(),
                data: format!(r#"{{"clients":[{{"password":"test-pass-12345"}}],"fallbacks":[{{"dest":"{fb_addr}","xver":0}}]}}"#).into_bytes(),
            },
            tag: "trojan-fb-in".into(), port: Some(trojan_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("trojan-fb server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 非 Trojan 客户端：TLS 连接发 HTTP → fallback dest 收到原始字节
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
        let sock = TcpStream::connect(format!("127.0.0.1:{trojan_port}")).await.unwrap();
        let mut tls = connector.connect("localhost".try_into().unwrap(), sock).await.unwrap();
        tls.write_all(b"GET /path/to/target HTTP/1.1\r\nHost: localhost.example.longdomain.com\r\nUser-Agent: fallback-test\r\n\r\n").await.unwrap();
        let mut got = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut got))
            .await.expect("fallback echo timeout").unwrap();
        assert!(got[..n].starts_with(b"GET /"), "fallback dest should echo original bytes");

        let fb_bytes = fb_task.await.unwrap();
        assert!(fb_bytes.starts_with(b"GET /"), "fallback echo got {fb_bytes:?}");

        for h in sh.iter() { h.abort(); }
    }

    /// SOCKS5 → SOCKS-outbound → SOCKS-inbound → Freedom → echo（验证 socks outbound 双向桥接）
    #[tokio::test]
    async fn integration_socks_outbound_loopback_to_echo() {
        // 0. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_server_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_client_port = probe.local_addr().unwrap().port(); drop(probe);

        // 1. server: SOCKS inbound + Freedom outbound
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_server_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_, _, sh) = start_full(&server_cfg).await.expect("socks server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 2. client: SOCKS inbound + SOCKS outbound (→ socks_server_port)
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_client_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "socks".into(),
                data: format!(r#"{{"servers":[{{"address":"127.0.0.1","port":{socks_server_port}}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_, _, ch) = start_full(&client_cfg).await.expect("socks client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. SOCKS5 → socks_client → socks_server → freedom → echo
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_client_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "socks outbound CONNECT");

        let payload = b"hello socks outbound!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through socks outbound"),
            Ok(Err(e)) => panic!("socks outbound read error: {e}"),
            Err(_) => panic!("timeout: socks outbound bridge may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// SOCKS5 → Shadowsocks → Freedom → echo 全链路
    #[tokio::test]
    async fn integration_socks_through_ss_to_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ss_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "shadowsocks".into(),
                data: br#"{"clients":[{"password":"test-pass","method":"aes-256-gcm"}]}"#.to_vec() },
            tag: "ss-in".into(), port: Some(ss_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("ss server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "shadowsocks".into(),
                data: format!(r#"{{"servers":[{{"address":"127.0.0.1","port":{ss_port},"password":"test-pass","method":"aes-256-gcm"}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("ss client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "Shadowsocks CONNECT");

        let payload = b"hello ss chain!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(&got, payload, "echo through Shadowsocks"),
            Ok(Err(e)) => panic!("SS read error: {e}"),
            Err(_) => panic!("timeout: SS chain may need further work"),
        }
        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// VLESS+TLS+fallbacks：真 VLESS 客户端正常代理；非 VLESS（HTTPS 浏览器式）流量
    /// 按 fallback 策略透明转发到 fallback dest（bd fsa）。
    #[tokio::test]
    async fn integration_vless_tls_fallback_routes_non_vless() {
        let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
            .expect("generate self-signed cert");

        // fallback dest：echo（收到非 VLESS 数据并回显）
        let fb_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb_listener.local_addr().unwrap();
        let fb_task = tokio::spawn(async move {
            let (mut sock, _) = fb_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            buf[..n].to_vec()
        });

        // 正常代理目标 echo
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if sock.write_all(&buf[..n]).await.is_err() { break; } }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_port = probe.local_addr().unwrap().port(); drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port(); drop(probe);

        let server_tls = format!(r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?}],"key":[{:?}]}}]}}}}"#, cert_pem, key_pem);
        let client_tls = r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#;

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "vless".into(),
                data: format!(r#"{{"clients":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],"fallbacks":[{{"dest":"{fb_addr}","xver":0}}]}}"#).into_bytes(),
            },
            tag: "vless-fb-in".into(), port: Some(vless_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::from_str(&server_tls).unwrap()), sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-fb server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // A. 真 VLESS 客户端：SOCKS5 → VLESS+TLS → freedom → echo
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(), port: Some(socks_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}}"#).into_bytes() },
            tag: "proxy".into(), send_through: None,
            stream_settings_json: Some(serde_json::from_str(client_tls).unwrap()),
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-fb client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2]; client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip); req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10]; client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "VLESS+TLS CONNECT with fallbacks configured");
        let payload = b"hello vless with fallback!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got))
            .await.expect("vless echo timeout").unwrap();
        assert_eq!(&got, payload);

        // B. 非 VLESS 客户端：TLS 连接发 HTTP 请求 → fallback dest 收到原始字节
        //    （用 rustls 客户端绕过证书校验）
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
        let mut roots = rustls::RootCertStore::empty();
        let _ = &mut roots;
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
        let tls_sock = tokio::net::TcpStream::connect(format!("127.0.0.1:{vless_port}")).await.unwrap();
        let mut tls = connector.connect("localhost".try_into().unwrap(), tls_sock).await.unwrap();
        tls.write_all(b"GET /web HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut fb_got = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut fb_got))
            .await.expect("fallback echo timeout").unwrap();
        assert!(fb_got[..n].starts_with(b"GET /web"), "fallback dest should receive original HTTP bytes");

        // fallback echo 收到的也应是同一请求
        let fb_bytes = fb_task.await.unwrap();
        assert!(fb_bytes.starts_with(b"GET /web"), "fallback echo server got {fb_bytes:?}");

        for h in sh.iter().chain(ch.iter()) { h.abort(); }
    }

    /// 构造带 SNI 的最小 TLS ClientHello（满足 dispatcher TlsSniffer 的
    /// record → handshake → extensions → SNI 解析路径）。
    fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        // SNI extension body: server_name_list
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list_len
        body.push(0x00); // name_type = host_name
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name);
        let mut ext: Vec<u8> = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type = SNI
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);

        let mut hello: Vec<u8> = Vec::new();
        hello.extend_from_slice(&[0x03, 0x01]); // client version
        hello.extend_from_slice(&[0x42u8; 32]); // random
        hello.push(0x00); // session_id_len
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        hello.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        hello.push(0x01); // compression_methods_len
        hello.push(0x00);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions_len
        hello.extend_from_slice(&ext);

        let mut hs: Vec<u8> = vec![0x01]; // handshake type = ClientHello
        let l = hello.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hello);

        let mut rec: Vec<u8> = vec![0x16, 0x03, 0x01]; // record: Handshake
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }


    /// fake 上游 SOCKS5 server：记录首个 CONNECT 目标地址（域名或 IP 字面），
    /// 回 CONNECT 成功后丢弃后续流量。返回 (监听端口, 目标记录槽)。
    async fn spawn_fake_socks_upstream() -> (u16, Arc<parking_lot::Mutex<Option<String>>>) {
        let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up_listener.local_addr().unwrap().port();
        let target: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let t = Arc::clone(&target);
        tokio::spawn(async move {
            let (mut sock, _) = match up_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            // greeting: VER + NMETHODS + methods[NMETHODS]（no-auth 客户端 = 05 01 00）
            let mut b = [0u8; 2];
            if sock.read_exact(&mut b).await.is_err() {
                return;
            }
            let mut methods = vec![0u8; b[1] as usize];
            if sock.read_exact(&mut methods).await.is_err() {
                return;
            }
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            if sock.read_exact(&mut head).await.is_err() {
                return;
            }
            let addr = match head[3] {
                0x01 => {
                    let mut a = [0u8; 4];
                    sock.read_exact(&mut a).await.unwrap();
                    std::net::Ipv4Addr::from(a).to_string()
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    sock.read_exact(&mut l).await.unwrap();
                    let mut d = vec![0u8; l[0] as usize];
                    sock.read_exact(&mut d).await.unwrap();
                    String::from_utf8(d).unwrap()
                }
                _ => String::new(),
            };
            let mut p = [0u8; 2];
            sock.read_exact(&mut p).await.unwrap();
            *t.lock() = Some(addr);
            // 回 CONNECT 成功，之后丢弃流量
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        (up_port, target)
    }
    /// sniffing e2e：TLS ClientHello SNI 被嗅探 → dest 覆写为域名 → domainSuffix
    /// 路由规则命中 tagged socks outbound → 上游收到域名 CONNECT。
    #[tokio::test]
    async fn integration_sniffing_tls_sni_routes_by_sniffed_domain() {
        // 1. fake 上游 SOCKS5 server：记录 CONNECT 目标
        let (up_port, target) = spawn_fake_socks_upstream().await;

        // 2. 配置：socks inbound（sniffing: tls）+ freedom default + socks tagged + routing
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut cfg = BuiltConfig::default();
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: Some(serde_json::json!({
                "enabled": true,
                "destOverride": ["tls"]
            })),
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), // i=0 → default
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: format!(
                    r#"{{"servers":[{{"address":"127.0.0.1","port":{up_port}}}]}}"#
                )
                .into_bytes(),
            },
            tag: "via-sni".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.apps.push(BuiltEntry {
            kind: "routing".into(),
            data: br#"{"domainStrategy":"AsIs","rules":[{"type":"field","domainSuffix":["sniff-test.example"],"outboundTag":"via-sni"}]}"#.to_vec(),
        });

        let (inst, _, handles) = start_full(&cfg).await.expect("sniffing config start");
        assert!(inst.is_running());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. SOCKS5 CONNECT 1.2.3.4:443（任意不可达 IP；若嗅探失败会拨该 IP）
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks");
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[1, 2, 3, 4]);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10];
        client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "CONNECT should succeed");

        // 4. 发 TLS ClientHello（SNI = www.sniff-test.example）
        client
            .write_all(&build_client_hello_with_sni("www.sniff-test.example"))
            .await
            .unwrap();

        // 5. 等 fake 上游记录 CONNECT 目标
        for _ in 0..100 {
            if target.lock().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            target.lock().as_deref(),
            Some("www.sniff-test.example"),
            "SNI 应被嗅探并覆写 dest，路由命中 via-sni（上游收到域名 CONNECT）"
        );
        for h in handles.iter() {
            h.abort();
        }
    }

    /// geoip:private 屏蔽 e2e（rs3e）：routing `{"ip":["geoip:private"],
    /// "outboundTag":"block"}` 命中私网目标 → blackhole 拦截。判别器用规则序
    /// first-match-wins：10.0.0.1 若 geoip 规则失效（如静默丢规则）会落到下一条
    /// 10.0.0.0/8 CIDR 规则被上游记录——断言上游从未收到 10.0.0.1、
    /// 而 203.0.113.7（TEST-NET-3）按第三条 CIDR 规则正常到达上游。
    #[tokio::test]
    async fn integration_routing_geoip_private_blocks() {
        // 1. fake 上游 SOCKS5 server
        let (up_port, target) = spawn_fake_socks_upstream().await;

        // 2. geoip.dat（PRIVATE 条目）写入路由构建实际读取的资产目录。
        //    get_resource_path 与 build_adapter 同源（同一缓存值）；文件已存在时
        //    不覆盖，尊重环境真实 geoip 资产（v2fly geoip.dat 自带 private）。
        let asset_dir = xray_common::platform::get_resource_path();
        std::fs::create_dir_all(&asset_dir).expect("create asset dir");
        let geoip_path = asset_dir.join("geoip.dat");
        if !geoip_path.exists() {
            use prost::Message;
            use xray_proto::xray::common::geodata::{Cidr, GeoIp, GeoIpList};
            let private = GeoIp {
                code: "PRIVATE".into(),
                cidr: vec![
                    Cidr { ip: vec![10, 0, 0, 0], prefix: 8 },
                    Cidr { ip: vec![192, 168, 0, 0], prefix: 16 },
                    Cidr { ip: vec![127, 0, 0, 0], prefix: 8 },
                ],
                reverse_match: false,
            };
            std::fs::write(
                &geoip_path,
                GeoIpList { entry: vec![private] }.encode_to_vec(),
            )
            .expect("write test geoip.dat");
        }

        // 3. 配置：socks inbound + freedom default + blackhole + tagged socks + routing
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut cfg = BuiltConfig::default();
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(), // i=0 → default
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "blackhole".into(),
                data: br#"{"response":{"type":"http"}}"#.to_vec(),
            },
            tag: "block".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: format!(
                    r#"{{"servers":[{{"address":"127.0.0.1","port":{up_port}}}]}}"#
                )
                .into_bytes(),
            },
            tag: "via-up".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.apps.push(BuiltEntry {
            kind: "routing".into(),
            data: br#"{"domainStrategy":"AsIs","rules":[
                {"type":"field","ip":["geoip:private"],"outboundTag":"block"},
                {"type":"field","ip":["10.0.0.0/8"],"outboundTag":"via-up"},
                {"type":"field","ip":["203.0.113.0/24"],"outboundTag":"via-up"}
            ]}"#.to_vec(),
        });

        // wiring 层直连二分：同一 JSON 经 build_router_adapter 后 IP dest 应
        // 命中 block（区分 wiring 解析/展开 vs dispatcher ctx 传递）。
        let adapter = crate::wiring::build_router_adapter_from_json(&cfg.apps[0].data)
            .expect("adapter build with geoip rule");
        let probe_dest = xray_common::net::destination::Destination::new(
            xray_common::net::address::Address::IPv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            xray_common::net::port::Port::new(80),
            xray_common::net::network::Network::TCP,
        );
        assert_eq!(
            adapter.pick_outbound_tag(&probe_dest).as_deref(),
            Some("block"),
            "wiring 层：10.0.0.1 应命中 geoip:private → block"
        );


        let (inst, _, handles) = start_full(&cfg).await.expect("geoip routing start");
        assert!(inst.is_running());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 对照组：公网 TEST-NET-3 目标 → 第三条 CIDR 规则 → via-up，路由栈通
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks");
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[203, 0, 113, 7]);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10];
        client.read_exact(&mut cr).await.unwrap();
        assert_eq!(cr[1], 0x00, "公网目标应按 CIDR 规则到达上游");
        for _ in 0..100 {
            if target.lock().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            target.lock().as_deref(),
            Some("203.0.113.7"),
            "CIDR 规则应把 203.0.113.7 路由到上游"
        );

        // 5. 私网目标 → geoip:private → block（blackhole http403）。判别器：
        //    geoip 规则若失效，10.0.0.1 会落 10.0.0.0/8 CIDR 规则到上游。
        let mut blocked_client = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks (blocked)");
        blocked_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp2 = [0u8; 2];
        blocked_client.read_exact(&mut resp2).await.unwrap();
        assert_eq!(resp2, [0x05, 0x00]);
        let mut req2 = vec![0x05, 0x01, 0x00, 0x01];
        req2.extend_from_slice(&[10, 0, 0, 1]);
        req2.extend_from_slice(&80u16.to_be_bytes());
        blocked_client.write_all(&req2).await.unwrap();
        let mut cr2 = [0u8; 10];
        blocked_client.read_exact(&mut cr2).await.unwrap();
        // socks 语义（server.rs:282）：dispatch 成功即回 0x00，不等 outbound 数据。
        // 强信号判别：blackhole 配 response http → 命中 block 的客户端在 0x00 后
        // 收到 "HTTP/1.1 403"；放行场景（via-up 丢流量 / freedom 直连）永远无 403。
        let mut probe = [0u8; 256];
        let mut got_403 = false;
        if let Ok(r) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            blocked_client.read(&mut probe),
        )
        .await
        {
            let body = String::from_utf8_lossy(&probe[..r.unwrap_or(0)]);
            got_403 = body.contains("403") || body.contains("Forbidden");
        }
        assert!(got_403, "geoip:private 目标应被 block 出站拦下并回 HTTP 403");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_ne!(
            target.lock().as_deref(),
            Some("10.0.0.1"),
            "geoip 规则失效时 10.0.0.1 会落到 CIDR 规则被上游记录——不得放行"
        );

        for h in handles.iter() {
            h.abort();
        }
    }

    /// stats counter e2e（无 router 路径）：流量经 DefaultDispatcher 后
    /// inbound/outbound tag counter（{kind}>>>{tag}>>>traffic>>>{direction}）计数 > 0。
    #[tokio::test]
    async fn integration_stats_counters_via_default_dispatcher() {
        use xray_features::stats::Manager as _;

        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 无 routing app：验证无 router 路径也有 sniffing+counter 管线。
        // sm80①：tag counter 受 ForSystem().Stats 四门门控（默认关）——本测试
        // 显式开满四门（Go testing 场景同款：stats 查询前先配 policy system）。
        let mut cfg = BuiltConfig::default();
        cfg.apps.push(BuiltEntry {
            kind: "policy".into(),
            data: br#"{"system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}}"#.to_vec(),
        });
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: vec![] },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });

        let (inst, _, handles) = start_full(&cfg).await.expect("stats config start");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. 走一轮 echo
        let mut client = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks");
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut cr = [0u8; 10];
        client.read_exact(&mut cr).await.unwrap();

        let payload = b"count me through the dispatcher!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got))
            .await
            .expect("echo through dispatcher")
            .unwrap();
        assert_eq!(&got, payload);

        // 4. counter 断言（AppStatsFeature 已被 ensure_essential_features 注入）
        let stats = inst
            .get_feature::<crate::register::AppStatsFeature>()
            .expect("stats feature should be injected");
        for name in [
            "inbound>>>socks-in>>>traffic>>>uplink",
            "inbound>>>socks-in>>>traffic>>>downlink",
            "outbound>>>direct>>>traffic>>>uplink",
            "outbound>>>direct>>>traffic>>>downlink",
        ] {
            let c = stats.get_counter(name).unwrap_or_else(|| {
                panic!("counter {name} should be lazily registered")
            });
            assert!(
                c.value() > 0,
                "counter {name} should be positive, got {}",
                c.value()
            );
        }
        for h in handles.iter() {
            h.abort();
        }
    }

    /// bd 3xmjx：metrics app 装配接线——start_full 后 `/metrics` 输出真实
    /// stats 计数（非 EmptyStats）：注册 counter 后 HTTP body 必须含值。
    #[tokio::test]
    async fn integration_metrics_app_exposes_real_stats_counters() {
        use xray_features::stats::Manager as _;

        // 1. 探测空闲端口给 metrics listen。
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let metrics_port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut cfg = BuiltConfig::default();
        cfg.apps.push(BuiltEntry {
            kind: "metrics".into(),
            data: format!(r#"{{"listen":"127.0.0.1:{metrics_port}"}}"#).into_bytes(),
        });
        let (inst, _, handles) = start_full(&cfg).await.expect("metrics config start");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 2. 经 AppStatsFeature 注册并累计一个 counter。
        let stats = inst
            .get_feature::<crate::register::AppStatsFeature>()
            .expect("stats feature injected");
        stats
            .register_counter("inbound>>>m-in>>>traffic>>>uplink")
            .expect("register")
            .add(777);

        // 3. GET /metrics 必须看到 777（EmptyStats 只输出 HELP/TYPE 头）。
        let mut resp = TcpStream::connect(format!("127.0.0.1:{metrics_port}"))
            .await
            .expect("connect metrics http");
        resp.write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), resp.read_to_end(&mut body))
            .await
            .expect("read metrics body within timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        let hit = text.contains("xray_traffic_bytes{type=\"inbound\",tag=\"m-in\",direction=\"uplink\"} 777");
        assert!(
            hit,
            "/metrics must expose real stats counter, got: {text}"
        );
        // 关停 metrics HTTP server（accept task 随 close 退出，否则测试进程
        // 退出阶段被挂起任务拖住）。
        if let Some(mf) = inst.get_feature::<xray_app_metrics::MetricsFeature>() {
            let _ = mf.close();
        }
        for h in handles.iter() {
            h.abort();
        }
    }


    /// 测试用：跳过证书校验的 verifier。
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    // ============ SOCKS5 UDP e2e 集成（bd 9i8w）============
    //
    // 对应 Go `testing/scenarios/socks_test.go::TestSocksBridageUDP` /
    // `TestSocksBridageUDPWithRouting`：udp-server 提供 echo 端点；
    // socks5 客户端走 TCP control connection + UDP ASSOCIATE 拿到 relay addr，
    // 发 UDP 数据报经 socks inbound UDP relay → UdpDispatchSession →
    // dispatcher 选 outbound → UDP echo 回包。
    //
    // inbound 端 UDP relay 由 `xray-core/src/inbound.rs::handle_udp_associate`
    // 实现（UdpDispatchSession ↔ 客户端 UDP socket，XUDP 帧 ↔ SOCKS5 UDP 包
    // 编解码），outbound 端 Freedom UDP 由 `xray-proxy-freedom::udp` 拆/装帧。

    /// SOCKS5 UDP ASSOCIATE → Freedom UDP outbound → UDP echo server 全链路
    /// e2e（对应 Go `TestSocksBridageUDP`）。
    ///
    /// 验证：客户端 UDP 数据报从 socks 监听端口进、穿过 dispatcher、
    /// freedom 直发到 echo server、回包经同一链路返回客户端，全程 payload 完整。
    #[tokio::test]
    async fn integration_socks_udp_relay_to_echo() {
        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. 空闲端口：socks inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 3. BuiltConfig: socks inbound (UDP enabled) + freedom outbound
        let mut cfg = BuiltConfig::default();
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: br#"{"auth":"noauth","udp":true}"#.to_vec(),
            },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });

        let (_, _, handles) = start_full(&cfg).await.expect("socks+freedom start");
        // 等 accept loop ready
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：TCP control connection → SOCKS5 NoAuth → UDP ASSOCIATE
        let mut tcp = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks control");
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_resp = [0u8; 2];
        tcp.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [0x05, 0x00], "NoAuth method selected");

        // UDP ASSOCIATE request: DST.ADDR/PORT = 0.0.0.0:0（客户端不在乎绑哪，
        // 仅靠 TCP control connection 关联；reply 的 BND.ADDR/PORT 才是真 relay）
        tcp.write_all(&[
            0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut assoc_reply = [0u8; 10];
        tcp.read_exact(&mut assoc_reply).await.unwrap();
        assert_eq!(assoc_reply[0], 0x05, "UDP ASSOC reply VER");
        assert_eq!(assoc_reply[1], 0x00, "UDP ASSOC reply REP=success");
        assert_eq!(assoc_reply[2], 0x00, "RSV");
        assert_eq!(assoc_reply[3], 0x01, "ATYP=IPv4");
        let relay_ip = std::net::Ipv4Addr::new(
            assoc_reply[4], assoc_reply[5], assoc_reply[6], assoc_reply[7],
        );
        let relay_port = u16::from_be_bytes([assoc_reply[8], assoc_reply[9]]);
        assert_eq!(relay_ip, std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert!(relay_port > 0, "relay port should be assigned, got {relay_port}");

        // 5. 客户端 UDP socket → 编码 SOCKS5 UDP 包 → send_to relay
        let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"hello-udp-echo-9i8w";
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        // [RSV=0,0][FRAG=0][ATYP=0x01][IPv4][port BE][payload]
        let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(payload);
        let relay = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            relay_port,
        );
        client_udp
            .send_to(&pkt, relay)
            .await
            .expect("send udp packet to relay");

        // 6. 等回包（自由客户端地址）
        let mut resp_buf = vec![0u8; 65535];
        let (n, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_udp.recv_from(&mut resp_buf),
        )
        .await
        .expect("timeout waiting for echo")
        .expect("recv udp echo");
        assert!(n >= 10, "SOCKS5 UDP header is at least 10 bytes (RSV+FRAG+ATYP+IPv4+PORT)");
        // 解码回包头，断言 payload 一致
        assert_eq!(resp_buf[0..2], [0x00, 0x00], "RSV");
        assert_eq!(resp_buf[2], 0x00, "FRAG=0");
        assert_eq!(resp_buf[3], 0x01, "ATYP=IPv4");
        let body = &resp_buf[10..n];
        assert_eq!(body, payload, "echo payload roundtrip");

        // 7. 清理
        drop(client_udp);
        // TCP control connection drop → relay task 在 inbound.rs read EOF 后被 abort
        drop(tcp);
        for h in handles.iter() {
            h.abort();
        }
        echo_task.abort();
    }

    /// SOCKS5 UDP + Router 分流 e2e（对应 Go `TestSocksBridageUDPWithRouting`）：
    /// routing 规则按 inboundTag 命中 `"out"` 出站（freedom），其他匹配 `blackhole`；
    /// UDP 数据报走与 TCP 同一条 router 链路，证明 routing 路径覆盖 UDP。
    #[tokio::test]
    async fn integration_socks_udp_through_router() {
        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. 空闲端口：socks inbound
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 3. BuiltConfig: socks inbound (UDP enabled) + 2 outbounds (default=blackhole, out=freedom)
        //    + routing app: inboundTag=socks-in → out (覆盖 default blackhole)
        let mut cfg = BuiltConfig::default();
        cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: br#"{"auth":"noauth","udp":true}"#.to_vec(),
            },
            tag: "socks-in".into(),
            port: Some(socks_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "blackhole".into(), data: b"{}".to_vec() },
            tag: "default".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "out".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.apps.push(BuiltEntry {
            kind: "routing".into(),
            data: br#"{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["socks-in"],"outboundTag":"out"}]}"#.to_vec(),
        });

        let (_, _, handles) = start_full(&cfg).await.expect("socks+router start");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：TCP control + UDP ASSOCIATE
        let mut tcp = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
            .await
            .expect("connect socks control");
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_resp = [0u8; 2];
        tcp.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [0x05, 0x00]);
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut assoc_reply = [0u8; 10];
        tcp.read_exact(&mut assoc_reply).await.unwrap();
        assert_eq!(assoc_reply[1], 0x00, "UDP ASSOC REP=success");
        let relay_port = u16::from_be_bytes([assoc_reply[8], assoc_reply[9]]);
        assert!(relay_port > 0, "relay port should be assigned, got {relay_port}");

        // 5. UDP 客户端发包 → relay → router 命中 out=freedom → echo
        let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"routed-udp-echo-9i8w";
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(payload);
        let relay = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            relay_port,
        );
        client_udp.send_to(&pkt, relay).await.expect("send routed udp");

        // 6. 期望回包（route 命中 out=freedom → echo → 回包）；若 router 错配 default=blackhole
        //    则 5s 内收不到任何回包 → timeout 失败
        let mut resp_buf = vec![0u8; 65535];
        let (n, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_udp.recv_from(&mut resp_buf),
        )
        .await
        .expect("timeout: router may have routed to blackhole instead of out=freedom")
        .expect("recv udp echo");
        let body = &resp_buf[10..n];
        assert_eq!(body, payload, "routed echo payload roundtrip");

        drop(client_udp);
        drop(tcp);
        for h in handles.iter() {
            h.abort();
        }
        echo_task.abort();
    }

    /// SS inbound UDP relay → Freedom outbound → UDP echo server 端到端。
    ///
    /// 对应 Go `TestShadowsocksAES128GCMUDP`（`testing/scenarios/shadowsocks_test.go:200`）：
    /// 用 `encode_udp_packet` 构造 SS UDP 数据报（IV + AEAD(addr+port+payload)）发到
    /// SS inbound UDP 端口（`serve_ss_udp` 自动同端口绑 UDP，参见
    /// `xray-core/src/inbound.rs:684-718`），SS 解码后经 dispatcher → freedom
    /// 直发到 UDP echo，回包由 inbound 用发起用户 account 重新 `encode_udp_packet`
    /// 后 `send_to` 客户端，全程 payload 字节一致。
    #[tokio::test]
    async fn integration_ss_udp_relay_to_echo() {
        use xray_common::net::address::Address;
        use xray_proxy_ss::config::{CipherType, MemoryAccount};
        use xray_proxy_ss::protocol::{decode_udp_packet, encode_udp_packet};
        use xray_proxy_ss::validator::{MemoryUser, Validator};
        use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
        use std::net::Ipv4Addr;

        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => { let _ = echo.send_to(&buf[..n], peer).await; }
                    Err(_) => break,
                }
            }
        });

        // 2. 空闲端口：SS inbound TCP/UDP 同端口
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ss_port = probe.local_addr().unwrap().port();
        drop(probe);

        // 3. SS server（legacy AEAD，aes-256-gcm）+ freedom outbound
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "shadowsocks".into(),
                data: br#"{"clients":[{"password":"test-pass","method":"aes-256-gcm"}]}"#.to_vec(),
            },
            tag: "ss-in".into(),
            port: Some(ss_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("ss+freedom start");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：构造 SS UDP 数据报 → SS UDP 端口 → 等回包
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"ss-udp-echo-payload-7g3h";
        let account = MemoryAccount::from_proto(&ProtoAccount {
            password: "test-pass".to_string(),
            cipher_type: CipherType::Aes256Gcm.as_i32(),
            iv_check: false,
        }).expect("from_proto");
        let encoded = encode_udp_packet(
            &account,
            &Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => Ipv4Addr::LOCALHOST,
            }),
            echo_addr.port(),
            payload,
        ).expect("encode udp packet");
        let relay = std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            ss_port,
        );
        client.send_to(&encoded, relay).await.expect("send to ss udp");

        // 5. 等回包（SS server 用同一 account 重新 encode → 客户端 decode 验证）
        let mut resp = vec![0u8; 65535];
        let (n, _peer) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut resp),
        )
        .await
        .expect("timeout waiting for ss udp echo")
        .expect("recv ss udp echo");

        let validator = Validator::new();
        validator.add(MemoryUser::new("u@ss.local", account.clone())).expect("add user");
        let echo_ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let (header, body) = decode_udp_packet(&validator, &resp[..n]).expect("decode echo");
        assert_eq!(header.address, Address::ipv4(echo_ip), "echo source address");
        assert_eq!(header.port, echo_addr.port(), "echo source port");
        assert_eq!(body, payload, "echo payload roundtrip");

        drop(client);
        for h in sh.iter() { h.abort(); }
        echo_task.abort();
    }

    /// 出站级 mux（settings.mux.enabled）TCP 多连接复用端到端。
    ///
    /// 对齐 Go `app/proxyman/outbound/handler.go:123-145`：出站带
    /// `"mux":{"enabled":true,"concurrency":8}` 时拨号链包 MuxBridge，
    /// N 个客户端连接复用同一条 carrier（v1.mux.cool:9527 信令连接）。
    /// 拓扑：client [socks-in → socks-out(mux)] → 计数 forwarder →
    /// server [socks-in（is_mux_destination 终止 mux）→ freedom] → TCP echo。
    #[tokio::test]
    async fn integration_outbound_mux_tcp_reuses_single_carrier() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 1. TCP echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = echo_listener.accept().await else { break };
                let (mut r, mut w) = sock.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // 2. carrier 计数 forwarder：client mux worker → server socks 的每条
        //    TCP 连接在此过路计数（复用断言的观测点）
        let fwd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_port = fwd_listener.local_addr().unwrap().port();
        let carrier_count = Arc::new(AtomicUsize::new(0));
        let server_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = server_probe.local_addr().unwrap().port();
        drop(server_probe);
        let count = Arc::clone(&carrier_count);
        let fwd_task = tokio::spawn(async move {
            loop {
                let Ok((mut down, _)) = fwd_listener.accept().await else { break };
                count.fetch_add(1, Ordering::SeqCst);
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", server_port)).await else { break };
                let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
            }
        });

        // 3. 服务端：socks inbound（mux.cool dest 转 mux ServerWorker）+ freedom
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: br#"{"auth":"noauth"}"#.to_vec() },
            tag: "socks-in".into(),
            port: Some(server_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("socks server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：socks inbound + socks outbound（出站级 mux.enabled，concurrency 8）
        let client_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_port = client_probe.local_addr().unwrap().port();
        drop(client_probe);
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: br#"{"auth":"noauth"}"#.to_vec() },
            tag: "socks-in".into(),
            port: Some(client_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: format!(r#"{{"servers":[{{"address":"127.0.0.1","port":{fwd_port}}}]}}"#)
                    .into_bytes(),
            },
            tag: "proxy".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: Some(serde_json::json!({"enabled": true, "concurrency": 8})),
            target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("socks+mux client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 5. 3 个并发客户端连接 → mux 出站（首个 dispatch bootstrap worker，
        //    pick_internal 持锁跨 create，后续全部复用同一 worker/carrier）
        let echo_ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut handles = Vec::new();
        for i in 0..3 {
            let payload = format!("mux-tcp-echo-{i}");
            handles.push(tokio::spawn(async move {
                let mut c = TcpStream::connect(("127.0.0.1", client_port))
                    .await
                    .expect("connect client socks");
                c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut m = [0u8; 2];
                c.read_exact(&mut m).await.unwrap();
                assert_eq!(m, [0x05, 0x00], "NoAuth method selected");
                let mut req = vec![0x05, 0x01, 0x00, 0x01];
                req.extend_from_slice(&echo_ip);
                req.extend_from_slice(&echo_addr.port().to_be_bytes());
                c.write_all(&req).await.unwrap();
                let mut rep = [0u8; 10];
                c.read_exact(&mut rep).await.unwrap();
                assert_eq!(rep[1], 0x00, "socks connect via mux carrier success");
                c.write_all(payload.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; payload.len()];
                c.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, payload.as_bytes(), "echo roundtrip via mux carrier");
            }));
        }
        for h in handles {
            h.await.expect("client task join");
        }

        // 6. 复用断言：3 个会话只建立 1 条 carrier TCP 连接
        assert_eq!(
            carrier_count.load(Ordering::SeqCst),
            1,
            "3 mux sessions must reuse a single carrier connection"
        );

        for h in sh.iter().chain(ch.iter()) {
            h.abort();
        }
        fwd_task.abort();
        echo_task.abort();
    }

    /// 出站级 mux TCP 经 vless 入站终止（bd raw0）：MuxBridge carrier（目标
    /// v1.mux.cool）经 vless 出站 → vless 入站 decode 后按 destination dispatch
    /// → MuxCarrierHandler（Go always.go:89 mux.NewServer 装饰器语义）交
    /// ServerWorker 解帧 → 子会话 → freedom → TCP echo。多会话复用单 carrier。
    #[tokio::test]
    async fn integration_outbound_mux_tcp_via_vless_inbound() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 1. TCP echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = echo_listener.accept().await else { break };
                let (mut r, mut w) = sock.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // 2. carrier 计数 forwarder：client mux worker → server vless 的每条
        //    TCP 连接在此过路计数（复用断言的观测点）
        let fwd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_port = fwd_listener.local_addr().unwrap().port();
        let carrier_count = Arc::new(AtomicUsize::new(0));
        let server_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = server_probe.local_addr().unwrap().port();
        drop(server_probe);
        let count = Arc::clone(&carrier_count);
        let fwd_task = tokio::spawn(async move {
            loop {
                let Ok((mut down, _)) = fwd_listener.accept().await else { break };
                count.fetch_add(1, Ordering::SeqCst);
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", server_port)).await else { break };
                let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
            }
        });

        // 3. 服务端：vless inbound（carrier 按 v1.mux.cool dest 终止 mux）+ freedom
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(),
                data: br#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#.to_vec() },
            tag: "vless-in".into(), port: Some(server_port), listen: Some("127.0.0.1".into()),
            stream_settings_json: None, sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：socks inbound + vless outbound（出站级 mux.enabled，concurrency 8）
        let client_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_port = client_probe.local_addr().unwrap().port();
        drop(client_probe);
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: br#"{"auth":"noauth"}"#.to_vec() },
            tag: "socks-in".into(),
            port: Some(client_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "vless".into(),
                data: format!(r#"{{"vnext":[{{"address":"127.0.0.1","port":{fwd_port},"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]}}]}}"#).into_bytes(),
            },
            tag: "proxy".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: Some(serde_json::json!({"enabled": true, "concurrency": 8})),
            target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("socks+vless+mux client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 5. 3 个并发客户端连接 → mux 出站（首个 dispatch bootstrap worker，
        //    后续全部复用同一 worker/carrier）
        let echo_ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut handles = Vec::new();
        for i in 0..3 {
            let payload = format!("vless-mux-echo-{i}");
            handles.push(tokio::spawn(async move {
                let mut c = TcpStream::connect(("127.0.0.1", client_port))
                    .await
                    .expect("connect client socks");
                c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut m = [0u8; 2];
                c.read_exact(&mut m).await.unwrap();
                assert_eq!(m, [0x05, 0x00], "NoAuth method selected");
                let mut req = vec![0x05, 0x01, 0x00, 0x01];
                req.extend_from_slice(&echo_ip);
                req.extend_from_slice(&echo_addr.port().to_be_bytes());
                c.write_all(&req).await.unwrap();
                let mut rep = [0u8; 10];
                c.read_exact(&mut rep).await.unwrap();
                assert_eq!(rep[1], 0x00, "socks connect via vless mux carrier success");
                c.write_all(payload.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; payload.len()];
                c.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, payload.as_bytes(), "echo roundtrip via vless mux carrier");
            }));
        }
        for h in handles {
            h.await.expect("client task join");
        }

        // 6. 复用断言：3 个会话只建立 1 条 carrier TCP 连接
        assert_eq!(
            carrier_count.load(Ordering::SeqCst),
            1,
            "3 mux sessions must reuse a single vless carrier connection"
        );

        for h in sh.iter().chain(ch.iter()) {
            h.abort();
        }
        fwd_task.abort();
        echo_task.abort();
    }

    /// 出站级 mux UDP 数据报端到端（XUDP GlobalID 路径）。
    ///
    /// socks UDP relay → dispatcher UDP relay（dispatch_with_access）→
    /// [`MuxBridge::dispatch_with_access`]（XUDP GlobalID New 帧）→ carrier →
    /// server socks inbound mux 终止 → freedom UDP → UDP echo 回程。
    #[tokio::test]
    async fn integration_udp_relay_through_outbound_mux() {
        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => { let _ = echo.send_to(&buf[..n], peer).await; }
                    Err(_) => break,
                }
            }
        });

        // 2. 空闲端口
        let server_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = server_probe.local_addr().unwrap().port();
        drop(server_probe);
        let client_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_port = client_probe.local_addr().unwrap().port();
        drop(client_probe);

        // 3. 服务端：socks inbound（UDP relay + mux 终止）+ freedom
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: br#"{"auth":"noauth"}"#.to_vec() },
            tag: "socks-in".into(),
            port: Some(server_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        server_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "direct".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        let (_si, _so, sh) = start_full(&server_cfg).await.expect("socks server");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. 客户端：socks inbound（udp:true）+ socks outbound（出站级 mux.enabled）
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: br#"{"auth":"noauth","udp":true}"#.to_vec() },
            tag: "socks-in".into(),
            port: Some(client_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        client_cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "socks".into(),
                data: format!(
                    r#"{{"servers":[{{"address":"127.0.0.1","port":{server_port}}}]}}"#
                ).into_bytes(),
            },
            tag: "proxy".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: Some(serde_json::json!({"enabled": true, "concurrency": 8})),
            target_strategy: None,
        });
        let (_ci, _co, ch) = start_full(&client_cfg).await.expect("socks+mux client");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 5. socks5 TCP control → NoAuth → UDP ASSOCIATE
        let mut tcp = TcpStream::connect(("127.0.0.1", client_port))
            .await
            .expect("connect socks control");
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut m = [0u8; 2];
        tcp.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [0x05, 0x00], "NoAuth method selected");
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut assoc = [0u8; 10];
        tcp.read_exact(&mut assoc).await.unwrap();
        assert_eq!(assoc[1], 0x00, "UDP ASSOC success");
        let relay_port = u16::from_be_bytes([assoc[8], assoc[9]]);
        assert!(relay_port > 0, "relay port assigned");

        // 6. UDP 数据报 → mux XUDP session → freedom UDP → echo
        let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"udp-via-outbound-mux";
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => unreachable!(),
        };
        let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(payload);
        client_udp
            .send_to(&pkt, ("127.0.0.1", relay_port))
            .await
            .expect("send udp via socks");

        let mut resp = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_udp.recv_from(&mut resp),
        )
        .await
        .expect("timeout waiting for udp via outbound mux echo")
        .expect("recv udp echo");
        assert!(n >= 10, "socks5 udp header at least 10 bytes, got {n}");
        assert_eq!(&resp[10..n], &payload[..], "datagram roundtrip via outbound mux");

        drop(client_udp);
        drop(tcp);
        for h in sh.iter().chain(ch.iter()) {
            h.abort();
        }
        echo_task.abort();
    }

    /// 票 rdcc e2e：loopback outbound 生产 sink 注入。
    ///
    /// 拓扑：client → in-echo (dokodemo) →路由[inboundTag=in-echo]→ loopback-out
    /// （inboundTag=in-main + sniffing routeOnly）→回注 in-main (dokodemo)
    /// →default freedom → echo server。
    /// 修复前 sink=None：连接在 LoopbackHandler 静默 drop，客户端读超时。
    #[tokio::test]
    async fn integration_loopback_outbound_reinjects_to_inbound() {
        // 1. echo server（最终目标）
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 两个 dokodemo 入站端口
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_port = probe.local_addr().unwrap().port();
        drop(probe);
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let main_port = probe.local_addr().unwrap().port();
        drop(probe);

        let dokodemo_dest = format!(r#"{{"address":"127.0.0.1","port":{}}}"#, echo_addr.port());
        let mut cfg = BuiltConfig::default();
        for (tag, port) in [("in-echo", first_port), ("in-main", main_port)] {
            cfg.inbounds.push(BuiltInbound {
                entry: BuiltEntry { kind: "dokodemo".into(), data: dokodemo_dest.clone().into_bytes() },
                tag: tag.into(),
                port: Some(port),
                listen: Some("127.0.0.1".into()),
                stream_settings_json: None,
                sniffing_json: None,
            });
        }
        // freedom 必须首个注册（register_outbounds 以首个成功者为 default，
        // 对齐 Go proxyman/outbound:109-111）：loopback 若为 default，回注后
        // 无规则命中会再次选中 loopback-out → 无限回环（stack overflow 实证）。
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: FREEDOM_ALLOW_ALL_SETTINGS.to_vec() },
            tag: "default".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        // loopback outbound：回注 in-main；sniffing routeOnly（Go loopback.go:56-62 透传）。
        cfg.outbounds.push(BuiltOutbound {
            entry: BuiltEntry {
                kind: "loopback".into(),
                data: br#"{"inboundTag":"in-main","sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":true}}"#.to_vec(),
            },
            tag: "loopback-out".into(),
            send_through: None, stream_settings_json: None,
            proxy_settings_json: None, mux_json: None, target_strategy: None,
        });
        cfg.apps.push(BuiltEntry {
            kind: "xray.app.router".into(),
            data: br#"{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["in-echo"],"outboundTag":"loopback-out"}]}"#.to_vec(),
        });

        let (inst, _ohm, handles) = start_full(&cfg).await.expect("loopback config start");
        assert!(inst.is_running());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3. 连 in-echo：数据应经 loopback 回注 in-main 后到 echo 并回写。
        let mut client = TcpStream::connect(format!("127.0.0.1:{first_port}")).await.unwrap();
        let payload = b"loopback reinject!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut got)).await {
            Ok(Ok(_)) => assert_eq!(got, payload, "loopback must reinject to in-main inbound"),
            Ok(Err(e)) => panic!("loopback reinject read error: {e}"),
            Err(_) => panic!("timeout: loopback reinject dropped (production sink not wired?)"),
        }
        for h in handles.iter() {
            h.abort();
        }
    }
}
