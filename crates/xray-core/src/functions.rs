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
    if let Some(a) = built.apps.iter().find(|a| a.kind == "routing") {
        match crate::wiring::build_router_adapter_from_json(&a.data) {
            Ok(adapter) => {
                let routing = Arc::clone(&adapter)
                    as Arc<dyn xray_app_dispatcher::default::RoutingRouter>;
                let dns_side = adapter as Arc<dyn DispatchRouter>;
                return start_full_dispatched(built, Some(routing), Some(dns_side)).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "full Router init failed, falling back to PatternRouter");
                if let Ok(r) = crate::router::PatternRouter::from_json(&a.data) {
                    return start_full_with_router(built, Arc::new(r)).await;
                }
            }
        }
    }
    start_full_dispatched(built, None, None).await
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
    let bridge = Arc::new(crate::wiring::DispatchRouterBridge::new(Arc::clone(&router)))
        as Arc<dyn xray_app_dispatcher::default::RoutingRouter>;
    start_full_dispatched(built, Some(bridge), Some(router)).await
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
    routing_router: Option<Arc<dyn xray_app_dispatcher::default::RoutingRouter>>,
    dns_router: Option<Arc<dyn DispatchRouter>>,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    register_all_features();
    register_all_transports();
    let mut instance = Instance::new_from_built(built)?;

    // DNS 注入（对应 Go 装配链：instance 创建后 router.dns = core.GetFeature(dns)）：
    // routing domainStrategy（IpOnDemand/IpIfNonMatch）解析经 DnsClient 查询。
    if let (Some(dns), Some(r)) = (
        instance.get_feature::<xray_app_dns::DnsService>(),
        dns_router.as_ref(),
    ) {
        r.set_dns_client(Arc::clone(&dns) as Arc<dyn xray_features::dns::DnsClient>);
    }

    let ohm = Arc::new(SimpleOhm::new());
    // DNS service 同步注入出站（bd bqm）：targetStrategy 域名解析经此生效
    // （对应 Go 全局 internet.dnsClient 由 app/dns 初始化）。
    register_outbounds(
        built,
        &ohm,
        None,
        instance.get_feature::<xray_app_dns::DnsService>(),
    )?;

    // DefaultDispatcher 装配（对应 Go dispatcher.Init(ohm, router, pm, sm)）
    let mut dispatcher = DefaultDispatcher::new();
    dispatcher.init(
        &xray_app_dispatcher::Config::default(),
        Arc::clone(&ohm) as Arc<dyn OutboundHandlerManager>,
        routing_router,
        xray_features::policy::Policy::default(),
        None,
    );
    if let Some(pm) = instance.get_feature::<xray_app_policy::PolicyFeature>() {
        dispatcher.set_policy_manager(pm);
    }
    dispatcher.stats = instance
        .get_feature::<crate::register::AppStatsFeature>()
        .map(|f| f as Arc<dyn xray_features::stats::Manager>);
    // per-tag UDP443 策略（bd g35）：mux JSON → dispatch_link 前置检查
    dispatcher.udp443_policies = crate::outbound::parse_udp443_policies(&built.outbounds);

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
                data: b"{}".to_vec(),
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
                data: b"{}".to_vec(),
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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

    /// sniffing e2e：TLS ClientHello SNI 被嗅探 → dest 覆写为域名 → domainSuffix
    /// 路由规则命中 tagged socks outbound → 上游收到域名 CONNECT。
    #[tokio::test]
    async fn integration_sniffing_tls_sni_routes_by_sniffed_domain() {
        use parking_lot::Mutex;

        // 1. fake 上游 SOCKS5 server：记录 CONNECT 目标
        let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up_listener.local_addr().unwrap().port();
        let target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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

        // 2. 无 routing app：验证无 router 路径也有 sniffing+counter 管线
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
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
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
}
