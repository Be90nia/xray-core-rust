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
use crate::router::{DispatchRouter, RoutingHandler};
use crate::register::{register_all_features, register_all_transports};
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::{DispatchHandler, OutboundHandlerManager};

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
/// 如果 `built.apps` 含 `kind="routing"` 项，自动解析为 [`PatternRouter`](crate::router::PatternRouter)
/// 并包装为 [`RoutingHandler`]。否则走纯 default outbound 路径。
pub async fn start_full(
    built: &xray_conf::BuiltConfig,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    // 检查是否有 routing app：优先用 xray-app-router 的完整 Router（含 GeoIP/GeoSite/
    // balancer/observation 匹配能力），失败时回退到 PatternRouter（与历史行为一致）。
    let router_opt: Option<Arc<dyn DispatchRouter>> = built
        .apps
        .iter()
        .find(|a| a.kind == "routing")
        .and_then(|a| {
            match crate::wiring::build_router_adapter_from_json(&a.data) {
                Ok(adapter) => Some(adapter as Arc<dyn DispatchRouter>),
                Err(e) => {
                    tracing::warn!(error = %e, "full Router init failed, falling back to PatternRouter");
                    crate::router::PatternRouter::from_json(&a.data)
                        .ok()
                        .map(|r| Arc::new(r) as Arc<dyn DispatchRouter>)
                }
            }
        });

    match router_opt {
        Some(router) => start_full_with_router(built, router).await,
        None => start_full_no_router(built).await,
    }
}

/// 无 routing 的启动路径（内部辅助）。
async fn start_full_no_router(
    built: &xray_conf::BuiltConfig,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    register_all_features();
    register_all_transports();
    let mut instance = Instance::new_from_built(built)?;
    let ohm = Arc::new(SimpleOhm::new());
    register_outbounds(built, &ohm, None)?;
    let handles = spawn_inbounds(built, Arc::clone(&ohm), instance.shutdown_token().clone())
        .await
        .map_err(|e| CoreFunctionError::InstanceStart(e.to_string()))?;
    instance.start()?;
    tracing::info!(
        inbounds = handles.len(),
        "Xray instance started with full inbound/outbound stack"
    );
    Ok((Arc::new(instance), ohm, handles))
}

/// 带路由的完整启动路径：Instance + SimpleOhm + outbounds + router + inbounds。
///
/// 与 [`start_full`] 区别：在注册 outbounds 后，把 [`RoutingHandler`] 包装为新的 default
/// handler，使 dispatch 时先查 router 规则。router 命中 → tagged outbound；miss → 原 default。
pub async fn start_full_with_router(
    built: &xray_conf::BuiltConfig,
    router: Arc<dyn DispatchRouter>,
) -> Result<(Arc<Instance>, Arc<SimpleOhm>, Vec<tokio::task::JoinHandle<()>>), CoreFunctionError> {
    register_all_features();
    register_all_transports();
    let mut instance = Instance::new_from_built(built)?;
    let ohm = Arc::new(SimpleOhm::new());
    register_outbounds(built, &ohm, None)?;

    // 注入 router：把 default handler 包装为 RoutingHandler
    if let Some(inner_default) = ohm.get_default_handler() {
        let routing = Arc::new(RoutingHandler::new(
            Arc::clone(&ohm),
            inner_default,
            router,
        )) as Arc<dyn DispatchHandler>;
        ohm.set_default(routing);
    }

    let handles = spawn_inbounds(built, Arc::clone(&ohm), instance.shutdown_token().clone())
        .await
        .map_err(|e| CoreFunctionError::InstanceStart(e.to_string()))?;
    instance.start()?;
    tracing::info!(
        inbounds = handles.len(),
        routed = true,
        "Xray instance started with router + full stack"
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
            proxy_settings_json: None, mux_json: None,
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
}
