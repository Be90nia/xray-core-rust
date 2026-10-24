#![allow(clippy::print_stderr)] // 启停报告走 stderr 直写：产品接口（对齐 run.rs 文件级豁免理由）
//! B5：`xray-frame` `Framework` 组合根启动路径 + handler 桥（feature `framework-assembly`）。
//!
//! 装配链：`register → build(ctx) → bring_up → 等信号 → shutdown → 停机报告`；
//! handler 桥：`OutboundProvider`（插件产出 handler 的声明面）→
//! [`HandlerBridge`]（tag → `Arc<dyn DispatchHandler>` 查表，dispatcher 消费面
//! 的最小就位形态——真 dispatch_link 接线与 inbound/outbound 装配门留后）。
//! 段路由：装配根 `with_config(config_root)`（`Config::to_json_value()` 同源投影，
//! 禁从原文件二次解析），插件 build 期经 `ctx.section()` 取自己那段。
//!
//! 插件集当前仅含装配探针（[`AssemblyProbe`]），16 族协议插件逐族实现
//! [`OutboundProvider`] 即入桥；配置前置与生产路径共享（run.rs `execute` 在
//! `built` 之后才分叉），此处不复制任何配置解析。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use xray_app_dispatcher::{DispatchHandler, PinFuture};
use xray_frame::{
    Framework, FrameworkOptions,
    context::PluginContext,
    error::PluginError,
    plugin::{Lifecycle, Plugin, PluginContract},
};

use crate::error::{CliError, Result};

/// 装配探针：零资源、零后台任务、零缓冲——证明框架装配链贯通的最小插件。
///
/// 契约声明留空：探针不涉协议语义与资源面，无条款适用；协议插件接线时逐条
/// 声明十二坑条款（`ClauseId`）并过 L4 契约测试，不在此预演。
#[derive(Debug, Default)]
struct AssemblyProbe {
    /// build 期看到的自己那段配置（缺段 = None——探针容忍缺段，fail-fast 归
    /// 真插件 `ctx.section()?`；段路由测试经此读回断言）。
    section_seen: Arc<Mutex<Option<serde_json::Value>>>,
}

const PROBE_CONTRACT: PluginContract =
    PluginContract { clauses: &[], extra: &[], not_applicable: &[] };

impl AssemblyProbe {
    fn section_seen(&self) -> Arc<Mutex<Option<serde_json::Value>>> {
        Arc::clone(&self.section_seen)
    }
}

impl Plugin for AssemblyProbe {
    fn name(&self) -> &'static str {
        "assembly-probe"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn contract(&self) -> &PluginContract {
        &PROBE_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &AssemblyProbeLifecycle
    }

    fn build(&self, ctx: &mut PluginContext) -> std::result::Result<(), PluginError> {
        if let Ok(section) = ctx.section() {
            *self.section_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(section.clone());
        }
        Ok(())
    }
}

struct AssemblyProbeLifecycle;

impl Lifecycle for AssemblyProbeLifecycle {
    fn init(&self, _ctx: &PluginContext) -> std::result::Result<(), PluginError> {
        crate::LOG.info("assembly-probe init");
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> std::result::Result<(), PluginError> {
        crate::LOG.info("assembly-probe start");
        Ok(())
    }

    fn stop(&self) -> std::result::Result<(), PluginError> {
        crate::LOG.info("assembly-probe stop");
        Ok(())
    }
}

/// 插件产出出站 handler 的声明面：实现本 trait 的插件，其 handler 经
/// [`HandlerBridge::collect`] 以 `plugin.name()` 为 tag 入桥表，dispatcher 侧
/// 即可按 tag 查询调用。协议插件逐族实现即完成入桥（16 族接线留后）。
trait OutboundProvider: Plugin {
    fn outbound_handler(&self) -> Arc<dyn DispatchHandler>;
}

/// 探针出站 handler：dispatcher 可调用形态的最小实现——dispatch 即关闭 link
/// （协议语义归协议插件族；本面只证明 tag 查询与调用路径贯通）。
#[derive(Debug)]
struct ProbeOutbound {
    tag: &'static str,
}

impl DispatchHandler for ProbeOutbound {
    fn tag(&self) -> &str {
        self.tag
    }

    fn dispatch(
        &self,
        _dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> PinFuture<()> {
        Box::pin(async move {
            drop(link);
            Ok(())
        })
    }
}

impl OutboundProvider for AssemblyProbe {
    fn outbound_handler(&self) -> Arc<dyn DispatchHandler> {
        Arc::new(ProbeOutbound { tag: self.name() })
    }
}

/// handler 桥：tag → `Arc<dyn DispatchHandler>` 查表（构造后只读，克隆廉价）。
/// dispatcher 消费面的最小就位形态——`get(tag)` 即未来 `SimpleOhm` 查表替换点。
#[derive(Debug, Default)]
struct HandlerBridge {
    handlers: HashMap<&'static str, Arc<dyn DispatchHandler>>,
}

impl HandlerBridge {
    /// 从插件集构造：每个 provider 的 handler 以其插件名入表（同名后到覆盖
    /// 先到——装配根注册链 v0.1 每插件一个 handler，重复名属装配 bug，由
    /// `PluginRegistry` 的重名拒绝先行拦截）。
    fn collect(providers: &[Arc<dyn OutboundProvider>]) -> Self {
        let mut handlers = HashMap::with_capacity(providers.len());
        for provider in providers {
            handlers.insert(provider.name(), provider.outbound_handler());
        }
        Self { handlers }
    }

    /// 按 tag 查询 handler（dispatcher 调用面）。
    fn get(&self, tag: &str) -> Option<&Arc<dyn DispatchHandler>> {
        self.handlers.get(tag)
    }

    fn len(&self) -> usize {
        self.handlers.len()
    }
}

/// 注册插件集 → build。fail-visible：装配期任一步失败原样上抛为 CLI 错误。
///
/// `config_root`：`Config::to_json_value()` 同源投影（run.rs 分叉点已持有唯一
/// 解析产物），经 `with_config` 注入 per-plugin `ctx.section()` 段路由底座。
fn assemble(
    config_root: serde_json::Value,
    providers: &[Arc<dyn OutboundProvider>],
) -> Result<Framework> {
    // registry_cap=16：探针 1 个 + 预留 16 族协议插件位；id_fingerprint/shutdown_timeout
    // 走框架默认（派生 fingerprint + 5s 停机超时，P0-8 拍板）。
    let options =
        FrameworkOptions { registry_cap: 16, id_fingerprint: None, shutdown_timeout: None };
    Framework::builder(options)
        .and_then(|builder| {
            let mut builder = builder.with_config(config_root);
            for provider in providers {
                // trait upcast：dyn OutboundProvider → dyn Plugin（supertrait）。
                let plugin: Arc<dyn Plugin> = Arc::clone(provider);
                builder = builder.register(plugin)?;
            }
            builder.build()
        })
        .map_err(|e| CliError::StartFailed(format!("framework assemble failed: {e}")))
}

/// 框架路径主流程：装配（含段路由注入）→ bring_up → 桥就位 → 等信号 → 停机报告。
///
/// `config_root`：`Config::to_json_value()` 投影（与生产同一份解析产物，禁从
/// 原文件二次解析）；`_built`：listener/dispatcher 接线后按段消费（P3 后续）。
pub(crate) async fn run_framework(
    _built: &xray_conf::BuiltConfig,
    config_root: serde_json::Value,
) -> Result<()> {
    // 插件注册链（本步 = 探针；16 族协议插件逐族追加）。同一份实例双面共享：
    // 注册进 Framework（生命周期）+ collect 进桥（dispatcher 查询面）。
    let providers: Vec<Arc<dyn OutboundProvider>> = vec![Arc::new(AssemblyProbe::default())];
    let bridge = HandlerBridge::collect(&providers);

    let mut framework = assemble(config_root, &providers)?;
    framework
        .bring_up()
        .map_err(|e| CliError::StartFailed(format!("framework bring_up failed: {e}")))?;
    // 启动可见：Debug 手写面含运行态与插件数（assembly.rs）。
    eprintln!("[framework] bring_up ok: {framework:?}");
    eprintln!("[framework] handler bridge ready: {} outbound handler(s)", bridge.len());

    crate::run::wait_for_signal().await;

    let report = framework.shutdown().await;
    for outcome in &report.per_component {
        eprintln!("[framework] stopped: {} {:?}", outcome.name, outcome.kind);
    }
    if report.is_clean() {
        eprintln!("[framework] shutdown clean ({} component(s))", report.per_component.len());
        Ok(())
    } else {
        Err(CliError::StartFailed(format!("framework shutdown unclean: {report:?}")))
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use super::*;

    fn probe_providers() -> Vec<Arc<dyn OutboundProvider>> {
        vec![Arc::new(AssemblyProbe::default())]
    }

    #[test]
    fn framework_bring_up_then_shutdown_reports_clean() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework =
                assemble(serde_json::json!({}), &probe_providers()).expect("assemble");
            framework.bring_up().expect("bring_up");
            assert!(framework.is_running(), "bring_up succeeded but is_running=false");

            let report = framework.shutdown().await;
            assert!(report.is_clean(), "shutdown unclean: {report:?}");
            assert_eq!(report.per_component.len(), 1, "expected only the probe plugin");
            assert_eq!(report.per_component[0].name, "assembly-probe");
        });
    }

    #[test]
    fn probe_plugin_surfaces_name_version_contract() {
        let probe: Arc<dyn Plugin> = Arc::new(AssemblyProbe::default());
        assert_eq!(probe.name(), "assembly-probe");
        assert_eq!(probe.version(), "0.1.0");
        assert!(probe.contract().clauses.is_empty());
    }

    /// 段路由验收①：插件 build 期经 `ctx.section()` 拿到自己那段，字段值可断言
    /// 来自配置投影（`Config::to_json_value()`——唯一解析产物的 JSON 视图，
    /// 全程无文件二次解析）。走 xray-frame P3-2 权威管线
    /// `build_plugins_from_config`（ctx 构造配方与装配根同款）。
    #[test]
    fn plugin_reads_own_section_from_config_projection() {
        let config = xray_conf::Config::from_json_str(
            r#"{"outbounds": [{"protocol": "assembly-probe", "settings": {"marker": "from-projection"}}]}"#,
        )
        .unwrap();
        let root = config.to_json_value().unwrap();

        let probe = Arc::new(AssemblyProbe::default());
        let seen = probe.section_seen();
        let plugins: Vec<Arc<dyn Plugin>> =
            probe_providers().iter().map(|p| Arc::clone(p) as Arc<dyn Plugin>).collect();

        let built =
            xray_frame::config::build_plugins_from_config(&root, &plugins).expect("config build");
        assert_eq!(built, vec!["assembly-probe"]);

        let seen = seen.lock().unwrap();
        let section = seen.as_ref().expect("probe build should record its section");
        assert_eq!(section["settings"]["marker"], "from-projection");
        assert_eq!(section["protocol"], "assembly-probe");
    }

    /// 段路由缺段面：配置无探针条目 → 探针容忍缺段（section_seen=None）、
    /// build 链不报错（fail-fast 归真插件 `ctx.section()?`，P3-2 语义）。
    #[test]
    fn probe_tolerates_missing_section() {
        let config = xray_conf::Config::from_json_str(r#"{"outbounds": []}"#).unwrap();
        let root = config.to_json_value().unwrap();
        let probe = Arc::new(AssemblyProbe::default());
        let seen = probe.section_seen();
        let plugins: Vec<Arc<dyn Plugin>> = vec![probe];

        let built =
            xray_frame::config::build_plugins_from_config(&root, &plugins).expect("config build");
        assert!(built.is_empty(), "no configured entry → no plugin built");
        assert!(seen.lock().unwrap().is_none(), "no section must be recorded");
    }

    /// handler 桥验收②：构造（collect）→ 查询（get/tag）→ 调用一次最小路径
    /// （dispatch 即关 link，协议语义归协议插件族）。
    #[test]
    fn handler_bridge_collect_query_and_dispatch_minimal() {
        let bridge = HandlerBridge::collect(&probe_providers());
        assert_eq!(bridge.len(), 1);
        assert!(bridge.get("nonexistent").is_none(), "unknown tag → None");

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let handler = bridge.get("assembly-probe").expect("probe handler");
            assert_eq!(handler.tag(), "assembly-probe");

            let dest =
                xray_common::net::destination::Destination::tcp("127.0.0.1".parse().unwrap(), 8080);
            let link = xray_transport::link::Link::new(Box::new(NullReader), Box::new(NullWriter));
            handler.dispatch(&dest, link).await.expect("minimal dispatch");
        });
    }

    // ── Link mock：dispatch 签名要求的 reader/writer 占位（探针不读写）──

    struct NullReader;

    impl xray_buf::io::Reader for NullReader {
        fn read_multi_buffer(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = std::result::Result<xray_buf::multi::MultiBuffer, xray_buf::Error>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(std::future::ready(Err(xray_buf::Error::ReadError("null reader".into()))))
        }
    }

    struct NullWriter;

    impl xray_buf::io::Writer for NullWriter {
        fn write_multi_buffer(
            &mut self,
            _mb: xray_buf::multi::MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = std::result::Result<(), xray_buf::Error>> + Send + '_>>
        {
            Box::pin(std::future::ready(Err(xray_buf::Error::WriteError("null writer".into()))))
        }
    }
}
