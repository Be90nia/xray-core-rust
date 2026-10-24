#![allow(clippy::print_stderr)] // 启停报告走 stderr 直写：产品接口（对齐 run.rs 文件级豁免理由）
//! B5：`xray-frame` `Framework` 组合根启动路径 + 配置驱动协议插件桥（feature
//! `framework-assembly`）。
//!
//! 装配链：`derive → register → build(ctx) → bring_up → 桥填表 → 等信号 →
//! shutdown → 停机报告`。
//!
//! - **配置派生注册**（禁硬编码协议清单）：从 `BuiltConfig` 的 `outbounds[]/inbounds[]` 轮出
//!   `protocol` 名，经族目录（[`family_catalog`]， 只提供构造器）注册进 xray-frame
//!   `PluginRegistry`；目录未覆盖的族 （shadowsocks 等未迁移族）记账不注册、不静默。
//! - **handler 桥**：从已 build 的插件族把每个配置条目转成 dispatcher 可调 handler（出站 =
//!   插件产出的 `DispatchHandler`/`DialBridge` 包装；入站 = `InboundDispatchHandler`，生产同款 tag
//!   面），填 [`HandlerBridge`] 查表。 转换失败逐条计数 + 日志（成功几个算几个），重复 tag
//!   拒绝（不覆盖）。
//! - **段路由**：装配根 `with_config(config_root)`（`Config::to_json_value()`
//!   同源投影，禁从原文件二次解析），插件 build 期经 `ctx.section()` 取自己 那段（缺段
//!   fail-fast，L5）。
//!
//! 探针（[`AssemblyProbe`]）恒注册：装配链贯通的金丝雀。v0.1 已知限制：同
//! protocol 多实例条目只转换首个（xray-frame v0.1 每 protocol 只 build 首段，
//! 余者记账失败）；listener/accept 面与 dispatcher 真接线（ohm 注入）留后续批。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use xray_app_dispatcher::{
    DispatchHandler,
    default::{DefaultDispatcher, DialBridge, DialFn},
};
use xray_conf::{BuiltConfig, BuiltOutbound};
use xray_core::wiring::{InboundDispatchHandler, sniffing_request_from_json};
use xray_frame::{
    Framework, FrameworkOptions,
    context::PluginContext,
    error::PluginError,
    plugin::{Lifecycle, Plugin, PluginContract},
};
use xray_proxy_anytls::AnytlsPlugin;
use xray_proxy_blackhole::BlackholePlugin;
use xray_proxy_dns::DnsPlugin;
use xray_proxy_dokodemo::DokodemoPlugin;
use xray_proxy_freedom::{
    FinalRule, FreedomDispatchBridge, FreedomPlugin, make_freedom_dial_fn_with_config,
};
use xray_proxy_http::HttpPlugin;
use xray_proxy_hysteria::HysteriaPlugin;
use xray_proxy_loopback::LoopbackPlugin;
use xray_proxy_socks::SocksPlugin;
use xray_proxy_trojan::TrojanPlugin;
use xray_proxy_tuic::TuicPlugin;
use xray_proxy_tun::TunPlugin;
use xray_proxy_vless::VlessPlugin;
use xray_proxy_vmess::VmessPlugin;
use xray_proxy_wireguard::WireguardPlugin;

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
    #[cfg(test)] // 测试观察锚（断言段路由投影值）；生产 build 不编译
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

/// 出站桥转换缝：插件族已 build → 配置出站条目 → dispatcher 可调 handler。
/// `Err` = 该条目入不了桥（[`fill_bridge`] 记账 + 日志，不静默）。
type OutboundConvert = Arc<
    dyn Fn(&BuiltOutbound) -> std::result::Result<Arc<dyn DispatchHandler>, String> + Send + Sync,
>;

/// 一个协议族的注册形态：插件实例（注册进 Framework，build 期状态被出站转换
/// 消费——同一 Arc）+ 可选的出站桥转换缝（无 = 该族暂无 dispatcher 可调出站
/// handler，如仅入站面的插件）。
struct RegisteredFamily {
    protocol: &'static str,
    plugin: Arc<dyn Plugin>,
    outbound: Option<OutboundConvert>,
}

/// 入站面族：插件产出 inbound server（listener 面消费，下一批）；桥面 =
/// [`InboundDispatchHandler`]（tag 派生，不依赖插件状态，[`fill_bridge`] 直造）。
fn inbound_only<P: Plugin + Default + 'static>(protocol: &'static str) -> RegisteredFamily {
    RegisteredFamily { protocol, plugin: Arc::new(P::default()), outbound: None }
}

/// `dial_fn` 形态出站族（vmess/vless）：插件暴露 `DialFn`（既有拨号语义全量），
/// 经 dispatcher 自家的 [`DialBridge`] 适配成 `DispatchHandler`。
fn dial_fn_family<P, F>(protocol: &'static str, dial: F) -> RegisteredFamily
where
    P: Plugin + Default + 'static,
    F: Fn(&P) -> std::result::Result<DialFn, PluginError> + Send + Sync + 'static,
{
    let plugin = Arc::new(P::default());
    let p = Arc::clone(&plugin);
    RegisteredFamily {
        protocol,
        outbound: Some(Arc::new(move |ob| {
            let dial_fn = dial(&p).map_err(|e| e.to_string())?;
            Ok(Arc::new(DialBridge::new(ob.tag.clone(), dial_fn)) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// freedom 出站族：`make_dial_fn_with_config`（拨号路径语义：fragment/
/// destinationOverride/proxyProtocol/domainStrategy/sockopt/bd 7p1m RCVBUF）+
/// [`FreedomDispatchBridge`]（dispatch 路径语义：finalRules Block 检查、noises、
/// UDP relay 策略）+ 生产同款 splice 标记（Go freedom.go:260）。
fn freedom_family() -> RegisteredFamily {
    let plugin = Arc::new(FreedomPlugin::default());
    let p = Arc::clone(&plugin);
    RegisteredFamily {
        protocol: "freedom",
        outbound: Some(Arc::new(move |ob| {
            let cfg = p.built_config().map_err(|e| e.to_string())?.clone();
            let dial_bridge = Arc::new(DialBridge::new(
                ob.tag.clone(),
                make_freedom_dial_fn_with_config(cfg.clone()),
            ));
            dial_bridge.set_splice_outbound(true);
            let final_rules = cfg
                .final_rules
                .iter()
                .map(FinalRule::build)
                .collect::<xray_proxy_freedom::Result<Vec<_>>>()
                .map_err(|e| format!("freedom finalRule: {e}"))?;
            let handler = FreedomDispatchBridge::from_bridge(dial_bridge)
                .with_noises(cfg.noises.clone())
                .with_destination_override(cfg.destination_override.clone())
                .with_domain_strategy(cfg.domain_strategy)
                .with_final_rules(final_rules);
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// blackhole 出站族：插件自家 `dispatch_handler`（[`xray_proxy_blackhole`]
/// `BlackholeHandler` 已是 `DispatchHandler`）。
fn blackhole_family() -> RegisteredFamily {
    let plugin = Arc::new(BlackholePlugin::default());
    let p = Arc::clone(&plugin);
    RegisteredFamily {
        protocol: "blackhole",
        outbound: Some(Arc::new(move |ob| {
            let handler = p.dispatch_handler(&ob.tag).map_err(|e| e.to_string())?;
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// loopback 出站族：插件自家 `handler`（`LoopbackHandler` 已是 `DispatchHandler`，
/// 回环目标 = build 期段里的 `inboundTag`）。
fn loopback_family() -> RegisteredFamily {
    let plugin = Arc::new(LoopbackPlugin::default());
    let p = Arc::clone(&plugin);
    RegisteredFamily {
        protocol: "loopback",
        outbound: Some(Arc::new(move |ob| {
            let handler = p.handler(&ob.tag).map_err(|e| e.to_string())?;
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// 协议目录：配置 `protocol` 串 → 插件族构造。目录只提供**构造器**，注册集 =
/// 配置引用集（禁硬编码清单）；目录未覆盖 = 未迁移（shadowsocks）/未知族 →
/// [`derive_families`] 记账不注册。族名与 xray-conf `BuiltEntry.kind` /
/// `Config::to_json_value()` 的 `protocol` 字段逐字对齐（插件 `name()` 同源）。
fn family_catalog(protocol: &str) -> Option<RegisteredFamily> {
    let family = match protocol {
        "socks" => inbound_only::<SocksPlugin>("socks"),
        "http" => inbound_only::<HttpPlugin>("http"),
        "dokodemo-door" => inbound_only::<DokodemoPlugin>("dokodemo-door"),
        "trojan" => inbound_only::<TrojanPlugin>("trojan"),
        "tuic" => inbound_only::<TuicPlugin>("tuic"),
        "anytls" => inbound_only::<AnytlsPlugin>("anytls"),
        "hysteria" => inbound_only::<HysteriaPlugin>("hysteria"),
        "wireguard" => inbound_only::<WireguardPlugin>("wireguard"),
        "tun" => inbound_only::<TunPlugin>("tun"),
        "dns" => inbound_only::<DnsPlugin>("dns"),
        "freedom" => freedom_family(),
        "vmess" => dial_fn_family::<VmessPlugin, _>("vmess", |p| p.dial_fn()),
        "vless" => dial_fn_family::<VlessPlugin, _>("vless", |p| p.dial_fn()),
        "blackhole" => blackhole_family(),
        "loopback" => loopback_family(),
        _ => return None,
    };
    Some(family)
}

/// 配置派生的注册计划。
struct FamilyPlan {
    families: Vec<RegisteredFamily>,
    /// 目录未覆盖、未注册的 protocol（去重、首现序）——调用方记账上抛。
    unregistered: Vec<String>,
}

/// 从 `BuiltConfig` 的 inbound/outbound 段轮出协议族（首现去重）：注册集 =
/// 配置引用集，禁硬编码清单。
fn derive_families(built: &BuiltConfig) -> FamilyPlan {
    let mut plan = FamilyPlan { families: Vec::new(), unregistered: Vec::new() };
    let push_family = |kind: &str, plan: &mut FamilyPlan| {
        if plan.families.iter().any(|f| f.protocol == kind)
            || plan.unregistered.iter().any(|u| u == kind)
        {
            return;
        }
        match family_catalog(kind) {
            Some(family) => plan.families.push(family),
            None => plan.unregistered.push(kind.to_string()),
        }
    };
    for ob in &built.outbounds {
        push_family(&ob.entry.kind, &mut plan);
    }
    for ib in &built.inbounds {
        push_family(&ib.entry.kind, &mut plan);
    }
    plan
}

/// handler 桥：tag → `Arc<dyn DispatchHandler>` 查表（构造后只读，克隆廉价）。
/// dispatcher 消费面的就位形态——`get(tag)` 即未来 `SimpleOhm` 查表替换点。
#[derive(Debug, Default)]
struct HandlerBridge {
    handlers: HashMap<String, Arc<dyn DispatchHandler>>,
}

impl HandlerBridge {
    fn insert(&mut self, tag: String, handler: Arc<dyn DispatchHandler>) {
        self.handlers.insert(tag, handler);
    }

    /// 按 tag 查询 handler（dispatcher 消费缝：P3 真接线 `SimpleOhm` 替换点，
    /// 集成面 API——当前 e2e/未来 dispatcher 两侧共用）。
    pub fn get(&self, tag: &str) -> Option<&Arc<dyn DispatchHandler>> {
        self.handlers.get(tag)
    }

    fn contains_key(&self, tag: &str) -> bool {
        self.handlers.contains_key(tag)
    }
}

/// 桥填表结果：成功 handler 计数 + 逐条失败（tag, 原因）——调用方记账上抛。
struct BridgeFill {
    bridge: HandlerBridge,
    ok: usize,
    failed: Vec<(String, String)>,
    /// 出站 handler（配置序，仅成功转换）——listener 面经
    /// `start_full_with_outbound_handlers` 灌入 ohm（首个 = default，S4 影子表镜像）。
    outbound_handlers: Vec<Arc<dyn DispatchHandler>>,
}

/// 出站条目的生产装配前置（framework 桥 v0 未接的面在场 → 拒，不静默丢语义）：
/// proxySettings 代理链 / mux 包装 / sendThrough / streamSettings 传输层。
fn guard_outbound_entry(ob: &BuiltOutbound) -> std::result::Result<(), String> {
    if ob.proxy_settings_json.is_some() {
        return Err("proxy chain (proxySettings) not wired in framework bridge".into());
    }
    if ob.mux_json.is_some() {
        return Err("mux wrapping not wired in framework bridge".into());
    }
    if ob.send_through.is_some() {
        return Err("sendThrough not wired in framework bridge".into());
    }
    if ob.stream_settings_json.is_some() {
        return Err("transport streamSettings not wired in framework bridge".into());
    }
    Ok(())
}

/// 把配置条目转成 dispatcher 可调 handler 填表：出站 = 族转换缝（缺缝/失败/
/// 重复 tag 逐条记账）；入站 = [`InboundDispatchHandler`]（生产同款 tag 面，
/// sniffing 解析复用 xray-core 权威实现）。
fn fill_bridge(
    built: &BuiltConfig,
    families: &[RegisteredFamily],
    dispatcher: &Arc<DefaultDispatcher>,
) -> BridgeFill {
    let mut fill = BridgeFill {
        bridge: HandlerBridge::default(),
        ok: 0,
        failed: Vec::new(),
        outbound_handlers: Vec::new(),
    };
    // v0.1：同 protocol 多实例只转换首个（xray-frame 每 protocol 只 build 首段）；
    // 仅成功转换才占位，失败后同 protocol 后继条目仍可重试。
    let mut converted_protocols: Vec<&'static str> = Vec::new();
    let record_failure = |fill: &mut BridgeFill, tag: &str, reason: String| {
        fill.failed.push((tag.to_string(), reason));
    };

    for ob in &built.outbounds {
        if fill.bridge.contains_key(&ob.tag) {
            record_failure(&mut fill, &ob.tag, "duplicate tag".into());
            continue;
        }
        let Some(family) = families.iter().find(|f| f.protocol == ob.entry.kind) else {
            record_failure(
                &mut fill,
                &ob.tag,
                format!(
                    "protocol {:?} not registered (family unmigrated or unknown)",
                    ob.entry.kind
                ),
            );
            continue;
        };
        let Some(convert) = &family.outbound else {
            record_failure(
                &mut fill,
                &ob.tag,
                format!(
                    "protocol {:?} exposes inbound-face plugin only; no framework outbound conversion",
                    ob.entry.kind
                ),
            );
            continue;
        };
        if let Err(reason) = guard_outbound_entry(ob) {
            record_failure(&mut fill, &ob.tag, reason);
            continue;
        }
        if converted_protocols.contains(&family.protocol) {
            record_failure(
                &mut fill,
                &ob.tag,
                "duplicate protocol entry: xray-frame v0.1 builds the first section only".into(),
            );
            continue;
        }
        match convert(ob) {
            Ok(handler) => {
                fill.bridge.insert(ob.tag.clone(), Arc::clone(&handler));
                fill.outbound_handlers.push(handler);
                converted_protocols.push(family.protocol);
                fill.ok += 1;
            },
            Err(reason) => record_failure(&mut fill, &ob.tag, reason),
        }
    }

    for ib in &built.inbounds {
        if fill.bridge.contains_key(&ib.tag) {
            record_failure(&mut fill, &ib.tag, "duplicate tag".into());
            continue;
        }
        let sniffing = sniffing_request_from_json(ib.sniffing_json.as_ref());
        let handler = InboundDispatchHandler::new(Arc::clone(dispatcher), sniffing, &ib.tag);
        fill.bridge.insert(ib.tag.clone(), Arc::new(handler));
        fill.ok += 1;
    }
    fill
}

/// 注册插件集（探针 + 配置派生族）→ build。fail-visible：装配期任一步失败原
/// 样上抛为 CLI 错误。
///
/// `config_root`：`Config::to_json_value()` 同源投影（run.rs 分叉点已持有唯一
/// 解析产物），经 `with_config` 注入 per-plugin `ctx.section()` 段路由底座。
fn assemble(config_root: serde_json::Value, families: &[RegisteredFamily]) -> Result<Framework> {
    let options = FrameworkOptions {
        registry_cap: 1 + families.len(), // 探针金丝雀 + 配置派生族
        id_fingerprint: None,             // 框架派生 fingerprint
        shutdown_timeout: None,           // 框架默认 5s（P0-8 拍板）
    };
    Framework::builder(options)
        .and_then(|builder| {
            let mut builder =
                builder.with_config(config_root).register(Arc::new(AssemblyProbe::default()))?;
            for family in families {
                builder = builder.register(Arc::clone(&family.plugin))?;
            }
            builder.build()
        })
        .map_err(|e| CliError::StartFailed(format!("framework assemble failed: {e}")))
}

/// 框架路径主流程：配置派生注册 → 装配 build → bring_up → 桥填表 → 等信号 →
/// 停机报告。
///
/// `built`：配置唯一解析产物（族派生源 + 桥条目源）；`config_root`：
/// `Config::to_json_value()` 投影（段路由底座，禁从原文件二次解析）。
pub(crate) async fn run_framework(
    built: &xray_conf::BuiltConfig,
    config_root: serde_json::Value,
) -> Result<()> {
    run_framework_until(built, config_root, crate::run::wait_for_signal()).await
}

/// 同 [`run_framework`]，停机信号源参数化（生产 = [`crate::run::wait_for_signal`]；
/// 集成测试注入确定性触发器——agent 环境控制台 CTRL_C 投递不可靠，实测
/// default 二进制同样不退，e2e 优雅停机验收经此确定性证明）。
pub(crate) async fn run_framework_until(
    built: &xray_conf::BuiltConfig,
    config_root: serde_json::Value,
    shutdown_signal: impl Future<Output = ()>,
) -> Result<()> {
    // ① 配置派生（禁硬编码清单）：未迁移族记账不静默。
    let plan = derive_families(built);
    for name in &plan.unregistered {
        crate::LOG.warn(format!(
            "framework: protocol {name:?} has no plugin family (unmigrated); its entries will not reach the bridge"
        ));
    }
    crate::LOG.info(format!(
        "framework: derived plugin families from config: {:?}",
        plan.families.iter().map(|f| f.protocol).collect::<Vec<_>>()
    ));

    // ② 装配 + build + bring_up（插件 build 期经 ctx.section() 取段，缺段 fail-fast）。
    let mut framework = assemble(config_root, &plan.families)?;
    framework
        .bring_up()
        .map_err(|e| CliError::StartFailed(format!("framework bring_up failed: {e}")))?;
    // 启动可见：Debug 手写面含运行态与插件数（assembly.rs）。
    eprintln!("[framework] bring_up ok: {framework:?}");

    // ③ 桥：插件 → dispatcher 可调 handler 填表（失败逐条计数 + 日志）。
    let dispatcher = Arc::new(DefaultDispatcher::new());
    let BridgeFill { bridge, ok, failed, outbound_handlers } =
        fill_bridge(built, &plan.families, &dispatcher);
    for (tag, reason) in &failed {
        crate::LOG.warn(format!("framework: bridge conversion failed tag={tag:?}: {reason}"));
    }
    eprintln!("[framework] handler bridge ready: {} handler(s), {} failed", ok, failed.len());
    // 启动可见：桥内容逐条（tag ↔ handler tag），操作者核对路由表。
    for tag in built.outbounds.iter().map(|o| &o.tag).chain(built.inbounds.iter().map(|i| &i.tag)) {
        if let Some(handler) = bridge.get(tag) {
            crate::LOG.info(format!("framework: bridge {tag:?} → handler {}", handler.tag()));
        }
    }

    // ④ listener/accept 面：xray-core 生产装配序列**完整复用**（Instance/routing/
    // sniffing/stats/access-log 与 start_full 同一条路，per-inbound
    // InboundDispatchHandler+MuxCarrier 由 spawn_inbounds 既有机制承担），唯一差异 =
    // 出站 handler 由本桥灌入（feature 门控注入点，禁第二套 dispatcher）。
    let (instance, _ohm, handles) =
        xray_core::functions::start_full_with_outbound_handlers(built, outbound_handlers)
            .await
            .map_err(|e| CliError::StartFailed(format!("framework inbound start failed: {e}")))?;
    crate::LOG.info(format!("framework: {} inbound listener(s) serving", handles.len()));

    shutdown_signal.await;

    // 停机顺序：listener 先停（close = cancel shutdown_token → serve 任务收 cancel
    // 通知，与 default 路径同语义），排空后插件停机报告。
    crate::run::close_if_sole_owner(instance)?;
    for h in handles {
        let _ = h.await;
    }

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

    use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};

    use super::*;

    /// 配置 JSON → (BuiltConfig, 投影, 派生计划)——e2e 测试共用前置。
    fn plan_from_json(json: &str) -> (xray_conf::BuiltConfig, serde_json::Value, FamilyPlan) {
        let config = xray_conf::Config::from_json_str(json).unwrap();
        let built = config.build().unwrap();
        let root = config.to_json_value().unwrap();
        let plan = derive_families(&built);
        (built, root, plan)
    }

    fn outbound_entry(kind: &str, tag: &str, data: &[u8]) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry { kind: kind.to_string(), data: data.to_vec() },
            tag: tag.to_string(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    #[test]
    fn framework_bring_up_then_shutdown_reports_clean() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework = assemble(serde_json::json!({}), &[]).expect("assemble");
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
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::clone(&probe) as Arc<dyn Plugin>];

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

    /// B5 第三步最小 e2e：socks inbound + freedom outbound 配置 → 配置派生注册
    /// → 装配 build/bring_up → 桥里两个 tag 都查得到 handler（freedom = 真协议
    /// 转换缝；socks = 生产同款 InboundDispatchHandler tag 面）。
    #[test]
    fn e2e_socks_inbound_freedom_outbound_both_tags_in_bridge() {
        let (built, root, plan) = plan_from_json(
            r#"{
            "inbounds": [{"protocol": "socks", "tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "settings": {}}],
            "outbounds": [{"protocol": "freedom", "tag": "freedom-out", "settings": {}}]
        }"#,
        );
        // ① 配置派生：两族都从配置轮出并注册（配置没有的族不注册）。
        assert_eq!(plan.families.len(), 2, "socks + freedom derived from config");
        assert!(plan.unregistered.is_empty(), "unregistered: {:?}", plan.unregistered);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // ② 装配链：register → build（真插件 ctx.section() 解析 settings）→ bring_up。
            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");
            assert!(framework.is_running());

            // ③ 桥填表：两个 tag 都查得到 handler。
            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected conversion failures: {:?}", fill.failed);
            assert_eq!(fill.ok, 2);
            assert_eq!(fill.bridge.get("socks-in").expect("socks tag").tag(), "socks-in");
            assert_eq!(fill.bridge.get("freedom-out").expect("freedom tag").tag(), "freedom-out");
            // listener 面灌入序：出站 handler 配置序、tag 相符（首个 = default）。
            assert_eq!(fill.outbound_handlers.len(), 1);
            assert_eq!(fill.outbound_handlers[0].tag(), "freedom-out");

            let report = framework.shutdown().await;
            assert!(report.is_clean(), "shutdown unclean: {report:?}");
        });
    }

    /// 失败记账：未迁移族（shadowsocks）出站条目 → 桥转换逐条计数失败（不静默
    /// 覆盖、不伪造成功）；入站面照常（InboundDispatchHandler tag 面不依赖族）。
    #[test]
    fn bridge_fill_counts_failures_for_unmigrated_family() {
        let mut built = xray_conf::BuiltConfig::default();
        built.outbounds.push(outbound_entry("shadowsocks", "ss-out", b"{}"));
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "socks".to_string(), data: b"{}".to_vec() },
            tag: "socks-in".to_string(),
            port: Some(10808),
            listen: Some("127.0.0.1".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        });

        let plan = derive_families(&built);
        assert_eq!(plan.families.len(), 1, "only socks has a plugin family");
        assert_eq!(plan.unregistered, vec!["shadowsocks".to_string()]);

        let dispatcher = Arc::new(DefaultDispatcher::new());
        let fill = fill_bridge(&built, &plan.families, &dispatcher);
        assert_eq!(fill.ok, 1, "only the socks inbound converts");
        assert_eq!(fill.failed.len(), 1);
        assert_eq!(fill.failed[0].0, "ss-out");
        assert!(
            fill.failed[0].1.contains("shadowsocks"),
            "failure reason must name the family: {}",
            fill.failed[0].1
        );
        assert!(fill.bridge.get("socks-in").is_some());
        assert!(fill.bridge.get("ss-out").is_none(), "failed conversion must not fake an entry");
    }

    /// B5 step4 优雅停机确定性验收（agent 环境控制台 CTRL_C 投递不可靠——
    /// default 二进制实测同样不退）：真实 socks listener 起真端口 → curl 语义
    /// 连接可建立 → 注入停机触发器 → close→join→插件停机 → 端口关闭 → Ok
    /// （run_framework_until 非clean即 Err，Ok = 停机报告 clean）。
    #[test]
    fn framework_graceful_shutdown_stops_listener_and_reports_clean() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let config = xray_conf::Config::from_json_str(
                r#"{
                "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 12836, "settings": {}}],
                "outbounds": [{"protocol": "freedom", "tag": "freedom-out", "settings": {}}]
            }"#,
            )
            .unwrap();
            let built = config.build().unwrap();
            let root = config.to_json_value().unwrap();

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let serve = crate::framework::run_framework_until(&built, root, async move {
                let _ = rx.await;
            });
            tokio::pin!(serve);

            // listener 真实可连（spawn_inbounds 生产机制起 bind；serve 并发驱动）。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut connected = false;
            while std::time::Instant::now() < deadline {
                tokio::select! {
                    biased;
                    res = serve.as_mut() => {
                        panic!("serve finished before listener came up: {res:?}");
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        if tokio::net::TcpStream::connect("127.0.0.1:12836").await.is_ok() {
                            connected = true;
                            break;
                        }
                    },
                }
            }
            assert!(connected, "socks listener never accepted within 10s");

            // 注入停机信号：与生产 wait_for_signal 同一停机序（close→join→插件停机）。
            tx.send(()).expect("shutdown trigger receiver alive");
            let result = tokio::time::timeout(std::time::Duration::from_secs(15), serve.as_mut())
                .await
                .expect("graceful shutdown exceeded 15s");
            assert!(result.is_ok(), "run_framework_until returned Err: {result:?}");

            // listener 已停（端口拒连）。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut refused = false;
            while std::time::Instant::now() < deadline {
                if tokio::net::TcpStream::connect("127.0.0.1:12836").await.is_err() {
                    refused = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(refused, "listener port still accepting after shutdown");
        });
    }

    /// 真协议 handler 最小 dispatch：blackhole 桥 handler（插件产出）dispatch 即
    /// 关 link——查询与调用路径贯通，无网络依赖。
    #[test]
    fn blackhole_bridge_handler_dispatch_closes_link() {
        let config = xray_conf::Config::from_json_str(
            r#"{"outbounds": [{"protocol": "blackhole", "tag": "block", "settings": {}}]}"#,
        )
        .unwrap();
        let built = config.build().unwrap();
        let root = config.to_json_value().unwrap();
        let plan = derive_families(&built);
        assert_eq!(plan.families.len(), 1);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");

            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected failures: {:?}", fill.failed);
            let handler = fill.bridge.get("block").expect("block handler");
            assert_eq!(handler.tag(), "block");

            let dest = xray_common::net::destination::Destination::tcp(
                "127.0.0.1".parse().unwrap(),
                xray_common::net::port::Port::new(8080),
            );
            let link = xray_transport::link::Link::new(Box::new(NullReader), Box::new(NullWriter));
            // DispatchHandler::dispatch 契约 Output = ()：fire-and-forget 语义，
            // blackhole 收敛即成功（读错误不冒泡）。
            handler.dispatch(&dest, link).await;

            framework.shutdown().await;
        });
    }

    // ── Link mock：dispatch 签名要求的 reader/writer 占位（blackhole 不读写）──

    struct NullReader;

    impl xray_buf::io::Reader for NullReader {
        fn read_multi_buffer(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<Output = xray_buf::io::Result<xray_buf::multi::MultiBuffer>> + Send + '_,
            >,
        > {
            Box::pin(std::future::ready(Err(xray_buf::io::Error::ReadError("null reader".into()))))
        }
    }

    struct NullWriter;

    impl xray_buf::io::Writer for NullWriter {
        fn write_multi_buffer(
            &mut self,
            _mb: xray_buf::multi::MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
            Box::pin(std::future::ready(Err(xray_buf::io::Error::WriteError("null writer".into()))))
        }
    }
}
