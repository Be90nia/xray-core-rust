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
//! - **handler 桥**：从已 build 的插件族把每个配置条目转成 dispatcher 可调 handler，填
//!   [`HandlerBridge`] 查表。出站两条路：插件缝族（freedom/vmess/vless/blackhole/loopback， 插件
//!   build 态 → `dispatch_handler`/`dial_fn`/`handler`）与 core 单出站构建族
//!   （trojan/http/socks/tuic/hysteria/anytls/wireguard/dns/tun——客户端解析在 xray-core 内部，经
//!   pub `outbound::build_single_outbound` 复用）；入站 = `InboundDispatchHandler` （生产同款 tag
//!   面）。转换失败逐条计数 + 日志（成功几个算几个），重复 tag 拒绝（不覆盖）；
//!   该族消费不了的条目级面（[`EntryFacet`]）在场即拒。代理链拆两态：应用层
//!   （`proxySettings.tag`）插件缝族经 [`ChainSlot`] 装配后 late-bind（生产 `register_outbounds`
//!   Phase 2 同款）；传输层（`sockopt.dialerProxy`）与 mux / sendThrough 仍拒（见
//!   [`EntryFacet::reason`]）。
//! - **段路由**：装配根 `with_config(config_root)`（`Config::to_json_value()`
//!   同源投影，禁从原文件二次解析），插件 build 期经 `ctx.section()` 取自己 那段（缺段
//!   fail-fast，L5）。
//!
//! 探针（[`AssemblyProbe`]）恒注册：装配链贯通的金丝雀。v0.1 已知限制：同
//! protocol 多实例条目只转换首个（xray-frame v0.1 每 protocol 只 build 首段，
//! 余者记账失败）；传输层代理链与 mux 包装属 `register_outbounds` 内接线（全局
//! 钩子 / MuxBridge），框架注入臂未接；core 单构建族的应用层代理链被
//! `build_single_outbound` 丢参守卫。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use xray_app_dispatcher::{
    DispatchHandler,
    default::{DefaultDispatcher, DialBridge, DialFn, SniffingRequest},
};
use xray_conf::{BuiltConfig, BuiltOutbound};
use xray_core::{
    outbound::BuildError as OutboundBuildError,
    wiring::{InboundDispatchHandler, sniffing_request_from_json},
};
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
use xray_proxy_loopback::{LoopbackError, LoopbackPlugin, LoopbackSink};
use xray_proxy_socks::SocksPlugin;
use xray_proxy_ss::SsPlugin;
use xray_proxy_trojan::TrojanPlugin;
use xray_proxy_tuic::TuicPlugin;
use xray_proxy_tun::TunPlugin;
use xray_proxy_vless::VlessPlugin;
use xray_proxy_vmess::VmessPlugin;
use xray_proxy_wireguard::WireguardPlugin;
use xray_transport::dialer::StreamSettings;

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
/// handler，如仅入站面的插件）+ 该族转换缝**不消费**的出站条目级配置面
/// （[`EntryFacet`]：在场即拒，不静默丢语义）。
struct RegisteredFamily {
    protocol: &'static str,
    plugin: Arc<dyn Plugin>,
    outbound: Option<OutboundConvert>,
    unhandled: &'static [EntryFacet],
    /// loopback 专用：回注 sink 的 late-bind 槽（其余族 `None`）。handler 构造期
    /// 生产 sink 尚不存在（dispatcher 在注入点内才就绪），装配返回后回填。
    loopback_slot: Option<LoopbackSlot>,
    /// 代理链 late-bind 槽（插件缝族有，其余 `None`）：填表时收集 chained
    /// `DialBridge` + tag，装配返回出站表后回填 `set_proxy_chain`。
    chain_slot: Option<ChainSlot>,
}

/// loopback 回注缝的 late-bind 槽：桥填表时随 handler 注入
/// [`DeferredLoopbackSink`] 占位，`start_full_with_outbound_handlers` 返回生产
/// sink（`DispatcherLoopbackSink`）后由 [`run_framework_until`] 回填。
type LoopbackSlot = Arc<OnceLock<Arc<dyn LoopbackSink>>>;

/// 代理链 late-bind 槽（[`LoopbackSlot`] 同族）：桥填表时随 handler 收集
/// `(DialBridge, chain_tag)`，装配返回出站表（`Arc<SimpleOhm>`）后由
/// [`run_framework_until`] 回填 `set_proxy_chain`——生产 `register_outbounds`
/// Phase 2 同款（表就绪前 chained dispatch 查无 manager）。
type ChainSlot = Arc<Mutex<Vec<(Arc<DialBridge>, String)>>>;

/// `proxySettings.tag` 非空 tag 提取（生产 `parse_proxy_chain_tag` 同规：缺失/
/// 空串 = 无链；tagless proxySettings 生产视为 inert，不拒）。
fn proxy_chain_tag(ob: &BuiltOutbound) -> Option<String> {
    ob.proxy_settings_json
        .as_ref()
        .and_then(|v| v.get("tag"))
        .and_then(serde_json::Value::as_str)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
}

/// loopback 条目的重分发 sniffing：`settings.sniffing` → xray-core wiring 权威
/// 解析（`sniffing_request_from_json`，destOverride 别名归一 / 排除表的 geodata
/// 语义都在那）——同生产 `parse_loopback_config` 的 sniffing 半边；tag 半边由
/// 插件 `built_inbound_tag` 提供。无配置 = 零值请求（不嗅探，同 Go）。
fn loopback_sniffing(ob: &BuiltOutbound) -> SniffingRequest {
    let settings = serde_json::from_slice::<serde_json::Value>(&ob.entry.data).ok();
    sniffing_request_from_json(settings.as_ref().and_then(|v| v.get("sniffing")))
}

/// 回注 sink 占位：转发到槽内生产 sink；未绑定即命中 = 装配时序 bug，显式
/// `SinkNotInjected`（LoopbackHandler 侧 warn + 断链，不静默黑洞）。
#[derive(Debug)]
struct DeferredLoopbackSink {
    slot: LoopbackSlot,
}

impl LoopbackSink for DeferredLoopbackSink {
    fn dispatch_loopback(
        &self,
        inbound_tag: String,
        destination: xray_common::net::destination::Destination,
        sniffing: SniffingRequest,
        link: xray_transport::link::Link,
    ) -> xray_proxy_loopback::LoopbackFuture<std::result::Result<(), LoopbackError>> {
        match self.slot.get() {
            Some(sink) => sink.dispatch_loopback(inbound_tag, destination, sniffing, link),
            None => Box::pin(async move { Err(LoopbackError::SinkNotInjected) }),
        }
    }
}

/// 出站条目级配置面中**仍有族消费不了**的部分（生产 `register_outbounds`
/// 消费的面；`streamSettings` 已全族解封——插件缝经 `with_stream_settings`、
/// core 单构建族原生消费、blackhole/loopback 生产同样忽略——故不入本枚举）。
#[derive(Clone, Copy)]
enum EntryFacet {
    /// 应用层代理链（`proxySettings.tag` 非空）：dispatch 经 chained handler
    /// （`DialBridge::set_proxy_chain` + `OutboundHandlerManager` 查表）。插件缝族
    /// 已解封：族自有 [`ChainSlot`]，装配返回出站表后 late-bind（生产
    /// `register_outbounds` Phase 2 同款）。core 单构建族仍拒——
    /// `build_single_outbound` 丢弃三组件装配形态的 bridge ref + tag，框架看不
    /// 见 `DialBridge` 就无法 late-bind。
    ProxyChainTag,
    /// 传输层代理链（`sockopt.dialerProxy` 非空）：拨号重定向走全局
    /// `DIALER_PROXY_HOOK`（pipe + chained Dispatch，Go dialer.go:270-279），
    /// 安装点在 `register_outbounds` 尾部；框架注入臂不装钩子（xray-core 未
    /// 暴露 pub 安装入口），sockopts 兄弟键覆盖与否均同拒。
    DialerProxy,
    /// `mux` 包装（`MuxBridge` 承载会话复用）。
    Mux,
    /// `sendThrough`（源地址/CIDR 解析 + `DIAL_SRC` 拨号包装）。
    SendThrough,
}

impl EntryFacet {
    /// 该面在条目上是否在场（在场 = 转换会丢语义）。
    fn present(self, ob: &BuiltOutbound) -> bool {
        match self {
            Self::ProxyChainTag => proxy_chain_tag(ob).is_some(),
            Self::DialerProxy => ob
                .stream_settings_json
                .as_ref()
                .and_then(|s| s.get("sockopt"))
                .and_then(|s| s.get("dialerProxy"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|tag| !tag.is_empty()),
            Self::Mux => ob.mux_json.is_some(),
            Self::SendThrough => ob.send_through.is_some(),
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::ProxyChainTag => {
                "proxySettings.tag chain needs the outbound-table phase 2 (DialBridge \
                 set_proxy_chain), but xray-core build_single_outbound drops the DialBridge \
                 reference and chain tag (three-component shape is pub(crate)); the framework \
                 cannot late-bind what it cannot see"
            },
            Self::DialerProxy => {
                "sockopt.dialerProxy redirects the transport dial through the global \
                 DIALER_PROXY_HOOK, which only register_outbounds installs; the framework \
                 injection arm has no hook (xray-core exposes no public hook installer)"
            },
            Self::Mux => "mux wrapping (MuxBridge) is not applied by this family's conversion",
            Self::SendThrough => {
                "sendThrough (parse_send_through / wrap_dial_with_send_through) is xray-core \
                 pub(crate); this family's conversion cannot honour it"
            },
        }
    }
}

/// 插件缝族（freedom/vmess/vless）：transport 与应用层代理链已接（后者经
/// [`ChainSlot`] late-bind），其余条目级面未接。
const PLUGIN_SEAM_UNHANDLED: &[EntryFacet] =
    &[EntryFacet::DialerProxy, EntryFacet::Mux, EntryFacet::SendThrough];

/// `xray-core` 单出站构建族：原生消费 `streamSettings`/`sendThrough`/`mux`，
/// 但 `build_single_outbound` 丢弃 `proxy_chain_tag` 与 DialBridge 引用（三组件
/// 装配形态的第二、三元），两类代理链仍拒。
const CORE_SINGLE_UNHANDLED: &[EntryFacet] = &[EntryFacet::ProxyChainTag, EntryFacet::DialerProxy];

/// 入站面族：插件产出 inbound server（listener 面由 `spawn_inbounds` 消费）；
/// 桥面 = [`InboundDispatchHandler`]（tag 派生，不依赖插件状态，[`fill_bridge`]
/// 直造）。
fn inbound_only<P: Plugin + Default + 'static>(protocol: &'static str) -> RegisteredFamily {
    RegisteredFamily {
        protocol,
        plugin: Arc::new(P::default()),
        outbound: None,
        unhandled: &[],
        loopback_slot: None,
        chain_slot: None,
    }
}

/// `xray-core` 单出站构建族（trojan/http/socks/tuic/hysteria/anytls/wireguard/
/// dns/tun）：这些族的客户端配置解析在 xray-core 内部（`pub(crate)`
/// `parse_*_config` + `wrap_bridge`），P2 插件化只迁移了入站解析面；桥内重写解析
/// = 第二份生产语义（漂移风险）。故复用 xray-core 的 **pub** 单出站构建入口
/// [`xray_core::outbound::build_single_outbound`]（API 动态 AddOutbound 同款，
/// 逐协议构造函数与 `register_outbounds` 同源）。
fn core_outbound_family<P: Plugin + Default + 'static>(protocol: &'static str) -> RegisteredFamily {
    RegisteredFamily {
        protocol,
        plugin: Arc::new(P::default()),
        unhandled: CORE_SINGLE_UNHANDLED,
        loopback_slot: None,
        chain_slot: None,
        outbound: Some(Arc::new(|ob| {
            xray_core::outbound::build_single_outbound(ob).map_err(|e| match e {
                // Unsupported 携带的是协议名或平台拒绝文案（如非 Linux 的 TUN），
                // 原样透出让失败记账可读。
                OutboundBuildError::Unsupported(reason) => {
                    format!("xray-core outbound builder rejected the entry: {reason}")
                },
                OutboundBuildError::Parse(e) => e,
            })
        })),
    }
}

/// 出站条目 transport：`StreamSettings::from_json` + 生产折叠规则（裸 TCP、无
/// TLS、无 `sockopt`/`finalmask`/transport 级配置 = 无 streamSettings）。与
/// xray-core `outbound::parse_stream_settings`（`pub(crate)`）逐条同规。
fn stream_settings(ob: &BuiltOutbound) -> Option<StreamSettings> {
    let settings = StreamSettings::from_json(ob.stream_settings_json.as_ref());
    let transport_extras = settings.sockopt_json.is_some()
        || settings.finalmask_json.is_some()
        || settings.transport_json.is_some();
    if settings.protocol == "tcp" && !settings.is_tls() && !transport_extras {
        None
    } else {
        Some(settings)
    }
}

/// `dial_fn` 形态出站族（vmess/vless）：插件暴露已解析的出站配置（`built_outbound`）
/// + `DialFn`（既有拨号语义全量）；桥补条目级 transport（生产
///   `build_vmess_outbound`/`build_vless_outbound` 同款 `with_stream_settings`）， 再经 dispatcher
///   自家的 [`DialBridge`] 适配成 `DispatchHandler`。
fn dial_fn_family<P, F>(protocol: &'static str, dial: F) -> RegisteredFamily
where
    P: Plugin + Default + 'static,
    F: Fn(&P, Option<StreamSettings>) -> std::result::Result<DialFn, PluginError>
        + Send
        + Sync
        + 'static,
{
    let plugin = Arc::new(P::default());
    let p = Arc::clone(&plugin);
    let chain_slot: ChainSlot = Arc::new(Mutex::new(Vec::new()));
    let slots = Arc::clone(&chain_slot);
    RegisteredFamily {
        protocol,
        unhandled: PLUGIN_SEAM_UNHANDLED,
        loopback_slot: None,
        chain_slot: Some(chain_slot),
        outbound: Some(Arc::new(move |ob| {
            let dial_fn = dial(&p, stream_settings(ob)).map_err(|e| e.to_string())?;
            let bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
            if let Some(chain_tag) = proxy_chain_tag(ob) {
                slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((Arc::clone(&bridge), chain_tag));
            }
            Ok(bridge as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// freedom 出站族：`make_dial_fn_with_config`（拨号路径语义：fragment/
/// destinationOverride/proxyProtocol/domainStrategy/sockopt/bd 7p1m RCVBUF）+
/// [`FreedomDispatchBridge`]（dispatch 路径语义：finalRules Block 检查、noises、
/// UDP relay 策略）+ 生产同款 splice 标记（Go freedom.go:260）。
fn freedom_family(
    inbound_rules: &HashMap<String, xray_proxy_freedom::DefaultRuleType>,
) -> RegisteredFamily {
    let plugin = Arc::new(FreedomPlugin::default());
    let p = Arc::clone(&plugin);
    let chain_slot: ChainSlot = Arc::new(Mutex::new(Vec::new()));
    let slots = Arc::clone(&chain_slot);
    let inbound_rules = inbound_rules.clone();
    RegisteredFamily {
        protocol: "freedom",
        unhandled: PLUGIN_SEAM_UNHANDLED,
        loopback_slot: None,
        chain_slot: Some(chain_slot),
        outbound: Some(Arc::new(move |ob| {
            let cfg = p.built_config().map_err(|e| e.to_string())?.clone();
            let dial_bridge = Arc::new(DialBridge::new(
                ob.tag.clone(),
                make_freedom_dial_fn_with_config(cfg.clone()),
            ));
            dial_bridge.set_splice_outbound(true);
            let chain_tag = proxy_chain_tag(ob);
            // 链上 freedom 非最终出站：finalRules 与入站默认规则都不注入（配了
            // finalRules 则 warn），Go freedom.go:193-198 + 生产
            // build_freedom_outbound 同款。
            let uses_dialer_proxy = chain_tag.is_some();
            let final_rules = if uses_dialer_proxy {
                if !cfg.final_rules.is_empty() {
                    crate::LOG.warn(format!(
                        "framework: freedom tag={:?}: The \"finalRules\" setting is ignored when \
                         \"sockopt.dialerProxy\" is set, since freedom is not the final outbound.",
                        ob.tag
                    ));
                }
                Vec::new()
            } else {
                cfg.final_rules
                    .iter()
                    .map(FinalRule::build)
                    .collect::<xray_proxy_freedom::Result<Vec<_>>>()
                    .map_err(|e| format!("freedom finalRule: {e}"))?
            };
            if let Some(chain_tag) = chain_tag {
                slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((Arc::clone(&dial_bridge), chain_tag));
            }
            let handler = FreedomDispatchBridge::from_bridge(
                // 接缝暂自持 for_plugin ctx（族级单实例）；P3 装配接线时改传装配根 ctx。
                Arc::new(PluginContext::for_plugin("freedom")),
                dial_bridge,
            )
            .with_noises(cfg.noises.clone())
            .with_destination_override(cfg.destination_override.clone())
            .with_domain_strategy(cfg.domain_strategy)
            .with_final_rules(final_rules);
            // Go 默认 BlockPrivate 兜底（私网/环回/169.254 元数据，Go
            // freedom.go:154-174 getDefaultFinalRule(inbound.Name)）；生产
            // build_freedom_outbound 同款注入，此前框架路径漏注入 = SSRF 面。
            let handler = if uses_dialer_proxy {
                handler
            } else {
                handler.with_inbound_default_rules(inbound_rules.clone())
            };
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
        // 生产构造器不消费这些面：代理链/sendThrough/streamSettings 生产同样
        // 忽略；mux 包装对本族无语义（流量全丢）。
        unhandled: &[],
        loopback_slot: None,
        chain_slot: None,
        outbound: Some(Arc::new(move |ob| {
            // 能力句柄随 ctx 注入（nn8os 2b：日志/spawn 只经 ctx）——与 freedom 族
            // 同款族级自持 ctx。
            let ctx = Arc::new(PluginContext::for_plugin("blackhole"));
            let handler = p.dispatch_handler(ctx, &ob.tag).map_err(|e| e.to_string())?;
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// loopback 出站族：插件自家 `handler`（`LoopbackHandler` 已是 `DispatchHandler`，
/// 回环目标 = build 期段里的 `inboundTag`）+ 回注 sink 的 late-bind 缝：构造期
/// 注入 [`DeferredLoopbackSink`] 占位，装配返回生产 `DispatcherLoopbackSink` 后
/// 由 [`run_framework_until`] 经 [`LoopbackSlot`] 回填（票 rdcc；此前无 sink =
/// `error!` + drop 黑洞）。
fn loopback_family() -> RegisteredFamily {
    let plugin = Arc::new(LoopbackPlugin::default());
    let p = Arc::clone(&plugin);
    let slot: LoopbackSlot = Arc::new(OnceLock::new());
    RegisteredFamily {
        protocol: "loopback",
        // 生产构造器只消费 inboundTag/sniffing：代理链/sendThrough/streamSettings
        // 生产同样忽略；mux 包装对本族无语义（链接回注即重新选路）。
        unhandled: &[],
        loopback_slot: Some(Arc::clone(&slot)),
        chain_slot: None,
        outbound: Some(Arc::new(move |ob| {
            let handler = p
                .handler(&ob.tag)
                .map_err(|e| e.to_string())?
                .with_sniffing_request(loopback_sniffing(ob))
                .with_sink(Arc::new(DeferredLoopbackSink { slot: Arc::clone(&slot) }));
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        })),
        plugin,
    }
}

/// 协议目录：配置 `protocol` 串 → 插件族构造。目录只提供**构造器**，注册集 =
/// 配置引用集（禁硬编码清单）；目录未覆盖 = 未迁移（shadowsocks）/未知族 →
/// [`derive_families`] 记账不注册。族名与 xray-conf `BuiltEntry.kind` /
/// `Config::to_json_value()` 的 `protocol` 字段逐字对齐（插件 `name()` 同源）。
fn family_catalog(
    protocol: &str,
    inbound_rules: &HashMap<String, xray_proxy_freedom::DefaultRuleType>,
) -> Option<RegisteredFamily> {
    let family = match protocol {
        // 入站面 + xray-core 单出站构建（客户端解析在 xray-core 内部）。
        "socks" => core_outbound_family::<SocksPlugin>("socks"),
        "http" => core_outbound_family::<HttpPlugin>("http"),
        "trojan" => core_outbound_family::<TrojanPlugin>("trojan"),
        "tuic" => core_outbound_family::<TuicPlugin>("tuic"),
        "anytls" => core_outbound_family::<AnytlsPlugin>("anytls"),
        "hysteria" => core_outbound_family::<HysteriaPlugin>("hysteria"),
        "wireguard" => core_outbound_family::<WireguardPlugin>("wireguard"),
        "tun" => core_outbound_family::<TunPlugin>("tun"),
        "dns" => core_outbound_family::<DnsPlugin>("dns"),
        // 纯入站协议（无出站形态；xray-core 出站构造表键为 "dokodemo"，与配置
        // protocol 名 "dokodemo-door" 不同源，故不走单出站构建）。
        "dokodemo-door" => inbound_only::<DokodemoPlugin>("dokodemo-door"),
        "freedom" => freedom_family(inbound_rules),
        "vmess" => dial_fn_family::<VmessPlugin, _>("vmess", |p, stream| {
            let config = (**p.built_outbound()?).clone().with_stream_settings(stream);
            // 接缝暂自持 for_plugin ctx（族级单实例）；P3 装配接线时改传装配根 ctx。
            Ok(xray_proxy_vmess::make_vmess_dial_fn(
                Arc::new(config),
                Arc::new(PluginContext::for_plugin("vmess")),
            ))
        }),
        "vless" => dial_fn_family::<VlessPlugin, _>("vless", |p, stream| {
            let config = (**p.built_outbound()?).clone().with_stream_settings(stream);
            Ok(xray_proxy_vless::make_vless_dial_fn(Arc::new(config)))
        }),
        "shadowsocks" => dial_fn_family::<SsPlugin, _>("shadowsocks", |p, stream| {
            let config = (**p.built_outbound()?).clone().with_stream_settings(stream);
            Ok(xray_proxy_ss::make_ss_dial_fn_with_ctx(
                Arc::new(config),
                Arc::new(PluginContext::for_plugin("shadowsocks")),
            ))
        }),
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
    // 生产同源表（xray-core `register_outbounds` 同一函数）：freedom 的默认
    // BlockPrivate 兜底按入站协议名生效。
    let inbound_rules = xray_core::outbound::inbound_default_rules(built);
    let push_family = |kind: &str, plan: &mut FamilyPlan| {
        if plan.families.iter().any(|f| f.protocol == kind)
            || plan.unregistered.iter().any(|u| u == kind)
        {
            return;
        }
        match family_catalog(kind, &inbound_rules) {
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
    /// 本桥 loopback handler 的回注 late-bind 槽——装配返回生产 sink 后回填。
    loopback_slots: Vec<LoopbackSlot>,
    /// 本桥插件缝族的代理链 late-bind 槽——装配返回出站表后回填。
    chain_slots: Vec<ChainSlot>,
}

/// 出站条目的转换前守卫：该族转换缝**不消费**的条目级面在场 → 拒（不静默丢
/// 语义）。各族消费能力见 [`EntryFacet`] 与 [`family_catalog`] 的族装配。
fn guard_outbound_entry(
    ob: &BuiltOutbound,
    family: &RegisteredFamily,
) -> std::result::Result<(), String> {
    family
        .unhandled
        .iter()
        .find(|facet| facet.present(ob))
        .map_or(Ok(()), |facet| Err(facet.reason().to_string()))
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
        loopback_slots: families
            .iter()
            .filter_map(|family| family.loopback_slot.as_ref().map(Arc::clone))
            .collect(),
        chain_slots: families
            .iter()
            .filter_map(|family| family.chain_slot.as_ref().map(Arc::clone))
            .collect(),
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
        if let Err(reason) = guard_outbound_entry(ob, family) {
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

/// 代理链 late-bind（生产 `register_outbounds` Phase 2 同款）：出站表就绪后为
/// 各 chained [`DialBridge`] 回填 `(chain_tag, manager)`。返回回填对数。
fn bind_proxy_chains(
    chain_slots: &[ChainSlot],
    manager: Arc<dyn xray_app_dispatcher::OutboundHandlerManager>,
) -> usize {
    let mut bound = 0;
    for slot in chain_slots {
        for (bridge, chain_tag) in
            slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).drain(..)
        {
            bridge.set_proxy_chain(chain_tag, Arc::clone(&manager));
            bound += 1;
        }
    }
    bound
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
    let BridgeFill { bridge, ok, failed, outbound_handlers, loopback_slots, chain_slots } =
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
    let (instance, ohm, handles, loopback_sink) =
        xray_core::functions::start_full_with_outbound_handlers(built, outbound_handlers)
            .await
            .map_err(|e| CliError::StartFailed(format!("framework inbound start failed: {e}")))?;
    crate::LOG.info(format!("framework: {} inbound listener(s) serving", handles.len()));

    // ⑤ loopback 回注 sink late-bind（票 rdcc）：桥 handler 构造期拿不到生产 sink
    // （dispatcher 在注入点内才就绪），持 `DeferredLoopbackSink` 占位；此刻生产
    // `DispatcherLoopbackSink` 随返回值就绪，回填后回注走生产 dispatch_link 全序
    // （routing/sniffing/stats/access-log）。绑定前的极小窗口内命中 loopback 的
    // 连接得到显式 `SinkNotInjected`（warn + 断链，非静默）。
    for slot in &loopback_slots {
        let _ = slot.set(Arc::clone(&loopback_sink));
    }
    if !loopback_slots.is_empty() {
        crate::LOG.info(format!(
            "framework: loopback re-injection sink bound ({} slot(s))",
            loopback_slots.len()
        ));
    }

    // 代理链 late-bind（生产 register_outbounds Phase 2 同款）：出站表此刻已就绪，
    // 回填 chained DialBridge 的 (chain_tag, manager)。回填前的极小窗口内 chained
    // 出站按未配链直拨（DialBridge dispatch 先判 chain_tag）——与 loopback 回注
    // 窗同源；零窗口需 dispatcher 拆分 tag/manager setter（本轮不动 xray-core）。
    let chain_bound = bind_proxy_chains(&chain_slots, ohm);
    if chain_bound > 0 {
        crate::LOG.info(format!("framework: proxy chains bound ({chain_bound} chain(s))"));
    }

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

    /// v787x：`framework-assembly` 路径的 freedom 必须保留 Go 默认 BlockPrivate 兜底
    /// （Go freedom.go:154-174 `getDefaultFinalRule(inbound.Name)`；与生产
    /// `register_outbounds` 同一张表）。判别力：目标 = 本机 127.0.0.1 真实监听器，
    /// 一旦被拨号计数必 > 0。阶段 1（vless 入站 → BlockPrivate）零拨号；阶段 2
    /// （socks 入站不在 Go 表）正常拨号 1 次——正控证明观察手段看得见拨号，故阶段 1
    /// 的 0 是真阻断而非假阴。修前（漏注入）阶段 1 计数 = 1，必红。
    #[test]
    fn framework_freedom_blocks_private_targets_for_default_rule_inbounds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use xray_buf::io::Writer as _; // pipe Writer::shutdown（drain EOF）

        let (built, root, plan) = plan_from_json(
            r#"{
            "inbounds": [
                {"protocol": "vless", "tag": "vless-in", "listen": "127.0.0.1", "port": 12840, "settings": {"decryption": "none"}},
                {"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 12841, "settings": {}}
            ],
            "outbounds": [{"protocol": "freedom", "tag": "freedom-out", "settings": {}}]
        }"#,
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // 环回目标监听器：被拨号即计数 1，并立即关闭（freedom 侧随即 EOF）。
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap();
            let dials = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&dials);
            let accept = tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(sock);
                }
            });

            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");
            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected conversion failures: {:?}", fill.failed);
            let handler = Arc::clone(fill.bridge.get("freedom-out").expect("freedom-out handler"));

            let dest = xray_common::net::destination::Destination::tcp(
                target.ip().into(),
                xray_common::net::port::Port::new(target.port()),
            );
            // xray-buf pipe 无 Drop 关闭：返回 up_w 供显式 shutdown（drain 才有 EOF）。
            let new_link = || {
                let (up_r, up_w) = xray_buf::pipe::new();
                let (dn_r, dn_w) = xray_buf::pipe::new();
                (
                    xray_transport::link::Link::new(
                        Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
                        Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
                    ),
                    up_w,
                    dn_r,
                )
            };
            let access = |inbound_tag: &str| xray_app_dispatcher::AccessContext {
                inbound_tag: inbound_tag.to_string(),
                ..Default::default()
            };

            // 阶段 1：vless 入站 → 默认 BlockPrivate 命中 127.0.0.1 → 黑洞，零拨号。
            let (link, up_w, _dn_r) = new_link();
            let blocked =
                tokio::spawn(handler.dispatch_with_access(&dest, link, access("vless-in")));
            up_w.shutdown();
            tokio::time::timeout(std::time::Duration::from_secs(5), blocked)
                .await
                .expect("blocked dispatch must converge on link EOF")
                .expect("blocked dispatch must not panic");
            assert_eq!(
                dials.load(Ordering::SeqCst),
                0,
                "vless 入站的环回目标必须被 Go 默认 BlockPrivate 规则阻断（零拨号）"
            );

            // 阶段 2：socks 入站不在 Go 默认表 → 无默认规则 → 正常拨号（正控）。
            let (link, _up_w, _dn_r) = new_link();
            let dialed =
                tokio::spawn(handler.dispatch_with_access(&dest, link, access("socks-in")));
            tokio::time::timeout(std::time::Duration::from_secs(5), dialed)
                .await
                .expect("dial dispatch must converge on peer close")
                .expect("dial dispatch must not panic");
            assert_eq!(
                dials.load(Ordering::SeqCst),
                1,
                "socks 入站无默认规则，必须真的拨到目标（正控）"
            );

            accept.abort();
            let report = framework.shutdown().await;
            assert!(report.is_clean(), "shutdown unclean: {report:?}");
        });
    }

    /// 失败记账：族转换失败（ss 出站族在场但未 build → `built_outbound` fail-visible）
    /// → 桥逐条计数失败（不静默覆盖、不伪造成功）；入站面照常
    /// （InboundDispatchHandler tag 面不依赖族）。
    #[test]
    fn bridge_fill_counts_failures_for_failed_family_conversion() {
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
        assert_eq!(plan.families.len(), 2, "shadowsocks outbound + socks inbound derived");
        assert!(plan.unregistered.is_empty(), "unregistered: {:?}", plan.unregistered);

        let dispatcher = Arc::new(DefaultDispatcher::new());
        let fill = fill_bridge(&built, &plan.families, &dispatcher);
        assert_eq!(fill.ok, 1, "only the socks inbound converts");
        assert_eq!(fill.failed.len(), 1);
        assert_eq!(fill.failed[0].0, "ss-out");
        assert!(
            fill.failed[0].1.contains("not built"),
            "failure reason must name the cause: {}",
            fill.failed[0].1
        );
        assert!(fill.bridge.get("socks-in").is_some());
        assert!(fill.bridge.get("ss-out").is_none(), "failed conversion must not fake an entry");
    }

    /// A：出站族逐族构造断言。10 族的客户端配置解析在 xray-core 内部
    /// （`pub(crate) parse_*_config`），桥经 pub 单出站构建入口
    /// `outbound::build_single_outbound` 消费；不能转换的族给出明确原因，不伪造
    /// 成功条目。
    #[test]
    fn core_outbound_families_convert_or_fail_per_family() {
        const UUID: &str = "f2b3c1d4-1234-4abc-9def-0123456789ab";
        let wireguard = format!(
            r#"{{"secretKey":"{}","peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:51820"}}]}}"#,
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let tuic = format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":443,"uuid":"{UUID}","password":"pw"}}]}}"#
        );
        // (protocol, settings, streamSettings, 期望) —— Ok = 真转换；Err(关键词) = 记账失败。
        // clippy type_complexity 拆型（用例原文不动；settings 两行借用本地 format!）。
        type CoreFamilyCase<'a> =
            (&'a str, &'a str, Option<&'a str>, std::result::Result<(), &'a str>);
        let cases: &[CoreFamilyCase<'_>] = &[
            (
                "trojan",
                r#"{"servers":[{"address":"127.0.0.1","port":443,"password":"pw"}]}"#,
                None,
                Ok(()),
            ),
            ("http", r#"{"servers":[{"address":"127.0.0.1","port":8080}]}"#, None, Ok(())),
            ("socks", r#"{"servers":[{"address":"127.0.0.1","port":1080}]}"#, None, Ok(())),
            ("tuic", &tuic, None, Ok(())),
            (
                "hysteria",
                r#"{"address":"example.com","port":39622}"#,
                Some(r#"{"security":"tls","tlsSettings":{"serverName":"example.com"}}"#),
                Ok(()),
            ),
            (
                "anytls",
                r#"{"server":"127.0.0.1","server_port":443,"password":"pw","insecure":true}"#,
                None,
                Ok(()),
            ),
            ("wireguard", &wireguard, None, Ok(())),
            ("dns", "{}", None, Ok(())),
            (
                "tun",
                "{}",
                None,
                if cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd")) {
                    Ok(())
                } else {
                    Err("TUN outbound is only supported")
                },
            ),
            // 纯入站协议：插件只暴露入站面，不入出站桥（不伪造 handler）。
            ("dokodemo-door", "{}", None, Err("inbound-face plugin only")),
        ];

        // anytls/hysteria 的客户端构造需要 tokio 反应器（anytls 会话池、QUIC 端点）。
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _enter = runtime.enter();
        let dispatcher = Arc::new(DefaultDispatcher::new());
        for (protocol, settings, stream, expected) in cases {
            let family = family_catalog(protocol, &HashMap::new()).expect("family catalog entry");
            let tag = format!("{protocol}-out");
            let mut built = xray_conf::BuiltConfig::default();
            let mut ob = outbound_entry(protocol, &tag, settings.as_bytes());
            ob.stream_settings_json =
                stream.map(|s| serde_json::from_str(s).expect("stream settings json"));
            built.outbounds.push(ob);

            let fill = fill_bridge(&built, &[family], &dispatcher);
            match expected {
                Ok(()) => {
                    assert!(
                        fill.failed.is_empty(),
                        "{protocol}: unexpected failure {:?}",
                        fill.failed
                    );
                    assert_eq!(fill.bridge.get(&tag).expect("bridge handler").tag(), tag);
                    assert_eq!(
                        fill.outbound_handlers.len(),
                        1,
                        "{protocol}: converted handler must reach the injection list"
                    );
                },
                Err(keyword) => {
                    assert_eq!(fill.ok, 0, "{protocol}: must not fabricate a handler");
                    assert_eq!(fill.failed.len(), 1, "{protocol}: exactly one recorded failure");
                    assert!(
                        fill.failed[0].1.contains(keyword),
                        "{protocol}: reason {:?} must mention {keyword:?}",
                        fill.failed[0].1
                    );
                    assert!(
                        fill.bridge.get(&tag).is_none(),
                        "{protocol}: failed entry must stay out"
                    );
                },
            }
        }
    }

    /// C：守卫按族能力表判定。插件缝族（vmess/vless/freedom）接了 transport +
    /// 应用层代理链（`proxySettings.tag` → [`ChainSlot`] late-bind，本测试只看
    /// 守卫放行），传输层代理链/mux/sendThrough 仍拒；core 单构建族原生消费
    /// streamSettings/sendThrough/mux，两类代理链拒（`build_single_outbound`
    /// 丢参）；blackhole/loopback 生产同样忽略这些面（无拨号腿），故不拒。
    #[test]
    fn guard_facets_follow_family_capability_table() {
        let plugin_seam = family_catalog("vless", &HashMap::new()).expect("vless family");
        let core_route = family_catalog("trojan", &HashMap::new()).expect("trojan family");
        let ignoring = family_catalog("blackhole", &HashMap::new()).expect("blackhole family");

        let with = |f: fn(&mut BuiltOutbound)| {
            let mut ob = outbound_entry("x", "entry", b"{}");
            f(&mut ob);
            ob
        };
        let proxy_chain = with(|ob| {
            ob.proxy_settings_json = Some(serde_json::json!({"tag": "chain-out"}));
        });
        let dialer_proxy = with(|ob| {
            ob.stream_settings_json = Some(serde_json::json!({"sockopt": {"dialerProxy": "hop"}}));
        });
        let mux = with(|ob| ob.mux_json = Some(serde_json::json!({"enabled": true})));
        let send_through = with(|ob| ob.send_through = Some("127.0.0.1".into()));
        let stream = with(|ob| {
            ob.stream_settings_json = Some(serde_json::json!({"network": "ws", "security": "tls"}));
        });

        // 插件缝：transport + 应用层代理链解封（后者 late-bind）。
        assert!(guard_outbound_entry(&proxy_chain, &plugin_seam).is_ok());
        assert!(guard_outbound_entry(&dialer_proxy, &plugin_seam).is_err());
        assert!(guard_outbound_entry(&mux, &plugin_seam).is_err());
        assert!(guard_outbound_entry(&send_through, &plugin_seam).is_err());
        assert!(guard_outbound_entry(&stream, &plugin_seam).is_ok());

        // core 单构建：transport / sendThrough / mux 原生消费，两类代理链仍拒。
        assert!(guard_outbound_entry(&stream, &core_route).is_ok());
        assert!(guard_outbound_entry(&send_through, &core_route).is_ok());
        assert!(guard_outbound_entry(&mux, &core_route).is_ok());
        assert!(guard_outbound_entry(&proxy_chain, &core_route).is_err());
        assert!(guard_outbound_entry(&dialer_proxy, &core_route).is_err());

        // 生产同样忽略这些面（无拨号腿/无回环腿）：不拒。
        for ob in [&proxy_chain, &dialer_proxy, &mux, &send_through, &stream] {
            assert!(guard_outbound_entry(ob, &ignoring).is_ok());
        }
    }

    /// B5 守卫收尾（proxyChain 解封）：应用层代理链（`proxySettings.tag`）端到端
    /// late-bind——vmess 链到 blackhole 的配置转换成功、链对随 [`ChainSlot`]
    /// 收集、出站表就绪后 `bind_proxy_chains` 回填（生产 Phase 2 等价形态）且
    /// 链目标在表中可查。
    #[test]
    fn proxy_chain_tag_late_binds_after_outbound_table() {
        use xray_app_dispatcher::OutboundHandlerManager;

        let (built, root, plan) = plan_from_json(
            r#"{
            "outbounds": [{
                "protocol": "blackhole", "tag": "block", "settings": {}
            }, {
                "protocol": "vmess", "tag": "vmess-out",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 8443,
                    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto"}]}]},
                "proxySettings": {"tag": "block"}
            }]
        }"#,
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");

            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected failures: {:?}", fill.failed);
            assert_eq!(fill.bridge.get("vmess-out").expect("vmess handler").tag(), "vmess-out");
            assert_eq!(fill.chain_slots.len(), 1, "vmess family exposes one chain slot");

            // 链对收集：tag 来自 proxySettings，bridge 与 handler 同源。
            let (chained_bridge, chain_tag) = {
                let pairs =
                    fill.chain_slots[0].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(pairs.len(), 1, "one chained entry collected: {:?}", *pairs);
                (Arc::clone(&pairs[0].0), pairs[0].1.clone())
            };
            assert_eq!(chain_tag, "block", "chain tag parsed from proxySettings");
            assert!(!chained_bridge.has_proxy_chain(), "must stay unbound before the table exists");

            // late-bind：出站表就绪形态（SimpleOhm 灌入两 handler，首个 = default，
            // 与 start_full_with_outbound_handlers 注入序同构）→ 回填成功。
            let ohm = Arc::new(xray_app_dispatcher::SimpleOhm::new());
            for handler in &fill.outbound_handlers {
                if ohm.get_default_handler().is_none() {
                    ohm.set_default(Arc::clone(handler));
                }
                ohm.add(handler.tag(), Arc::clone(handler));
            }
            assert!(
                ohm.get_handler("block").is_some(),
                "chain target must resolve in the outbound table"
            );
            assert_eq!(
                bind_proxy_chains(
                    &fill.chain_slots,
                    Arc::clone(&ohm) as Arc<dyn OutboundHandlerManager>
                ),
                1,
                "exactly one chain pair bound"
            );
            assert!(chained_bridge.has_proxy_chain(), "late-bind must configure the bridge");
            assert!(
                fill.chain_slots[0]
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty(),
                "slots drained after bind"
            );

            framework.shutdown().await;
        });
    }

    /// 传输层代理链（`sockopt.dialerProxy`）仍守卫：拒绝理由点名全局钩子与安装
    /// 点；sockopt 兄弟键覆盖在场同拒（同机制，与覆盖无关）。
    #[test]
    fn dialer_proxy_stays_guarded_with_hook_reason() {
        let vless = family_catalog("vless", &HashMap::new()).expect("vless family");
        let mut ob = outbound_entry("vless", "vless-out", b"{}");
        ob.stream_settings_json =
            Some(serde_json::json!({"sockopt": {"dialerProxy": "hop", "mark": 42}}));
        let err = guard_outbound_entry(&ob, &vless).expect_err("dialerProxy must stay rejected");
        assert!(err.contains("DIALER_PROXY_HOOK"), "reason must name the hook: {err}");
        assert!(err.contains("register_outbounds"), "reason must name the installer: {err}");
    }

    /// core 单构建族应用层代理链守卫：`build_single_outbound` 丢 DialBridge 引用
    /// 与 tag，框架无法 late-bind，理由点名丢参。
    #[test]
    fn core_single_family_proxy_chain_tag_stays_guarded() {
        let trojan = family_catalog("trojan", &HashMap::new()).expect("trojan family");
        let mut ob = outbound_entry("trojan", "trojan-out", b"{}");
        ob.proxy_settings_json = Some(serde_json::json!({"tag": "hop"}));
        let err = guard_outbound_entry(&ob, &trojan)
            .expect_err("proxySettings.tag must stay rejected on core families");
        assert!(err.contains("build_single_outbound"), "reason must name the dropped ref: {err}");
    }

    /// freedom 链上形态（Go freedom.go:193-198 镜像）：配 finalRules + 链 →
    /// 转换成功（规则不构建，warn 记账）且链对入槽；无链时同配置照常构建。
    #[test]
    fn freedom_chained_entry_converts_and_skips_final_rules() {
        let (built, root, plan) = plan_from_json(
            r#"{
            "outbounds": [{
                "protocol": "blackhole", "tag": "block", "settings": {}
            }, {
                "protocol": "freedom", "tag": "freedom-out",
                "settings": {"finalRules": [{"action": "allow"}]},
                "proxySettings": {"tag": "block"}
            }]
        }"#,
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");

            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected failures: {:?}", fill.failed);
            assert_eq!(
                fill.bridge.get("freedom-out").expect("freedom handler").tag(),
                "freedom-out"
            );
            let pairs = fill
                .chain_slots
                .iter()
                .flat_map(|s| s.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())
                .collect::<Vec<_>>();
            assert_eq!(pairs.len(), 1, "freedom chain pair collected: {pairs:?}");
            assert_eq!(pairs[0].1, "block");

            framework.shutdown().await;
        });
    }

    /// transport 折叠规则与生产 `outbound::parse_stream_settings`（pub(crate)）同规：
    /// 裸 TCP 无 TLS 无 transport 级配置 = 无 streamSettings；sockopt/finalmask/
    /// tcpSettings.header 在场或带 TLS/ws 时不折叠（折叠会静默丢伪装与 sockopt）。
    #[test]
    fn stream_settings_fold_matches_production() {
        let fold = |json: serde_json::Value| {
            let mut ob = outbound_entry("x", "entry", b"{}");
            ob.stream_settings_json = Some(json);
            stream_settings(&ob)
        };
        assert!(fold(serde_json::json!({"network": "tcp"})).is_none());
        assert!(fold(serde_json::json!({"sockopt": {"mark": 1}})).is_some());
        assert!(fold(serde_json::json!({"tcpSettings": {"header": {"type": "http"}}})).is_some());
        assert!(fold(serde_json::json!({"network": "ws"})).is_some());
        assert!(fold(serde_json::json!({"security": "tls"})).is_some());
    }

    /// 插件缝族的 transport 解封端到端：vless/vmess 出站配 streamSettings（ws+TLS）
    /// → 配置派生 → 装配 build（插件解析 vnext）→ 桥转换成功（旧行为一律拒）。
    #[test]
    fn plugin_seam_stream_settings_reaches_bridge() {
        let (built, root, plan) = plan_from_json(
            r#"{
            "outbounds": [{
                "protocol": "vless",
                "tag": "vless-out",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                    "users": [{"id": "f2b3c1d4-1234-4abc-9def-0123456789ab", "encryption": "none"}]}]},
                "streamSettings": {"network": "ws", "security": "tls",
                    "wsSettings": {"path": "/ray"}, "tlsSettings": {"serverName": "example.com"}}
            }, {
                "protocol": "vmess",
                "tag": "vmess-out",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 8443,
                    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto"}]}]},
                "streamSettings": {"network": "grpc", "security": "tls",
                    "grpcSettings": {"serviceName": "svc"}, "tlsSettings": {"serverName": "example.com"}}
            }]
        }"#,
        );
        assert_eq!(plan.families.len(), 2);
        assert!(plan.unregistered.is_empty(), "unregistered: {:?}", plan.unregistered);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut framework = assemble(root, &plan.families).expect("assemble");
            framework.bring_up().expect("bring_up");

            let dispatcher = Arc::new(DefaultDispatcher::new());
            let fill = fill_bridge(&built, &plan.families, &dispatcher);
            assert!(fill.failed.is_empty(), "unexpected failures: {:?}", fill.failed);
            assert_eq!(fill.bridge.get("vless-out").expect("vless handler").tag(), "vless-out");
            assert_eq!(fill.bridge.get("vmess-out").expect("vmess handler").tag(), "vmess-out");
            assert_eq!(fill.outbound_handlers.len(), 2);

            assert!(framework.shutdown().await.is_clean());
        });
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

    /// B5 loopback 回注 sink e2e：socks 入站 + loopback 出站（配置序首个 =
    /// default）+ freedom + 路由规则（inboundTag "loopback-return" → freedom）。
    /// 客户端 → socks-in → 无规则命中 → default = loopback-out（桥 handler，持
    /// `DeferredLoopbackSink` 占位）→ 注入点返回生产 `DispatcherLoopbackSink` 后
    /// late-bind → 回注（access.inboundTag = "loopback-return"）→ 规则命中
    /// freedom-out → 本机 echo 回显。判别力：late-bind 失败 = SinkNotInjected
    /// 断链（读超时）；回注丢 tag = 再落 default loopback → 无限回环（读超时）。
    /// 双向 payload 逐字节相等 = 回注贯通。
    #[test]
    fn loopback_outbound_reinjection_round_trips_through_framework_bridge() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // 本机 echo 终点（freedom 落地点）。
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_addr = echo.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = echo.accept().await else { return };
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(sock);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            });

            const SOCKS_PORT: u16 = 12837;
            let config = xray_conf::Config::from_json_str(&format!(
                r#"{{
                "inbounds": [{{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": {SOCKS_PORT}, "settings": {{}}}}],
                "outbounds": [
                    {{"protocol": "loopback", "tag": "loopback-out", "settings": {{"inboundTag": "loopback-return"}}}},
                    {{"protocol": "freedom", "tag": "freedom-out", "settings": {{}}}}
                ],
                "routing": {{"rules": [{{"type": "field", "inboundTag": ["loopback-return"], "outboundTag": "freedom-out"}}]}}
            }}"#
            ))
            .unwrap();
            let built = config.build().unwrap();
            let root = config.to_json_value().unwrap();

            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let serve = crate::framework::run_framework_until(&built, root, async move {
                let _ = rx.await;
            });
            tokio::pin!(serve);

            // listener 真实可连（同 graceful 停机测试的轮询形态）。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut connected = false;
            while std::time::Instant::now() < deadline {
                tokio::select! {
                    biased;
                    res = serve.as_mut() => panic!("serve finished before listener came up: {res:?}"),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        if tokio::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).await.is_ok() {
                            connected = true;
                            break;
                        }
                    },
                }
            }
            assert!(connected, "socks listener never accepted within 10s");

            // SOCKS5 no-auth 握手 → CONNECT echo。
            let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", SOCKS_PORT)).await.unwrap();
            sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x00], "socks must accept no-auth");

            let ip = match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                other => panic!("test assumes v4 echo target, got {other:?}"),
            };
            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&ip);
            request.extend_from_slice(&echo_addr.port().to_be_bytes());
            sock.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10]; // VER REP RSV ATYP + IPv4 + port
            sock.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0x00, "socks CONNECT must succeed: {reply:?}");

            // payload 回环往返：socks-in → loopback-out（回注）→ freedom-out → echo。
            let payload = b"loopback-reinjection-round-trip";
            sock.write_all(payload).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            tokio::time::timeout(std::time::Duration::from_secs(10), sock.read_exact(&mut echoed))
                .await
                .expect("round trip within 10s (timeout = sink not bound or tag lost)")
                .expect("echo connection must stay open until payload returns");
            assert_eq!(&echoed, payload, "echo must match byte-for-byte");

            tx.send(()).expect("shutdown trigger receiver alive");
            let result = tokio::time::timeout(std::time::Duration::from_secs(15), serve.as_mut())
                .await
                .expect("graceful shutdown exceeded 15s");
            assert!(result.is_ok(), "run_framework_until returned Err: {result:?}");
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
