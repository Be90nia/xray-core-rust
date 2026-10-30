//! 协议臂构造函数 + 构造表（T4.2 五阶段法 phase 1 抽臂 / phase 2 建表 /
//! phase 4 删旧 match）。
//!
//! phase 1：`crate::inbound::spawn_one_inbound` 与 `crate::outbound::build_protocol_handler`
//! 的 match 协议臂构造逻辑原样搬迁至此，臂内只留一行调用。入参/出参类型、错误
//! 变体、日志文案、注册顺序、失败语义与拆分前逐字段一致（行为零变化）。
//!
//! phase 4:本模块的**构造器** `(方向:协议名) -> builder fn` 是唯一构造路径——
//! 入口经 `crate::arm_registry` 的 xray-frame `PluginRegistry` lookup 命中即构造,
//! 未命中即显式失败(inbound warn+skip、outbound `BuildError::Unsupported`),
//! 旧 match 与回退 feature 已删。表值适配器只做参数解包,转发到 phase 1 同一
//! 构造函数。
//!
//! ## 表实现选型:xray-frame PluginRegistry(W1 切片 1a 落地)
//!
//! 原为 `BTreeMap` 裸 fn 表(与生产装配面的框架注册表两套并存)。现改为
//! **纯数据源** `INBOUND_CTORS` / `OUTBOUND_CTORS`(`&'static` 切片,零分配),
//! 由 `crate::arm_registry` 装配成 xray-frame `PluginRegistry`:容量 fail-closed、
//! 重名拒、deps 拓扑序(缺依赖/成环 → 启动前 `Err`)三道门在**生产路径**生效。
//! 构造 fn 以类型擦除载荷挂在 `Arc<dyn Plugin>` 上,宿主经 `Plugin::payload()`
//! 下转取回。键取 `<方向>:<协议>`(方向前缀):入/出站同名协议不撞重名,且为
//! 将来 16 个协议 Plugin(键 = 裸协议名)并入同一注册表留位。
//!
//! 协议运行时条款(坑约束 12 条)的真源仍各协议 crate 的 `impl Plugin`
//! (见 `xray-proxy-*/src/plugin.rs`);本模块只提供**构造器**,不承载协议语义——
//! 详见 `crate::arm_registry` 的模块文档。

use std::{future::Future, pin::Pin, sync::Arc};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, SimpleOhm},
};
use xray_conf::{BuiltInbound, BuiltOutbound};
use xray_frame::PluginContext;
use xray_proxy_freedom::DomainStrategy;

use crate::outbound::BuildError;

pub(crate) mod inbound;
pub(crate) mod outbound;

// ============ 构造表（T4.2 phase 2 建表 / phase 4 唯一构造路径） ============

/// inbound 构造上下文：spawn_one_inbound 前置逻辑（tun 早退/sockopt 硬错/unix
/// 分派/port 解析/addr+settings 派生）产物按原样打包，入口与表值消费同一份
/// 前置换算结果。
pub(crate) struct InboundCtx<'a> {
    pub(crate) ib: &'a BuiltInbound,
    pub(crate) ohm: Arc<SimpleOhm>,
    pub(crate) policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    pub(crate) shutdown_token: CancellationToken,
    pub(crate) addr: &'a str,
    pub(crate) settings: &'a xray_transport::dialer::StreamSettings,
    pub(crate) api: Option<&'a crate::inbound::InboundRuntime>,
    /// L2 能力句柄（nn8os 2b 装配期注入：按协议 kind 经
    /// [`arm_plugin_ctx`] 构造，handler 收编 spawn/log/audit 面）。
    pub(crate) plugin_ctx: PluginContext,
}

/// inbound 构造 future（async fn 匿名 future 无法作 fn 指针值，统一装箱；
/// 构造属启动路径非数据面热路径）。
pub(crate) type InboundBuildFut<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Option<JoinHandle<()>>>> + Send + 'a>>;

pub(crate) type InboundBuilder = for<'a> fn(InboundCtx<'a>) -> InboundBuildFut<'a>;

/// UDS 裸流 serve 构造上下文：UDS listener 与默认 handler 由
/// [`crate::inbound::spawn_unix_inbound`] 绑定/取出后传入，臂只组装 per-conn 栈。
///
/// 类型面刻意不引用平台专属类型（listener 走 `dyn SystemListener`）——UDS 臂因此
/// 与非 unix 平台同源编译；非 unix 平台永不调用（`spawn_unix_inbound` 有拒绝臂）。
pub(crate) struct UnixInboundCtx<'a> {
    pub(crate) ib: &'a BuiltInbound,
    pub(crate) policy: &'a Option<Arc<dyn xray_features::policy::PolicyManager>>,
    pub(crate) settings: &'a xray_transport::dialer::StreamSettings,
    /// UDS 路径（监听标识；per-instance 日志同源）。
    pub(crate) listen: &'a str,
    pub(crate) listener: Box<dyn xray_transport::system_listener::SystemListener>,
    pub(crate) handler: Arc<dyn DispatchHandler>,
    /// L2 能力句柄（与 TCP 臂同源，见 [`InboundCtx::plugin_ctx`]）；serve future
    /// 与 [`crate::inbound::spawn_inbound_serve`] 各持一份克隆。
    pub(crate) plugin_ctx: Arc<PluginContext>,
}

/// UDS accept 循环 future（与 `crate::inbound::serve_unix_listener` 同形）。
pub(crate) type UnixServe = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

pub(crate) type UnixInboundBuilder = for<'a> fn(UnixInboundCtx<'a>) -> std::io::Result<UnixServe>;

/// UDS 上 transport 协议的 per-conn 构造上下文（对应
/// `crate::inbound::spawn_unix_transport_inbound`）。
pub(crate) struct UnixTransportCtx<'a> {
    pub(crate) ib: &'a BuiltInbound,
    pub(crate) ohm: &'a Arc<SimpleOhm>,
    pub(crate) policy: &'a Option<Arc<dyn xray_features::policy::PolicyManager>>,
    pub(crate) settings: &'a xray_transport::dialer::StreamSettings,
    pub(crate) api: Option<&'a crate::inbound::InboundRuntime>,
    /// 监听标识：UDS 路径（TCP 侧同位置传 `addr:port`）。
    pub(crate) ident: &'a str,
}

pub(crate) type UnixTransportBuilder =
    for<'a> fn(
        UnixTransportCtx<'a>,
    ) -> std::io::Result<xray_transport::listener_registry::ConnHandler>;

/// 入站表条目：一个 `<方向>:<协议>` 条目承载该协议的**三种监听形态**构造器。
///
/// 单表是「协议 → 可构造形态」的唯一真源：TCP 主路径走 [`Self::stream`]，UDS 裸流
/// 走 [`Self::uds_stream`]，UDS transport 走 [`Self::uds_transport`]；槽为 `None`
/// 即该形态不支持，调用方显式失败（不再有第二份手写白名单或内联 match）。
#[derive(Clone, Copy)]
pub(crate) struct InboundCtor {
    /// TCP 地址监听的主构造器（平台门控的拒绝臂也在此槽，如 tun 非支持平台）。
    pub(crate) stream: InboundBuilder,
    /// 是否消费 listen 地址/端口；`false` = 自管监听面（tun：设备 + netstack），
    /// 入口跳过 sockopt 校验与 port/addr 解析。
    pub(crate) needs_listen_addr: bool,
    /// UDS 裸流 serve 栈（`None` = 该协议不支持 unix socket）。
    ///
    /// 非 unix 平台不读该槽（无 UDS 监听路径可走），槽位仍登记以保持表条目
    /// 平台无关——单表是「协议 → 形态」唯一真源，不按平台分叉。
    #[cfg_attr(
        not(unix),
        allow(
            dead_code,
            reason = "UDS 槽只在 unix 监听路径被读；非 unix 平台仍登记以维持单表结构"
        )
    )]
    pub(crate) uds_stream: Option<UnixInboundBuilder>,
    /// UDS 上 transport 协议的 per-conn 构造（`None` = 该协议无 transport 分支）。
    #[cfg_attr(not(unix), allow(dead_code, reason = "同上：UDS 槽只在 unix 监听路径被读"))]
    pub(crate) uds_transport: Option<UnixTransportBuilder>,
}

/// 纯 TCP 形态的表条目（无 UDS 形态、消费 listen 地址）。
pub(crate) const fn tcp(stream: InboundBuilder) -> InboundCtor {
    ctor(stream, true, None, None)
}

/// 表条目全字段构造（const：表是 `&'static` 纯数据源，零分配）。
pub(crate) const fn ctor(
    stream: InboundBuilder,
    needs_listen_addr: bool,
    uds_stream: Option<UnixInboundBuilder>,
    uds_transport: Option<UnixTransportBuilder>,
) -> InboundCtor {
    InboundCtor { stream, needs_listen_addr, uds_stream, uds_transport }
}

/// outbound 构造上下文：build_protocol_handler 臂前公共前解析产物 + 装配参数
/// 原样打包（各协议消费子集，未消费字段随 ctx 丢弃，与拆分前臂未消费局部一致）。
pub(crate) struct OutboundCtx<'a, 'b> {
    pub(crate) ob: &'a BuiltOutbound,
    pub(crate) loopback_sink: Option<Arc<dyn xray_proxy_loopback::LoopbackSink>>,
    pub(crate) mux_bridges: &'b mut Vec<(Arc<crate::outbound::MuxBridge>, Option<String>)>,
    pub(crate) dns: Option<&'a Arc<xray_app_dns::DnsService>>,
    pub(crate) inbound_default_rules:
        &'a std::collections::HashMap<String, xray_proxy_freedom::DefaultRuleType>,
    pub(crate) policy_manager: Option<&'a dyn xray_features::policy::PolicyManager>,
    pub(crate) proxy_chain_tag: Option<String>,
    pub(crate) target_strategy: Option<DomainStrategy>,
    pub(crate) send_through: Option<&'a xray_transport::system_dialer::SendThroughSpec>,
    /// L2 能力句柄（nn8os 2b 装配期注入，语义同 [`InboundCtx::plugin_ctx`]）。
    pub(crate) plugin_ctx: PluginContext,
}

/// 运行期协议 kind 串 → `'static` 键冻结（进程级 intern 表，一次写缓存）。
///
/// `PluginContext`/`LogFacade` 的域参数是 `'static` 契约（框架冻结面，根治 =
/// 签名改 `Arc<str>`，W1 §6 遗留决策点）；本表把动态 kind 串按**种类**去重
/// 冻结——上界 = 协议构造表条目数（~17），非实例数。禁喂 per-instance tag。
pub(crate) fn intern_protocol_kind(kind: &str) -> &'static str {
    static INTERN: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, &'static str>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut table = INTERN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frozen) = table.get(kind) {
        return frozen;
    }
    // 上界=协议表大小的一次性冻结（同 W1 feature_framework intern 表先例）。
    let frozen: &'static str = Box::leak(kind.to_string().into_boxed_str());
    table.insert(kind.to_string(), frozen);
    frozen
}

/// 臂构造的 L2 ctx 配方：协议 kind → 独立 [`PluginContext`]（自持 scope +
/// 系统钟 + 独享审计环；nn8os 2b）。scope 随收编 handler 的 drop 兜底 abort
/// （blackhole B6 生命周期等价）；未被消费的字段随臂丢弃（OutboundCtx 同语义）。
pub(crate) fn arm_plugin_ctx(kind: &str) -> PluginContext {
    PluginContext::for_plugin(intern_protocol_kind(kind))
}

#[allow(clippy::type_complexity)]
pub(crate) type OutboundResult = std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
>;

pub(crate) type OutboundBuilder = for<'a, 'b> fn(OutboundCtx<'a, 'b>) -> OutboundResult;

/// 入站构造器**数据源**（纯数据：只被 `crate::arm_registry` 的注册表构造消费；
/// 生产查表唯一路径 = `crate::arm_registry::lookup_inbound_builder`）。
///
/// 键 = `<方向>:<协议>`：方向前缀使入/出站同名协议不撞注册表重名，并为将来
/// 16 个协议 Plugin（键 = 裸协议名）并入同一注册表留出键空间。
///
/// 一条目 = 该协议的全部监听形态（TCP / UDS 裸流 / UDS transport，见
/// [`InboundCtor`]）——加协议即加一行，不存在第二张表或手写白名单。
pub(crate) static INBOUND_CTORS: &[(&str, InboundCtor)] = &[
    ("inbound:socks", ctor(inbound::socks_entry, true, Some(inbound::unix_socks_serve), None)),
    ("inbound:mixed", tcp(inbound::mixed_entry)),
    (
        "inbound:vless",
        ctor(
            inbound::vless_entry,
            true,
            Some(inbound::unix_vless_serve),
            Some(inbound::unix_vless_transport),
        ),
    ),
    (
        "inbound:trojan",
        ctor(
            inbound::trojan_entry,
            true,
            Some(inbound::unix_trojan_serve),
            Some(inbound::unix_trojan_transport),
        ),
    ),
    (
        "inbound:vmess",
        ctor(
            inbound::vmess_entry,
            true,
            Some(inbound::unix_vmess_serve),
            Some(inbound::unix_vmess_transport),
        ),
    ),
    ("inbound:http", tcp(inbound::http_entry)),
    // Go 注册名是 `dokodemo-door`（infra/conf/dokodemo.go + proxy/dokodemo 的
    // ProtocolName），配置按 Go 文档写 `dokodemo-door`——只留 `dokodemo` 键会
    // 使整条入站落到「未支持协议」被静默跳过；两个键都收。
    ("inbound:dokodemo-door", tcp(inbound::dokodemo_entry)),
    ("inbound:dokodemo", tcp(inbound::dokodemo_entry)),
    (
        "inbound:shadowsocks",
        ctor(
            inbound::shadowsocks_entry,
            true,
            Some(inbound::unix_shadowsocks_serve),
            Some(inbound::unix_shadowsocks_transport),
        ),
    ),
    // 原 match 臂为 `"hysteria" | "hysteria2"` 双键——数据源同样双键指向同一适配器，
    // 否则 hysteria2 配置会漏查落到「未支持协议」分支。
    ("inbound:hysteria", tcp(inbound::hysteria_entry)),
    ("inbound:hysteria2", tcp(inbound::hysteria_entry)),
    ("inbound:anytls", tcp(inbound::anytls_entry)),
    ("inbound:tuic", tcp(inbound::tuic_entry)),
    ("inbound:naive", tcp(inbound::naive_entry)),
    ("inbound:wireguard", tcp(inbound::wireguard_entry)),
    ("inbound:dns", tcp(inbound::dns_entry)),
    ("inbound:loopback", tcp(inbound::loopback_entry)),
    ("inbound:blackhole", tcp(inbound::blackhole_entry)),
    ("inbound:freedom", tcp(inbound::freedom_entry)),
    // tun 恒有键：入口见 `needs_listen_addr == false` 即跳过 sockopt 校验与
    // port/addr 解析直接分派；非支持平台的值是拒绝臂（错误变体/文案与删除前
    // cfg(not) 臂逐字一致），与 outbound:tun 同款形态。
    ("inbound:tun", ctor(inbound::tun_entry, false, None, None)),
];

/// 出站构造器**数据源**（纯数据；键格式同 `INBOUND_CTORS`）。
pub(crate) static OUTBOUND_CTORS: &[(&str, OutboundBuilder)] = &[
    ("outbound:freedom", outbound::freedom_entry),
    ("outbound:vless", outbound::vless_entry),
    ("outbound:trojan", outbound::trojan_entry),
    ("outbound:blackhole", outbound::blackhole_entry),
    ("outbound:socks", outbound::socks_entry),
    ("outbound:mux", outbound::mux_entry),
    ("outbound:vmess", outbound::vmess_entry),
    ("outbound:shadowsocks", outbound::shadowsocks_entry),
    ("outbound:hysteria", outbound::hysteria_entry),
    ("outbound:anytls", outbound::anytls_entry),
    ("outbound:tuic", outbound::tuic_entry),
    ("outbound:wireguard", outbound::wireguard_entry),
    ("outbound:dns", outbound::dns_entry),
    ("outbound:loopback", outbound::loopback_entry),
    ("outbound:http", outbound::http_entry),
    ("outbound:naive", outbound::naive_entry),
    ("outbound:dokodemo", outbound::dokodemo_entry),
    // tun 恒有键：非 linux 平台的值是拒绝臂（错误变体/文案与删除前 cfg(not) 臂
    // 逐字一致），与 linux 的构造臂同样经表分派。
    ("outbound:tun", outbound::tun_entry),
];

#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod uds_tests;
