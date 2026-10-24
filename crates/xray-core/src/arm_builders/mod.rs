//! 协议臂构造函数（T4.2 五阶段法 phase 1 抽臂 + phase 2 构造侧查表）。
//!
//! phase 1：`crate::inbound::spawn_one_inbound` 与 `crate::outbound::build_protocol_handler`
//! 的 match 协议臂构造逻辑原样搬迁至此，臂内只留一行调用。入参/出参类型、错误
//! 变体、日志文案、注册顺序、失败语义与拆分前逐字段一致（行为零变化）。
//!
//! phase 2：本模块持有**构造表** `(协议名, 方向) → builder fn`。表本体始终编译
//! （等价性测试在默认构建即可运行）；feature `arm-lookup`（默认关）只门控
//! 构造入口的**切换点**——开 = 入口先查表，未命中/关闭走原 match。表值适配器
//! 只做参数解包，转发到 phase 1 同一构造函数，两路到达同一实现。
//!
//! ## 表实现选型：BTreeMap + 显式注册（不用 xray-frame PluginRegistry）
//!
//! `PluginRegistry` 值类型为 `Arc<dyn Plugin>`（name/version/deps/contract/
//! lifecycle/build 强约束五件套，面向 P2 插件装配编排：容量 fail-closed、
//! start_order 逆序停机、bring_up 生命周期迁移）。构造表的值是裸 `fn` 指针，
//! 注册发生在静态 init 一次性完成——用 PluginRegistry 须为 34 个 fn 伪造全套
//! Plugin 语义，零增益纯形态税；机制与内容分离，机制（注册表模式）留待
//! P2 装配面用框架件，本表属内容面。键选 `BTreeMap`：静态表无并发写，
//! 确定性迭代序便于等价性测试枚举。

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock},
};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, SimpleOhm},
};
use xray_conf::{BuiltInbound, BuiltOutbound};
use xray_proxy_freedom::DomainStrategy;

use crate::outbound::BuildError;

// 适配器模块级 dead_code 豁免：适配器仅表与 cfg(test) 等价性测试消费
// （理由同查表形态节；phase 1 构造函数有生产调用方，allow 对其惰性）。
#[allow(dead_code)]
pub(crate) mod inbound;
#[allow(dead_code)]
pub(crate) mod outbound;

// ============ 查表形态（T4.2 phase 2） ============
//
// dead_code 豁免纪律（lib.rs deny(warnings)：显式 allow + 理由）：下列表装置
// 仅 feature `arm-lookup` 切换点与 cfg(test) 等价性测试消费，默认 lib 构建
// 无生产调用方；表须随默认构建编译，等价性测试才能在两 feature 态下运行
// （任务书：默认走 match，不删臂不改默认）。

/// inbound 构造上下文：spawn_one_inbound 前置逻辑（tun 早退/sockopt 硬错/unix
/// 分派/port 解析/addr+settings 派生）产物按原样打包，表路径与 match 路径消费
/// 同一前置换算结果。
#[allow(dead_code)] // 见上：默认态仅 cfg(test) 消费
pub(crate) struct InboundCtx<'a> {
    pub(crate) ib: &'a BuiltInbound,
    pub(crate) ohm: Arc<SimpleOhm>,
    pub(crate) policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    pub(crate) shutdown_token: CancellationToken,
    pub(crate) addr: &'a str,
    pub(crate) settings: &'a xray_transport::dialer::StreamSettings,
    pub(crate) api: Option<&'a crate::inbound::InboundRuntime>,
}

/// inbound 构造 future（async fn 匿名 future 无法作 fn 指针值，统一装箱；
/// 构造属启动路径非数据面热路径）。
#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免，理由见查表形态节）
pub(crate) type InboundBuildFut<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Option<JoinHandle<()>>>> + Send + 'a>>;

#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
pub(crate) type InboundBuilder = for<'a> fn(InboundCtx<'a>) -> InboundBuildFut<'a>;

/// outbound 构造上下文：build_protocol_handler 臂前公共前解析产物 + 装配参数
/// 原样打包（各协议消费子集，未消费字段随 ctx 丢弃，与 match 臂未消费局部一致）。
#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
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
}

#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
#[allow(clippy::type_complexity)]
pub(crate) type OutboundResult = std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
>;

#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
pub(crate) type OutboundBuilder = for<'a, 'b> fn(OutboundCtx<'a, 'b>) -> OutboundResult;

#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
static INBOUND_TABLE: LazyLock<BTreeMap<&'static str, InboundBuilder>> = LazyLock::new(|| {
    let mut m: BTreeMap<&'static str, InboundBuilder> = BTreeMap::new();
    m.insert("socks", inbound::socks_entry);
    m.insert("mixed", inbound::mixed_entry);
    m.insert("vless", inbound::vless_entry);
    m.insert("trojan", inbound::trojan_entry);
    m.insert("vmess", inbound::vmess_entry);
    m.insert("http", inbound::http_entry);
    m.insert("dokodemo", inbound::dokodemo_entry);
    m.insert("shadowsocks", inbound::shadowsocks_entry);
    // match 臂为 `"hysteria" | "hysteria2"` 双键——表同样双键指向同一适配器，
    // 否则 feature 开启时 hysteria2 配置会漏查回落 wildcard。
    m.insert("hysteria", inbound::hysteria_entry);
    m.insert("hysteria2", inbound::hysteria_entry);
    m.insert("anytls", inbound::anytls_entry);
    m.insert("tuic", inbound::tuic_entry);
    m.insert("naive", inbound::naive_entry);
    m.insert("wireguard", inbound::wireguard_entry);
    m.insert("dns", inbound::dns_entry);
    m.insert("loopback", inbound::loopback_entry);
    m.insert("blackhole", inbound::blackhole_entry);
    m.insert("freedom", inbound::freedom_entry);
    m
});

#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
static OUTBOUND_TABLE: LazyLock<BTreeMap<&'static str, OutboundBuilder>> = LazyLock::new(|| {
    let mut m: BTreeMap<&'static str, OutboundBuilder> = BTreeMap::new();
    m.insert("freedom", outbound::freedom_entry);
    m.insert("vless", outbound::vless_entry);
    m.insert("trojan", outbound::trojan_entry);
    m.insert("blackhole", outbound::blackhole_entry);
    m.insert("socks", outbound::socks_entry);
    m.insert("mux", outbound::mux_entry);
    m.insert("vmess", outbound::vmess_entry);
    m.insert("shadowsocks", outbound::shadowsocks_entry);
    m.insert("hysteria", outbound::hysteria_entry);
    m.insert("anytls", outbound::anytls_entry);
    m.insert("tuic", outbound::tuic_entry);
    m.insert("wireguard", outbound::wireguard_entry);
    m.insert("dns", outbound::dns_entry);
    m.insert("loopback", outbound::loopback_entry);
    m.insert("http", outbound::http_entry);
    m.insert("naive", outbound::naive_entry);
    m.insert("dokodemo", outbound::dokodemo_entry);
    // tun 与 match 臂同 cfg 门控：非 linux 平台表内同样无键（两侧对称缺席）。
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    m.insert("tun", outbound::tun_entry);
    m
});

/// inbound 构造入口查表（feature `arm-lookup` 切换点消费；表常编译供等价性测试）。
#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
pub(crate) fn lookup_inbound_builder(protocol: &str) -> Option<InboundBuilder> {
    INBOUND_TABLE.get(protocol).copied()
}

/// outbound 构造入口查表（feature `arm-lookup` 切换点消费；表常编译供等价性测试）。
#[allow(dead_code)] // 默认态仅 cfg(test) 消费（表装置豁免）
pub(crate) fn lookup_outbound_builder(protocol: &str) -> Option<OutboundBuilder> {
    OUTBOUND_TABLE.get(protocol).copied()
}

#[cfg(test)]
mod tests;
