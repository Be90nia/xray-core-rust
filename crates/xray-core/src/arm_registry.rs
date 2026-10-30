//! 生产装配主路的构造器注册表（W1 切片 1a：arm 构造表并入 xray-frame PluginRegistry）。
//!
//! 机制：37 个 arm 构造器（入站 19 键 + 出站 18 键）以**类型擦除载荷**挂在
//! [`Plugin`] 实例上注册进 [`PluginRegistry`]；生产查表唯一路径 =
//! [`lookup_inbound_builder`] / [`lookup_outbound_builder`]（`registry.get(<方向>:<协议>)`
//! → 载荷下转 → 构造 fn → 调用）。
//!
//! 命名空间：注册表键 = `<方向>:<协议>`（如 `inbound:vless` / `outbound:vless`）。
//! 方向前缀使同名协议的入/出站条目不撞 `Duplicate`，并为将来 16 个协议 Plugin
//! （键 = 裸协议名）并入同一注册表留位——两类载荷共存不撞名。
//!
//! deps/contract/lifecycle 真值（**不造假语义**）：arm 条目是**构造器索引**，
//! 不是协议实现——
//! - `deps()` = 空：构造输入全部经 arm ctx 显式传入（`InboundCtx`/`OutboundCtx`），
//!   构造期无协议间先后依赖（mux 的底层 outbound、loopback 的 sink 均为运行期注入）；
//! - `contract()` = 12 条协议运行时条款**全部 N/A**（理由：真源在协议 crate 的 Plugin 契约，见
//!   `xray-proxy-*/src/plugin.rs`；本条目不承载协议语义）， `extra` 标注条目种类与键格式；
//! - `lifecycle()` = 三相直通：本条目不持有运行期资源（产物生命周期归
//!   `Instance`/dispatcher）；`build()` 不做配置解析（配置面归既有解析面，见 `xray-conf` 旧解析面 ↔
//!   `xray-frame` per-plugin 段路由两面对拍 `tests_config_parity.rs`）。
//!
//! 门：注册期容量 fail-closed（cap 64）+ 重名拒；启动期 `start_order()` 走一遍
//! deps 门（缺依赖/成环 → `Err`，启动前 fail-visible）。

use std::{
    any::Any,
    sync::{Arc, LazyLock},
};

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
    PluginRegistry,
};

use crate::arm_builders::{INBOUND_CTORS, InboundBuilder, OUTBOUND_CTORS, OutboundBuilder};

/// 入站方向前缀（注册表键 = `<前缀><协议>`）。
const INBOUND_PREFIX: &str = "inbound:";
/// 出站方向前缀。
const OUTBOUND_PREFIX: &str = "outbound:";

/// 注册表容量上界（fail-closed）：当前 37 条（入站 19 + 出站 18），留余量给
/// 将来并入的 16 个协议 Plugin 条目。
const REGISTRY_CAP: usize = 64;

/// 构造器载荷：入站/出站两种 HRTB fn 指针。
///
/// `'static` 成立：fn 指针的 `'a` 由 `for<'a>` 绑定（类型内无自由生命周期），
/// 故本枚举满足 `Any` 约束，可经 `downcast_ref` 还原为具体构造 fn。
#[derive(Clone, Copy)]
enum ArmCtor {
    /// 入站协议臂构造器（`fn(InboundCtx) -> InboundBuildFut`）。
    Inbound(InboundBuilder),
    /// 出站协议臂构造器（`fn(OutboundCtx) -> OutboundResult`）。
    Outbound(OutboundBuilder),
}

/// arm 条目的通用条款声明：12 条协议运行时条款**全部不适用**（真源在协议 crate
/// 的 Plugin 契约），逐条给出理由（L4 夹具要求 N/A 理由非空）。
static ARM_CTOR_CONTRACT: PluginContract = PluginContract {
    clauses: &[],
    extra: &[("kind", "arm-constructor"), ("registry_key", "<方向>:<协议>")],
    not_applicable: &[
        (
            ClauseId::AuthErrorClassified,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::HandshakeDeadline,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::ConnIdPresent,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::PoolDiscipline,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::SpawnManaged,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::StopRegistered,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::ConfigSectionOnly,
            "配置面归既有解析面（xray-conf 旧解析面 ↔ xray-frame per-plugin 段路由，tests_config_parity.rs 对拍）；本条目不读配置段",
        ),
        (
            ClauseId::ErrorClassifiedNoPanicEscape,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::BoundedResources,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::LogDiscipline,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::SecretMasking,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
        (
            ClauseId::HotPathFreeze,
            "协议运行时条款真源在协议 crate 的 Plugin 契约（xray-proxy-*/src/plugin.rs）；本条目是生产装配的构造器索引，不承载协议语义",
        ),
    ],
};

/// 生命周期三相直通：arm 条目不持有运行期资源（产物 handler 的生命周期归
/// `Instance`/dispatcher），三相皆无操作。
struct NoopLifecycle;

impl Lifecycle for NoopLifecycle {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

/// arm 构造器注册条目：名字 = 注册表键（方向前缀），载荷 = 构造 fn。
struct ArmEntry {
    /// 注册表键（`<方向>:<协议>`）。
    name: &'static str,
    /// 构造器载荷（类型擦除下转回 `ArmCtor`）。
    ctor: ArmCtor,
}

impl Plugin for ArmEntry {
    fn name(&self) -> &'static str {
        self.name
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &ARM_CTOR_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &NoopLifecycle
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        // 无装配期产物：构造发生在运行期（按配置条目调用载荷里的 fn）。
        Ok(())
    }

    fn payload(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(&self.ctor)
    }
}

/// 生产构造器注册表（唯一构造路径的权威表）。
static ARM_REGISTRY: LazyLock<PluginRegistry> = LazyLock::new(build_arm_registry);

/// 注册 37 个 arm 构造条目（数据源 = `arm_builders` 的构造器表）并走一遍 deps 门。
fn build_arm_registry() -> PluginRegistry {
    let mut reg = PluginRegistry::new(REGISTRY_CAP).expect("arm registry cap > 0");
    for (name, builder) in INBOUND_CTORS {
        reg.register(Arc::new(ArmEntry { name, ctor: ArmCtor::Inbound(*builder) }))
            .expect("arm registry: 入站键唯一（方向前缀）");
    }
    for (name, builder) in OUTBOUND_CTORS {
        reg.register(Arc::new(ArmEntry { name, ctor: ArmCtor::Outbound(*builder) }))
            .expect("arm registry: 出站键唯一（方向前缀）");
    }
    // deps 门：生产路径走一遍拓扑排序（缺依赖/成环 → Err，启动前 fail-visible）。
    reg.start_order().expect("arm registry: deps 门（当前无 deps 声明）");
    reg
}

/// 查表键 = `<方向前缀><协议名>`（栈上拼装，零堆分配；超长 → 未命中）。
fn with_key<R>(prefix: &str, protocol: &str, f: impl FnOnce(&str) -> Option<R>) -> Option<R> {
    let mut buf = [0u8; 64];
    let p = prefix.as_bytes();
    let n = protocol.as_bytes();
    if p.len() + n.len() > buf.len() {
        return None;
    }
    buf[..p.len()].copy_from_slice(p);
    buf[p.len()..p.len() + n.len()].copy_from_slice(n);
    let key = std::str::from_utf8(&buf[..p.len() + n.len()]).ok()?;
    f(key)
}

/// 经注册表取构造器（唯一查表路径）。
fn lookup_ctor(prefix: &str, protocol: &str) -> Option<ArmCtor> {
    with_key(prefix, protocol, |key| {
        let plugin = ARM_REGISTRY.get(key)?;
        let payload = plugin.payload()?;
        let ctor = payload.downcast_ref::<ArmCtor>()?;
        Some(*ctor)
    })
}

/// 入站构造器查表（未命中 = 未支持协议，入口显式 warn+skip）。
pub(crate) fn lookup_inbound_builder(protocol: &str) -> Option<InboundBuilder> {
    match lookup_ctor(INBOUND_PREFIX, protocol)? {
        ArmCtor::Inbound(builder) => Some(builder),
        ArmCtor::Outbound(_) => None,
    }
}

/// 出站构造器查表（未命中 = 未支持协议，入口显式 `Unsupported` 错误）。
pub(crate) fn lookup_outbound_builder(protocol: &str) -> Option<OutboundBuilder> {
    match lookup_ctor(OUTBOUND_PREFIX, protocol)? {
        ArmCtor::Outbound(builder) => Some(builder),
        ArmCtor::Inbound(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;
    use tokio_util::sync::CancellationToken;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};

    use super::*;
    use crate::{
        arm_builders::{
            InboundCtx, OutboundResult, inbound as in_entries, outbound as out_entries,
        },
        inbound::spawn_one_inbound,
        outbound::build_protocol_handler,
    };

    /// 17 个出站协议的最小可构造 settings（与 `arm_builders::tests` 同源形态）。
    /// 第二项 = streamSettings（hysteria 构造期硬错要求 security=tls）。
    fn outbound_settings() -> Vec<(&'static str, serde_json::Value, Option<serde_json::Value>)> {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        vec![
            ("freedom", json!({}), None),
            (
                "vless",
                json!({"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":uuid,"encryption":"none"}]}]}),
                None,
            ),
            ("trojan", json!({"servers":[{"address":"1.2.3.4","port":443,"password":"pw"}]}), None),
            ("blackhole", json!({}), None),
            ("socks", json!({"servers":[{"address":"1.2.3.4","port":1080}]}), None),
            ("mux", json!({"concurrency": 8}), None),
            (
                "vmess",
                json!({"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":uuid}]}]}),
                None,
            ),
            (
                "shadowsocks",
                json!({"servers":[{"address":"1.2.3.4","port":8388,"method":"aes-128-gcm","password":"pw"}]}),
                None,
            ),
            (
                "hysteria",
                json!({"address":"1.2.3.4","port":443,"auth":"pw"}),
                Some(json!({"security":"tls"})),
            ),
            ("anytls", json!({"server":"1.2.3.4","server_port":443,"password":"pw"}), None),
            (
                "tuic",
                json!({"servers":[{"address":"1.2.3.4","port":443,"uuid":uuid,"password":"pw"}]}),
                None,
            ),
            ("wireguard", json!({"secretKey": "aa".repeat(32), "peers": []}), None),
            ("dns", json!({"servers":["8.8.8.8:53"]}), None),
            ("loopback", json!({"inboundTag": "in-main"}), None),
            ("http", json!({"servers":[{"address":"1.2.3.4","port":8080}]}), None),
            ("naive", json!({"server":"1.2.3.4","port":443,"username":"u","password":"p"}), None),
            ("dokodemo", json!({"address":"1.2.3.4","port":443}), None),
        ]
    }

    /// 三个配置变体：最小可用 / 最小可用+无关键 / 畸形 settings。
    fn config_variants(base: &serde_json::Value) -> Vec<serde_json::Value> {
        let mut extra = base.clone();
        if let Some(obj) = extra.as_object_mut() {
            obj.insert("x-probe".to_string(), json!(1));
        }
        vec![base.clone(), extra, json!([])]
    }

    fn ob_of(
        protocol: &str,
        settings: &serde_json::Value,
        stream: Option<&serde_json::Value>,
    ) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry {
                kind: protocol.to_string(),
                data: serde_json::to_vec(settings).expect("settings serialize"),
            },
            tag: "t-arm-registry".to_string(),
            send_through: None,
            stream_settings_json: stream.cloned(),
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    /// 硬编码的独立期望映射（不随数据源改动而变）——对拍第三路（防"两路一起错"）。
    fn expected_inbound(protocol: &str) -> Option<InboundBuilder> {
        Some(match protocol {
            "socks" => in_entries::socks_entry,
            "mixed" => in_entries::mixed_entry,
            "vless" => in_entries::vless_entry,
            "trojan" => in_entries::trojan_entry,
            "vmess" => in_entries::vmess_entry,
            "http" => in_entries::http_entry,
            "dokodemo" | "dokodemo-door" => in_entries::dokodemo_entry,
            "shadowsocks" => in_entries::shadowsocks_entry,
            "hysteria" | "hysteria2" => in_entries::hysteria_entry,
            "anytls" => in_entries::anytls_entry,
            "tuic" => in_entries::tuic_entry,
            "naive" => in_entries::naive_entry,
            "wireguard" => in_entries::wireguard_entry,
            "dns" => in_entries::dns_entry,
            "loopback" => in_entries::loopback_entry,
            "blackhole" => in_entries::blackhole_entry,
            "freedom" => in_entries::freedom_entry,
            _ => return None,
        })
    }

    fn expected_outbound(protocol: &str) -> Option<OutboundBuilder> {
        Some(match protocol {
            "freedom" => out_entries::freedom_entry,
            "vless" => out_entries::vless_entry,
            "trojan" => out_entries::trojan_entry,
            "blackhole" => out_entries::blackhole_entry,
            "socks" => out_entries::socks_entry,
            "mux" => out_entries::mux_entry,
            "vmess" => out_entries::vmess_entry,
            "shadowsocks" => out_entries::shadowsocks_entry,
            "hysteria" => out_entries::hysteria_entry,
            "anytls" => out_entries::anytls_entry,
            "tuic" => out_entries::tuic_entry,
            "wireguard" => out_entries::wireguard_entry,
            "dns" => out_entries::dns_entry,
            "loopback" => out_entries::loopback_entry,
            "http" => out_entries::http_entry,
            "naive" => out_entries::naive_entry,
            "dokodemo" => out_entries::dokodemo_entry,
            "tun" => out_entries::tun_entry,
            _ => return None,
        })
    }

    /// 注册表键空间自检：37 条、方向前缀唯一、无裸协议名（为 16 个协议 Plugin 留位）。
    #[test]
    fn registry_keyspace_is_direction_prefixed_and_unique() {
        assert_eq!(ARM_REGISTRY.len(), INBOUND_CTORS.len() + OUTBOUND_CTORS.len());
        let mut seen = std::collections::HashSet::new();
        for name in
            INBOUND_CTORS.iter().map(|(n, _)| *n).chain(OUTBOUND_CTORS.iter().map(|(n, _)| *n))
        {
            assert!(seen.insert(name), "注册表键重复：{name}");
            assert!(
                name.starts_with(INBOUND_PREFIX) || name.starts_with(OUTBOUND_PREFIX),
                "键缺方向前缀：{name}"
            );
        }
        // 裸协议名不得占用（协议 Plugin 的键空间）。
        assert!(ARM_REGISTRY.get("vless").is_none(), "裸协议名须留给协议 Plugin");
    }

    /// 双写对照（硬门）：新路径（经注册表查表）vs 旧路径（数据源直查）vs 独立期望
    /// 映射，三路 fn 指针逐键一致；出站再逐字段比构造产物。
    ///
    /// 报告口径：`配置变体数 × 协议数`，差异数必须为 0。
    #[tokio::test]
    async fn dual_write_diff_rate_is_zero() {
        let empty_rules: HashMap<String, xray_proxy_freedom::DefaultRuleType> = HashMap::new();
        let mut diffs = 0usize;
        let mut comparisons = 0usize;
        let mut protocol_count = 0usize;

        // ── 入站：fn 指针三路一致（构造产物对照见 loopback 一路）──
        for (name, _) in INBOUND_CTORS {
            let protocol = name.strip_prefix(INBOUND_PREFIX).expect("入站键带前缀");
            protocol_count += 1;
            let new = lookup_inbound_builder(protocol);
            let old = INBOUND_CTORS.iter().find(|(n, _)| *n == *name).map(|(_, b)| *b);
            let expected = expected_inbound(protocol);
            comparisons += 1;
            let a = new.map(|f| f as usize);
            let b = old.map(|f| f as usize);
            let c = expected.map(|f| f as usize);
            if a != b || a != c {
                diffs += 1;
                println!(
                    "[dual-write] inbound:{protocol} fn 指针不一致 new={a:?} old={b:?} exp={c:?}"
                );
            }
        }

        // ── 出站：fn 指针三路一致 + 逐字段构造产物对拍 ──
        for (protocol, base, stream) in outbound_settings() {
            protocol_count += 1;
            let new = lookup_outbound_builder(protocol);
            let old = OUTBOUND_CTORS
                .iter()
                .find(|(n, _)| n.strip_prefix(OUTBOUND_PREFIX) == Some(protocol))
                .map(|(_, b)| *b);
            let expected = expected_outbound(protocol);
            comparisons += 1;
            let a = new.map(|f| f as usize);
            let b = old.map(|f| f as usize);
            let c = expected.map(|f| f as usize);
            if a != b || a != c {
                diffs += 1;
                println!(
                    "[dual-write] outbound:{protocol} fn 指针不一致 new={a:?} old={b:?} exp={c:?}"
                );
            }
            // 逐字段：同配置下两路构造产物（handler tag / proxy_chain / mux 注册数 / 错误变体）。
            for (variant, settings) in config_variants(&base).into_iter().enumerate() {
                comparisons += 1;
                let ob = ob_of(protocol, &settings, stream.as_ref());
                let mut new_bridges = Vec::new();
                let new_result =
                    build_protocol_handler(&ob, None, &mut new_bridges, None, &empty_rules, None);
                let Some(old_builder) = old else { continue };
                let mut old_bridges = Vec::new();
                let old_result = old_builder(crate::arm_builders::OutboundCtx {
                    ob: &ob,
                    loopback_sink: None,
                    mux_bridges: &mut old_bridges,
                    dns: None,
                    inbound_default_rules: &empty_rules,
                    policy_manager: None,
                    proxy_chain_tag: None,
                    target_strategy: None,
                    send_through: None,
                    plugin_ctx: xray_frame::PluginContext::for_plugin(
                        crate::arm_builders::intern_protocol_kind(protocol),
                    ),
                });
                let new_view = view_of(&new_result, new_bridges.len());
                let old_view = view_of(&old_result, old_bridges.len());
                if new_view != old_view {
                    diffs += 1;
                    println!(
                        "[dual-write] outbound:{protocol} v{variant} 产物不一致 new={new_view:?} old={old_view:?}"
                    );
                }
            }
        }

        println!(
            "[dual-write] 配置变体 3 × 协议 {protocol_count} → 比较 {comparisons} 次，差异 {diffs} 处"
        );
        assert_eq!(diffs, 0, "双写对照差异必须为 0");
        assert!(protocol_count >= 34, "协议数覆盖不足：{protocol_count}");
    }

    /// 构造产物的可观测投影（`Arc<dyn DispatchHandler>` 表面无 Any 下转口 → 用
    /// 可观测代理属性：tag 回显 / proxy_chain / mux 注册数 / 错误变体）。
    fn view_of(result: &OutboundResult, bridges: usize) -> String {
        match result {
            Ok((handler, _bridge, proxy_chain)) => {
                format!("ok tag={} chain={proxy_chain:?} bridges={bridges}", handler.tag())
            },
            Err(err) => format!("err {err:?}"),
        }
    }

    /// 入站 e2e 对照：loopback（唯一无 bind 副作用的臂）新旧两路都 `Ok(None)`。
    #[tokio::test]
    async fn inbound_loopback_dual_write_matches() {
        let ib = BuiltInbound {
            entry: BuiltEntry {
                kind: "loopback".to_string(),
                data: serde_json::to_vec(&json!({"inboundTag": "in-main"})).expect("settings"),
            },
            tag: "t-arm-registry-in".to_string(),
            port: Some(1),
            listen: Some("127.0.0.1".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        let token = CancellationToken::new();
        let r1 = spawn_one_inbound(&ib, Arc::new(SimpleOhm::new()), None, token.clone(), None)
            .await
            .expect("entry spawn");
        let entry = lookup_inbound_builder("loopback").expect("loopback 必须在注册表内");
        let settings = xray_transport::dialer::StreamSettings::from_json(None);
        let r2 = entry(InboundCtx {
            ib: &ib,
            ohm: Arc::new(SimpleOhm::new()),
            policy: None,
            shutdown_token: token,
            addr: "127.0.0.1:1",
            settings: &settings,
            api: None,
            plugin_ctx: xray_frame::PluginContext::for_plugin("loopback"),
        })
        .await
        .expect("registry path spawn");
        assert!(r1.is_none() && r2.is_none(), "loopback 两路都须 Ok(None)");
    }

    /// 未命中协议：注册表查表返回 None（入口显式 warn+skip / Unsupported，绝不静默构造）。
    #[test]
    fn unknown_protocol_is_absent() {
        assert!(lookup_inbound_builder("no-such-protocol").is_none());
        assert!(lookup_outbound_builder("no-such-protocol").is_none());
        // tun 入站在入口内联处理（平台专用），不经表分派 → 注册表内刻意无键。
        assert!(lookup_inbound_builder("tun").is_none());
    }

    /// L5 门自查（装配期 fail-visible）：缺 deps / 成环 / 缺配置段三情形。
    #[test]
    fn l5_gates_fail_visible_at_assembly() {
        // ① 缺依赖 → MissingDep
        struct DepPlugin;
        static DEPS: [PluginDep; 1] = [PluginDep { name: "dep-b" }];
        impl Plugin for DepPlugin {
            fn name(&self) -> &'static str {
                "dep-a"
            }

            fn version(&self) -> &'static str {
                "0.1.0"
            }

            fn deps(&self) -> &'static [PluginDep] {
                &DEPS
            }

            fn contract(&self) -> &PluginContract {
                &ARM_CTOR_CONTRACT
            }

            fn lifecycle(&self) -> &dyn Lifecycle {
                &NoopLifecycle
            }

            fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        let mut reg = PluginRegistry::new(8).expect("cap ok");
        reg.register(Arc::new(DepPlugin)).expect("register");
        assert!(
            matches!(reg.start_order(), Err(PluginError::MissingDep { .. })),
            "缺依赖必须在装配期 Err"
        );

        // ② 成环 → CyclicDep
        struct CyclePlugin(&'static str, &'static [PluginDep]);
        static CYCLE_A: [PluginDep; 1] = [PluginDep { name: "cycle-b" }];
        static CYCLE_B: [PluginDep; 1] = [PluginDep { name: "cycle-a" }];
        impl Plugin for CyclePlugin {
            fn name(&self) -> &'static str {
                self.0
            }

            fn version(&self) -> &'static str {
                "0.1.0"
            }

            fn deps(&self) -> &'static [PluginDep] {
                self.1
            }

            fn contract(&self) -> &PluginContract {
                &ARM_CTOR_CONTRACT
            }

            fn lifecycle(&self) -> &dyn Lifecycle {
                &NoopLifecycle
            }

            fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        let mut reg = PluginRegistry::new(8).expect("cap ok");
        reg.register(Arc::new(CyclePlugin("cycle-a", &CYCLE_A))).expect("register");
        reg.register(Arc::new(CyclePlugin("cycle-b", &CYCLE_B))).expect("register");
        assert!(
            matches!(reg.start_order(), Err(PluginError::CyclicDep { .. })),
            "成环必须在装配期 Err"
        );

        // ③ 缺配置段 → Err（framework per-plugin 段路由，xray-frame 既有机制；
        //    ConfigError 未从 xray-frame 公开重导出 → 按错误文案断言）。
        let missing = xray_frame::PluginConfig::section("no-such-protocol", &json!({}))
            .expect_err("缺段必须 Err");
        assert!(missing.to_string().contains("section missing"), "缺配置段必须 Missing：{missing}");
    }
}
