//! Dns 协议插件（P2 批次 D，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`DnsPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(DnsPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 规则非法（未知 action / rCode 越界 / geosite 资产缺失）→ build `Err` →
//!   整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`handler.rs`（含 :234-236 TCP 长度前缀 u16 显式 Err 样板）、
//! `inbound.rs`、`outbound.rs` 逐行不动；插件只负责配置注入与构建（构建接缝 =
//! [`Handler::init`] / [`DnsInbound::new`] 既有构造器）。
//!
//! DNS-ANTILOOP 语义锚（条款 extra；运行时半边不在本 crate）：fakedns 与真实
//! DNS 回环防护（ownLink 判定，Go dns.go:242-247）在 xray-core
//! `DnsDispatchBridge` 与 xray-app-dns，本 crate 零实现零触碰。
//!
//! udf 判定（A7，非通用件）：DNS 规则编译（geodata 展开）+ Go 方言配置解析
//! 是 Xray 语义方向件——按 CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，
//! 留主仓最近消费方；无提炼候选。

use std::{sync::OnceLock, time::Duration};

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{config::Config, handler::Handler, inbound::DnsInbound, outbound::DnsOutbound};

/// 通用条款适用子集（差异表 §2.2 第 16 行 + PM 拍板 2026-10-24：3,4,5,6,7,8,9,10,12；
/// 1/2/11 走 [`DNS_NOT_APPLICABLE`]——DNS 无认证面、无会话握手、无密钥）。
static DNS_CLAUSES: &[ClauseId] = &[
    ClauseId::ConnIdPresent,
    ClauseId::PoolDiscipline,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::HotPathFreeze,
];

/// 协议专属条款（差异表 §2.2 第 16 行：u16 显式 Err 样板冻结 + 回环防护不变）。
static DNS_EXTRA: &[(&str, &str)] = &[
    ("DNS-U16", "TCP DNS 长度前缀 u16 超限必须 Err（样板 handler.rs:234-236），禁改回截断"),
    ("DNS-ANTILOOP", "fakedns 与真实 DNS 回环防护语义不变"),
];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由；条款 1 为
/// PM 拍板 2026-10-24 补齐，同 freedom 先例）。
static DNS_NOT_APPLICABLE: &[(ClauseId, &str)] = &[
    (ClauseId::AuthErrorClassified, "DNS 无凭证/无认证协商"),
    (
        ClauseId::HandshakeDeadline,
        "DNS 无会话握手：UDP 单包查询、TCP 2B 长度帧直读，无协商轮次与首包 deadline 面",
    ),
    (ClauseId::SecretMasking, "DNS 无密钥材料（无认证凭据/无 TLS 私钥），无掩码面"),
];

static DNS_CONTRACT: PluginContract =
    PluginContract { clauses: DNS_CLAUSES, extra: DNS_EXTRA, not_applicable: DNS_NOT_APPLICABLE };

static DNS_LIFECYCLE: DnsLifecycle = DnsLifecycle;

/// Dns 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]` 内 `protocol == "dns"` 的
/// 元素）解析 `settings` → [`Config`] 并持有；规则核 [`Handler`] 与入站
/// [`DnsInbound`] 经 [`rule_handler`](DnsPlugin::rule_handler) /
/// [`inbound_handler`](DnsPlugin::inbound_handler) 由插件产出（tag/timeout/
/// 上游 outbound 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct DnsPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<Config>,
}

impl DnsPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&Config, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("dns plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：规则核 [`Handler`]（qType + domain 匹配决策面）。
    ///
    /// PM 拍板 2026-10-24：走 [`Handler::try_init`] fail-visible 拒启——任一
    /// 规则编译失败（geosite 资产缺失/规则非法）→ `Err(PluginError::Other)`
    /// → L5 装配门报错，不允许 fail-closed 半启动（crate 既有 Result API，
    /// 无 panic 路径，无需 catch_unwind）。timeout 对应 Go dns.go:85 policy
    /// ConnectionIdle（装配层注入）。
    pub fn rule_handler(&self, timeout: Duration) -> Result<Handler, PluginError> {
        Handler::try_init(self.built_config()?, timeout)
            .map_err(|e| PluginError::Other(format!("dns: {e}").into()))
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现不变，[`DnsInbound::new`]
    /// 即构建接缝——inbound.rs 零 diff）。上游 [`DnsOutbound`] 由装配层选择
    /// （`new_system` / `new_with_servers`），不属插件 build 期。
    pub fn inbound_handler(
        &self,
        tag: &str,
        timeout: Duration,
        outbound: DnsOutbound,
    ) -> Result<DnsInbound, PluginError> {
        Ok(DnsInbound::new(tag, self.rule_handler(timeout)?, outbound))
    }
}

impl Plugin for DnsPlugin {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &DNS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &DNS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_settings_section(ctx.section()?)?;
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("dns plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Dns 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 inactivity 计时 task 的托管（坑约束 5/6 运行时半边）属
/// [`DnsInbound::handle_conn`] 实例面（既有行为，ticker abort；FxScope/
/// ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
pub struct DnsLifecycle;

impl Lifecycle for DnsLifecycle {
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

/// per-plugin 段 → [`Config`]（段无 `settings` 时退化用段本体，socks/freedom
/// 同款约定）。
fn parse_settings_section(section: &serde_json::Value) -> Result<Config, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    parse_dns_outbound_settings(settings)
        .map_err(|e| PluginError::Other(format!("dns plugin: {e}").into()))
}

/// settings → [`Config`]。同规 xray-core
/// `outbound.rs::build_dns_outbound_config`（权威生产解析，票 alwc 双方言）；
/// 解析面收敛属 P3 入口收口，此处不回头改 core。
///
/// Go 方言（`infra/conf/dns_proxy.go:59-94`）：`rules[]`（action/qType/domain/
/// rCode）、`rewriteNetwork`/`rewriteAddress`/`rewritePort`、legacy 别名
/// `network`/`address`/`port`（非空/非零覆盖 rewrite*）、`userLevel`、legacy
/// `nonIPQuery`/`blockTypes`（迁移路径，与 rules 混用报错）。
/// Rust 方言（保留）：`rule[]`（单数）、`rewriteServer` 对象（逐项覆盖）。
/// 未知键 warn 留痕，不静默。
fn parse_dns_outbound_settings(v: &serde_json::Value) -> std::result::Result<Config, String> {
    warn_unknown_dns_outbound_keys(v);
    let mut config = Config::default();

    // geodata 资源目录（geosite: 展开用；与 xray-app-dns 同源 platform 探测）。
    let datadir = xray_common::platform::get_asset_dir();
    let loader = xray_geodata::loader::GeoDataLoader::new(datadir.clone());

    // legacy nonIPQuery/blockTypes：与任一 rules 载体（Go rules / Rust rule）
    // 混用即拒（Go dns_proxy.go:99-102 文案）。
    let has_rules = v.get("rules").is_some() || v.get("rule").is_some();
    let non_ip_query = match v.get("nonIPQuery") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.as_str()),
        Some(other) => {
            return Err(format!("dns outbound: nonIPQuery must be a string, got {other}"));
        },
    };
    let block_types = match v.get("blockTypes") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(arr)) => {
            let mut list = Vec::with_capacity(arr.len());
            for item in arr {
                list.push(item.as_i64().and_then(|n| i32::try_from(n).ok()).ok_or_else(|| {
                    format!("dns outbound: blockTypes must be integers, got {item}")
                })?);
            }
            Some(list)
        },
        Some(other) => {
            return Err(format!("dns outbound: blockTypes must be an array, got {other}"));
        },
    };
    if non_ip_query.is_some() || block_types.is_some() {
        if has_rules {
            return Err("legacy nonIPQuery and blockTypes cannot be mixed with rules".into());
        }
        // Go errors.PrintDeprecatedFeatureWarning（feature_errors.go:15-18）。
        tracing::warn!(
            target: "xray_proxy_dns::plugin",
            "This feature \"nonIPQuery\" and \"blockTypes\" is deprecated, will be removed soon and being migrated to \"rules\". Please update your config(s) according to release note and documentation before removal."
        );
        config.rule = build_legacy_dns_policy(non_ip_query, block_types)?;
    }

    // 新/旧规则载体按序追加（Go rules 优先，Rust rule 兼容在后）。
    for key in ["rules", "rule"] {
        let Some(serde_json::Value::Array(arr)) = v.get(key) else { continue };
        for r in arr {
            config.rule.push(parse_dns_outbound_rule(r, &datadir, &loader)?);
        }
    }

    // 重写目标（Go Build dns_proxy.go:73-94）：rewrite* 为基，legacy 别名
    // 非空/非零覆盖；rewriteServer 对象（Rust 方言）逐项再覆盖。
    let mut endpoint =
        xray_proto::xray::common::net::Endpoint { network: 0, address: None, port: 0 };
    let mut rewrite_touched = false;
    if let Some(n) = go_json_str(v, "rewriteNetwork")? {
        endpoint.network = build_go_dns_network(n);
        rewrite_touched = true;
    }
    if let Some(a) = go_json_str(v, "rewriteAddress")? {
        endpoint.address = parse_go_dns_address(a);
        rewrite_touched = true;
    }
    if let Some(p) = go_json_u64(v, "rewritePort")? {
        endpoint.port = u16::try_from(p)
            .map_err(|_| format!("dns outbound: rewritePort out of range: {p}"))?
            as u32;
        rewrite_touched = true;
    }
    // legacy 别名（Go :74-82）。
    if let Some(n) = go_json_str(v, "network")? {
        if !n.is_empty() {
            endpoint.network = build_go_dns_network(n);
            rewrite_touched = true;
        }
    }
    if let Some(a) = go_json_str(v, "address")? {
        endpoint.address = parse_go_dns_address(a);
        rewrite_touched = true;
    }
    if let Some(p) = go_json_u64(v, "port")? {
        if p != 0 {
            endpoint.port = u16::try_from(p)
                .map_err(|_| format!("dns outbound: port out of range: {p}"))?
                as u32;
            rewrite_touched = true;
        }
    }
    // Rust 方言 rewriteServer 对象（既有行为保留；类型宽松同旧实现）。
    if let Some(rw) = v.get("rewriteServer") {
        rewrite_touched = true;
        if let Some(n) = rw.get("network").and_then(|x| x.as_str()) {
            endpoint.network = build_go_dns_network(n);
        }
        if let Some(a) = rw.get("address").and_then(|x| x.as_str()) {
            endpoint.address = parse_go_dns_address(a);
        }
        if let Some(p) = rw.get("port").and_then(|x| x.as_u64()) {
            endpoint.port = p as u32;
        }
    }
    if rewrite_touched {
        config.rewrite_server = Some(endpoint);
    }

    // userLevel（Go dns_proxy.go:66 → dns.Config.UserLevel）。
    if let Some(level) = go_json_u64(v, "userLevel")? {
        config.user_level = u32::try_from(level)
            .map_err(|_| format!("dns outbound: userLevel out of range: {level}"))?;
    }

    Ok(config)
}

/// dns outbound settings 已知键全集（票 alwc）：Go `infra/conf/dns_proxy.go:59-69`
/// 方言 + 本仓既有 Rust 方言（`rule`/`rewriteServer` 等）。
const DNS_OUTBOUND_KNOWN_KEYS: &[&str] = &[
    // Rust 既有方言
    "rule",
    "rewriteServer",
    "servers",
    "queryStrategy",
    "disableCache",
    "disableFallback",
    // Go 方言（dns_proxy.go:59-69）
    "rules",
    "rewriteNetwork",
    "rewriteAddress",
    "rewritePort",
    "network",
    "address",
    "port",
    "userLevel",
    "nonIPQuery",
    "blockTypes",
];

/// alwc：未知键不得静默丢弃——Go 默认也忽略未知键，这里至少 warn 留痕。
fn warn_unknown_dns_outbound_keys(v: &serde_json::Value) {
    let Some(map) = v.as_object() else { return };
    let unknown: Vec<&String> =
        map.keys().filter(|k| !DNS_OUTBOUND_KNOWN_KEYS.contains(&k.as_str())).collect();
    if !unknown.is_empty() {
        tracing::warn!(
            target: "xray_proxy_dns::plugin",
            keys = ?unknown,
            "dns outbound settings: unrecognized keys are ignored (must match Go infra/conf/dns_proxy.go names or the Rust legacy dialect)"
        );
    }
}

/// 类型严格取键（对齐 Go：JSON 类型不匹配 → 整体配置错误拒启，而非静默忽略）。
fn go_json_str<'a>(
    v: &'a serde_json::Value,
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    match v.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.as_str())),
        Some(other) => Err(format!("dns outbound: {key} must be a string, got {other}")),
    }
}

fn go_json_u64(v: &serde_json::Value, key: &str) -> std::result::Result<Option<u64>, String> {
    match v.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("dns outbound: {key} must be a non-negative integer, got {n}")),
        Some(other) => Err(format!("dns outbound: {key} must be an integer, got {other}")),
    }
}

/// Go `Address`（infra/conf/common.go:53-66）：字符串，`env:` 前缀读环境变量；
/// IPv4/IPv6 呈 Ip 形态，其余按 Domain。空串 → None（无重写地址）。
fn parse_go_dns_address(s: &str) -> Option<xray_proto::xray::common::net::IpOrDomain> {
    let raw = match s.strip_prefix("env:") {
        Some(var) => std::env::var(var).unwrap_or_default(),
        None => s.to_string(),
    };
    use xray_proto::xray::common::net::ip_or_domain::Address as IoD;
    if let Ok(v4) = raw.parse::<std::net::Ipv4Addr>() {
        return Some(xray_proto::xray::common::net::IpOrDomain {
            address: Some(IoD::Ip(v4.octets().to_vec())),
        });
    }
    if let Ok(v6) = raw.parse::<std::net::Ipv6Addr>() {
        return Some(xray_proto::xray::common::net::IpOrDomain {
            address: Some(IoD::Ip(v6.octets().to_vec())),
        });
    }
    if raw.is_empty() {
        None
    } else {
        Some(xray_proto::xray::common::net::IpOrDomain { address: Some(IoD::Domain(raw)) })
    }
}

/// Go `Network.Build`（infra/conf/common.go:69-80）：大小写不敏感，
/// tcp/udp/unix → proto 枚举（common/net/network.proto），其余 Unknown。
fn build_go_dns_network(s: &str) -> i32 {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => 2,  // Network_TCP
        "udp" => 3,  // Network_UDP
        "unix" => 4, // Network_UNIX
        _ => 0,      // Network_Unknown → 不覆盖网络形态
    }
}

/// Go `PortList`（infra/conf/common.go:233-270）+ 本仓数组方言 → qType 列表。
/// 形态：`"53"`、`"53,80-853"`（段支持 `env:VAR` 前缀，单段 `-` 分隔区间）、
/// 数字（0 = 空 → 匹配所有类型，Go `if number != 0`）、数字数组（Rust 方言）。
fn parse_dns_q_type(v: &serde_json::Value) -> std::result::Result<Vec<i32>, String> {
    let mut out: Vec<i32> = Vec::new();
    match v {
        serde_json::Value::Number(n) => {
            let p = n.as_u64().ok_or_else(|| format!("invalid port: {v}"))?;
            // Go PortFromInt：>65535 报错；顶层 0 → 不追加（匹配所有类型）。
            if p > 65535 {
                return Err(format!("invalid port: {p}"));
            }
            if p != 0 {
                out.push(p as i32);
            }
        },
        serde_json::Value::String(s) => {
            for part in s.split(',') {
                let t = part.trim();
                if t.is_empty() {
                    continue;
                }
                if t.contains('-') || t.starts_with("env:") {
                    let (from, to) = parse_go_string_port(t)?;
                    for q in from..=to {
                        out.push(q as i32);
                    }
                } else {
                    let p: u32 = t.parse().map_err(|_| format!("invalid port: {t}"))?;
                    if p > 65535 {
                        return Err(format!("invalid port: {t}"));
                    }
                    out.push(p as i32);
                }
            }
        },
        // 本仓 Rust 方言：数字数组。
        serde_json::Value::Array(arr) => {
            for item in arr {
                let n = item.as_i64().ok_or_else(|| format!("invalid port: {item}"))?;
                if !(0..=65535).contains(&n) {
                    return Err(format!("invalid port: {n}"));
                }
                out.push(n as i32);
            }
        },
        other => return Err(format!("invalid port: {other}")),
    }
    Ok(out)
}

/// Go `parseStringPort`（infra/conf/common.go:159-181）：`env:VAR` 前缀先解析
/// 环境变量，再按首个 `-` 拆 from/to；两侧均须 0-65535。
fn parse_go_string_port(s: &str) -> std::result::Result<(u32, u32), String> {
    let resolved = match s.strip_prefix("env:") {
        Some(var) => std::env::var(var).map_err(|_| format!("invalid port range: {s}"))?,
        None => s.to_string(),
    };
    let parse_side = |side: &str| -> std::result::Result<u32, String> {
        let p: u32 = side.trim().parse().map_err(|_| format!("invalid port range: {resolved}"))?;
        if p > 65535 {
            return Err(format!("invalid port range: {resolved}"));
        }
        Ok(p)
    };
    match resolved.split_once('-') {
        None => {
            let p = parse_side(&resolved)?;
            Ok((p, p))
        },
        Some((from, to)) => Ok((parse_side(from)?, parse_side(to)?)),
    }
}

/// domain 规则串列表 → proto `DomainRule` 列表。
///
/// 对齐 Go `geodata.ParseDomainRules(*c.Domain, Domain_Substr)`（dns_proxy.go:44-49）：
/// 每条串按 Substr 默认类型解析；`geosite:` 条目就地展开为具体 Domain 条目
/// （运行时 `DnsRule::from_config` 无 geo loader，Geosite 变体会被跳过——此处
/// 展开后端到端可用）。attrs 过滤已在 `load_site_with_attrs` 内完成，展开条目
/// 不再携带 attribute。解析失败 → 错误拒启（Go 同为 Build error）。
fn parse_dns_domain_rules(
    rules: &[String],
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> std::result::Result<Vec<xray_proto::xray::common::geodata::DomainRule>, String> {
    use xray_proto::xray::common::geodata::{Domain, domain_rule::Value as PV};
    let mut out = Vec::new();
    for s in rules {
        let pb_rule = xray_geodata::rule_parser::parse_domain_rule(
            s,
            xray_geodata::geosite::DomainType::Substr,
            datadir,
        )
        .map_err(|e| format!("parse dns outbound domain rule {s}: {e}"))?;
        let Some(value) = pb_rule.value else { continue };
        match value {
            xray_geodata::pb::domain_rule::Value::Custom(d) => {
                out.push(xray_proto::xray::common::geodata::DomainRule {
                    value: Some(PV::Custom(Domain {
                        r#type: d.r#type,
                        value: d.value,
                        attribute: Vec::new(),
                    })),
                });
            },
            xray_geodata::pb::domain_rule::Value::Geosite(g) => {
                let file = if g.file.is_empty() { "geosite.dat" } else { &g.file };
                let site = loader
                    .load_site_with_attrs(file, &g.code, &g.attrs)
                    .map_err(|e| format!("load geosite {file}/{}: {e}", g.code))?;
                for d in site.domain {
                    out.push(xray_proto::xray::common::geodata::DomainRule {
                        value: Some(PV::Custom(Domain {
                            r#type: d.r#type,
                            value: d.value,
                            attribute: Vec::new(),
                        })),
                    });
                }
            },
        }
    }
    Ok(out)
}

/// rules[]/rule[] 单条 → `DnsRuleConfig`。
///
/// 对齐 Go `DNSOutboundRuleConfig.Build`（dns_proxy.go:21-56）：
/// - action 小写匹配 direct/drop/return/hijack，未知值报错（Go 文案）；缺省 → Direct（本仓 Rust
///   方言既有行为，Go 缺省报错——宽松面保留兼容）；
/// - qType 为 PortList 展开列表；domain 为 geodata 规则；rCode ≤ 65535。
fn parse_dns_outbound_rule(
    r: &serde_json::Value,
    datadir: &std::path::Path,
    loader: &xray_geodata::loader::GeoDataLoader,
) -> std::result::Result<crate::DnsRuleConfig, String> {
    let action = match r.get("action") {
        None | Some(serde_json::Value::Null) => crate::RuleAction::Direct,
        Some(serde_json::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "direct" => crate::RuleAction::Direct,
            "drop" => crate::RuleAction::Drop,
            "return" => crate::RuleAction::Return,
            "hijack" => crate::RuleAction::Hijack,
            _ => return Err(format!("unknown action: {s}")),
        },
        Some(other) => {
            return Err(format!("dns outbound: rule action must be a string, got {other}"));
        },
    };
    let q_type = match r.get("qType") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(v) => parse_dns_q_type(v)?,
    };
    let domain = match r.get("domain") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        // Go StringList（infra/conf/common.go:17-34）：单字符串按逗号拆分。
        Some(serde_json::Value::String(s)) => {
            let list: Vec<String> = s.split(',').map(str::to_string).collect();
            parse_dns_domain_rules(&list, datadir, loader)?
        },
        Some(serde_json::Value::Array(arr)) => {
            let mut list = Vec::with_capacity(arr.len());
            for item in arr {
                list.push(
                    item.as_str()
                        .ok_or_else(|| {
                            format!("dns outbound: rule domain must be strings, got {item}")
                        })?
                        .to_string(),
                );
            }
            parse_dns_domain_rules(&list, datadir, loader)?
        },
        Some(other) => {
            return Err(format!(
                "dns outbound: rule domain must be a string or array, got {other}"
            ));
        },
    };
    let r_code = match r.get("rCode") {
        None | Some(serde_json::Value::Null) => 0,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| format!("dns outbound: rule rCode must be an integer, got {v}"))?;
            if n > 65535 {
                return Err(format!("rCode out of range: {n}"));
            }
            n as u32
        },
    };
    Ok(crate::DnsRuleConfig { action, q_type, domain, r_code })
}

/// Go legacy `buildLegacyDNSPolicy`（dns_proxy.go:120-168）：
/// `[blockTypes 规则?] + hijack{qType:[1,28]} + 兜底规则`。
/// mode：reject → Return+RCode5；drop → Drop；skip → Direct；"" → Return。
fn build_legacy_dns_policy(
    non_ip_query: Option<&str>,
    block_types: Option<Vec<i32>>,
) -> std::result::Result<Vec<crate::DnsRuleConfig>, String> {
    let mode = non_ip_query.unwrap_or("reject");
    match mode {
        "" | "reject" | "drop" | "skip" => {},
        other => return Err(format!("unknown nonIPQuery: {other}")),
    }
    let mut rules = Vec::new();
    if let Some(types) = block_types.filter(|t| !t.is_empty()) {
        let mut rule =
            crate::DnsRuleConfig { action: crate::RuleAction::Drop, ..Default::default() };
        if mode == "reject" {
            rule.action = crate::RuleAction::Return;
            rule.r_code = 5;
        }
        for q in types {
            if !(0..=65535).contains(&q) {
                return Err(format!("legacy blockTypes qType out of range: {q}"));
            }
            rule.q_type.push(q);
        }
        rules.push(rule);
    }
    rules.push(crate::DnsRuleConfig {
        action: crate::RuleAction::Hijack,
        q_type: vec![1, 28],
        ..Default::default()
    });
    let mut last = crate::DnsRuleConfig { action: crate::RuleAction::Return, ..Default::default() };
    if mode == "reject" {
        last.r_code = 5;
    } else if mode == "drop" {
        last.action = crate::RuleAction::Drop;
    } else if mode == "skip" {
        last.action = crate::RuleAction::Direct;
    }
    rules.push(last);
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::RuleAction;

    #[test]
    fn section_rules_go_dialect_maps_fields() {
        let section = json!({
            "protocol": "dns",
            "tag": "dns-out",
            "settings": {
                "rules": [
                    {
                        "action": "drop",
                        "qType": [1, 28],
                        "domain": ["domain:ads.example.com"],
                        "rCode": 3
                    }
                ],
                "userLevel": 2
            }
        });
        let cfg = parse_settings_section(&section).expect("valid settings");
        assert_eq!(cfg.user_level, 2);
        assert_eq!(cfg.rule.len(), 1);
        let r = &cfg.rule[0];
        assert_eq!(r.action, RuleAction::Drop);
        assert_eq!(r.q_type, vec![1, 28]);
        assert_eq!(r.r_code, 3);
        assert_eq!(r.domain.len(), 1, "domain 串展开为 proto DomainRule");
        assert!(cfg.rewrite_server.is_none());
    }

    #[test]
    fn section_rule_rust_carrier_appended_after_go_rules() {
        let section = json!({"settings": {
            "rule": [{"action": "return"}],
            "rules": [{"action": "hijack", "qType": "1,28"}]
        }});
        let cfg = parse_settings_section(&section).expect("dual carrier");
        assert_eq!(cfg.rule.len(), 2);
        assert_eq!(cfg.rule[0].action, RuleAction::Hijack, "Go rules 优先");
        assert_eq!(cfg.rule[0].q_type, vec![1, 28], "qType 字符串按逗号拆分");
        assert_eq!(cfg.rule[1].action, RuleAction::Return, "Rust rule 兼容在后");
    }

    #[test]
    fn section_rewrite_layers_override_in_order() {
        // rewrite* 为基，legacy 别名覆盖，rewriteServer 再覆盖。
        let section = json!({"settings": {
            "rewriteNetwork": "udp",
            "rewriteAddress": "8.8.8.8",
            "rewritePort": 53,
            "address": "dns.google",
            "rewriteServer": {"network": "tcp", "port": 5353}
        }});
        let cfg = parse_settings_section(&section).expect("rewrite layers");
        let ep = cfg.rewrite_server.expect("rewrite touched");
        assert_eq!(
            ep.network, 2,
            "rewriteServer.network=tcp 覆盖 rewriteNetwork=udp（Network_TCP）"
        );
        use xray_proto::xray::common::net::ip_or_domain::Address as IoD;
        assert!(
            matches!(ep.address.as_ref().and_then(|a| a.address.as_ref()),
                Some(IoD::Domain(d)) if d == "dns.google"),
            "rewriteServer 无 address → 保留 legacy address（Domain 形态）"
        );
        assert_eq!(ep.port, 5353);
    }

    #[test]
    fn section_no_rewrite_stays_none() {
        let section = json!({"settings": {"userLevel": 1}});
        let cfg = parse_settings_section(&section).expect("no rewrite");
        assert!(cfg.rewrite_server.is_none(), "未触碰 rewrite 不得注入空 endpoint");
    }

    #[test]
    fn section_nonipquery_block_types_builds_legacy_policy() {
        let section = json!({"settings": {"nonIPQuery": "reject", "blockTypes": [1]}});
        let cfg = parse_settings_section(&section).expect("legacy policy");
        assert_eq!(cfg.rule.len(), 3);
        assert_eq!(cfg.rule[0].action, RuleAction::Return);
        assert_eq!(cfg.rule[0].r_code, 5);
        assert_eq!(cfg.rule[0].q_type, vec![1]);
        assert_eq!(cfg.rule[1].action, RuleAction::Hijack);
        assert_eq!(cfg.rule[1].q_type, vec![1, 28]);
        assert_eq!(cfg.rule[2].action, RuleAction::Return);
        assert_eq!(cfg.rule[2].r_code, 5);
    }

    #[test]
    fn section_nonipquery_mixed_with_rules_rejected() {
        let section = json!({"settings": {"nonIPQuery": "drop", "rules": [{"action": "drop"}]}});
        let err = parse_settings_section(&section).expect_err("混用必须拒");
        assert!(err.to_string().contains("cannot be mixed with rules"), "实际: {err}");
    }

    #[test]
    fn section_unknown_action_fails_with_original_case() {
        let section = json!({"settings": {"rules": [{"action": "DropAll"}]}});
        let err = parse_settings_section(&section).expect_err("未知 action 必须拒");
        assert!(err.to_string().contains("unknown action: DropAll"), "实际: {err}");
    }

    #[test]
    fn section_rcode_out_of_range_fails() {
        let section = json!({"settings": {"rules": [{"rCode": 65536}]}});
        let err = parse_settings_section(&section).expect_err("rCode 越界必须拒");
        assert!(err.to_string().contains("rCode out of range"), "实际: {err}");
    }

    #[test]
    fn section_empty_settings_defaults() {
        let section = json!({"protocol": "dns", "settings": {}});
        let cfg = parse_settings_section(&section).expect("empty settings → default");
        assert_eq!(cfg, Config::default());
    }
}
