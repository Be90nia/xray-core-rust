//! Dokodemo-door 协议插件（P2 批次 B，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`DokodemoPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(DokodemoPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 → build `Err` → 整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`server.rs` 的 `impl InboundHandler`（start/close 生命周期）与
//! `fakeudp.rs`（TPROXY/IP_TRANSPARENT 平台门控）、`outbound.rs` dial 面一行不动；
//! 插件只负责配置注入与构建（构建接缝 = [`DokodemoServer::new`]，server.rs 零 diff）。
//!
//! 协议名核实：Go 注册名 `dokodemo-door`（proto 包名 `xray.proxy.dokodemo`，配置
//! 层 `protocol: "dokodemo-door"`）；本仓 wire/config 层既有名同为 `dokodemo-door`
//! （`xray-conf/src/protocols.rs:1338` 段路由 + xray-cli `go_proxy_type_url`），
//! 插件 name 取 `dokodemo-door`。
//!
//! udf 判定（A7，非通用件）：dokodemo 无自有 wire 编解码，语义面 = 转发目标构造 +
//! TPROXY（SO_ORIGINAL_DST / IP_TRANSPARENT syscall）——协议 + 平台方向件，按
//! CLAUDE.md §3.5.3 留主仓最近消费方，无提炼候选。

use std::sync::OnceLock;

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{Config, Network},
    server::DokodemoServer,
};

/// 通用条款适用子集（差异表 §2.2 第 7 行：3,5,6,7,8,9,10,12；**2/11 N/A**
/// 见 [`DOKODEMO_NOT_APPLICABLE`]——dokodemo 无协议握手、无认证凭据/密钥）。
static DOKODEMO_CLAUSES: &[ClauseId] = &[
    ClauseId::ConnIdPresent,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::HotPathFreeze,
];

/// 协议专属条款（差异表 §2.2 第 7 行：dokodemo-tproxy-platform-gated）。
static DOKODEMO_EXTRA: &[(&str, &str)] =
    &[("DKD-TPROXY", "TPROXY 路径仅 Linux，平台门控不得在非 Linux 编译期裁掉语义测试")];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由）。
static DOKODEMO_NOT_APPLICABLE: &[(ClauseId, &str)] = &[
    (
        ClauseId::HandshakeDeadline,
        "dokodemo 无协议握手——连接建立即按 rewrite/followRedirect 目标转发，无首包 deadline 面",
    ),
    (ClauseId::SecretMasking, "dokodemo 无认证凭据/密钥，无掩码面"),
];

static DOKODEMO_CONTRACT: PluginContract = PluginContract {
    clauses: DOKODEMO_CLAUSES,
    extra: DOKODEMO_EXTRA,
    not_applicable: DOKODEMO_NOT_APPLICABLE,
};

static DOKODEMO_LIFECYCLE: DokodemoLifecycle = DokodemoLifecycle;

/// Dokodemo-door 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]` 内 `protocol == "dokodemo-door"`
/// 的元素）解析 `settings` → [`Config`] 并持有；入站 handler 经
/// [`inbound_handler`](DokodemoPlugin::inbound_handler) 由插件产出（tag 属实例
/// 注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct DokodemoPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<Config>,
}

impl DokodemoPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&Config, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("dokodemo plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`DokodemoServer::new`] 即构建接缝——server.rs 零 diff）。
    pub fn inbound_handler(&self, tag: &str) -> Result<DokodemoServer, PluginError> {
        Ok(DokodemoServer::new(tag, self.built_config()?.clone()))
    }
}

impl Plugin for DokodemoPlugin {
    fn name(&self) -> &'static str {
        "dokodemo-door"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &DOKODEMO_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &DOKODEMO_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_config_section(ctx.section()?)?;
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("dokodemo plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Dokodemo 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept loop 的托管（坑约束 5/6 运行时半边）属 [`DokodemoServer`]
/// 实例面（既有行为；FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
pub struct DokodemoLifecycle;

impl Lifecycle for DokodemoLifecycle {
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

/// per-plugin 段 → [`Config`]。
///
/// 字段集同规 Go `DokodemoConfig`（dokodemo.go:10-20：address/port/network/
/// followRedirect/userLevel）+ 本仓 xray-conf `DokodemoDoorInboundSettings`
/// 扩展名（rewrite_address/rewrite_port/allowed_network/portMap；扩展名与 Go 名
/// 同槽位时**扩展名覆盖**）。`timeout` 等本仓 [`Config`] 未建模的字段不解析
/// （切片边界；conf 层收敛属 P3 入口收口，此处不回头改 conf）。端口/级别越界
/// 与未知网络名 = 显式硬错（对齐 Go uint16/uint32 反序列化 + ParseNetwork 语义，
/// 禁静默截断/忽略）。
fn parse_config_section(section: &serde_json::Value) -> Result<Config, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let mut cfg = Config::default();

    // 地址：Go `address`；本仓扩展名 rewrite_address 在场时覆盖（同槽位）。
    if let Some(s) =
        settings.get("rewrite_address").or_else(|| settings.get("address")).and_then(|x| x.as_str())
    {
        cfg.rewrite_address = Some(proto_ip_or_domain_from_str(s));
    }

    // 端口：Go `Port uint16`——越界 = conf 错。
    if let Some(v) = settings.get("rewrite_port").or_else(|| settings.get("port")) {
        let raw = v.as_u64().ok_or_else(|| section_err("port 必须是非负整数"))?;
        let port = u16::try_from(raw)
            .map_err(|_| section_err(&format!("port {raw} 超出 u16（Go uint16 语义）")))?;
        cfg.rewrite_port = u32::from(port);
    }

    // 网络：network 缺失回落 allowed_network（xray-conf 双名同槽）。
    if let Some(v) = settings.get("network").or_else(|| settings.get("allowed_network")) {
        cfg.allowed_networks = parse_network_list(v)?;
    }

    if let Some(m) = settings.get("portMap").and_then(|x| x.as_object()) {
        for (k, v) in m {
            let val = v.as_str().ok_or_else(|| section_err("portMap 值必须是字符串"))?;
            cfg.port_map.insert(k.clone(), val.to_string());
        }
    }

    cfg.follow_redirect = settings.get("followRedirect").and_then(|x| x.as_bool()).unwrap_or(false);

    // 级别：Go `UserLevel uint32`——越界 = conf 错。
    if let Some(v) = settings.get("userLevel") {
        let raw = v.as_u64().ok_or_else(|| section_err("userLevel 必须是非负整数"))?;
        cfg.user_level = u32::try_from(raw)
            .map_err(|_| section_err(&format!("userLevel {raw} 超出 u32（Go uint32 语义）")))?;
    }

    Ok(cfg)
}

fn section_err(msg: &str) -> PluginError {
    PluginError::Other(format!("dokodemo section: {msg}").into())
}

/// 网络列表解析：Go `NetworkList` 双形态——字符串（逗号分隔）或字符串数组；
/// 未知网络名（含空段）= conf 硬错（Go net.ParseNetwork 同语义，禁静默忽略）。
fn parse_network_list(v: &serde_json::Value) -> Result<Vec<Network>, PluginError> {
    let names: Vec<&str> = match v {
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(item.as_str().ok_or_else(|| section_err("network 数组元素必须是字符串"))?);
            }
            out
        },
        serde_json::Value::String(s) => s.split(',').collect(),
        _ => return Err(section_err("network 必须是字符串或字符串数组")),
    };
    names
        .into_iter()
        .map(|name| match name {
            "tcp" => Ok(Network::Tcp),
            "udp" => Ok(Network::Udp),
            other => Err(section_err(&format!("未知 network: {other}"))),
        })
        .collect()
}

/// 字符串 → proto `IpOrDomain`：IPv4 → IPv6 → 域名（同规 xray-core
/// parse_address_str；socks 插件同款先例）。
fn proto_ip_or_domain_from_str(s: &str) -> xray_proto::xray::common::net::IpOrDomain {
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;
    let address = if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        ProtoAddress::Ip(v4.octets().to_vec())
    } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        ProtoAddress::Ip(v6.octets().to_vec())
    } else {
        ProtoAddress::Domain(s.to_owned())
    };
    xray_proto::xray::common::net::IpOrDomain { address: Some(address) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use xray_proto::xray::common::net::{
        IpOrDomain as ProtoIpOrDomain, ip_or_domain::Address as ProtoAddress,
    };

    use super::*;

    #[test]
    fn section_full_mapping() {
        let section = json!({
            "settings": {
                "address": "8.8.8.8",
                "port": 53,
                "network": ["tcp", "udp"],
                "followRedirect": true,
                "userLevel": 2,
                "portMap": {"5353": "8.8.8.8:53"}
            }
        });
        let parsed = parse_config_section(&section).expect("full mapping");
        assert_eq!(
            parsed.rewrite_address,
            Some(ProtoIpOrDomain { address: Some(ProtoAddress::Ip(vec![8, 8, 8, 8])) })
        );
        assert_eq!(parsed.rewrite_port, 53);
        assert_eq!(parsed.allowed_networks, vec![Network::Tcp, Network::Udp]);
        assert!(parsed.follow_redirect);
        assert_eq!(parsed.user_level, 2);
        assert_eq!(parsed.port_map.get("5353").map(String::as_str), Some("8.8.8.8:53"));
    }

    #[test]
    fn section_rewrite_names_override_go_names() {
        // 本仓扩展名与 Go 名同槽位时扩展名覆盖。
        let section = json!({
            "settings": {
                "address": "1.1.1.1",
                "port": 53,
                "rewrite_address": "9.9.9.9",
                "rewrite_port": 853
            }
        });
        let parsed = parse_config_section(&section).expect("rewrite override");
        assert_eq!(
            parsed.rewrite_address,
            Some(ProtoIpOrDomain { address: Some(ProtoAddress::Ip(vec![9, 9, 9, 9])) })
        );
        assert_eq!(parsed.rewrite_port, 853);
    }

    #[test]
    fn section_network_csv_string_and_allowed_network_alias() {
        let csv =
            parse_config_section(&json!({"settings": {"network": "tcp,udp"}})).expect("csv 形态");
        assert_eq!(csv.allowed_networks, vec![Network::Tcp, Network::Udp]);

        let alias = parse_config_section(&json!({"settings": {"allowed_network": ["udp"]}}))
            .expect("allowed_network 别名");
        assert_eq!(alias.allowed_networks, vec![Network::Udp]);
    }

    #[test]
    fn section_domain_and_ipv6_address() {
        let domain = parse_config_section(&json!({"settings": {"address": "example.com"}}))
            .expect("domain 形态");
        assert_eq!(
            domain.rewrite_address,
            Some(ProtoIpOrDomain { address: Some(ProtoAddress::Domain("example.com".into())) })
        );

        let v6 = parse_config_section(&json!({"settings": {"address": "::1"}})).expect("IPv6");
        assert!(v6.rewrite_address.is_some());
    }

    #[test]
    fn section_empty_defaults() {
        let parsed = parse_config_section(&json!({"protocol": "dokodemo-door"}))
            .expect("无 settings → 默认");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn section_boundary_errors_are_visible() {
        // Go uint16/uint32 反序列化越界与未知网络名 = conf 错，禁静默截断/忽略。
        assert!(
            parse_config_section(&json!({"settings": {"port": 70_000}})).is_err(),
            "port 超出 u16 必须显式硬错"
        );
        assert!(
            parse_config_section(&json!({"settings": {"userLevel": 4_294_967_296u64}})).is_err(),
            "userLevel 超出 u32 必须显式硬错"
        );
        assert!(
            parse_config_section(&json!({"settings": {"network": "sctp"}})).is_err(),
            "未知 network 必须显式硬错"
        );
    }
}
