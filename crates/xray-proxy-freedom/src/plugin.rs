//! Freedom 协议插件（P2 批次 B 末位，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`FreedomPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(FreedomPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 → build `Err` → 整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`handler.rs` 的 `impl OutboundHandler` / `inbound.rs` 的
//! `impl InboundHandler` 逐行不动（v49/v50/v52 三轮 splice 挂死战役战场；
//! FREEDOM-SPLICE 判定点在 dispatcher `default.rs:1805-1818`，不在本 crate）；
//! 插件只负责配置注入与构建（构建接缝 = [`FreedomHandler::new`] /
//! [`FreedomInboundHandler::new`] 既有构造器）。
//!
//! finalRules 语义不变（FREEDOM-FINALRULES）：settings 缺 `finalRules` →
//! 空规则表，**不静默注入** `{action: allow}`（默认规则 blackholing 行为保留，
//! 部署面显式配置责任不因插件化转移）；单条非法 → 硬错拒启（Go freedom.go
//! Build 语义，同规 xray-core `parse_freedom_config`）。
//!
//! udf 判定（A7，非通用件）：freedom 直连拨号 + finalRules 匹配 + fragment
//! 分片是网络/协议方向件——按 CLAUDE.md §3.5.3「带领域方向的件不进
//! udf-frame」，留主仓最近消费方；无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_app_dispatcher::default::SimpleOhm;
use xray_common::net::destination::Destination;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{Config, DestinationOverride, DomainStrategy, FinalRuleConfig, Fragment, Noise},
    handler::FreedomHandler,
    inbound::FreedomInboundHandler,
};

/// 通用条款适用子集（差异表 §2.2 第 8 行 3,5,6,7,8,9,10,12 + **4 适用**——
/// 直连面走 buf，受 BufferPool 接缝约束；**1/2/11 N/A** 见
/// [`FREEDOM_NOT_APPLICABLE`]——freedom 无认证、无协议握手、无密钥，条款 1 为
/// PM 拍板 2026-10-24 补齐，同 dokodemo 先例）。
static FREEDOM_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 8 行：splice 面冻结 + finalRules 部署纪律）。
static FREEDOM_EXTRA: &[(&str, &str)] = &[
    ("FREEDOM-SPLICE", "splice 直连面禁动（判定点 dispatcher default.rs:1805-1818），插件化不触碰"),
    (
        "FREEDOM-FINALRULES",
        "裸 freedom outbound 必带 settings.finalRules=[{action:allow}]，否则 final rule 默认 blackholing，会伪装成数据面 bug",
    ),
];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由）。
static FREEDOM_NOT_APPLICABLE: &[(ClauseId, &str)] = &[
    (ClauseId::AuthErrorClassified, "freedom 无认证/无凭证（直连出站），认证失败分类不适用"),
    (ClauseId::HandshakeDeadline, "freedom 无协议握手（直连拨号，无协商轮次），无首包 deadline 面"),
    (ClauseId::SecretMasking, "freedom 无密钥材料（无 TLS 私钥/无认证凭据），无掩码面"),
];

static FREEDOM_CONTRACT: PluginContract = PluginContract {
    clauses: FREEDOM_CLAUSES,
    extra: FREEDOM_EXTRA,
    not_applicable: FREEDOM_NOT_APPLICABLE,
};

static FREEDOM_LIFECYCLE: FreedomLifecycle = FreedomLifecycle;

/// Freedom 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]` 内 `protocol == "freedom"`
/// 的元素）解析 `settings` → [`Config`] 并持有；出/入站 handler 经
/// [`dispatch_handler`](FreedomPlugin::dispatch_handler) /
/// [`inbound_handler`](FreedomPlugin::inbound_handler) 由插件产出
/// （tag/listen/dest/ohm 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct FreedomPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<Config>,
}

impl FreedomPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&Config, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("freedom plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：出站 handler（`OutboundHandler`/`ProxyOutbound` 实现与行为
    /// 不变，[`FreedomHandler::new`] 即构建接缝——finalRules 预构建硬错语义
    /// 由此处沿用，handler.rs 零 diff）。
    pub fn dispatch_handler(&self, tag: &str) -> Result<FreedomHandler, PluginError> {
        FreedomHandler::new(tag, self.built_config()?.clone())
            .map_err(|e| PluginError::Other(format!("freedom: {e}").into()))
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现不变）。入站 handler 不
    /// 消费 freedom settings（dest/ohm 属实例注册期信息），故不设 built 门。
    pub fn inbound_handler(
        &self,
        tag: &str,
        listen_addr: &str,
        dest: Destination,
        ohm: Arc<SimpleOhm>,
    ) -> Result<FreedomInboundHandler, PluginError> {
        Ok(FreedomInboundHandler::new(tag, listen_addr, dest, ohm))
    }
}

impl Plugin for FreedomPlugin {
    fn name(&self) -> &'static str {
        "freedom"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &FREEDOM_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &FREEDOM_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_settings_section(ctx.section()?)?;
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("freedom plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Freedom 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级拨号/转发任务的托管（坑约束 5/6 运行时半边）属 handler 实例面与
/// dispatcher（既有行为；FxScope/ShutdownCoordinator 接线随 P3 入口收口统一
/// 迁移）。
pub struct FreedomLifecycle;

impl Lifecycle for FreedomLifecycle {
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
/// 同规 xray-core `outbound.rs::parse_freedom_config`（权威生产解析），字段
/// 对齐 Go `infra/conf/freedom.go`：`targetStrategy` 非空优先、否则回退
/// `domainStrategy`（Go :62-64；11 值全谱含 forceip 族，未知值硬错且错误
/// 保留原始大小写，Go :65-88）；`finalRules` 单条非法整出站拒启（Go :186-191
/// Build 硬错），缺 `finalRules` → 空表不注入 allow（FREEDOM-FINALRULES）。
/// `fragment`/`noises` 按 freedom crate 自身 `Config` 语义接全（`fragment`
/// 被 `FreedomHandler` process 消费做 FragmentConnection 包装；xray-core 权威
/// 面现 parse-then-drop 两键，收敛属 P3 入口收口，此处不回头改 core）。
fn parse_settings_section(section: &serde_json::Value) -> Result<Config, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let strategy_raw = settings
        .get("targetStrategy")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| settings.get("domainStrategy").and_then(|s| s.as_str()));
    let domain_strategy = match strategy_raw {
        Some(s) => parse_domain_strategy(s)?,
        None => DomainStrategy::AsIs,
    };
    let destination_override =
        settings.get("destinationOverride").and_then(DestinationOverride::from_json);
    let user_level = settings.get("userLevel").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let proxy_protocol = settings.get("proxyProtocol").and_then(|p| p.as_u64()).unwrap_or(0) as u32;
    let final_rules = match settings.get("finalRules").and_then(|r| r.as_array()) {
        Some(arr) => arr
            .iter()
            .map(|rv| {
                FinalRuleConfig::from_json(rv)
                    .map_err(|e| PluginError::Other(format!("freedom finalRule: {e}").into()))
            })
            .collect::<Result<Vec<_>, PluginError>>()?,
        None => Vec::new(),
    };
    let fragment = match settings.get("fragment") {
        Some(f) => Some(
            Fragment::from_json(f)
                .map_err(|e| PluginError::Other(e.to_string().into()))?,
        ),
        None => None,
    };
    let noises: Vec<Noise> = settings
        .get("noises")
        .and_then(|n| n.as_array())
        .map(|arr| {
            arr.iter()
                .map(|n| Noise::from_json(n).map_err(|e| PluginError::Other(e.to_string().into())))
                .collect::<Result<Vec<_>, PluginError>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Config {
        domain_strategy: domain_strategy as i32,
        destination_override,
        user_level,
        fragment,
        proxy_protocol,
        noises,
        final_rules,
    })
}

/// domainStrategy 字符串 → 枚举（Go freedom.go:65-88：ToLower + 11 值全谱，
/// 未知值硬错；错误信息保留原始大小写）。
fn parse_domain_strategy(s: &str) -> Result<DomainStrategy, PluginError> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "asis" | "" => DomainStrategy::AsIs,
        "useip" => DomainStrategy::UseIP,
        "useipv4" => DomainStrategy::UseIPv4,
        "useipv6" => DomainStrategy::UseIPv6,
        "useipv4v6" => DomainStrategy::UseIPv4v6,
        "useipv6v4" => DomainStrategy::UseIPv6v4,
        "forceip" => DomainStrategy::ForceIP,
        "forceipv4" => DomainStrategy::ForceIPv4,
        "forceipv6" => DomainStrategy::ForceIPv6,
        "forceipv4v6" => DomainStrategy::ForceIPv4v6,
        "forceipv6v4" => DomainStrategy::ForceIPv6v4,
        _ => {
            return Err(PluginError::Other(format!("unsupported domain strategy: {s}").into()));
        },
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_settings_mapped() {
        let section = json!({"protocol": "freedom", "settings": {
            "domainStrategy": "UseIP",
            "userLevel": 2,
            "proxyProtocol": 2,
            "destinationOverride": {"server": {"address": "9.9.9.9", "port": 1080}},
            "finalRules": [{"action": "allow"}]
        }});
        let parsed = parse_settings_section(&section).expect("valid settings");
        assert_eq!(parsed.domain_strategy, DomainStrategy::UseIP as i32);
        assert_eq!(parsed.user_level, 2);
        assert_eq!(parsed.proxy_protocol, 2);
        assert!(parsed.destination_override.is_some());
        assert_eq!(parsed.final_rules.len(), 1);
        assert_eq!(parsed.final_rules[0].action, crate::config::RuleAction::Allow);
    }

    #[test]
    fn section_target_strategy_priority() {
        // Go freedom.go:62-64：targetStrategy 非空优先，空串回退 domainStrategy。
        let section = json!({"settings": {
            "domainStrategy": "UseIP", "targetStrategy": "ForceIPv4"
        }});
        assert_eq!(
            parse_settings_section(&section).expect("parse").domain_strategy,
            DomainStrategy::ForceIPv4 as i32
        );
        let fallback = json!({"settings": {
            "domainStrategy": "UseIP", "targetStrategy": ""
        }});
        assert_eq!(
            parse_settings_section(&fallback).expect("parse").domain_strategy,
            DomainStrategy::UseIP as i32
        );
    }

    #[test]
    fn section_unknown_domain_strategy_preserves_case() {
        let err = parse_settings_section(&json!({"settings": {"domainStrategy": "UseIPv3"}}))
            .expect_err("未知值硬错");
        assert!(err.to_string().contains("unsupported domain strategy: UseIPv3"), "实际: {err}");
    }

    #[test]
    fn section_final_rules_absent_stays_empty() {
        let parsed = parse_settings_section(&json!({"settings": {}})).expect("parse");
        assert!(parsed.final_rules.is_empty(), "缺省不注入 allow（FREEDOM-FINALRULES）");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn section_invalid_final_rule_hard_error() {
        let err = parse_settings_section(&json!({"settings": {
            "finalRules": [{"action": "bogus"}]
        }}))
        .expect_err("单条非法整出站拒启（Go Build 硬错语义）");
        assert!(err.to_string().contains("freedom finalRule"), "实际: {err}");
    }

    #[test]
    fn section_fragment_and_noises_wired() {
        let parsed = parse_settings_section(&json!({"settings": {
            "fragment": {"packets": 2, "lengthMin": 10, "lengthMax": 20},
            "noises": [{"packet": "rand", "delayMin": 1}]
        }}))
        .expect("parse");
        let fragment = parsed.fragment.expect("fragment 接入 Config");
        assert_eq!(fragment.packets_from, 2);
        assert_eq!(fragment.packets_to, 2);
        assert_eq!(fragment.length_min, 10);
        assert_eq!(fragment.length_max, 20);
        assert_eq!(parsed.noises.len(), 1);
        assert!(parsed.noises[0].packet.is_empty(), "rand → 空包占位");
        assert_eq!(parsed.noises[0].delay_min, 1);
    }

    #[test]
    fn section_without_settings_uses_section_body() {
        // 无 settings 子对象时退化用段本体（装配根自持 fixture 形态）。
        let parsed =
            parse_settings_section(&json!({"protocol": "freedom", "domainStrategy": "UseIPv6"}))
                .expect("parse");
        assert_eq!(parsed.domain_strategy, DomainStrategy::UseIPv6 as i32);
    }
}
