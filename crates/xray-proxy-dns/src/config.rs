//! DNS 代理配置。
//!
//! 对应 Go `proxy/dns/dns.go` + `config.proto`。
//!
//! ## 协议本质
//!
//! DNS 代理拦截 DNS 查询，按规则（qType + domain）决定动作：直接转发 / 丢弃 /
//! 返回空响应 / 劫持重写。支持把查询重定向到指定上游 DNS 服务器。
//!
//! 实现配置层 + [`DNSRule::match_q_type`] / [`DNSRule::apply`] 纯函数。
//! domain 匹配已接 `xray_geodata` matcher（`SimpleMatcherGroup`，就地编译）；
//! 实际 DNS 转发依赖 `dns::Client` feature + transport::Link。

use std::sync::Arc;

use xray_geodata::matcher::domain::{
    DomainRule as GeoDomainRule, DomainType as GeoDomainType, parse_domain,
};
use xray_geodata::matcher::MatcherGroup;
use crate::error::Result;

/// DNS 规则动作。对应 proto `RuleAction` 枚举。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum RuleAction {
    /// 直接转发（默认）。
    #[default]
    Direct = 0,
    /// 丢弃查询（不响应）。
    Drop = 1,
    /// 返回空响应（REFUSED rCode）。
    Return = 2,
    /// 劫持：重写到 `rewrite_server` 指定的上游。
    Hijack = 3,
}

impl RuleAction {
    /// 从 proto i32 值构造。非法值返回 `Direct`（默认）。
    #[must_use]
    pub fn from_proto_value(v: i32) -> Self {
        match v {
            1 => Self::Drop,
            2 => Self::Return,
            3 => Self::Hijack,
            _ => Self::Direct,
        }
    }

    /// 转换为 proto i32 值。
    #[must_use]
    pub fn to_proto_value(self) -> i32 {
        self as i32
    }
}

/// DNS 规则配置（proto 层）。对应 `xray.proxy.dns.DNSRuleConfig`。
///
/// `domain` 字段在 proto 中是 `repeated DomainRule`，切片1 用 `Vec<u8>` 占位
/// （prost message bytes），切片2 接入强类型 `geodata::DomainRule`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsRuleConfig {
    /// 规则动作。
    pub action: RuleAction,
    /// 匹配的 DNS 查询类型（如 1=A、2=NS、28=AAAA）。空列表匹配所有类型。
    pub q_type: Vec<i32>,
    /// 域名规则（prost message，切片2 接入 geodata::DomainMatcher 强类型匹配）。
    pub domain: Vec<xray_proto::xray::common::geodata::DomainRule>,
    /// 响应码（用于 `Return` 动作）。
    pub r_code: u32,
}

/// DNS 代理主配置。对应 proto `xray.proxy.dns.Config`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    /// 用户等级（用于 policy 查询）。
    pub user_level: u32,
    /// 规则列表（按顺序匹配，首个命中决定动作）。
    pub rule: Vec<DnsRuleConfig>,
    /// 劫持重写的上游 DNS 服务器。None 时不重写。
    pub rewrite_server: Option<xray_proto::xray::common::net::Endpoint>,
}

impl Config {
    /// 从 prost 生成的 proto Config 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::dns::Config) -> Result<Self> {
        Ok(Self {
            user_level: p.user_level,
            rule: p
                .rule
                .into_iter()
                .map(|r| DnsRuleConfig {
                    action: RuleAction::from_proto_value(r.action),
                    q_type: r.q_type,
                    domain: r.domain,
                    r_code: r.r_code,
                })
                .collect(),
            rewrite_server: p.rewrite_server,
        })
    }

    /// 转换为 prost Config。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::dns::Config {
        xray_proto::xray::proxy::dns::Config {
            user_level: self.user_level,
            rule: self
                .rule
                .iter()
                .map(|r| xray_proto::xray::proxy::dns::DnsRuleConfig {
                    action: r.action.to_proto_value(),
                    q_type: r.q_type.clone(),
                    domain: r.domain.clone(),
                    r_code: r.r_code,
                })
                .collect(),
            rewrite_server: self.rewrite_server.clone(),
        }
    }
}

/// 运行时 DNS 规则（含编译后的 qType 列表 + 域名匹配器）。对应 Go `dns.go::DNSRule`。
///
/// `domains` 用 geodata `SimpleMatcherGroup`（strmatcher 基建，支持
/// Full/Domain/Substr/Regex 全类型线性匹配，与 Go `BuildDomainMatcher` 语义对齐）。
 #[derive(Debug, Clone)]
 pub struct DnsRule {
     /// 规则动作。
     pub action: RuleAction,
     /// 匹配的 DNS 查询类型（已转为 u16）。空列表匹配所有类型。
     pub q_types: Vec<u16>,
     /// rCode（用于 `Return` 动作）。
     pub r_code: u16,
    /// 编译后的域名匹配器。
    ///
    /// - `None`：配置未填 domains → 恒真（Go `domains==nil`）
    /// - `Some(空组)`：domains 非空但全部条目解析失败 → 永不命中（fail-closed）
    domains: Option<Arc<xray_geodata::matcher::SimpleMatcherGroup>>,
 }

impl DnsRule {
    /// 从 [`DnsRuleConfig`] 构造运行时规则。
    ///
    /// - `q_type` → u16 列表；`domain` → 就地编译为匹配器组。
    /// - proto `geosite` 变体需 geo dat 文件加载器，DNS 代理配置路径未持有
    ///   datadir：warn + 跳过该条目（对齐 router 无 loader 时的降级）。
    #[must_use]
    pub fn from_config(cfg: &DnsRuleConfig) -> Self {
        let mut group = xray_geodata::matcher::SimpleMatcherGroup::new();
        for (i, r) in cfg.domain.iter().enumerate() {
            let Some(value) = r.value.as_ref() else { continue };
            match value {
                xray_proto::xray::common::geodata::domain_rule::Value::Custom(d) => {
                    // proto Domain.Type：Substr=0, Regex=1, Domain=2, Full=3
                    // （与 matcher DomainType：Full=0/Domain=1/Substr=2/Regex=3 不同序）
                    let dt = match d.r#type {
                        0 => GeoDomainType::Substr,
                        1 => GeoDomainType::Regex,
                        2 => GeoDomainType::Domain,
                        3 => GeoDomainType::Full,
                        other => {
                            tracing::warn!(target: "xray_proxy_dns::config", domain_type = other, "unknown domain rule type, skipping");
                            continue;
                        }
                    };
                    let rule = GeoDomainRule::new(dt, d.value.clone(), (i + 1) as u32);
                    match parse_domain(&rule) {
                        Ok(m) => group.add(m, (i + 1) as u32),
                        Err(e) => {
                            tracing::error!(target: "xray_proxy_dns::config", error = %e, value = %d.value, "domain rule parse failed; entry skipped");
                        }
                    }
                }
                xray_proto::xray::common::geodata::domain_rule::Value::Geosite(g) => {
                    tracing::warn!(target: "xray_proxy_dns::config", file = %g.file, code = %g.code, "geosite domain rule present but no geo_loader on DNS proxy path, skipping");
                }
            }
        }
        let domains = if cfg.domain.is_empty() {
            None
        } else {
            Some(Arc::new(group))
        };
        Self {
            action: cfg.action,
            q_types: cfg.q_type.iter().map(|&v| v as u16).collect(),
            r_code: cfg.r_code as u16,
            domains,
        }
    }

    /// 检查 qType 是否匹配本规则。
    ///
    /// - 空列表 → 匹配所有类型（与 Go `matchQType` 一致）
    /// - 非空 → 列表中含 `q_type` 则匹配
    ///
    /// 对应 Go `dns.go::DNSRule.matchQType`。
    #[must_use]
    pub fn match_q_type(&self, q_type: u16) -> bool {
        if self.q_types.is_empty() {
            return true;
        }
        self.q_types.contains(&q_type)
    }

    /// 完整匹配检查（qType + domain）。
    ///
    /// 对应 Go `dns.go::DNSRule.Apply`：
    /// `matchQType(qType) && (domains == nil || domains.MatchAny(TrimSuffix(ToLower(domain), ".")))`。
    #[must_use]
    pub fn apply(&self, q_type: u16, domain: &str) -> bool {
        if !self.match_q_type(q_type) {
            return false;
        }
        let Some(group) = self.domains.as_ref() else {
            return true; // 空 domains 恒真（Go domains==nil）
        };
        let lower = domain.to_lowercase();
        let lower = lower.strip_suffix('.').unwrap_or(&lower);
        group.match_any(lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== RuleAction =====

    #[test]
    fn rule_action_proto_roundtrip() {
        let cases = [
            (0, RuleAction::Direct),
            (1, RuleAction::Drop),
            (2, RuleAction::Return),
            (3, RuleAction::Hijack),
        ];
        for (v, expected) in cases {
            assert_eq!(RuleAction::from_proto_value(v), expected);
            assert_eq!(expected.to_proto_value(), v);
        }
    }

    #[test]
    fn rule_action_invalid_defaults_to_direct() {
        assert_eq!(RuleAction::from_proto_value(99), RuleAction::Direct);
        assert_eq!(RuleAction::from_proto_value(-1), RuleAction::Direct);
    }

    // ===== DNSRule::match_q_type =====

    #[test]
    fn match_q_type_empty_matches_all() {
        let rule = DnsRule {
            action: RuleAction::Direct,
            q_types: vec![],
            r_code: 0,
            domains: None,
        };
        assert!(rule.match_q_type(1)); // A
        assert!(rule.match_q_type(28)); // AAAA
        assert!(rule.match_q_type(255)); // ANY
    }

    #[test]
    fn match_q_type_specific_list() {
        let rule = DnsRule {
            action: RuleAction::Drop,
            q_types: vec![1, 28], // A, AAAA
            r_code: 0,
            domains: None,
        };
        assert!(rule.match_q_type(1));
        assert!(rule.match_q_type(28));
        assert!(!rule.match_q_type(2)); // NS
        assert!(!rule.match_q_type(15)); // MX
    }

    #[test]
    fn apply_q_type_gate_with_empty_domains() {
        let rule = DnsRule {
            action: RuleAction::Drop,
            q_types: vec![1],
            r_code: 0,
            domains: None,
        };
        // qType 匹配 + 空 domains 恒真 → true
        assert!(rule.apply(1, "example.com"));
        // qType 不匹配 → false
        assert!(!rule.apply(28, "example.com"));
    }

    #[test]
    fn from_config_converts_qtypes_to_u16() {
        let cfg = DnsRuleConfig {
            action: RuleAction::Hijack,
            q_type: vec![1, 2, 28],
            r_code: 5,
            ..Default::default()
        };
        let rule = DnsRule::from_config(&cfg);
        assert_eq!(rule.action, RuleAction::Hijack);
        assert_eq!(rule.q_types, vec![1, 2, 28]);
        assert_eq!(rule.r_code, 5);
    }

    // ===== Config proto roundtrip =====

    #[test]
    fn proto_roundtrip_minimal() {
        let cfg = Config {
            user_level: 0,
            rule: vec![],
            rewrite_server: None,
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn proto_roundtrip_with_rules() {
        let cfg = Config {
            user_level: 1,
            rule: vec![
                DnsRuleConfig {
                    action: RuleAction::Drop,
                    q_type: vec![1, 28],
                    r_code: 0,
                    ..Default::default()
                },
                DnsRuleConfig {
                    action: RuleAction::Return,
                    q_type: vec![],
                    r_code: 5, // REFUSED
                    ..Default::default()
                },
            ],
            rewrite_server: None,
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg.user_level, cfg2.user_level);
        assert_eq!(cfg.rule.len(), cfg2.rule.len());
        assert_eq!(cfg.rule[0].action, cfg2.rule[0].action);
        assert_eq!(cfg.rule[0].q_type, cfg2.rule[0].q_type);
        assert_eq!(cfg.rule[1].action, cfg2.rule[1].action);
        assert_eq!(cfg.rule[1].r_code, cfg2.rule[1].r_code);
    }

    // ===== DnsRule domain 匹配（geodata matcher 接线）=====

    /// proto geodata `Domain`（Custom 变体）。
    fn custom_domain(ty: i32, value: &str) -> xray_proto::xray::common::geodata::DomainRule {
        xray_proto::xray::common::geodata::DomainRule {
            value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Custom(
                xray_proto::xray::common::geodata::Domain {
                    r#type: ty,
                    value: value.into(),
                    ..Default::default()
                },
            )),
        }
    }

    fn rule_with_domains(
        domain: Vec<xray_proto::xray::common::geodata::DomainRule>,
    ) -> DnsRule {
        DnsRule::from_config(&DnsRuleConfig {
            action: RuleAction::Drop,
            q_type: vec![],
            domain,
            r_code: 0,
        })
    }

    #[test]
    fn domain_full_match_hit_and_miss() {
        // proto Type::Full = 3：精确等值
        let rule = rule_with_domains(vec![custom_domain(3, "example.com")]);
        assert!(rule.apply(1, "example.com"));
        assert!(!rule.apply(1, "a.example.com"), "Full 不做子域匹配");
        assert!(!rule.apply(1, "notexample.com"));
    }

    #[test]
    fn domain_suffix_match_hit_and_miss() {
        // proto Type::Domain = 2：自身 + 子域
        let rule = rule_with_domains(vec![custom_domain(2, "example.com")]);
        assert!(rule.apply(1, "example.com"));
        assert!(rule.apply(1, "www.example.com"));
        assert!(!rule.apply(1, "notexample.com"), "无点边界不命中");
    }

    #[test]
    fn domain_substr_and_regex_match() {
        // proto Type::Substr = 0：子串包含
        let rule = rule_with_domains(vec![custom_domain(0, "ads")]);
        assert!(rule.apply(1, "ads.example.com"));
        assert!(rule.apply(1, "example.adsx"));
        assert!(!rule.apply(1, "example.com"));
        // proto Type::Regex = 1：正则
        let rule = rule_with_domains(vec![custom_domain(1, r"^a.*\.org$")]);
        assert!(rule.apply(1, "a.example.org"));
        assert!(!rule.apply(1, "b.example.org"));
    }

    #[test]
    fn domain_empty_is_always_true() {
        // 空 domains 恒真（Go domains==nil）
        let rule = rule_with_domains(vec![]);
        assert!(rule.apply(1, "anything.net"));
    }

    #[test]
    fn domain_match_is_case_insensitive_and_trims_trailing_dot() {
        // Go Apply：TrimSuffix(ToLower(domain), ".")
        let rule = rule_with_domains(vec![custom_domain(3, "example.com")]);
        assert!(rule.apply(1, "EXAMPLE.COM"));
        assert!(rule.apply(1, "Example.com."));
    }

    #[test]
    fn geosite_entry_without_loader_makes_rule_inert() {
        // geosite 变体无 datadir 加载器：条目跳过；非空 domains 剩空组 →
        // 永不命中（fail-closed，而非恒真误放大规则范围）
        let rule = rule_with_domains(vec![xray_proto::xray::common::geodata::DomainRule {
            value: Some(xray_proto::xray::common::geodata::domain_rule::Value::Geosite(
                xray_proto::xray::common::geodata::GeoSiteRule {
                    file: "geosite.dat".into(),
                    code: "cn".into(),
                    attrs: String::new(),
                },
            )),
        }]);
        assert!(!rule.apply(1, "baidu.com"));
    }

    #[test]
    fn qtype_gate_still_applies_before_domain() {
        let rule = DnsRule::from_config(&DnsRuleConfig {
            action: RuleAction::Drop,
            q_type: vec![1], // A only
            domain: vec![custom_domain(3, "example.com")],
            r_code: 0,
        });
        assert!(rule.apply(1, "example.com"));
        assert!(!rule.apply(28, "example.com"), "qType 不匹配直接短路");
    }

    #[test]
    fn default_config_empty() {
        let cfg = Config::default();
        assert_eq!(cfg.user_level, 0);
        assert!(cfg.rule.is_empty());
        assert!(cfg.rewrite_server.is_none());
    }
}
