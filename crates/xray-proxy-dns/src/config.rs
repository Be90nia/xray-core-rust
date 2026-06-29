//! DNS 代理配置。
//!
//! 对应 Go `proxy/dns/dns.go` + `config.proto`。
//!
//! ## 协议本质
//!
//! DNS 代理拦截 DNS 查询，按规则（qType + domain）决定动作：直接转发 / 丢弃 /
//! 返回空响应 / 劫持重写。支持把查询重定向到指定上游 DNS 服务器。
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 实现配置层 + [`DNSRule::match_q_type`] 纯函数。domain 匹配依赖
//! `geodata::DomainMatcher`（切片2），实际 DNS 转发依赖 `dns::Client` feature
//! （切片2）+ transport::Link。

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

/// 运行时 DNS 规则（含编译后的 qType 列表）。对应 Go `dns.go::DNSRule`。
///
/// `domains` 字段依赖 `geodata::DomainMatcher`，切片2 接入。
#[derive(Debug, Clone)]
pub struct DnsRule {
    /// 规则动作。
    pub action: RuleAction,
    /// 匹配的 DNS 查询类型（已转为 u16）。空列表匹配所有类型。
    pub q_types: Vec<u16>,
    /// rCode（用于 `Return` 动作）。
    pub r_code: u16,
    // domains: Option<geodata::DomainMatcher> 留切片2
}

impl DnsRule {
    /// 从 [`DnsRuleConfig`] 构造运行时规则。
    ///
    /// 切片1 仅转换 qType 与 action；domain 匹配器留切片2。
    #[must_use]
    pub fn from_config(cfg: &DnsRuleConfig) -> Self {
        Self {
            action: cfg.action,
            q_types: cfg.q_type.iter().map(|&v| v as u16).collect(),
            r_code: cfg.r_code as u16,
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
    /// 切片1 只校验 qType（domain 匹配留切片2，当前视为匹配）。
    /// 返回 `true` 表示规则命中。
    ///
    /// 对应 Go `dns.go::DNSRule.Apply`（domain 部分未实现）。
    #[must_use]
    pub fn apply(&self, q_type: u16, _domain: &str) -> bool {
        if !self.match_q_type(q_type) {
            return false;
        }
        // ponytail: domain 匹配留切片2，当前视为匹配（与 Go domains==nil 一致）
        true
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
        };
        assert!(rule.match_q_type(1));
        assert!(rule.match_q_type(28));
        assert!(!rule.match_q_type(2)); // NS
        assert!(!rule.match_q_type(15)); // MX
    }

    #[test]
    fn apply_q_type_only_when_domain_unimplemented() {
        let rule = DnsRule {
            action: RuleAction::Drop,
            q_types: vec![1],
            r_code: 0,
        };
        // qType 匹配 → true（domain 当前视为匹配）
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

    #[test]
    fn default_config_empty() {
        let cfg = Config::default();
        assert_eq!(cfg.user_level, 0);
        assert!(cfg.rule.is_empty());
        assert!(cfg.rewrite_server.is_none());
    }
}
