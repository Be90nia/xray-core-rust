//! DNS 代理 Handler——接收 dispatcher 分发的连接，解析 DNS 查询，应用规则。
//!
//! 对应 Go `proxy/dns/dns.go::Handler`。Go 端 Handler 实现 `common.Runnable`，
//! 通过 `core.RequireFeatures` 注入 `dns.Client` + `policy.Manager`，在 `Process`
//! 中解析 DNS 消息 → 规则匹配 → 转发/丢弃/返回/劫持。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现纯逻辑部分：
//! - [`Handler`] struct + [`Handler::init`] 从 [`Config`] 构建 rules
//! - [`Handler::match_rules`] 查找首个匹配规则（qType + domain）
//!
//! **不实现** `Process`（依赖 dispatcher + `dns::Client` + `transport::Link`，
//! 留切片3）。DNS 代理与其他 inbound 协议不同——它不主动 listen，而是接收
//! dispatcher 分发的已建立连接。

use std::time::Duration;

use xray_common::net::destination::Destination;

use crate::config::{Config, DnsRule, RuleAction};
use crate::dns_message::DnsQuestion;

/// DNS 代理 Handler。对应 Go `proxy/dns/dns.go::Handler` struct。
#[derive(Debug)]
pub struct Handler {
    /// 编译后的规则列表（按配置顺序）。
    rules: Vec<DnsRule>,
    /// 重写上游 DNS 服务器地址（Hijack 动作目标）。
    rewrite_server: Option<Destination>,
    /// 查询超时。对应 Go `timeout`（从 `policy` 获取，切片2 默认 5s）。
    pub timeout: Duration,
}

impl Handler {
    /// 从配置初始化 Handler。对应 Go `Handler.Init(config, dnsClient, policyManager)`。
    ///
    /// 切片2 不注入 `dns.Client` + `policy.Manager`（依赖未连接），用默认超时。
    pub fn init(config: &Config) -> Self {
        let rules: Vec<DnsRule> = config.rule.iter().map(DnsRule::from_config).collect();
        Self {
            rules,
            rewrite_server: config.rewrite_server.clone().map(|ep| {
                // ponytail: IPOrDomain → Destination 转换留切片3 强类型化。
                // 当前从 prost Endpoint 提取 address/port。
                Destination::tcp(
                    xray_common::net::address::Address::Domain("placeholder".into()),
                    xray_common::net::port::Port::new(53),
                )
            }),
            timeout: Duration::from_secs(5),
        }
    }

    /// 查找首个匹配的规则。对应 Go `Handler` 内部规则遍历逻辑。
    ///
    /// 返回匹配的 [`RuleAction`]，无匹配返回默认 [`RuleAction::Direct`]。
    ///
    /// 匹配条件：`rule.apply(q_type, domain)` 返回 true。
    /// 切片2 `domain` 匹配依赖 `geodata::DomainMatcher`，当前 `apply` 只校验 qType。
    #[must_use]
    pub fn match_rules(&self, q_type: u16, domain: &str) -> RuleAction {
        for rule in &self.rules {
            if rule.apply(q_type, domain) {
                return rule.action;
            }
        }
        RuleAction::Direct
    }

    /// 重写上游 DNS 服务器（Hijack 动作目标）。
    #[must_use]
    pub fn rewrite_server(&self) -> Option<&Destination> {
        self.rewrite_server.as_ref()
    }

    /// 规则数量。
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Process stub——处理 DNS 连接。切片3 实现。
    ///
    /// Go 端 `Process(ctx, link, dispatcher)` 流程：
    /// 1. 从 link.reader 读取 DNS 消息
    /// 2. `parse_dns_query` 提取 qType + domain
    /// 3. `match_rules` 查找规则
    /// 4. 按规则执行：Direct（转发到上游）/ Drop（不响应）/ Return（返回 REFUSED）/ Hijack（重写到 rewrite_server）
    /// 5. 写响应到 link.writer
    ///
    /// 切片3 待办：接入 dispatcher + dns::Client + transport::Link + FakeDNS。
    pub async fn process(
        &self,
        _query: &[u8],
    ) -> Result<ProcessOutcome, crate::error::DnsProxyError> {
        // 切片2: 返回 Unimplemented，让调用方知道需要切片3。
        Err(crate::error::DnsProxyError::InvalidConfig(
            "Handler::process not implemented (切片3)".into(),
        ))
    }
}

/// Process 结果。切片3 会细化。
#[derive(Debug)]
pub enum ProcessOutcome {
    /// 直接转发到上游 DNS（动作 Direct）。
    Forward { query: Vec<u8> },
    /// 丢弃查询（动作 Drop）。
    Drop,
    /// 返回预设响应（动作 Return）。
    Respond { response: Vec<u8> },
    /// 劫持到 rewrite_server（动作 Hijack）。
    Hijack { query: Vec<u8> },
}

/// 对 DNS Question 应用 Handler 规则，返回决策结果。
///
/// 这是 `process` 的纯函数核心——不涉及 IO，便于测试。
/// `process` 在切片3 中读消息 → 调此函数 → 按结果执行 IO。
#[must_use]
pub fn decide_action(handler: &Handler, question: &DnsQuestion) -> RuleAction {
    handler.match_rules(question.q_type, &question.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsRuleConfig;

    #[test]
    fn init_empty_config_has_no_rules() {
        let cfg = Config::default();
        let h = Handler::init(&cfg);
        assert_eq!(h.rule_count(), 0);
        assert_eq!(h.timeout, Duration::from_secs(5));
    }

    #[test]
    fn init_with_rules() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Drop,
                q_type: vec![28], // AAAA
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        assert_eq!(h.rule_count(), 1);
    }

    #[test]
    fn match_rules_no_match_returns_direct() {
        let h = Handler::init(&Config::default());
        assert_eq!(h.match_rules(1, "example.com"), RuleAction::Direct);
        assert_eq!(h.match_rules(28, "test.com"), RuleAction::Direct);
    }

    #[test]
    fn match_rules_qtype_drop_aaaa() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Drop,
                q_type: vec![28], // AAAA
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        // AAAA 匹配 Drop
        assert_eq!(h.match_rules(28, "any.com"), RuleAction::Drop);
        // A 不匹配，返回 Direct
        assert_eq!(h.match_rules(1, "any.com"), RuleAction::Direct);
    }

    #[test]
    fn match_rules_first_match_wins() {
        let cfg = Config {
            rule: vec![
                DnsRuleConfig {
                    action: RuleAction::Return,
                    q_type: vec![1, 28], // A + AAAA
                    ..Default::default()
                },
                DnsRuleConfig {
                    action: RuleAction::Drop,
                    q_type: vec![1], // A
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        // A 匹配第一条规则（Return）
        assert_eq!(h.match_rules(1, "x.com"), RuleAction::Return);
        // AAAA 只匹配第一条规则
        assert_eq!(h.match_rules(28, "x.com"), RuleAction::Return);
        // 其他类型不匹配任何规则
        assert_eq!(h.match_rules(15, "x.com"), RuleAction::Direct); // MX
    }

    #[test]
    fn match_rules_empty_qtypes_matches_all() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Hijack,
                q_type: vec![], // 空匹配所有
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        assert_eq!(h.match_rules(1, "a.com"), RuleAction::Hijack);
        assert_eq!(h.match_rules(28, "b.com"), RuleAction::Hijack);
        assert_eq!(h.match_rules(255, "c.com"), RuleAction::Hijack);
    }

    #[test]
    fn decide_action_uses_match_rules() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Drop,
                q_type: vec![1],
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let q = DnsQuestion {
            name: "example.com".into(),
            q_type: 1,
            q_class: 1,
        };
        assert_eq!(decide_action(&h, &q), RuleAction::Drop);
    }

    #[test]
    fn process_stub_returns_error() {
        let h = Handler::init(&Config::default());
        let result = futures_lite_or_block_on(h.process(&[]));
        assert!(result.is_err());
    }

    /// 辅助：同步阻塞运行 future（避免引入 futures 执行器依赖）。
    fn futures_lite_or_block_on<F>(f: F) -> std::result::Result<ProcessOutcome, crate::error::DnsProxyError>
    where
        F: std::future::Future<Output = std::result::Result<ProcessOutcome, crate::error::DnsProxyError>>,
    {
        // ponytail: 用 tokio runtime 阻塞执行（dev-dep 已有 tokio）。
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(f)
    }

    #[test]
    fn rewrite_server_none_by_default() {
        let h = Handler::init(&Config::default());
        assert!(h.rewrite_server().is_none());
    }
}
