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

use tokio::io::{AsyncRead, AsyncReadExt};
use xray_common::net::destination::Destination;

use crate::config::{Config, DnsRule, RuleAction};
use crate::dns_message::{build_dns_response, parse_dns_query, DnsQuestion};
use crate::error::{DnsProxyError, Result};
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
            rewrite_server: config.rewrite_server.clone().map(|_ep| {
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

    /// 处理一条 DNS 查询，返回决策结果。对应 Go `Handler.Process` 的纯决策部分。
    ///
    /// 本函数不做 IO（dispatcher 模式）：
    /// - 解析 DNS query（`parse_dns_query`）
    /// - `match_rules` 查找首个命中规则
    /// - 按 action 构造 [`ProcessOutcome`] 交由调用方（dispatcher）执行
    ///
    /// action → outcome 映射：
    /// - `Direct` → [`ProcessOutcome::Forward`]（query 原样转给调用方）
    /// - `Drop` → [`ProcessOutcome::Drop`]（不响应）
    /// - `Return` → [`ProcessOutcome::Respond`]（构造 REFUSED 空响应）
    /// - `Hijack` → [`ProcessOutcome::Hijack`]（转给 `rewrite_server`，调用方执行）
    ///
    /// # Errors
    /// - [`DnsProxyError::QueryParseFailed`]：`query` 不是合法 DNS 消息。
    pub async fn process(&self, query: &[u8]) -> Result<ProcessOutcome> {
        let (header, question) = parse_dns_query(query)
            .map_err(|e| DnsProxyError::QueryParseFailed(e.to_string()))?;
        let action = self.match_rules(question.q_type, &question.name);
        let outcome = match action {
            RuleAction::Drop => ProcessOutcome::Drop,
            RuleAction::Return => {
                // Return 动作：REFUSED(5) 空响应
                let response = build_dns_response(&header, &question, 5);
                ProcessOutcome::Respond { response }
            }
            RuleAction::Direct => ProcessOutcome::Forward {
                query: query.to_vec(),
            },
            RuleAction::Hijack => ProcessOutcome::Hijack {
                query: query.to_vec(),
            },
        };
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// DNS over TCP 长度前缀帧（RFC 1035 §4.2.2）
// ---------------------------------------------------------------------------

/// 给 DNS 消息加 TCP 长度前缀（2B BE）。
///
/// TCP DNS 流每条 message 前有 2 字节 big-endian 长度前缀；UDP DNS 无此前缀。
///
/// # Errors
/// - [`DnsProxyError::ResponseBuildFailed`]：`msg.len() > u16::MAX`。
pub fn encode_tcp_dns_message(msg: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(msg.len())
        .map_err(|_| DnsProxyError::ResponseBuildFailed("msg too long for u16".into()))?;
    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    Ok(out)
}

/// 从 TCP 流读取 DNS 消息（去除 2B BE 长度前缀）。
///
/// # Errors
/// - 透传底层 IO 错误（包含 EOF）。
pub async fn decode_tcp_dns_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    reader.read_exact(&mut msg).await?;
    Ok(msg)
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

    // ---- Handler::process E2E ----

    /// 构造最小 DNS A 查询消息。
    fn make_query_bytes(domain: &str, q_type: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xABCDu16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // QNAME 终止
        buf.extend_from_slice(&q_type.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        buf
    }

    /// 辅助：同步阻塞运行 future（避免引入 futures 执行器依赖）。
    fn futures_lite_or_block_on<F>(f: F) -> std::result::Result<ProcessOutcome, DnsProxyError>
    where
        F: std::future::Future<Output = std::result::Result<ProcessOutcome, DnsProxyError>>,
    {
        // ponytail: 用 tokio runtime 阻塞执行（dev-dep 已有 tokio）。
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(f)
    }

    #[test]
    fn process_drop_when_rule_matches() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Drop,
                q_type: vec![1], // A
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("example.com", 1);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        assert!(matches!(outcome, ProcessOutcome::Drop));
    }

    #[test]
    fn process_respond_refused_when_action_return() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Return,
                q_type: vec![1],
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("example.com", 1);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Respond { response } => {
                // 解析响应验证 RCODE=5(REFUSED) + QR=1
                let (header, _) = crate::dns_message::parse_dns_query(&response).expect("parse resp");
                assert!(header.is_response());
                assert_eq!(header.rcode(), 5);
            }
            _ => panic!("expected Respond, got {outcome:?}"),
        }
    }

    #[test]
    fn process_forward_when_action_direct() {
        // 默认配置无规则 → Direct
        let h = Handler::init(&Config::default());
        let query = make_query_bytes("x.com", 28);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Forward { query: q } => assert_eq!(q, query),
            _ => panic!("expected Forward, got {outcome:?}"),
        }
    }

    #[test]
    fn process_hijack_when_action_hijack() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Hijack,
                q_type: vec![], // 匹配所有
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("hijack.example.com", 1);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Hijack { query: q } => assert_eq!(q, query),
            _ => panic!("expected Hijack, got {outcome:?}"),
        }
    }

    #[test]
    fn process_invalid_query_returns_parse_error() {
        let h = Handler::init(&Config::default());
        // 空字节不是合法 DNS 消息
        let err = futures_lite_or_block_on(h.process(&[])).unwrap_err();
        assert!(matches!(err, DnsProxyError::QueryParseFailed(_)));
    }

    // ---- TCP DNS frame helper ----

    #[tokio::test]
    async fn encode_decode_tcp_dns_frame_roundtrip() {
        let msg = b"hello dns over tcp payload";
        let framed = encode_tcp_dns_message(msg).expect("encode");
        // 2B BE len + msg
        assert_eq!(framed.len(), 2 + msg.len());
        assert_eq!(&framed[0..2], &(msg.len() as u16).to_be_bytes());

        let mut cursor = std::io::Cursor::new(framed);
        let got = decode_tcp_dns_message(&mut cursor).await.expect("decode");
        assert_eq!(got, msg);
    }

    #[test]
    fn encode_tcp_dns_message_too_long_errors() {
        let huge = vec![0u8; (u16::MAX as usize) + 1];
        let err = encode_tcp_dns_message(&huge).unwrap_err();
        assert!(matches!(err, DnsProxyError::ResponseBuildFailed(_)));
    }


    #[test]
    fn rewrite_server_none_by_default() {
        let h = Handler::init(&Config::default());
        assert!(h.rewrite_server().is_none());
    }
}
