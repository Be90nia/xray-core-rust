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

use crate::{
    config::{Config, DnsRule, RuleAction},
    dns_message::{DnsQuestion, build_dns_response, parse_dns_query},
    error::{DnsProxyError, Result},
};
/// DNS 代理 Handler。对应 Go `proxy/dns/dns.go::Handler` struct。
#[derive(Debug, Clone)]
pub struct Handler {
    /// 编译后的规则列表（按配置顺序）。
    rules: Vec<DnsRule>,
    /// 重写上游 DNS 服务器（network/address/port 三字段独立覆盖）。
    /// 对应 Go `rewriteServer` + `Process` 中逐字段覆盖 dest 的逻辑。
    rewrite: RewriteOverrides,
    /// 查询超时。对应 Go `timeout`（从 `policy` 获取）。
    pub timeout: Duration,
}

/// rewriteServer 字段级覆盖。对应 Go `net.Destination` 三字段非零覆盖语义。
#[derive(Debug, Clone, Default)]
pub struct RewriteOverrides {
    /// 覆盖网络类型（proto network != Unknown 时生效）。
    pub network: Option<xray_common::net::network::Network>,
    /// 覆盖地址。
    pub address: Option<xray_common::net::address::Address>,
    /// 覆盖端口（proto port != 0 时生效）。
    pub port: Option<xray_common::net::port::Port>,
}

/// prost Endpoint → 字段级覆盖（Go `rewriteServer.AsDestination()` 的覆盖语义）。
fn prost_endpoint_to_overrides(ep: &xray_proto::xray::common::net::Endpoint) -> RewriteOverrides {
    use xray_common::net::{address::Address, network::Network, port::Port};

    let network = xray_proto::xray::common::net::Network::try_from(ep.network)
        .ok()
        .filter(|n| *n != xray_proto::xray::common::net::Network::Unknown)
        .map(|n| match n {
            xray_proto::xray::common::net::Network::Tcp => Network::TCP,
            _ => Network::UDP,
        });
    let address = ep.address.as_ref().and_then(|iod| iod.address.as_ref()).map(|a| match a {
        xray_proto::xray::common::net::ip_or_domain::Address::Ip(bytes) => {
            if bytes.len() == 4 {
                let mut b = [0u8; 4];
                b.copy_from_slice(bytes);
                Address::IPv4(std::net::Ipv4Addr::from(b))
            } else {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes[..16.min(bytes.len())]);
                Address::IPv6(std::net::Ipv6Addr::from(b))
            }
        },
        xray_proto::xray::common::net::ip_or_domain::Address::Domain(d) => {
            Address::Domain(d.clone())
        },
    });
    let port = u16::try_from(ep.port).ok().filter(|p| *p != 0).map(Port::new);
    RewriteOverrides { network, address, port }
}

impl Handler {
    /// 从配置初始化 Handler。对应 Go `Handler.Init(config, dnsClient, policyManager)`。
    ///
    /// Rust 切片不注入 `dns.Client` + `policy.Manager`（由生产装配层
    /// `DnsDispatchBridge` 持有 DnsService），超时用固定值。
    pub fn init(config: &Config) -> Self {
        let rules: Vec<DnsRule> = config.rule.iter().map(DnsRule::from_config).collect();
        let rewrite =
            config.rewrite_server.as_ref().map(prost_endpoint_to_overrides).unwrap_or_default();
        Self { rules, rewrite, timeout: Duration::from_secs(5) }
    }

    /// 查找首个匹配的规则，返回 `(action, rCode)`。
    ///
    /// 对应 Go `applyRules`：无规则命中时默认 A/AAAA → `Hijack`（内部
    /// DNS 客户端解析，可触发 FakeDNS），其余类型 → `Return`（空响应）。
    #[must_use]
    pub fn match_rules(&self, q_type: u16, domain: &str) -> (RuleAction, u16) {
        for rule in &self.rules {
            if rule.apply(q_type, domain) {
                return (rule.action, rule.r_code);
            }
        }
        if q_type == QTYPE_A || q_type == QTYPE_AAAA {
            (RuleAction::Hijack, 0)
        } else {
            (RuleAction::Return, 0)
        }
    }

    /// 应用 rewriteServer 覆盖。对应 Go `Process` 开头的 dest 三字段覆盖。
    #[must_use]
    pub fn rewrite_dest(&self, base: &Destination) -> Destination {
        let mut dest = base.clone();
        if let Some(n) = self.rewrite.network {
            dest = dest.with_network(n);
        }
        if self.rewrite.address.is_some() || self.rewrite.port.is_some() {
            let address = self.rewrite.address.clone().unwrap_or_else(|| base.address().clone());
            let port = self.rewrite.port.unwrap_or(base.port());
            dest = Destination::new(address, port, dest.network());
        }
        dest
    }

    /// 是否配置了 rewriteServer。
    #[must_use]
    pub fn has_rewrite(&self) -> bool {
        self.rewrite.network.is_some()
            || self.rewrite.address.is_some()
            || self.rewrite.port.is_some()
    }

    /// 规则数量。
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 处理一条 DNS 查询，返回决策结果（`process` 的纯决策核心，无 IO）。
    ///
    /// # Errors
    /// - [`DnsProxyError::QueryParseFailed`]：`query` 不是合法 DNS 消息。
    pub async fn process(&self, query: &[u8]) -> Result<ProcessOutcome> {
        let (header, question) =
            parse_dns_query(query).map_err(|e| DnsProxyError::QueryParseFailed(e.to_string()))?;
        let (action, r_code) = self.match_rules(question.q_type, &question.name);
        let outcome = match action {
            RuleAction::Drop => ProcessOutcome::Drop,
            RuleAction::Return => {
                // Go rejectNonIPQuery：空域名（去尾点后）不构造响应。
                if question.name.trim_end_matches('.').is_empty() {
                    ProcessOutcome::Drop
                } else {
                    ProcessOutcome::Respond {
                        response: build_dns_response(&header, &question, r_code as u8),
                    }
                }
            },
            RuleAction::Direct => ProcessOutcome::Forward { query: query.to_vec() },
            RuleAction::Hijack => {
                // Go：非 A/AAAA 劫持 → rejectNonIPQuery（按规则 rCode 拒绝）。
                if question.q_type != QTYPE_A && question.q_type != QTYPE_AAAA {
                    if question.name.trim_end_matches('.').is_empty() {
                        ProcessOutcome::Drop
                    } else {
                        ProcessOutcome::Respond {
                            response: build_dns_response(&header, &question, r_code as u8),
                        }
                    }
                } else {
                    ProcessOutcome::Hijack { query: query.to_vec() }
                }
            },
        };
        Ok(outcome)
    }
}

/// DNS QTYPE 常量（RFC 1035 §3.2.3）。
pub const QTYPE_A: u16 = 1;
/// AAAA 记录类型（RFC 3596）。
pub const QTYPE_AAAA: u16 = 28;

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

/// 对 DNS Question 应用 Handler 规则，返回决策结果（action）。
///
/// 这是 `process` 的纯函数核心——不涉及 IO，便于测试。
#[must_use]
pub fn decide_action(handler: &Handler, question: &DnsQuestion) -> RuleAction {
    handler.match_rules(question.q_type, &question.name).0
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
        assert_eq!(h.match_rules(28, "any.com"), (RuleAction::Drop, 0));
        // A 不匹配规则 → Go 默认 A/AAAA = Hijack（dns.go:148-150）
        assert_eq!(h.match_rules(1, "any.com"), (RuleAction::Hijack, 0));
    }

    #[test]
    fn match_rules_first_match_wins() {
        let cfg = Config {
            rule: vec![
                DnsRuleConfig {
                    action: RuleAction::Return,
                    q_type: vec![1, 28], // A + AAAA
                    r_code: 5,
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
        // A 匹配第一条规则（Return + rCode 5 透传）
        assert_eq!(h.match_rules(1, "x.com"), (RuleAction::Return, 5));
        // AAAA 只匹配第一条规则
        assert_eq!(h.match_rules(28, "x.com"), (RuleAction::Return, 5));
        // 其他类型不匹配任何规则 → Go 默认非 A/AAAA = Return（rCode 0）
        assert_eq!(h.match_rules(15, "x.com"), (RuleAction::Return, 0)); // MX
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
        assert_eq!(h.match_rules(1, "a.com"), (RuleAction::Hijack, 0));
        assert_eq!(h.match_rules(28, "b.com"), (RuleAction::Hijack, 0));
        assert_eq!(h.match_rules(255, "c.com"), (RuleAction::Hijack, 0));
    }

    /// Go applyRules 无匹配默认：A/AAAA → Hijack；其余 → Return。
    #[test]
    fn match_rules_defaults_a_hijack_others_return() {
        let h = Handler::init(&Config::default());
        assert_eq!(h.match_rules(1, "a.com"), (RuleAction::Hijack, 0));
        assert_eq!(h.match_rules(28, "b.com"), (RuleAction::Hijack, 0));
        assert_eq!(h.match_rules(15, "mx.com"), (RuleAction::Return, 0));
        assert_eq!(h.match_rules(16, "txt.com"), (RuleAction::Return, 0));
    }

    /// rewriteServer 三字段独立覆盖（Go dns.go:166-174）。
    #[test]
    fn rewrite_dest_overrides_fields_independently() {
        use xray_common::net::{address::Address, port::Port};

        let base = Destination::udp(Address::IPv4("8.8.8.8".parse().unwrap()), Port::new(53));

        // 未配置 → 原样。
        let h = Handler::init(&Config::default());
        assert!(!h.has_rewrite());
        assert_eq!(h.rewrite_dest(&base), base);

        // 仅重写端口（Go: RewriteServer.Port != 0 覆盖 port）。
        let cfg = Config {
            rewrite_server: Some(xray_proto::xray::common::net::Endpoint {
                network: 0, // Unknown → 不覆盖
                address: None,
                port: 5353,
            }),
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        assert!(h.has_rewrite());
        let d = h.rewrite_dest(&base);
        assert_eq!(d.port().value(), 5353);
        assert_eq!(*d.address(), base.address().clone());
        assert!(d.is_udp());

        // network=TCP + domain + port 全覆盖。
        let cfg = Config {
            rewrite_server: Some(xray_proto::xray::common::net::Endpoint {
                network: 2, // TCP（xray.common.net.Network.TCP = 2）
                address: Some(xray_proto::xray::common::net::IpOrDomain {
                    address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Domain(
                        "dns.example.com".into(),
                    )),
                }),
                port: 853,
            }),
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let d = h.rewrite_dest(&base);
        assert!(d.is_tcp());
        assert_eq!(d.port().value(), 853);
        assert_eq!(*d.address(), Address::Domain("dns.example.com".into()));
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
        let q = DnsQuestion { name: "example.com".into(), q_type: 1, q_class: 1 };
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
    fn process_respond_uses_rule_rcode() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Return,
                q_type: vec![1],
                r_code: 5, // REFUSED
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("example.com", 1);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Respond { response } => {
                let (header, _) =
                    crate::dns_message::parse_dns_query(&response).expect("parse resp");
                assert!(header.is_response());
                assert_eq!(header.rcode(), 5);
            },
            _ => panic!("expected Respond, got {outcome:?}"),
        }

        // rCode 未配置（默认 0）→ rcode 0 空响应。
        let cfg0 = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Return,
                q_type: vec![1],
                ..Default::default()
            }],
            ..Default::default()
        };
        let h0 = Handler::init(&cfg0);
        let outcome = futures_lite_or_block_on(h0.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Respond { response } => {
                let (header, _) =
                    crate::dns_message::parse_dns_query(&response).expect("parse resp");
                assert_eq!(header.rcode(), 0);
            },
            _ => panic!("expected Respond, got {outcome:?}"),
        }
    }

    #[test]
    fn process_forward_when_action_direct() {
        // 显式 Direct 规则（无规则时 A/AAAA 默认 Hijack）。
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Direct,
                q_type: vec![28],
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("x.com", 28);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Forward { query: q } => assert_eq!(q, query),
            _ => panic!("expected Forward, got {outcome:?}"),
        }
    }

    /// 无规则 + A 查询 → 默认 Hijack（Go dns.go:148）。
    #[test]
    fn process_default_a_query_hijacks() {
        let h = Handler::init(&Config::default());
        let query = make_query_bytes("default.example.com", 1);
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        assert!(matches!(outcome, ProcessOutcome::Hijack { .. }));
    }

    /// 无规则 + TXT 查询 → 默认 Return 空响应（Go dns.go:150-151）。
    #[test]
    fn process_default_txt_query_returns_empty() {
        let h = Handler::init(&Config::default());
        let query = make_query_bytes("default.example.com", 16); // TXT
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Respond { response } => {
                let (header, _) =
                    crate::dns_message::parse_dns_query(&response).expect("parse resp");
                assert!(header.is_response());
                assert_eq!(header.rcode(), 0);
            },
            _ => panic!("expected Respond, got {outcome:?}"),
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

    /// Hijack 规则命中非 A/AAAA → rejectNonIPQuery（Go dns.go:268-272）。
    #[test]
    fn process_hijack_non_ip_query_rejects() {
        let cfg = Config {
            rule: vec![DnsRuleConfig {
                action: RuleAction::Hijack,
                q_type: vec![], // 匹配所有
                r_code: 5,
                ..Default::default()
            }],
            ..Default::default()
        };
        let h = Handler::init(&cfg);
        let query = make_query_bytes("txt.example.com", 16); // TXT
        let outcome = futures_lite_or_block_on(h.process(&query)).expect("process");
        match outcome {
            ProcessOutcome::Respond { response } => {
                let (header, _) =
                    crate::dns_message::parse_dns_query(&response).expect("parse resp");
                assert_eq!(header.rcode(), 5);
            },
            _ => panic!("expected Respond, got {outcome:?}"),
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
        assert!(!h.has_rewrite());
    }
}
