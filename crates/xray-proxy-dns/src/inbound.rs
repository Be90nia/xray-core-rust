//! DNS inbound——接收 DNS 查询，应用规则，路由到 outbound。
//!
//! 对应 Go `proxy/dns/dns.go::Handler.Process`。Go 端 Handler 实现 `Runnable`，
//! 在 Process 中读取 DNS 消息 → 决策 → 转发/丢弃/返回/劫持。
//!
//! ## 与其他 inbound 的区别
//!
//! DNS 代理不主动 listen，而是由 dispatcher 分发已建立的连接/数据包：
//! - UDP：dispatcher 接收 UDP 包 → 调 [`DnsInbound::handle_packet`]
//! - TCP：dispatcher accept 连接 → 调 [`DnsInbound::handle_conn`]

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::error::{DnsProxyError, Result};
use crate::handler::{decode_tcp_dns_message, encode_tcp_dns_message, Handler, ProcessOutcome};
use crate::outbound::DnsOutbound;

/// DNS inbound——持有规则 [`Handler`] + 上游 [`DnsOutbound`]。
///
/// 接收 DNS 查询 → Handler 决策 → 路由：
/// - [`ProcessOutcome::Forward`]：转给 DnsOutbound（hickory-resolver）
/// - [`ProcessOutcome::Drop`]：不响应（UDP）/ 关闭连接（TCP）
/// - [`ProcessOutcome::Respond`]：返回预设响应
/// - [`ProcessOutcome::Hijack`]：转给 rewrite_server（当前实现转给默认 outbound）
pub struct DnsInbound {
    tag: String,
    handler: Handler,
    outbound: DnsOutbound,
}

impl DnsInbound {
    /// 创建 DNS inbound。
    pub fn new(tag: impl Into<String>, handler: Handler, outbound: DnsOutbound) -> Self {
        Self {
            tag: tag.into(),
            handler,
            outbound,
        }
    }

    /// 处理 UDP DNS 包：返回响应字节（`None` 表示 Drop，不响应）。
    ///
    /// # Errors
    /// 透传 [`Handler::process`] 和 [`DnsOutbound::process`] 的错误。
    pub async fn handle_packet(&self, query: &[u8]) -> Result<Option<Vec<u8>>> {
        let outcome = self.handler.process(query).await?;
        route_outcome(&self.outbound, outcome).await
    }

    /// 处理 TCP DNS 连接：循环读取（2B 长度前缀帧）→ 处理 → 写回。
    ///
    /// 客户端关闭连接（EOF）时正常退出。
    ///
    /// # Errors
    /// 透传底层 IO 错误和处理错误。
    pub async fn handle_conn(&self, mut conn: TcpStream) -> Result<()> {
        loop {
            let query = match decode_tcp_dns_message(&mut conn).await {
                Ok(q) => q,
                // EOF = 客户端关闭，正常退出
                Err(DnsProxyError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let outcome = self.handler.process(&query).await?;
            if let Some(resp) = route_outcome(&self.outbound, outcome).await? {
                let framed = encode_tcp_dns_message(&resp)?;
                conn.write_all(&framed).await?;
            }
            // Drop：不写响应，继续等下一条（不主动关闭）
        }
    }
}

/// 将 Handler 决策结果路由到 outbound，返回最终响应字节（None=Drop）。
async fn route_outcome(
    outbound: &DnsOutbound,
    outcome: ProcessOutcome,
) -> Result<Option<Vec<u8>>> {
    match outcome {
        ProcessOutcome::Drop => Ok(None),
        ProcessOutcome::Respond { response } => Ok(Some(response)),
        // Forward 和 Hijack 都转给 outbound 转发
        ProcessOutcome::Forward { query } | ProcessOutcome::Hijack { query } => {
            let resp = outbound.process(&query).await?;
            Ok(Some(resp))
        }
    }
}

#[async_trait]
impl InboundHandler for DnsInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        // ponytail: DNS inbound 由 dispatcher 驱动，不主动 listen。
        // trait 要求实现，start 是无操作。
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        Ok(())
    }

    fn port(&self) -> u16 {
        // DNS inbound 不绑定端口（dispatcher 负责）
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DnsRuleConfig, RuleAction};
    use std::net::Ipv4Addr;

    /// 构造最小 DNS A 查询消息（handler.rs tests 中同款）。
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

    fn make_inbound_with_rules(rules: Vec<DnsRuleConfig>) -> DnsInbound {
        let cfg = Config {
            rule: rules,
            ..Default::default()
        };
        let handler = Handler::init(&cfg);
        let outbound = DnsOutbound::new_with_servers(
            "test-dns",
            &[(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)],
        )
        .expect("build outbound");
        DnsInbound::new("test-in", handler, outbound)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_packet_drop_rule_returns_none() {
        let inbound = make_inbound_with_rules(vec![DnsRuleConfig {
            action: RuleAction::Drop,
            q_type: vec![1], // A
            ..Default::default()
        }]);
        let query = make_query_bytes("example.com", 1);
        let result = inbound.handle_packet(&query).await.expect("process");
        assert!(result.is_none(), "Drop 动作应返回 None");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_packet_return_rule_responds_with_rule_rcode() {
        let inbound = make_inbound_with_rules(vec![DnsRuleConfig {
            action: RuleAction::Return,
            q_type: vec![1],
            ..Default::default()
        }]);
        let query = make_query_bytes("example.com", 1);
        let resp = inbound
            .handle_packet(&query)
            .await
            .expect("process")
        .expect("Return 应返回 Some");
        // Go rejectNonIPQuery：rCode 未配置 → 0（不再硬编码 REFUSED）。
        let (header, _) = crate::dns_message::parse_dns_query(&resp).expect("parse resp");
        assert!(header.is_response());
        assert_eq!(header.rcode(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_packet_invalid_query_returns_error() {
        let inbound = make_inbound_with_rules(vec![]);
        let err = inbound.handle_packet(&[]).await.unwrap_err();
        assert!(matches!(err, DnsProxyError::QueryParseFailed(_)));
    }

    #[test]
    fn inbound_tag_and_port() {
        let inbound = make_inbound_with_rules(vec![]);
        assert_eq!(inbound.tag(), "test-in");
        assert_eq!(inbound.port(), 0);
    }

    /// 集成测试：inbound(无规则→Direct) → outbound(hickory resolver) → mock UDP DNS server
    /// → 验证响应包含 A 记录 1.2.3.4。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inbound_forward_to_outbound_returns_upstream_response() {
        use hickory_resolver::proto::op::{
            Message as HickoryMessage, MessageType, OpCode, ResponseCode,
        };
        use hickory_resolver::proto::rr::rdata::A;
        use hickory_resolver::proto::rr::{RData, Record};
        use std::net::{IpAddr, Ipv4Addr};
        use tokio::net::UdpSocket;

        // 1. 启动 mock UDP DNS server——收到 A 查询返回 1.2.3.4
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_port = sock.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (len, client) = sock.recv_from(&mut buf).await.expect("recv");
            let req = HickoryMessage::from_vec(&buf[..len]).expect("parse query");
            let mut resp = HickoryMessage::new(req.id, MessageType::Response, OpCode::Query);
            // MessageType::Response 默认 RCODE=NoError，无需显式设置
            if let Some(q) = req.queries.first().cloned() {
                let name = q.name().clone();
                resp.add_query(q);
                let record = Record::from_rdata(
                    name,
                    300,
                    RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                );
                resp.add_answer(record);
            }
            let bytes = resp.to_vec().expect("serialize");
            sock.send_to(&bytes, client).await.expect("send");
        });

        // 2. 创建 DnsOutbound 指向 mock server
        let outbound = DnsOutbound::new_with_servers(
            "mock-upstream",
            &[(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port)],
        )
        .expect("build outbound");

        // 3. 创建 DnsInbound（无规则 → Direct 转发）
        let handler = Handler::init(&Config::default());
        let inbound = DnsInbound::new("test-in", handler, outbound);

        // 4. 构造 DNS A 查询 "example.com"
        let query = make_query_bytes("example.com", 1);

        // 5. 通过 inbound 处理（Direct → outbound → mock → 响应）
        let response = inbound
            .handle_packet(&query)
            .await
            .expect("process")
            .expect("Direct 动作应返回 Some");

        // 6. 验证响应——用 hickory 解析（比 parse_dns_query 更完整）
        let parsed = HickoryMessage::from_vec(&response).expect("parse resp");
        assert_eq!(
            parsed.message_type,
            MessageType::Response,
            "应为响应"
        );
        assert_eq!(
            parsed.response_code,
            ResponseCode::NoError,
            "RCODE 应为 NOERROR"
        );
        // 验证 answer 含 A 1.2.3.4
        let found = parsed.answers.iter().any(|r| match &r.data {
            RData::A(A(ip)) => *ip == Ipv4Addr::new(1, 2, 3, 4),
            _ => false,
        });
        assert!(found, "响应应包含 A 记录 1.2.3.4");

        server.await.expect("server task");
    }
}
