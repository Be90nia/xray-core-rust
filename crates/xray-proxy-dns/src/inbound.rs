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

use std::sync::Arc;

use async_trait::async_trait;
use skeleton_infra::fx::FxScope;
use tokio::io::AsyncWriteExt;
use xray_common::signal::ActivityTimer;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::{
    error::{DnsProxyError, Result},
    handler::{Handler, ProcessOutcome, decode_tcp_dns_message, encode_tcp_dns_message},
    outbound::DnsOutbound,
};

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
    /// 组件内自持托管 scope（B6，app 家族同款；不接 close，闸关不可达）。
    /// per-conn inactivity ticker 经此托管（坑约束 5）；连接结束 abort，
    /// scope 随 handler drop 兜底 abort 残余。
    fx: Arc<FxScope>,
}

impl DnsInbound {
    /// 创建 DNS inbound。
    pub fn new(tag: impl Into<String>, handler: Handler, outbound: DnsOutbound) -> Self {
        Self { tag: tag.into(), handler, outbound, fx: Arc::new(FxScope::new()) }
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
    /// 客户端关闭连接（EOF）时正常退出；静默超过 `handler.timeout`（装配层
    /// 注入的 policy `ConnectionIdle`）即关闭——对应 Go dns.go:226
    /// `signal.CancelAfterInactivity`，读帧/写响应均重置窗口，非硬截止总时长。
    ///
    /// # Errors
    /// 透传底层 IO 错误和处理错误。
    pub async fn handle_conn<S>(&self, mut conn: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Go CancelAfterInactivity：run 循环 task 与连接循环共享 Arc，
        // 活动即 update_activity 重置空闲窗口（proxyman worker 同款模式）。
        let timer = Arc::new(ActivityTimer::new(self.handler.timeout));
        let mut done = timer.done_signal();
        let run_timer = Arc::clone(&timer);
        let ticker = self
            .fx
            .spawn(async move { run_timer.run().await })
            .expect("internal FxScope is never closed");
        let result = async {
            loop {
                let query = tokio::select! {
                    // 静默超窗 → 终止连接（Go terminate → conn.Close()）。
                    _ = done.wait() => return Ok(()),
                    q = decode_tcp_dns_message(&mut conn) => match q {
                        // EOF = 客户端关闭，正常退出
                        Err(DnsProxyError::Io(e))
                            if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(e) => return Err(e),
                        Ok(q) => {
                            timer.update_activity();
                            q
                        },
                    },
                };
                let outcome = self.handler.process(&query).await?;
                if let Some(resp) = route_outcome(&self.outbound, outcome).await? {
                    let framed = encode_tcp_dns_message(&resp)?;
                    conn.write_all(&framed).await?;
                    timer.update_activity();
                }
                // Drop：不写响应，继续等下一条（不主动关闭）
            }
        }
        .await;
        ticker.abort();
        result
    }
}

/// 将 Handler 决策结果路由到 outbound，返回最终响应字节（None=Drop）。
async fn route_outcome(outbound: &DnsOutbound, outcome: ProcessOutcome) -> Result<Option<Vec<u8>>> {
    match outcome {
        ProcessOutcome::Drop => Ok(None),
        ProcessOutcome::Respond { response } => Ok(Some(response)),
        // Forward 和 Hijack 都转给 outbound 转发
        ProcessOutcome::Forward { query } | ProcessOutcome::Hijack { query } => {
            let resp = outbound.process(&query).await?;
            Ok(Some(resp))
        },
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
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{io::AsyncReadExt as _, net::TcpStream};

    use super::*;
    use crate::config::{Config, DnsRuleConfig, RuleAction};

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
        make_inbound_with_timeout(rules, Duration::from_secs(5))
    }

    fn make_inbound_with_timeout(rules: Vec<DnsRuleConfig>, timeout: Duration) -> DnsInbound {
        let cfg = Config { rule: rules, ..Default::default() };
        let handler = Handler::init(&cfg, timeout);
        let outbound = DnsOutbound::new_with_servers(
            "test-dns",
            &[(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)],
        )
        .expect("build outbound");
        DnsInbound::new("test-in", handler, outbound)
    }

    /// 起真实 loopback TCP listener → accept 一条连接交给 handle_conn，
    /// 返回客户端应连的地址。
    async fn spawn_handle_conn(inbound: Arc<DnsInbound>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        xray_common::testing::spawn("dns-accept-handle-conn", async move {
            if let Ok((conn, _)) = listener.accept().await {
                let _ = inbound.handle_conn(conn).await;
            }
        });
        addr
    }

    // ---- G14：handle_conn inactivity 计时（真实时钟） ----

    /// 验收①：注入短超时（200ms）→ 静默连接按时被终止。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_conn_idle_timeout_terminates_silent_connection() {
        let inbound = Arc::new(make_inbound_with_timeout(vec![], Duration::from_millis(200)));
        let addr = spawn_handle_conn(inbound).await;
        let mut client = TcpStream::connect(addr).await.expect("connect");

        let start = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("EOF 应在 2s 内到达")
            .expect("read");
        assert_eq!(n, 0, "静默超窗后服务端应关闭连接（EOF）");
        assert!(start.elapsed() >= Duration::from_millis(150), "不应早于超时窗口被杀");
    }

    /// 验收②：注入长超时（5s）→ 200ms 窗口内不误杀（超时可注入生效，
    /// 不存在更短的硬编码值反向影响）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_conn_long_timeout_does_not_kill_within_window() {
        let inbound = Arc::new(make_inbound_with_timeout(vec![], Duration::from_secs(5)));
        let addr = spawn_handle_conn(inbound).await;
        let mut client = TcpStream::connect(addr).await.expect("connect");

        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await {
            Err(_) => {}, // 连接仍开 = 正确
            Ok(Ok(0)) => panic!("5s 超时注入下连接不得在 300ms 内被杀"),
            Ok(Ok(_)) => panic!("静默期不应有数据"),
            Ok(Err(e)) => panic!("read error: {e}"),
        }
    }

    /// 验收③：持续有读活动时不被 inactivity 计时器杀掉（活动重置窗口）。
    ///
    /// 窗口设计（真实时钟，边界必须与杀点分离——首版杀点 1000ms 与存活窗
    /// 终点 1000ms 贴死，微秒级调度竞态导致 flaky）：
    /// - idle=500ms，最后写 1350ms → 杀点 1850ms；
    /// - 存活窗 [1350, 1500]，距杀点 350ms 余量（>10 次调度的累积抖动）；
    /// - 断言只看 EOF：被杀 = EOF 提前出现；读到数据也证明连接存活
    ///   （数据内容不属本测试断言范围，Drop 语义下理论无数据）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_conn_activity_resets_idle_window() {
        // 全类型 Drop 规则：查询被静默丢弃，只靠读活动续命，无响应写。
        let rules = vec![DnsRuleConfig { action: RuleAction::Drop, ..Default::default() }];
        let inbound = Arc::new(make_inbound_with_timeout(rules, Duration::from_millis(500)));
        let addr = spawn_handle_conn(inbound).await;
        let mut client = TcpStream::connect(addr).await.expect("connect");

        // 每 150ms 发一个合法查询帧 × 10：最后写 1350ms，杀点 1350+500=1850ms。
        let query = make_query_bytes("example.com", 1);
        let frame = encode_tcp_dns_message(&query).expect("frame");
        for _ in 0..10 {
            client.write_all(&frame).await.expect("write");
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        // 存活窗 [1350, 1500]：距杀点 350ms，EOF 若在此出现 = 活动重置失效。
        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(150), client.read(&mut buf)).await {
            Ok(Ok(0)) => panic!("持续活动下连接不得被 inactivity 计时器杀掉"),
            Ok(Err(e)) => panic!("read error: {e}"),
            // 连接仍开（无论有无数据）= 活动重置生效。
            Err(_) | Ok(Ok(_)) => {},
        }

        // 停止活动 → 杀点 1850ms：循环读排干直到 EOF（不假设「无残余数据」）。
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if client.read(&mut buf).await.expect("read") == 0 {
                    return; // EOF = 连接已按超时窗口终止
                }
            }
        })
        .await
        .expect("EOF 应在停活动后到达");
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
        let resp =
            inbound.handle_packet(&query).await.expect("process").expect("Return 应返回 Some");
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
        use std::net::{IpAddr, Ipv4Addr};

        use hickory_resolver::proto::{
            op::{Message as HickoryMessage, MessageType, OpCode, ResponseCode},
            rr::{RData, Record, rdata::A},
        };
        use tokio::net::UdpSocket;

        // 1. 启动 mock UDP DNS server——收到 A 查询返回 1.2.3.4
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_port = sock.local_addr().expect("addr").port();
        let server = xray_common::testing::spawn("mock-udp-dns-server", async move {
            let mut buf = [0u8; 1500];
            let (len, client) = sock.recv_from(&mut buf).await.expect("recv");
            let req = HickoryMessage::from_vec(&buf[..len]).expect("parse query");
            let mut resp = HickoryMessage::new(req.id, MessageType::Response, OpCode::Query);
            // MessageType::Response 默认 RCODE=NoError，无需显式设置
            if let Some(q) = req.queries.first().cloned() {
                let name = q.name().clone();
                resp.add_query(q);
                let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
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
        let handler = Handler::init(&Config::default(), Duration::from_secs(5));
        let inbound = DnsInbound::new("test-in", handler, outbound);

        // 4. 构造 DNS A 查询 "example.com"
        let query = make_query_bytes("example.com", 1);

        // 5. 通过 inbound 处理（Direct → outbound → mock → 响应）
        let response =
            inbound.handle_packet(&query).await.expect("process").expect("Direct 动作应返回 Some");

        // 6. 验证响应——用 hickory 解析（比 parse_dns_query 更完整）
        let parsed = HickoryMessage::from_vec(&response).expect("parse resp");
        assert_eq!(parsed.message_type, MessageType::Response, "应为响应");
        assert_eq!(parsed.response_code, ResponseCode::NoError, "RCODE 应为 NOERROR");
        // 验证 answer 含 A 1.2.3.4
        let found = parsed.answers.iter().any(|r| match &r.data {
            RData::A(A(ip)) => *ip == Ipv4Addr::new(1, 2, 3, 4),
            _ => false,
        });
        assert!(found, "响应应包含 A 记录 1.2.3.4");

        server.await.expect("server task");
    }
}
