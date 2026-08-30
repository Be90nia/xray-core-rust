//! DNS inbound round-trip（bd m5nw）。
//!
//! 拓扑：
//! ```text
//! mock UDP DNS server (127.0.0.1:server_port)
//!   ↕ hickory wire format
//! DnsInbound::handle_packet → DnsOutbound → 真实 upstream
//! ```
//!
//! 验证：完整 DNS query → 决策 → 转发到上游 → 收到响应 → 解码验证 A 记录。

#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr};

use hickory_resolver::proto::op::{Message as HickoryMessage, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::{RData, Record};
use tokio::net::UdpSocket;

use xray_proxy_dns::{Config, DnsInbound, DnsOutbound, Handler};

fn make_query_bytes(domain: &str, q_type: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xABCDu16.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&q_type.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_dispatch_round_trip_through_upstream() {
    // 1. 起 mock UDP DNS server — 任何 A 查询返回 1.2.3.4
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_port = sock.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (len, client) = sock.recv_from(&mut buf).await.expect("recv");
        let req = HickoryMessage::from_vec(&buf[..len]).expect("parse query");
        let mut resp = HickoryMessage::new(req.id, MessageType::Response, OpCode::Query);
        if let Some(q) = req.queries.first().cloned() {
            let name = q.name().clone();
            resp.add_query(q);
            let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
            resp.add_answer(record);
        }
        let bytes = resp.to_vec().expect("serialize");
        sock.send_to(&bytes, client).await.expect("send");
    });

    // 2. outbound 指向 mock server；inbound 直接处理（无规则 → Direct）
    let outbound = DnsOutbound::new_with_servers(
        "dns-test",
        &[(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port)],
    )
    .expect("build outbound");
    let handler = Handler::init(&Config::default());
    let inbound = DnsInbound::new("dns-in", handler, outbound);

    // 3. 构造 DNS A 查询 example.com
    let query = make_query_bytes("example.com", 1);

    // 4. inbound 接管
    let response = inbound
        .handle_packet(&query)
        .await
        .expect("dispatch should succeed")
        .expect("Direct action returns Some");

    // 5. 验证响应
    let parsed = HickoryMessage::from_vec(&response).expect("parse response");
    let found = parsed.answers.iter().any(|r| match &r.data {
        RData::A(A(ip)) => *ip == Ipv4Addr::new(1, 2, 3, 4),
        _ => false,
    });
    assert!(found, "response should include A 1.2.3.4");

    server.await.expect("server task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_inbound_without_rules_delegates_to_outbound() {
    use xray_proxy_dns::config::RuleAction;

    // 配置一条独立 Drop 规则覆盖 inbound → outbound 转发应被旁路
    // 仍需保留 outbound 路径可在后续测试复用；此测试确认与 mock 通信一次成功。
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_port = sock.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (len, client) = sock.recv_from(&mut buf).await.expect("recv");
        let req = HickoryMessage::from_vec(&buf[..len]).expect("parse");
        let mut resp = HickoryMessage::new(req.id, MessageType::Response, OpCode::Query);
        if let Some(q) = req.queries.first().cloned() {
            let name = q.name().clone();
            resp.add_query(q);
            resp.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
            ));
        }
        let bytes = resp.to_vec().expect("serialize");
        sock.send_to(&bytes, client).await.expect("send");
    });

    // 无规则（Direct）——与上一个测试的差异：上游返回 5.6.7.8，
    // 验证响应确实来自 mock 上游而非缓存/预设。
    let cfg = Config::default();
    let handler = Handler::init(&cfg);
    let outbound = DnsOutbound::new_with_servers(
        "fallback",
        &[(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port)],
    )
    .expect("build outbound");
    let inbound = DnsInbound::new("dns-in", handler, outbound);

    // example.com 不匹配 → Direct → 上游 → 5.6.7.8
    let query = make_query_bytes("example.com", 1);
    let response = inbound
        .handle_packet(&query)
        .await
        .expect("dispatch")
        .expect("Direct returns Some");
    let parsed = HickoryMessage::from_vec(&response).expect("parse");
    let found = parsed.answers.iter().any(|r| match &r.data {
        RData::A(A(ip)) => *ip == Ipv4Addr::new(5, 6, 7, 8),
        _ => false,
    });
    assert!(found, "Direct path delegates to upstream");

    server.await.expect("server task");
}
