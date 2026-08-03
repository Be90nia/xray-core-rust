//! DNS wire-protocol 嗅探器
//!
//! 对应 Go `app/dispatcher/dnssniffer.go`。
//!
//! 解析 DNS 查询包（UDP/TCP），从 Question section 提取域名。
//! 仅嗅探 DNS **查询**（QR=0），响应包跳过。

use crate::error::DispatcherError;
use crate::sniffer::{ProtocolSniffer, SniffError, SniffResult, SnifferIsProtoSubsetOf};
use std::fmt::Debug;
use xray_common::net::network::Network;

/// DNS 嗅探结果。
#[derive(Debug, Clone)]
pub struct DnsSniffResult {
    domain: String,
}

impl DnsSniffResult {
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
        }
    }
}

impl SniffResult for DnsSniffResult {
    fn protocol(&self) -> &str {
        "dns"
    }
    fn domain(&self) -> &str {
        &self.domain
    }
}

impl SnifferIsProtoSubsetOf for DnsSniffResult {
    fn is_proto_subset_of(&self, _protocol_name: &str) -> bool {
        false
    }
}

/// DNS wire-protocol 嗅探器。
#[derive(Debug, Default)]
pub struct DnsSniffer;

impl ProtocolSniffer for DnsSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        Ok(parse_dns_query_domain(payload)?.map(|d| Box::new(DnsSniffResult::new(d)) as Box<dyn SniffResult>))
    }

    fn network(&self) -> Network {
        Network::UDP
    }
}

/// 解析 DNS 查询包，提取第一个 Question 的域名。
///
/// DNS wire format (RFC 1035):
/// - Header: 12 bytes (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
/// - Question: QNAME (labels) + QTYPE(2) + QCLASS(2)
///
/// 仅处理 QR=0（查询），QDCOUNT≥1。返回 `None` 表示不是 DNS 查询包。
pub fn parse_dns_query_domain(payload: &[u8]) -> Result<Option<String>, DispatcherError> {
    if payload.len() < 12 {
        return Ok(None);
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 0 {
        return Ok(None);
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qdcount == 0 {
        return Ok(None);
    }

    let domain = parse_qname(payload, 12)?;

    if domain.is_empty() {
        Ok(None)
    } else {
        Ok(Some(domain))
    }
}

/// 从 offset 开始解析 QNAME，返回点分域名。
///
/// QNAME: 一系列 label，每个 label 前缀为长度字节（最高两 bit 必须为 0）。
/// 查询包中不应出现压缩指针（0xC0 前缀），遇到则报错。
fn parse_qname(buf: &[u8], offset: usize) -> Result<String, DispatcherError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;

    loop {
        if pos >= buf.len() {
            return Err(DispatcherError::Other(
                "DNS QNAME truncated: unexpected end of buffer".into(),
            ));
        }

        let len_byte = buf[pos];
        if len_byte == 0 {
            break;
        }

        if (len_byte & 0xC0) != 0 {
            return Err(DispatcherError::Other(
                "DNS QNAME: compression pointer not allowed in question section".into(),
            ));
        }

        let label_len = usize::from(len_byte);
        if label_len > 63 {
            return Err(DispatcherError::Other(format!(
                "DNS QNAME: label length {label_len} exceeds 63"
            )));
        }

        pos += 1;
        if pos + label_len > buf.len() {
            return Err(DispatcherError::Other(
                "DNS QNAME: label data truncated".into(),
            ));
        }

        let label_bytes = &buf[pos..pos + label_len];
        // DNS label 不保证 UTF-8 有效——lossy 转换避免 panic
        labels.push(String::from_utf8_lossy(label_bytes).into_owned());
        pos += label_len;
    }

    Ok(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query(domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1, QR=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            assert!(bytes.len() <= 63, "label too long");
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0); // 终止符
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&qclass.to_be_bytes());
        buf
    }

    #[test]
    fn parse_simple_query() {
        let pkt = build_dns_query("www.example.com", 1, 1);
        let domain = parse_dns_query_domain(&pkt).unwrap();
        assert_eq!(domain.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn parse_single_label() {
        let pkt = build_dns_query("localhost", 1, 1);
        let domain = parse_dns_query_domain(&pkt).unwrap();
        assert_eq!(domain.as_deref(), Some("localhost"));
    }

    #[test]
    fn response_packet_returns_none() {
        let mut pkt = build_dns_query("example.com", 1, 1);
        pkt[2] |= 0x80; // QR=1
        assert_eq!(parse_dns_query_domain(&pkt).unwrap(), None);
    }

    #[test]
    fn short_packet_returns_none() {
        assert_eq!(parse_dns_query_domain(&[0u8; 5]).unwrap(), None);
    }

    #[test]
    fn qdcount_zero_returns_none() {
        let pkt = vec![0u8; 12];
        assert_eq!(parse_dns_query_domain(&pkt).unwrap(), None);
    }

    #[test]
    fn truncated_qname_errors() {
        let pkt: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
            3, b'w', b'w', b'w', // label "www" 但无终止符
        ];
        assert!(parse_dns_query_domain(&pkt).is_err());
    }

    #[test]
    fn dns_sniffer_sniff_returns_result() {
        let pkt = build_dns_query("test.example.org", 1, 1);
        let sniffer = DnsSniffer;
        let result = sniffer.sniff(&pkt).unwrap().unwrap();
        assert_eq!(result.protocol(), "dns");
        assert_eq!(result.domain(), "test.example.org");
    }

    #[test]
    fn dns_sniffer_non_dns_returns_none() {
        let sniffer = DnsSniffer;
        assert!(sniffer.sniff(&[0u8; 3]).unwrap().is_none());
    }

    #[test]
    fn dns_sniffer_network_is_udp() {
        let sniffer = DnsSniffer;
        assert_eq!(sniffer.network(), Network::UDP);
    }
}
