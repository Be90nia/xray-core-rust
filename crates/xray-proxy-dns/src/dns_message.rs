//! DNS 消息最小解析（RFC 1035）。
//!
//! 对应 Go 端 `golang.org/x/net/dns/dnsmessage` 用法。workspace 无 DNS 解析
//! crate，手写最小解析（Header 12B + 第一个 Question section），足够 DNS 代理
//! 提取 qType + domain 做规则匹配。
//!
//! ## 支持范围
//!
//! - DNS Header（12 字节，所有字段）
//! - Question section 第一个问题（QNAME + QTYPE + QCLASS）
//! - QNAME 解码为可读 domain（label 拼接 + 大小写保留）
//!
//! 不支持：Answer/Authority/Additional section、压缩指针（0xC0）、EDNS0。

use crate::error::{DnsProxyError, Result};

/// DNS 消息 Header（12 字节）。对应 RFC 1035 §4.1.1。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// 事务 ID（客户端生成，服务端原样返回）。
    pub id: u16,
    /// 原始 Flags（16 位，含 QR/Opcode/AA/TC/RD/RA/Z/RCODE）。
    pub flags: u16,
    /// Question section 条目数。
    pub qd_count: u16,
    /// Answer section 条目数。
    pub an_count: u16,
    /// Authority section 条目数。
    pub ns_count: u16,
    /// Additional section 条目数。
    pub ar_count: u16,
}

impl DnsHeader {
    /// 是否为响应（QR 位 bit 15）。
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Opcode（bits 11-14）。0=标准查询，1=反向查询。
    #[must_use]
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x000F) as u8
    }

    /// 是否截断（TC 位 bit 9）。UDP 响应超 512 字节时置位。
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// 递归期望（RD 位 bit 8）。
    #[must_use]
    pub fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// RCODE（bits 0-3）。0=NOERROR，2=SERVFAIL，3=NXDOMAIN，5=REFUSED。
    #[must_use]
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
}

/// DNS Question section 单条。对应 RFC 1035 §4.1.2。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// 查询域名（已解码为可读形式，如 `"example.com"`）。
    pub name: String,
    /// 查询类型（QTYPE）。常见值：1=A，2=NS，5=CNAME，6=SOA，12=PTR，
    /// 15=MX，16=TXT，28=AAAA，33=SRV，255=ANY。
    pub q_type: u16,
    /// 查询类（QCLASS）。1=IN（互联网），唯一常见值。
    pub q_class: u16,
}

/// 解析 DNS 消息的 Header + 第一个 Question。
///
/// 入参 `bytes` 是完整 DNS 消息（UDP 通常 ≤512 字节，TCP 前缀 2 字节长度）。
/// 返回 `(header, question)`。如果 QDCOUNT=0 或解析失败返回错误。
///
/// # 错误
///
/// - 消息 < 12 字节 → InvalidConfig("truncated header")
/// - QDCOUNT = 0 → InvalidConfig("no question")
/// - QNAME 格式非法（超长/截断/嵌套深度过大）→ InvalidConfig
pub fn parse_dns_query(bytes: &[u8]) -> Result<(DnsHeader, DnsQuestion)> {
    if bytes.len() < 12 {
        return Err(DnsProxyError::InvalidConfig(
            "DNS message too short: header is 12 bytes".into(),
        ));
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qd_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let an_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    let ns_count = u16::from_be_bytes([bytes[8], bytes[9]]);
    let ar_count = u16::from_be_bytes([bytes[10], bytes[11]]);
    let header = DnsHeader {
        id,
        flags,
        qd_count,
        an_count,
        ns_count,
        ar_count,
    };
    if qd_count == 0 {
        return Err(DnsProxyError::InvalidConfig(
            "DNS message has no question (QDCOUNT=0)".into(),
        ));
    }
    let (name, offset) = parse_qname(bytes, 12)?;
    if offset + 4 > bytes.len() {
        return Err(DnsProxyError::InvalidConfig(
            "DNS question truncated: QTYPE/QCLASS missing".into(),
        ));
    }
    let q_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    let q_class = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
    Ok((
        header,
        DnsQuestion {
            name,
            q_type,
            q_class,
        },
    ))
}

/// 解析 QNAME 为可读 domain 字符串。
///
/// QNAME 格式：一系列 label，每个 label 前有 1 byte 长度（≤63），以 0 byte 终止。
/// 例如 `example.com` → `\x07example\x03com\x00`。
///
/// 返回 `(domain_string, offset_after_qname)`。
///
/// 不支持压缩指针（0xC0 前缀）—— DNS 查询消息的 Question section 不使用压缩。
fn parse_qname(bytes: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut hops = 0;
    loop {
        if offset >= bytes.len() {
            return Err(DnsProxyError::InvalidConfig(
                "QNAME truncated: length byte beyond buffer".into(),
            ));
        }
        let len = bytes[offset] as usize;
        if len == 0 {
            offset += 1; // 跳过终止 0 byte
            break;
        }
        // 压缩指针（前 2 bit = 0b11）在 Question section 不合法
        if len & 0xC0 == 0xC0 {
            return Err(DnsProxyError::InvalidConfig(
                "QNAME compression pointer not allowed in question section".into(),
            ));
        }
        if len > 63 {
            return Err(DnsProxyError::InvalidConfig(format!(
                "QNAME label too long: {len} > 63"
            )));
        }
        offset += 1;
        if offset + len > bytes.len() {
            return Err(DnsProxyError::InvalidConfig(
                "QNAME label truncated: label bytes beyond buffer".into(),
            ));
        }
        let label = std::str::from_utf8(&bytes[offset..offset + len])
            .map_err(|e| DnsProxyError::InvalidConfig(format!("QNAME non-utf8 label: {e}")))?;
        labels.push(label.to_string());
        offset += len;
        hops += 1;
        if hops > 127 {
            return Err(DnsProxyError::InvalidConfig(
                "QNAME too many labels: > 127".into(),
            ));
        }
    }
    Ok((labels.join("."), offset))
}

/// 构造最小 DNS 响应消息（Header + 空 Answer + Question 回显）。
///
/// 用于 DNS 代理的 Return 动作（返回 REFUSED）或 Hijack 动作的占位。
/// `rcode` 填入 Header flags 低 4 位。
#[must_use]
pub fn build_dns_response(query_header: &DnsHeader, question: &DnsQuestion, rcode: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // Header（12B）：ID 原样 + flags(QR=1 + RD 回显 + RCODE)
    let flags = 0x8000 // QR=1 (response)
        | (query_header.flags & 0x0100) // 回显 RD
        | (rcode as u16 & 0x000F); // RCODE
    buf.extend_from_slice(&query_header.id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    // Question 回显
    for label in question.name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // QNAME 终止
    buf.extend_from_slice(&question.q_type.to_be_bytes());
    buf.extend_from_slice(&question.q_class.to_be_bytes());
    buf
}

/// 构造包含 IP 记录的 DNS 响应消息（Header + Question + Answer records）。
///
/// 用于 Hijack 动作：调用 DnsService::lookup_ip() 获取 IP 后构造响应。
/// `ips` 为解析结果，`ttl` 为缓存有效期（秒）。
///
/// # DNS 记录格式（RFC 1035 §4.1.3）
///
/// ```text
/// NAME    (QNAME 回显)
/// TYPE    (1=A, 28=AAAA)
/// CLASS   (1=IN)
/// TTL     (4 bytes, big-endian)
/// RDLENGTH(2 bytes)
/// RDATA   (4 bytes for A, 16 bytes for AAAA)
/// ```
#[must_use]
pub fn build_ip_response(
    query_header: &DnsHeader,
    question: &DnsQuestion,
    ips: &[std::net::IpAddr],
    ttl: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // Header（12B）
    let flags = 0x8000 // QR=1 (response)
        | (query_header.flags & 0x0100) // 回显 RD
        | 0x0080 // RA=1 (recursion available)
        | 0; // RCODE=0 (NOERROR)
    buf.extend_from_slice(&query_header.id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    // Question 回显
    for label in question.name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // QNAME 终止
    buf.extend_from_slice(&question.q_type.to_be_bytes());
    buf.extend_from_slice(&question.q_class.to_be_bytes());
    // Answer records
    for ip in ips {
        // NAME：与 Question 相同的 QNAME（使用压缩指针指向 Question section）
        // 压缩指针格式：0xC0 | offset（offset = 12，即 Question section 起始）
        buf.push(0xC0);
        buf.push(12); // 指向 Header 后的 Question QNAME
        // TYPE
        let rtype: u16 = match ip {
            std::net::IpAddr::V4(_) => 1,  // A
            std::net::IpAddr::V6(_) => 28, // AAAA
        };
        buf.extend_from_slice(&rtype.to_be_bytes());
        // CLASS = IN(1)
        buf.extend_from_slice(&1u16.to_be_bytes());
        // TTL
        buf.extend_from_slice(&ttl.to_be_bytes());
        // RDLENGTH + RDATA
        match ip {
            std::net::IpAddr::V4(v4) => {
                buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
                buf.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                buf.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH=16
                buf.extend_from_slice(&v6.octets());
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 DNS A 查询消息（example.com, type A, class IN）。
    fn make_dns_a_query(domain: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question QNAME
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // 终止
        // QTYPE=A(1) QCLASS=IN(1)
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    #[test]
    fn parse_valid_a_query() {
        let bytes = make_dns_a_query("example.com");
        let (header, question) = parse_dns_query(&bytes).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(!header.is_response()); // 查询 QR=0
        assert!(header.recursion_desired()); // RD=1
        assert_eq!(header.qd_count, 1);
        assert_eq!(header.opcode(), 0); // 标准查询
        assert_eq!(header.rcode(), 0); // NOERROR
        assert_eq!(question.name, "example.com");
        assert_eq!(question.q_type, 1); // A
        assert_eq!(question.q_class, 1); // IN
    }

    #[test]
    fn parse_multi_label_domain() {
        let bytes = make_dns_a_query("a.b.c.example.com");
        let (_, question) = parse_dns_query(&bytes).unwrap();
        assert_eq!(question.name, "a.b.c.example.com");
    }

    #[test]
    fn parse_single_label_domain() {
        let bytes = make_dns_a_query("localhost");
        let (_, question) = parse_dns_query(&bytes).unwrap();
        assert_eq!(question.name, "localhost");
    }

    #[test]
    fn parse_aaaa_query() {
        let mut bytes = make_dns_a_query("example.com");
        // 改 QTYPE 为 AAAA(28)
        let qtype_offset = bytes.len() - 4;
        bytes[qtype_offset..qtype_offset + 2].copy_from_slice(&28u16.to_be_bytes());
        let (_, question) = parse_dns_query(&bytes).unwrap();
        assert_eq!(question.q_type, 28); // AAAA
    }

    #[test]
    fn parse_too_short_header_rejected() {
        let bytes = [0u8; 11]; // < 12
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(matches!(err, DnsProxyError::InvalidConfig(_)));
    }

    #[test]
    fn parse_qdcount_zero_rejected() {
        let mut bytes = make_dns_a_query("example.com");
        bytes[4] = 0; // QDCOUNT 高字节
        bytes[5] = 0; // QDCOUNT 低字节
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(err.to_string().contains("no question"));
    }

    #[test]
    fn parse_truncated_qname_rejected() {
        let mut bytes = make_dns_a_query("example.com");
        bytes.truncate(20); // 截断 QNAME
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(matches!(err, DnsProxyError::InvalidConfig(_)));
    }

    #[test]
    fn parse_truncated_qtype_rejected() {
        let mut bytes = make_dns_a_query("example.com");
        bytes.truncate(bytes.len() - 2); // 截断 QTYPE/QCLASS
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(matches!(err, DnsProxyError::InvalidConfig(_)));
    }

    #[test]
    fn parse_compression_pointer_rejected() {
        let mut bytes = make_dns_a_query("example.com");
        // 把第一个 label 长度字节改成压缩指针 (0xC0 | offset)
        bytes[12] = 0xC0;
        bytes[13] = 0x0C; // 指向 offset 12（自身，形成循环）
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(err.to_string().contains("compression pointer"));
    }

    #[test]
    fn parse_oversized_label_rejected() {
        let mut bytes = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
            64, // label length = 64 > 63
        ];
        bytes.extend_from_slice(&[b'a'; 64]); // label bytes
        bytes.push(0); // QNAME 终止
        bytes.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
        bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
        let err = parse_dns_query(&bytes).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn header_flags_decoding() {
        let h = DnsHeader {
            id: 1,
            flags: 0x8180, // QR=1, RD=1, RA=1, RCODE=0 (标准响应)
            qd_count: 1,
            an_count: 2,
            ns_count: 0,
            ar_count: 0,
        };
        assert!(h.is_response());
        assert!(h.recursion_desired());
        assert_eq!(h.rcode(), 0);
        assert_eq!(h.opcode(), 0);
    }

    #[test]
    fn header_servfail_rcode() {
        let h = DnsHeader {
            id: 1,
            flags: 0x8182, // RCODE=2 (SERVFAIL)
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };
        assert_eq!(h.rcode(), 2);
    }

    #[test]
    fn header_nxdomain_rcode() {
        let h = DnsHeader {
            id: 1,
            flags: 0x8183, // RCODE=3 (NXDOMAIN)
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };
        assert_eq!(h.rcode(), 3);
    }

    #[test]
    fn build_response_roundtrip() {
        let query = make_dns_a_query("test.example.com");
        let (header, question) = parse_dns_query(&query).unwrap();
        let resp = build_dns_response(&header, &question, 5); // REFUSED
        // 解析响应
        let (resp_header, resp_question) = parse_dns_query(&resp).unwrap();
        assert!(resp_header.is_response());
        assert_eq!(resp_header.rcode(), 5);
        assert_eq!(resp_header.id, header.id);
        assert_eq!(resp_question.name, "test.example.com");
        assert_eq!(resp_question.q_type, question.q_type);
    }

    #[test]
    fn build_response_preserves_rd_flag() {
        let query = make_dns_a_query("x.com");
        let (header, question) = parse_dns_query(&query).unwrap();
        assert!(header.recursion_desired()); // 原始 RD=1
        let resp = build_dns_response(&header, &question, 0);
        let (resp_header, _) = parse_dns_query(&resp).unwrap();
        assert!(resp_header.recursion_desired()); // RD 回显
    }

    #[test]
    fn parse_empty_domain_qname() {
        // QNAME = 0x00（root 域名，空字符串）
        let mut bytes = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
            0x00, // 空 QNAME（root）
        ];
        bytes.extend_from_slice(&255u16.to_be_bytes()); // QTYPE=ANY
        bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        let (_, question) = parse_dns_query(&bytes).unwrap();
        assert_eq!(question.name, "");
        assert_eq!(question.q_type, 255);
    }

    #[test]
    fn build_ip_response_with_a_records() {
        let query = make_dns_a_query("example.com");
        let (header, question) = parse_dns_query(&query).unwrap();
        let ips: Vec<std::net::IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
        ];
        let resp = build_ip_response(&header, &question, &ips, 300);
        // 验证响应可解析
        let (resp_header, resp_question) = parse_dns_query(&resp).unwrap();
        assert!(resp_header.is_response());
        assert_eq!(resp_header.rcode(), 0); // NOERROR
        assert_eq!(resp_header.an_count, 2);
        assert_eq!(resp_question.name, "example.com");
        // 验证 A 记录数据（手动检查 RDATA）
        // Answer section 在 Question section 之后
        let qname_end = 12 + "example.com".len() + 2 + 4; // header + qname + qtype + qclass
        // 第一个 A 记录：压缩指针(2B) + TYPE(2B) + CLASS(2B) + TTL(4B) + RDLENGTH(2B) + RDATA(4B) = 16B
        let rec1_start = qname_end;
        assert_eq!(resp[rec1_start], 0xC0); // 压缩指针
        assert_eq!(resp[rec1_start + 2..rec1_start + 4], [0, 1]); // TYPE=A
        assert_eq!(resp[rec1_start + 4..rec1_start + 6], [0, 1]); // CLASS=IN
        let ttl_bytes = &resp[rec1_start + 6..rec1_start + 10];
        assert_eq!(u32::from_be_bytes(ttl_bytes.try_into().unwrap()), 300);
        assert_eq!(resp[rec1_start + 10..rec1_start + 12], [0, 4]); // RDLENGTH=4
        assert_eq!(&resp[rec1_start + 12..rec1_start + 16], &[1, 2, 3, 4]); // 1.2.3.4
    }

    #[test]
    fn build_ip_response_with_aaaa_record() {
        let mut query = make_dns_a_query("test.com");
        // 改 QTYPE 为 AAAA(28)
        let qtype_offset = query.len() - 4;
        query[qtype_offset..qtype_offset + 2].copy_from_slice(&28u16.to_be_bytes());
        let (header, question) = parse_dns_query(&query).unwrap();
        let ips: Vec<std::net::IpAddr> = vec![
            "::1".parse().unwrap(),
        ];
        let resp = build_ip_response(&header, &question, &ips, 60);
        let (resp_header, _) = parse_dns_query(&resp).unwrap();
        assert_eq!(resp_header.an_count, 1);
        // 验证 AAAA 记录 RDLENGTH=16
        let qname_end = 12 + "test.com".len() + 2 + 4;
        let rec_start = qname_end;
        assert_eq!(resp[rec_start + 2..rec_start + 4], [0, 28]); // TYPE=AAAA
        assert_eq!(resp[rec_start + 10..rec_start + 12], [0, 16]); // RDLENGTH=16
    }

    #[test]
    fn build_ip_response_empty_ips_returns_noerror_with_zero_answers() {
        let query = make_dns_a_query("empty.com");
        let (header, question) = parse_dns_query(&query).unwrap();
        let ips: Vec<std::net::IpAddr> = vec![];
        let resp = build_ip_response(&header, &question, &ips, 0);
        let (resp_header, _) = parse_dns_query(&resp).unwrap();
        assert!(resp_header.is_response());
        assert_eq!(resp_header.rcode(), 0);
        assert_eq!(resp_header.an_count, 0);
    }
}
