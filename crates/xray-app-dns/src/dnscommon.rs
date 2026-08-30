//! DNS 通用功能：FQDN 规范化、IP 记录、缓存辅助。
//!
//! 对应 Go `app/dns/dnscommon.go`。
//!
//! **跳过范围**（IO 边界，依赖 DNS 协议层）：
//! - `genEDNS0Options`、`buildReqMsgs`：依赖 Go `golang.org/x/net/dns/dnsmessage`
//!   的 `Message`/`Question`/`OPTResource`/`Header`/`Resource`。Rust 生态等价品
//!   （`hickory-proto`）引入后可实现；此处保留 `DnsMessage` 类型别名与占位 trait，
//!   保证调用方签名稳定。

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::IpOption;
use crate::error::DnsError;

/// DNS 标准返回码。对应 Go `dnsmessage.RCode`（u16 宽度足以覆盖实际值）。
pub type RCode = u16;

pub mod rcode {
    //! 常用 DNS RCode 常量。对应 Go `dnsmessage.RCode*`。
    use super::RCode;
    pub const NO_ERROR: RCode = 0;
    pub const FORM_ERR: RCode = 1;
    pub const SERV_FAIL: RCode = 2;
    pub const NX_DOMAIN: RCode = 3;
    pub const NOT_IMPL: RCode = 4;
    pub const REFUSED: RCode = 5;
}

/// DNS 请求 ID 生成器。对应 Go `reqIDGen func() uint16`。
pub trait ReqIdGen: Send + Sync {
    /// 返回下一个 16-bit DNS 请求 ID。
    fn next_id(&self) -> u16;
}

/// DNS 原始报文抽象。对应 Go `*dnsmessage.Message`。
///
/// 真正的 DNS 报文构造/解析引入 `hickory-proto` 或自研后实现。
pub trait DnsMessage: Send + Sync {
    /// 报文 ID。
    fn id(&self) -> u16;
    /// 序列化为 wire format 字节。
    fn to_wire(&self) -> Vec<u8>;
}

/// FQDN 规范化：确保以 `.` 结尾。
///
/// 对应 Go `app/dns/dnscommon.go::Fqdn`。
#[must_use]
pub fn fqdn(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    }
}

/// 可缓存的 IP 记录。对应 Go `IPRecord`。
#[derive(Debug, Clone)]
pub struct IpRecord {
    /// 请求 ID（用于匹配响应）。
    pub req_id: u16,
    /// 解析得到的 IP 列表（可能为空）。
    pub ips: Vec<IpAddr>,
    /// 过期时间。
    pub expire: Instant,
    /// DNS RCode。
    pub rcode: RCode,
}

impl IpRecord {
    /// 按过期时间与 RCode 取出可用 IP 列表。
    ///
    /// 对应 Go `(*IPRecord).getIPs()`。返回 `(ips, ttl_seconds, result)`：
    /// - 记录过期：`(空, ttl=0, RecordNotFound)`
    /// - RCode 非 0：`(空, ttl, from_rcode(rcode))`
    /// - IP 为空：`(空, ttl, EmptyResponse)`
    /// - 正常：`(ips, ttl, Ok(ips))`
    #[must_use]
    pub fn get_ips(&self, now: Instant) -> Result<(Vec<IpAddr>, i32), DnsError> {
        let ttl = self.ttl_seconds(now);
        if ttl <= 0 {
            return Err(DnsError::RecordNotFound);
        }
        if self.rcode != rcode::NO_ERROR {
            return Err(DnsError::from_rcode(self.rcode));
        }
        if self.ips.is_empty() {
            return Err(DnsError::EmptyResponse);
        }
        Ok((self.ips.clone(), ttl))
    }

    /// 剩余 TTL（秒，向上取整）。对应 Go `int32(math.Ceil(untilExpire.Seconds()))`。
    #[must_use]
    pub fn ttl_seconds(&self, now: Instant) -> i32 {
        match self.expire.checked_duration_since(now) {
            Some(d) => i32::try_from((d.as_secs_f64().ceil()) as i64).unwrap_or(0),
            None => 0,
        }
    }

    /// 是否已过期。
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        self.expire <= now
    }
}

/// 构造带 TTL 的 `IpRecord`。
#[must_use]
pub fn ip_record(req_id: u16, ips: Vec<IpAddr>, ttl: Duration, rcode: RCode, now: Instant) -> IpRecord {
    IpRecord {
        req_id,
        ips,
        expire: now + ttl,
        rcode,
    }
}

/// 同时缓存 A/AAAA 记录。对应 Go `record` struct。
#[derive(Debug, Clone, Default)]
pub struct Record {
    /// IPv4 (A) 记录。
    pub a: Option<IpRecord>,
    /// IPv6 (AAAA) 记录。
    pub aaaa: Option<IpRecord>,
}

impl Record {
    /// 是否两条记录都已过期。
    #[must_use]
    pub fn is_empty_or_expired(&self, now: Instant) -> bool {
        let a_expired = self.a.as_ref().is_none_or(|r| r.is_expired(now));
        let aaaa_expired = self.aaaa.as_ref().is_none_or(|r| r.is_expired(now));
        a_expired && aaaa_expired
    }
}

/// 合并 A/AAAA 记录的 IP 列表。对应 Go `app/dns/nameserver_cached.go::merge`。
///
/// 输入：`option`（查询什么）+ 可选的 rec4/rec6 + 已知错误。
/// 输出：`(ips, min_ttl)` 或第一个非 RecordNotFound 错误。
pub fn merge_records(
    option: IpOption,
    rec4: Option<&IpRecord>,
    rec6: Option<&IpRecord>,
    now: Instant,
) -> Result<(Vec<IpAddr>, i32), DnsError> {
    const DEFAULT_TTL: i32 = 600;
    let merge_req = option.ipv4_enable && option.ipv6_enable;

    // 默认 TTL，对应 Go `var rTTL int32 = dns.DefaultTTL`。
    let mut all_ips: Vec<IpAddr> = Vec::new();
    let mut r_ttl: i32 = DEFAULT_TTL;
    let mut deferred_errs: Vec<DnsError> = Vec::new();

    if option.ipv4_enable {
        match rec4.map(|r| r.get_ips(now)) {
            None => return Err(DnsError::RecordNotFound),
            Some(Err(e)) if !merge_req || matches!(e, DnsError::RecordNotFound) => {
                return Err(e);
            }
            Some(Err(e)) => {
                deferred_errs.push(e);
            }
            Some(Ok((ips, ttl))) => {
                if ttl < r_ttl {
                    r_ttl = ttl;
                }
                if !ips.is_empty() {
                    all_ips.extend(ips);
                }
            }
        }
    }

    if option.ipv6_enable {
        match rec6.map(|r| r.get_ips(now)) {
            None => return Err(DnsError::RecordNotFound),
            Some(Err(e)) if !merge_req || matches!(e, DnsError::RecordNotFound) => {
                return Err(e);
            }
            Some(Err(e)) => {
                deferred_errs.push(e);
            }
            Some(Ok((ips, ttl))) => {
                if ttl < r_ttl {
                    r_ttl = ttl;
                }
                if !ips.is_empty() {
                    all_ips.extend(ips);
                }
            }
        }
    }

    if all_ips.is_empty() && !deferred_errs.is_empty() {
        return Err(deferred_errs.into_iter().next().unwrap_or(DnsError::EmptyResponse));
    }
    Ok((all_ips, r_ttl))
}

// ---- DNS wire format helpers（hickory-proto 后端）----
//
// 提供 build_dns_query / parse_dns_response / AtomicReqIdGen，供 udp/tcp nameserver
// 直接调用。避免在多个 nameserver 文件里重复实现。

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use std::sync::atomic::{AtomicU16, Ordering};

/// 将 ResponseCode 转为项目 RCode (u16)。
///
/// hickory ResponseCode 是 enum，high/low 分别是 8-bit。
#[must_use]
pub fn response_code_to_u16(rc: ResponseCode) -> RCode {
    let low = u16::from(rc.low());
    let high = u16::from(rc.high());
    (high << 8) | low
}

/// 构造 DNS 查询 wire bytes。
///
/// 参数：
/// - `fqdn`: 已规范化的全限定域名（不以 `.` 结尾会被自动补上）
/// `client_ip`: EDNS0 client subnet。空 Vec 表示不加 EDNS0；
/// 长度 4 表示 IPv4 (/24)，长度 16 表示 IPv6 (/96)。
/// 对齐 Go `app/dns/dnscommon.go:91` 注释 `// 24 for IPV4, 96 for IPv6` 和
/// `dnscommon.go:94 netmask = 96`：IPv6 默认 /96（v26.6.1 行为）。
///
/// 返回序列化后的 DNS wire bytes。
pub fn build_dns_query(
    fqdn: &str,
    record_type: RecordType,
    req_id: u16,
    client_ip: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let name = Name::parse(fqdn, None).map_err(|e| DnsError::WireFormat(e.to_string()))?;
    let mut msg = Message::new(req_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, record_type));

    // EDNS0 client subnet（可选）。
    if matches!(client_ip.len(), 4 | 16) {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        let addr = if client_ip.len() == 4 {
            let mut b = [0u8; 4];
            b.copy_from_slice(client_ip);
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(b))
        } else {
            let mut b = [0u8; 16];
            b.copy_from_slice(client_ip);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
        };
        let source_prefix: u8 = if client_ip.len() == 4 { 24 } else { 96 };
        edns.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
            addr,
            source_prefix,
            0,
        )));
        msg.set_edns(edns);
    }

    msg.to_vec().map_err(|e| DnsError::WireFormat(e.to_string()))
}

/// DNS 响应解析结果。
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    /// 请求 ID（与查询时的 req_id 匹配）。
    pub req_id: u16,
    /// 解析得到的 IP 列表（A 查询返回 IPv4，AAAA 查询返回 IPv6）。
    pub ips: Vec<IpAddr>,
    /// 最小 TTL（秒）。
    pub ttl_secs: u32,
    /// DNS RCode。
    pub rcode: RCode,
    /// Truncated 标志（UDP 包过大需重试 TCP）。
    pub truncated: bool,
}

/// 解析 DNS 响应。
///
/// 参数：
/// - `payload`: wire bytes
/// - `expected_req_id`: 预期请求 ID（不匹配返错）
/// - `expected_type`: A 或 AAAA（仅提取该类型记录）
/// - `now`: 当前时间（计算过期时间）
pub fn parse_dns_response(
    payload: &[u8],
    expected_req_id: u16,
    expected_type: RecordType,
    _now: Instant,
) -> Result<ParsedResponse, DnsError> {
    let msg = Message::from_vec(payload).map_err(|e| DnsError::WireFormat(e.to_string()))?;

    if msg.metadata.id != expected_req_id {
        return Err(DnsError::WireFormat(format!(
            "req_id mismatch: expected {}, got {}",
            expected_req_id, msg.metadata.id
        )));
    }

    let rcode = response_code_to_u16(msg.metadata.response_code);
    let truncated = msg.metadata.truncation;

    // 仅提取预期类型的 A/AAAA 记录（其他类型如 MX/TXT 不进 IP cache）。
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for rec in &msg.answers {
        if rec.record_type() != expected_type {
            continue;
        }
        match &rec.data {
            RData::A(a) => {
                ips.push(IpAddr::V4(a.0));
            }
            RData::AAAA(aaaa) => {
                ips.push(IpAddr::V6(aaaa.0));
            }
            _ => continue,
        }
        let ttl = rec.ttl;
        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
    }

    let ttl_secs = min_ttl.unwrap_or(0);

    Ok(ParsedResponse {
        req_id: expected_req_id,
        ips,
        ttl_secs,
        rcode,
        truncated,
    })
}

/// 将 ParsedResponse 转为 IpRecord。
///
/// TTL 0 + RCode 0 + 空 ips 仍会生成记录（调用方用 IpRecord::get_ips 判断有效性）。
#[must_use]
pub fn parsed_to_ip_record(parsed: &ParsedResponse, now: Instant) -> IpRecord {
    let ttl = if parsed.ttl_secs > 0 {
        Duration::from_secs(u64::from(parsed.ttl_secs))
    } else {
        // 默认 60 秒，避免 RCode 错误响应被缓存为永久过期。
        Duration::from_secs(60)
    };
    ip_record(parsed.req_id, parsed.ips.clone(), ttl, parsed.rcode, now)
}

/// 原子计数请求 ID 生成器。对应 Go `reqIDGen`（基于 atomic counter）。
#[derive(Debug, Default)]
pub struct AtomicReqIdGen {
    counter: AtomicU16,
}

impl AtomicReqIdGen {
    #[must_use]
    pub const fn new() -> Self {
        Self { counter: AtomicU16::new(0) }
    }
}

impl ReqIdGen for AtomicReqIdGen {
    fn next_id(&self) -> u16 {
        // wrapping_add 避免 u16 溢出 panic；DNS ID 仅需唯一性不需递增。
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn fqdn_appends_dot_if_missing() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
        assert_eq!(fqdn(""), ".");
    }

    fn rec(req_id: u16, ips: Vec<IpAddr>, ttl_secs: u64, rcode: RCode) -> IpRecord {
        ip_record(req_id, ips, Duration::from_secs(ttl_secs), rcode, Instant::now())
    }

    #[test]
    fn ip_record_get_ips_normal() {
        let r = rec(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], 60, rcode::NO_ERROR);
        let (ips, ttl) = r.get_ips(Instant::now()).unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ttl > 0 && ttl <= 60);
    }

    #[test]
    fn ip_record_get_ips_expired() {
        let r = rec(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], 0, rcode::NO_ERROR);
        // 构造已过期：expire 已是 now，加微小 Negative
        let expired = IpRecord {
            req_id: 1,
            ips: r.ips.clone(),
            expire: Instant::now() - Duration::from_secs(1),
            rcode: rcode::NO_ERROR,
        };
        assert!(matches!(
            expired.get_ips(Instant::now()),
            Err(DnsError::RecordNotFound)
        ));
    }

    #[test]
    fn ip_record_get_ips_with_rcode() {
        let r = rec(1, vec![], 60, rcode::NX_DOMAIN);
        assert!(matches!(
            r.get_ips(Instant::now()),
            Err(DnsError::RCodeError(3))
        ));
    }

    #[test]
    fn ip_record_get_ips_empty_when_no_rcode() {
        let r = rec(1, vec![], 60, rcode::NO_ERROR);
        assert!(matches!(
            r.get_ips(Instant::now()),
            Err(DnsError::EmptyResponse)
        ));
    }

    #[test]
    fn merge_picks_min_ttl_across_v4_v6() {
        let now = Instant::now();
        let rec4 = IpRecord {
            req_id: 1,
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            expire: now + Duration::from_secs(120),
            rcode: rcode::NO_ERROR,
        };
        let rec6 = IpRecord {
            req_id: 2,
            ips: vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            expire: now + Duration::from_secs(30),
            rcode: rcode::NO_ERROR,
        };
        let (ips, ttl) = merge_records(IpOption::all(), Some(&rec4), Some(&rec6), now).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ttl, 30);
    }

    #[test]
    fn merge_returns_immediately_when_one_record_missing() {
        // option 同时查 v4+v6，但 v4 缺失 → RecordNotFound 直接返回。
        let now = Instant::now();
        let res = merge_records(IpOption::all(), None, None, now);
        assert!(matches!(res, Err(DnsError::RecordNotFound)));
    }
}
