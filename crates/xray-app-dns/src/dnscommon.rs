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

// TODO(ponytail): `genEDNS0Options` / `buildReqMsgs` —— 依赖 DNS 协议层（hickory-proto 或
// 自研 wire format）。引入后实现 `ReqIdGen::Default`、`DnsMessage` 默认实现。

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
