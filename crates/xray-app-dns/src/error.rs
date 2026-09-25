//! DNS 应用层错误类型。
//!
//! 对应 Go `app/dns/` 各文件中 `errors.New(...)` 与 `features/dns` 包错误。

/// DNS 应用错误。
///
/// 单一 crate 级错误枚举，聚合 nameserver / hosts / cache_controller / fakedns
/// 等子模块的错误，避免业务代码到处字符串匹配。
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// 缓存中未找到记录（对应 Go `errRecordNotFound`）。
    #[error("record not found")]
    RecordNotFound,

    /// 响应为空（对应 Go `dns_feature.ErrEmptyResponse`）。
    #[error("empty response")]
    EmptyResponse,

    /// DNS 服务器返回错误码（对应 Go `dns_feature.RCodeError(uint16)`）。
    /// `rcode == 0` 视为 `EmptyResponse`，非 0 视为错误。
    #[error("dns rcode error: {0}")]
    RCodeError(u16),

    /// 未知的查询策略（对应 Go `unexpected query strategy`）。
    #[error("unexpected query strategy: {0}")]
    InvalidQueryStrategy(i32),

    /// 该 nameserver 无可用查询策略（IPv4/IPv6 都禁用）。
    #[error("no query strategy available for {0}")]
    NoQueryStrategy(String),

    /// 客户端 IP 长度非法（合法值：0/4/16）。
    #[error("unexpected client ip length: {0}")]
    InvalidClientIpLength(usize),

    /// 静态 hosts 中包含非法 IP（已忽略该 IP）。
    #[error("invalid ip address in static hosts: {0}")]
    InvalidStaticHostsIP(String),

    /// FakeDNS 配置非法（IP 池为空或 LRU 为 0）。
    #[error("invalid fake dns setting")]
    InvalidFakeDnsSetting,

    /// FakeDNS IP 池 CIDR 解析失败。
    #[error("unable to parse cidr for fake dns ip assignment: {0}")]
    InvalidFakeDnsCidr(String),

    /// FakeDNS LRU 容量超出子网地址空间。
    #[error("lru size {lru} is bigger than subnet size {rooms}")]
    LruBiggerThanSubnet {
        /// 配置的 LRU 大小。
        lru: usize,
        /// 子网可用地址位数。
        rooms: u32,
    },

    /// 未注册任何 FakeDNSEngine。
    #[error("unable to locate a fake dns engine")]
    NoFakeDnsEngine,

    /// `features::dns::DnsClient` 上一层错误（DomainNotFound/ServerError/Timeout/Other）。
    #[error(transparent)]
    Features(#[from] xray_features::dns::DnsError),

    /// 当前路径尚未实现（IO 边界 / 待生态成熟）。
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// DNS wire format 编解码错误（来自 hickory-proto）。
    #[error("dns wire format error: {0}")]
    WireFormat(String),

    /// 系统 DNS 解析失败（hickory-resolver 错误）。
    #[error("system dns resolution failed: {0}")]
    SystemResolve(String),
}

impl DnsError {
    /// 当 RCode == 0 视为 `EmptyResponse`，否则 `RCodeError(rcode)`。
    ///
    /// 对应 Go `dns.RCodeError(rcode)` 的语义：构造时 0 也合法，业务处用
    /// `uint16(err) == 0` 区分（见 `app/dns/hosts.go:84`）。
    #[must_use]
    pub fn from_rcode(rcode: u16) -> Self {
        if rcode == 0 { Self::EmptyResponse } else { Self::RCodeError(rcode) }
    }
}

/// `RCodeError` 的便捷判断：判断当前错误是否携带非 0 RCode。
impl DnsError {
    /// 返回错误携带的 RCode（仅 `RCodeError` 变体返回 `Some`）。
    #[must_use]
    pub fn rcode(&self) -> Option<u16> {
        if let Self::RCodeError(code) = self { Some(*code) } else { None }
    }
}

/// app 层错误 → features 层错误（trait 边界透传）。
///
/// `EmptyResponse` / `RCodeError` 语义保真映射（Go 中两者为同一错误类型跨层传递），
/// 其余降级为 `Other` 字符串。
impl From<DnsError> for xray_features::dns::DnsError {
    fn from(e: DnsError) -> Self {
        use xray_features::dns::DnsError as F;
        match e {
            DnsError::EmptyResponse => F::EmptyResponse,
            DnsError::RCodeError(code) => F::Rcode(code),
            DnsError::Features(f) => f,
            other => F::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_rcode_zero_is_empty_response() {
        assert!(matches!(DnsError::from_rcode(0), DnsError::EmptyResponse));
    }

    #[test]
    fn from_rcode_nonzero_is_rcode_error() {
        match DnsError::from_rcode(3) {
            DnsError::RCodeError(3) => {},
            other => panic!("expected RCodeError(3), got {other:?}"),
        }
    }

    #[test]
    fn rcode_extracts_only_rcode_variant() {
        assert_eq!(DnsError::RCodeError(2).rcode(), Some(2));
        assert_eq!(DnsError::EmptyResponse.rcode(), None);
        assert_eq!(DnsError::RecordNotFound.rcode(), None);
    }

    #[test]
    fn features_error_converts_via_from() {
        let upstream = xray_features::dns::DnsError::Timeout;
        let err: DnsError = upstream.into();
        assert!(matches!(err, DnsError::Features(_)));
    }

    #[test]
    fn display_messages_match_go_style() {
        assert_eq!(DnsError::RecordNotFound.to_string(), "record not found");
        assert_eq!(DnsError::EmptyResponse.to_string(), "empty response");
        assert_eq!(DnsError::InvalidQueryStrategy(99).to_string(), "unexpected query strategy: 99");
        assert_eq!(
            DnsError::InvalidClientIpLength(7).to_string(),
            "unexpected client ip length: 7"
        );
    }
}
