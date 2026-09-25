//! 嗅探配置与嗅探请求
//!
//! 对应 Go `app/proxyman/config.go` 的 `BuildSniffingRequest` 函数。
//!
//! Go 原版调用 `geodata.DomainReg.BuildDomainMatcher(...)` 把 proto 的 `DomainRule`
//! 列表编译成 `domain.Matcher`。Rust 端 `xray-geodata` 暂未暴露等价 API，
//! 这里保留原始字符串 + 提供匹配 helper（与 P4-3 dispatcher 的 `SniffingRequest` 同模式）。

use std::net::IpAddr;

use ipnet::IpNet;
use xray_proto::xray::{
    app::proxyman::SniffingConfig,
    common::geodata::{domain_rule, ip_rule},
};

use crate::error::ProxymanError;

/// 嗅探请求（对应 Go `session.SniffingRequest`）
///
/// 注意：与 `xray-app-dispatcher` crate 内的 `SniffingRequest` 是**同名独立类型**——
/// proxyman 与 dispatcher 同为 Layer 4 应用服务，互不依赖，各自维护此结构。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniffingRequest {
    /// 是否启用嗅探
    pub enabled: bool,
    /// 命中以下协议时覆盖目的地（"http"、"tls"、"fakedns" 等）
    pub override_destination_for_protocol: Vec<String>,
    /// 仅嗅探元数据（不读 payload）
    pub metadata_only: bool,
    /// 仅路由（不改 target）
    pub route_only: bool,
    /// 排除域名（不做 sniff 覆盖），原始字符串（字面量或正则）
    pub exclude_for_domain: Vec<String>,
    /// 排除 CIDR / IP（不做 sniff 覆盖），存储为 CIDR 字符串便于 `IpNet::contains` 判断
    pub exclude_for_ip: Vec<String>,
}

impl SniffingRequest {
    /// 从 proto [`SniffingConfig`] 构造 [`SniffingRequest`]。
    ///
    /// `cfg = None` 时返回空请求（Go 原版同样行为）。
    ///
    /// # Errors
    ///
    /// 当前实现**不返回错误**（与 Go 行为一致：matcher 构建失败才报错，Rust
    /// 跳过编译直接保留字符串）。 保留 `Result` 签名以匹配 Go 接口风格，便于未来接入真实
    /// matcher 时返回错误。
    pub fn from_proto(cfg: Option<&SniffingConfig>) -> Result<Self, ProxymanError> {
        let Some(cfg) = cfg else {
            return Ok(Self::default());
        };

        let mut req = Self {
            enabled: cfg.enabled,
            override_destination_for_protocol: cfg.destination_override.clone(),
            metadata_only: cfg.metadata_only,
            route_only: cfg.route_only,
            ..Self::default()
        };

        // DomainRule oneof：仅取 Custom.value（字面量/正则），跳过 Geosite（依赖 geodata 文件加载）
        for rule in &cfg.domains_excluded {
            if let Some(domain_rule::Value::Custom(d)) = rule.value.as_ref() {
                if !d.value.is_empty() {
                    req.exclude_for_domain.push(d.value.clone());
                }
            }
            // ponytail: Geosite 变体依赖 xray-geodata 文件加载，TODO 接入后处理
        }

        // IpRule oneof：仅取 Custom.cidr → 转 CIDR 字符串
        for rule in &cfg.ips_excluded {
            if let Some(ip_rule::Value::Custom(c)) = rule.value.as_ref() {
                if let Some(cidr) = c.cidr.as_ref() {
                    if let Some(net) = cidr_from_proto(&cidr.ip, cidr.prefix) {
                        req.exclude_for_ip.push(net.to_string());
                    }
                }
            }
            // ponytail: Geoip 变体依赖 xray-geodata 文件加载，TODO 接入后处理
        }

        Ok(req)
    }

    /// 判断域名是否命中"排除域名"列表。
    ///
    /// 对应 Go `request.ExcludeForDomain.MatchAny(domain)`。
    /// 当前用 `contains` 子串匹配（与 P4-3 dispatcher 同模式），
    /// 真实 matcher（前缀/正则/完整匹配）待 xray-geodata 暴露 API 后接入。
    #[must_use]
    pub fn matches_domain_excluded(&self, domain: &str) -> bool {
        if self.exclude_for_domain.is_empty() {
            return false;
        }
        let domain_lower = domain.to_lowercase();
        self.exclude_for_domain.iter().any(|excl| domain_lower.contains(&excl.to_lowercase()))
    }

    /// 判断 IP 是否命中"排除 IP"列表（CIDR contains 判断）。
    ///
    /// 对应 Go `request.ExcludeForIP.Match(ip)`。
    #[must_use]
    pub fn matches_ip_excluded(&self, ip: IpAddr) -> bool {
        self.exclude_for_ip.iter().any(|cidr_str| {
            // ponytail: 解析失败按不匹配处理（保留容错）；性能不是热路径（每次连接 1 次）
            cidr_str.parse::<IpNet>().map(|net| net.contains(&ip)).unwrap_or(false)
        })
    }
}

/// 把 proto CIDR（4 字节 / 16 字节 + prefix 长度）转 `IpNet`。
fn cidr_from_proto(bytes: &[u8], prefix: u32) -> Option<IpNet> {
    match bytes.len() {
        4 => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(bytes);
            IpNet::new(IpAddr::V4(arr.into()), u8::try_from(prefix).ok()?).ok()
        },
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            IpNet::new(IpAddr::V6(arr.into()), u8::try_from(prefix).ok()?).ok()
        },
        _ => None,
    }
}

/// 构造 [`SniffingRequest`]（对应 Go `proxyman.BuildSniffingRequest`）
///
/// # Errors
///
/// 见 [`SniffingRequest::from_proto`]。
pub fn build_sniffing_request(
    cfg: Option<&SniffingConfig>,
) -> Result<SniffingRequest, ProxymanError> {
    SniffingRequest::from_proto(cfg)
}

#[cfg(test)]
mod tests {
    // 测试构造以字段赋值表意（对齐 Go 逐字段装配），struct update 化反而降低对照度
    #![allow(clippy::field_reassign_with_default)]
    use xray_proto::xray::{
        app::proxyman::SniffingConfig as ProtoSniffingConfig,
        common::geodata::{
            Cidr, CidrRule, Domain, DomainRule, IpRule, domain::Type as DomainType,
            domain_rule::Value as DomainValue, ip_rule::Value as IpValue,
        },
    };

    use super::*;

    #[test]
    fn from_proto_none_returns_default() {
        let req = SniffingRequest::from_proto(None).unwrap();
        assert_eq!(req, SniffingRequest::default());
    }

    #[test]
    fn from_proto_basic_fields() {
        let mut cfg = ProtoSniffingConfig::default();
        cfg.enabled = true;
        cfg.metadata_only = false;
        cfg.route_only = true;
        cfg.destination_override = vec!["http".to_string(), "tls".to_string()];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert!(req.enabled);
        assert!(!req.metadata_only);
        assert!(req.route_only);
        assert_eq!(req.override_destination_for_protocol, vec!["http", "tls"]);
    }

    #[test]
    fn from_proto_extracts_domain_excluded_literal() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = DomainRule::default();
        let mut d = Domain::default();
        d.r#type = DomainType::Domain as i32;
        d.value = "example.com".to_string();
        rule.value = Some(DomainValue::Custom(d));
        cfg.domains_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert_eq!(req.exclude_for_domain, vec!["example.com".to_string()]);
    }

    #[test]
    fn from_proto_skips_empty_domain_value() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = DomainRule::default();
        let mut d = Domain::default();
        d.value = String::new();
        rule.value = Some(DomainValue::Custom(d));
        cfg.domains_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert!(req.exclude_for_domain.is_empty());
    }

    #[test]
    fn from_proto_skips_geosite_variant() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = DomainRule::default();
        rule.value = Some(DomainValue::Geosite(Default::default()));
        cfg.domains_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert!(req.exclude_for_domain.is_empty());
    }

    #[test]
    fn from_proto_extracts_cidr_v4() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = IpRule::default();
        let mut custom = CidrRule::default();
        let mut cidr = Cidr::default();
        cidr.ip = vec![192, 168, 1, 0];
        cidr.prefix = 24;
        custom.cidr = Some(cidr);
        rule.value = Some(IpValue::Custom(custom));
        cfg.ips_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert_eq!(req.exclude_for_ip, vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn from_proto_extracts_cidr_v6() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = IpRule::default();
        let mut custom = CidrRule::default();
        let mut cidr = Cidr::default();
        cidr.ip = vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        cidr.prefix = 64;
        custom.cidr = Some(cidr);
        rule.value = Some(IpValue::Custom(custom));
        cfg.ips_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert_eq!(req.exclude_for_ip, vec!["fe80::/64".to_string()]);
    }

    #[test]
    fn from_proto_skips_invalid_cidr_length() {
        let mut cfg = ProtoSniffingConfig::default();
        let mut rule = IpRule::default();
        let mut custom = CidrRule::default();
        let mut cidr = Cidr::default();
        cidr.ip = vec![1, 2, 3]; // 非法长度
        cidr.prefix = 24;
        custom.cidr = Some(cidr);
        rule.value = Some(IpValue::Custom(custom));
        cfg.ips_excluded = vec![rule];

        let req = SniffingRequest::from_proto(Some(&cfg)).unwrap();
        assert!(req.exclude_for_ip.is_empty());
    }

    #[test]
    fn matches_domain_excluded_substring_case_insensitive() {
        let mut req = SniffingRequest::default();
        req.exclude_for_domain = vec!["evil.com".to_string()];

        assert!(req.matches_domain_excluded("www.EVIL.COM"));
        assert!(req.matches_domain_excluded("evil.com.evil.com"));
        assert!(!req.matches_domain_excluded("good.org"));
    }

    #[test]
    fn matches_domain_excluded_empty_list() {
        let req = SniffingRequest::default();
        assert!(!req.matches_domain_excluded("anything.com"));
    }

    #[test]
    fn matches_ip_excluded_in_cidr_v4() {
        let mut req = SniffingRequest::default();
        req.exclude_for_ip = vec!["192.168.1.0/24".to_string()];

        assert!(req.matches_ip_excluded("192.168.1.100".parse().unwrap()));
        assert!(req.matches_ip_excluded("192.168.1.1".parse().unwrap()));
        assert!(!req.matches_ip_excluded("192.168.2.1".parse().unwrap()));
        assert!(!req.matches_ip_excluded("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn matches_ip_excluded_v6() {
        let mut req = SniffingRequest::default();
        req.exclude_for_ip = vec!["fe80::/64".to_string()];

        assert!(req.matches_ip_excluded("fe80::1".parse().unwrap()));
        assert!(!req.matches_ip_excluded("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn matches_ip_excluded_invalid_cidr_ignored() {
        let mut req = SniffingRequest::default();
        req.exclude_for_ip = vec!["not-a-cidr".to_string()];

        assert!(!req.matches_ip_excluded("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn build_sniffing_request_delegates_to_from_proto() {
        let cfg = ProtoSniffingConfig { enabled: true, ..Default::default() };
        let req = build_sniffing_request(Some(&cfg)).unwrap();
        assert!(req.enabled);
    }

    #[test]
    fn cidr_from_proto_v4_round_trip() {
        let net = cidr_from_proto(&[10, 0, 0, 0], 8).unwrap();
        assert_eq!(net.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn cidr_from_proto_invalid_prefix_overflow() {
        assert!(cidr_from_proto(&[10, 0, 0, 0], 33).is_none());
    }

    #[test]
    fn cidr_from_proto_wrong_byte_count() {
        assert!(cidr_from_proto(&[1, 2, 3], 24).is_none());
        assert!(cidr_from_proto(&[0; 15], 64).is_none());
        assert!(cidr_from_proto(&[0; 17], 64).is_none());
    }
}
