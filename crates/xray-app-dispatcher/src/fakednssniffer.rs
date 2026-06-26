//! Fake DNS 嗅探器
//!
//! 对应 Go `app/dispatcher/fakednssniffer.go`。
//!
//! ## 设计
//!
//! Fake DNS 用 IP 池伪造域名映射，分发器在嗅探阶段查询映射以恢复真实域名。
//! 本 crate 不直接依赖 xray-app-dns，而是定义 [`FakeDnsEngine`] trait，
//! 由上层注入实现（避免循环依赖）。
//!
//! ## 当前状态
//!
//! - [`FakeDnsSnifferResult`] / [`DnsThenOthersSniffResult`] 均为纯数据结构，可测
//! - [`FakeDnsSnifferFactory`] 持有 `Box<dyn FakeDnsEngine>`，sniff 实现独立可测
//! - [`FakeDnsEngine`] trait 由 xray-app-dns crate 实现

use crate::error::DispatcherError;
use crate::sniffer::{ProtocolSniffer, SniffError, SniffResult, SnifferIsProtoSubsetOf};
use std::fmt::Debug;
use std::net::IpAddr;
use xray_common::net::network::Network;

/// Fake DNS 引擎 trait
///
/// 对应 Go `features/dns.FakeDNSEngine` + `FakeDNSEngineRev0`。
/// 由 xray-app-dns crate 实现（P4-1），本 crate 只定义接口避免循环依赖。
pub trait FakeDnsEngine: Send + Sync + Debug {
    /// 根据 fake IP 查询真实域名，无匹配返回空字符串。
    ///
    /// 对应 Go `FakeDNSEngine.GetDomainFromFakeDNS(addr)`。
    fn get_domain_from_fake_dns(&self, addr: &IpAddr) -> String;

    /// 判断 IP 是否在 fake IP 池中（`FakeDNSEngineRev0.IsIPInIPPool`）。
    ///
    /// 默认实现返回 `false`，表示引擎不支持池查询。
    fn is_ip_in_ip_pool(&self, _addr: &IpAddr) -> bool {
        false
    }
}

/// Fake DNS 嗅探结果（持有域名）
///
/// 对应 Go `fakeDNSSniffResult` struct。
#[derive(Debug, Clone)]
pub struct FakeDnsSniffResult {
    domain_name: String,
}

impl FakeDnsSniffResult {
    /// 用域名构造。
    #[must_use]
    pub fn new(domain_name: impl Into<String>) -> Self {
        Self {
            domain_name: domain_name.into(),
        }
    }

    /// 获取持有的域名。
    #[must_use]
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }
}

impl SniffResult for FakeDnsSniffResult {
    fn protocol(&self) -> &str {
        "fakedns"
    }

    fn domain(&self) -> &str {
        &self.domain_name
    }
}

/// "fake DNS 优先，失败则试其他协议" 嗅探结果
///
/// 对应 Go `DNSThenOthersSniffResult` struct。协议名为 `fakedns+others`。
#[derive(Debug, Clone)]
pub struct DnsThenOthersSniffResult {
    /// fakedns 查到的域名
    pub domain_name: String,
    /// 备用嗅探器查出的原始协议（如 "http"/"tls"）
    pub protocol_original_name: String,
}

impl DnsThenOthersSniffResult {
    /// 用域名 + 备用协议名构造。
    #[must_use]
    pub fn new(domain_name: impl Into<String>, protocol_original_name: impl Into<String>) -> Self {
        Self {
            domain_name: domain_name.into(),
            protocol_original_name: protocol_original_name.into(),
        }
    }
}

impl SniffResult for DnsThenOthersSniffResult {
    fn protocol(&self) -> &str {
        "fakedns+others"
    }

    fn domain(&self) -> &str {
        &self.domain_name
    }
}

impl SnifferIsProtoSubsetOf for DnsThenOthersSniffResult {
    fn is_proto_subset_of(&self, protocol_name: &str) -> bool {
        protocol_name.starts_with(&self.protocol_original_name)
    }
}

/// Fake DNS 嗅探器工厂，包装 [`FakeDnsEngine`] 并提供 [`ProtocolSniffer`] impl。
///
/// 对应 Go `newFakeDNSSniffer(ctx)` 返回的 `protocolSnifferWithMetadata`。
/// 是 metadata 嗅探器（仅在连接建立时调用，不参与路由协议识别）。
pub struct FakeDnsSnifferFactory {
    /// 引用 FakeDnsEngine，由上层注入
    pub engine: Box<dyn FakeDnsEngine>,
    /// 嗅探时查询的目标 IP（从 session.Outbound.Target.Address 提取，由调用方提供）
    pub target_ip: Option<IpAddr>,
}

impl Debug for FakeDnsSnifferFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
 f.debug_struct("FakeDnsSnifferFactory")
            .field("target_ip", &self.target_ip)
            .finish()
    }
}

impl FakeDnsSnifferFactory {
    /// 用 engine 构造嗅探器。
    #[must_use]
    pub fn new(engine: Box<dyn FakeDnsEngine>) -> Self {
        Self {
            engine,
            target_ip: None,
        }
    }

    /// 设置要查询的 IP（builder）。
    pub fn with_target_ip(mut self, ip: IpAddr) -> Self {
        self.target_ip = Some(ip);
        self
    }
}

impl ProtocolSniffer for FakeDnsSnifferFactory {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        let Some(ip) = self.target_ip else {
            return Ok(None); // NoClue
        };
        let domain = self.engine.get_domain_from_fake_dns(&ip);
        if domain.is_empty() {
            return Ok(None);
        }
        Ok(Some(Box::new(FakeDnsSniffResult::new(domain)) as Box<dyn SniffResult>))
    }

    fn metadata_only(&self) -> bool {
        true
    }

    fn network(&self) -> Network {
        // metadata 嗅探器不按 network 过滤，这里返回默认 TCP
        Network::TCP
    }
}

/// 从 `engine` 构造 fake DNS 嗅探器，若 engine 为 None 则返回错误。
///
/// 对应 Go `newFakeDNSSniffer`。
pub fn try_new_fake_dns_sniffer(
    engine: Option<Box<dyn FakeDnsEngine>>,
) -> Result<FakeDnsSnifferFactory, DispatcherError> {
    let Some(engine) = engine else {
        return Err(DispatcherError::FakeDnsNotInitialized);
    };    Ok(FakeDnsSnifferFactory::new(engine))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 FakeDnsEngine
    #[derive(Debug)]
    struct MockEngine {
        mapping: std::collections::HashMap<IpAddr, String>,
        pool: Vec<IpAddr>,
    }

    impl FakeDnsEngine for MockEngine {
        fn get_domain_from_fake_dns(&self, addr: &IpAddr) -> String {
            self.mapping.get(addr).cloned().unwrap_or_default()
        }
        fn is_ip_in_ip_pool(&self, addr: &IpAddr) -> bool {
            self.pool.contains(addr)
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fake_dns_sniff_result_protocol_is_fakedns() {
        let r = FakeDnsSniffResult::new("example.com");
        assert_eq!(r.protocol(), "fakedns");
        assert_eq!(r.domain(), "example.com");
    }

    #[test]
    fn fake_dns_sniff_result_domain_name_accessor() {
        let r = FakeDnsSniffResult::new("example.com");
        assert_eq!(r.domain_name(), "example.com");
    }

    #[test]
    fn dns_then_others_protocol_is_fakedns_plus_others() {
        let r = DnsThenOthersSniffResult::new("example.com", "http");
        assert_eq!(r.protocol(), "fakedns+others");
        assert_eq!(r.domain(), "example.com");
    }

    #[test]
    fn dns_then_others_is_proto_subset_of_prefix_match() {
        let r = DnsThenOthersSniffResult::new("a.com", "http");
        assert!(r.is_proto_subset_of("http"));
        assert!(r.is_proto_subset_of("https"));
        assert!(!r.is_proto_subset_of("tls"));
    }

    #[test]
    fn try_new_fake_dns_sniffer_err_when_engine_none() {
        let r = try_new_fake_dns_sniffer(None);
        assert!(matches!(r, Err(DispatcherError::FakeDnsNotInitialized)));
    }

    #[test]
    fn fake_dns_sniffer_factory_returns_noclue_without_target_ip() {
        let engine = Box::new(MockEngine {
            mapping: std::collections::HashMap::new(),
            pool: vec![],
        });
        let s = FakeDnsSnifferFactory::new(engine);
        let r = s.sniff(&[]).expect("no error");
        assert!(r.is_none());
    }

    #[test]
    fn fake_dns_sniffer_factory_returns_domain_when_mapped() {
        let mut map = std::collections::HashMap::new();
        map.insert(ip("198.51.100.1"), "mapped.example.com".to_string());
        let engine = Box::new(MockEngine {
            mapping: map,
            pool: vec![],
        });
        let s = FakeDnsSnifferFactory::new(engine).with_target_ip(ip("198.51.100.1"));
        let r = s.sniff(&[]).expect("no error").expect("match");
        assert_eq!(r.protocol(), "fakedns");
        assert_eq!(r.domain(), "mapped.example.com");
    }

    #[test]
    fn fake_dns_sniffer_factory_returns_noclue_when_ip_not_in_pool() {
        let engine = Box::new(MockEngine {
            mapping: std::collections::HashMap::new(),
            pool: vec![],
        });
        let s = FakeDnsSnifferFactory::new(engine).with_target_ip(ip("198.51.100.99"));
        let r = s.sniff(&[]).expect("no error");
        assert!(r.is_none());
    }

    #[test]
    fn fake_dns_sniffer_is_metadata_only() {
        let engine = Box::new(MockEngine {
            mapping: std::collections::HashMap::new(),
            pool: vec![],
        });
        let s = FakeDnsSnifferFactory::new(engine);
        assert!(s.metadata_only());
    }
}
