//! DNS 名称服务器：Server trait + Client + 工厂占位。
//!
//! 对应 Go `app/dns/nameserver.go`。
//!
//! ## 范围
//!
//! - `Server` trait：保持 dyn-compatible，手写 `Pin<Box<dyn Future>>`（与项目风格一致）。
//! - `Client` 结构体 + `new_client` 构造逻辑：完整翻译。
//! - `new_server` 工厂：占位（依赖 transport / routing / DoH/QUIC 客户端等 IO 边界）。

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use xray_common::net::address::Address;

use crate::config::{IpOption, QueryStrategy, resolve_ip_option_override};
use crate::error::DnsError;

pub mod udp;
pub mod tcp;
pub mod dot;
pub mod doh;
pub mod quic;
pub mod local;
pub mod fakedns;
pub mod cached;

/// DNS 名称服务器接口。对应 Go `Server` interface。
///
/// 实现：`ClassicNameServer` (UDP)、`TCPNameServer`、`DoHNameServer`、`QUICNameServer`、
/// `LocalNameServer`、`FakeDNSServer`。当前仅 `FakeDNSServer` 实现；其他等 transport
/// / hickory 等依赖就位后接入。
pub trait Server: Send + Sync {
    /// 服务名（用于日志/诊断）。
    fn name(&self) -> &str;

    /// 是否禁用缓存。
    fn is_disable_cache(&self) -> bool;

    /// 查询域名对应的 IP。
    ///
    /// 返回 `(ips, ttl_seconds)`。
    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>>;
}

/// DNS 客户端：包装单个 Server，附加期望 IP / 超时 / 标签等。对应 Go `Client`。
pub struct Client {
    /// 内部 Server 实现。
    pub server: Box<dyn Server>,
    /// 是否跳过 fallback。
    pub skip_fallback: bool,
    /// 期望 IP 匹配器（Go `expectedIPs geodata.IPMatcher`）。
    /// ponytail: trait 已存在 `xray_geodata::matcher::ip::IPMatcher`，保留为可选。
    pub expected_ips: Option<Box<dyn xray_geodata::matcher::ip::IPMatcher>>,
    /// 不期望 IP 匹配器。
    pub unexpected_ips: Option<Box<dyn xray_geodata::matcher::ip::IPMatcher>>,
    /// 标签（用于日志）。
    pub tag: String,
    /// 超时时长。
    pub timeout: Duration,
    /// 是否作为最终查询。
    pub final_query: bool,
    /// IP 选项。
    pub ip_option: IpOption,
    /// 是否跟随系统偏好。
    pub check_system: bool,
    /// 策略 ID（用于多策略路由）。
    pub policy_id: u32,
    /// ActPrior 标记。
    pub act_prior: bool,
    /// ActUnprior 标记。
    pub act_unprior: bool,
}

/// 单个 NameServer 的 proto 配置（手写等价 Go `NameServer` proto message）。
///
/// proto 文件未生成，本结构作为上层构造 Client 的入参。
#[derive(Debug, Clone)]
pub struct NameServerConfig {
    /// 服务地址（域名或 IP）。
    pub address: Address,
    /// 客户端 IP（EDNS0 subnet）。
    pub client_ip: Vec<u8>,
    /// 端口（默认 53）。
    pub port: u16,
    /// 是否跳过 fallback。
    pub skip_fallback: bool,
    /// 是否优先解析。
    pub act_prior: bool,
    /// 是否降级解析。
    pub act_unprior: bool,
    /// 自定义 tag。
    pub tag: String,
    /// 自定义超时（毫秒）。0 表示默认 4000ms。
    pub timeout_ms: u32,
    /// 是否最终查询。
    pub final_query: bool,
    /// 是否禁用缓存。
    pub disable_cache: Option<bool>,
    /// 是否提供过期数据。
    pub serve_stale: Option<bool>,
    /// 过期 TTL。
    pub serve_expired_ttl: Option<u32>,
    /// 查询策略覆写（None 表示跟随全局）。
    pub query_strategy: Option<QueryStrategy>,
    /// 策略 ID。
    pub policy_id: u32,
}

impl Default for NameServerConfig {
    fn default() -> Self {
        Self {
            address: Address::IPv4(std::net::Ipv4Addr::UNSPECIFIED),
            client_ip: Vec::new(),
            port: 53,
            skip_fallback: false,
            act_prior: false,
            act_unprior: false,
            tag: String::new(),
            timeout_ms: 0,
            final_query: false,
            disable_cache: None,
            serve_stale: None,
            serve_expired_ttl: None,
            query_strategy: None,
            policy_id: 0,
        }
    }
}

impl Client {
    /// 从配置构造 Client。对应 Go `NewClient`。
    ///
    /// 入参：nameserver 配置 + 基线 IP 选项 + 可选 server 实现。
    /// ponytail: Go 用 `core.RequireFeatures` 从容器拿 Dispatcher，Rust 端要求调用方传入
    /// `Box<dyn Server>`，避免依赖全局容器。
    #[must_use]
    pub fn new(
        ns: NameServerConfig,
        base_ip_option: IpOption,
        server: Box<dyn Server>,
    ) -> Result<Self, DnsError> {
        let ip_option = resolve_ip_option_override(base_ip_option, ns.query_strategy);
        if !ip_option.ipv4_enable && !ip_option.ipv6_enable {
            return Err(DnsError::NoQueryStrategy(format!("{:?}", ns.address)));
        }

        let timeout = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };

        Ok(Self {
            server,
            skip_fallback: ns.skip_fallback,
            expected_ips: None,
            unexpected_ips: None,
            tag: if ns.tag.is_empty() {
                "default".to_string()
            } else {
                ns.tag
            },
            timeout,
            final_query: ns.final_query,
            ip_option,
            check_system: matches!(ns.query_strategy, Some(QueryStrategy::UseSys)),
            policy_id: ns.policy_id,
            act_prior: ns.act_prior,
            act_unprior: ns.act_unprior,
        })
    }

    /// 委托查询给内部 Server。
    pub fn query_ip<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        self.server.query_ip(domain, self.ip_option)
    }
}

/// `new_server` 工厂占位。对应 Go `NewServer`。
///
/// **本切片未实现 URL scheme 解析**。DoH/DoT/DoQ 留 follow-up bd 任务。
/// 调用方应直接使用具体子模块：
/// - UDP：`crate::nameserver::udp::new_classic_name_server(&ns)`
/// - TCP：`crate::nameserver::tcp::new_tcp_name_server(&ns)`
///
/// TODO: follow-up 任务解析 `tcp://` / `https://` / `quic://` URL scheme 后再实现。
pub fn new_server(_dest: Address) -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("new_server factory; use udp/tcp submodule directly"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 测试用 Server：固定返回指定 IP + TTL。
    struct StaticServer {
        name: String,
        ips: Vec<IpAddr>,
        ttl: u32,
    }

    impl Server for StaticServer {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_disable_cache(&self) -> bool {
            false
        }

        fn query_ip<'a>(
            &'a self,
            _domain: &'a str,
            _option: IpOption,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
            let ips = self.ips.clone();
            let ttl = self.ttl;
            Box::pin(async move { Ok((ips, ttl)) })
        }
    }

    fn sample_ns() -> NameServerConfig {
        NameServerConfig {
            address: Address::Domain("8.8.8.8".to_string()),
            timeout_ms: 1000,
            tag: "gcp".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn client_new_with_default_timeout_when_zero() {
        let mut ns = sample_ns();
        ns.timeout_ms = 0;
        let server: Box<dyn Server> =
            Box::new(StaticServer { name: "test".to_string(), ips: Vec::new(), ttl: 0 });
        let client = Client::new(ns, IpOption::all(), server).unwrap();
        assert_eq!(client.timeout, Duration::from_millis(4000));
    }

    #[test]
    fn client_new_uses_configured_timeout() {
        let ns = sample_ns();
        let server: Box<dyn Server> =
            Box::new(StaticServer { name: "test".to_string(), ips: Vec::new(), ttl: 0 });
        let client = Client::new(ns, IpOption::all(), server).unwrap();
        assert_eq!(client.timeout, Duration::from_millis(1000));
        assert_eq!(client.tag, "gcp");
    }

    #[test]
    fn client_new_rejects_when_both_v4_v6_disabled_by_override() {
        let mut ns = sample_ns();
        // 强制子 ns 仅查 IPv6，但基线 IP 选项禁用 IPv6。
        ns.query_strategy = Some(QueryStrategy::UseIp6);
        let server: Box<dyn Server> =
            Box::new(StaticServer { name: "test".to_string(), ips: Vec::new(), ttl: 0 });
        let base = IpOption {
            ipv4_enable: true,
            ipv6_enable: false,
            fake_enable: false,
        };
        match Client::new(ns, base, server) {
            Err(DnsError::NoQueryStrategy(_)) => {}
            Err(e) => panic!("expected NoQueryStrategy, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn client_query_ip_delegates_to_server() {
        let ns = sample_ns();
        let server: Box<dyn Server> = Box::new(StaticServer {
            name: "test".to_string(),
            ips: vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))],
            ttl: 60,
        });
        let client = Client::new(ns, IpOption::all(), server).unwrap();
        let (ips, ttl) = client.query_ip("example.com").await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn new_server_factory_returns_not_implemented() {
        match new_server(Address::Domain("8.8.8.8".to_string())) {
            Err(DnsError::NotImplemented(_)) => {}
            Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn server_trait_is_dyn_compatible() {
        // 验证 trait 可作 trait object。
        let s: Box<dyn Server> =
            Box::new(StaticServer { name: "x".to_string(), ips: Vec::new(), ttl: 0 });
        assert_eq!(s.name(), "x");
        assert!(!s.is_disable_cache());
    }
}
