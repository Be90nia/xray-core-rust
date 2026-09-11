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
use xray_tls::utls;

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
    /// 负缓存 TTL（秒）。None = 禁用。
    pub negative_ttl_secs: Option<u32>,
    /// 查询策略覆写（None 表示跟随全局）。
    pub query_strategy: Option<QueryStrategy>,
    /// 策略 ID。
    pub policy_id: u32,
    /// 期望 IP 规则（CIDR / geoip）。对应 Go `ExpectedIp`。
    pub expected_ip_rules: Vec<xray_geodata::pb::IpRule>,
    /// 不期望 IP 规则。对应 Go `UnexpectedIp`。
    pub unexpected_ip_rules: Vec<xray_geodata::pb::IpRule>,
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
            negative_ttl_secs: None,
            query_strategy: None,
            policy_id: 0,
            expected_ip_rules: Vec::new(),
            unexpected_ip_rules: Vec::new(),
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
            // Go dns.go:89-92/142-145：tag 空 → `xray.system.<uuid>`（全局唯一，
            // 防用户配置碰撞后 IsOwnLink 误判环）；此前恒 "default"。
            tag: if ns.tag.is_empty() {
                crate::config::generate_random_tag()
            } else {
                ns.tag
            },
            timeout,
            final_query: ns.final_query,
            ip_option,
            policy_id: ns.policy_id,
            act_prior: ns.act_prior,
            act_unprior: ns.act_unprior,
            // matcher 构建失败 → 启动报错（Go BuildIPMatcher 错误上抛，
            // 此前静默 None 使 expectedIPs 过滤整体失效）。
            expected_ips: build_ip_matcher(&ns.expected_ip_rules)?,
            unexpected_ips: build_ip_matcher(&ns.unexpected_ip_rules)?,
        })
    }

    /// 委托查询给内部 Server：per-query option 先与 client 静态策略取 AND
    /// （对应 Go nameserver.go:173-180，双双禁用即 ErrEmptyResponse），再应用
    /// expected/unexpected IP 四分支过滤（nameserver.go 195-225）：
    /// 非 prior 的 expected 过滤空即 Err；非 unprior 的 unexpected 剥离空即 Err；
    /// actPrior/actUnprior 命中非空时替换结果集。
    pub fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        let option = IpOption {
            ipv4_enable: option.ipv4_enable && self.ip_option.ipv4_enable,
            ipv6_enable: option.ipv6_enable && self.ip_option.ipv6_enable,
            ..option
        };
        if !option.ipv4_enable && !option.ipv6_enable {
            return Box::pin(async { Err(DnsError::EmptyResponse) });
        }
        let fut = self.server.query_ip(domain, option);
        Box::pin(async move {
            let (ips, ttl) = fut.await?;
            if ips.is_empty() {
                return Err(DnsError::EmptyResponse);
            }
            let mut ips = ips;
            if let Some(m) = self.expected_ips.as_ref() {
                if !self.act_prior {
                    ips = m.filter_ips(&ips);
                    if ips.is_empty() {
                        return Err(DnsError::EmptyResponse);
                    }
                }
            }
            if let Some(m) = self.unexpected_ips.as_ref() {
                if !self.act_unprior {
                    ips.retain(|ip| !m.match_ip(*ip));
                    if ips.is_empty() {
                        return Err(DnsError::EmptyResponse);
                    }
                }
            }
            if let Some(m) = self.expected_ips.as_ref() {
                if self.act_prior {
                    let matched = m.filter_ips(&ips);
                    if !matched.is_empty() {
                        ips = matched;
                    }
                }
            }
            if let Some(m) = self.unexpected_ips.as_ref() {
                if self.act_unprior {
                    let matched = m.filter_ips(&ips);
                    if !matched.is_empty() {
                        ips = matched;
                    }
                }
            }
            Ok((ips, ttl))
        })
    }
}

/// 从 IP 规则列表构建匹配器。对应 Go `geodata.IPReg.BuildIPMatcher`：
/// 规则列表为空 → None（无过滤）；构建失败 → 传播错误（启动报错）。
fn build_ip_matcher(
    rules: &[xray_geodata::pb::IpRule],
) -> Result<Option<Box<dyn xray_geodata::matcher::ip::IPMatcher>>, DnsError> {
    if rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        xray_geodata::matcher::ip::build_optimized_ip_matcher(rules)
            .map_err(|e| DnsError::WireFormat(format!("build ip matcher: {e}")))?,
    ))
}
/// - `tls://IP[:port]` → DoT (默认 853)
/// - `https://IP[:port][/path]` → DoH (默认 443, path 默认 /dns-query)
/// - `quic://IP[:port]` → DoQ (默认 853，Go nameserver_quic.go:41)
///
/// 仅接受 IP 地址（不含域名解析，避免 DNS 循环依赖）。
/// server_name (TLS SNI) 取自 IP 字符串。
pub fn new_server(url: &str) -> Result<Box<dyn Server>, DnsError> {
    new_server_with_config(url, NameServerConfig::default()).map(|(server, _)| server)
}

/// 从 URL + 完整配置构造 Server。对应 Go `nameserver.go NewServer` 收全量
/// `dns.NameServer` proto——`TimeoutMs`/`ClientIp`/`DisableCache`/`ServeStale`/
/// `ServeExpiredTTL`/`NegativeTtl` 逐字段流入具体 nameserver 构造（cache +
/// query_timeout + EDNS0）。默认字段路径见 [`new_server`]。
///
/// 返回补好 `address`/`port`（URL 解析结果）的完整 config，供 `Client::new` 复用。
pub fn new_server_with_config(
    url: &str,
    mut cfg: NameServerConfig,
) -> Result<(Box<dyn Server>, NameServerConfig), DnsError> {
    // Go nameserver.go NewServer：整串 localhost/fakedns 特判
    let lower = url.trim().to_ascii_lowercase();
    if lower == "localhost" {
        return Ok((local::new_local_name_server()?, cfg));
    }
    if lower == "fakedns" {
        // 9vu4：共享引擎 + `new_default` 兜底（Go nameserver.go:70-79
        // RequireFeatures 全局唯一 FakeDNSEngine；无 fakeDns app 时保持兼容）。
        let holder = crate::fakedns::Holder::new_default()?;
        return Ok((
            Box::new(fakedns::FakeDnsServer::new(fakedns::SharedFakeDnsEngine::new(holder))),
            cfg,
        ));
    }

    let (scheme_raw, rest) = url.split_once("://").unwrap_or(("", url));
    // "+local" 后缀（Go 经 dispatcher vs 直连）：Rust DNS 拨号均直连，语义等价 → 剥后缀
    let scheme = scheme_raw.strip_suffix("+local").unwrap_or(scheme_raw);

    let default_port = match scheme {
        "" | "tcp" => 53u16,
        "tls" => 853,
        "https" | "h2c" => 443,
        // Go nameserver_quic.go:41：DoQ 缺省端口 853。
        "quic" => 853,
        other => return Err(DnsError::WireFormat(format!("unknown DNS scheme: {other}"))),
    };

    // Strip path for DoH (https://IP/dns-query → IP:port)
    let host_port = rest.split('/').next().unwrap_or(rest);

    let (address, port, server_name) = parse_dns_url_host(host_port, default_port)?;
    cfg.address = address;
    cfg.port = port;

    let server = match scheme {
        "" => udp::new_classic_name_server(&cfg)?,
        "tcp" => tcp::new_tcp_name_server(&cfg)?,
        "tls" => dot::new_dot_name_server(&cfg, server_name, utls::default_client_config())?,
        "https" => doh::new_doh_name_server(&cfg, server_name, utls::default_client_config())?,
        "h2c" => doh::new_doh_h2c_name_server(&cfg)?,
        "quic" => quic::new_quic_name_server(&cfg, server_name, utls::default_client_config())?,
        _ => unreachable!(),
    };
    Ok((server, cfg))
}

/// 解析 DNS URL 的 host:port 部分。仅接受 IP（IPv4/IPv6），拒绝域名。
fn parse_dns_url_host(input: &str, default_port: u16) -> Result<(Address, u16, String), DnsError> {
    if let Ok(sa) = input.parse::<std::net::SocketAddr>() {
        let addr = match sa.ip() {
            IpAddr::V4(v4) => Address::IPv4(v4),
            IpAddr::V6(v6) => Address::IPv6(v6),
        };
        return Ok((addr, sa.port(), sa.ip().to_string()));
    }
    if let Ok(v4) = input.parse::<std::net::Ipv4Addr>() {
        return Ok((Address::IPv4(v4), default_port, v4.to_string()));
    }
    if let Ok(v6) = input.parse::<std::net::Ipv6Addr>() {
        return Ok((Address::IPv6(v6), default_port, v6.to_string()));
    }
    Err(DnsError::WireFormat(format!(
        "new_server requires IP address, got: {input}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| { let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default(); });
    }

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
    fn new_server_recognizes_localhost_and_fakedns() {
        let local = new_server("localhost").unwrap();
        assert_eq!(local.name(), "localhost");
        let local_ci = new_server("LocalHost").unwrap();
        assert_eq!(local_ci.name(), "localhost");
        let fake = new_server("fakedns").unwrap();
        assert!(fake.name().contains("FakeDNS"), "got: {}", fake.name());
    }

    #[test]
    fn new_server_strips_local_suffix() {
        // Go：https+local / tcp+local / quic+local 与无后缀版本等价（Rust 均直连）。
        let a = new_server("tcp+local://8.8.8.8").unwrap();
        assert!(a.name().contains("TCP") || a.name().contains("tcp"), "got: {}", a.name());
        let b = new_server("https+local://8.8.8.8").unwrap();
        assert!(b.name().starts_with("DoH:"), "got: {}", b.name());
    }

    #[test]
    fn new_server_h2c_scheme_builds_plain_doh() {
        let ns = new_server("h2c://8.8.8.8").unwrap();
        assert!(ns.name().starts_with("DoH-h2c:"), "got: {}", ns.name());
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
        let (ips, ttl) = client.query_ip("example.com", IpOption::all()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn new_server_udp_for_plain_ip() {
        let server = new_server("8.8.8.8").unwrap();
        assert!(server.name().starts_with("UDP"));
    }

    #[test]
    fn new_server_tcp_for_tcp_scheme() {
        let server = new_server("tcp://8.8.8.8").unwrap();
        assert!(server.name().starts_with("TCP"));
    }

    #[test]
    fn new_server_dot_for_tls_scheme() {
        ensure_crypto_provider();
        let server = new_server("tls://8.8.8.8").unwrap();
        assert!(server.name().starts_with("DoT"));
    }

    #[test]
    fn new_server_doh_for_https_scheme() {
        ensure_crypto_provider();
        let server = new_server("https://8.8.8.8").unwrap();
        assert!(server.name().starts_with("DoH"));
    }

    #[test]
    fn new_server_quic_for_quic_scheme() {
        ensure_crypto_provider();
        let server = new_server("quic://8.8.8.8").unwrap();
        assert!(server.name().starts_with("DoQ"));
    }

    #[test]
    fn new_server_rejects_unknown_scheme() {
        assert!(new_server("foo://8.8.8.8").is_err());
    }

    #[test]
    fn new_server_rejects_domain_name() {
        assert!(new_server("dns.google").is_err());
    }

    #[test]
    fn new_server_parses_custom_port() {
        let server = new_server("tcp://8.8.8.8:5353").unwrap();
        assert!(server.name().contains("5353"));
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
