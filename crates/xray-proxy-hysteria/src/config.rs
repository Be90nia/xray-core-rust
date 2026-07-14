//! Hysteria 代理配置（proxy 层）。
//!
//! 对应 Go `proxy/hysteria/outbound.go` 中的 dial 配置 + transport Config 的组合。
//! transport 层的 [`xray_transport_hysteria::proto_config::Config`] 负责 QUIC 参数，
//! 本模块负责 proxy 层（auth / server 地址 / ALPN）。

use crate::error::{Result, HysteriaProxyError};

/// Hysteria 代理配置（客户端出站）。
#[derive(Debug, Clone)]
pub struct HysteriaConfig {
    /// 服务器地址 `host:port`。
    pub server_addr: String,
    /// TLS SNI（默认等于 server_addr 的 host 部分）。
    pub server_name: String,
    /// 鉴权 token。
    pub auth: String,
    /// QUIC ALPN 协议列表（hysteria 默认 `hysteria`/`h3`）。
    pub alpn: Vec<String>,
    /// Brutal 拥塞控制上行带宽（bps，0=禁用 Brutal）。
    pub brutal_up_bps: u64,
    /// UDP session 空闲超时（秒）。
    pub udp_idle_timeout_secs: u64,
}

impl HysteriaConfig {
    /// 默认 ALPN（与 Go hysteria 一致）。
    pub const DEFAULT_ALPN: &'static [&'static str] = &["hysteria", "h3"];

    /// UDP 空闲超时默认值（与 Go init() 一致）。
    pub const DEFAULT_UDP_IDLE_TIMEOUT: u64 = 60;

    /// 构造最小配置。其它字段用默认值。
    #[must_use]
    pub fn new(server_addr: impl Into<String>, auth: impl Into<String>) -> Self {
        let server_addr = server_addr.into();
        let server_name = server_name_from_addr(&server_addr);
        Self {
            server_addr,
            server_name,
            auth: auth.into(),
            alpn: Self::DEFAULT_ALPN.iter().map(|s| (*s).to_string()).collect(),
            brutal_up_bps: 0,
            udp_idle_timeout_secs: Self::DEFAULT_UDP_IDLE_TIMEOUT,
        }
    }

    /// 设置 TLS SNI（不设则用 server_addr 的 host 部分）。
    #[must_use]
    pub fn with_server_name(mut self, sni: impl Into<String>) -> Self {
        self.server_name = sni.into();
        self
    }

    /// 设置 ALPN 列表。
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }

    /// 设置 Brutal 上行带宽。
    #[must_use]
    pub fn with_brutal_up(mut self, bps: u64) -> Self {
        self.brutal_up_bps = bps;
        self
    }

    /// 验证配置完整。
    pub fn validate(&self) -> Result<()> {
        if self.server_addr.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("server_addr empty".into()));
        }
        if self.server_name.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("server_name empty".into()));
        }
        if self.alpn.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("alpn empty".into()));
        }
        Ok(())
    }

    /// 从 transport 层 hysteria Config + server 地址构造。
    /// 复用 transport Config 的 auth / udp_idle_timeout 字段。
    #[must_use]
    pub fn from_transport(
        server_addr: impl Into<String>,
        transport: &xray_transport_hysteria::proto_config::Config,
    ) -> Self {
        let server_addr = server_addr.into();
        let server_name = server_name_from_addr(&server_addr);
        Self {
            server_addr,
            server_name,
            auth: transport.auth.clone(),
            alpn: Self::DEFAULT_ALPN.iter().map(|s| (*s).to_string()).collect(),
            brutal_up_bps: 0,
            udp_idle_timeout_secs: transport.udp_idle_timeout.max(0) as u64,
        }
    }
}

/// 从 `host:port` 提取 host 部分（用于默认 SNI）。
fn server_name_from_addr(addr: &str) -> String {
    // ponytail: 简单字符串切分，避免引入 url crate；handle `[ipv6]:port` 与 `host:port`
    if let Some(stripped) = addr.strip_prefix('[') {
        // IPv6 字面量 [::1]:443
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }
    // 普通 host:port——从右往左找第一个 ':'
    match addr.rfind(':') {
        Some(idx) => addr[..idx].to_string(),
        None => addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_host_as_default_sni() {
        let cfg = HysteriaConfig::new("example.com:443", "secret");
        assert_eq!(cfg.server_name, "example.com");
        assert_eq!(cfg.auth, "secret");
        assert_eq!(cfg.alpn, vec!["hysteria", "h3"]);
    }

    #[test]
    fn ipv6_addr_sni_extraction() {
        let cfg = HysteriaConfig::new("[::1]:443", "");
        assert_eq!(cfg.server_name, "::1");
    }

    #[test]
    fn with_server_name_overrides() {
        let cfg = HysteriaConfig::new("a.com:443", "").with_server_name("b.com");
        assert_eq!(cfg.server_name, "b.com");
    }

    #[test]
    fn validate_rejects_empty_server_addr() {
        let cfg = HysteriaConfig::new("", "");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_alpn() {
        let mut cfg = HysteriaConfig::new("a.com:443", "");
        cfg.alpn.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_minimal_config() {
        let cfg = HysteriaConfig::new("a.com:443", "tok");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn server_name_from_addr_no_port() {
        // 没 port 的情况——直接返回整个字符串
        assert_eq!(server_name_from_addr("example.com"), "example.com");
    }

    #[test]
    fn from_transport_inherits_auth_and_timeout() {
        let transport = xray_transport_hysteria::proto_config::Config {
            udp_idle_timeout: 120,
            auth: "transport-auth".into(),
            ..Default::default()
        };
        let cfg = HysteriaConfig::from_transport("server.com:443", &transport);
        assert_eq!(cfg.auth, "transport-auth");
        assert_eq!(cfg.udp_idle_timeout_secs, 120);
        assert_eq!(cfg.server_name, "server.com");
    }
}
