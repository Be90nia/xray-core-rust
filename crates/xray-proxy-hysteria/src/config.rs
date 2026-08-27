//! Hysteria 代理配置（proxy 层）。
//!
//! 对应 Go `proxy/hysteria/outbound.go` 中的 dial 配置 + transport Config 的组合。
//! transport 层的 [`xray_transport_hysteria::proto_config::Config`] 负责 QUIC 参数，
//! 本模块负责 proxy 层（auth / server 地址 / ALPN）。
//!
//! 入站配置 [`HysteriaInboundConfig`] 对应 Go `proxy/hysteria/server.go` 的 ServerConfig。

use std::sync::Arc;
use std::collections::HashMap;

use parking_lot::Mutex;
use xray_transport_hysteria::hub::AuthValidator;
use xray_transport_hysteria::quic_params::default_hysteria_quic_params;

use crate::error::{Result, HysteriaProxyError};

/// Hysteria 代理配置（客户端出站）。
#[derive(Debug, Clone)]
pub struct HysteriaConfig {
    /// 服务器地址 `host:port`。
    pub server_addr: String,
    /// TLS SNI（默认等于 server_addr 的 host 部分）。
    pub server_name: String,
    /// 鉴权 token（明文或 base64 编码，由 [`auth_header_value`] 统一处理）。
    pub auth: String,
    /// QUIC ALPN 协议列表（hysteria 默认 `hysteria`/`h3`）。
    pub alpn: Vec<String>,
    /// Brutal 拥塞控制上行带宽（bps，0=禁用 Brutal）。
    pub brutal_up_bps: u64,
    /// Brutal 拥塞控制下行带宽（bps，0=禁用 Brutal，服务端 auth 响应回传）。
    pub brutal_down_bps: u64,
    /// Salamander 混淆密码（None=不启用 obfs）。
    pub obfs: Option<String>,
    /// UDP session 空闲超时（秒）。
    pub udp_idle_timeout_secs: u64,
    /// QUIC 参数（`streamSettings.finalmask.quicParams` 解析产物；
    /// 无配置时为 Go nil 默认 bbr_profile=standard）。
    pub quic_params: Arc<xray_proto::xray::transport::internet::QuicParams>,
    /// Masquerade 配置（`hysteriaSettings.masquerade` JSON 解析产物，Go infra/conf
    /// 展开后的形态）。None = 走 proto Config 默认路径（NotFound）。
    pub masq: Option<xray_transport_hysteria::hub::MasqType>,
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
            brutal_down_bps: 0,
            obfs: None,
            udp_idle_timeout_secs: Self::DEFAULT_UDP_IDLE_TIMEOUT,
            quic_params: Arc::new(default_hysteria_quic_params()),
            masq: None,
        }
    }

    /// 设置 masquerade 配置（`hysteriaSettings.masquerade` → MasqType）。
    #[must_use]
    pub fn with_masq(mut self, masq: xray_transport_hysteria::hub::MasqType) -> Self {
        self.masq = Some(masq);
        self
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

    /// 设置 Brutal 下行带宽。
    #[must_use]
    pub fn with_brutal_down(mut self, bps: u64) -> Self {
        self.brutal_down_bps = bps;
        self
    }

    /// 设置 Salamander 混淆密码（启用 obfs）。
    #[must_use]
    pub fn with_obfs(mut self, password: impl Into<String>) -> Self {
        self.obfs = Some(password.into());
        self
    }

    /// 设置 UDP 空闲超时（秒）。
    #[must_use]
    pub fn with_udp_idle_timeout(mut self, secs: u64) -> Self {
        self.udp_idle_timeout_secs = secs;
        self
    }

    /// 设置 QUIC 参数（`finalmask.quicParams` 解析产物）。
    #[must_use]
    pub fn with_quic_params(mut self, p: xray_proto::xray::transport::internet::QuicParams) -> Self {
        self.quic_params = Arc::new(p);
        self
    }

    /// 返回 auth 的 HTTP 头值。
    ///
    /// Hysteria 协议支持两种 auth 格式：
    /// - 明文 password：直接作为 `Hysteria-Auth` 头值
    /// - base64 编码：以 `base64:` 前缀标识，本方法去掉前缀后返回原始 base64
    #[must_use]
    pub fn auth_header_value(&self) -> &str {
        self.auth.strip_prefix("base64:").unwrap_or(&self.auth)
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
            brutal_down_bps: 0,
            obfs: None,
            udp_idle_timeout_secs: transport.udp_idle_timeout.max(0) as u64,
            quic_params: Arc::new(default_hysteria_quic_params()),
            masq: None,
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

// ===== 入站配置 =====

/// Hysteria 用户账号（对应 Go `proxy/hysteria/account/config.go` 的 `Account`）。
///
/// 每个用户一个 `auth` token，客户端在 `Hysteria-Auth` 头中携带。
#[derive(Debug, Clone)]
pub struct HysteriaUser {
    /// 用户邮箱（唯一标识，可为空）。
    pub email: String,
    /// 鉴权 token。
    pub auth: String,
    /// 用户等级（对应 Go `protocol.MemoryUser.Level`，预留）。
    pub level: u32,
}

impl HysteriaUser {
    /// 构造用户（level=0）。
    #[must_use]
    pub fn new(email: impl Into<String>, auth: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            auth: auth.into(),
            level: 0,
        }
    }

    /// 设置用户等级。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }
}

/// Hysteria 入站配置（服务端，对应 Go `proxy/hysteria/server.go` 的 ServerConfig）。
///
/// 持有绑定地址、用户列表、ALPN、UDP 空闲超时等。
#[derive(Debug, Clone)]
pub struct HysteriaInboundConfig {
    /// QUIC 监听地址（如 `0.0.0.0:443`）。
    pub bind_addr: String,
    /// TLS SNI。
    pub server_name: String,
    /// QUIC ALPN 列表。
    pub alpn: Vec<String>,
    /// 用户列表。
    pub users: Vec<HysteriaUser>,
    /// UDP session 空闲超时（秒）。
    pub udp_idle_timeout_secs: u64,
    /// Masquerade 类型（对应 Go `config.MasqType`，空字符串 = NotFound）。
    pub masq_type: String,
}

impl HysteriaInboundConfig {
    /// UDP 空闲超时默认值。
    pub const DEFAULT_UDP_IDLE_TIMEOUT: u64 = 60;

    /// 构造最小入站配置。
    #[must_use]
    pub fn new(bind_addr: impl Into<String>) -> Self {
        let bind_addr = bind_addr.into();
        let server_name = server_name_from_addr(&bind_addr);
        Self {
            bind_addr,
            server_name,
            alpn: HysteriaConfig::DEFAULT_ALPN.iter().map(|s| (*s).to_string()).collect(),
            users: Vec::new(),
            udp_idle_timeout_secs: Self::DEFAULT_UDP_IDLE_TIMEOUT,
            masq_type: String::new(),
        }
    }

    /// 设置 TLS SNI。
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

    /// 添加用户。
    #[must_use]
    pub fn with_user(mut self, user: HysteriaUser) -> Self {
        self.users.push(user);
        self
    }

    /// 设置 UDP 空闲超时（秒）。
    #[must_use]
    pub fn with_udp_idle_timeout(mut self, secs: u64) -> Self {
        self.udp_idle_timeout_secs = secs;
        self
    }

    /// 设置 Masquerade 类型。
    #[must_use]
    pub fn with_masq_type(mut self, masq: impl Into<String>) -> Self {
        self.masq_type = masq.into();
        self
    }

    /// 验证配置完整。
    pub fn validate(&self) -> Result<()> {
        if self.bind_addr.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("bind_addr empty".into()));
        }
        if self.server_name.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("server_name empty".into()));
        }
        if self.alpn.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("alpn empty".into()));
        }
        // 检查 email 唯一性（空 email 跳过）
        let mut seen = std::collections::HashSet::new();
        for user in &self.users {
            if user.email.is_empty() {
                continue;
            }
            if !seen.insert(&user.email) {
                return Err(HysteriaProxyError::InvalidConfig(format!(
                    "duplicate user email: {}", user.email
                )));
            }
        }
        Ok(())
    }
}

/// 多用户认证验证器（对应 Go `proxy/hysteria/account/config.go` 的 `Validator`）。
///
/// 线程安全，内部用 Mutex 保护 users map。
/// 支持运行时动态增删用户。
pub struct MultiUserValidator {
    /// auth token -> user email 映射（运行时增删）。
    users: Mutex<HashMap<String, String>>,
    /// email 集合（用于去重 + Del 查找）。
    emails: Mutex<std::collections::HashSet<String>>,
}

impl MultiUserValidator {
    /// 构造空验证器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            emails: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// 从用户列表构造验证器（对应 Go `NewServer` 中遍历 config.Users 调 validator.Add）。
    #[must_use]
    pub fn from_users(users: &[HysteriaUser]) -> Self {
        let v = Self::new();
        for user in users {
            let _ = v.add(user);
        }
        v
    }

    /// 添加用户。返回 Err 若 email 重复。
    ///
    /// 对应 Go `Validator.Add`。
    pub fn add(&self, user: &HysteriaUser) -> Result<()> {
        let mut emails = self.emails.lock();
        if !user.email.is_empty() {
            if emails.contains(&user.email) {
                return Err(HysteriaProxyError::InvalidConfig(format!(
                    "user {} already exists", user.email
                )));
            }
            emails.insert(user.email.clone());
        }
        let mut users = self.users.lock();
        users.insert(user.auth.clone(), user.email.clone());
        Ok(())
    }

    /// 删除用户（按 email）。
    ///
    /// 对应 Go `Validator.Del`。
    pub fn remove(&self, email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(HysteriaProxyError::InvalidConfig("email must not be empty".into()));
        }
        let mut emails = self.emails.lock();
        if !emails.remove(email) {
            return Err(HysteriaProxyError::InvalidConfig(format!(
                "user {email} not found"
            )));
        }
        let mut users = self.users.lock();
        // 找到对应 auth 删除
        let key_to_remove = users
            .iter()
            .find_map(|(k, v)| if v == email { Some(k.clone()) } else { None });
        if let Some(k) = key_to_remove {
            users.remove(&k);
        }
        Ok(())
    }

    /// 按 auth token 查找用户 email。
    ///
    /// 对应 Go `Validator.Get`。
    #[must_use]
    pub fn get(&self, auth: &str) -> Option<String> {
        self.users.lock().get(auth).cloned()
    }

    /// 当前用户数。
    #[must_use]
    pub fn count(&self) -> usize {
        self.users.lock().len()
    }
}

impl Default for MultiUserValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthValidator for MultiUserValidator {
    fn validate(&self, auth: &str) -> Option<String> {
        self.get(auth)
    }

    fn count(&self) -> usize {
        Self::count(self)
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

    #[test]
    fn auth_header_value_strips_base64_prefix() {
        let cfg = HysteriaConfig::new("a.com:443", "base64:dGVzdA==");
        assert_eq!(cfg.auth_header_value(), "dGVzdA==");
    }

    #[test]
    fn auth_header_value_passthrough_plaintext() {
        let cfg = HysteriaConfig::new("a.com:443", "plain-password");
        assert_eq!(cfg.auth_header_value(), "plain-password");
    }

    #[test]
    fn with_brutal_down_and_obfs_chain() {
        let cfg = HysteriaConfig::new("a.com:443", "x")
            .with_brutal_down(5_000_000)
            .with_obfs("salamander-key");
        assert_eq!(cfg.brutal_down_bps, 5_000_000);
        assert_eq!(cfg.obfs.as_deref(), Some("salamander-key"));
    }
}
