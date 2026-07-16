//! # D6: Realm 协议
//!
//! 对应 Go `transport/internet/finalmask/realm/`。
//!
//! Realm 是一种基于 TLS 1.3 的流量伪装协议，把代理流量伪装成正常 HTTPS。
//!
//! ## TODO rpn-future
//!
//! - 实现 Realm handshake（伪装 ClientHello + ServerHello）
//! - 实现 Realm record layer（ApplicationData 包装）
//! - 实现 Realm keepalive（模拟 HTTPS 长连接行为）

/// Realm 配置。
#[derive(Debug, Clone, Default)]
pub struct RealmConfig {
    /// 伪装的 SNI（如 "www.cloudflare.com"）。
    pub server_name: String,
    /// ALPN 列表（如 ["h2", "http/1.1"]）。
    pub alpn: Vec<String>,
    /// 是否启用 session resumption。
    pub session_resumption: bool,
}

/// Realm session（stub）。
pub struct RealmSession {
    config: RealmConfig,
}

impl RealmSession {
    #[must_use]
    pub fn new(config: RealmConfig) -> Self {
        Self { config }
    }

    /// 伪装的 SNI。
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    /// 发起 Realm handshake（stub）。
    ///
    /// TODO rpn-future: 实现完整 TLS 1.3 handshake 伪装。
    pub async fn handshake(&self) -> std::io::Result<()> {
        Ok(())
    }
}
