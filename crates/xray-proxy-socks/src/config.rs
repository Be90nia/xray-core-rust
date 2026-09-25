//! SOCKS 代理配置。
//!
//! 对应 Go `proxy/socks/config.go` + `config.proto`。
//!
//! ## 切片边界（P6-5 49t 切片1）
//!
//! 实现配置层 + 账户认证 + `AuthType` 枚举 + prost 双向转换。
//! 完整 SOCKS4/5 握手（`protocol.go::ServerSession`）依赖 io.Reader/Writer +
//! transport.Link，留切片2。

use std::collections::HashMap;

use crate::error::Result;

/// SOCKS 账户。对应 proto `Account`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
}

impl Account {
    /// 构造账户。
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self { username: username.into(), password: password.into() }
    }

    /// 比较两个账户是否相同（仅按 `username` 判断，与 Go `Equals` 一致）。
    #[must_use]
    pub fn equals(&self, other: &Self) -> bool {
        self.username == other.username
    }

    /// 从 prost `Account` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::socks::Account) -> Result<Self> {
        Ok(Self { username: p.username, password: p.password })
    }

    /// 转换为 prost `Account`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::socks::Account {
        xray_proto::xray::proxy::socks::Account {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

/// SOCKS 认证类型。对应 proto `AuthType` 枚举。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthType {
    /// 匿名（无认证）。
    #[default]
    NoAuth = 0,
    /// 用户名/密码认证。
    Password = 1,
}

impl AuthType {
    /// 从 proto i32 值构造。非法值返回 `NoAuth`（默认）。
    #[must_use]
    pub fn from_proto_value(v: i32) -> Self {
        match v {
            1 => Self::Password,
            _ => Self::NoAuth,
        }
    }

    /// 转换为 proto i32 值。
    #[must_use]
    pub fn to_proto_value(self) -> i32 {
        self as i32
    }
}

/// SOCKS 服务端配置。对应 proto `ServerConfig`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerConfig {
    /// 认证类型。
    pub auth_type: AuthType,
    /// 用户账户表（username → password）。仅 `auth_type == Password` 时使用。
    pub accounts: HashMap<String, String>,
    /// 监听地址（IPOrDomain）。直接保存 prost 类型。
    pub address: Option<xray_proto::xray::common::net::IpOrDomain>,
    /// 是否启用 UDP 中继。
    pub udp_enabled: bool,
    /// 用户等级（policy 分级）。
    pub user_level: u32,
}

impl ServerConfig {
    /// 校验用户名/密码。对应 Go `ServerConfig.HasAccount`。
    ///
    /// `accounts` 为空时返回 `false`（与 Go 一致）。
    #[must_use]
    pub fn has_account(&self, username: &str, password: &str) -> bool {
        if self.accounts.is_empty() {
            return false;
        }
        self.accounts.get(username).is_some_and(|p| p == password)
    }

    /// 是否需要认证。
    #[must_use]
    pub fn requires_auth(&self) -> bool {
        self.auth_type == AuthType::Password && !self.accounts.is_empty()
    }

    /// 从 prost `ServerConfig` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::socks::ServerConfig) -> Result<Self> {
        Ok(Self {
            auth_type: AuthType::from_proto_value(p.auth_type),
            accounts: p.accounts.into_iter().collect(),
            address: p.address,
            udp_enabled: p.udp_enabled,
            user_level: p.user_level,
        })
    }

    /// 转换为 prost `ServerConfig`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::socks::ServerConfig {
        xray_proto::xray::proxy::socks::ServerConfig {
            auth_type: self.auth_type.to_proto_value(),
            accounts: self.accounts.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            address: self.address.clone(),
            udp_enabled: self.udp_enabled,
            user_level: self.user_level,
        }
    }
}

/// SOCKS 客户端配置。对应 proto `ClientConfig`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientConfig {
    /// 上游 SOCKS 服务器端点。
    pub server: Option<xray_proto::xray::common::protocol::ServerEndpoint>,
}

impl ClientConfig {
    /// 从 prost `ClientConfig` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::socks::ClientConfig) -> Result<Self> {
        Ok(Self { server: p.server })
    }

    /// 转换为 prost `ClientConfig`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::socks::ClientConfig {
        xray_proto::xray::proxy::socks::ClientConfig { server: self.server.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_equals_username_only() {
        let a = Account::new("alice", "p1");
        let b = Account::new("alice", "p2");
        assert!(a.equals(&b));
    }

    #[test]
    fn auth_type_roundtrip() {
        assert_eq!(AuthType::from_proto_value(0), AuthType::NoAuth);
        assert_eq!(AuthType::from_proto_value(1), AuthType::Password);
        assert_eq!(AuthType::NoAuth.to_proto_value(), 0);
        assert_eq!(AuthType::Password.to_proto_value(), 1);
        assert_eq!(AuthType::from_proto_value(99), AuthType::NoAuth);
    }

    #[test]
    fn server_has_account_matches() {
        let mut accounts = HashMap::new();
        accounts.insert("u".into(), "p".into());
        let cfg = ServerConfig { accounts, ..Default::default() };
        assert!(cfg.has_account("u", "p"));
        assert!(!cfg.has_account("u", "wrong"));
        assert!(!cfg.has_account("x", "p"));
    }

    #[test]
    fn server_has_account_empty_returns_false() {
        let cfg = ServerConfig::default();
        assert!(!cfg.has_account("any", "any"));
    }

    #[test]
    fn server_requires_auth_logic() {
        let cfg = ServerConfig::default();
        assert!(!cfg.requires_auth());

        let mut accounts = HashMap::new();
        accounts.insert("u".into(), "p".into());
        let cfg = ServerConfig { auth_type: AuthType::Password, accounts, ..Default::default() };
        assert!(cfg.requires_auth());

        // Password 类型但空 accounts → 不要求认证
        let cfg = ServerConfig { auth_type: AuthType::Password, ..Default::default() };
        assert!(!cfg.requires_auth());
    }

    #[test]
    fn account_proto_roundtrip() {
        let a = Account::new("u", "p");
        let p = a.to_proto();
        assert_eq!(Account::from_proto(p).unwrap(), a);
    }

    #[test]
    fn server_config_proto_roundtrip() {
        let mut accounts = HashMap::new();
        accounts.insert("u".into(), "p".into());
        let cfg = ServerConfig {
            auth_type: AuthType::Password,
            accounts,
            udp_enabled: true,
            user_level: 3,
            ..Default::default()
        };
        let p = cfg.to_proto();
        let cfg2 = ServerConfig::from_proto(p).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn client_config_proto_roundtrip() {
        let cfg = ClientConfig::default();
        let p = cfg.to_proto();
        assert_eq!(ClientConfig::from_proto(p).unwrap(), cfg);
    }
}
