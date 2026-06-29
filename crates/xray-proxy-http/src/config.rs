//! HTTP 代理配置。
//!
//! 对应 Go `proxy/http/config.go` + `config.proto`。
//!
//! ## 切片边界（P6-5 49t 切片1）
//!
//! 实现配置层 + `Account`/`ServerConfig`/`ClientConfig`/`Header` 强类型 +
//! `ServerConfig::has_account` 纯函数（用户名/密码校验）+ prost 双向转换。
//! 实际 HTTP CONNECT 隧道处理（`client.go`/`server.go`）依赖 transport/session/
//! policy 完整翻译，留切片2。

use std::collections::HashMap;

use crate::error::Result;

/// HTTP 代理账户。对应 proto `Account`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// 用户名。
    pub username: String,
    /// 密码（明文，与 Go 一致；生产环境建议配合 TLS）。
    pub password: String,
}

impl Account {
    /// 构造账户。
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// 比较两个账户是否相同（仅按 `username` 判断，与 Go `Equals` 一致）。
    ///
    /// Go 端 `Account.Equals` 只比较 username——因为同一用户名在同一 ServerConfig
    /// 中只允许一个密码，username 相同即视为同一账户。
    #[must_use]
    pub fn equals(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

/// HTTP 代理服务端配置。对应 proto `ServerConfig`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerConfig {
    /// 用户账户表（username → password）。空表示允许匿名访问。
    pub accounts: HashMap<String, String>,
    /// 是否允许透明代理（解析绝对 URI 而非 Host header）。
    pub allow_transparent: bool,
    /// 用户等级（用于 policy 分级）。
    pub user_level: u32,
}

impl ServerConfig {
    /// 校验用户名/密码是否匹配已注册账户。
    ///
    /// 对应 Go `ServerConfig.HasAccount`。`accounts` 为空时返回 `false`
    ///（与 Go 一致：空 map 拒绝所有认证，需走匿名路径）。
    #[must_use]
    pub fn has_account(&self, username: &str, password: &str) -> bool {
        if self.accounts.is_empty() {
            return false;
        }
        self.accounts
            .get(username)
            .is_some_and(|p| p == password)
    }

    /// 是否需要认证（`accounts` 非空）。
    #[must_use]
    pub fn requires_auth(&self) -> bool {
        !self.accounts.is_empty()
    }
}

/// HTTP 自定义 header。对应 proto `Header`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// header 名（如 `X-Forwarded-For`）。
    pub key: String,
    /// header 值。
    pub value: String,
}

/// HTTP 代理客户端配置。对应 proto `ClientConfig`。
///
/// 客户端把流量转发到上游 HTTP 代理服务器（`server`），可附加自定义 header。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientConfig {
    /// 上游 HTTP 代理服务器端点。
    ///
    /// ponytail: 直接保存 prost 生成的 `ServerEndpoint` 类型，避免拆解嵌套字段。
    pub server: Option<xray_proto::xray::common::protocol::ServerEndpoint>,
    /// 自定义 header 列表（追加到出站请求）。
    pub headers: Vec<Header>,
}

// ===== proto 转换 =====

impl Account {
    /// 从 prost `Account` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::http::Account) -> Result<Self> {
        Ok(Self {
            username: p.username,
            password: p.password,
        })
    }

    /// 转换为 prost `Account`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::http::Account {
        xray_proto::xray::proxy::http::Account {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

impl ServerConfig {
    /// 从 prost `ServerConfig` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::http::ServerConfig) -> Result<Self> {
        Ok(Self {
            accounts: p.accounts.into_iter().collect(),
            allow_transparent: p.allow_transparent,
            user_level: p.user_level,
        })
    }

    /// 转换为 prost `ServerConfig`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::http::ServerConfig {
        xray_proto::xray::proxy::http::ServerConfig {
            accounts: self.accounts.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            allow_transparent: self.allow_transparent,
            user_level: self.user_level,
        }
    }
}

impl ClientConfig {
    /// 从 prost `ClientConfig` 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::http::ClientConfig) -> Result<Self> {
        Ok(Self {
            server: p.server,
            headers: p
                .header
                .into_iter()
                .map(|h| Header {
                    key: h.key,
                    value: h.value,
                })
                .collect(),
        })
    }

    /// 转换为 prost `ClientConfig`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::http::ClientConfig {
        xray_proto::xray::proxy::http::ClientConfig {
            server: self.server.clone(),
            header: self
                .headers
                .iter()
                .map(|h| xray_proto::xray::proxy::http::Header {
                    key: h.key.clone(),
                    value: h.value.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Account =====

    #[test]
    fn account_equals_compares_username_only() {
        let a = Account::new("alice", "pass1");
        let b = Account::new("alice", "pass2"); // 同名不同密码
        let c = Account::new("bob", "pass1");
        assert!(a.equals(&b)); // 与 Go 一致：仅 username 判定
        assert!(!a.equals(&c));
    }

    #[test]
    fn account_proto_roundtrip() {
        let a = Account::new("user", "secret");
        let p = a.to_proto();
        let a2 = Account::from_proto(p).unwrap();
        assert_eq!(a, a2);
    }

    // ===== ServerConfig::has_account =====

    #[test]
    fn server_has_account_matches() {
        let mut accounts = HashMap::new();
        accounts.insert("alice".into(), "pass123".into());
        let cfg = ServerConfig {
            accounts,
            ..Default::default()
        };
        assert!(cfg.has_account("alice", "pass123"));
    }

    #[test]
    fn server_has_account_wrong_password_rejected() {
        let mut accounts = HashMap::new();
        accounts.insert("alice".into(), "pass123".into());
        let cfg = ServerConfig {
            accounts,
            ..Default::default()
        };
        assert!(!cfg.has_account("alice", "wrong"));
    }

    #[test]
    fn server_has_account_unknown_user_rejected() {
        let mut accounts = HashMap::new();
        accounts.insert("alice".into(), "pass".into());
        let cfg = ServerConfig {
            accounts,
            ..Default::default()
        };
        assert!(!cfg.has_account("bob", "pass"));
    }

    #[test]
    fn server_has_account_empty_map_returns_false() {
        // 与 Go 一致：空 accounts 返回 false（拒绝所有认证）
        let cfg = ServerConfig::default();
        assert!(!cfg.has_account("anyone", "anything"));
    }

    #[test]
    fn server_requires_auth_when_accounts_non_empty() {
        let mut accounts = HashMap::new();
        accounts.insert("u".into(), "p".into());
        let cfg = ServerConfig {
            accounts,
            ..Default::default()
        };
        assert!(cfg.requires_auth());

        let cfg_empty = ServerConfig::default();
        assert!(!cfg_empty.requires_auth());
    }

    #[test]
    fn server_config_proto_roundtrip() {
        let mut accounts = HashMap::new();
        accounts.insert("u".into(), "p".into());
        let cfg = ServerConfig {
            accounts,
            allow_transparent: true,
            user_level: 5,
        };
        let p = cfg.to_proto();
        let cfg2 = ServerConfig::from_proto(p).unwrap();
        assert_eq!(cfg, cfg2);
    }

    // ===== ClientConfig =====

    #[test]
    fn client_config_proto_roundtrip_empty() {
        let cfg = ClientConfig::default();
        let p = cfg.to_proto();
        let cfg2 = ClientConfig::from_proto(p).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn client_config_proto_roundtrip_with_headers() {
        let cfg = ClientConfig {
            server: None,
            headers: vec![
                Header {
                    key: "X-Custom".into(),
                    value: "v1".into(),
                },
                Header {
                    key: "X-Auth".into(),
                    value: "token".into(),
                },
            ],
        };
        let p = cfg.to_proto();
        let cfg2 = ClientConfig::from_proto(p).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
