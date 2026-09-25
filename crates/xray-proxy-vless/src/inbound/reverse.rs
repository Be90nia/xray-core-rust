//! VLESS inbound 反向代理注册表（Portal 端）。
//!
//! 对应 Go `proxy/vless/inbound/inbound.go` 的反向代理注册管理。
//!
//! 在 Xray 反向代理架构中，Portal（公网服务端）的 VLESS inbound 收到
//! `command=Rvs`（destination `v1.rvs.cool`）的连接时，需要将这条隧道
//! 交给对应的 `proxy/reverse` Portal handler 处理。注册表以 outbound tag
//! 为键，将 Portal 配置（domain 等）关联到 inbound，使 `Rvs` 连接能被
//! 正确路由。
//!
//! 本模块是纯逻辑 + 线程安全状态（`Arc<RwLock<HashMap>>`），不含 IO。
//! 实际连接桥接由 dispatcher 注入。

use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;

use crate::error::{Result, VlessError};

/// Portal 配置（对应 Go `reverse.PortalConfig`）。
///
/// 一个 Portal 代表反向代理的服务端入口：外部客户端连接 Portal，
/// Portal 通过反向隧道把流量转给 Bridge。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalConfig {
    /// Portal 标识（对应 routing outbound tag）。
    pub tag: String,
    /// 反向隧道域名（默认 `v1.rvs.cool`）。
    ///
    /// Bridge 与 Portal 通过此域名识别反向连接。Go 端默认值是
    /// `v1.rvs.cool`，见 `proxy/reverse` 包 `rvsDomain` 常量。
    pub domain: String,
}

impl PortalConfig {
    /// 用 tag 创建，domain 默认 `v1.rvs.cool`。
    #[must_use]
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into(), domain: crate::RVS_DOMAIN.to_string() }
    }

    /// 链式设置 domain。
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }
}

/// 反向代理注册表。
///
/// 对应 Go inbound Handler 的 `conds map[string]*PortalConfig` + `sync.RWMutex`。
/// 线程安全：`AddReverse` / `GetReverse` / `RemoveReverse` 操作受读写锁保护。
#[derive(Debug, Default, Clone)]
pub struct ReverseRegistry {
    entries: Arc<RwLock<HashMap<String, PortalConfig>>>,
}

impl ReverseRegistry {
    /// 创建空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个 reverse portal 配置。
    ///
    /// # Errors
    /// tag 已存在时返回 [`VlessError::Other`]。
    pub fn add_reverse(&self, config: PortalConfig) -> Result<()> {
        let mut map = self.entries.write();
        if map.contains_key(&config.tag) {
            return Err(VlessError::Other(format!(
                "reverse proxy by tag '{}' already exists",
                config.tag
            )));
        }
        map.insert(config.tag.clone(), config);
        Ok(())
    }

    /// 查找已注册的 portal 配置（克隆返回）。
    ///
    /// # Errors
    /// tag 不存在时返回 [`VlessError::Other`]。
    pub fn get_reverse(&self, tag: &str) -> Result<PortalConfig> {
        self.entries
            .read()
            .get(tag)
            .cloned()
            .ok_or_else(|| VlessError::Other(format!("reverse proxy not found by tag: {}", tag)))
    }

    /// 移除已注册的 portal 配置。
    ///
    /// # Errors
    /// tag 不存在时返回 [`VlessError::Other`]。
    pub fn remove_reverse(&self, tag: &str) -> Result<()> {
        let mut map = self.entries.write();
        map.remove(tag)
            .ok_or_else(|| VlessError::Other(format!("reverse proxy not found by tag: {}", tag)))?;
        Ok(())
    }

    /// 是否已注册指定 tag。
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.entries.read().contains_key(tag)
    }

    /// 已注册的 tag 数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// 列出所有已注册的 tag（快照）。
    #[must_use]
    pub fn tags(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_config_default_domain() {
        let cfg = PortalConfig::new("portal_out");
        assert_eq!(cfg.tag, "portal_out");
        assert_eq!(cfg.domain, crate::RVS_DOMAIN);
    }

    #[test]
    fn portal_config_custom_domain() {
        let cfg = PortalConfig::new("p").with_domain("custom.example");
        assert_eq!(cfg.domain, "custom.example");
    }

    #[test]
    fn add_get_remove_lifecycle() {
        let reg = ReverseRegistry::new();
        assert!(reg.is_empty());

        reg.add_reverse(PortalConfig::new("alpha")).unwrap();
        reg.add_reverse(PortalConfig::new("beta")).unwrap();
        assert_eq!(reg.len(), 2);
        assert!(reg.contains("alpha"));
        assert!(!reg.contains("gamma"));

        let got = reg.get_reverse("alpha").unwrap();
        assert_eq!(got.tag, "alpha");

        reg.remove_reverse("alpha").unwrap();
        assert!(!reg.contains("alpha"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn add_duplicate_errors() {
        let reg = ReverseRegistry::new();
        reg.add_reverse(PortalConfig::new("dup")).unwrap();
        let err = reg.add_reverse(PortalConfig::new("dup")).unwrap_err();
        assert!(matches!(&err, VlessError::Other(m) if m.contains("already exists")));
    }

    #[test]
    fn get_missing_errors() {
        let reg = ReverseRegistry::new();
        let err = reg.get_reverse("nope").unwrap_err();
        assert!(matches!(&err, VlessError::Other(m) if m.contains("not found")));
    }

    #[test]
    fn remove_missing_errors() {
        let reg = ReverseRegistry::new();
        let err = reg.remove_reverse("nope").unwrap_err();
        assert!(matches!(&err, VlessError::Other(m) if m.contains("not found")));
    }

    #[test]
    fn tags_snapshot() {
        let reg = ReverseRegistry::new();
        reg.add_reverse(PortalConfig::new("b")).unwrap();
        reg.add_reverse(PortalConfig::new("a")).unwrap();
        let mut t = reg.tags();
        t.sort();
        assert_eq!(t, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn clone_shares_state() {
        let reg = ReverseRegistry::new();
        let reg2 = reg.clone();
        reg2.add_reverse(PortalConfig::new("shared")).unwrap();
        assert!(reg.contains("shared"));
    }
}
