//! RuleSet 外部规则加载
//!
//! 对应 Go `app/router/rule_set.go`。
//!
//! Go xray-core v1.8+ 支持 `rule_set` 配置，引用外部规则文件：
//! ```json
//! "rule_set": [
//!   { "tag": "geosite", "type": "file", "format": "json", "path": "geosite.json" }
//! ]
//! ```
//!
//! 路由规则通过 `rule_set:tag` 引用加载的规则集合。
//!
//! ## 当前状态
//!
//! Proto `RoutingRule` 无 `rule_set` 字段（proto 版本较早）。
//! 本模块实现独立的加载 + 注册基础设施，待 proto 更新后接入 Router。
//!
//! ## 用法
//!
//! ```no_run
//! use xray_app_router::rule_set::{RuleSetConfig, RuleSetFormat, RuleSetRegistry, RuleSetType};
//!
//! let cfg = RuleSetConfig {
//!     tag: "geosite".into(),
//!     rule_set_type: RuleSetType::File,
//!     format: RuleSetFormat::Json,
//!     path: "/path/to/geosite.json".into(),
//!     url: String::new(),
//! };
//! let registry = RuleSetRegistry::new();
//! registry.load(&cfg).unwrap();
//! let domains = registry.get_domains("geosite").unwrap();
//! ```

use std::{collections::HashMap, path::Path};

use parking_lot::RwLock;

use crate::error::RouterError;

/// RuleSet 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetType {
    /// 本地文件。
    File,
    /// 远程下载（当前仅解析配置，不实际下载）。
    Remote,
}

/// RuleSet 格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetFormat {
    /// JSON 格式（xray domain/IP 列表）。
    Json,
}

/// RuleSet 配置项。
#[derive(Debug, Clone)]
pub struct RuleSetConfig {
    pub tag: String,
    pub rule_set_type: RuleSetType,
    pub format: RuleSetFormat,
    pub path: String,
    pub url: String,
}

/// 加载后的规则集内容。
#[derive(Debug, Default, Clone)]
pub struct LoadedRuleSet {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// RuleSet 注册表。线程安全，按 tag 缓存加载结果。
#[derive(Debug, Default)]
pub struct RuleSetRegistry {
    sets: RwLock<HashMap<String, LoadedRuleSet>>,
}

impl RuleSetRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 加载 RuleSet 文件并缓存。
    ///
    /// 仅 `File` + `Json` 格式实现；`Remote` 返回 `Err`。
    pub fn load(&self, cfg: &RuleSetConfig) -> Result<(), RouterError> {
        if cfg.rule_set_type == RuleSetType::Remote {
            return Err(RouterError::Other("remote rule_set download not implemented".into()));
        }

        let loaded = load_json_rule_set(Path::new(&cfg.path))?;
        self.sets.write().insert(cfg.tag.clone(), loaded);
        Ok(())
    }

    /// 批量加载。
    pub fn load_all(&self, configs: &[RuleSetConfig]) -> Result<(), RouterError> {
        for cfg in configs {
            self.load(cfg)?;
        }
        Ok(())
    }

    /// 获取 tag 对应的域名列表。
    pub fn get_domains(&self, tag: &str) -> Result<Vec<String>, RouterError> {
        self.sets
            .read()
            .get(tag)
            .map(|s| s.domains.clone())
            .ok_or_else(|| RouterError::Other(format!("rule_set '{tag}' not loaded")))
    }

    /// 获取 tag 对应的 IP 列表。
    pub fn get_ips(&self, tag: &str) -> Result<Vec<String>, RouterError> {
        self.sets
            .read()
            .get(tag)
            .map(|s| s.ips.clone())
            .ok_or_else(|| RouterError::Other(format!("rule_set '{tag}' not loaded")))
    }

    /// 检查域名是否在 rule_set 中。
    pub fn contains_domain(&self, tag: &str, domain: &str) -> bool {
        self.sets.read().get(tag).map(|s| s.domains.iter().any(|d| d == domain)).unwrap_or(false)
    }
}

/// 解析 JSON 格式的 rule_set 文件。
///
/// 支持两种 JSON 格式：
/// 1. xray 原生格式：`{ "domain": ["a.com", "b.com"], "ip": ["1.2.3.0/24"] }`
/// 2. 简单列表格式：`["a.com", "b.com"]`（全部视为域名）
fn load_json_rule_set(path: &Path) -> Result<LoadedRuleSet, RouterError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| RouterError::Other(format!("failed to read rule_set file {:?}: {e}", path)))?;

    let trimmed = content.trim();
    if trimmed.starts_with('[') {
        // 简单列表格式
        let domains: Vec<String> = serde_json::from_str(&content)
            .map_err(|e| RouterError::Other(format!("failed to parse rule_set JSON array: {e}")))?;
        return Ok(LoadedRuleSet { domains, ips: Vec::new() });
    }

    // xray 原生格式
    let v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| RouterError::Other(format!("failed to parse rule_set JSON: {e}")))?;

    let domains = v
        .get("domain")
        .and_then(|d| d.as_array())
        .map(|arr| arr.iter().filter_map(|d| d.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let ips = v
        .get("ip")
        .and_then(|d| d.as_array())
        .map(|arr| arr.iter().filter_map(|d| d.as_str().map(String::from)).collect())
        .unwrap_or_default();

    Ok(LoadedRuleSet { domains, ips })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_temp_json(content: &str, name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("xray_router_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_native_format() {
        let json = r#"{"domain": ["a.com", "b.com"], "ip": ["10.0.0.0/8"]}"#;
        let path = write_temp_json(json, "ruleset_native.json");
        let loaded = load_json_rule_set(&path).unwrap();
        assert_eq!(loaded.domains, vec!["a.com", "b.com"]);
        assert_eq!(loaded.ips, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn load_simple_array_format() {
        let json = r#"["x.com", "y.com"]"#;
        let path = write_temp_json(json, "ruleset_array.json");
        let loaded = load_json_rule_set(&path).unwrap();
        assert_eq!(loaded.domains, vec!["x.com", "y.com"]);
        assert!(loaded.ips.is_empty());
    }

    #[test]
    fn registry_load_and_query() {
        let json = r#"{"domain": ["test.com"]}"#;
        let path = write_temp_json(json, "ruleset_reg.json");
        let cfg = RuleSetConfig {
            tag: "test".into(),
            rule_set_type: RuleSetType::File,
            format: RuleSetFormat::Json,
            path: path.to_string_lossy().into_owned(),
            url: String::new(),
        };
        let reg = RuleSetRegistry::new();
        reg.load(&cfg).unwrap();
        assert!(reg.contains_domain("test", "test.com"));
        assert!(!reg.contains_domain("test", "other.com"));
    }

    #[test]
    fn registry_missing_tag_errors() {
        let reg = RuleSetRegistry::new();
        assert!(reg.get_domains("nonexistent").is_err());
    }

    #[test]
    fn remote_ruleset_not_implemented() {
        let reg = RuleSetRegistry::new();
        let cfg = RuleSetConfig {
            tag: "remote".into(),
            rule_set_type: RuleSetType::Remote,
            format: RuleSetFormat::Json,
            path: String::new(),
            url: "https://example.com/rules.json".into(),
        };
        assert!(reg.load(&cfg).is_err());
    }

    #[test]
    fn nonexistent_file_errors() {
        let cfg = RuleSetConfig {
            tag: "bad".into(),
            rule_set_type: RuleSetType::File,
            format: RuleSetFormat::Json,
            path: "/nonexistent/path/file.json".into(),
            url: String::new(),
        };
        let reg = RuleSetRegistry::new();
        assert!(reg.load(&cfg).is_err());
    }
}
