//! 域名属性匹配器
//!
//! 对应 Go 版本 `common/geodata/geodat_loader` 中的属性匹配逻辑，
//! 提供基于属性的域名过滤能力。
//!
//! # 接口层级
//!
//! - [`DomainAttribute`] - 域名属性（key + 可选 bool/int 值）
//! - [`AttributeMatcher`] - 属性匹配器 trait
//! - [`HasAttrMatcher`] - 单属性匹配：检查是否包含指定 key
//! - [`AllAttrsMatcher`] - 全属性匹配：所有属性都必须匹配
//!
//! # 属性字符串格式
//!
//! 属性字符串使用 `@` 分隔多个属性 key，例如 `"@tls@port"` 表示
//! 域名必须同时拥有 `tls` 和 `port` 两个属性。

// ===== DomainAttribute =====

/// 域名属性。
///
/// 对应 Go 版本 protobuf `Domain.Attribute`，但使用 Rust 友好的
/// 类型表示。每个属性包含一个 key 和可选的 bool/int 值。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::attributes::DomainAttribute;
///
/// let attr = DomainAttribute::new("tls");
/// assert_eq!(attr.key, "tls");
/// assert!(attr.bool_value.is_none());
/// assert!(attr.int_value.is_none());
///
/// let bool_attr = DomainAttribute::with_bool("tls", true);
/// assert_eq!(bool_attr.bool_value, Some(true));
///
/// let int_attr = DomainAttribute::with_int("port", 443);
/// assert_eq!(int_attr.int_value, Some(443));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttribute {
    /// 属性键名
    pub key: String,
    /// 可选布尔值
    pub bool_value: Option<bool>,
    /// 可选整数值
    pub int_value: Option<i64>,
}

impl DomainAttribute {
    /// 创建仅有 key 的属性（无值）。
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into(), bool_value: None, int_value: None }
    }

    /// 创建带布尔值的属性。
    #[must_use]
    pub fn with_bool(key: impl Into<String>, value: bool) -> Self {
        Self { key: key.into(), bool_value: Some(value), int_value: None }
    }

    /// 创建带整数值的属性。
    #[must_use]
    pub fn with_int(key: impl Into<String>, value: i64) -> Self {
        Self { key: key.into(), bool_value: None, int_value: Some(value) }
    }
}

impl std::fmt::Display for DomainAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.bool_value, self.int_value) {
            (Some(b), _) => write!(f, "{}={}", self.key, b),
            (None, Some(i)) => write!(f, "{}={}", self.key, i),
            (None, None) => write!(f, "{}", self.key),
        }
    }
}

// ===== AttributeMatcher trait =====

/// 属性匹配器 trait。
///
/// 对应 Go 版本 `AttributeMatcher`，检查域名属性列表是否满足匹配条件。
pub trait AttributeMatcher: Send + Sync {
    /// 判断属性列表是否满足匹配条件。
    #[must_use]
    fn match_domain(&self, attrs: &[DomainAttribute]) -> bool;
}

// ===== HasAttrMatcher =====

/// 单属性匹配器。
///
/// 对应 Go 版本 `HasAttrMatcher`，检查属性列表中是否存在指定 key 的属性。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::attributes::{AttributeMatcher, DomainAttribute, HasAttrMatcher};
///
/// let attrs =
///     vec![DomainAttribute::with_bool("tls", true), DomainAttribute::with_int("port", 443)];
///
/// let matcher = HasAttrMatcher::new("tls");
/// assert!(matcher.match_domain(&attrs));
///
/// let matcher2 = HasAttrMatcher::new("http");
/// assert!(!matcher2.match_domain(&attrs));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HasAttrMatcher {
    key: String,
}

impl HasAttrMatcher {
    /// 创建新的单属性匹配器。
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// 返回匹配的属性 key。
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl AttributeMatcher for HasAttrMatcher {
    fn match_domain(&self, attrs: &[DomainAttribute]) -> bool {
        attrs.iter().any(|attr| attr.key == self.key)
    }
}

impl std::fmt::Display for HasAttrMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "has_attr:{}", self.key)
    }
}

// ===== AllAttrsMatcher =====

/// 全属性匹配器。
///
/// 对应 Go 版本 `AllAttrsMatcher`，要求属性列表同时满足所有
/// 指定的属性 key。空匹配器列表匹配一切。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::attributes::{
///     AllAttrsMatcher, AttributeMatcher, DomainAttribute, HasAttrMatcher,
/// };
///
/// let attrs =
///     vec![DomainAttribute::with_bool("tls", true), DomainAttribute::with_int("port", 443)];
///
/// // 两个属性都有
/// let matcher = AllAttrsMatcher::from_matchers(vec![
///     HasAttrMatcher::new("tls"),
///     HasAttrMatcher::new("port"),
/// ]);
/// assert!(matcher.match_domain(&attrs));
///
/// // 缺少 http 属性
/// let matcher2 = AllAttrsMatcher::from_matchers(vec![
///     HasAttrMatcher::new("tls"),
///     HasAttrMatcher::new("http"),
/// ]);
/// assert!(!matcher2.match_domain(&attrs));
/// ```
#[derive(Debug, Clone)]
pub struct AllAttrsMatcher {
    matchers: Vec<HasAttrMatcher>,
}

impl AllAttrsMatcher {
    /// 创建新的全属性匹配器。
    ///
    /// `matchers` 为空时匹配一切。
    #[must_use]
    pub fn from_matchers(matchers: Vec<HasAttrMatcher>) -> Self {
        Self { matchers }
    }

    /// 返回内部匹配器列表的引用。
    #[must_use]
    pub fn matchers(&self) -> &[HasAttrMatcher] {
        &self.matchers
    }
}

impl AttributeMatcher for AllAttrsMatcher {
    fn match_domain(&self, attrs: &[DomainAttribute]) -> bool {
        self.matchers.iter().all(|m| m.match_domain(attrs))
    }
}

impl std::fmt::Display for AllAttrsMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<&str> = self.matchers.iter().map(|m| m.key()).collect();
        write!(f, "all_attrs:@{}", keys.join("@"))
    }
}

// ===== parse_attrs =====

/// 从 `"@attr1@attr2"` 格式的字符串解析属性匹配器。
///
/// 对应 Go 版本 `NewAllAttrsMatcher`，将 `"@key1@key2"` 格式
/// 解析为 `AllAttrsMatcher`。空字符串或仅包含 `@` 的字符串
/// 返回 `None`（表示无需属性过滤）。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::attributes::parse_attrs;
///
/// let matcher = parse_attrs("@tls@port").unwrap();
/// // matcher 要求同时拥有 tls 和 port 属性
///
/// assert!(parse_attrs("").is_none());
/// assert!(parse_attrs("@").is_none());
/// ```
#[must_use]
pub fn parse_attrs(attrs: &str) -> Option<AllAttrsMatcher> {
    if attrs.is_empty() {
        return None;
    }

    let matchers: Vec<HasAttrMatcher> =
        attrs.split('@').filter(|s| !s.is_empty()).map(|s| HasAttrMatcher::new(s)).collect();

    if matchers.is_empty() {
        return None;
    }

    Some(AllAttrsMatcher::from_matchers(matchers))
}

/// 使用属性匹配器过滤域名属性列表。
///
/// 对应 Go 版本 `loadSiteWithAttrs` 中的过滤逻辑。
/// 如果 `matcher` 为 `None`，返回原始列表的克隆。
#[must_use]
pub fn filter_by_attrs(
    domains: &[(Vec<DomainAttribute>, String)],
    matcher: Option<&AllAttrsMatcher>,
) -> Vec<(Vec<DomainAttribute>, String)> {
    match matcher {
        Some(m) => domains.iter().filter(|(attrs, _)| m.match_domain(attrs)).cloned().collect(),
        None => domains.to_vec(),
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    // ----- DomainAttribute 测试 -----

    #[test]
    fn test_domain_attribute_new() {
        let attr = DomainAttribute::new("tls");
        assert_eq!(attr.key, "tls");
        assert!(attr.bool_value.is_none());
        assert!(attr.int_value.is_none());
    }

    #[test]
    fn test_domain_attribute_with_bool() {
        let attr = DomainAttribute::with_bool("tls", true);
        assert_eq!(attr.key, "tls");
        assert_eq!(attr.bool_value, Some(true));
        assert!(attr.int_value.is_none());
    }

    #[test]
    fn test_domain_attribute_with_int() {
        let attr = DomainAttribute::with_int("port", 443);
        assert_eq!(attr.key, "port");
        assert!(attr.bool_value.is_none());
        assert_eq!(attr.int_value, Some(443));
    }

    #[test]
    fn test_domain_attribute_display() {
        assert_eq!(format!("{}", DomainAttribute::new("tls")), "tls");
        assert_eq!(format!("{}", DomainAttribute::with_bool("tls", true)), "tls=true");
        assert_eq!(format!("{}", DomainAttribute::with_int("port", 443)), "port=443");
    }

    #[test]
    fn test_domain_attribute_equality() {
        let a1 = DomainAttribute::with_bool("tls", true);
        let a2 = DomainAttribute::with_bool("tls", true);
        let a3 = DomainAttribute::with_bool("tls", false);
        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    // ----- HasAttrMatcher 测试 -----

    #[test]
    fn test_has_attr_matcher_found() {
        let attrs =
            vec![DomainAttribute::with_bool("tls", true), DomainAttribute::with_int("port", 443)];
        let matcher = HasAttrMatcher::new("tls");
        assert!(matcher.match_domain(&attrs));
    }

    #[test]
    fn test_has_attr_matcher_not_found() {
        let attrs = vec![DomainAttribute::with_bool("tls", true)];
        let matcher = HasAttrMatcher::new("http");
        assert!(!matcher.match_domain(&attrs));
    }

    #[test]
    fn test_has_attr_matcher_empty_attrs() {
        let matcher = HasAttrMatcher::new("tls");
        assert!(!matcher.match_domain(&[]));
    }

    #[test]
    fn test_has_attr_matcher_key_accessor() {
        let matcher = HasAttrMatcher::new("port");
        assert_eq!(matcher.key(), "port");
    }

    #[test]
    fn test_has_attr_matcher_display() {
        let matcher = HasAttrMatcher::new("tls");
        assert_eq!(format!("{}", matcher), "has_attr:tls");
    }

    // ----- AllAttrsMatcher 测试 -----

    #[test]
    fn test_all_attrs_matcher_all_present() {
        let attrs =
            vec![DomainAttribute::with_bool("tls", true), DomainAttribute::with_int("port", 443)];
        let matcher = AllAttrsMatcher::from_matchers(vec![
            HasAttrMatcher::new("tls"),
            HasAttrMatcher::new("port"),
        ]);
        assert!(matcher.match_domain(&attrs));
    }

    #[test]
    fn test_all_attrs_matcher_partial_missing() {
        let attrs = vec![DomainAttribute::with_bool("tls", true)];
        let matcher = AllAttrsMatcher::from_matchers(vec![
            HasAttrMatcher::new("tls"),
            HasAttrMatcher::new("port"),
        ]);
        assert!(!matcher.match_domain(&attrs));
    }

    #[test]
    fn test_all_attrs_matcher_empty_matchers() {
        let attrs = vec![DomainAttribute::with_bool("tls", true)];
        let matcher = AllAttrsMatcher::from_matchers(vec![]);
        // 空匹配器列表匹配一切
        assert!(matcher.match_domain(&attrs));
    }

    #[test]
    fn test_all_attrs_matcher_empty_attrs_with_empty_matchers() {
        let matcher = AllAttrsMatcher::from_matchers(vec![]);
        assert!(matcher.match_domain(&[]));
    }

    #[test]
    fn test_all_attrs_matcher_display() {
        let matcher = AllAttrsMatcher::from_matchers(vec![
            HasAttrMatcher::new("tls"),
            HasAttrMatcher::new("port"),
        ]);
        assert_eq!(format!("{}", matcher), "all_attrs:@tls@port");
    }

    // ----- parse_attrs 测试 -----

    #[test]
    fn test_parse_attrs_normal() {
        let matcher = parse_attrs("@tls@port").unwrap();
        assert_eq!(matcher.matchers().len(), 2);
        assert_eq!(matcher.matchers()[0].key(), "tls");
        assert_eq!(matcher.matchers()[1].key(), "port");
    }

    #[test]
    fn test_parse_attrs_single() {
        let matcher = parse_attrs("@tls").unwrap();
        assert_eq!(matcher.matchers().len(), 1);
        assert_eq!(matcher.matchers()[0].key(), "tls");
    }

    #[test]
    fn test_parse_attrs_empty() {
        assert!(parse_attrs("").is_none());
    }

    #[test]
    fn test_parse_attrs_only_at_signs() {
        assert!(parse_attrs("@").is_none());
        assert!(parse_attrs("@@").is_none());
    }

    #[test]
    fn test_parse_attrs_no_leading_at() {
        // "tls@port" - split by @ gives ["tls", "port"]
        let matcher = parse_attrs("tls@port").unwrap();
        assert_eq!(matcher.matchers().len(), 2);
        assert_eq!(matcher.matchers()[0].key(), "tls");
        assert_eq!(matcher.matchers()[1].key(), "port");
    }

    #[test]
    fn test_parse_attrs_trailing_at() {
        let matcher = parse_attrs("@tls@").unwrap();
        assert_eq!(matcher.matchers().len(), 1);
        assert_eq!(matcher.matchers()[0].key(), "tls");
    }

    // ----- filter_by_attrs 测试 -----

    #[test]
    fn test_filter_by_attrs_with_matcher() {
        let domains = vec![
            (vec![DomainAttribute::with_bool("tls", true)], "a.com".to_string()),
            (vec![DomainAttribute::with_int("port", 80)], "b.com".to_string()),
            (vec![], "c.com".to_string()),
        ];
        let matcher = AllAttrsMatcher::from_matchers(vec![HasAttrMatcher::new("tls")]);
        let filtered = filter_by_attrs(&domains, Some(&matcher));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, "a.com");
    }

    #[test]
    fn test_filter_by_attrs_no_matcher() {
        let domains = vec![
            (vec![DomainAttribute::new("tls")], "a.com".to_string()),
            (vec![], "b.com".to_string()),
        ];
        let filtered = filter_by_attrs(&domains, None);
        assert_eq!(filtered.len(), 2);
    }
}
