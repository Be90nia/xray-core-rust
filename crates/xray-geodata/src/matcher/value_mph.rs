//! MPH 策略的值匹配器
//!
//! 对应 Go 版本 `strmatcher.MPHValueMatcher`，组合 MPH 匹配器组
//! （Full + Domain）、AC 自动机（Substr）和简单匹配器组（Regex），
//! 提供高性能的值匹配能力。

use super::{
    Matcher, MatcherError, MatcherGroup, MatcherType, composite_matches,
    matcher_groups::{ACMatcherGroup, MPHMatcherGroup, SimpleMatcherGroup},
};
use crate::matcher::domain::ValueMatcher;

/// `&dyn Matcher` 的引用 wrapper，用于传递到 `ACMatcherGroup::add`。
///
/// `ACMatcherGroup::add` 接受 `impl Matcher`，而 `&dyn Matcher`
/// 不直接实现 `Matcher` trait。通过此 wrapper 间接实现。
struct MatcherRef<'a>(&'a dyn Matcher);

impl Matcher for MatcherRef<'_> {
    fn matcher_type(&self) -> MatcherType {
        self.0.matcher_type()
    }

    fn pattern(&self) -> &str {
        self.0.pattern()
    }

    fn match_str(&self, input: &str) -> bool {
        self.0.match_str(input)
    }
}

/// MPH 策略的值匹配器。
///
/// 内部组合三个匹配器组：
/// - `MPHMatcherGroup`: 处理 Full 和 Domain 类型
/// - `ACMatcherGroup`: 处理 Substr 类型
/// - `SimpleMatcherGroup`: 处理 Regex 类型
///
/// # 构建流程
///
/// 必须在添加所有匹配器后调用 `build()` 构建 MPH 哈希表和
/// AC 自动机，之后才能查询。
///
/// # 值语义
///
/// 值以 `u32` 全程存储与返回，与 Go 版本 `uint32` 一致，无截断。
pub struct MphValueMatcher {
    mph: MPHMatcherGroup,
    ac: ACMatcherGroup,
    simple: SimpleMatcherGroup,
}

impl MphValueMatcher {
    /// 创建新的 MPH 值匹配器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            mph: MPHMatcherGroup::new(),
            ac: ACMatcherGroup::new(),
            simple: SimpleMatcherGroup::new(),
        }
    }

    /// 添加匹配器及关联值。
    ///
    /// 按 `matcher_type()` 分派到对应的内部 Group：
    /// - Full/Domain → `mph`
    /// - Substr → `ac`
    /// - Regex → `simple`
    ///
    /// 值以 `u32` 存入 Group。
    pub fn add(&mut self, matcher: Box<dyn Matcher>, value: u32) {
        match matcher.matcher_type() {
            MatcherType::Full => {
                self.mph.add_full_matcher(matcher.pattern(), value);
            },
            MatcherType::Domain => {
                self.mph.add_domain_matcher(matcher.pattern(), value);
            },
            MatcherType::Substr => {
                self.ac.add(MatcherRef(matcher.as_ref()), value);
            },
            MatcherType::Regex => {
                self.simple.add(matcher, value);
            },
        }
    }

    /// 构建内部数据结构。
    ///
    /// 先构建 MPH 哈希表，再构建 AC 自动机。
    /// MPH 构建可能因空规则而失败，此时忽略错误
    /// （空 MPH 在查询时安全返回空结果）。
    pub fn build(&mut self) -> Result<(), MatcherError> {
        // MPH 构建可能因空规则失败，忽略以保持兼容
        let _ = self.mph.build();
        self.ac
            .build()
            .map_err(|e| MatcherError::RegexCompile(regex::Error::Syntax(e.to_string())))?;
        Ok(())
    }

    /// 只要有一个匹配器匹配就返回 `true`。
    ///
    /// 短路求值：依次检查 mph、ac、simple。
    pub fn match_any(&self, input: &str) -> bool {
        self.mph.match_any(input) || self.ac.match_any(input) || self.simple.match_any(input)
    }
}

impl Default for MphValueMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueMatcher for MphValueMatcher {
    fn match_str(&self, input: &str) -> Vec<u32> {
        let mph_results = self.mph.match_str(input);
        let ac_results = self.ac.match_str(input);
        let simple_results = self.simple.match_str(input);

        composite_matches(&[mph_results, ac_results, simple_results])
    }
}

impl std::fmt::Debug for MphValueMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MphValueMatcher").field("mph_built", &self.mph.is_built()).finish()
    }
}

impl std::fmt::Display for MphValueMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let built = self.mph.is_built();
        write!(f, "mph_value:built={built}")
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{
        DomainMatcher as DomainMatcherImpl, FullMatcher, RegexMatcher, SubstrMatcher,
    };

    #[test]
    fn test_mph_value_full_match() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(FullMatcher::new("example.com")), 1);
        m.build().unwrap();
        assert_eq!(m.match_str("example.com"), vec![1u32]);
        assert!(m.match_any("example.com"));
    }

    #[test]
    fn test_mph_value_domain_match() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(DomainMatcherImpl::new("example.com")), 2);
        m.build().unwrap();
        assert_eq!(m.match_str("sub.example.com"), vec![2u32]);
        assert!(m.match_any("example.com"));
    }

    #[test]
    fn test_mph_value_substr_match() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(SubstrMatcher::new("evil")), 3);
        m.build().unwrap();
        assert_eq!(m.match_str("evil.com"), vec![3u32]);
        assert!(m.match_any("evil.com"));
    }

    #[test]
    fn test_mph_value_regex_match() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(RegexMatcher::new(r"evil\..*").unwrap()), 4);
        m.build().unwrap();
        assert_eq!(m.match_str("evil.com"), vec![4u32]);
        assert!(m.match_any("evil.com"));
    }

    #[test]
    fn test_mph_value_mixed_types() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(FullMatcher::new("exact.com")), 1);
        m.add(Box::new(DomainMatcherImpl::new("domain.com")), 2);
        m.add(Box::new(SubstrMatcher::new("keyword")), 3);
        m.add(Box::new(RegexMatcher::new(r"regex\d+").unwrap()), 4);
        m.build().unwrap();

        assert_eq!(m.match_str("exact.com"), vec![1u32]);
        assert_eq!(m.match_str("sub.domain.com"), vec![2u32]);
        assert!(m.match_any("keyword-site.com"));
        assert!(m.match_any("regex42"));
    }

    #[test]
    fn test_mph_value_no_match() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(FullMatcher::new("example.com")), 1);
        m.build().unwrap();
        assert!(m.match_str("other.com").is_empty());
        assert!(!m.match_any("other.com"));
    }

    #[test]
    fn test_mph_value_not_built() {
        let mut m = MphValueMatcher::new();
        m.add(Box::new(FullMatcher::new("example.com")), 1);
        // 未调用 build()
        assert!(m.match_str("example.com").is_empty());
        assert!(!m.match_any("example.com"));
    }

    #[test]
    fn test_mph_value_empty_matcher() {
        let mut m = MphValueMatcher::new();
        m.build().unwrap();
        assert!(m.match_str("anything.com").is_empty());
        assert!(!m.match_any("anything.com"));
    }

    #[test]
    fn test_mph_value_match_any_short_circuit() {
        let mut m = MphValueMatcher::new();
        // 仅添加 Full 匹配器，match_any 应在 mph 层短路
        m.add(Box::new(FullMatcher::new("fast.com")), 1);
        m.build().unwrap();
        assert!(m.match_any("fast.com"));
    }

    #[test]
    fn test_mph_value_display() {
        let m = MphValueMatcher::new();
        assert!(format!("{}", m).contains("mph_value"));
    }

    #[test]
    fn test_mph_value_no_u32_truncation() {
        // Go 语义：value 全程 uint32 存储，无 u16 截断（matchergroup_mph.go 等）
        for &v in &[65535u32, 65536, u32::MAX] {
            let mut m = MphValueMatcher::new();
            m.add(Box::new(FullMatcher::new("exact.com")), v);
            m.add(Box::new(DomainMatcherImpl::new("domain.com")), v);
            m.add(Box::new(SubstrMatcher::new("keyword")), v);
            m.add(Box::new(RegexMatcher::new(r"evil\..*").unwrap()), v);
            m.build().unwrap();
            assert_eq!(m.match_str("exact.com"), vec![v], "full v={v}");
            assert_eq!(m.match_str("sub.domain.com"), vec![v], "domain v={v}");
            assert_eq!(m.match_str("keyword.net"), vec![v], "substr v={v}");
            assert_eq!(m.match_str("evil.com"), vec![v], "regex v={v}");
        }
    }
}
