//! 4种基础字符串匹配器实现
//!
//! 对应 Go 版本 `common/geodata/strmatcher/matchers.go`，提供：
//!
//! - [`FullMatcher`] - 精确全匹配（HashMap 语义）
//! - [`DomainMatcher`] - 域名后缀匹配（如 "example.com" 匹配 "sub.example.com"）
//! - [`SubstrMatcher`] - 子串包含匹配
//! - [`RegexMatcher`] - 正则表达式匹配

use regex::Regex;

use super::{Matcher, MatcherType};

// ===== FullMatcher =====

/// 精确全匹配器。
///
/// 输入字符串必须与模式完全相等才匹配。
/// 对应 Go 版本 `strmatcher.FullMatcher`。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::{FullMatcher, Matcher};
///
/// let m = FullMatcher::new("example.com");
/// assert!(m.match_str("example.com"));
/// assert!(!m.match_str("sub.example.com"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FullMatcher {
    pattern: String,
}

impl FullMatcher {
    /// 创建新的精确全匹配器。
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { pattern: pattern.into() }
    }
}

impl Matcher for FullMatcher {
    fn matcher_type(&self) -> MatcherType {
        MatcherType::Full
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn match_str(&self, input: &str) -> bool {
        self.pattern == input
    }
}

impl std::fmt::Display for FullMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "full:{}", self.pattern)
    }
}

// ===== DomainMatcher =====

/// 域名后缀匹配器。
///
/// 输入字符串必须是模式的子域名或自身才匹配。
/// 匹配规则：输入以模式结尾，且输入长度等于模式长度
/// （完全相等）或模式前一个字符是点号（域名边界）。
///
/// 对应 Go 版本 `strmatcher.DomainMatcher`。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::{DomainMatcher, Matcher};
///
/// let m = DomainMatcher::new("example.com");
/// assert!(m.match_str("example.com")); // 完全相等
/// assert!(m.match_str("sub.example.com")); // 子域名
/// assert!(!m.match_str("notexample.com")); // 非域名边界
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainMatcher {
    pattern: String,
}

impl DomainMatcher {
    /// 创建新的域名后缀匹配器。
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { pattern: pattern.into() }
    }
}

impl Matcher for DomainMatcher {
    fn matcher_type(&self) -> MatcherType {
        MatcherType::Domain
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn match_str(&self, input: &str) -> bool {
        if !input.ends_with(&self.pattern) {
            return false;
        }
        let input_len = input.len();
        let pattern_len = self.pattern.len();
        if input_len == pattern_len {
            // 完全相等
            return true;
        }
        if pattern_len == 0 {
            // 空模式：任何非空输入都不匹配
            // （域名匹配要求域名边界，空模式无边界）
            return false;
        }
        // 模式前一个字符是点号（域名边界）
        input.as_bytes()[input_len - pattern_len - 1] == b'.'
    }
}

impl std::fmt::Display for DomainMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "domain:{}", self.pattern)
    }
}

// ===== SubstrMatcher =====

/// 子串包含匹配器。
///
/// 输入字符串包含模式作为子串即匹配。
/// 对应 Go 版本 `strmatcher.SubstrMatcher`。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::{Matcher, SubstrMatcher};
///
/// let m = SubstrMatcher::new("evil");
/// assert!(m.match_str("evil.com"));
/// assert!(m.match_str("not-evil-site.com"));
/// assert!(!m.match_str("example.com"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubstrMatcher {
    pattern: String,
}

impl SubstrMatcher {
    /// 创建新的子串包含匹配器。
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { pattern: pattern.into() }
    }
}

impl Matcher for SubstrMatcher {
    fn matcher_type(&self) -> MatcherType {
        MatcherType::Substr
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn match_str(&self, input: &str) -> bool {
        input.contains(&self.pattern)
    }
}

impl std::fmt::Display for SubstrMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keyword:{}", self.pattern)
    }
}

// ===== RegexMatcher =====

/// 正则表达式匹配器。
///
/// 输入字符串匹配正则表达式即匹配。
/// 正则匹配默认区分大小写。
///
/// 对应 Go 版本 `strmatcher.RegexMatcher`。
///
/// # 示例
///
/// ```
/// use xray_geodata::matcher::{Matcher, RegexMatcher};
///
/// let m = RegexMatcher::new(r"evil\..*").unwrap();
/// assert!(m.match_str("evil.com"));
/// assert!(m.match_str("evil.org"));
/// assert!(!m.match_str("good.com"));
/// ```
#[derive(Debug)]
pub struct RegexMatcher {
    pattern: String,
    regex: Regex,
}

impl RegexMatcher {
    /// 创建新的正则表达式匹配器。
    ///
    /// # 错误
    ///
    /// 正则表达式编译失败时返回 `MatcherError::RegexCompile`。
    pub fn new(pattern: &str) -> Result<Self, super::MatcherError> {
        let regex = Regex::new(pattern)?;
        Ok(Self { pattern: pattern.to_owned(), regex })
    }
}

impl Matcher for RegexMatcher {
    fn matcher_type(&self) -> MatcherType {
        MatcherType::Regex
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn match_str(&self, input: &str) -> bool {
        self.regex.is_match(input)
    }
}

impl std::fmt::Display for RegexMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "regexp:{}", self.pattern)
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Matcher;

    // ----- FullMatcher 测试 -----

    #[test]
    fn test_full_matcher_exact_match() {
        let m = FullMatcher::new("example.com");
        assert!(m.match_str("example.com"));
    }

    #[test]
    fn test_full_matcher_no_match() {
        let m = FullMatcher::new("example.com");
        assert!(!m.match_str("sub.example.com"));
        assert!(!m.match_str("notexample.com"));
        assert!(!m.match_str("EXAMPLE.COM"));
    }

    #[test]
    fn test_full_matcher_empty_pattern() {
        let m = FullMatcher::new("");
        assert!(m.match_str(""));
        assert!(!m.match_str("a"));
    }

    #[test]
    fn test_full_matcher_type_and_pattern() {
        let m = FullMatcher::new("test.com");
        assert_eq!(m.matcher_type(), MatcherType::Full);
        assert_eq!(m.pattern(), "test.com");
    }

    #[test]
    fn test_full_matcher_display() {
        let m = FullMatcher::new("example.com");
        assert_eq!(format!("{}", m), "full:example.com");
    }

    // ----- DomainMatcher 测试 -----

    #[test]
    fn test_domain_matcher_exact_match() {
        let m = DomainMatcher::new("example.com");
        assert!(m.match_str("example.com"));
    }

    #[test]
    fn test_domain_matcher_subdomain() {
        let m = DomainMatcher::new("example.com");
        assert!(m.match_str("sub.example.com"));
        assert!(m.match_str("a.b.example.com"));
    }

    #[test]
    fn test_domain_matcher_no_boundary() {
        // "notexample.com" 以 "example.com" 结尾，
        // 但前一个字符不是点号
        let m = DomainMatcher::new("example.com");
        assert!(!m.match_str("notexample.com"));
    }

    #[test]
    fn test_domain_matcher_no_suffix() {
        let m = DomainMatcher::new("example.com");
        assert!(!m.match_str("example.org"));
        assert!(!m.match_str("other.com"));
    }

    #[test]
    fn test_domain_matcher_empty_input() {
        let m = DomainMatcher::new("example.com");
        assert!(!m.match_str(""));
    }

    #[test]
    fn test_domain_matcher_empty_pattern() {
        let m = DomainMatcher::new("");
        // 空模式：仅匹配空字符串
        // （域名匹配要求域名边界，空模式无边界）
        assert!(m.match_str(""));
        assert!(!m.match_str("anything.com"));
    }

    #[test]
    fn test_domain_matcher_type_and_pattern() {
        let m = DomainMatcher::new("test.com");
        assert_eq!(m.matcher_type(), MatcherType::Domain);
        assert_eq!(m.pattern(), "test.com");
    }

    #[test]
    fn test_domain_matcher_display() {
        let m = DomainMatcher::new("example.com");
        assert_eq!(format!("{}", m), "domain:example.com");
    }

    // ----- SubstrMatcher 测试 -----

    #[test]
    fn test_substr_matcher_contains() {
        let m = SubstrMatcher::new("evil");
        assert!(m.match_str("evil.com"));
        assert!(m.match_str("not-evil-site.com"));
        assert!(m.match_str("evil"));
    }

    #[test]
    fn test_substr_matcher_not_contains() {
        let m = SubstrMatcher::new("evil");
        assert!(!m.match_str("example.com"));
        assert!(!m.match_str("good.org"));
    }

    #[test]
    fn test_substr_matcher_empty_pattern() {
        let m = SubstrMatcher::new("");
        // 空子串包含于任何字符串
        assert!(m.match_str(""));
        assert!(m.match_str("anything"));
    }

    #[test]
    fn test_substr_matcher_empty_input() {
        let m = SubstrMatcher::new("pattern");
        assert!(!m.match_str(""));
    }

    #[test]
    fn test_substr_matcher_type_and_pattern() {
        let m = SubstrMatcher::new("test");
        assert_eq!(m.matcher_type(), MatcherType::Substr);
        assert_eq!(m.pattern(), "test");
    }

    #[test]
    fn test_substr_matcher_display() {
        let m = SubstrMatcher::new("evil");
        assert_eq!(format!("{}", m), "keyword:evil");
    }

    // ----- RegexMatcher 测试 -----

    #[test]
    fn test_regex_matcher_match() {
        let m = RegexMatcher::new(r"evil\..*").unwrap();
        assert!(m.match_str("evil.com"));
        assert!(m.match_str("evil.org"));
    }

    #[test]
    fn test_regex_matcher_no_match() {
        let m = RegexMatcher::new(r"evil\..*").unwrap();
        assert!(!m.match_str("good.com"));
        assert!(!m.match_str("evil")); // 无点号
    }

    #[test]
    fn test_regex_matcher_case_sensitive() {
        let m = RegexMatcher::new(r"Evil").unwrap();
        assert!(m.match_str("Evil.com"));
        assert!(!m.match_str("evil.com")); // 区分大小写
    }

    #[test]
    fn test_regex_matcher_invalid_pattern() {
        let result = RegexMatcher::new(r"[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_regex_matcher_type_and_pattern() {
        let m = RegexMatcher::new(r"test\d+").unwrap();
        assert_eq!(m.matcher_type(), MatcherType::Regex);
        assert_eq!(m.pattern(), r"test\d+");
    }

    #[test]
    fn test_regex_matcher_display() {
        let m = RegexMatcher::new(r"evil\..*").unwrap();
        assert_eq!(format!("{}", m), r"regexp:evil\..*");
    }

    // ----- MatcherType 工厂测试 -----

    #[test]
    fn test_matcher_type_new_full() {
        let m = MatcherType::Full.new_matcher("example.com").unwrap();
        assert_eq!(m.matcher_type(), MatcherType::Full);
        assert!(m.match_str("example.com"));
        assert!(!m.match_str("other.com"));
    }

    #[test]
    fn test_matcher_type_new_domain() {
        let m = MatcherType::Domain.new_matcher("example.com").unwrap();
        assert_eq!(m.matcher_type(), MatcherType::Domain);
        assert!(m.match_str("sub.example.com"));
    }

    #[test]
    fn test_matcher_type_new_substr() {
        let m = MatcherType::Substr.new_matcher("evil").unwrap();
        assert_eq!(m.matcher_type(), MatcherType::Substr);
        assert!(m.match_str("evil.com"));
    }

    #[test]
    fn test_matcher_type_new_regex() {
        let m = MatcherType::Regex.new_matcher(r"evil\..*").unwrap();
        assert_eq!(m.matcher_type(), MatcherType::Regex);
        assert!(m.match_str("evil.com"));
    }

    #[test]
    fn test_matcher_type_new_regex_invalid() {
        let result = MatcherType::Regex.new_matcher(r"[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_matcher_type_display() {
        assert_eq!(format!("{}", MatcherType::Full), "full");
        assert_eq!(format!("{}", MatcherType::Domain), "domain");
        assert_eq!(format!("{}", MatcherType::Substr), "keyword");
        assert_eq!(format!("{}", MatcherType::Regex), "regexp");
    }

    // ----- Clone / PartialEq 测试 -----

    #[test]
    fn test_full_matcher_clone_eq() {
        let m1 = FullMatcher::new("test.com");
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_domain_matcher_clone_eq() {
        let m1 = DomainMatcher::new("test.com");
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_substr_matcher_clone_eq() {
        let m1 = SubstrMatcher::new("test");
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }
}
