//! 线性策略的存在性匹配器
//!
//! 对应 Go 版本 `strmatcher.LinearAnyMatcher`，组合四个 MatcherSet
//! 仅做存在性检查，不返回任何值。

use super::{
    AnyMatcher, Matcher, MatcherSet, MatcherType,
    matcher_sets::{DomainMatcherSet, FullMatcherSet, SimpleMatcherSet, SubstrMatcherSet},
};

/// 线性策略的存在性匹配器。
///
/// 内部组合四个匹配器集合：
/// - `FullMatcherSet`: 精确全匹配
/// - `DomainMatcherSet`: 域名后缀匹配
/// - `SubstrMatcherSet`: 子串匹配
/// - `SimpleMatcherSet`: 任意匹配器（含 Regex）
///
/// 使用轻量级 MatcherSet 实现，仅提供存在性检查。
pub struct LinearAnyMatcher {
    full: FullMatcherSet,
    domain: DomainMatcherSet,
    substr: SubstrMatcherSet,
    simple: SimpleMatcherSet,
}

impl LinearAnyMatcher {
    /// 创建新的线性存在性匹配器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            full: FullMatcherSet::new(),
            domain: DomainMatcherSet::new(),
            substr: SubstrMatcherSet::new(),
            simple: SimpleMatcherSet::new(),
        }
    }
}

impl Default for LinearAnyMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AnyMatcher for LinearAnyMatcher {
    fn add(&mut self, matcher: Box<dyn Matcher>) {
        match matcher.matcher_type() {
            MatcherType::Full => {
                self.full.add(matcher.pattern());
            },
            MatcherType::Domain => {
                self.domain.add(matcher.pattern());
            },
            MatcherType::Substr => {
                self.substr.add(matcher.pattern());
            },
            MatcherType::Regex => {
                // Regex 需要 matcher 对象，无法用 Set 的模式字符串
                self.simple.add(matcher);
            },
        }
    }

    fn match_any(&self, input: &str) -> bool {
        self.full.match_any(input)
            || self.domain.match_any(input)
            || self.substr.match_any(input)
            || self.simple.match_any(input)
    }
}

impl std::fmt::Debug for LinearAnyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearAnyMatcher").finish()
    }
}

impl std::fmt::Display for LinearAnyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linear_any")
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
    fn test_any_linear_full_match() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(FullMatcher::new("example.com")));
        assert!(m.match_any("example.com"));
        assert!(!m.match_any("other.com"));
    }

    #[test]
    fn test_any_linear_domain_match() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(DomainMatcherImpl::new("example.com")));
        assert!(m.match_any("sub.example.com"));
        assert!(m.match_any("example.com"));
        assert!(!m.match_any("notexample.com"));
    }

    #[test]
    fn test_any_linear_substr_match() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(SubstrMatcher::new("evil")));
        assert!(m.match_any("evil.com"));
        assert!(!m.match_any("good.com"));
    }

    #[test]
    fn test_any_linear_regex_match() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(RegexMatcher::new(r"evil\..*").unwrap()));
        assert!(m.match_any("evil.com"));
        assert!(!m.match_any("good.com"));
    }

    #[test]
    fn test_any_linear_mixed_types() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(FullMatcher::new("exact.com")));
        m.add(Box::new(DomainMatcherImpl::new("domain.com")));
        m.add(Box::new(SubstrMatcher::new("keyword")));
        m.add(Box::new(RegexMatcher::new(r"regex\d+").unwrap()));

        assert!(m.match_any("exact.com"));
        assert!(m.match_any("sub.domain.com"));
        assert!(m.match_any("keyword-site.com"));
        assert!(m.match_any("regex42"));
        assert!(!m.match_any("other.org"));
    }

    #[test]
    fn test_any_linear_no_match() {
        let mut m = LinearAnyMatcher::new();
        m.add(Box::new(FullMatcher::new("example.com")));
        assert!(!m.match_any("other.com"));
    }

    #[test]
    fn test_any_linear_empty() {
        let m = LinearAnyMatcher::new();
        assert!(!m.match_any("anything.com"));
    }

    #[test]
    fn test_any_linear_short_circuit() {
        let mut m = LinearAnyMatcher::new();
        // 仅添加 Full 匹配器，match_any 应在 full 层短路
        m.add(Box::new(FullMatcher::new("fast.com")));
        assert!(m.match_any("fast.com"));
    }

    #[test]
    fn test_any_linear_display() {
        let m = LinearAnyMatcher::new();
        assert_eq!(format!("{}", m), "linear_any");
    }
}
