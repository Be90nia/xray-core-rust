//! 线性策略的索引匹配器
//!
//! 对应 Go 版本 `strmatcher.LinearIndexMatcher`，自动为每个添加的匹配器
//! 分配自增索引，使用线性扫描匹配器组。

use super::{composite_matches, IndexMatcher, Matcher, MatcherGroup, MatcherType};
use super::matcher_groups::{
  DomainMatcherGroup, FullMatcherGroup, SimpleMatcherGroup,
  SubstrMatcherGroup,
};

/// 线性策略的索引匹配器。
///
/// 与 `LinearValueMatcher` 相同的内部组合（Full + Domain + Substr +
/// Simple），额外维护自增索引计数器。
///
/// # 索引分配
///
/// 每次调用 `add` 时索引从 1 开始自增，调用者无需指定值。
///
/// # 与 MPH 版本的区别
///
/// 无需 `build()` 步骤，添加后立即可查询。
pub struct LinearIndexMatcher {
  full: FullMatcherGroup,
  domain: DomainMatcherGroup,
  substr: SubstrMatcherGroup,
  simple: SimpleMatcherGroup,
  count: u32,
}

impl LinearIndexMatcher {
  /// 创建新的线性索引匹配器。
  #[must_use]
  pub fn new() -> Self {
    Self {
      full: FullMatcherGroup::new(),
      domain: DomainMatcherGroup::new(),
      substr: SubstrMatcherGroup::new(),
      simple: SimpleMatcherGroup::new(),
      count: 0,
    }
  }
}

impl Default for LinearIndexMatcher {
  fn default() -> Self {
    Self::new()
  }
}

impl IndexMatcher for LinearIndexMatcher {
  fn size(&self) -> u32 {
    self.count
  }

  fn add(&mut self, matcher: Box<dyn Matcher>) -> u32 {
    self.count += 1;
    let idx = self.count;

    match matcher.matcher_type() {
      MatcherType::Full => {
        self.full.add(
          crate::matcher::FullMatcher::new(matcher.pattern()),
          idx,
        );
      }
      MatcherType::Domain => {
        self.domain.add(
          crate::matcher::DomainMatcher::new(matcher.pattern()),
          idx,
        );
      }
      MatcherType::Substr => {
        self.substr.add(matcher.pattern(), idx);
      }
      MatcherType::Regex => {
        self.simple.add(matcher, idx);
      }
    }

    idx
  }

  fn build(&mut self) -> Result<(), super::MatcherError> {
    // 线性匹配器无需构建
    Ok(())
  }

  fn match_str(&self, input: &str) -> Vec<u32> {
    let full_results = self.full.match_str(input);
    let domain_results = self.domain.match_str(input);
    let substr_results = self.substr.match_str(input);
    let simple_results = self.simple.match_str(input);

    composite_matches(&[
      full_results,
      domain_results,
      substr_results,
      simple_results,
    ])
  }

  fn match_any(&self, input: &str) -> bool {
    self.full.match_any(input)
      || self.domain.match_any(input)
      || self.substr.match_any(input)
      || self.simple.match_any(input)
  }
}

impl std::fmt::Debug for LinearIndexMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("LinearIndexMatcher")
      .field("count", &self.count)
      .finish()
  }
}

impl std::fmt::Display for LinearIndexMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "linear_index:{}", self.count)
  }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
  use super::*;
  use crate::matcher::{
    DomainMatcher as DomainMatcherImpl, FullMatcher,
    RegexMatcher, SubstrMatcher,
  };

  #[test]
  fn test_linear_index_full_match() {
    let mut m = LinearIndexMatcher::new();
    let idx = m.add(Box::new(FullMatcher::new("example.com")));
    assert_eq!(idx, 1);
    assert_eq!(m.match_str("example.com"), vec![1u32]);
    assert!(m.match_any("example.com"));
  }

  #[test]
  fn test_linear_index_domain_match() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(DomainMatcherImpl::new("example.com")));
    assert_eq!(m.match_str("sub.example.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_index_substr_match() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(SubstrMatcher::new("evil")));
    assert_eq!(m.match_str("evil.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_index_regex_match() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(RegexMatcher::new(r"evil\..*").unwrap()));
    assert_eq!(m.match_str("evil.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_index_auto_increment() {
    let mut m = LinearIndexMatcher::new();
    let i1 = m.add(Box::new(FullMatcher::new("a.com")));
    let i2 = m.add(Box::new(DomainMatcherImpl::new("b.org")));
    let i3 = m.add(Box::new(SubstrMatcher::new("xyz")));
    let i4 = m.add(
      Box::new(RegexMatcher::new(r"pat\d+").unwrap()),
    );
    assert_eq!(i1, 1);
    assert_eq!(i2, 2);
    assert_eq!(i3, 3);
    assert_eq!(i4, 4);
    assert_eq!(m.size(), 4);

    assert_eq!(m.match_str("a.com"), vec![1u32]);
    assert_eq!(m.match_str("sub.b.org"), vec![2u32]);
    assert!(m.match_any("xyz-site.com"));
    assert!(m.match_any("pat42"));
  }

  #[test]
  fn test_linear_index_no_match() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")));
    assert!(m.match_str("other.com").is_empty());
    assert!(!m.match_any("other.com"));
  }

  #[test]
  fn test_linear_index_empty_matcher() {
    let m = LinearIndexMatcher::new();
    assert_eq!(m.size(), 0);
    assert!(m.match_str("anything.com").is_empty());
    assert!(!m.match_any("anything.com"));
  }

  #[test]
  fn test_linear_index_no_build_needed() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")));
    // 不调用 build() 也能查询
    assert_eq!(m.match_str("example.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_index_build_noop() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")));
    m.build().unwrap(); // 空操作
    assert_eq!(m.match_str("example.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_index_match_any_short_circuit() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("fast.com")));
    assert!(m.match_any("fast.com"));
    assert!(!m.match_any("slow.com"));
  }

  #[test]
  fn test_linear_index_display() {
    let mut m = LinearIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("a.com")));
    m.add(Box::new(FullMatcher::new("b.com")));
    assert_eq!(format!("{}", m), "linear_index:2");
  }
}
