//! MPH 策略的索引匹配器
//!
//! 对应 Go 版本 `strmatcher.MPHIndexMatcher`，自动为每个添加的匹配器
//! 分配自增索引，查询时返回匹配的索引列表。

use super::{composite_matches, IndexMatcher, Matcher, MatcherError, MatcherGroup, MatcherType};
use super::matcher_groups::{ACMatcherGroup, MPHMatcherGroup, SimpleMatcherGroup};

/// `&dyn Matcher` 的引用 wrapper，用于传递到 `ACMatcherGroup::add`。
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

/// MPH 策略的索引匹配器。
///
/// 与 `MphValueMatcher` 相同的内部组合（MPH + AC + Simple），
/// 额外维护自增索引计数器。
///
/// # 索引分配
///
/// 每次调用 `add` 时索引从 1 开始自增，调用者无需指定值。
///
/// # 构建流程
///
/// 必须在添加所有匹配器后调用 `build()` 构建内部数据结构。
pub struct MphIndexMatcher {
  mph: MPHMatcherGroup,
  ac: ACMatcherGroup,
  simple: SimpleMatcherGroup,
  count: u32,
}

impl MphIndexMatcher {
  /// 创建新的 MPH 索引匹配器。
  #[must_use]
  pub fn new() -> Self {
    Self {
      mph: MPHMatcherGroup::new(),
      ac: ACMatcherGroup::new(),
      simple: SimpleMatcherGroup::new(),
      count: 0,
    }
  }
}

impl Default for MphIndexMatcher {
  fn default() -> Self {
    Self::new()
  }
}

impl IndexMatcher for MphIndexMatcher {
  fn size(&self) -> u32 {
    self.count
  }

  fn add(&mut self, matcher: Box<dyn Matcher>) -> u32 {
    self.count += 1;
    let idx = self.count;

    match matcher.matcher_type() {
      MatcherType::Full => {
        self.mph.add_full_matcher(matcher.pattern(), idx);
      }
      MatcherType::Domain => {
        self.mph.add_domain_matcher(matcher.pattern(), idx);
      }
      MatcherType::Substr => {
        self.ac.add(MatcherRef(matcher.as_ref()), idx);
      }
      MatcherType::Regex => {
        self.simple.add(matcher, idx);
      }
    }

    idx
  }

  fn build(&mut self) -> Result<(), MatcherError> {
    // MPH 构建可能因空规则失败，忽略以保持兼容
    let _ = self.mph.build();
    self.ac.build().map_err(|e| {
      MatcherError::RegexCompile(
        regex::Error::Syntax(e.to_string()),
      )
    })?;
    Ok(())
  }

  fn match_str(&self, input: &str) -> Vec<u32> {
    let mph_results = self.mph.match_str(input);
    let ac_results = self.ac.match_str(input);
    let simple_results = self.simple.match_str(input);

    composite_matches(&[mph_results, ac_results, simple_results])
  }

  fn match_any(&self, input: &str) -> bool {
    self.mph.match_any(input)
      || self.ac.match_any(input)
      || self.simple.match_any(input)
  }
}

impl std::fmt::Debug for MphIndexMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MphIndexMatcher")
      .field("count", &self.count)
      .field("mph_built", &self.mph.is_built())
      .finish()
  }
}

impl std::fmt::Display for MphIndexMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "mph_index:{}", self.count)
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
  fn test_mph_index_full_match() {
    let mut m = MphIndexMatcher::new();
    let idx = m.add(Box::new(FullMatcher::new("example.com")));
    assert_eq!(idx, 1);
    m.build().unwrap();
    assert_eq!(m.match_str("example.com"), vec![1u32]);
    assert!(m.match_any("example.com"));
  }

  #[test]
  fn test_mph_index_domain_match() {
    let mut m = MphIndexMatcher::new();
    let idx = m.add(
      Box::new(DomainMatcherImpl::new("example.com")),
    );
    assert_eq!(idx, 1);
    m.build().unwrap();
    assert_eq!(m.match_str("sub.example.com"), vec![1u32]);
  }

  #[test]
  fn test_mph_index_substr_match() {
    let mut m = MphIndexMatcher::new();
    let idx = m.add(Box::new(SubstrMatcher::new("evil")));
    assert_eq!(idx, 1);
    m.build().unwrap();
    assert_eq!(m.match_str("evil.com"), vec![1u32]);
  }

  #[test]
  fn test_mph_index_regex_match() {
    let mut m = MphIndexMatcher::new();
    let idx = m.add(
      Box::new(RegexMatcher::new(r"evil\..*").unwrap()),
    );
    assert_eq!(idx, 1);
    m.build().unwrap();
    assert_eq!(m.match_str("evil.com"), vec![1u32]);
  }

  #[test]
  fn test_mph_index_auto_increment() {
    let mut m = MphIndexMatcher::new();
    let i1 = m.add(Box::new(FullMatcher::new("a.com")));
    let i2 = m.add(Box::new(FullMatcher::new("b.org")));
    let i3 = m.add(Box::new(SubstrMatcher::new("xyz")));
    assert_eq!(i1, 1);
    assert_eq!(i2, 2);
    assert_eq!(i3, 3);
    assert_eq!(m.size(), 3);
    m.build().unwrap();

    assert_eq!(m.match_str("a.com"), vec![1u32]);
    assert_eq!(m.match_str("b.org"), vec![2u32]);
    assert_eq!(m.match_str("xyz-site.com"), vec![3u32]);
  }

  #[test]
  fn test_mph_index_no_match() {
    let mut m = MphIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")));
    m.build().unwrap();
    assert!(m.match_str("other.com").is_empty());
    assert!(!m.match_any("other.com"));
  }

  #[test]
  fn test_mph_index_not_built() {
    let mut m = MphIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")));
    // 未调用 build()
    assert!(m.match_str("example.com").is_empty());
    assert!(!m.match_any("example.com"));
  }

  #[test]
  fn test_mph_index_empty_matcher() {
    let mut m = MphIndexMatcher::new();
    assert_eq!(m.size(), 0);
    m.build().unwrap();
    assert!(m.match_str("anything.com").is_empty());
    assert!(!m.match_any("anything.com"));
  }

  #[test]
  fn test_mph_index_match_any_short_circuit() {
    let mut m = MphIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("fast.com")));
    m.build().unwrap();
    assert!(m.match_any("fast.com"));
  }

  #[test]
  fn test_mph_index_display() {
    let mut m = MphIndexMatcher::new();
    m.add(Box::new(FullMatcher::new("a.com")));
    m.add(Box::new(FullMatcher::new("b.com")));
    assert_eq!(format!("{}", m), "mph_index:2");
  }
}
