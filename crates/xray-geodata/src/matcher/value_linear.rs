//! 线性策略的值匹配器
//!
//! 对应 Go 版本 `strmatcher.LinearValueMatcher`，组合四个线性匹配器组
//! （Full、Domain、Substr、Simple），提供简单直接的值匹配能力。
//!
//! 与 MPH 版本的区别：无需 `build()` 步骤，添加后立即可查询。

use super::{composite_matches, Matcher, MatcherGroup, MatcherType};
use super::matcher_groups::{
  DomainMatcherGroup, FullMatcherGroup, SimpleMatcherGroup,
  SubstrMatcherGroup,
};
use crate::matcher::domain::ValueMatcher;

/// 线性策略的值匹配器。
///
/// 内部组合四个匹配器组：
/// - `FullMatcherGroup`: 精确全匹配
/// - `DomainMatcherGroup`: 域名后缀匹配
/// - `SubstrMatcherGroup`: 子串匹配
/// - `SimpleMatcherGroup`: 正则匹配
///
/// # 值转换
///
/// 内部 Group 使用 `u16` 存储，对外以 `u32` 返回。
/// `add` 时 `u32` 截断为 `u16`，`match_str` 时 `u16` 扩展回 `u32`。
pub struct LinearValueMatcher {
  full: FullMatcherGroup,
  domain: DomainMatcherGroup,
  substr: SubstrMatcherGroup,
  simple: SimpleMatcherGroup,
}

impl LinearValueMatcher {
  /// 创建新的线性值匹配器。
  #[must_use]
  pub fn new() -> Self {
    Self {
      full: FullMatcherGroup::new(),
      domain: DomainMatcherGroup::new(),
      substr: SubstrMatcherGroup::new(),
      simple: SimpleMatcherGroup::new(),
    }
  }

  /// 添加匹配器及关联值。
  ///
  /// 按 `matcher_type()` 分派到对应的内部 Group。
  /// 值从 `u32` 截断为 `u16` 存入 Group。
  pub fn add(&mut self, matcher: Box<dyn Matcher>, value: u32) {
    let v = value as u16;
    match matcher.matcher_type() {
      MatcherType::Full => {
        // FullMatcherGroup 需要 FullMatcher 类型
        self.full.add(
          crate::matcher::FullMatcher::new(matcher.pattern()),
          v,
        );
      }
      MatcherType::Domain => {
        self.domain.add(
          crate::matcher::DomainMatcher::new(matcher.pattern()),
          v,
        );
      }
      MatcherType::Substr => {
        self.substr.add(matcher.pattern(), v);
      }
      MatcherType::Regex => {
        self.simple.add(matcher, v);
      }
    }
  }

  /// 构建内部数据结构（空操作）。
  ///
  /// 为接口一致性提供，线性匹配器无需构建步骤。
  pub fn build(&mut self) {}

  /// 只要有一个匹配器匹配就返回 `true`。
  ///
  /// 短路求值：依次检查 full、domain、substr、simple。
  pub fn match_any(&self, input: &str) -> bool {
    self.full.match_any(input)
      || self.domain.match_any(input)
      || self.substr.match_any(input)
      || self.simple.match_any(input)
  }
}

impl Default for LinearValueMatcher {
  fn default() -> Self {
    Self::new()
  }
}

impl ValueMatcher for LinearValueMatcher {
  fn match_str(&self, input: &str) -> Vec<u32> {
    let full_results: Vec<u32> = self
      .full
      .match_str(input)
      .into_iter()
      .map(|v| v as u32)
      .collect();

    let domain_results: Vec<u32> = self
      .domain
      .match_str(input)
      .into_iter()
      .map(|v| v as u32)
      .collect();

    let substr_results: Vec<u32> = self
      .substr
      .match_str(input)
      .into_iter()
      .map(|v| v as u32)
      .collect();

    let simple_results: Vec<u32> = self
      .simple
      .match_str(input)
      .into_iter()
      .map(|v| v as u32)
      .collect();

    composite_matches(&[
      full_results,
      domain_results,
      substr_results,
      simple_results,
    ])
  }
}

impl std::fmt::Debug for LinearValueMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("LinearValueMatcher").finish()
  }
}

impl std::fmt::Display for LinearValueMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "linear_value")
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
  fn test_linear_value_full_match() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")), 1);
    assert_eq!(m.match_str("example.com"), vec![1u32]);
    assert!(m.match_any("example.com"));
  }

  #[test]
  fn test_linear_value_domain_match() {
    let mut m = LinearValueMatcher::new();
    m.add(
      Box::new(DomainMatcherImpl::new("example.com")),
      2,
    );
    assert_eq!(m.match_str("sub.example.com"), vec![2u32]);
    assert!(m.match_any("example.com"));
  }

  #[test]
  fn test_linear_value_substr_match() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(SubstrMatcher::new("evil")), 3);
    assert_eq!(m.match_str("evil.com"), vec![3u32]);
    assert!(m.match_any("evil.com"));
  }

  #[test]
  fn test_linear_value_regex_match() {
    let mut m = LinearValueMatcher::new();
    m.add(
      Box::new(RegexMatcher::new(r"evil\..*").unwrap()),
      4,
    );
    assert_eq!(m.match_str("evil.com"), vec![4u32]);
    assert!(m.match_any("evil.com"));
  }

  #[test]
  fn test_linear_value_mixed_types() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(FullMatcher::new("exact.com")), 1);
    m.add(
      Box::new(DomainMatcherImpl::new("domain.com")),
      2,
    );
    m.add(Box::new(SubstrMatcher::new("keyword")), 3);
    m.add(
      Box::new(RegexMatcher::new(r"regex\d+").unwrap()),
      4,
    );

    assert_eq!(m.match_str("exact.com"), vec![1u32]);
    assert_eq!(m.match_str("sub.domain.com"), vec![2u32]);
    assert!(m.match_any("keyword-site.com"));
    assert!(m.match_any("regex42"));
  }

  #[test]
  fn test_linear_value_no_match() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")), 1);
    assert!(m.match_str("other.com").is_empty());
    assert!(!m.match_any("other.com"));
  }

  #[test]
  fn test_linear_value_empty_matcher() {
    let m = LinearValueMatcher::new();
    assert!(m.match_str("anything.com").is_empty());
    assert!(!m.match_any("anything.com"));
  }

  #[test]
  fn test_linear_value_no_build_needed() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")), 1);
    // 不调用 build() 也能立即查询
    assert!(m.match_any("example.com"));
    assert_eq!(m.match_str("example.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_value_match_any_short_circuit() {
    let mut m = LinearValueMatcher::new();
    // 仅添加 Full 匹配器，match_any 应在 full 层短路
    m.add(Box::new(FullMatcher::new("fast.com")), 1);
    assert!(m.match_any("fast.com"));
    assert!(!m.match_any("slow.com"));
  }

  #[test]
  fn test_linear_value_build_noop() {
    let mut m = LinearValueMatcher::new();
    m.add(Box::new(FullMatcher::new("example.com")), 1);
    m.build(); // 空操作，不应影响结果
    assert_eq!(m.match_str("example.com"), vec![1u32]);
  }

  #[test]
  fn test_linear_value_display() {
    let m = LinearValueMatcher::new();
    assert_eq!(format!("{}", m), "linear_value");
  }
}
