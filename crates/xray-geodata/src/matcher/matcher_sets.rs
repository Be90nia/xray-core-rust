//! 4 种 MatcherSet 变体实现
//!
//! 对应 Go 版本 `common/geodata/strmatcher/` 目录下的匹配器集合，
//! 仅提供存在性检查（不返回值）。
//!
//! # 匹配器集合类型
//!
//! - [`FullMatcherSet`] - 哈希集合精确匹配
//! - [`DomainMatcherSet`] - 字典树域名后缀匹配
//! - [`SubstrMatcherSet`] - 线性扫描子串匹配
//! - [`SimpleMatcherSet`] - 线性扫描任意匹配器

use std::collections::{HashMap, HashSet};

use super::{Matcher, MatcherSet};

// ===== FullMatcherSet =====

/// 精确全匹配器集合。
///
/// 使用 `HashSet<String>` 存储模式，O(1) 存在性检查。
/// 对应 Go 版本 `strmatcher.FullMatcherSet`。
#[derive(Debug, Clone, Default)]
pub struct FullMatcherSet {
  patterns: HashSet<String>,
}

impl FullMatcherSet {
  /// 创建新的精确全匹配器集合。
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// 添加匹配模式。
  pub fn add(&mut self, pattern: impl Into<String>) {
    self.patterns.insert(pattern.into());
  }
}

impl MatcherSet for FullMatcherSet {
  fn match_any(&self, input: &str) -> bool {
    self.patterns.contains(input)
  }
}

impl std::fmt::Display for FullMatcherSet {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "full_set:{}", self.patterns.len())
  }
}

// ===== DomainMatcherSet =====

/// 域名字典树节点。
#[derive(Debug, Clone, Default)]
struct TrieNode {
  /// 当前节点是否为匹配终点
  matched: bool,
  /// 子标签到子节点的映射
  children: HashMap<String, TrieNode>,
}

/// 域名后缀匹配器集合。
///
/// 使用字典树按域名标签逆序组织，仅做存在性检查。
/// 对应 Go 版本 `strmatcher.DomainMatcherSet`。
#[derive(Debug, Clone, Default)]
pub struct DomainMatcherSet {
  root: TrieNode,
}

impl DomainMatcherSet {
  /// 创建新的域名后缀匹配器集合。
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// 添加域名匹配模式。
  ///
  /// 域名按 `.` 分隔后逆序插入字典树。
  pub fn add(&mut self, pattern: impl Into<String>) {
    let pattern = pattern.into();
    let labels: Vec<&str> = pattern.split('.').rev().collect();
    let mut node = &mut self.root;
    for label in &labels {
      node = node
        .children
        .entry((*label).to_owned())
        .or_default();
    }
    node.matched = true;
  }
}

impl MatcherSet for DomainMatcherSet {
  fn match_any(&self, input: &str) -> bool {
    let labels: Vec<&str> = input.split('.').rev().collect();
    let mut node = &self.root;

    // 根节点匹配表示空模式
    if node.matched {
      return true;
    }

    for label in &labels {
      if label.is_empty() {
        return false;
      }
      match node.children.get(*label) {
        Some(child) => {
          node = child;
          if node.matched {
            return true;
          }
        }
        None => return false,
      }
    }
    false
  }
}

impl std::fmt::Display for DomainMatcherSet {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // 统计字典树中的匹配节点数
    fn count_matched(node: &TrieNode) -> usize {
      let mut count = if node.matched { 1 } else { 0 };
      for child in node.children.values() {
        count += count_matched(child);
      }
      count
    }
    write!(f, "domain_set:{}", count_matched(&self.root))
  }
}

// ===== SubstrMatcherSet =====

/// 子串匹配器集合。
///
/// 使用 `Vec<String>` 存储，线性扫描 `input.contains()`。
/// 对应 Go 版本 `strmatcher.SubstrMatcherSet`。
#[derive(Debug, Clone, Default)]
pub struct SubstrMatcherSet {
  patterns: Vec<String>,
}

impl SubstrMatcherSet {
  /// 创建新的子串匹配器集合。
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// 添加子串匹配模式。
  pub fn add(&mut self, pattern: impl Into<String>) {
    self.patterns.push(pattern.into());
  }
}

impl MatcherSet for SubstrMatcherSet {
  fn match_any(&self, input: &str) -> bool {
    self.patterns.iter().any(|p| input.contains(p))
  }
}

impl std::fmt::Display for SubstrMatcherSet {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "substr_set:{}", self.patterns.len())
  }
}

// ===== SimpleMatcherSet =====

/// 简单线性扫描匹配器集合。
///
/// 使用 `Vec<Box<dyn Matcher>>` 存储，线性扫描逐个检查。
/// 支持所有类型的匹配器，对应 Go 版本 `strmatcher.SimpleMatcherSet`。
pub struct SimpleMatcherSet {
  matchers: Vec<Box<dyn Matcher>>,
}

impl SimpleMatcherSet {
  /// 创建新的简单匹配器集合。
  #[must_use]
  pub fn new() -> Self {
    Self {
      matchers: Vec::new(),
    }
  }

  /// 添加任意类型的匹配器。
  pub fn add(&mut self, matcher: Box<dyn Matcher>) {
    self.matchers.push(matcher);
  }
}

impl Default for SimpleMatcherSet {
  fn default() -> Self {
    Self::new()
  }
}

impl MatcherSet for SimpleMatcherSet {
  fn match_any(&self, input: &str) -> bool {
    self.matchers.iter().any(|m| m.match_str(input))
  }
}

impl std::fmt::Debug for SimpleMatcherSet {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("SimpleMatcherSet")
      .field("count", &self.matchers.len())
      .finish()
  }
}

impl std::fmt::Display for SimpleMatcherSet {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "simple_set:{}", self.matchers.len())
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

  // ----- FullMatcherSet 测试 -----

  #[test]
  fn test_full_set_basic_match() {
    let mut set = FullMatcherSet::new();
    set.add("example.com");
    assert!(set.match_any("example.com"));
  }

  #[test]
  fn test_full_set_no_match() {
    let mut set = FullMatcherSet::new();
    set.add("example.com");
    assert!(!set.match_any("other.com"));
  }

  #[test]
  fn test_full_set_empty() {
    let set = FullMatcherSet::new();
    assert!(!set.match_any("anything.com"));
  }

  #[test]
  fn test_full_set_multiple_patterns() {
    let mut set = FullMatcherSet::new();
    set.add("a.com");
    set.add("b.org");
    set.add("c.net");
    assert!(set.match_any("a.com"));
    assert!(set.match_any("b.org"));
    assert!(set.match_any("c.net"));
    assert!(!set.match_any("d.io"));
  }

  #[test]
  fn test_full_set_duplicate_pattern() {
    let mut set = FullMatcherSet::new();
    set.add("example.com");
    set.add("example.com");
    assert!(set.match_any("example.com"));
  }

  #[test]
  fn test_full_set_display() {
    let mut set = FullMatcherSet::new();
    set.add("a.com");
    set.add("b.com");
    assert_eq!(format!("{}", set), "full_set:2");
  }

  // ----- DomainMatcherSet 测试 -----

  #[test]
  fn test_domain_set_exact_match() {
    let mut set = DomainMatcherSet::new();
    set.add("example.com");
    assert!(set.match_any("example.com"));
  }

  #[test]
  fn test_domain_set_subdomain() {
    let mut set = DomainMatcherSet::new();
    set.add("example.com");
    assert!(set.match_any("sub.example.com"));
    assert!(set.match_any("a.b.example.com"));
  }

  #[test]
  fn test_domain_set_no_boundary() {
    let mut set = DomainMatcherSet::new();
    set.add("example.com");
    assert!(!set.match_any("notexample.com"));
  }

  #[test]
  fn test_domain_set_no_match() {
    let mut set = DomainMatcherSet::new();
    set.add("example.com");
    assert!(!set.match_any("other.org"));
  }

  #[test]
  fn test_domain_set_empty() {
    let set = DomainMatcherSet::new();
    assert!(!set.match_any("anything.com"));
  }

  #[test]
  fn test_domain_set_multiple_domains() {
    let mut set = DomainMatcherSet::new();
    set.add("example.com");
    set.add("test.org");
    assert!(set.match_any("sub.example.com"));
    assert!(set.match_any("test.org"));
    assert!(!set.match_any("other.net"));
  }

  // ----- SubstrMatcherSet 测试 -----

  #[test]
  fn test_substr_set_basic_match() {
    let mut set = SubstrMatcherSet::new();
    set.add("evil");
    assert!(set.match_any("evil.com"));
    assert!(set.match_any("not-evil-site.com"));
  }

  #[test]
  fn test_substr_set_no_match() {
    let mut set = SubstrMatcherSet::new();
    set.add("evil");
    assert!(!set.match_any("good.com"));
  }

  #[test]
  fn test_substr_set_empty() {
    let set = SubstrMatcherSet::new();
    assert!(!set.match_any("anything.com"));
  }

  #[test]
  fn test_substr_set_multiple_patterns() {
    let mut set = SubstrMatcherSet::new();
    set.add("evil");
    set.add("bad");
    assert!(set.match_any("evil.com"));
    assert!(set.match_any("bad-site.com"));
    assert!(!set.match_any("good.com"));
  }

  // ----- SimpleMatcherSet 测试 -----

  #[test]
  fn test_simple_set_full_matcher() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(FullMatcher::new("example.com")));
    assert!(set.match_any("example.com"));
    assert!(!set.match_any("other.com"));
  }

  #[test]
  fn test_simple_set_domain_matcher() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(DomainMatcherImpl::new("example.com")));
    assert!(set.match_any("sub.example.com"));
  }

  #[test]
  fn test_simple_set_substr_matcher() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(SubstrMatcher::new("evil")));
    assert!(set.match_any("evil.com"));
  }

  #[test]
  fn test_simple_set_regex_matcher() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(
      RegexMatcher::new(r"evil\..*").unwrap(),
    ));
    assert!(set.match_any("evil.com"));
    assert!(!set.match_any("good.com"));
  }

  #[test]
  fn test_simple_set_mixed_matchers() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(FullMatcher::new("exact.com")));
    set.add(Box::new(DomainMatcherImpl::new("domain.com")));
    set.add(Box::new(SubstrMatcher::new("keyword")));
    assert!(set.match_any("exact.com"));
    assert!(set.match_any("sub.domain.com"));
    assert!(set.match_any("keyword-site.com"));
    assert!(!set.match_any("other.org"));
  }

  #[test]
  fn test_simple_set_empty() {
    let set = SimpleMatcherSet::new();
    assert!(!set.match_any("anything.com"));
  }

  #[test]
  fn test_simple_set_display() {
    let mut set = SimpleMatcherSet::new();
    set.add(Box::new(FullMatcher::new("a.com")));
    set.add(Box::new(FullMatcher::new("b.com")));
    assert_eq!(format!("{}", set), "simple_set:2");
  }
}
