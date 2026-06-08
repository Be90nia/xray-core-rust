//! 6种 MatcherGroup 变体实现
//!
//! 对应 Go 版本 `common/geodata/strmatcher/` 目录下的匹配器组，
//! 提供批量匹配能力，使用优化的数据结构加速查找。
//!
//! # 匹配器组类型
//!
//! - [`FullMatcherGroup`] - 哈希表精确匹配
//! - [`DomainMatcherGroup`] - 字典树域名后缀匹配
//! - [`SimpleMatcherGroup`] - 线性扫描（支持所有匹配器类型）
//! - [`SubstrMatcherGroup`] - 子串搜索（位置优先排序）
//! - [`ACMatcherGroup`] - Aho-Corasick 自动机多模式匹配
//! - [`MPHMatcherGroup`] - 最小完美哈希查找

use std::collections::HashMap;

use aho_corasick::AhoCorasick;

use super::{DomainMatcher, FullMatcher, Matcher, MatcherGroup, MatcherType};

// ===== FullMatcherGroup =====

/// 精确全匹配器组。
///
/// 使用 `HashMap<String, Vec<u16>>` 加速精确匹配查找。
/// 对应 Go 版本 `strmatcher.FullMatcherGroup`。
#[derive(Debug, Clone)]
pub struct FullMatcherGroup {
    matchers: HashMap<String, Vec<u16>>,
}

impl FullMatcherGroup {
    /// 创建新的精确全匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self {
            matchers: HashMap::new(),
        }
    }

    /// 添加精确匹配规则。
    ///
    /// 同一模式可添加多个值，按添加顺序保留。
    pub fn add(&mut self, matcher: FullMatcher, value: u16) {
        self.matchers
            .entry(matcher.pattern().to_owned())
            .or_default()
            .push(value);
    }
}

impl Default for FullMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherGroup for FullMatcherGroup {
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16> {
        self.matchers.get(input).cloned().unwrap_or_default()
    }

    #[must_use]
    fn match_any(&self, input: &str) -> bool {
        self.matchers.contains_key(input)
    }
}

// ===== DomainMatcherGroup =====

/// 域名字典树节点。
#[derive(Debug, Clone, Default)]
struct DomainTrieNode {
    values: Vec<u16>,
    children: HashMap<String, DomainTrieNode>,
}

/// 域名后缀匹配器组。
///
/// 使用字典树按域名标签逆序组织，支持域名后缀匹配。
/// 匹配结果按层级从深到浅（最远匹配优先）排列。
///
/// 对应 Go 版本 `strmatcher.DomainMatcherGroup`。
#[derive(Debug, Clone, Default)]
pub struct DomainMatcherGroup {
    root: DomainTrieNode,
}

impl DomainMatcherGroup {
    /// 创建新的域名后缀匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: DomainTrieNode::default(),
        }
    }

    /// 添加域名匹配规则。
    ///
    /// 域名按 `.` 分隔后逆序插入字典树。
    pub fn add(&mut self, matcher: DomainMatcher, value: u16) {
        let labels: Vec<&str> = matcher.pattern().split('.').rev().collect();
        let mut node = &mut self.root;
        for label in &labels {
            node = node
                .children
                .entry((*label).to_owned())
                .or_default();
        }
        node.values.push(value);
    }
}

impl MatcherGroup for DomainMatcherGroup {
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16> {
        let labels: Vec<&str> = input.split('.').rev().collect();
        let mut node = &self.root;
        let mut matches: Vec<Vec<u16>> = Vec::new();

        if !node.values.is_empty() {
            matches.push(node.values.clone());
        }

        for label in &labels {
            if label.is_empty() {
                return matches.into_iter().flatten().collect();
            }
            match node.children.get(*label) {
                Some(child) => {
                    node = child;
                    if !node.values.is_empty() {
                        matches.push(node.values.clone());
                    }
                }
                None => break,
            }
        }

        // 逆序扁平化：最远匹配优先
        matches.into_iter().rev().flatten().collect()
    }

    #[must_use]
    fn match_any(&self, input: &str) -> bool {
        let labels: Vec<&str> = input.split('.').rev().collect();
        let mut node = &self.root;

        if !node.values.is_empty() {
            return true;
        }

        for label in &labels {
            if label.is_empty() {
                return false;
            }
            match node.children.get(*label) {
                Some(child) => {
                    node = child;
                    if !node.values.is_empty() {
                        return true;
                    }
                }
                None => return false,
            }
        }
        false
    }
}

// ===== SimpleMatcherGroup =====

/// 匹配器条目。
struct SimpleMatcherEntry {
    matcher: Box<dyn Matcher>,
    value: u16,
}

/// 简单线性扫描匹配器组。
///
/// 支持所有类型的匹配器，通过线性扫描逐个检查。
/// 对应 Go 版本 `strmatcher.SimpleMatcherGroup`。
pub struct SimpleMatcherGroup {
    entries: Vec<SimpleMatcherEntry>,
}

impl SimpleMatcherGroup {
    /// 创建新的简单匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 添加任意类型的匹配器。
    pub fn add(&mut self, matcher: Box<dyn Matcher>, value: u16) {
        self.entries.push(SimpleMatcherEntry { matcher, value });
    }
}

impl Default for SimpleMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherGroup for SimpleMatcherGroup {
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16> {
        self.entries
            .iter()
            .filter(|e| e.matcher.match_str(input))
            .map(|e| e.value)
            .collect()
    }

    #[must_use]
    fn match_any(&self, input: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.matcher.match_str(input))
    }
}

impl std::fmt::Debug for SimpleMatcherGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleMatcherGroup")
            .field("count", &self.entries.len())
            .finish()
    }
}

// ===== SubstrMatcherGroup =====

/// 子串匹配条目。
#[derive(Debug, Clone)]
struct SubstrMatcherEntry {
    pattern: String,
    value: u16,
}

/// 子串搜索匹配器组。
///
/// 查找每个模式在输入中的最后出现位置，按位置从远到近排序返回。
/// 同一位置按添加顺序排列。
///
/// 对应 Go 版本 `strmatcher.SubstrMatcherGroup`。
#[derive(Debug, Clone, Default)]
pub struct SubstrMatcherGroup {
    entries: Vec<SubstrMatcherEntry>,
}

impl SubstrMatcherGroup {
    /// 创建新的子串匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 添加子串匹配规则。
    pub fn add(&mut self, pattern: impl Into<String>, value: u16) {
        self.entries.push(SubstrMatcherEntry {
            pattern: pattern.into(),
            value,
        });
    }
}

impl MatcherGroup for SubstrMatcherGroup {
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16> {
        // 对每个模式，找到其在输入中的最后出现位置
        let mut positioned: Vec<(usize, usize, u16)> = Vec::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            if let Some(pos) = input.rfind(&entry.pattern) {
                positioned.push((pos, idx, entry.value));
            }
        }

        // 按位置降序（更远匹配优先），同位置按 pattern_idx 升序
        positioned.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        positioned.into_iter().map(|(_, _, v)| v).collect()
    }

    #[must_use]
    fn match_any(&self, input: &str) -> bool {
        self.entries
            .iter()
            .any(|e| input.contains(&e.pattern))
    }
}

// ===== ACMatcherGroup =====

/// AC 自动机匹配规则类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ACMatchKind {
    Full,
    Domain,
    Substr,
}

/// AC 自动机匹配条目。
#[derive(Debug, Clone)]
struct ACMatcherEntry {
    value: u16,
    kind: ACMatchKind,
}

/// Aho-Corasick 自动机匹配器组。
///
/// 使用 Aho-Corasick 算法进行多模式匹配，支持 Full、Domain 和 Substr
/// 三种匹配类型。Domain 类型模式会自动添加 `.` 前缀以匹配子域名边界。
///
/// 对应 Go 版本 `strmatcher.ACAutomatonMatcherGroup`。
pub struct ACMatcherGroup {
    patterns: Vec<String>,
    entries: Vec<ACMatcherEntry>,
    ac: Option<AhoCorasick>,
}

impl ACMatcherGroup {
    /// 创建新的 AC 自动机匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            entries: Vec::new(),
            ac: None,
        }
    }

    /// 添加匹配规则。
    pub fn add(&mut self, matcher: impl Matcher, value: u16) {
        let kind = match matcher.matcher_type() {
            MatcherType::Full => ACMatchKind::Full,
            MatcherType::Domain => ACMatchKind::Domain,
            MatcherType::Substr => ACMatchKind::Substr,
            MatcherType::Regex => ACMatchKind::Substr,
        };

        let pattern = matcher.pattern().to_owned();
        self.entries.push(ACMatcherEntry { value, kind });
        self.patterns.push(pattern);
    }

    /// 构建 Aho-Corasick 自动机。
    ///
    /// 必须在添加所有模式后、使用 `match_str` 之前调用。
    /// Domain 类型模式会添加 `.` 前缀。
    pub fn build(&mut self) -> Result<(), ACMatcherGroupError> {
        let ac_patterns: Vec<String> = self
            .entries
            .iter()
            .zip(self.patterns.iter())
            .map(|(entry, pattern)| match entry.kind {
                ACMatchKind::Domain => format!(".{pattern}"),
                _ => pattern.clone(),
            })
            .collect();

        if ac_patterns.is_empty() {
            self.ac = Some(
                AhoCorasick::new(&[""])
                    .map_err(|e| ACMatcherGroupError::BuildFailed(e.to_string()))?,
            );
            return Ok(());
        }

        let ac = AhoCorasick::builder()
            .kind(aho_corasick::AhoCorasickKind::DFA)
            .build(&ac_patterns)
            .map_err(|e| ACMatcherGroupError::BuildFailed(e.to_string()))?;

        self.ac = Some(ac);
        Ok(())
    }
}

/// AC 自动机匹配器组错误类型。
#[derive(Debug, thiserror::Error)]
pub enum ACMatcherGroupError {
    /// 自动机构建失败
    #[error("AC\u{81ea}\u{52a8}\u{673a}\u{6784}\u{5efa}\u{5931}\u{8d25}: {0}")]
    BuildFailed(String),

    /// 自动机未构建
    #[error("AC\u{81ea}\u{52a8}\u{673a}\u{672a}\u{6784}\u{5efa}\u{ff0c}\u{8bf7}\u{5148}\u{8c03}\u{7528} build()")]
    NotBuilt,
}

impl MatcherGroup for ACMatcherGroup {
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16> {
        let ac = match &self.ac {
            Some(ac) => ac,
            None => return Vec::new(),
        };

        let mut full_matches: Vec<(usize, u16)> = Vec::new();
        let mut domain_matches: Vec<(usize, u16)> = Vec::new();
        let mut substr_matches: Vec<(usize, u16)> = Vec::new();

        for mat in ac.find_iter(input) {
            let idx = mat.pattern().as_usize();
            if idx >= self.entries.len() {
                continue;
            }
            let entry = &self.entries[idx];
            let end_pos = mat.end();

            match entry.kind {
                ACMatchKind::Full => {
                    if input == self.patterns[idx] {
                        full_matches.push((end_pos, entry.value));
                    }
                }
                ACMatchKind::Domain => {
                    let pattern = &self.patterns[idx];
                    if input == pattern {
                        domain_matches.push((end_pos, entry.value));
                    } else if input.ends_with(pattern) {
                        let prefix_pos = input.len() - pattern.len();
                        if prefix_pos > 0
                            && input.as_bytes()[prefix_pos - 1] == b'.'
                        {
                            domain_matches.push((end_pos, entry.value));
                        }
                    }
                }
                ACMatchKind::Substr => {
                    substr_matches.push((end_pos, entry.value));
                }
            }
        }

        // 排序：按 end_pos 降序，同位置 Full > Domain > Substr
        let mut all_matches: Vec<(usize, u8, u16)> = Vec::new();
        for (pos, val) in full_matches {
            all_matches.push((pos, 0, val));
        }
        for (pos, val) in domain_matches {
            all_matches.push((pos, 1, val));
        }
        for (pos, val) in substr_matches {
            all_matches.push((pos, 2, val));
        }

        all_matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        all_matches.into_iter().map(|(_, _, v)| v).collect()
    }

    #[must_use]
    fn match_any(&self, input: &str) -> bool {
        let ac = match &self.ac {
            Some(ac) => ac,
            None => return false,
        };

        for mat in ac.find_iter(input) {
            let idx = mat.pattern().as_usize();
            if idx >= self.entries.len() {
                continue;
            }
            let entry = &self.entries[idx];

            match entry.kind {
                ACMatchKind::Full => {
                    if input == self.patterns[idx] {
                        return true;
                    }
                }
                ACMatchKind::Domain => {
                    let pattern = &self.patterns[idx];
                    if input == pattern {
                        return true;
                    }
                    if input.ends_with(pattern) {
                        let prefix_pos = input.len() - pattern.len();
                        if prefix_pos > 0
                            && input.as_bytes()[prefix_pos - 1] == b'.'
                        {
                            return true;
                        }
                    }
                }
                ACMatchKind::Substr => {
                    return true;
                }
            }
        }
        false
    }
}

impl std::fmt::Debug for ACMatcherGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ACMatcherGroup")
            .field("pattern_count", &self.patterns.len())
            .field("built", &self.ac.is_some())
            .finish()
    }
}

impl Default for ACMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}
