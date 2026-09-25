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

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use aho_corasick::AhoCorasick;

use super::{DomainMatcher, FullMatcher, Matcher, MatcherGroup, MatcherType};

// ===== FullMatcherGroup =====

/// 精确全匹配器组。
///
/// 使用 `HashMap<String, Vec<u32>>` 加速精确匹配查找。
/// 对应 Go 版本 `strmatcher.FullMatcherGroup`。
#[derive(Debug, Clone)]
pub struct FullMatcherGroup {
    matchers: HashMap<String, Vec<u32>>,
}

impl FullMatcherGroup {
    /// 创建新的精确全匹配器组。
    #[must_use]
    pub fn new() -> Self {
        Self { matchers: HashMap::new() }
    }

    /// 添加精确匹配规则。
    ///
    /// 同一模式可添加多个值，按添加顺序保留。
    pub fn add(&mut self, matcher: FullMatcher, value: u32) {
        self.matchers.entry(matcher.pattern().to_owned()).or_default().push(value);
    }
}

impl Default for FullMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherGroup for FullMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        self.matchers.get(input).cloned().unwrap_or_default()
    }

    fn match_any(&self, input: &str) -> bool {
        self.matchers.contains_key(input)
    }
}

// ===== DomainMatcherGroup =====

/// 域名字典树节点。
#[derive(Debug, Clone, Default)]
struct DomainTrieNode {
    values: Vec<u32>,
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
        Self { root: DomainTrieNode::default() }
    }

    /// 添加域名匹配规则。
    ///
    /// 域名按 `.` 分隔后逆序插入字典树。
    pub fn add(&mut self, matcher: DomainMatcher, value: u32) {
        let labels: Vec<&str> = matcher.pattern().split('.').rev().collect();
        let mut node = &mut self.root;
        for label in &labels {
            node = node.children.entry((*label).to_owned()).or_default();
        }
        node.values.push(value);
    }
}

impl MatcherGroup for DomainMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        let labels: Vec<&str> = input.split('.').rev().collect();
        let mut node = &self.root;
        let mut matches: Vec<Vec<u32>> = Vec::new();

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
                },
                None => break,
            }
        }

        // 逆序扁平化：最远匹配优先
        matches.into_iter().rev().flatten().collect()
    }

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
                },
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
    value: u32,
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
        Self { entries: Vec::new() }
    }

    /// 添加任意类型的匹配器。
    pub fn add(&mut self, matcher: Box<dyn Matcher>, value: u32) {
        self.entries.push(SimpleMatcherEntry { matcher, value });
    }
}

impl Default for SimpleMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherGroup for SimpleMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        self.entries.iter().filter(|e| e.matcher.match_str(input)).map(|e| e.value).collect()
    }

    fn match_any(&self, input: &str) -> bool {
        self.entries.iter().any(|e| e.matcher.match_str(input))
    }
}

impl std::fmt::Debug for SimpleMatcherGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleMatcherGroup").field("count", &self.entries.len()).finish()
    }
}

// ===== SubstrMatcherGroup =====

/// 子串匹配条目。
#[derive(Debug, Clone)]
struct SubstrMatcherEntry {
    pattern: String,
    value: u32,
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
        Self { entries: Vec::new() }
    }

    /// 添加子串匹配规则。
    pub fn add(&mut self, pattern: impl Into<String>, value: u32) {
        self.entries.push(SubstrMatcherEntry { pattern: pattern.into(), value });
    }
}

impl MatcherGroup for SubstrMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        // 对每个模式，找到其在输入中的最后出现位置
        let mut positioned: Vec<(usize, usize, u32)> = Vec::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            if let Some(pos) = input.rfind(&entry.pattern) {
                positioned.push((pos, idx, entry.value));
            }
        }

        // 按位置降序（更远匹配优先），同位置按 pattern_idx 升序
        positioned.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        positioned.into_iter().map(|(_, _, v)| v).collect()
    }

    fn match_any(&self, input: &str) -> bool {
        self.entries.iter().any(|e| input.contains(&e.pattern))
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
    value: u32,
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
        Self { patterns: Vec::new(), entries: Vec::new(), ac: None }
    }

    /// 添加匹配规则。
    pub fn add(&mut self, matcher: impl Matcher, value: u32) {
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
            .kind(Some(aho_corasick::AhoCorasickKind::DFA))
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
    #[error(
        "AC\u{81ea}\u{52a8}\u{673a}\u{672a}\u{6784}\u{5efa}\u{ff0c}\u{8bf7}\u{5148}\u{8c03}\u{7528} build()"
    )]
    NotBuilt,
}

impl MatcherGroup for ACMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        let ac = match &self.ac {
            Some(ac) => ac,
            None => return Vec::new(),
        };

        let mut full_matches: Vec<(usize, u32)> = Vec::new();
        let mut domain_matches: Vec<(usize, u32)> = Vec::new();
        let mut substr_matches: Vec<(usize, u32)> = Vec::new();

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
                },
                ACMatchKind::Domain => {
                    let pattern = &self.patterns[idx];
                    if input == pattern {
                        domain_matches.push((end_pos, entry.value));
                    } else if input.ends_with(pattern) {
                        let prefix_pos = input.len() - pattern.len();
                        if prefix_pos > 0 && input.as_bytes()[prefix_pos - 1] == b'.' {
                            domain_matches.push((end_pos, entry.value));
                        }
                    }
                },
                ACMatchKind::Substr => {
                    substr_matches.push((end_pos, entry.value));
                },
            }
        }

        // 排序：按 end_pos 降序，同位置 Full > Domain > Substr
        let mut all_matches: Vec<(usize, u8, u32)> = Vec::new();
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
                },
                ACMatchKind::Domain => {
                    let pattern = &self.patterns[idx];
                    if input == pattern {
                        return true;
                    }
                    if input.ends_with(pattern) {
                        let prefix_pos = input.len() - pattern.len();
                        if prefix_pos > 0 && input.as_bytes()[prefix_pos - 1] == b'.' {
                            return true;
                        }
                    }
                },
                ACMatchKind::Substr => {
                    return true;
                },
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

// ===== MPHMatcherGroup =====

/// Rabin-Karp 算法使用的素数基数。
const PRIME_RK: u32 = 16777619;

/// MPH 匹配类型数量（Full 和 Domain）。
const MPH_MATCH_TYPE_COUNT: usize = 2;

/// MPH 规则信息（仅构建阶段使用）。
#[derive(Debug, Clone)]
struct MphRuleInfo {
    rolling_hash: u32,
    matchers: [Vec<u32>; MPH_MATCH_TYPE_COUNT],
}

/// 计算滚动 Rabin-Karp 哈希。
///
/// 从输入字符串末尾向前扫描，基于给定的后缀哈希值递推计算。
/// 对应 Go 版本 `RollingHash`。
#[must_use]
fn rolling_hash(suffix_hash: u32, input: &str) -> u32 {
    let mut hash = suffix_hash;
    for byte in input.bytes().rev() {
        hash = hash.wrapping_mul(PRIME_RK).wrapping_add(u32::from(byte));
    }
    hash
}

/// 带种子的哈希函数。
///
/// 使用标准库哈希器，将种子与输入组合产生不同哈希值。
/// 对应 Go 版本 `MemHash`。
#[must_use]
fn seeded_hash(seed: u32, input: &str) -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    input.hash(&mut hasher);
    hasher.finish() as u32
}

/// 计算大于等于 `v` 的最小 2 的幂。
#[must_use]
fn next_pow2(v: usize) -> usize {
    if v <= 1 {
        return 1;
    }
    1usize << (usize::BITS - (v - 1).leading_zeros())
}

/// 最小完美哈希匹配器组。
///
/// 使用 Rabin-Karp 滚动哈希和 Hash-Displace-Compress 算法构建
/// 最小完美哈希表，支持 Full 和 Domain 两种匹配类型。
///
/// 适用于静态规则集（构建后不变），查询时间 O(1)。
/// 对应 Go 版本 `strmatcher.MphMatcherGroup`。
///
/// # 算法
///
/// 1. **Level 0**: 按 Rabin-Karp 滚动哈希分桶
/// 2. **Level 1**: 每个桶内使用带种子的哈希函数，通过 Hash-Displace-Compress 算法找到无冲突的种子
/// 3. **查询**: 两级哈希定位 + 字符串验证
///
/// # 参考
///
/// <http://cmph.sourceforge.net/papers/esa09.pdf>
pub struct MPHMatcherGroup {
    rules: Vec<String>,
    values: Vec<Vec<u32>>,
    level0: Vec<u32>,
    level0_mask: u32,
    level1: Vec<u32>,
    level1_mask: u32,
    rule_infos: Option<HashMap<String, MphRuleInfo>>,
}

/// MPH 匹配器组错误类型。
#[derive(Debug, thiserror::Error)]
pub enum MPHMatcherGroupError {
    /// 哈希表构建失败
    #[error("MPH\u{54c8}\u{5e0c}\u{8868}\u{6784}\u{5efa}\u{5931}\u{8d25}: {0}")]
    BuildFailed(String),

    /// 哈希表未构建
    #[error(
        "MPH\u{54c8}\u{5e0c}\u{8868}\u{672a}\u{6784}\u{5efa}\u{ff0c}\u{8bf7}\u{5148}\u{8c03}\u{7528} build()"
    )]
    NotBuilt,

    /// 规则为空
    #[error(
        "\u{6ca1}\u{6709}\u{6dfb}\u{52a0}\u{4efb}\u{4f55}\u{89c4}\u{5219}\u{ff0c}\u{65e0}\u{6cd5}\u{6784}\u{5efa} MPH \u{54c8}\u{5e0c}\u{8868}"
    )]
    Empty,
}

impl MPHMatcherGroup {
    /// 创建新的最小完美哈希匹配器组。
    ///
    /// 索引 0 保留用于查找失败标记。
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: vec![String::new()],
            values: vec![Vec::new()],
            level0: Vec::new(),
            level0_mask: 0,
            level1: Vec::new(),
            level1_mask: 0,
            rule_infos: Some(HashMap::new()),
        }
    }

    /// 添加精确全匹配规则。
    ///
    /// 模式会被转为小写存储。
    pub fn add_full_matcher(&mut self, pattern: &str, value: u32) {
        let pattern = pattern.to_lowercase();
        self.add_pattern(0, "", &pattern, MatcherType::Full, value);
    }

    /// 添加域名后缀匹配规则。
    ///
    /// 会自动添加两条规则：
    /// - 完整域名匹配（如 `example.com`）
    /// - 子域名匹配（如 `.example.com`）
    pub fn add_domain_matcher(&mut self, pattern: &str, value: u32) {
        let pattern = pattern.to_lowercase();
        let hash = self.add_pattern(0, "", &pattern, MatcherType::Domain, value);
        self.add_pattern(hash, &pattern, ".", MatcherType::Domain, value);
    }

    /// 内部方法：添加模式到规则信息表。
    ///
    /// 返回该模式的滚动哈希值。
    fn add_pattern(
        &mut self,
        suffix_hash: u32,
        suffix_pattern: &str,
        pattern: &str,
        matcher_type: MatcherType,
        value: u32,
    ) -> u32 {
        let full_pattern = format!("{pattern}{suffix_pattern}");
        let rule_infos = self
            .rule_infos
            .as_mut()
            .expect("rule_infos \u{5e94}\u{5728}\u{6784}\u{5efa}\u{524d}\u{53ef}\u{7528}");

        let type_idx = match matcher_type {
            MatcherType::Full => 0,
            MatcherType::Domain => 1,
            _ => 0,
        };

        match rule_infos.get_mut(&full_pattern) {
            Some(info) => {
                info.matchers[type_idx].push(value);
                info.rolling_hash
            },
            None => {
                let rh = rolling_hash(suffix_hash, pattern);
                self.rules.push(full_pattern.clone());
                self.values.push(Vec::new());

                let mut info = MphRuleInfo { rolling_hash: rh, matchers: [Vec::new(), Vec::new()] };
                info.matchers[type_idx].push(value);
                rule_infos.insert(full_pattern, info);
                rh
            },
        }
    }

    /// 构建最小完美哈希表。
    ///
    /// 使用 Hash-Displace-Compress 算法。
    /// 构建完成后 `rule_infos` 会被释放以节省内存。
    ///
    /// # 错误
    ///
    /// - 没有添加任何规则时返回 `Empty` 错误
    pub fn build(&mut self) -> Result<(), MPHMatcherGroupError> {
        let rule_infos = self.rule_infos.take().ok_or_else(|| {
            MPHMatcherGroupError::BuildFailed("rule_infos \u{5df2}\u{88ab}\u{6d88}\u{8d39}".into())
        })?;

        let rule_count = rule_infos.len();
        if rule_count == 0 {
            self.rule_infos = Some(rule_infos);
            return Err(MPHMatcherGroupError::Empty);
        }

        // 初始化两级哈希表
        let level0_size = next_pow2(rule_count / 4).max(1);
        self.level0 = vec![0u32; level0_size];
        self.level0_mask = (level0_size as u32).wrapping_sub(1);

        let level1_size = next_pow2(rule_count);
        self.level1 = vec![0u32; level1_size];
        self.level1_mask = (level1_size as u32).wrapping_sub(1);

        // 按滚动哈希分桶
        let mut buckets: Vec<Vec<u32>> = vec![Vec::new(); level0_size];
        for rule_idx in 1..self.rules.len() {
            let rule = &self.rules[rule_idx];
            let info = rule_infos.get(rule).ok_or_else(|| {
                MPHMatcherGroupError::BuildFailed(format!(
                    "\u{89c4}\u{5219} {rule_idx} \u{672a}\u{5728} rule_infos \u{4e2d}\u{627e}\u{5230}"
                ))
            })?;
            let bucket_idx = (info.rolling_hash & self.level0_mask) as usize;
            buckets[bucket_idx].push(rule_idx as u32);

            // 合并 Full 和 Domain 的值（Full 优先）
            let mut combined = info.matchers[0].clone();
            combined.extend_from_slice(&info.matchers[1]);
            self.values[rule_idx] = combined;
        }

        // rule_infos 已不再需要，释放内存
        drop(rule_infos);

        // 按桶大小降序排列桶索引
        let mut bucket_indices: Vec<usize> = (0..buckets.len()).collect();
        bucket_indices.sort_by(|&a, &b| buckets[b].len().cmp(&buckets[a].len()));

        // Hash-Displace-Compress 算法
        let mut occupied = vec![false; level1_size];
        let mut hashed_bucket: Vec<u32> = Vec::with_capacity(4);

        for bucket_idx in bucket_indices {
            let bucket = &buckets[bucket_idx];
            hashed_bucket.clear();
            let mut seed: u32 = 0;

            while hashed_bucket.len() != bucket.len() {
                for &rule_idx in bucket {
                    let mem_hash =
                        seeded_hash(seed, &self.rules[rule_idx as usize]) & self.level1_mask;
                    let mem_hash_usize = mem_hash as usize;

                    if occupied[mem_hash_usize] {
                        // 冲突：回滚当前桶的所有哈希
                        for &hash in &hashed_bucket {
                            occupied[hash as usize] = false;
                            self.level1[hash as usize] = 0;
                        }
                        hashed_bucket.clear();
                        seed += 1;
                        break;
                    }

                    occupied[mem_hash_usize] = true;
                    self.level1[mem_hash_usize] = rule_idx;
                    hashed_bucket.push(mem_hash);
                }
            }

            self.level0[bucket_idx] = seed;
        }

        Ok(())
    }

    /// 在最小完美哈希表中查找输入字符串。
    ///
    /// 返回规则索引（0 表示未找到）。
    #[must_use]
    fn lookup(&self, rolling_hash: u32, input: &str) -> u32 {
        let i0 = (rolling_hash & self.level0_mask) as usize;
        let seed = self.level0[i0];
        let i1 = (seeded_hash(seed, input) & self.level1_mask) as usize;
        let rule_idx = self.level1[i1];
        if rule_idx as usize >= self.rules.len() {
            return 0;
        }
        if self.rules[rule_idx as usize] == input { rule_idx } else { 0 }
    }

    /// 检查哈希表是否已构建。
    #[must_use]
    pub fn is_built(&self) -> bool {
        self.rule_infos.is_none() && !self.level0.is_empty()
    }
}

impl Default for MPHMatcherGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherGroup for MPHMatcherGroup {
    fn match_str(&self, input: &str) -> Vec<u32> {
        if !self.is_built() {
            return Vec::new();
        }

        let input_lower = input.to_lowercase();
        let mut matches: Vec<Vec<u32>> = Vec::with_capacity(5);
        let mut hash: u32 = 0;

        let bytes = input_lower.as_bytes();
        for i in (0..bytes.len()).rev() {
            hash = hash.wrapping_mul(PRIME_RK).wrapping_add(u32::from(bytes[i]));
            if bytes[i] == b'.' {
                let mph_idx = self.lookup(hash, &input_lower[i..]);
                if mph_idx != 0 {
                    matches.push(self.values[mph_idx as usize].clone());
                }
            }
        }

        // 检查完整输入
        let mph_idx = self.lookup(hash, &input_lower);
        if mph_idx != 0 {
            matches.push(self.values[mph_idx as usize].clone());
        }

        // 逆序扁平化：完整匹配优先
        matches.into_iter().rev().flatten().collect()
    }

    fn match_any(&self, input: &str) -> bool {
        if !self.is_built() {
            return false;
        }

        let input_lower = input.to_lowercase();
        let mut hash: u32 = 0;

        let bytes = input_lower.as_bytes();
        for i in (0..bytes.len()).rev() {
            hash = hash.wrapping_mul(PRIME_RK).wrapping_add(u32::from(bytes[i]));
            if bytes[i] == b'.' && self.lookup(hash, &input_lower[i..]) != 0 {
                return true;
            }
        }

        self.lookup(hash, &input_lower) != 0
    }
}

impl std::fmt::Debug for MPHMatcherGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MPHMatcherGroup")
            .field("rule_count", &(self.rules.len().saturating_sub(1)))
            .field("built", &self.is_built())
            .finish()
    }
}

#[cfg(test)]
mod tests_mph {
    use super::*;

    #[test]
    fn test_mph_full_matcher_basic() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("example.com", 1);
        group.build().unwrap();

        assert_eq!(group.match_str("example.com"), vec![1]);
        assert!(group.match_any("example.com"));
    }

    #[test]
    fn test_mph_full_matcher_case_insensitive() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("Example.COM", 1);
        group.build().unwrap();

        assert_eq!(group.match_str("example.com"), vec![1]);
        assert_eq!(group.match_str("EXAMPLE.COM"), vec![1]);
    }

    #[test]
    fn test_mph_full_matcher_no_match() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("example.com", 1);
        group.build().unwrap();

        assert!(group.match_str("other.com").is_empty());
        assert!(!group.match_any("other.com"));
    }

    #[test]
    fn test_mph_domain_matcher_basic() {
        let mut group = MPHMatcherGroup::new();
        group.add_domain_matcher("example.com", 1);
        group.build().unwrap();

        assert_eq!(group.match_str("example.com"), vec![1]);
        assert_eq!(group.match_str("www.example.com"), vec![1]);
        assert!(group.match_any("sub.example.com"));
    }

    #[test]
    fn test_mph_domain_matcher_no_partial_match() {
        let mut group = MPHMatcherGroup::new();
        group.add_domain_matcher("example.com", 1);
        group.build().unwrap();

        // notexample.com 不应匹配（需要 . 边界）
        assert!(group.match_str("notexample.com").is_empty());
        assert!(!group.match_any("notexample.com"));
    }

    #[test]
    fn test_mph_not_built_returns_empty() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("example.com", 1);
        // 未调用 build()

        assert!(group.match_str("example.com").is_empty());
        assert!(!group.match_any("example.com"));
    }

    #[test]
    fn test_mph_empty_build_error() {
        let mut group = MPHMatcherGroup::new();
        let result = group.build();
        assert!(result.is_err());
        match result {
            Err(MPHMatcherGroupError::Empty) => {},
            _ => panic!("\u{671f}\u{671b} Empty \u{9519}\u{8bef}"),
        }
    }

    #[test]
    fn test_mph_multiple_full_matchers() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("example.com", 1);
        group.add_full_matcher("test.org", 2);
        group.add_full_matcher("demo.net", 3);
        group.build().unwrap();

        assert_eq!(group.match_str("example.com"), vec![1]);
        assert_eq!(group.match_str("test.org"), vec![2]);
        assert_eq!(group.match_str("demo.net"), vec![3]);
        assert!(group.match_str("other.io").is_empty());
    }

    #[test]
    fn test_mph_mixed_full_and_domain() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("exact.com", 1);
        group.add_domain_matcher("domain.com", 2);
        group.build().unwrap();

        // Full match
        assert_eq!(group.match_str("exact.com"), vec![1]);
        // Domain match (subdomain)
        assert_eq!(group.match_str("www.domain.com"), vec![2]);
        // Domain match (exact)
        assert_eq!(group.match_str("domain.com"), vec![2]);
    }

    #[test]
    fn test_mph_multiple_values_same_pattern() {
        let mut group = MPHMatcherGroup::new();
        group.add_full_matcher("example.com", 1);
        group.add_full_matcher("example.com", 2);
        group.build().unwrap();

        let result = group.match_str("example.com");
        assert!(result.contains(&1));
        assert!(result.contains(&2));
    }

    #[test]
    fn test_mph_deep_subdomain() {
        let mut group = MPHMatcherGroup::new();
        group.add_domain_matcher("example.com", 1);
        group.build().unwrap();

        assert!(group.match_any("a.b.c.example.com"));
        assert_eq!(group.match_str("a.b.c.example.com"), vec![1]);
    }

    #[test]
    fn test_mph_is_built_flag() {
        let mut group = MPHMatcherGroup::new();
        assert!(!group.is_built());

        group.add_full_matcher("example.com", 1);
        assert!(!group.is_built());

        group.build().unwrap();
        assert!(group.is_built());
    }

    #[test]
    fn test_rolling_hash_consistency() {
        let h1 = rolling_hash(0, "example.com");
        let h2 = rolling_hash(0, "example.com");
        assert_eq!(h1, h2);

        // 不同输入应产生不同哈希（大概率）
        let h3 = rolling_hash(0, "other.com");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_rolling_hash_incremental() {
        // RollingHash(0, "example.com") 应等于
        // 先算 RollingHash(0, ".com") 再算 RollingHash(result, "example")
        let full = rolling_hash(0, "example.com");
        let suffix = rolling_hash(0, ".com");
        let incremental = rolling_hash(suffix, "example");
        assert_eq!(full, incremental);
    }

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(4), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(8), 8);
        assert_eq!(next_pow2(9), 16);
    }

    #[test]
    fn test_seeded_hash_different_seeds() {
        let h1 = seeded_hash(0, "example.com");
        let h2 = seeded_hash(1, "example.com");
        // 不同种子应产生不同哈希（大概率）
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_mph_large_pattern_set() {
        let mut group = MPHMatcherGroup::new();
        for i in 0..100u32 {
            group.add_domain_matcher(&format!("domain{i}.com"), i);
        }
        group.build().unwrap();

        // 验证随机几个
        assert_eq!(group.match_str("domain0.com"), vec![0u32]);
        assert_eq!(group.match_str("domain50.com"), vec![50u32]);
        assert_eq!(group.match_str("domain99.com"), vec![99u32]);
        assert!(group.match_any("sub.domain42.com"));
        assert!(group.match_str("nonexistent.com").is_empty());
    }
}
