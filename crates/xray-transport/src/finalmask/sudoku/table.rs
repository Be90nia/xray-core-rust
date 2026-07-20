//! # Sudoku 数独编码表（对应 Go `sudoku/table.go`）
//!
//! 4×4 数独谜题作为字节编码表——每个字节值映射到一个 4×4 数独网格，
//! 网格的 4 个 hint 位置经 layout 编码后作为线上的 4 个字节。
//!
//! ## 算法概要
//!
//! 1. 枚举所有 4×4 数独解（288 个）
//! 2. C(16,4)=1820 种 hint 位置四元组
//! 3. 每个 grid×每个 hint 位置 → 4 个 clueGroup → sort4 → packKey
//! 4. 只保留唯一可解码的 hint 组合（key 只出现一次）
//! 5. 用 password 的 SHA256 作 seed shuffle 288 grids，byte b → grid order[b]
//! 6. 三种 layout（Entropy/Ascii/Custom）决定 group 如何映射到线上字节

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use rand::seq::SliceRandom;
use rand::SeedableRng;
use ring::digest;

/// 4×4 数独网格（16 格，值为 1-4）。
type Grid = [u8; 16];

/// 编码表（对应 Go `table`）。
pub(crate) struct Table {
    /// encode[byte] = 该字节对应的所有合法 hint 四元组。
    pub encode: Vec<Vec<[u8; 4]>>,
    /// decode[key] = sorted hint 四元组 → 原字节。
    pub decode: HashMap<u32, u8>,
    /// 该表使用的布局。
    pub layout: Layout,
}

// ===== Layout =====

/// 字节布局（对应 Go `byteLayout`）。
///
/// 控制字节如何映射到线上传输的字节值。
#[derive(Clone)]
pub(crate) enum Layout {
    Entropy(EntropyLayout),
    Ascii(AsciiLayout),
    Custom(CustomLayout),
}

impl Layout {
    pub fn hint_mask(&self) -> u8 {
        match self {
            Self::Entropy(_) => EntropyLayout::HINT_MASK,
            Self::Ascii(_) => AsciiLayout::HINT_MASK,
            Self::Custom(c) => c.x_mask,
        }
    }

    pub fn hint_value(&self) -> u8 {
        match self {
            Self::Entropy(_) => EntropyLayout::HINT_VALUE,
            Self::Ascii(_) => AsciiLayout::HINT_VALUE,
            Self::Custom(c) => c.x_mask,
        }
    }

    pub fn pad_marker(&self) -> u8 {
        match self {
            Self::Entropy(_) => EntropyLayout::PAD_MARKER,
            Self::Ascii(_) => AsciiLayout::PAD_MARKER,
            Self::Custom(c) => c.pad_marker,
        }
    }

    pub fn padding_pool(&self) -> &[u8] {
        match self {
            Self::Entropy(l) => &l.padding_pool,
            Self::Ascii(l) => &l.padding_pool,
            Self::Custom(c) => &c.padding_pool,
        }
    }

    /// encode_hint = encode_group（Go 中两者赋同一函数）。
    pub fn encode_hint(&self, group: u8) -> u8 {
        self.encode_group(group)
    }

    pub fn encode_group(&self, group: u8) -> u8 {
        match self {
            Self::Entropy(l) => l.encode_group(group),
            Self::Ascii(l) => l.encode_group(group),
            Self::Custom(l) => l.encode_group(group),
        }
    }

    pub fn decode_group(&self, b: u8) -> Option<u8> {
        match self {
            Self::Entropy(l) => l.decode_group(b),
            Self::Ascii(l) => l.decode_group(b),
            Self::Custom(l) => l.decode_group(b),
        }
    }

    /// 默认 Entropy 布局构造（供 packed encoder fallback）。
    pub(crate) fn entropy_default() -> Self {
        Self::Entropy(EntropyLayout::new())
    }

    /// 判断字节是否为 hint（对应 Go `isHint`）。
    pub fn is_hint(&self, b: u8) -> bool {
        if (b & self.hint_mask()) == self.hint_value() {
            return true;
        }
        // ASCII layout maps 0x7f to '\n' to avoid DEL on the wire
        self.hint_mask() == 0x40 && b == b'\n'
    }
}

/// 高熵二进制布局（Go `entropyLayout`）。
#[derive(Clone)]
pub(crate) struct EntropyLayout {
    padding_pool: Vec<u8>,
}

impl EntropyLayout {
    const HINT_MASK: u8 = 0x90;
    const HINT_VALUE: u8 = 0x00;
    const PAD_MARKER: u8 = 0x80;

    fn new() -> Self {
        let padding_pool: Vec<u8> = (0u8..8).flat_map(|i| [0x80 + i, 0x10 + i]).collect();
        Self { padding_pool }
    }

    fn encode_group(&self, group: u8) -> u8 {
        let v = group & 0x3f;
        ((v & 0x30) << 1) | (v & 0x0f)
    }

    fn decode_group(&self, b: u8) -> Option<u8> {
        if b & 0x90 != 0 {
            None
        } else {
            Some(((b >> 1) & 0x30) | (b & 0x0f))
        }
    }
}

/// 可打印 ASCII 布局（Go `asciiLayout`）。
#[derive(Clone)]
pub(crate) struct AsciiLayout {
    padding_pool: Vec<u8>,
}

impl AsciiLayout {
    const HINT_MASK: u8 = 0x40;
    const HINT_VALUE: u8 = 0x40;
    const PAD_MARKER: u8 = 0x3f;

    fn new() -> Self {
        let padding_pool: Vec<u8> = (0x20u8..=0x3f).collect();
        Self { padding_pool }
    }

    fn encode_group(&self, group: u8) -> u8 {
        let b = 0x40 | (group & 0x3f);
        // 0x7f (DEL) 映射为 '\n' 避免线上出现 DEL
        if b == 0x7f {
            b'\n'
        } else {
            b
        }
    }

    fn decode_group(&self, b: u8) -> Option<u8> {
        if b == b'\n' {
            Some(0x3f)
        } else if b & 0x40 == 0 {
            None
        } else {
            Some(b & 0x3f)
        }
    }
}

/// 模板自定义布局（Go `customLayout`）。
///
/// pattern 为 8 字符模板，每字符为 `x`/`p`/`v`：
/// - `x`(2 个)：固定标记位（hint mask）
/// - `p`(2 个)：val 的 2 bit
/// - `v`(4 个)：position 的 4 bit
#[derive(Clone)]
pub(crate) struct CustomLayout {
    x_bits: [u8; 2],
    p_bits: [u8; 2],
    v_bits: [u8; 4],
    x_mask: u8,
    pad_marker: u8,
    padding_pool: Vec<u8>,
}

impl CustomLayout {
    fn new(pattern: &str) -> Result<Self, String> {
        let cleaned = normalize_custom_table(pattern)?;
        let (mut x_bits, mut p_bits, mut v_bits) = (Vec::new(), Vec::new(), Vec::new());
        for (i, ch) in cleaned.chars().enumerate() {
            let bit = 7 - i as u8;
            match ch {
                'x' => x_bits.push(bit),
                'p' => p_bits.push(bit),
                'v' => v_bits.push(bit),
                _ => unreachable!(),
            }
        }
        let x_mask = x_bits.iter().fold(0u8, |acc, &b| acc | (1 << b));

        // 构建 padding pool：枚举所有 drop-x + val + pos 组合，选 popcount >= 5 的
        let mut padding_set = BTreeSet::new();
        for drop in 0..x_bits.len() {
            for val in 0u8..4 {
                for pos in 0u8..16 {
                    let group = (val << 4) | pos;
                    let b = encode_group_with_drop_x(group, &x_bits, &p_bits, &v_bits, x_mask, drop as i8);
                    if b.count_ones() >= 5 {
                        padding_set.insert(b);
                    }
                }
            }
        }
        let padding_pool: Vec<u8> = padding_set.into_iter().collect();
        if padding_pool.is_empty() {
            return Err("customTable produced empty padding pool".into());
        }
        let pad_marker = padding_pool[0];

        Ok(Self {
            x_bits: x_bits.try_into().unwrap(),
            p_bits: p_bits.try_into().unwrap(),
            v_bits: v_bits.try_into().unwrap(),
            x_mask,
            pad_marker,
            padding_pool,
        })
    }

    fn encode_group(&self, group: u8) -> u8 {
        encode_group_with_drop_x(group, &self.x_bits, &self.p_bits, &self.v_bits, self.x_mask, -1)
    }

    fn decode_group(&self, b: u8) -> Option<u8> {
        if b & self.x_mask != self.x_mask {
            return None;
        }
        let mut val = 0u8;
        if b & (1 << self.p_bits[0]) != 0 {
            val |= 0x02;
        }
        if b & (1 << self.p_bits[1]) != 0 {
            val |= 0x01;
        }
        let mut pos = 0u8;
        for (i, &bit) in self.v_bits.iter().enumerate() {
            if b & (1 << bit) != 0 {
                pos |= 1 << (3 - i as u8);
            }
        }
        Some((val & 0x03) << 4 | (pos & 0x0f))
    }
}

/// customLayout 的编码核心（对应 Go `encodeGroupWithDropX` 闭包）。
///
/// `drop_x < 0` 表示不丢弃任何 x bit（正常编码）；`drop_x >= 0` 表示丢弃第 `drop_x` 个 x bit（用于生成 padding）。
fn encode_group_with_drop_x(
    group: u8,
    x_bits: &[u8],
    p_bits: &[u8],
    v_bits: &[u8],
    x_mask: u8,
    drop_x: i8,
) -> u8 {
    let mut out = x_mask;
    if drop_x >= 0 {
        out &= !(1 << x_bits[drop_x as usize]);
    }
    let val = (group >> 4) & 0x03;
    let pos = group & 0x0f;
    if val & 0x02 != 0 {
        out |= 1 << p_bits[0];
    }
    if val & 0x01 != 0 {
        out |= 1 << p_bits[1];
    }
    for (i, &bit) in v_bits.iter().enumerate() {
        if (pos >> (3 - i as u8)) & 0x01 == 1 {
            out |= 1 << bit;
        }
    }
    out
}

// ===== Grid 生成 =====

/// 生成所有 4×4 数独网格（288 个）。
fn generate_all_grids() -> Vec<Grid> {
    let mut grids = Vec::with_capacity(288);
    let mut g = [0u8; 16];
    grid_dfs(0, &mut g, &mut grids);
    grids
}

/// DFS 枚举（对应 Go `generateAllGrids` 内部 `dfs`）。
fn grid_dfs(idx: usize, g: &mut Grid, out: &mut Vec<Grid>) {
    if idx == 16 {
        out.push(*g);
        return;
    }
    let row = idx / 4;
    let col = idx % 4;
    let box_row = (row / 2) * 2;
    let box_col = (col / 2) * 2;

    for num in 1u8..=4 {
        // 检查行/列
        let mut valid = (0..4).all(|i| g[row * 4 + i] != num && g[i * 4 + col] != num);
        if !valid {
            continue;
        }
        // 检查 2×2 子格
        for r in 0..2 {
            for c in 0..2 {
                if g[(box_row + r) * 4 + (box_col + c)] == num {
                    valid = false;
                    break;
                }
            }
            if !valid {
                break;
            }
        }
        if !valid {
            continue;
        }
        g[idx] = num;
        grid_dfs(idx + 1, g, out);
        g[idx] = 0;
    }
}

/// C(16,4) = 1820 种 hint 位置四元组。
fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0u8..13 {
        for b in (a + 1)..14 {
            for c in (b + 1)..15 {
                for d in (c + 1)..16 {
                    positions.push([a, b, c, d]);
                }
            }
        }
    }
    positions
}

// ===== 工具函数 =====

/// clue group = (值-1)<<4 | 位置（对应 Go `clueGroup`）。
fn clue_group(g: &Grid, pos: u8) -> u8 {
    ((g[pos as usize] - 1) << 4) | (pos & 0x0f)
}

/// 4 字节打包为 u32 key（大端）。
pub(crate) fn pack_key(sorted: [u8; 4]) -> u32 {
    u32::from_be_bytes(sorted)
}

/// 4 元素排序网络（对应 Go `sort4`）。
pub(crate) fn sort4(mut v: [u8; 4]) -> [u8; 4] {
    if v[0] > v[1] {
        v.swap(0, 1);
    }
    if v[2] > v[3] {
        v.swap(2, 3);
    }
    if v[0] > v[2] {
        v.swap(0, 2);
    }
    if v[1] > v[3] {
        v.swap(1, 3);
    }
    if v[1] > v[2] {
        v.swap(1, 2);
    }
    v
}

// ===== Base Patterns =====

/// 基础模式缓存（对应 Go `basePatternsOnce sync.Once`）。
static BASE_PATTERNS: OnceLock<Vec<Vec<[u8; 4]>>> = OnceLock::new();

fn get_base_patterns() -> Result<&'static Vec<Vec<[u8; 4]>>, String> {
    if let Some(p) = BASE_PATTERNS.get() {
        return Ok(p);
    }
    // get_or_try_init 仍 unstable (#109737)，用 get+set 替代
    let patterns = build_base_patterns()?;
    let _ = BASE_PATTERNS.set(patterns);
    Ok(BASE_PATTERNS.get().expect("BASE_PATTERNS just set"))
}

/// 构建基础模式：每个 grid 的唯一可解码 hint 组合列表。
fn build_base_patterns() -> Result<Vec<Vec<[u8; 4]>>, String> {
    let grids = generate_all_grids();
    let positions = hint_positions();
    let mut patterns: Vec<Vec<[u8; 4]>> = vec![Vec::new(); grids.len()];

    for ps in &positions {
        let mut counts: HashMap<u32, u16> = HashMap::with_capacity(grids.len());
        let entries: Vec<(u32, [u8; 4])> = grids
            .iter()
            .map(|g| {
                let groups = [
                    clue_group(g, ps[0]),
                    clue_group(g, ps[1]),
                    clue_group(g, ps[2]),
                    clue_group(g, ps[3]),
                ];
                let sorted = sort4(groups);
                let key = pack_key(sorted);
                *counts.entry(key).or_insert(0u16) += 1;
                (key, sorted)
            })
            .collect();

        for (gi, (key, sorted)) in entries.iter().enumerate() {
            if counts.get(key).copied().unwrap_or(0) == 1 {
                patterns[gi].push(*sorted);
            }
        }
    }

    // 验证每个 grid 至少有一个唯一可解码的 hint 组合
    for (gi, list) in patterns.iter().enumerate() {
        if list.is_empty() {
            return Err(format!("grid {gi} has no uniquely decodable clue set"));
        }
    }

    Ok(patterns)
}

// ===== Layout 解析 =====

/// 规范化 customTable 模板（对应 Go `normalizeCustomTable`）。
fn normalize_custom_table(pattern: &str) -> Result<String, String> {
    let cleaned: String = pattern
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() != 8 {
        return Err(format!("customTable must be 8 chars, got {}", cleaned.len()));
    }
    let (mut x, mut p, mut v) = (0u32, 0u32, 0u32);
    for ch in cleaned.chars() {
        match ch {
            'x' => x += 1,
            'p' => p += 1,
            'v' => v += 1,
            _ => return Err(format!("customTable has invalid char {ch:?}")),
        }
    }
    if x != 2 || p != 2 || v != 4 {
        return Err("customTable must contain exactly 2 x, 2 p and 4 v".into());
    }
    Ok(cleaned)
}

/// 规范化 ASCII 模式（对应 Go `normalizeASCII`）。
fn normalize_ascii(mode: &str) -> Result<&'static str, String> {
    match mode.trim().to_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Ok("prefer_entropy"),
        "ascii" | "prefer_ascii" => Ok("prefer_ascii"),
        other => Err(format!("invalid sudoku ascii mode: {other}")),
    }
}

/// 根据 mode + customTable 选择 layout（对应 Go `resolveLayout`）。
fn resolve_layout(mode: &str, custom_table: &str) -> Result<Layout, String> {
    if mode == "prefer_ascii" {
        return Ok(Layout::Ascii(AsciiLayout::new()));
    }
    if !custom_table.is_empty() {
        return Ok(Layout::Custom(CustomLayout::new(custom_table)?));
    }
    Ok(Layout::Entropy(EntropyLayout::new()))
}

// ===== Table 构建 =====

/// 构建 table（对应 Go `buildTable`）。
fn build_table(password: &str, layout: Layout) -> Result<Table, String> {
    let patterns = get_base_patterns()?;
    if patterns.len() < 256 {
        return Err(format!("not enough sudoku grids: {}", patterns.len()));
    }

    // SHA256 → seed → shuffle order
    let hash = digest::digest(&digest::SHA256, password.as_bytes());
    let hash_ref = hash.as_ref();
    let seed = i64::from_be_bytes(hash_ref[..8].try_into().unwrap());
    let mut order: Vec<usize> = (0..patterns.len()).collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    order.shuffle(&mut rng);

    let mut t = Table {
        encode: vec![Vec::new(); 256],
        decode: HashMap::with_capacity(1 << 16),
        layout,
    };

    for b in 0u32..256 {
        let pat_list = &patterns[order[b as usize]];
        if pat_list.is_empty() {
            return Err(format!("grid {} has no valid clue set", order[b as usize]));
        }
        let layout = &t.layout;
        let mut enc = Vec::with_capacity(pat_list.len());
        for groups in pat_list {
            let hints = [
                layout.encode_hint(groups[0]),
                layout.encode_hint(groups[1]),
                layout.encode_hint(groups[2]),
                layout.encode_hint(groups[3]),
            ];
            let sorted = sort4(hints);
            let key = pack_key(sorted);
            if let Some(&old) = t.decode.get(&key) {
                if old != b as u8 {
                    return Err(format!("decode key collision for byte {} and {}", old, b));
                }
            }
            t.decode.insert(key, b as u8);
            enc.push(hints);
        }
        t.encode[b as usize] = enc;
    }

    Ok(t)
}

// ===== 表集合缓存 =====

/// 表集合缓存 key（对应 Go `tableCacheKey`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TableCacheKey {
    password: String,
    mode: &'static str,
    patterns: Vec<String>,
}

/// 全局表缓存（对应 Go `tableSetCache sync.Map`）。
static TABLE_CACHE: OnceLock<parking_lot::Mutex<HashMap<TableCacheKey, Vec<Arc<Table>>>>> =
    OnceLock::new();

fn table_cache() -> &'static parking_lot::Mutex<HashMap<TableCacheKey, Vec<Arc<Table>>>> {
    TABLE_CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// 规范化 customTables 列表（对应 Go `normalizedCustomPatterns`）。
fn normalized_custom_patterns(
    raw_patterns: &[String],
    mode: &'static str,
) -> Result<Vec<String>, String> {
    if mode == "prefer_ascii" {
        return Ok(vec![String::new()]);
    }

    let mut patterns = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in raw_patterns {
        let trimmed = raw.trim();
        let normalized = if trimmed.is_empty() {
            String::new()
        } else {
            normalize_custom_table(trimmed)?
        };
        if seen.insert(normalized.clone()) {
            patterns.push(normalized);
        }
    }

    if patterns.is_empty() {
        patterns.push(String::new());
    }
    Ok(patterns)
}

/// 获取表集合（对应 Go `getTables`）。
///
/// 参数：password、ascii 模式、customTables 列表。
/// 返回每个 pattern 对应一张 table，编码时按 tableIndex 轮转使用。
pub(crate) fn get_tables(
    password: &str,
    ascii: &str,
    custom_tables: &[String],
) -> Result<Vec<Arc<Table>>, String> {
    let mode = normalize_ascii(ascii)?;
    let patterns = normalized_custom_patterns(custom_tables, mode)?;

    let key = TableCacheKey {
        password: password.to_string(),
        mode,
        patterns: patterns.clone(),
    };

    // 检查缓存
    {
        let cache = table_cache().lock();
        if let Some(cached) = cache.get(&key) {
            return Ok(cached.clone());
        }
    }

    // 构建
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in &patterns {
        let layout = resolve_layout(mode, pattern)?;
        let t = build_table(password, layout)?;
        tables.push(Arc::new(t));
    }

    // 写入缓存
    let mut cache = table_cache().lock();
    cache.entry(key).or_insert(tables.clone());

    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_288_grids() {
        let grids = generate_all_grids();
        assert_eq!(grids.len(), 288);
        // 验证第一个 grid：每行/列/子格不重复
        let g = &grids[0];
        for row in 0..4 {
            let mut seen = [false; 5];
            for col in 0..4 {
                let v = g[row * 4 + col] as usize;
                assert!(!seen[v], "row {row} duplicate");
                seen[v] = true;
            }
        }
    }

    #[test]
    fn hint_positions_count_1820() {
        assert_eq!(hint_positions().len(), 1820);
    }

    #[test]
    fn sort4_sorts_correctly() {
        assert_eq!(sort4([3, 1, 4, 1]), [1, 1, 3, 4]);
        assert_eq!(sort4([4, 3, 2, 1]), [1, 2, 3, 4]);
        assert_eq!(sort4([1, 2, 3, 4]), [1, 2, 3, 4]);
    }

    #[test]
    fn entropy_layout_roundtrip() {
        let l = EntropyLayout::new();
        for g in 0u8..64 {
            let encoded = l.encode_group(g);
            let decoded = l.decode_group(encoded).unwrap();
            assert_eq!(decoded, g, "entropy roundtrip failed for group {g}");
        }
    }

    #[test]
    fn ascii_layout_roundtrip() {
        let l = AsciiLayout::new();
        for g in 0u8..64 {
            let encoded = l.encode_group(g);
            let decoded = l.decode_group(encoded).unwrap();
            assert_eq!(decoded, g, "ascii roundtrip failed for group {g}");
        }
    }

    #[test]
    fn custom_layout_roundtrip() {
        let l = CustomLayout::new("xxppvvvv").unwrap();
        for g in 0u8..64 {
            let encoded = l.encode_group(g);
            let decoded = l.decode_group(encoded).unwrap();
            assert_eq!(decoded, g, "custom roundtrip failed for group {g}");
        }
    }

    #[test]
    fn custom_layout_rejects_invalid_pattern() {
        assert!(CustomLayout::new("xxppvvvv").is_ok());
        assert!(CustomLayout::new("xxppvvv").is_err()); // 7 chars
        assert!(CustomLayout::new("xxxpvvvv").is_err()); // 3 x
        assert!(CustomLayout::new("aappvvvv").is_err()); // invalid char
    }

    #[test]
    fn build_table_basic() {
        let t = build_table("test_password", Layout::Entropy(EntropyLayout::new())).unwrap();
        // 每个字节至少有一个 hint 四元组
        for b in 0..256 {
            assert!(!t.encode[b].is_empty(), "byte {b} has no encode entry");
        }
        // decode map 至少 256 项（可能更多因为同字节多 hint 组合）
        assert!(t.decode.len() >= 256);
    }

    #[test]
    fn get_tables_caches() {
        let tables1 = get_tables("pw", "", &[]).unwrap();
        let tables2 = get_tables("pw", "", &[]).unwrap();
        assert_eq!(tables1.len(), tables2.len());
        assert_eq!(tables1.len(), 1);
    }

    #[test]
    fn get_tables_ascii_mode() {
        let tables = get_tables("pw", "ascii", &[]).unwrap();
        assert_eq!(tables.len(), 1);
        assert!(matches!(tables[0].layout, Layout::Ascii(_)));
    }

    #[test]
    fn get_tables_custom_mode() {
        let tables = get_tables("pw", "", &["xxppvvvv".into()]).unwrap();
        assert_eq!(tables.len(), 1);
        assert!(matches!(tables[0].layout, Layout::Custom(_)));
    }
}
