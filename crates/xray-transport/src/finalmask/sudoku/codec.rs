//! # Sudoku 编解码器（对应 Go `sudoku/codec.go` + `conn_tcp_packed.go`）
//!
//! 两种编码模式：
//! - **Pure**：每字节 → 4 个 hint（数独位置编码），随机 padding 插入
//! - **Packed**：6-bit group 编码（每字节 8 bit 拆分跨字节累积），下行优化

use std::sync::Arc;

use rand::{Rng, SeedableRng};

use super::table::{Layout, Table, pack_key, sort4};

/// 4 元素全排列（24 种），对应 Go `perm4`。
const PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

// ===== Pure 编解码 =====

/// Pure 编码器（对应 Go `codec`）。
pub(crate) struct Codec {
    tables: Vec<Arc<Table>>,
    rng: rand::rngs::StdRng,
    padding_chance: usize,
    table_index: usize,
}

impl Codec {
    pub fn new(tables: Vec<Arc<Table>>, p_min: usize, p_max: usize) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rand::rng().random());
        let padding_chance = pick_padding_chance(&mut rng, p_min, p_max);
        Self { tables, rng, padding_chance, table_index: 0 }
    }

    /// 当前轮转的 table（对应 Go `currentTable`）。
    fn current_table(&self) -> Option<&Table> {
        if self.tables.is_empty() {
            None
        } else {
            Some(&self.tables[self.table_index % self.tables.len()])
        }
    }

    /// 编码（对应 Go `codec.encode`）。
    pub fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(input.len() * 6 + 8);

        // 拆借用：tables 不可变，rng 可变，table_index 拷贝
        let tables = &self.tables;
        let rng = &mut self.rng;
        let chance = self.padding_chance;
        let mut table_index = self.table_index;

        for &b in input {
            if tables.is_empty() {
                return Err("sudoku table set missing".into());
            }
            let table = &tables[table_index % tables.len()];

            if should_pad(rng, chance) {
                out.push(random_padding(rng, table));
            }

            let enc = &table.encode[b as usize];
            if enc.is_empty() {
                return Err(format!("sudoku encode table missing for byte {b}"));
            }
            let hints = &enc[rng.random_range(0..enc.len())];
            let perm = &PERM4[rng.random_range(0..PERM4.len())];
            for &idx in perm {
                if should_pad(rng, chance) {
                    out.push(random_padding(rng, table));
                }
                out.push(hints[idx as usize]);
            }
            table_index += 1;
        }

        // 尾部 padding
        if should_pad(rng, chance) && !tables.is_empty() {
            let table = &tables[table_index % tables.len()];
            out.push(random_padding(rng, table));
        }

        self.table_index = table_index;
        Ok(out)
    }
}

/// 解码（对应 Go `decodeBytes`）。
///
/// 跨调用保持 `hint_buf` 和 `table_index` 状态，用于 TCP 流式解码。
#[allow(clippy::type_complexity)]
pub(crate) fn decode_bytes(
    tables: &[Arc<Table>],
    table_index: &mut usize,
    input: &[u8],
    mut hint_buf: Vec<u8>,
    mut out: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if tables.is_empty() {
        return Err("sudoku table set missing".into());
    }
    for &b in input {
        let table = &tables[*table_index % tables.len()];
        if !table.layout.is_hint(b) {
            continue;
        }
        hint_buf.push(b);
        if hint_buf.len() < 4 {
            continue;
        }
        let key_bytes = sort4([hint_buf[0], hint_buf[1], hint_buf[2], hint_buf[3]]);
        let key = pack_key(key_bytes);
        match table.decode.get(&key) {
            Some(&decoded) => {
                out.push(decoded);
                hint_buf.clear();
                *table_index += 1;
            },
            None => return Err("invalid sudoku hint tuple".into()),
        }
    }
    Ok((hint_buf, out))
}

// ===== Packed 编解码（6-bit group，下行优化）=====

/// Packed 编码器（对应 Go `packedEncoder`）。
pub(crate) struct PackedEncoder {
    layouts: Vec<Layout>,
    rng: rand::rngs::StdRng,
    padding_chance: usize,
    group_index: usize,
}

impl PackedEncoder {
    pub fn new(tables: &[Arc<Table>], p_min: usize, p_max: usize) -> Self {
        let layouts: Vec<Layout> = if tables.is_empty() {
            vec![Layout::entropy_default()]
        } else {
            tables.iter().map(|t| t.layout.clone()).collect()
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(rand::rng().random());
        let padding_chance = pick_padding_chance(&mut rng, p_min, p_max);
        Self { layouts, rng, padding_chance, group_index: 0 }
    }

    /// 编码（对应 Go `packedEncoder.encode`）。
    pub fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(input.len() * 2 + 8);
        let mut bit_buf: u64 = 0;
        let mut bit_count: u8 = 0;

        // 拆借用：layouts 不可变，rng 可变，group_index 拷贝
        let layouts = &self.layouts;
        let rng = &mut self.rng;
        let chance = self.padding_chance;
        let mut group_index = self.group_index;

        for &b in input {
            bit_buf = (bit_buf << 8) | u64::from(b);
            bit_count += 8;

            while bit_count >= 6 {
                bit_count -= 6;
                let layout = &layouts[group_index % layouts.len()];
                let group = ((bit_buf >> bit_count) & 0x3f) as u8;
                maybe_pad(rng, chance, &mut out, layout);
                out.push(layout.encode_group(group));
                group_index += 1;
                if bit_count > 0 {
                    bit_buf &= (1u64 << bit_count) - 1;
                } else {
                    bit_buf = 0;
                }
            }
        }

        // 尾部剩余 bit
        if bit_count > 0 {
            let layout = &layouts[group_index % layouts.len()];
            let group = ((bit_buf << (6 - bit_count)) & 0x3f) as u8;
            maybe_pad(rng, chance, &mut out, layout);
            out.push(layout.encode_group(group));
            group_index += 1;
            let next_layout = &layouts[group_index % layouts.len()];
            out.push(next_layout.pad_marker());
        }

        let layout = &layouts[group_index % layouts.len()];
        maybe_pad(rng, chance, &mut out, layout);

        self.group_index = group_index;
        Ok(out)
    }
}

/// 按 padding 概率插入 padding 字节（对应 Go `packedEncoder.maybePad`）。
fn maybe_pad(rng: &mut impl Rng, chance: usize, out: &mut Vec<u8>, layout: &Layout) {
    if !should_pad(rng, chance) {
        return;
    }
    let pool = layout.padding_pool();
    if pool.len() == 1 {
        out.push(pool[0]);
        return;
    }
    let pad_marker = layout.pad_marker();
    loop {
        let b = pool[rng.random_range(0..pool.len())];
        if b != pad_marker {
            out.push(b);
            return;
        }
    }
}

/// Packed 流解码状态（对应 Go `packedStreamDecoder`）。
#[derive(Default)]
pub(crate) struct PackedDecoder {
    pub group_index: usize,
    pub bit_buf: u64,
    pub bit_count: u8,
}

impl PackedDecoder {
    /// 解码一个 chunk（对应 Go `packedStreamDecoder.decodeChunk`）。
    pub fn decode_chunk(
        &mut self,
        layouts: &[Layout],
        input: &[u8],
        mut out: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        if layouts.is_empty() {
            return Err("sudoku layout set missing".into());
        }
        for &b in input {
            let layout = &layouts[self.group_index % layouts.len()];
            if !layout.is_hint(b) {
                if b == layout.pad_marker() {
                    self.bit_buf = 0;
                    self.bit_count = 0;
                }
                continue;
            }
            let group =
                layout.decode_group(b).ok_or_else(|| format!("invalid packed sudoku byte: {b}"))?;
            self.group_index += 1;
            self.bit_buf = (self.bit_buf << 6) | u64::from(group);
            self.bit_count += 6;
            while self.bit_count >= 8 {
                self.bit_count -= 8;
                out.push(((self.bit_buf >> self.bit_count) & 0xff) as u8);
                if self.bit_count > 0 {
                    self.bit_buf &= (1u64 << self.bit_count) - 1;
                } else {
                    self.bit_buf = 0;
                }
            }
        }
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.bit_buf = 0;
        self.bit_count = 0;
    }
}

// ===== 辅助函数 =====

/// 选取 padding 概率 [0, 100]（对应 Go `pickPaddingChance`）。
fn pick_padding_chance(rng: &mut impl Rng, p_min: usize, p_max: usize) -> usize {
    let p_min = p_min.min(100);
    let p_max = if p_max < p_min { p_min } else { p_max.min(100) };
    if p_max == p_min {
        return p_min;
    }
    rng.random_range(p_min..=p_max)
}

/// 按 padding_chance 判定是否插入 padding（对应 Go `codec.shouldPad`）。
fn should_pad(rng: &mut impl Rng, chance: usize) -> bool {
    match chance {
        0 => false,
        c if c >= 100 => true,
        c => rng.random_range(0..100) < c,
    }
}

/// 从 table 的 padding pool 随机取一字节（对应 Go `codec.randomPadding`）。
fn random_padding(rng: &mut impl Rng, table: &Table) -> u8 {
    let pool = table.layout.padding_pool();
    pool[rng.random_range(0..pool.len())]
}

#[cfg(test)]
mod tests {
    use super::{super::table::get_tables, *};

    fn make_tables() -> Vec<Arc<Table>> {
        get_tables("test_codec", "", &[]).unwrap()
    }

    #[test]
    fn perm4_has_24_entries() {
        assert_eq!(PERM4.len(), 24);
        // 每个排列都是 [0,1,2,3] 的全排列
        for p in &PERM4 {
            let mut sorted = *p;
            sorted.sort();
            assert_eq!(sorted, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn pure_encode_decode_roundtrip() {
        let tables = make_tables();
        let mut enc = Codec::new(tables.clone(), 0, 0);
        let input = b"hello sudoku!";
        let encoded = enc.encode(input).unwrap();
        // 解码（tableIndex 从 0 开始）
        let mut table_index = 0;
        let (hint_buf, decoded) =
            decode_bytes(&tables, &mut table_index, &encoded, Vec::new(), Vec::new()).unwrap();
        assert!(hint_buf.is_empty(), "hint_buf should be drained");
        assert_eq!(decoded, input);
    }

    #[test]
    fn pure_encode_with_padding_roundtrip() {
        let tables = make_tables();
        let mut enc = Codec::new(tables.clone(), 50, 50);
        let input: Vec<u8> = (0..200u32).map(|i| (i & 0xff) as u8).collect();
        let encoded = enc.encode(&input).unwrap();
        let mut table_index = 0;
        let (hint_buf, decoded) =
            decode_bytes(&tables, &mut table_index, &encoded, Vec::new(), Vec::new()).unwrap();
        assert!(hint_buf.is_empty());
        assert_eq!(decoded, input);
    }

    #[test]
    fn pure_encode_empty_input() {
        let tables = make_tables();
        let mut enc = Codec::new(tables, 0, 0);
        let encoded = enc.encode(&[]).unwrap();
        assert!(encoded.is_empty());
    }

    #[test]
    fn packed_encode_decode_roundtrip() {
        let tables = make_tables();
        let mut enc = PackedEncoder::new(&tables, 0, 0);
        let mut dec = PackedDecoder::default();
        let layouts: Vec<Layout> = tables.iter().map(|t| t.layout.clone()).collect();

        let input = b"packed sudoku roundtrip test data 12345";
        let encoded = enc.encode(input).unwrap();
        let decoded = dec.decode_chunk(&layouts, &encoded, Vec::new()).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn packed_encode_empty_input() {
        let tables = make_tables();
        let mut enc = PackedEncoder::new(&tables, 0, 0);
        let encoded = enc.encode(&[]).unwrap();
        // 空输入不产生输出（bitBuf 空，bitCount=0，跳过尾部处理）
        assert!(encoded.is_empty());
    }

    #[test]
    fn packed_stream_chunked_decode() {
        // 分块解码：模拟 TCP 流式接收
        let tables = make_tables();
        let mut enc = PackedEncoder::new(&tables, 0, 0);
        let layouts: Vec<Layout> = tables.iter().map(|t| t.layout.clone()).collect();
        let input = b"chunked decode test";
        let encoded = enc.encode(input).unwrap();

        let mut dec = PackedDecoder::default();
        let mid = encoded.len() / 2;
        let mut out = dec.decode_chunk(&layouts, &encoded[..mid], Vec::new()).unwrap();
        out = dec.decode_chunk(&layouts, &encoded[mid..], out).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn pick_padding_chance_clamps() {
        let mut rng = rand::rng();
        assert_eq!(pick_padding_chance(&mut rng, 150, 200), 100);
        assert_eq!(pick_padding_chance(&mut rng, 50, 10), 50); // max < min → min
        assert_eq!(pick_padding_chance(&mut rng, 30, 30), 30);
        for _ in 0..100 {
            let c = pick_padding_chance(&mut rng, 20, 40);
            assert!((20..=40).contains(&c));
        }
    }

    #[test]
    fn should_pad_boundaries() {
        let mut rng = rand::rng();
        assert!(!should_pad(&mut rng, 0));
        assert!(should_pad(&mut rng, 100));
        assert!(should_pad(&mut rng, 200));
    }
}
