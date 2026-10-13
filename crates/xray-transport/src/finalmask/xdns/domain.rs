//! # Domain：伪装域名与容量计算（对应 Go `xdns/domain.go`，v26.9.30）
//!
//! 把 payload base32 编码进 query name 的前缀 label；`cap` 是单条 query 可
//! 携带的最大 payload 字节数（由 lenLimit/labelLimit 推导）。

use std::io;

use super::{
    base32::{decode_upper, encode_lower},
    dns::Name,
};

/// 支持的 RR 类型（Go `TypeA/TypeCNAME/TypeTXT/TypeAAAA`）。
pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28;

/// qtype → 2bit 标识（塞进首字节低 2 位），对齐 Go `TypeMap`。
pub(crate) fn type_map(qtype: u16) -> io::Result<u8> {
    match qtype {
        TYPE_A => Ok(0),
        TYPE_CNAME => Ok(1),
        TYPE_TXT => Ok(2),
        TYPE_AAAA => Ok(3),
        _ => Err(invalid_data("unknown types")),
    }
}

/// 2bit 标识 → qtype，对齐 Go `TypeMap_`。
pub(crate) fn type_map_(b: u8) -> u16 {
    match b {
        0 => TYPE_A,
        1 => TYPE_CNAME,
        2 => TYPE_TXT,
        _ => TYPE_AAAA,
    }
}

/// base32 解码后长度：`DecodedLen(n) = n*5/8`（Go table）。
fn decoded_len(n: usize) -> usize {
    n * 5 / 8
}

/// base32 编码后长度：`EncodedLen(n) = ceil(n*8/5)`（Go table_）。
fn encoded_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

/// Name 的 wire 长度（len 前缀逐 label + 根 0 字节），对齐 Go `name.Length`。
fn name_wire_len(name: &Name) -> usize {
    let mut total = 1;
    for label in &name.labels {
        total += 1 + label.len();
    }
    total
}

/// 伪装域名（对应 Go `Domain`）。
#[derive(Debug, Clone)]
pub(crate) struct Domain {
    name: Name,
    #[allow(dead_code)] // 保存原始配置值，对齐 Go 字段
    len_limit: usize,
    label_limit: usize,
    types: Vec<u16>,
    edns0: u16,
    /// 单条 query 最大 payload 容量。
    pub(crate) cap: usize,
    /// CNAME 单条 answer 编码后 name 的最大 wire 长度。
    pub(crate) len_max: usize,
}

impl Domain {
    /// 构造并校验，对应 Go `NewDomain`。
    pub(crate) fn new(
        domain: &str,
        len_limit: usize,
        label_limit: usize,
        types: &[u16],
        edns0: u16,
    ) -> io::Result<Self> {
        if domain.contains("..") {
            return Err(invalid_data("invalid domain"));
        }
        if len_limit > 255 {
            return Err(invalid_data("lenLimit < 0 || lenLimit > 255"));
        }
        if label_limit > 63 {
            return Err(invalid_data("labelLimit < 0 || labelLimit > 63"));
        }
        if types.is_empty() {
            return Err(invalid_data("empty types"));
        }
        for t in types {
            type_map(*t)?;
        }
        if edns0 != 0 && !(512..=4096).contains(&edns0) {
            return Err(invalid_data("edns0 != 0 && (edns0 < 512 || edns0 > 4096)"));
        }

        // Go idna.ToASCII 后 Trim "."——本实现按配置即 ASCII 处理（配置面
        // 偏差：非 ASCII 域名由 Name::parse 字节直收，无 punycode）。
        let ascii = domain.trim_matches('.');
        let name = Name::parse(&format!("{ascii}."))?;
        let name_len = name_wire_len(&name);

        if len_limit < name_len + 1 {
            return Err(invalid_data("lenLimit < int(name.Length)+1"));
        }
        let n = (len_limit - name_len - 1) / (label_limit + 1);
        let left = (len_limit - name_len - 1) % (label_limit + 1);
        let mut total = n * label_limit;
        if left > 1 {
            total += left - 1;
        }
        let cap = decoded_len(total);
        if cap < 17 {
            return Err(invalid_data("cap < 17"));
        }
        let total = encoded_len(cap);
        let mut len_max = name_len + 1 + total + total / label_limit;
        if total % label_limit > 0 {
            len_max += 1;
        }
        Ok(Self { name, len_limit, label_limit, types: types.to_vec(), edns0, cap, len_max })
    }

    /// name 是否以本域名为后缀（大小写不敏感且严格更长），对齐 Go `IsDomain`。
    pub(crate) fn is_domain(&self, name: &Name) -> bool {
        if self.name.labels.len() >= name.labels.len() {
            return false;
        }
        let split = name.labels.len() - self.name.labels.len();
        for i in 0..self.name.labels.len() {
            if !eq_ascii_ci(&name.labels[split + i], &self.name.labels[i]) {
                return false;
            }
        }
        true
    }

    /// qtype 是否在支持列表，对齐 Go `HasType`。
    pub(crate) fn has_type(&self, qtype: u16) -> bool {
        self.types.contains(&qtype)
    }

    /// 支持的 qtype 数量。
    pub(crate) fn types_len(&self) -> usize {
        self.types.len()
    }

    /// 第 i 个支持的 qtype。
    pub(crate) fn qtype_at(&self, i: usize) -> u16 {
        self.types[i]
    }

    /// EDNS0 payload size 配置。
    pub(crate) fn edns0(&self) -> u16 {
        self.edns0
    }

    /// payload → base32 → 按 label_limit 切 label → 拼到域名前，对齐 Go `Encode`。
    ///
    /// Go 端超 254 字节 panic；本实现返回错误（调用路径由 cap 保证不触达）。
    pub(crate) fn encode(&self, data: &[u8]) -> io::Result<Name> {
        let mut encoded = encode_lower(data);
        // 解码长度与编码长度严格对应（无 padding），直接按 encoded_len 截齐
        let enc_len = encoded_len(data.len());
        encoded.truncate(enc_len);

        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut rest = encoded.as_slice();
        while !rest.is_empty() {
            let size = rest.len().min(self.label_limit);
            labels.push(rest[..size].to_vec());
            rest = &rest[size..];
        }
        labels.extend(self.name.labels.iter().cloned());
        Name::new(labels)
    }

    /// 从 query name 前缀解码 payload；非本域名/非法 base32 返回空，对齐 Go `Decode`。
    pub(crate) fn decode(&self, name: &Name) -> Vec<u8> {
        if !self.is_domain(name) {
            return Vec::new();
        }
        let suffix_len = self.name.labels.len();
        let mut b1: Vec<u8> = Vec::new();
        for label in &name.labels[..name.labels.len() - suffix_len] {
            b1.extend_from_slice(label);
        }
        b1.iter_mut().for_each(|b| b.make_ascii_uppercase());
        decode_upper(&b1).unwrap_or_default()
    }
}

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_domain_validates() {
        assert!(Domain::new("a..com", 255, 63, &[TYPE_A], 0).is_err());
        assert!(Domain::new("a.com", 256, 63, &[TYPE_A], 0).is_err());
        assert!(Domain::new("a.com", 255, 64, &[TYPE_A], 0).is_err());
        assert!(Domain::new("a.com", 255, 63, &[], 0).is_err());
        assert!(Domain::new("a.com", 255, 63, &[42], 0).is_err());
        assert!(Domain::new("a.com", 255, 63, &[TYPE_TXT], 100).is_err());
        assert!(Domain::new("a.com", 255, 63, &[TYPE_TXT], 511).is_err());
        // lenLimit < name.Length + 1（"a.com." wire = 6）
        assert!(Domain::new("a.com", 6, 63, &[TYPE_A], 0).is_err());
        let d = Domain::new("a.com", 255, 63, &[TYPE_A, TYPE_TXT], 0).unwrap();
        assert!(d.cap >= 17);
        assert!(d.has_type(TYPE_A));
        assert!(!d.has_type(TYPE_CNAME));
    }

    #[test]
    fn encode_decode_round_trip() {
        let d = Domain::new("a.example.com", 255, 63, &[TYPE_A], 0).unwrap();
        // 容量内最大 payload（Go 超容量在 Encode panic，本实现报错——都用 cap 定界）
        let payload: Vec<u8> = (0..d.cap as u8).cycle().take(d.cap).collect();
        let name = d.encode(&payload).unwrap();
        // 严格后缀：完整域名匹配
        assert!(d.is_domain(&name));
        // 自身（等长）不匹配（严格更长要求）
        assert!(!d.is_domain(&Name::parse("a.example.com").unwrap()));
        let decoded = d.decode(&name);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn is_domain_case_insensitive() {
        let d = Domain::new("a.example.com", 255, 63, &[TYPE_A], 0).unwrap();
        let q = Name::parse("XxYz.A.EXAMPLE.COM").unwrap();
        assert!(d.is_domain(&q));
        // "XxYz" 4 字符 base32 → 2 字节
        assert_eq!(d.decode(&q).len(), 2);
    }

    #[test]
    fn decode_rejects_non_base32() {
        let d = Domain::new("a.example.com", 255, 63, &[TYPE_A], 0).unwrap();
        let q = Name::parse("!!!.a.example.com").unwrap();
        assert!(d.decode(&q).is_empty());
        assert!(d.decode(&Name::parse("other.com").unwrap()).is_empty());
    }

    #[test]
    fn cap_formula_matches_go() {
        // Go TestXxx：NewDomain("a.example.com", 200, 1, [TypeA], 0)
        let d = Domain::new("a.example.com", 200, 1, &[TYPE_A], 0).unwrap();
        // name wire: "a.example.com." = 1+1 +1+7 +1+3 +1+3 +1 = 18? 逐 label：a(2) example(8)
        // com(4) root(1) = 15 lenLimit 200: n=(200-15-1)/2=92, left=0, total=92*1=92,
        // cap=92*5/8=57
        assert_eq!(d.cap, 57);
        assert_eq!(d.len_max, 15 + 1 + encoded_len(57) + encoded_len(57));
    }
}
