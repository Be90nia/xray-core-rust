//! # RFC4648 base32 编解码（无 padding）
//!
//! 对应 Go `base32.StdEncoding.WithPadding(base32.NoPadding)`：
//! - 编码：字节流 → A-Z 2-7 字符（小写形式输出）。
//! - 解码：A-Z a-z 2-7 → 字节流；非法字符返回错误。
//!
//! 不依赖外部 crate，自实现约 60 行。

use std::io;

const ALPHABET_UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 编码为 base32 小写字符串（无 padding）。返回 `Vec<u8>` 便于直接拼接到 name。
pub(crate) fn encode_lower(p: &[u8]) -> Vec<u8> {
    let encoded_len = encoded_len(p.len());
    let mut out = vec![0u8; encoded_len];
    encode_into(p, &mut out);
    // 转小写
    for b in &mut out {
        b.make_ascii_lowercase();
    }
    out
}

/// 解码 base32 字符串（接受大小写）。返回 `Vec<u8>`。
pub(crate) fn decode_upper(p: &[u8]) -> io::Result<Vec<u8>> {
    // 接受任意大小写，统一转大写查表
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(decoded_len(p.len()));
    for &c in p {
        let v = decode_char(c)?;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

fn decode_char(c: u8) -> io::Result<u32> {
    let upper = c.to_ascii_uppercase();
    let v = match upper {
        b'A'..=b'Z' => (upper - b'A') as u32,
        b'2'..=b'7' => (upper - b'2' + 26) as u32,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid base32 char: {c:#x}"),
            ));
        },
    };
    Ok(v)
}

/// 计算 base32 编码后长度（无 padding）：ceil(n * 8 / 5)。
fn encoded_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

/// 估算 base32 解码后长度上限：floor(n * 5 / 8)。
fn decoded_len(n: usize) -> usize {
    n * 5 / 8
}

/// 把 `input` 编码到 `output`（output 已分配好长度，由 encoded_len 计算）。
fn encode_into(input: &[u8], output: &mut [u8]) {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut idx = 0;
    for &b in input {
        bits = (bits << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            output[idx] = ALPHABET_UPPER[((bits >> nbits) & 0x1f) as usize];
            idx += 1;
        }
    }
    if nbits > 0 {
        output[idx] = ALPHABET_UPPER[((bits << (5 - nbits)) & 0x1f) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_vectors() {
        // RFC4648 测试向量（去掉 padding 后）
        assert_eq!(encode_lower(b""), b"");
        assert_eq!(encode_lower(b"f"), b"my");
        assert_eq!(encode_lower(b"fo"), b"mzxq");
        assert_eq!(encode_lower(b"foo"), b"mzxw6");
        assert_eq!(encode_lower(b"foob"), b"mzxw6yq");
        assert_eq!(encode_lower(b"fooba"), b"mzxw6ytb");
        assert_eq!(encode_lower(b"foobar"), b"mzxw6ytboi");
    }

    #[test]
    fn decode_known_vectors() {
        assert_eq!(decode_upper(b"").unwrap(), b"");
        assert_eq!(decode_upper(b"MY").unwrap(), b"f");
        assert_eq!(decode_upper(b"MZXQ").unwrap(), b"fo");
        assert_eq!(decode_upper(b"mzxw6").unwrap(), b"foo");
        assert_eq!(decode_upper(b"mzxw6yq").unwrap(), b"foob");
        assert_eq!(decode_upper(b"mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(decode_upper(b"mzxw6ytboi").unwrap(), b"foobar");
    }

    #[test]
    fn roundtrip_random_data() {
        // 各种长度都应能 roundtrip
        for n in 0..=32 {
            let data: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
            let encoded = encode_lower(&data);
            let decoded = decode_upper(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed at n={n}");
        }
    }

    #[test]
    fn decode_rejects_invalid_char() {
        assert!(decode_upper(b"abc!").is_err());
        // 1 / 0 / 8 / 9 不是 base32 字符
        assert!(decode_upper(b"0").is_err());
        assert!(decode_upper(b"8").is_err());
        assert!(decode_upper(b"1").is_err());
    }
}
