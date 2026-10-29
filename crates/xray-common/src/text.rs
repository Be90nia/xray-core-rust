//! 字节 ↔ 字符串的无损承载（Latin-1 / ISO-8859-1 的 1:1 映射）。
//!
//! Go 侧的头处理与 DNS 名字解析全程按字节（不解 UTF-8，≥0x80 原始字节合法）：
//! HTTP 头行（bd t3lzr）、DNS QNAME label（非法 UTF-8 label，D8）。本项目用 `String`
//! 承载这些字节，`from_utf8_lossy` 会把非法序列换成 U+FFFD 并在回写时放大。
//! Latin-1 让每个字节映射到同码位字符，配 [`latin1_encode`] 原样还原。
//!
//! 唯一实现：`xray-proxy-http`（头行）与 `xray-proxy-dns`（QNAME）共用此处。

/// 字节 → String 的 Latin-1（ISO-8859-1）解码：每个字节映射到同码位字符，字节零丢失。
#[must_use]
pub fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// String → 字节的 Latin-1 编码（[`latin1_decode`] 的逆）。
///
/// U+0000..=U+00FF 映射回单字节；更大码位只可能来自代码合成值（读入侧不可能产出），
/// 按 UTF-8 编码，避免截断成乱码。
#[must_use]
pub fn latin1_encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        match u8::try_from(u32::from(ch)) {
            Ok(b) => out.push(b),
            Err(_) => {
                let mut tmp = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 任意字节（含非 UTF-8）解码后必须原样还原——这是头行/QNAME 字节透传的地基。
    #[test]
    fn latin1_roundtrip_is_lossless_for_any_bytes() {
        let raw = [0x00u8, 0x41, 0x7f, 0x80, 0xe9, 0xff];
        assert_eq!(latin1_encode(&latin1_decode(&raw)), raw);
        assert_eq!(latin1_decode(&raw), "\u{0}A\u{7f}\u{80}\u{e9}\u{ff}");
    }

    /// 超出 U+00FF 的码位（代码合成值）按 UTF-8 编码，不静默截断。
    #[test]
    fn latin1_encode_encodes_wide_chars_as_utf8() {
        assert_eq!(latin1_encode("\u{4e2d}"), "中".as_bytes());
    }
}
