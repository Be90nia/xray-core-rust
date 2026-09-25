//! 证书哈希（pinned certificate SHA-256）。
//!
//! 翻译自 Go `transport/internet/tls/pin.go`。
//!
//! # 用途
//! 配合 `Config.pinned_peer_cert_sha256` 字段做证书钉扎（pinning）：
//! peer 证书的 SHA-256 必须在配置的 hash 列表里，否则握手失败。
//! 见 `config::verify_chain`。

use sha2::{Digest, Sha256};

/// 计算证书的 SHA-256 哈希（32 字节）。
///
/// 对应 Go `GenerateCertHash[T]`，但 Rust 端只接受 DER 字节切片
/// （Go 通过泛型同时接受 `*x509.Certificate` 和 `[]byte`）。
///
/// 上游调用方拿到的是 ASN.1 DER 字节流，直接传入即可。
///
/// # 示例
/// ```
/// use xray_tls::pin::generate_cert_hash;
/// let der: &[u8] = &[0x30, 0x82, 0x01]; // 真实场景是完整 DER
/// let hash = generate_cert_hash(der);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn generate_cert_hash(der: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hasher.finalize().to_vec()
}

/// 同 [`generate_cert_hash`]，但返回小写 hex 字符串。
///
/// 对应 Go `GenerateCertHashHex`。主要用于日志/调试输出。
pub fn generate_cert_hash_hex(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_known_hash() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = generate_cert_hash(&[]);
        assert_eq!(h.len(), 32);
        assert_eq!(
            generate_cert_hash_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn deterministic_same_input_same_hash() {
        let der = b"hello cert";
        assert_eq!(generate_cert_hash(der), generate_cert_hash(der));
        assert_eq!(generate_cert_hash_hex(der), generate_cert_hash_hex(der));
    }

    #[test]
    fn different_input_different_hash() {
        assert_ne!(generate_cert_hash(b"a"), generate_cert_hash(b"b"));
    }

    #[test]
    fn single_block_vs_full_cert() {
        // 模拟真实场景：DER 通常是几百到几千字节
        let der: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let h = generate_cert_hash(&der);
        assert_eq!(h.len(), 32);
        // 与逐字节预期一致：手动构造 hash 比对
        let mut manual = Sha256::new();
        for b in &der {
            manual.update([*b]);
        }
        assert_eq!(h, manual.finalize().to_vec());
    }

    #[test]
    fn hex_lowercase() {
        let h = generate_cert_hash_hex(b"x");
        assert!(h.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
    }
}
