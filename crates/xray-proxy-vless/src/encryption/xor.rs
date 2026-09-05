//! XTLS Vision 的 CTR XOR 流（对应 Go `encryption/xor.go`）。
//!
//! Go `NewCTR(key, iv)`：`blake3.DeriveKey(k, "VLESS", key)` 派生 32 字节密钥 → AES-256-CTR。
//! Go `cipher.NewCTR` 是 128 位 big-endian counter。
//!
//! Rust 用 RustCrypto `ctr::Ctr128BE<Aes256>`（与 xray-crypto 对齐），counter 语义一致。
//!
//! `XorConn`（xor_mode==2）见 [`crate::encryption::xor_conn`]：header-only XOR 状态机。

use crate::error::{Result, VlessError};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;

/// BLAKE3 派生密钥的上下文（Go 端硬编码 `"VLESS"`）。
const BLAKE3_CONTEXT: &str = "VLESS";

/// AES-256-CTR 流（128 位 big-endian counter，对齐 Go `cipher.NewCTR`）。
type Aes256Ctr = Ctr128BE<Aes256>;

/// CTR XOR 流（对齐 Go `cipher.Stream`）。
#[derive(Debug)]
pub struct CtrXor {
    cipher: Aes256Ctr,
}

impl CtrXor {
    /// 创建：`blake3.DeriveKey("VLESS", key)` → AES-256-CTR，`iv` 16 字节作初始 counter。
    ///
    /// # Errors
    /// `iv` 长度不是 16 字节返回 [`VlessError::Other`]。
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 16 {
            return Err(VlessError::Other(format!(
                "CTR iv must be 16 bytes, got {}",
                iv.len()
            )));
        }
        let derived = blake3::derive_key(BLAKE3_CONTEXT, key);
        let cipher = Aes256Ctr::new_from_slices(&derived, iv)
            .map_err(|e| VlessError::Other(format!("CTR init failed: {e}")))?;
        Ok(Self { cipher })
    }

    /// In-place XOR（对应 Go `ctr.XORKeyStream(buf, buf)`）。
    pub fn apply(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
    }

    /// `dst = src XOR keystream`（对应 Go `ctr.XORKeyStream(dst, src)`，dst≠src）。
    ///
    /// # Panics
    /// `dst.len() != src.len()` 时 debug 断言失败。
    pub fn xor_into(&mut self, dst: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dst.len(), src.len(), "xor_into: dst/src length mismatch");
        dst.copy_from_slice(src);
        self.cipher.apply_keystream(dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 相同 key/iv 的两个 CtrXor 产生相同 keystream（确定性验证）。
    #[test]
    fn ctr_deterministic_same_key_iv() {
        let mut a = CtrXor::new(b"key-a", &[0xAA; 16]).unwrap();
        let mut b = CtrXor::new(b"key-a", &[0xAA; 16]).unwrap();
        let mut buf_a = [0u8; 100];
        let mut buf_b = [0u8; 100];
        a.apply(&mut buf_a);
        b.apply(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    /// 不同 key 产生不同 keystream。
    #[test]
    fn ctr_different_key_diverges() {
        let mut a = CtrXor::new(b"key-a", &[0; 16]).unwrap();
        let mut b = CtrXor::new(b"key-b", &[0; 16]).unwrap();
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.apply(&mut buf_a);
        b.apply(&mut buf_b);
        assert_ne!(buf_a, buf_b);
    }

    /// apply 分两次与一次等价（跨 block 边界状态保持）。
    #[test]
    fn ctr_stream_state_across_blocks() {
        let mut a = CtrXor::new(b"k", &[0; 16]).unwrap();
        let mut b = CtrXor::new(b"k", &[0; 16]).unwrap();

        let mut buf1 = [0u8; 10];
        let mut buf2 = [0u8; 26];
        a.apply(&mut buf1);
        a.apply(&mut buf2);
        let combined_a: Vec<u8> = buf1.iter().chain(buf2.iter()).copied().collect();

        let mut combined = [0u8; 36];
        b.apply(&mut combined);

        assert_eq!(combined_a, combined.to_vec());
    }

    /// xor_into：dst = src XOR keystream，连续流与 apply 一致。
    #[test]
    fn xor_into_matches_apply() {
        let mut a = CtrXor::new(b"k", &[1; 16]).unwrap();
        let mut b = CtrXor::new(b"k", &[1; 16]).unwrap();

        let src = [0x55u8; 32];
        let mut dst_a = [0u8; 32];
        a.xor_into(&mut dst_a, &src);

        let mut keystream = [0u8; 32];
        b.apply(&mut keystream);
        let expected: Vec<u8> = src.iter().zip(keystream.iter()).map(|(s, k)| s ^ k).collect();
        assert_eq!(dst_a, expected.as_slice());
    }

    /// iv 长度校验。
    #[test]
    fn iv_length_validated() {
        let err = CtrXor::new(b"k", &[0; 15]).unwrap_err();
        assert!(matches!(err, VlessError::Other(_)));
        assert!(CtrXor::new(b"k", &[0; 16]).is_ok());
    }
}
