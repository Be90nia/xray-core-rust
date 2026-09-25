//! # AES-CFB8 流加密（对应 Go `xmc/cfb8.go`）
//!
//! Minecraft 协议使用 AES-128-CFB8（1 字节 feedback，非标准 CFB-128）。
//! 算法：每个字节都重新加密整个 IV，取 keystream 第一字节做 XOR，密文（加密）或
//! 原密文（解密）补到 IV 末尾，IV 左移 1 字节。
//!
//! 简化实现：不抄 Go 的 unsafe 重叠缓冲优化（性能差距在 4 KiB 量级无显著影响）。

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};

/// AES-128 block size（固定 16 字节）。
pub const BLOCK_SIZE: usize = 16;

/// CFB8 加密器。
pub struct Cfb8Enc {
    cipher: Aes128,
    iv: [u8; BLOCK_SIZE],
}

/// CFB8 解密器。
pub struct Cfb8Dec {
    cipher: Aes128,
    iv: [u8; BLOCK_SIZE],
}

impl Cfb8Enc {
    /// 新建加密器：`key` 和 `iv` 均为 16 字节（MC 中 `iv == key`）。
    #[must_use]
    pub fn new(key: &[u8; BLOCK_SIZE], iv: &[u8; BLOCK_SIZE]) -> Self {
        Self { cipher: Aes128::new(&Array::from(*key)), iv: *iv }
    }

    /// 原地加密 `buf`。
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            let mut block = Array::from(self.iv);
            self.cipher.encrypt_block(&mut block);
            let c = *byte ^ block[0];
            // IV 左移 1 字节，密文补尾
            self.iv.copy_within(1..BLOCK_SIZE, 0);
            self.iv[BLOCK_SIZE - 1] = c;
            *byte = c;
        }
    }
}

impl Cfb8Dec {
    /// 新建解密器。
    #[must_use]
    pub fn new(key: &[u8; BLOCK_SIZE], iv: &[u8; BLOCK_SIZE]) -> Self {
        Self { cipher: Aes128::new(&Array::from(*key)), iv: *iv }
    }

    /// 原地解密 `buf`。
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            let mut block = Array::from(self.iv);
            self.cipher.encrypt_block(&mut block);
            let p = *byte ^ block[0];
            // 注意：解密时反馈的是密文（原 *byte），不是解密出的明文
            let c = *byte;
            self.iv.copy_within(1..BLOCK_SIZE, 0);
            self.iv[BLOCK_SIZE - 1] = c;
            *byte = p;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自校验：CFB8 加密再解密应恢复原文（IV 相同）。
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello minecraft cfb8 world";
        let mut buf = plaintext.to_vec();
        Cfb8Enc::new(&key, &iv).encrypt(&mut buf);
        assert_ne!(&buf, plaintext, "ciphertext should differ from plaintext");
        Cfb8Dec::new(&key, &iv).decrypt(&mut buf);
        assert_eq!(&buf, plaintext, "decrypt should recover plaintext");
    }

    /// CFB8 是流密码：相同明文 + 不同 IV 应产生不同密文。
    #[test]
    fn different_iv_yields_different_ciphertext() {
        let key = [1u8; 16];
        let plaintext = b"abcdefghijklmnopqrstuvwxyz0123";
        let mut a = plaintext.to_vec();
        Cfb8Enc::new(&key, &[0u8; 16]).encrypt(&mut a);
        let mut b = plaintext.to_vec();
        Cfb8Enc::new(&key, &[1u8; 16]).encrypt(&mut b);
        assert_ne!(a, b);
    }

    /// 空 buf 应为 no-op。
    #[test]
    fn empty_buf_is_noop() {
        let mut buf: Vec<u8> = vec![];
        Cfb8Enc::new(&[0u8; 16], &[0u8; 16]).encrypt(&mut buf);
        assert!(buf.is_empty());
    }

    /// 单字节加密应等价于 `AES(IV)[0] XOR p`。
    #[test]
    fn single_byte_encryption_matches_definition() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let p = 0xABu8;
        // 直接 AES_encrypt(IV)[0]
        let cipher = Aes128::new(&Array::from(key));
        let mut block = Array::from(iv);
        cipher.encrypt_block(&mut block);
        let expected = p ^ block[0];
        // 用 Cfb8Enc 验证
        let mut buf = vec![p];
        Cfb8Enc::new(&key, &iv).encrypt(&mut buf);
        assert_eq!(buf[0], expected);
    }
}
