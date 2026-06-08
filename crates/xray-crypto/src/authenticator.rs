//! Authenticator trait and implementations.
//!
//! 对应 Go 版本 `common/crypto/auth.go`，定义认证加密接口和 AEAD 实现。
//!
//! # 核心类型
//!
//! - [`Authenticator`] — 认证加密接口（Nonce + Overhead + Open/Seal）
//! - [`AEADAuthenticator`] — 基于 AeadCipher 的实现
//! - [`BytesGenerator`] — 字节生成器（nonce/aad 生成）

use crate::aead::{AeadCipher, CryptoError};
use std::sync::Mutex;

// ========== BytesGenerator ==========

/// 字节生成器函数类型。
///
/// 对应 Go 版本的 `BytesGenerator func() []byte`。
/// 使用 `Mutex<Vec<u8>>` 实现内部可变性，支持递增 nonce 等有状态生成器。
/// `Send + Sync` 保证线程安全。
pub type BytesGenerator = Box<dyn Fn() -> Vec<u8> + Send + Sync>;

/// 创建空字节生成器。
///
/// 对应 Go 版本的 `GenerateEmptyBytes()`。
pub fn generate_empty_bytes() -> BytesGenerator {
    Box::new(|| Vec::new())
}

/// 创建静态字节生成器。
///
/// 对应 Go 版本的 `GenerateStaticBytes(content)`。
pub fn generate_static_bytes(content: Vec<u8>) -> BytesGenerator {
    Box::new(move || content.clone())
}

/// 创建递增 nonce 生成器。
///
/// 对应 Go 版本的 `GenerateIncreasingNonce(nonce)`。
/// 每次调用递增，与 Go 的 `for i := range c { c[i]++; if c[i] != 0 { break } }` 一致。
pub fn generate_increasing_nonce(nonce: Vec<u8>) -> BytesGenerator {
    let state = Mutex::new(nonce);
    Box::new(move || {
        let mut current = state.lock().unwrap();
        for b in current.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        current.clone()
    })
}

/// 创建指定大小的 AEAD nonce 生成器。
///
/// 对应 Go 版本的 `GenerateAEADNonceWithSize(nonceSize)`。
/// 初始值为全 `0xFF`，然后递增。
pub fn generate_aead_nonce_with_size(nonce_size: usize) -> BytesGenerator {
    let initial = vec![0xFFu8; nonce_size];
    generate_increasing_nonce(initial)
}

// ========== Authenticator ==========

/// 认证加密接口。
///
/// 对应 Go 版本的 `Authenticator` 接口。
pub trait Authenticator: Send + Sync {
    /// 返回 nonce 所需的字节长度。
    fn nonce_size(&self) -> usize;

    /// 返回认证标签的字节长度（密文比明文多出的部分）。
    fn overhead(&self) -> usize;

    /// 解密并验证密文。
    fn open(&self, dst: &mut [u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// 加密并认证明文。
    fn seal(&self, dst: &mut [u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// ========== AEADAuthenticator ==========

/// 基于 AEAD 的认证器实现。
///
/// 对应 Go 版本的 `AEADAuthenticator`。
pub struct AEADAuthenticator<A: AeadCipher + Send + Sync> {
    cipher: A,
    nonce_generator: BytesGenerator,
    additional_data_generator: Option<BytesGenerator>,
}

impl<A: AeadCipher + Send + Sync> AEADAuthenticator<A> {
    /// 创建新的 AEAD 认证器。
    pub fn new(
        cipher: A,
        nonce_generator: BytesGenerator,
        additional_data_generator: Option<BytesGenerator>,
    ) -> Self {
        Self {
            cipher,
            nonce_generator,
            additional_data_generator,
        }
    }
}

impl<A: AeadCipher + Send + Sync> Authenticator for AEADAuthenticator<A> {
    fn nonce_size(&self) -> usize {
        self.cipher.nonce_size()
    }

    fn overhead(&self) -> usize {
        self.cipher.tag_size()
    }

    fn open(&self, _dst: &mut [u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = (self.nonce_generator)();
        if iv.len() != self.cipher.nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: self.cipher.nonce_size(),
                actual: iv.len(),
            });
        }
        let aad = self
            .additional_data_generator
            .as_ref()
            .map(|g| g())
            .unwrap_or_default();
        self.cipher.open(&iv, &aad, ciphertext)
    }

    fn seal(&self, _dst: &mut [u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = (self.nonce_generator)();
        if iv.len() != self.cipher.nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: self.cipher.nonce_size(),
                actual: iv.len(),
            });
        }
        let aad = self
            .additional_data_generator
            .as_ref()
            .map(|g| g())
            .unwrap_or_default();
        self.cipher.seal(&iv, &aad, plaintext)
    }
}

// ========== DynamicAEADAuthenticator ==========

/// 动态分发的 AEAD 认证器。
pub struct DynamicAEADAuthenticator {
    cipher: Box<dyn AeadCipher + Send + Sync>,
    nonce_generator: BytesGenerator,
    additional_data_generator: Option<BytesGenerator>,
}

impl DynamicAEADAuthenticator {
    /// 创建新的动态 AEAD 认证器。
    pub fn new(
        cipher: Box<dyn AeadCipher + Send + Sync>,
        nonce_generator: BytesGenerator,
        additional_data_generator: Option<BytesGenerator>,
    ) -> Self {
        Self {
            cipher,
            nonce_generator,
            additional_data_generator,
        }
    }
}

impl Authenticator for DynamicAEADAuthenticator {
    fn nonce_size(&self) -> usize {
        self.cipher.nonce_size()
    }

    fn overhead(&self) -> usize {
        self.cipher.tag_size()
    }

    fn open(&self, _dst: &mut [u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = (self.nonce_generator)();
        let expected = self.cipher.nonce_size();
        if iv.len() != expected {
            return Err(CryptoError::InvalidNonceLength {
                expected,
                actual: iv.len(),
            });
        }
        let aad = self
            .additional_data_generator
            .as_ref()
            .map(|g| g())
            .unwrap_or_default();
        self.cipher.open(&iv, &aad, ciphertext)
    }

    fn seal(&self, _dst: &mut [u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = (self.nonce_generator)();
        let expected = self.cipher.nonce_size();
        if iv.len() != expected {
            return Err(CryptoError::InvalidNonceLength {
                expected,
                actual: iv.len(),
            });
        }
        let aad = self
            .additional_data_generator
            .as_ref()
            .map(|g| g())
            .unwrap_or_default();
        self.cipher.seal(&iv, &aad, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};

    #[test]
    fn test_generate_empty_bytes() {
        let generator = generate_empty_bytes();
        assert!(generator().is_empty());
        assert!(generator().is_empty());
    }

    #[test]
    fn test_generate_static_bytes() {
        let content = vec![1, 2, 3, 4, 5];
        let generator = generate_static_bytes(content.clone());
        assert_eq!(generator(), content);
        assert_eq!(generator(), content);
    }

    #[test]
    fn test_generate_increasing_nonce() {
        // Go: for i := range c { c[i]++; if c[i] != 0 { break } }
        // 索引0先递增（小端序）
        let generator = generate_increasing_nonce(vec![0u8, 0u8, 0u8]);
        assert_eq!(generator(), vec![1, 0, 0]);
        assert_eq!(generator(), vec![2, 0, 0]);
        assert_eq!(generator(), vec![3, 0, 0]);
    }

    #[test]
    fn test_generate_increasing_nonce_overflow() {
        // [0xFF, 0xFF]: c[0]++ = 0x00, c[0]==0 so continue; c[1]++ = 0x00, c[1]==0 so continue
        // 结果: [0x00, 0x00]（全部溢出归零）
        let generator = generate_increasing_nonce(vec![0xFF, 0xFF]);
        assert_eq!(generator(), vec![0x00, 0x00]);
        // 下一次: [0x01, 0x00]
        assert_eq!(generator(), vec![0x01, 0x00]);
    }

    #[test]
    fn test_generate_increasing_nonce_single_byte() {
        let generator = generate_increasing_nonce(vec![254u8]);
        assert_eq!(generator(), vec![255u8]);
        assert_eq!(generator(), vec![0u8]);
        assert_eq!(generator(), vec![1u8]);
    }

    #[test]
    fn test_generate_aead_nonce_with_size() {
        let generator = generate_aead_nonce_with_size(12);
        let n1 = generator();
        assert_eq!(n1.len(), 12);
        // 初始 [0xFF; 12] 递增一次: 全部变为 [0x00; 12]（溢出进位）
        assert_eq!(n1, vec![0u8; 12]);
        let n2 = generator();
        // [0x00; 12] + 1 = [0x01, 0x00, ..., 0x00]（索引0先递增）
        assert_eq!(n2[0], 1u8);
        assert_eq!(&n2[1..12], &[0u8; 11][..]);
    }

    #[test]
    fn test_auth_nonce_size() {
        let c = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth = AEADAuthenticator::new(c, generate_aead_nonce_with_size(12), None);
        assert_eq!(auth.nonce_size(), 12);
    }

    #[test]
    fn test_auth_overhead() {
        let c = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth = AEADAuthenticator::new(c, generate_aead_nonce_with_size(12), None);
        assert_eq!(auth.overhead(), 16);
    }

    #[test]
    fn test_auth_seal_open_roundtrip() {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_s = AEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), None);
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_o = AEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), None);
        let sealed = auth_s.seal(&mut [], b"hello world").unwrap();
        assert_eq!(sealed.len(), 11 + 16);
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn test_auth_with_aad() {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let aad = generate_static_bytes(vec![1, 2, 3, 4]);
        let auth_s = AEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), Some(aad));
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let aad2 = generate_static_bytes(vec![1, 2, 3, 4]);
        let auth_o = AEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), Some(aad2));
        let sealed = auth_s.seal(&mut [], b"test aad").unwrap();
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert_eq!(opened, b"test aad");
    }

    #[test]
    fn test_auth_wrong_aad_fails() {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_s = AEADAuthenticator::new(
            c1,
            generate_static_bytes(vec![0u8; 12]),
            Some(generate_static_bytes(vec![1, 2, 3])),
        );
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_o = AEADAuthenticator::new(
            c2,
            generate_static_bytes(vec![0u8; 12]),
            Some(generate_static_bytes(vec![9, 9, 9])),
        );
        let sealed = auth_s.seal(&mut [], b"secret").unwrap();
        assert!(auth_o.open(&mut [], &sealed).is_err());
    }

    #[test]
    fn test_auth_invalid_nonce_size() {
        let c = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth = AEADAuthenticator::new(c, generate_static_bytes(vec![0u8; 8]), None);
        let r = auth.seal(&mut [], b"test");
        assert!(matches!(
            r,
            Err(CryptoError::InvalidNonceLength { expected: 12, actual: 8 })
        ));
    }

    #[test]
    fn test_auth_aes256_roundtrip() {
        let c1 = Aes256Gcm::new(&[0u8; 32]).unwrap();
        let auth_s = AEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), None);
        let c2 = Aes256Gcm::new(&[0u8; 32]).unwrap();
        let auth_o = AEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), None);
        let sealed = auth_s.seal(&mut [], b"aes256").unwrap();
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert_eq!(opened, b"aes256");
    }

    #[test]
    fn test_auth_chacha20_roundtrip() {
        let c1 = ChaCha20Poly1305Aead::new(&[0u8; 32]).unwrap();
        let auth_s = AEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), None);
        let c2 = ChaCha20Poly1305Aead::new(&[0u8; 32]).unwrap();
        let auth_o = AEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), None);
        let sealed = auth_s.seal(&mut [], b"chacha20").unwrap();
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert_eq!(opened, b"chacha20");
    }

    #[test]
    fn test_auth_empty_plaintext() {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_s = AEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), None);
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_o = AEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), None);
        let sealed = auth_s.seal(&mut [], &[]).unwrap();
        assert_eq!(sealed.len(), 16);
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn test_dynamic_auth_roundtrip() {
        let c1: Box<dyn AeadCipher + Send + Sync> =
            Box::new(Aes128Gcm::new(&[0u8; 16]).unwrap());
        let auth_s = DynamicAEADAuthenticator::new(c1, generate_static_bytes(vec![0u8; 12]), None);
        let c2: Box<dyn AeadCipher + Send + Sync> =
            Box::new(Aes128Gcm::new(&[0u8; 16]).unwrap());
        let auth_o = DynamicAEADAuthenticator::new(c2, generate_static_bytes(vec![0u8; 12]), None);
        let sealed = auth_s.seal(&mut [], b"dynamic").unwrap();
        let opened = auth_o.open(&mut [], &sealed).unwrap();
        assert_eq!(opened, b"dynamic");
    }
}