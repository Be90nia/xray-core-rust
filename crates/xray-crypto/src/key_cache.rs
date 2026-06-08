//! Key cache for AEAD encryption keys.
//!
//! Provide a key factory for AEAD ciphers.

use crate::aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead, CryptoError};

/// AEAD key type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

/// Key cache / factory for AEAD ciphers.
pub struct KeyCache {
    _private: (),
}

impl KeyCache {
    /// Create a new key cache.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Create AES-128-GCM cipher.
    pub fn create_aes128_gcm(key: &[u8]) -> Result<Aes128Gcm, CryptoError> {
        Aes128Gcm::new(key)
    }

    /// Create AES-256-GCM cipher.
    pub fn create_aes256_gcm(key: &[u8]) -> Result<Aes256Gcm, CryptoError> {
        Aes256Gcm::new(key)
    }

    /// Create ChaCha20-Poly1305 cipher.
    pub fn create_chacha20_poly1305(key: &[u8]) -> Result<ChaCha20Poly1305Aead, CryptoError> {
        ChaCha20Poly1305Aead::new(key)
    }

    /// Return key size for the given key type.
    pub fn key_type_size(kt: KeyType) -> usize {
        match kt {
            KeyType::Aes128Gcm => 16,
            KeyType::Aes256Gcm | KeyType::ChaCha20Poly1305 => 32,
        }
    }
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::AeadCipher;

    #[test]
    fn test_key_cache_new() {
        let _cache = KeyCache::new();
    }

    #[test]
    fn test_key_cache_default() {
        let _cache = KeyCache::default();
    }

    #[test]
    fn test_create_aes128_gcm() {
        let key = [0u8; 16];
        let cipher = KeyCache::create_aes128_gcm(&key).unwrap();
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), 16);
        assert_eq!(cipher.key_size(), 16);
    }

    #[test]
    fn test_create_aes256_gcm() {
        let key = [0u8; 32];
        let cipher = KeyCache::create_aes256_gcm(&key).unwrap();
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), 16);
        assert_eq!(cipher.key_size(), 32);
    }

    #[test]
    fn test_create_chacha20_poly1305() {
        let key = [0u8; 32];
        let cipher = KeyCache::create_chacha20_poly1305(&key).unwrap();
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), 16);
        assert_eq!(cipher.key_size(), 32);
    }

    #[test]
    fn test_invalid_key_length() {
        let bad_key = [0u8; 8];
        assert!(KeyCache::create_aes128_gcm(&bad_key).is_err());
        assert!(KeyCache::create_aes256_gcm(&bad_key).is_err());
        assert!(KeyCache::create_chacha20_poly1305(&bad_key).is_err());
    }

    #[test]
    fn test_key_type_sizes() {
        assert_eq!(KeyCache::key_type_size(KeyType::Aes128Gcm), 16);
        assert_eq!(KeyCache::key_type_size(KeyType::Aes256Gcm), 32);
        assert_eq!(KeyCache::key_type_size(KeyType::ChaCha20Poly1305), 32);
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = [0xABu8; 16];
        let cipher = KeyCache::create_aes128_gcm(&key).unwrap();
        let nonce = vec![0u8; 12];
        let plaintext = b"hello key cache";
        let sealed = cipher.seal(&nonce, &[], plaintext).unwrap();
        let opened = cipher.open(&nonce, &[], &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_key_type_equality() {
        assert_eq!(KeyType::Aes128Gcm, KeyType::Aes128Gcm);
        assert_ne!(KeyType::Aes128Gcm, KeyType::Aes256Gcm);
        assert_ne!(KeyType::Aes128Gcm, KeyType::ChaCha20Poly1305);
    }
}
