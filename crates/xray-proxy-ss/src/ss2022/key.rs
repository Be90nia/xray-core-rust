//! SS-2022 key derivation (blake3, SIP022)
//!
//! 参考：
//! - https://shadowsocks.org/doc/sip022.html
//! - sing-shadowsocks/shadowaead_2022/protocol.go

use crate::error::{Result, SsError};

/// SS-2022 cipher kind（SIP022 支持的 3 种 cipher）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind2022 {
    /// 2022-blake3-aes-128-gcm
    Aes128Gcm,
    /// 2022-blake3-aes-256-gcm
    Aes256Gcm,
    /// 2022-blake3-chacha20-poly1305
    ChaCha20Poly1305,
}

impl CipherKind2022 {
    /// 从 cipher 名称解析（如 "2022-blake3-aes-256-gcm"）。
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(SsError::InvalidCipherName(name.to_string())),
        }
    }

    /// PSK 长度（= key 长度）。
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// salt 长度（= key 长度，SIP022）。
    pub fn salt_size(&self) -> usize {
        self.key_size()
    }
}

/// blake3 derive session subkey。
///
/// context = "shadowsocks 2022 session subkey"
/// material = PSK || salt
///
/// 对应 Go `shadowaead_2022.SessionKey(psk, salt, keyLength)`。
pub fn derive_session_subkey(psk: &[u8], salt: &[u8], kind: CipherKind2022) -> Vec<u8> {
    const CTX: &str = "shadowsocks 2022 session subkey";
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let hash = blake3::derive_key(CTX, &material);
    hash[..kind.key_size()].to_vec()
}

/// PSK 从 base64 解码（SIP022 要求 PSK 密码学安全随机 + base64 编码）。
pub fn psk_from_base64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| SsError::InvalidPassword(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_kind_from_name() {
        assert_eq!(
            CipherKind2022::from_name("2022-blake3-aes-128-gcm").unwrap(),
            CipherKind2022::Aes128Gcm
        );
        assert_eq!(
            CipherKind2022::from_name("2022-blake3-aes-256-gcm").unwrap(),
            CipherKind2022::Aes256Gcm
        );
        assert_eq!(
            CipherKind2022::from_name("2022-blake3-chacha20-poly1305").unwrap(),
            CipherKind2022::ChaCha20Poly1305
        );
        assert!(CipherKind2022::from_name("aes-256-gcm").is_err());
    }

    #[test]
    fn key_salt_size() {
        assert_eq!(CipherKind2022::Aes128Gcm.key_size(), 16);
        assert_eq!(CipherKind2022::Aes128Gcm.salt_size(), 16);
        assert_eq!(CipherKind2022::Aes256Gcm.key_size(), 32);
        assert_eq!(CipherKind2022::Aes256Gcm.salt_size(), 32);
        assert_eq!(CipherKind2022::ChaCha20Poly1305.key_size(), 32);
    }

    #[test]
    fn session_subkey_32b_aes256() {
        let psk = vec![0xab; 32];
        let salt = vec![0xcd; 32];
        let subkey = derive_session_subkey(&psk, &salt, CipherKind2022::Aes256Gcm);
        assert_eq!(subkey.len(), 32);
        // 同输入同输出（确定性）
        let subkey2 = derive_session_subkey(&psk, &salt, CipherKind2022::Aes256Gcm);
        assert_eq!(subkey, subkey2);
        // 不同 salt 不同输出
        let salt2 = vec![0xcd; 31].iter().chain(&[0xce]).copied().collect::<Vec<_>>();
        let subkey3 = derive_session_subkey(&psk, &salt2, CipherKind2022::Aes256Gcm);
        assert_ne!(subkey, subkey3);
    }

    #[test]
    fn session_subkey_16b_aes128() {
        let psk = vec![0xab; 16];
        let salt = vec![0xcd; 16];
        let subkey = derive_session_subkey(&psk, &salt, CipherKind2022::Aes128Gcm);
        assert_eq!(subkey.len(), 16);
    }

    #[test]
    fn psk_decode() {
        // "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=" → 32 bytes (aes-256-gcm PSK)
        let psk = psk_from_base64("swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=").unwrap();
        assert_eq!(psk.len(), 32);
    }

    #[test]
    fn psk_decode_invalid() {
        assert!(psk_from_base64("!!!invalid base64!!!").is_err());
    }
}
