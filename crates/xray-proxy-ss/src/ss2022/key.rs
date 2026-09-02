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

/// 从 subkey 构造 SS-2022 AEAD cipher。
///
/// 对应 sing `Method.constructor`：3 种 2022 cipher 之一。
pub(crate) fn build_aead(kind: CipherKind2022, subkey: &[u8]) -> Result<Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>> {
    use xray_crypto::aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};
    match kind {
        CipherKind2022::Aes128Gcm => Ok(Box::new(Aes128Gcm::new(subkey)?)),
        CipherKind2022::Aes256Gcm => Ok(Box::new(Aes256Gcm::new(subkey)?)),
        CipherKind2022::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Aead::new(subkey)?)),
    }
}

/// SIP023 identity subkey context。
const IDENTITY_CTX: &str = "shadowsocks 2022 identity subkey";

/// EIH 固定长度（16 字节 AES block）。
pub const IDENTITY_HEADER_LEN: usize = 16;

/// SIP023 EIH：identity subkey = blake3::derive_key("shadowsocks 2022 identity subkey", iPSK||salt)[..key_size]。
pub fn derive_identity_subkey(ipsk: &[u8], salt: &[u8], kind: CipherKind2022) -> Vec<u8> {
    let mut material = Vec::with_capacity(ipsk.len() + salt.len());
    material.extend_from_slice(ipsk);
    material.extend_from_slice(salt);
    let hash = blake3::derive_key(IDENTITY_CTX, &material);
    hash[..kind.key_size()].to_vec()
}

/// PSK 的 identity：`blake3::hash(psk)[0..16]`（SIP023 identity header 明文）。
pub fn psk_identity(psk: &[u8]) -> [u8; IDENTITY_HEADER_LEN] {
    let h = blake3::hash(psk);
    h.as_bytes()[..IDENTITY_HEADER_LEN].try_into().unwrap()
}

/// 加密 EIH：AES-ECB 单块（SIP023 TCP identity_header）。
pub fn encrypt_identity_header(ipsk: &[u8], next_psk: &[u8], salt: &[u8], kind: CipherKind2022) -> Result<[u8; IDENTITY_HEADER_LEN]> {
    let plaintext = psk_identity(next_psk);
    ecb_block(kind, &derive_identity_subkey(ipsk, salt, kind), &plaintext, true)
}

/// 解密 EIH：AES-ECB 单块。返回 16B 明文（下一层 PSK 的 hash 前 16 字节）。
pub fn decrypt_identity_header(ipsk: &[u8], header: &[u8], salt: &[u8], kind: CipherKind2022) -> Result<[u8; IDENTITY_HEADER_LEN]> {
    let block: [u8; IDENTITY_HEADER_LEN] = header.try_into().map_err(|_| SsError::InsufficientData(header.len()))?;
    ecb_block(kind, &derive_identity_subkey(ipsk, salt, kind), &block, false)
}

/// AES-ECB 单块加/解密。128 cipher 用 AES-128，256/chacha 用 AES-256。
pub fn ecb_block(kind: CipherKind2022, key: &[u8], block: &[u8; 16], encrypt: bool) -> Result<[u8; 16]> {
    use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    let mut buf = *block;
    let enc = |buf: &mut [u8; 16]| -> Result<()> {
        match (kind, encrypt) {
            (CipherKind2022::Aes128Gcm, true) => {
                let k: [u8; 16] = key[..16].try_into().unwrap();
                let arr: Array<u8, _> = k.into();
                let mut b: Array<u8, _> = (*buf).into();
                aes::Aes128::new(&arr).encrypt_block(&mut b);
                *buf = b.into();
            }
            (CipherKind2022::Aes128Gcm, false) => {
                let k: [u8; 16] = key[..16].try_into().unwrap();
                let arr: Array<u8, _> = k.into();
                let mut b: Array<u8, _> = (*buf).into();
                aes::Aes128::new(&arr).decrypt_block(&mut b);
                *buf = b.into();
            }
            (_, true) => {
                let k: [u8; 32] = key[..32].try_into().unwrap();
                let arr: Array<u8, _> = k.into();
                let mut b: Array<u8, _> = (*buf).into();
                aes::Aes256::new(&arr).encrypt_block(&mut b);
                *buf = b.into();
            }
            (_, false) => {
                let k: [u8; 32] = key[..32].try_into().unwrap();
                let arr: Array<u8, _> = k.into();
                let mut b: Array<u8, _> = (*buf).into();
                aes::Aes256::new(&arr).decrypt_block(&mut b);
                *buf = b.into();
            }
        }
        Ok(())
    };
    enc(&mut buf)?;
    Ok(buf)
}

/// 把用户提供的 PSK 规整为 cipher 所需的 key 长度。
///
/// 对应 sing-shadowsocks `shadowaead_2022.Key(key, keyLength)`：
/// - 等长：原样返回
/// - 太长：SHA-256 后截断到 `kind.key_size()`（sing-shadowsocks Go 行为）
/// - 太短：报错
///
/// 这允许用户在 aes-128-gcm (16B) 配置下提供 32B PSK——sing-shadowsocks 测试里
/// `rand.Read(password)` 永远是 32 字节就靠这条规则通过。
pub fn derive_psk(psk: &[u8], kind: CipherKind2022) -> Result<Vec<u8>> {
    let want = kind.key_size();
    if psk.len() == want {
        Ok(psk.to_vec())
    } else if psk.len() > want {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(psk);
        Ok(h.finalize()[..want].to_vec())
    } else {
        Err(SsError::InvalidPassword(format!(
            "PSK length {} < key_size {}",
            psk.len(),
            want
        )))
    }
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

    #[test]
    fn derive_psk_exact_length_passthrough() {
        // 16B PSK + aes-128-gcm（key_size 16）→ 原样返回
        let psk = vec![0xAAu8; 16];
        let got = derive_psk(&psk, CipherKind2022::Aes128Gcm).unwrap();
        assert_eq!(got, psk);
    }

    #[test]
    fn derive_psk_too_long_sha256_truncates() {
        // #26 URI 场景：32B PSK + aes-128-gcm → SHA-256 截断到 16B
        let psk = vec![0xBBu8; 32];
        let got = derive_psk(&psk, CipherKind2022::Aes128Gcm).unwrap();
        assert_eq!(got.len(), 16);
        // 等价手算 SHA-256(psk)[..16]
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&psk);
        assert_eq!(got, h.finalize()[..16].to_vec());
    }

    #[test]
    fn derive_psk_too_long_chacha_passthrough() {
        // chacha20-poly1305 key_size=32；32B PSK 直接返回
        let psk = vec![0xCCu8; 32];
        let got = derive_psk(&psk, CipherKind2022::ChaCha20Poly1305).unwrap();
        assert_eq!(got, psk);
    }

    #[test]
    fn derive_psk_too_short_errors() {
        // aes-128-gcm 需要 16B，输入 8B → 报错
        let psk = vec![0u8; 8];
        assert!(derive_psk(&psk, CipherKind2022::Aes128Gcm).is_err());
    }
}
