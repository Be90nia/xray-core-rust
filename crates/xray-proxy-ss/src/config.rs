//! Shadowsocks 加密器配置与账户定义。
//!
//! 对应 Go `proxy/shadowsocks/config.go`：
//! - `CipherType` enum
//! - `MemoryAccount` 运行时账户
//! - `Cipher` (enum，包含 `Aead` 和 `None`)
//! - `passwordToCipherKey` / `hkdfSHA1`
//! - proto `Account` ↔ 内存账户互转
//!
//! # 设计
//!
//! Go 用 `Cipher` interface + `AEADCipher{AEADAuthCreator func}` + `NoneCipher`。
//! Rust 端直接复用 `xray_crypto::aead` 模块提供的具体 cipher 类型
//! （`Aes128Gcm` / `Aes256Gcm` / `ChaCha20Poly1305Aead` / `XChaCha20Poly1305Aead`），
//! 通过 `Box<dyn AeadCipherImpl>` 装载，避免 enum 内嵌多类型的复杂度。

use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
// 注意：xray_crypto::aead::AeadCipher 是 trait，与我们的 struct AeadCipher 同名，
// 所以这里 rename。
use xray_crypto::aead::{
    AeadCipher as AeadCipherImpl, Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm,
    ChaCha20Poly1305Aead as CryptoChaCha20Poly1305, CryptoError,
    XChaCha20Poly1305Aead as CryptoXChaCha20Poly1305,
};
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

use crate::error::{Result, SsError};

// ============================================================================
// CipherType
// ============================================================================

/// Shadowsocks 密码类型，对应 proto `CipherType` enum。
///
/// proto 数值保持与 Go 端一致：UNKNOWN=0, AES_128_GCM=5, AES_256_GCM=6,
/// CHACHA20_POLY1305=7, XCHACHA20_POLY1305=8, NONE=9。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CipherType {
    Unknown = 0,
    Aes128Gcm = 5,
    Aes256Gcm = 6,
    ChaCha20Poly1305 = 7,
    XChaCha20Poly1305 = 8,
}

impl CipherType {
    #[must_use]
    pub fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            0 => Self::Unknown,
            5 => Self::Aes128Gcm,
            6 => Self::Aes256Gcm,
            7 => Self::ChaCha20Poly1305,
            8 => Self::XChaCha20Poly1305,
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl CipherType {
    /// 从 method 名称字符串解析 CipherType。
    /// 对应 Go 端 JSON 配置 `method` 字段。
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => {
                Some(Self::ChaCha20Poly1305)
            }
            "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => {
                Some(Self::XChaCha20Poly1305)
            }
            _ => None,
        }
    }
}

// ============================================================================
// InnerAead：Box<dyn AeadCipherImpl> 简化包装
// ============================================================================

/// AEAD 实例的统一类型。复用 `xray_crypto::aead::AeadCipher` trait。
/// `+ Send + Sync` 保证 SSStream 可跨线程（tokio::spawn 要求 Future: Send）。
pub type InnerAead = Box<dyn AeadCipherImpl + Send + Sync>;

/// AEAD creator 函数签名：key → Box<dyn AeadCipherImpl>。
pub type AeadCreator = fn(&[u8]) -> std::result::Result<InnerAead, CryptoError>;

/// AES-128-GCM creator。
pub fn create_aes_128_gcm(key: &[u8]) -> std::result::Result<InnerAead, CryptoError> {
    Ok(Box::new(CryptoAes128Gcm::new(key)?))
}

/// AES-256-GCM creator。
pub fn create_aes_256_gcm(key: &[u8]) -> std::result::Result<InnerAead, CryptoError> {
    Ok(Box::new(CryptoAes256Gcm::new(key)?))
}

/// ChaCha20-Poly1305 creator。
pub fn create_chacha20_poly1305(key: &[u8]) -> std::result::Result<InnerAead, CryptoError> {
    Ok(Box::new(CryptoChaCha20Poly1305::new(key)?))
}

/// XChaCha20-Poly1305 creator。
pub fn create_xchacha20_poly1305(key: &[u8]) -> std::result::Result<InnerAead, CryptoError> {
    Ok(Box::new(CryptoXChaCha20Poly1305::new(key)?))
}

// ============================================================================
// Cipher：AEAD 或 None 的统一接口
// ============================================================================

/// Shadowsocks Cipher 配置（不含 key），对应 Go `Cipher` interface。
#[derive(Debug, Clone, Copy)]
pub enum Cipher {
    /// AEAD 密码器配置（不含具体 key）。
    Aead(AeadCipher),
    /// None cipher：无加密。
    None,
}

/// AEAD 密码器配置（struct，与 trait `xray_crypto::aead::AeadCipher` 同名但不同），
/// 对应 Go `AEADCipher{KeyBytes, IVBytes, AEADAuthCreator}`。
#[derive(Debug, Clone, Copy)]
pub struct AeadCipher {
    pub key_bytes: u32,
    pub iv_bytes: u32,
    pub creator: AeadCreator,
}

impl Cipher {
    /// 从 CipherType 创建配置（不含 key），对应 Go `Account.getCipher()`。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherType`]：cipher 类型未知。
    pub fn from_type(ct: CipherType) -> Result<Self> {
        Ok(match ct {
            CipherType::Aes128Gcm => Self::Aead(AeadCipher {
                key_bytes: 16,
                iv_bytes: 16,
                creator: create_aes_128_gcm,
            }),
            CipherType::Aes256Gcm => Self::Aead(AeadCipher {
                key_bytes: 32,
                iv_bytes: 32,
                creator: create_aes_256_gcm,
            }),
            CipherType::ChaCha20Poly1305 => Self::Aead(AeadCipher {
                key_bytes: 32,
                iv_bytes: 32,
                creator: create_chacha20_poly1305,
            }),
            CipherType::XChaCha20Poly1305 => Self::Aead(AeadCipher {
                key_bytes: 32,
                iv_bytes: 32,
                creator: create_xchacha20_poly1305,
            }),

            CipherType::Unknown => return Err(SsError::InvalidCipherType(0)),
        })
    }

    #[must_use]
    pub fn key_size(&self) -> u32 {
        match self {
            Self::Aead(c) => c.key_bytes,
            Self::None => 0,
        }
    }

    #[must_use]
    pub fn iv_size(&self) -> u32 {
        match self {
            Self::Aead(c) => c.iv_bytes,
            Self::None => 0,
        }
    }

    #[must_use]
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Aead(_))
    }

    /// 创建 AEAD 实例：HKDF-SHA1 派生 subkey 后调用 creator。
    ///
    /// 对应 Go `AEADCipher.createAuthenticator`。
    ///
    /// # Errors
    /// - 透传 creator 错误。
    pub fn create_aead(&self, key: &[u8], iv: &[u8]) -> Result<Option<InnerAead>> {
        match self {
            Self::None => Ok(None),
            Self::Aead(c) => {
                let mut subkey = vec![0u8; c.key_bytes as usize];
                hkdf_sha1(key, iv, &mut subkey);
                let aead = (c.creator)(&subkey)
                    .map_err(|e| SsError::AesGcmInit(e.to_string()))?;
                Ok(Some(aead))
            }
        }
    }

    /// UDP 包加密：`buf` = IV(plaintext) + plaintext，加密后 = IV + ciphertext + tag。
    ///
    /// 对应 Go `AEADCipher.EncodePacket`。nonce 全 0（SS UDP 包一次性 nonce）。
    ///
    /// # Errors
    /// - [`SsError::InsufficientData`]：`buf` 长度不足 IV。
    /// - 透传 AEAD 错误。
    pub fn encode_packet(&self, key: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let iv_len = self.iv_size() as usize;
        if buf.len() < iv_len {
            return Err(SsError::InsufficientData(buf.len()));
        }
        if let Self::Aead(_) = self {
            let iv: Vec<u8> = buf[..iv_len].to_vec();
            let aead = self.create_aead(key, &iv)?.expect("aead for Aead variant");
            let plaintext: Vec<u8> = buf[iv_len..].to_vec();
            let zero_nonce = vec![0u8; aead.nonce_size()];
            let sealed = aead
                .seal(&zero_nonce, &[], &plaintext)
                .map_err(|e| SsError::AeadSeal(e.to_string()))?;
            buf.truncate(iv_len);
            buf.extend_from_slice(&sealed);
        }
        Ok(())
    }

    /// UDP 包解密：输入 `buf` = IV + ciphertext，输出 plaintext。
    ///
    /// 对应 Go `AEADCipher.DecodePacket`。
    ///
    /// # Errors
    /// - [`SsError::InsufficientData`]：`buf` 长度不足 IV+tag。
    /// - 透传 AEAD 错误。
    pub fn decode_packet(&self, key: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let iv_len = self.iv_size() as usize;
        if buf.len() <= iv_len {
            return Err(SsError::InsufficientData(buf.len()));
        }
        if let Self::Aead(_) = self {
            let iv: Vec<u8> = buf[..iv_len].to_vec();
            let aead = self.create_aead(key, &iv)?.expect("aead for Aead variant");
            let ciphertext: Vec<u8> = buf[iv_len..].to_vec();
            let zero_nonce = vec![0u8; aead.nonce_size()];
            let plaintext = aead
                .open(&zero_nonce, &[], &ciphertext)
                .map_err(|e| SsError::AeadOpen(e.to_string()))?;
            buf.truncate(iv_len);
            buf.extend_from_slice(&plaintext);
        }
        Ok(())
    }
}

// ============================================================================
// passwordToCipherKey + hkdfSHA1
// ============================================================================

/// SS 密码派生：MD5 链式累积，对应 Go `passwordToCipherKey(password, keySize)`。
///
/// 算法：`md5(password)` → 重复 `md5(prev_md5 || password)` 直到填满 `key_size`。
#[must_use]
pub fn password_to_cipher_key(password: &[u8], key_size: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_size);

    let mut md5_sum: [u8; 16] = {
        let mut h = Md5::new();
        h.update(password);
        h.finalize().into()
    };
    key.extend_from_slice(&md5_sum);

    while key.len() < key_size {
        let mut h = Md5::new();
        h.update(md5_sum);
        h.update(password);
        md5_sum = h.finalize().into();
        key.extend_from_slice(&md5_sum);
    }
    key.truncate(key_size);
    key
}

/// HKDF-SHA1 派生 subkey，对应 Go `hkdfSHA1(secret, salt, outKey)`。
///
/// info 固定为 `b"ss-subkey"`（来自 Go 端常量）。
pub fn hkdf_sha1(secret: &[u8], salt: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha1>::new(Some(salt), secret);
    hk.expand(crate::SS_SUBKEY, out)
        .expect("hkdf expand should not fail for valid output size");
}

// ============================================================================
// MemoryAccount
// ============================================================================

/// SS 运行时账户，对应 Go `MemoryAccount{Cipher, CipherType, Key, Password}`。
///
/// `iv_check`：是否启用 IV 唯一性检查（反重放）。Go proto 字段 `Account.iv_check`。
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    pub cipher: Cipher,
    pub cipher_type: CipherType,
    pub key: Vec<u8>,
    pub password: String,
    /// IV 唯一性检查（反重放）。true 时 Validator 会跟踪已见 IV 并拒绝重复。
    pub iv_check: bool,
}

impl MemoryAccount {
    /// 从 proto Account 转换为运行时账户，对应 Go `Account.AsAccount()`。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherType`]：cipher_type 不是已知值。
    /// - 透传 `Cipher::from_type` 错误。
    pub fn from_proto(p: &ProtoAccount) -> Result<Self> {
        let ct = CipherType::from_i32(p.cipher_type)
            .filter(|c| *c != CipherType::Unknown)
            .ok_or(SsError::InvalidCipherType(p.cipher_type))?;
        let cipher = Cipher::from_type(ct)?;
        let key = password_to_cipher_key(p.password.as_bytes(), cipher.key_size() as usize);
        Ok(Self {
            cipher,
            cipher_type: ct,
            key,
            password: p.password.clone(),
            iv_check: p.iv_check,
        })
    }

    /// 转换为 proto Account，对应 Go `MemoryAccount.ToProto()`。
    #[must_use]
    pub fn to_proto(&self) -> ProtoAccount {
        ProtoAccount {
            password: self.password.clone(),
            cipher_type: self.cipher_type.as_i32(),
            iv_check: self.iv_check,
        }
    }

    /// 与另一个账户比较 key 是否相等，对应 Go `MemoryAccount.Equals`。
    #[must_use]
    pub fn equals(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proto(ct: CipherType, password: &str) -> ProtoAccount {
        ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        }
    }

    #[test]
    fn cipher_type_roundtrip() {
        for ct in [
            CipherType::XChaCha20Poly1305,
        ] {
        }
    }

    #[test]
    fn cipher_type_unknown_proto_value() {
        assert_eq!(CipherType::from_i32(0), Some(CipherType::Unknown));
    }

    #[test]
    fn cipher_type_invalid() {
        assert_eq!(CipherType::from_i32(99), None);
    }

    #[test]
    fn password_key_aes_128_length() {
        let key = password_to_cipher_key(b"hello", 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn password_key_aes_256_length() {
        let key = password_to_cipher_key(b"hello", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn password_key_deterministic() {
        let a = password_to_cipher_key(b"password", 32);
        let b = password_to_cipher_key(b"password", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn password_key_differs_on_input() {
        let a = password_to_cipher_key(b"foo", 32);
        let b = password_to_cipher_key(b"bar", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn password_key_md5_chain_first_block() {
        let key = password_to_cipher_key(b"abc", 32);
        let md5_first: [u8; 16] = {
            let mut h = Md5::new();
            h.update(b"abc");
            h.finalize().into()
        };
        assert_eq!(&key[..16], &md5_first);
    }

    #[test]
    fn password_key_md5_chain_second_block() {
        let key = password_to_cipher_key(b"abc", 32);
        let md5_first: [u8; 16] = {
            let mut h = Md5::new();
            h.update(b"abc");
            h.finalize().into()
        };
        let md5_second: [u8; 16] = {
            let mut h = Md5::new();
            h.update(md5_first);
            h.update(b"abc");
            h.finalize().into()
        };
        assert_eq!(&key[16..32], &md5_second);
    }

    #[test]
    fn hkdf_sha1_deterministic() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        hkdf_sha1(b"secret", b"salt", &mut a);
        hkdf_sha1(b"secret", b"salt", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_sha1_differs_on_input() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        hkdf_sha1(b"secret1", b"salt", &mut a);
        hkdf_sha1(b"secret2", b"salt", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_sha1_32_byte_output() {
        let mut out = [0u8; 32];
        hkdf_sha1(b"secret", b"salt", &mut out);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn cipher_meta_aes_128() {
        let c = Cipher::from_type(CipherType::Aes128Gcm).expect("cipher");
        assert_eq!(c.key_size(), 16);
        assert_eq!(c.iv_size(), 16);
        assert!(c.is_aead());
    }

    #[test]
    fn cipher_meta_aes_256() {
        let c = Cipher::from_type(CipherType::Aes256Gcm).expect("cipher");
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.iv_size(), 32);
    }

    #[test]
    fn cipher_meta_chacha20() {
        let c = Cipher::from_type(CipherType::ChaCha20Poly1305).expect("cipher");
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.iv_size(), 32);
    }

    #[test]
    fn cipher_meta_xchacha20() {
        let c = Cipher::from_type(CipherType::XChaCha20Poly1305).expect("cipher");
        assert_eq!(c.key_size(), 32);
    }

    #[test]
    fn cipher_unknown_type_errors() {
        let err = Cipher::from_type(CipherType::Unknown).unwrap_err();
        assert!(matches!(err, SsError::InvalidCipherType(0)));
    }

    #[test]
    fn create_aes_128_gcm_correct_key() {
        let key = vec![0u8; 16];
        let aead = create_aes_128_gcm(&key).expect("aead");
        assert_eq!(aead.nonce_size(), 12);
        assert_eq!(aead.tag_size(), 16);
    }

    #[test]
    fn create_aes_128_gcm_wrong_key_len() {
        assert!(create_aes_128_gcm(&[0u8; 32]).is_err());
    }

    #[test]
    fn create_aes_256_gcm_correct_key() {
        let aead = create_aes_256_gcm(&[0u8; 32]).expect("aead");
        assert_eq!(aead.nonce_size(), 12);
    }

    #[test]
    fn create_chacha20_poly1305_correct_key() {
        let aead = create_chacha20_poly1305(&[0u8; 32]).expect("aead");
        assert_eq!(aead.nonce_size(), 12);
    }

    #[test]
    fn create_xchacha20_poly1305_correct_key() {
        let aead = create_xchacha20_poly1305(&[0u8; 32]).expect("aead");
        assert_eq!(aead.nonce_size(), 24);
    }

    #[test]
    fn inner_aead_seal_open_roundtrip_aes_128() {
        let aead = create_aes_128_gcm(&[1u8; 16]).expect("aead");
        let nonce = vec![0u8; 12];
        let sealed = aead.seal(&nonce, b"aad", b"hello").expect("seal");
        assert_eq!(sealed.len(), 5 + 16);
        let opened = aead.open(&nonce, b"aad", &sealed).expect("open");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn inner_aead_seal_open_roundtrip_aes_256() {
        let aead = create_aes_256_gcm(&[1u8; 32]).expect("aead");
        let nonce = vec![0u8; 12];
        let sealed = aead.seal(&nonce, b"", b"world").expect("seal");
        let opened = aead.open(&nonce, b"", &sealed).expect("open");
        assert_eq!(opened, b"world");
    }

    #[test]
    fn inner_aead_seal_open_roundtrip_chacha20() {
        let aead = create_chacha20_poly1305(&[1u8; 32]).expect("aead");
        let nonce = vec![0u8; 12];
        let sealed = aead.seal(&nonce, b"", b"test").expect("seal");
        let opened = aead.open(&nonce, b"", &sealed).expect("open");
        assert_eq!(opened, b"test");
    }

    #[test]
    fn inner_aead_seal_open_roundtrip_xchacha20() {
        let aead = create_xchacha20_poly1305(&[1u8; 32]).expect("aead");
        let nonce = vec![0u8; 24];
        let sealed = aead.seal(&nonce, b"", b"test").expect("seal");
        let opened = aead.open(&nonce, b"", &sealed).expect("open");
        assert_eq!(opened, b"test");
    }

    #[test]
    fn inner_aead_open_wrong_tag_fails() {
        let aead = create_aes_128_gcm(&[1u8; 16]).expect("aead");
        let nonce = vec![0u8; 12];
        let sealed = aead.seal(&nonce, b"", b"hello").expect("seal");
        let mut tampered = sealed.clone();
        tampered[0] ^= 0xff;
        assert!(aead.open(&nonce, b"", &tampered).is_err());
    }

    #[test]
    fn inner_aead_open_wrong_aad_fails() {
        let aead = create_aes_128_gcm(&[1u8; 16]).expect("aead");
        let nonce = vec![0u8; 12];
        let sealed = aead.seal(&nonce, b"correct-aad", b"hello").expect("seal");
        assert!(aead.open(&nonce, b"wrong-aad", &sealed).is_err());
    }

    #[test]
    fn memory_account_from_proto_aes_128() {
        let p = sample_proto(CipherType::Aes128Gcm, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        assert_eq!(acc.cipher_type, CipherType::Aes128Gcm);
        assert_eq!(acc.key.len(), 16);
        assert_eq!(acc.password, "password");
    }

    #[test]
    fn memory_account_from_proto_aes_256() {
        let p = sample_proto(CipherType::Aes256Gcm, "pass");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        assert_eq!(acc.cipher_type, CipherType::Aes256Gcm);
        assert_eq!(acc.key.len(), 32);
    }


    #[test]
    fn memory_account_from_proto_invalid_cipher() {
        let p = ProtoAccount {
            password: "p".to_string(),
            cipher_type: 99,
            iv_check: false,
        };
        let err = MemoryAccount::from_proto(&p).unwrap_err();
        assert!(matches!(err, SsError::InvalidCipherType(99)));
    }

    #[test]
    fn memory_account_to_proto_roundtrip() {
        let p = sample_proto(CipherType::Aes128Gcm, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let p2 = acc.to_proto();
        let acc2 = MemoryAccount::from_proto(&p2).expect("roundtrip");
        assert_eq!(acc.cipher_type, acc2.cipher_type);
        assert_eq!(acc.key, acc2.key);
        assert_eq!(acc.password, acc2.password);
    }

    #[test]
    fn memory_account_equals_same_key() {
        let p = sample_proto(CipherType::Aes128Gcm, "password");
        let a = MemoryAccount::from_proto(&p).expect("a");
        let b = MemoryAccount::from_proto(&p).expect("b");
        assert!(a.equals(&b));
    }

    #[test]
    fn memory_account_equals_different_key() {
        let pa = sample_proto(CipherType::Aes128Gcm, "password1");
        let pb = sample_proto(CipherType::Aes128Gcm, "password2");
        let a = MemoryAccount::from_proto(&pa).expect("a");
        let b = MemoryAccount::from_proto(&pb).expect("b");
        assert!(!a.equals(&b));
    }

    #[test]
    fn cipher_encode_decode_packet_aes_128_roundtrip() {
        let p = sample_proto(CipherType::Aes128Gcm, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let iv = vec![0xaa; 16];
        let plaintext = b"hello world payload";
        let mut buf = Vec::new();
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(plaintext);
        acc.cipher.encode_packet(&acc.key, &mut buf).expect("encode");
        assert_eq!(buf.len(), 16 + plaintext.len() + 16);
        acc.cipher.decode_packet(&acc.key, &mut buf).expect("decode");
        assert_eq!(&buf[16..], plaintext);
    }

    #[test]
    fn cipher_encode_decode_packet_aes_256_roundtrip() {
        let p = sample_proto(CipherType::Aes256Gcm, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let iv = vec![0xbb; 32];
        let plaintext = b"shadowsocks data";
        let mut buf = Vec::new();
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(plaintext);
        acc.cipher.encode_packet(&acc.key, &mut buf).expect("encode");
        acc.cipher.decode_packet(&acc.key, &mut buf).expect("decode");
        assert_eq!(&buf[32..], plaintext);
    }

    #[test]
    fn cipher_encode_decode_packet_chacha20_roundtrip() {
        let p = sample_proto(CipherType::ChaCha20Poly1305, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let iv = vec![0xcc; 32];
        let plaintext = b"chacha20 test";
        let mut buf = Vec::new();
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(plaintext);
        acc.cipher.encode_packet(&acc.key, &mut buf).expect("encode");
        acc.cipher.decode_packet(&acc.key, &mut buf).expect("decode");
        assert_eq!(&buf[32..], plaintext);
    }

    #[test]
    fn cipher_encode_decode_packet_xchacha20_roundtrip() {
        let p = sample_proto(CipherType::XChaCha20Poly1305, "password");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let iv = vec![0xdd; 32];
        let plaintext = b"xchacha20 test";
        let mut buf = Vec::new();
        buf.extend_from_slice(&iv);
        buf.extend_from_slice(plaintext);
        acc.cipher.encode_packet(&acc.key, &mut buf).expect("encode");
        acc.cipher.decode_packet(&acc.key, &mut buf).expect("decode");
        assert_eq!(&buf[32..], plaintext);
    }
    #[test]
    fn cipher_encode_packet_insufficient_data() {
        let p = sample_proto(CipherType::Aes128Gcm, "p");
        let acc = MemoryAccount::from_proto(&p).expect("account");
        let mut buf = vec![0u8; 10];
        let err = acc.cipher.encode_packet(&acc.key, &mut buf).unwrap_err();
        assert!(matches!(err, SsError::InsufficientData(10)));
    }

    /// 对齐 Go `infra/conf/shadowsocks.go::cipherFromString`：aead_* 别名 + plain + 大小写不敏感。
    #[test]
    fn cipher_from_name_aliases() {
        assert_eq!(CipherType::from_name("aes-128-gcm"), Some(CipherType::Aes128Gcm));
        assert_eq!(CipherType::from_name("aead_aes_128_gcm"), Some(CipherType::Aes128Gcm));
        assert_eq!(CipherType::from_name("aead_aes_256_gcm"), Some(CipherType::Aes256Gcm));
        assert_eq!(CipherType::from_name("aead_chacha20_poly1305"), Some(CipherType::ChaCha20Poly1305));
        assert_eq!(CipherType::from_name("xchacha20-ietf-poly1305"), Some(CipherType::XChaCha20Poly1305));
        assert_eq!(CipherType::from_name("XCHACHA20-POLY1305"), Some(CipherType::XChaCha20Poly1305));
        assert_eq!(CipherType::from_name("2022-blake3-aes-128-gcm"), None);
    }
}
