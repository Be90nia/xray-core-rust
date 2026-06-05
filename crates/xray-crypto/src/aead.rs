//! AEAD (Authenticated Encryption with Associated Data) and stream
//! cipher implementations for Xray-core.
//!
//! This module provides:
//! - **AES-GCM**: Authenticated encryption via ring (hot path)
//! - **AES-CFB**: Stream cipher encryption/decryption via RustCrypto
//! - **AES-CTR**: Counter mode stream cipher via RustCrypto
//! - **ChaCha20**: Stream cipher via RustCrypto
//! - **ChaCha20-Poly1305**: AEAD via RustCrypto
//! - **XChaCha20-Poly1305**: AEAD with extended nonce via RustCrypto
//!
//! # Design
//!
//! The implementation follows the Go `common/crypto` API:
//! - `NewAesGcm(key)` -> AEAD cipher
//! - `NewAesEncryptionStream(key, iv)` -> CFB encryptor
//! - `NewAesDecryptionStream(key, iv)` -> CFB decryptor
//! - `NewAesCtrStream(key, iv)` -> CTR stream
//! - `NewChaCha20Stream(key, iv)` -> ChaCha20 stream
//!
//! # Security
//!
//! - AES-128 requires 16-byte keys, AES-256 requires 32-byte keys
//! - GCM nonces must be 12 bytes
//! - CFB/CTR IVs must be 16 bytes
//! - ChaCha20 keys must be 32 bytes, nonces 8 or 12 bytes
//! - ChaCha20-Poly1305 nonces must be 12 bytes
//! - XChaCha20-Poly1305 nonces must be 24 bytes
//! - All public APIs return `Result` instead of panicking

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes256};
use cfb_mode::{
    BufDecryptor as CfbDecryptor, BufEncryptor as CfbEncryptor,
};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use ctr::Ctr128BE;
use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM,
};

/// Cryptographic operation errors.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key length (expected 16 or 32 bytes).
    #[error("invalid key length: expected 16 or 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Invalid nonce/IV length.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length provided.
        actual: usize,
    },

    /// AEAD authentication failed during decryption.
    #[error("authentication failed: ciphertext may be corrupted or tampered")]
    AuthenticationFailed,

    /// Encryption operation failed.
    #[error("encryption error: {0}")]
    EncryptionError(String),
}

/// AEAD cipher trait for authenticated encryption.
///
/// Provides seal (encrypt+authenticate) and open (decrypt+verify)
/// operations with associated data support.
pub trait AeadCipher {
    /// Returns the required nonce size in bytes.
    fn nonce_size() -> usize;

    /// Returns the authentication tag size in bytes.
    fn tag_size() -> usize;

    /// Returns the required key size in bytes.
    fn key_size() -> usize;

    /// Encrypts and authenticates `plaintext` with `nonce` and
    /// `aad`.
    ///
    /// Returns ciphertext with authentication tag appended.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidNonceLength` if nonce size is
    /// incorrect.
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Decrypts and verifies `ciphertext` with `nonce` and `aad`.
    ///
    /// The `ciphertext` must include the authentication tag.
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidNonceLength` if nonce size is
    ///   incorrect.
    /// - `CryptoError::AuthenticationFailed` if tag verification
    ///   fails.
    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

// ---------------------------------------------------------------------------
// AES-GCM (ring backend)
// ---------------------------------------------------------------------------

/// AES-128-GCM authenticated cipher (ring backend).
///
/// Provides high-performance authenticated encryption suitable for
/// transport layer security (TLS) and VPN protocols.
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{AeadCipher, Aes128Gcm, CryptoError};
///
/// let key = [0u8; 16];
/// let nonce = [0u8; 12];
/// let aad = b"additional data";
/// let plaintext = b"secret message";
///
/// let cipher = Aes128Gcm::new(&key)?;
/// let ciphertext = cipher.seal(&nonce, aad, plaintext)?;
/// let decrypted = cipher.open(&nonce, aad, &ciphertext)?;
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub struct Aes128Gcm {
    key: LessSafeKey,
}

impl Aes128Gcm {
    /// Creates a new AES-128-GCM cipher.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if key is not 16
    /// bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let unbound = UnboundKey::new(&AES_128_GCM, key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }
}

impl AeadCipher for Aes128Gcm {
    #[inline]
    fn nonce_size() -> usize {
        12
    }

    #[inline]
    fn tag_size() -> usize {
        16
    }

    #[inline]
    fn key_size() -> usize {
        16
    }

    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let ring_nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        let ring_aad = Aad::from(aad);
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(ring_nonce, ring_aad, &mut in_out)
            .map_err(|_| {
                CryptoError::EncryptionError("seal failed".into())
            })?;
        Ok(in_out)
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let ring_nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        let ring_aad = Aad::from(aad);
        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(ring_nonce, ring_aad, &mut in_out)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(plaintext.to_vec())
    }
}

/// AES-256-GCM authenticated cipher (ring backend).
///
/// Provides high-security authenticated encryption with 256-bit
/// keys.
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{AeadCipher, Aes256Gcm, CryptoError};
///
/// let key = [0u8; 32];
/// let nonce = [0u8; 12];
/// let aad = b"additional data";
/// let plaintext = b"secret message";
///
/// let cipher = Aes256Gcm::new(&key)?;
/// let ciphertext = cipher.seal(&nonce, aad, plaintext)?;
/// let decrypted = cipher.open(&nonce, aad, &ciphertext)?;
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub struct Aes256Gcm {
    key: LessSafeKey,
}

impl Aes256Gcm {
    /// Creates a new AES-256-GCM cipher.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if key is not 32
    /// bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }
}

impl AeadCipher for Aes256Gcm {
    #[inline]
    fn nonce_size() -> usize {
        12
    }

    #[inline]
    fn tag_size() -> usize {
        16
    }

    #[inline]
    fn key_size() -> usize {
        32
    }

    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let ring_nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        let ring_aad = Aad::from(aad);
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(ring_nonce, ring_aad, &mut in_out)
            .map_err(|_| {
                CryptoError::EncryptionError("seal failed".into())
            })?;
        Ok(in_out)
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let ring_nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        let ring_aad = Aad::from(aad);
        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(ring_nonce, ring_aad, &mut in_out)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(plaintext.to_vec())
    }
}

// ---------------------------------------------------------------------------
// AES-CFB (RustCrypto backend)
// ---------------------------------------------------------------------------

/// AES-CFB encryption stream (RustCrypto backend).
///
/// Cipher Feedback mode provides self-synchronizing stream
/// encryption. Each block's ciphertext feeds into the next
/// block's encryption.
///
/// Supports both AES-128 (16-byte key) and AES-256 (32-byte key).
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{
///     AesCfbEncryptor, AesCfbDecryptor, CryptoError,
/// };
///
/// let key = [0u8; 16];
/// let iv = [0u8; 16];
/// let plaintext = b"secret message";
///
/// let mut encryptor = AesCfbEncryptor::new(&key, &iv)?;
/// let mut ciphertext = plaintext.to_vec();
/// encryptor.encrypt(&mut ciphertext);
///
/// let mut decryptor = AesCfbDecryptor::new(&key, &iv)?;
/// decryptor.decrypt(&mut ciphertext);
/// assert_eq!(plaintext.as_slice(), ciphertext.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub enum AesCfbEncryptor {
    /// AES-128-CFB encryptor.
    Aes128(CfbEncryptor<Aes128>),
    /// AES-256-CFB encryptor.
    Aes256(CfbEncryptor<Aes256>),
}

impl AesCfbEncryptor {
    /// Creates a new AES-CFB encryptor.
    ///
    /// Selects AES-128 or AES-256 based on key length.
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidKeyLength` if key is not 16 or 32
    ///   bytes.
    /// - `CryptoError::InvalidNonceLength` if IV is not 16 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        match key.len() {
            16 => {
                let cipher = CfbEncryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| {
                        CryptoError::EncryptionError(e.to_string())
                    })?;
                Ok(Self::Aes128(cipher))
            }
            32 => {
                let cipher = CfbEncryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| {
                        CryptoError::EncryptionError(e.to_string())
                    })?;
                Ok(Self::Aes256(cipher))
            }
            _ => Err(CryptoError::InvalidKeyLength(key.len())),
        }
    }

    /// Encrypts data in-place.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128(c) => c.encrypt(data),
            Self::Aes256(c) => c.encrypt(data),
        }
    }
}

/// AES-CFB decryption stream (RustCrypto backend).
///
/// Supports both AES-128 (16-byte key) and AES-256 (32-byte key).
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{
///     AesCfbEncryptor, AesCfbDecryptor, CryptoError,
/// };
///
/// let key = [0u8; 16];
/// let iv = [0u8; 16];
/// let plaintext = b"secret message";
///
/// let mut encryptor = AesCfbEncryptor::new(&key, &iv)?;
/// let mut ciphertext = plaintext.to_vec();
/// encryptor.encrypt(&mut ciphertext);
///
/// let mut decryptor = AesCfbDecryptor::new(&key, &iv)?;
/// decryptor.decrypt(&mut ciphertext);
/// assert_eq!(plaintext.as_slice(), ciphertext.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub enum AesCfbDecryptor {
    /// AES-128-CFB decryptor.
    Aes128(CfbDecryptor<Aes128>),
    /// AES-256-CFB decryptor.
    Aes256(CfbDecryptor<Aes256>),
}

impl AesCfbDecryptor {
    /// Creates a new AES-CFB decryptor.
    ///
    /// Selects AES-128 or AES-256 based on key length.
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidKeyLength` if key is not 16 or 32
    ///   bytes.
    /// - `CryptoError::InvalidNonceLength` if IV is not 16 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        match key.len() {
            16 => {
                let cipher = CfbDecryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| {
                        CryptoError::EncryptionError(e.to_string())
                    })?;
                Ok(Self::Aes128(cipher))
            }
            32 => {
                let cipher = CfbDecryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| {
                        CryptoError::EncryptionError(e.to_string())
                    })?;
                Ok(Self::Aes256(cipher))
            }
            _ => Err(CryptoError::InvalidKeyLength(key.len())),
        }
    }

    /// Decrypts data in-place.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128(c) => c.decrypt(data),
            Self::Aes256(c) => c.decrypt(data),
        }
    }
}
// ---------------------------------------------------------------------------
// AES-CTR (RustCrypto backend)
// ---------------------------------------------------------------------------

/// AES-CTR stream cipher (RustCrypto backend).
///
/// Counter mode turns a block cipher into a stream cipher by
/// encrypting successive counter values. Same operation for
/// encryption and decryption (XOR with keystream).
///
/// Supports both AES-128 (16-byte key) and AES-256 (32-byte key).
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{AesCtrStream, CryptoError};
///
/// let key = [0u8; 16];
/// let iv = [0u8; 16];
/// let plaintext = b"secret message";
///
/// let mut cipher = AesCtrStream::new(&key, &iv)?;
/// let mut data = plaintext.to_vec();
/// cipher.apply_keystream(&mut data);
///
/// // Decrypt by applying keystream again
/// let mut cipher2 = AesCtrStream::new(&key, &iv)?;
/// cipher2.apply_keystream(&mut data);
/// assert_eq!(plaintext.as_slice(), data.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub enum AesCtrStream {
    /// AES-128-CTR stream cipher.
    Aes128(Ctr128BE<Aes128>),
    /// AES-256-CTR stream cipher.
    Aes256(Ctr128BE<Aes256>),
}

impl AesCtrStream {
    /// Creates a new AES-CTR stream cipher.
    ///
    /// Selects AES-128 or AES-256 based on key length.
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidKeyLength` if key is not 16 or 32
    ///   bytes.
    /// - `CryptoError::InvalidNonceLength` if IV is not 16 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        match key.len() {
            16 => {
                let cipher =
                    Ctr128BE::<Aes128>::new_from_slices(key, iv)
                        .map_err(|e| {
                            CryptoError::EncryptionError(e.to_string())
                        })?;
                Ok(Self::Aes128(cipher))
            }
            32 => {
                let cipher =
                    Ctr128BE::<Aes256>::new_from_slices(key, iv)
                        .map_err(|e| {
                            CryptoError::EncryptionError(e.to_string())
                        })?;
                Ok(Self::Aes256(cipher))
            }
            _ => Err(CryptoError::InvalidKeyLength(key.len())),
        }
    }

    /// Applies the keystream to data (XOR operation).
    ///
    /// Same operation for encryption and decryption.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128(c) => c.apply_keystream(data),
            Self::Aes256(c) => c.apply_keystream(data),
        }
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 Stream Cipher (RustCrypto backend)
// ---------------------------------------------------------------------------

/// ChaCha20 stream cipher (RustCrypto backend).
///
/// Provides XOR keystream encryption/decryption, corresponding to
/// Go `common/crypto/chacha20.go`'s `NewChaCha20Stream`.
///
/// # Nonce formats
///
/// - 12-byte nonce: IETF RFC 8439 standard format
/// - 8-byte nonce: Legacy Bernstein format (padded to 12 bytes
///   internally with 4 zero bytes prepended)
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{ChaCha20Stream, CryptoError};
///
/// let key = [0x42u8; 32];
/// let nonce = [0x24u8; 12];
/// let mut stream = ChaCha20Stream::new(&key, &nonce)?;
///
/// let mut data = b"hello world".to_vec();
/// stream.xor_key_stream(&mut data);
///
/// // Decrypt by applying the same keystream
/// let mut stream2 = ChaCha20Stream::new(&key, &nonce)?;
/// stream2.xor_key_stream(&mut data);
/// assert_eq!(b"hello world".as_slice(), data.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub struct ChaCha20Stream {
    inner: ChaCha20,
}

/// ChaCha20 key size in bytes.
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 standard nonce size (IETF RFC 8439).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20 legacy nonce size (original Bernstein format).
pub const CHACHA20_LEGACY_NONCE_SIZE: usize = 8;

/// ChaCha20-Poly1305 nonce size in bytes.
pub const CHACHA20POLY1305_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 nonce size in bytes.
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size in bytes.
pub const POLY1305_TAG_SIZE: usize = 16;

impl ChaCha20Stream {
    /// Creates a new ChaCha20 stream cipher.
    ///
    /// Corresponds to Go `NewChaCha20Stream(key, iv)`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidKeyLength` if key is not 32 bytes
    /// - `CryptoError::InvalidNonceLength` if nonce is not 8 or 12
    ///   bytes
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }

        match nonce.len() {
            CHACHA20_NONCE_SIZE => {
                let cipher = ChaCha20::new_from_slices(key, nonce)
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                Ok(Self { inner: cipher })
            }
            CHACHA20_LEGACY_NONCE_SIZE => {
                // 8-byte nonce padded to 12 bytes:
                // [0, 0, 0, 0] + nonce[0..8]
                let mut padded = [0u8; CHACHA20_NONCE_SIZE];
                padded[4..].copy_from_slice(nonce);
                let cipher = ChaCha20::new_from_slices(key, &padded)
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                Ok(Self { inner: cipher })
            }
            _ => Err(CryptoError::InvalidNonceLength {
                expected: CHACHA20_NONCE_SIZE,
                actual: nonce.len(),
            }),
        }
    }

    /// Applies XOR keystream to data in-place.
    ///
    /// Corresponds to Go `cipher.Stream.XORKeyStream`.
    /// ChaCha20 is symmetric: encryption and decryption use the
    /// same operation.
    pub fn xor_key_stream(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }

    /// Applies XOR keystream from `src` to `dst`.
    ///
    /// When `dst` and `src` point to the same buffer, this is
    /// equivalent to [`xor_key_stream`].
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EncryptionError` if `dst` is shorter
    /// than `src`.
    pub fn xor_key_stream_b2b(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<(), CryptoError> {
        if dst.len() < src.len() {
            return Err(CryptoError::EncryptionError(
                "destination buffer too short".into(),
            ));
        }
        self.inner.apply_keystream_b2b(src, dst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RustCrypto backend)
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 authenticated cipher (RustCrypto backend).
///
/// Provides authenticated encryption with a 12-byte nonce and
/// 16-byte authentication tag.
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{
///     AeadCipher, ChaCha20Poly1305Aead, CryptoError,
/// };
///
/// let key = [0x42u8; 32];
/// let cipher = ChaCha20Poly1305Aead::new(&key)?;
/// let nonce = [0u8; 12];
///
/// let sealed = cipher.seal(&nonce, b"aad", b"secret")?;
/// let opened = cipher.open(&nonce, b"aad", &sealed)?;
/// assert_eq!(b"secret".as_slice(), opened.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub struct ChaCha20Poly1305Aead {
    inner: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Aead {
    /// Creates a new ChaCha20-Poly1305 AEAD cipher.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if key is not 32
    /// bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let inner = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
        Ok(Self { inner })
    }
}

impl AeadCipher for ChaCha20Poly1305Aead {
    #[inline]
    fn nonce_size() -> usize {
        CHACHA20POLY1305_NONCE_SIZE
    }

    #[inline]
    fn tag_size() -> usize {
        POLY1305_TAG_SIZE
    }

    #[inline]
    fn key_size() -> usize {
        CHACHA20_KEY_SIZE
    }

    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let nonce_arr: chacha20poly1305::Nonce = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            })?;
        self.inner
            .encrypt(
                &nonce_arr,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let nonce_arr: chacha20poly1305::Nonce = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            })?;
        self.inner
            .decrypt(
                &nonce_arr,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 AEAD (RustCrypto backend)
// ---------------------------------------------------------------------------

/// XChaCha20-Poly1305 authenticated cipher (RustCrypto backend).
///
/// Provides authenticated encryption with an extended 24-byte nonce,
/// reducing collision probability without requiring a global nonce
/// counter.
///
/// # Example
///
/// ```
/// use xray_crypto::aead::{
///     AeadCipher, XChaCha20Poly1305Aead, CryptoError,
/// };
///
/// let key = [0x42u8; 32];
/// let cipher = XChaCha20Poly1305Aead::new(&key)?;
/// let nonce = [0u8; 24];
///
/// let sealed = cipher.seal(&nonce, b"aad", b"secret")?;
/// let opened = cipher.open(&nonce, b"aad", &sealed)?;
/// assert_eq!(b"secret".as_slice(), opened.as_slice());
/// # Ok::<(), CryptoError>(())
/// ```
pub struct XChaCha20Poly1305Aead {
    inner: XChaCha20Poly1305,
}

impl XChaCha20Poly1305Aead {
    /// Creates a new XChaCha20-Poly1305 AEAD cipher.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if key is not 32
    /// bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let inner = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
        Ok(Self { inner })
    }
}

impl AeadCipher for XChaCha20Poly1305Aead {
    #[inline]
    fn nonce_size() -> usize {
        XCHACHA20POLY1305_NONCE_SIZE
    }

    #[inline]
    fn tag_size() -> usize {
        POLY1305_TAG_SIZE
    }

    #[inline]
    fn key_size() -> usize {
        CHACHA20_KEY_SIZE
    }

    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let nonce_arr: chacha20poly1305::XNonce = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            })?;
        self.inner
            .encrypt(
                &nonce_arr,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != Self::nonce_size() {
            return Err(CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }
        let nonce_arr: chacha20poly1305::XNonce = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            })?;
        self.inner
            .decrypt(
                &nonce_arr,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === AES-GCM Tests ===

    #[test]
    fn aes128_gcm_seal_open_roundtrip() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let aad = b"additional authenticated data";
        let plaintext = b"secret message to encrypt";

        let cipher = Aes128Gcm::new(&key).expect("key should be valid");
        let ciphertext =
            cipher.seal(&nonce, aad, plaintext).expect("seal should work");
        assert!(ciphertext.len() > plaintext.len());

        let decrypted =
            cipher.open(&nonce, aad, &ciphertext).expect("open should work");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn aes256_gcm_seal_open_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = b"aad";
        let plaintext = b"secret message";

        let cipher = Aes256Gcm::new(&key).expect("key should be valid");
        let ciphertext =
            cipher.seal(&nonce, aad, plaintext).expect("seal should work");
        let decrypted =
            cipher.open(&nonce, aad, &ciphertext).expect("open should work");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn aes128_gcm_invalid_key_length() {
        let key = [0u8; 15];
        let result = Aes128Gcm::new(&key);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn aes256_gcm_invalid_key_length() {
        let key = [0u8; 31];
        let result = Aes256Gcm::new(&key);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(31))
        ));
    }

    #[test]
    fn aes_gcm_invalid_nonce_length() {
        let key = [0u8; 16];
        let cipher = Aes128Gcm::new(&key).expect("key should be valid");
        let bad_nonce = [0u8; 10];
        let result = cipher.seal(&bad_nonce, b"", b"test");
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { expected: 12, actual: 10 })
        ));
    }

    #[test]
    fn aes_gcm_authentication_failed() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key).expect("key should be valid");
        let result = cipher.open(&nonce, b"", b"corrupted ciphertext");
        assert!(matches!(
            result,
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn aes_gcm_aad_sizes() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key).expect("key should be valid");

        // Empty AAD
        let ct = cipher
            .seal(&nonce, b"", b"msg")
            .expect("empty aad seal");
        let pt = cipher.open(&nonce, b"", &ct).expect("empty aad open");
        assert_eq!(b"msg".as_slice(), pt.as_slice());

        // Non-empty AAD
        let ct2 = cipher
            .seal(&nonce, b"auth data", b"msg2")
            .expect("non-empty aad seal");
        let pt2 = cipher
            .open(&nonce, b"auth data", &ct2)
            .expect("non-empty aad open");
        assert_eq!(b"msg2".as_slice(), pt2.as_slice());

        // Wrong AAD should fail
        assert!(cipher.open(&nonce, b"wrong", &ct2).is_err());
    }

    #[test]
    fn aes_gcm_empty_plaintext() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key).expect("key should be valid");

        let ct = cipher.seal(&nonce, b"", b"").expect("empty seal");
        // Tag only (16 bytes) for empty plaintext
        assert_eq!(ct.len(), 16);
        let pt = cipher.open(&nonce, b"", &ct).expect("empty open");
        assert!(pt.is_empty());
    }

    // === AES-CFB Tests ===

    #[test]
    fn aes_cfb128_encrypt_decrypt_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"secret message for cfb mode";

        let mut encryptor =
            AesCfbEncryptor::new(&key, &iv).expect("new encryptor");
        let mut ciphertext = plaintext.to_vec();
        encryptor.encrypt(&mut ciphertext);
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let mut decryptor =
            AesCfbDecryptor::new(&key, &iv).expect("new decryptor");
        decryptor.decrypt(&mut ciphertext);
        assert_eq!(plaintext.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn aes_cfb256_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = b"secret message for cfb-256";

        let mut encryptor =
            AesCfbEncryptor::new(&key, &iv).expect("new encryptor");
        let mut ciphertext = plaintext.to_vec();
        encryptor.encrypt(&mut ciphertext);

        let mut decryptor =
            AesCfbDecryptor::new(&key, &iv).expect("new decryptor");
        decryptor.decrypt(&mut ciphertext);
        assert_eq!(plaintext.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn aes_cfb_invalid_key_length() {
        let key = [0u8; 8];
        let iv = [0u8; 16];
        let result = AesCfbEncryptor::new(&key, &iv);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(8))
        ));
    }

    #[test]
    fn aes_cfb_invalid_iv_length() {
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let result = AesCfbEncryptor::new(&key, &iv);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { expected: 16, actual: 8 })
        ));
    }

    #[test]
    fn aes_cfb_empty_data() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut encryptor =
            AesCfbEncryptor::new(&key, &iv).expect("new encryptor");
        let mut data: [u8; 0] = [];
        encryptor.encrypt(&mut data);
        assert!(data.is_empty());
    }

    // === AES-CTR Tests ===

    #[test]
    fn aes_ctr128_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"secret message for ctr mode";

        let mut cipher =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        let mut data = plaintext.to_vec();
        cipher.apply_keystream(&mut data);
        assert_ne!(plaintext.as_slice(), data.as_slice());

        let mut cipher2 =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        cipher2.apply_keystream(&mut data);
        assert_eq!(plaintext.as_slice(), data.as_slice());
    }

    #[test]
    fn aes_ctr256_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = b"secret message for ctr-256";

        let mut cipher =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        let mut data = plaintext.to_vec();
        cipher.apply_keystream(&mut data);

        let mut cipher2 =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        cipher2.apply_keystream(&mut data);
        assert_eq!(plaintext.as_slice(), data.as_slice());
    }

    #[test]
    fn aes_ctr_invalid_key_length() {
        let key = [0u8; 8];
        let iv = [0u8; 16];
        let result = AesCtrStream::new(&key, &iv);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(8))
        ));
    }

    #[test]
    fn aes_ctr_invalid_iv_length() {
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let result = AesCtrStream::new(&key, &iv);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { expected: 16, actual: 8 })
        ));
    }

    #[test]
    fn aes_ctr_empty_data() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut cipher =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        let mut data: [u8; 0] = [];
        cipher.apply_keystream(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn aes_ctr_streaming() {
        // Test that CTR can process data in chunks
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello world streaming test";

        let mut cipher1 =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        let mut full_data = plaintext.to_vec();
        cipher1.apply_keystream(&mut full_data);

        // Process in two chunks
        let mut cipher2 =
            AesCtrStream::new(&key, &iv).expect("new ctr cipher");
        let mut chunked_data = plaintext.to_vec();
        cipher2.apply_keystream(&mut chunked_data[..5]);
        cipher2.apply_keystream(&mut chunked_data[5..]);

        assert_eq!(full_data.as_slice(), chunked_data.as_slice());
    }

    // === ChaCha20 Stream Tests ===

    #[test]
    fn chacha20_stream_roundtrip_12byte_nonce() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"hello chacha20 world";

        let mut cipher =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        let mut data = plaintext.to_vec();
        cipher.xor_key_stream(&mut data);
        assert_ne!(plaintext.as_slice(), data.as_slice());

        let mut cipher2 =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        cipher2.xor_key_stream(&mut data);
        assert_eq!(plaintext.as_slice(), data.as_slice());
    }

    #[test]
    fn chacha20_stream_roundtrip_8byte_nonce() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 8];
        let plaintext = b"legacy nonce test";

        let mut cipher =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        let mut data = plaintext.to_vec();
        cipher.xor_key_stream(&mut data);

        let mut cipher2 =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        cipher2.xor_key_stream(&mut data);
        assert_eq!(plaintext.as_slice(), data.as_slice());
    }

    #[test]
    fn chacha20_stream_invalid_key_length() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let result = ChaCha20Stream::new(&key, &nonce);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn chacha20_stream_invalid_nonce_length() {
        let key = [0u8; 32];
        let nonce = [0u8; 10];
        let result = ChaCha20Stream::new(&key, &nonce);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 10
            })
        ));
    }

    #[test]
    fn chacha20_stream_empty_data() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut cipher =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        let mut data: [u8; 0] = [];
        cipher.xor_key_stream(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn chacha20_stream_b2b() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"buffer to buffer test";

        let mut cipher =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        let mut dst = vec![0u8; plaintext.len()];
        cipher
            .xor_key_stream_b2b(&mut dst, plaintext)
            .expect("b2b should work");

        // Decrypt back
        let mut cipher2 =
            ChaCha20Stream::new(&key, &nonce).expect("new chacha20");
        let mut decrypted = vec![0u8; dst.len()];
        cipher2
            .xor_key_stream_b2b(&mut decrypted, &dst)
            .expect("b2b decrypt");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    // === ChaCha20-Poly1305 AEAD Tests ===

    #[test]
    fn chacha20poly1305_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"authenticated secret";

        let cipher =
            ChaCha20Poly1305Aead::new(&key).expect("new chacha20poly1305");
        let ciphertext = cipher
            .seal(&nonce, aad, plaintext)
            .expect("seal should work");
        // Ciphertext = encrypted data + 16-byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = cipher
            .open(&nonce, aad, &ciphertext)
            .expect("open should work");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn chacha20poly1305_invalid_key_length() {
        let key = [0u8; 16];
        let result = ChaCha20Poly1305Aead::new(&key);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn chacha20poly1305_invalid_nonce_length() {
        let key = [0u8; 32];
        let cipher =
            ChaCha20Poly1305Aead::new(&key).expect("new chacha20poly1305");
        let bad_nonce = [0u8; 8];
        let result = cipher.seal(&bad_nonce, b"", b"test");
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 8
            })
        ));
    }

    #[test]
    fn chacha20poly1305_authentication_failed() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher =
            ChaCha20Poly1305Aead::new(&key).expect("new chacha20poly1305");
        let result = cipher.open(&nonce, b"", b"corrupted ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn chacha20poly1305_aad_mismatch() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let cipher =
            ChaCha20Poly1305Aead::new(&key).expect("new chacha20poly1305");
        let ct = cipher
            .seal(&nonce, b"correct aad", b"secret")
            .expect("seal");
        let result = cipher.open(&nonce, b"wrong aad", &ct);
        assert!(result.is_err());
    }

    #[test]
    fn chacha20poly1305_empty_plaintext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher =
            ChaCha20Poly1305Aead::new(&key).expect("new chacha20poly1305");
        let ct = cipher.seal(&nonce, b"", b"").expect("empty seal");
        assert_eq!(ct.len(), 16); // Tag only
        let pt = cipher.open(&nonce, b"", &ct).expect("empty open");
        assert!(pt.is_empty());
    }

    // === XChaCha20-Poly1305 AEAD Tests ===

    #[test]
    fn xchacha20poly1305_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 24];
        let aad = b"additional data";
        let plaintext = b"authenticated secret";

        let cipher = XChaCha20Poly1305Aead::new(&key)
            .expect("new xchacha20poly1305");
        let ciphertext = cipher
            .seal(&nonce, aad, plaintext)
            .expect("seal should work");
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = cipher
            .open(&nonce, aad, &ciphertext)
            .expect("open should work");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn xchacha20poly1305_invalid_key_length() {
        let key = [0u8; 16];
        let result = XChaCha20Poly1305Aead::new(&key);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn xchacha20poly1305_invalid_nonce_length() {
        let key = [0u8; 32];
        let cipher = XChaCha20Poly1305Aead::new(&key)
            .expect("new xchacha20poly1305");
        let bad_nonce = [0u8; 12];
        let result = cipher.seal(&bad_nonce, b"", b"test");
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 12
            })
        ));
    }

    #[test]
    fn xchacha20poly1305_authentication_failed() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let cipher = XChaCha20Poly1305Aead::new(&key)
            .expect("new xchacha20poly1305");
        let result = cipher.open(&nonce, b"", b"corrupted ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn xchacha20poly1305_aad_mismatch() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 24];
        let cipher = XChaCha20Poly1305Aead::new(&key)
            .expect("new xchacha20poly1305");
        let ct = cipher
            .seal(&nonce, b"correct aad", b"secret")
            .expect("seal");
        let result = cipher.open(&nonce, b"wrong aad", &ct);
        assert!(result.is_err());
    }

    #[test]
    fn xchacha20poly1305_empty_plaintext() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let cipher = XChaCha20Poly1305Aead::new(&key)
            .expect("new xchacha20poly1305");
        let ct = cipher.seal(&nonce, b"", b"").expect("empty seal");
        assert_eq!(ct.len(), 16); // Tag only
        let pt = cipher.open(&nonce, b"", &ct).expect("empty open");
        assert!(pt.is_empty());
    }
}
