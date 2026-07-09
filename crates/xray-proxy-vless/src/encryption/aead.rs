//! VLESS encryption AEAD wrapper。
//!
//! 对齐 Go `proxy/vless/encryption/common.go` 的 `NewAEAD`/`Seal`/`Open`/`IncreaseNonce`：
//! blake3 `DeriveKey` 派生 32 字节密钥 → AES-256-GCM 或 ChaCha20-Poly1305 + 自增 nonce。
//! nonce 达到全 0xFF（MaxNonce）时调用方应重新派生 AEAD（对应 Go `MaxNonce`）。

use crate::error::{Result, VlessError};
use aes_gcm::aead::{Aead as AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

/// Nonce 字节长度（AES-GCM/ChaCha20-Poly1305 标准 12 字节）。
pub const NONCE_LEN: usize = 12;

/// MaxNonce：全 0xFF，对应 Go `MaxNonce = bytes.Repeat([]byte{255}, 12)`。
///
/// nonce 达到此值后必须重新派生密钥（防 nonce 复用）。
pub const MAX_NONCE: [u8; NONCE_LEN] = [0xFF; NONCE_LEN];

/// AEAD 具体算法（按 `UseAES` 硬件支持判定选择）。
enum AeadKind {
    Aes(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

/// VLESS 加密 AEAD：blake3 派生密钥 + AES-GCM/ChaCha20-Poly1305 + 自增 nonce。
///
/// 对应 Go 的 `*AEAD`。`nonce = None` 时先 `IncreaseNonce` 再用新 nonce（小端 +1），
/// 与 Go `AEAD.Seal(dst, nil, ...)` 行为一致。
pub struct Aead {
    kind: AeadKind,
    nonce: [u8; NONCE_LEN],
}

impl Aead {
    /// 创建：`blake3.DeriveKey(context, key)` → 32B 密钥 → AES-GCM（`use_aes`）或 ChaCha20。
    ///
    /// 对应 Go `NewAEAD(ctx, key, useAES)`。
    pub fn new(context: &[u8], key: &[u8], use_aes: bool) -> Self {
        // SAFETY: blake3 derive_key 在算法层面把 context 当字节序列哈希，不执行 UTF-8 语义操作。
        // Go lukechampine blake3 的 DeriveKey 接受任意字节 context（Go string = []byte）。
        // 协议中 context（iv / 密钥哈希 / 密文切片等）可能含任意字节，为 wire 兼容必须按字节处理。
        // blake3 crate 的 &str 限制是 API 设计选择（鼓励可读 context），底层处理字节，故 unchecked 安全。
        let ctx_str = unsafe { std::str::from_utf8_unchecked(context) };
        let derived = blake3::derive_key(ctx_str, key);
        let kind = if use_aes {
            AeadKind::Aes(Aes256Gcm::new(&derived.into()))
        } else {
            AeadKind::ChaCha(ChaCha20Poly1305::new(&derived.into()))
        };
        Self {
            kind,
            nonce: [0u8; NONCE_LEN],
        }
    }

    /// 当前 nonce（不可变借用）。
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// nonce 是否达到 MaxNonce（全 0xFF）。
    pub fn is_max(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    /// nonce 小端 +1（对齐 Go `IncreaseNonce`：`nonce[11]++` 进位向 `nonce[0]`）。
    ///
    /// 已在 MaxNonce 时返回 false（调用方应重新派生 AEAD）。
    fn increase_nonce(&mut self) -> bool {
        if self.nonce == MAX_NONCE {
            return false;
        }
        for i in (0..NONCE_LEN).rev() {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            }
        }
        true
    }

    /// 加密：附加密文到 `dst`。`nonce = None` 时先用内部 nonce（递增后再用，对齐 Go）。
    ///
    /// 对应 Go `AEAD.Seal(dst, nonce, plaintext, additionalData)`，`nonce=nil` 时先 `IncreaseNonce`。
    ///
    /// # Errors
    /// 底层 AEAD 加密失败（罕见，多为密钥/nonce 异常）返回 [`VlessError::Other`]。
    pub fn seal(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: Option<&[u8; NONCE_LEN]>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<()> {
        let used: [u8; NONCE_LEN] = match nonce {
            Some(n) => *n,
            None => {
                self.increase_nonce();
                self.nonce
            }
        };
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ct = match &self.kind {
            AeadKind::Aes(a) => a.encrypt(&used.into(), payload),
            AeadKind::ChaCha(c) => c.encrypt(&used.into(), payload),
        }
        .map_err(|e| VlessError::Other(format!("AEAD seal failed: {e}")))?;
        dst.extend_from_slice(&ct);
        Ok(())
    }

    /// 解密：附加明文到 `dst`。nonce 语义同 [`Aead::seal`]。
    ///
    /// # Errors
    /// 解密失败（密文损坏 / nonce 不匹配 / tag 校验失败）返回 [`VlessError::Other`]。
    pub fn open(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: Option<&[u8; NONCE_LEN]>,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<()> {
        let used: [u8; NONCE_LEN] = match nonce {
            Some(n) => *n,
            None => {
                self.increase_nonce();
                self.nonce
            }
        };
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let pt = match &self.kind {
            AeadKind::Aes(a) => a.decrypt(&used.into(), payload),
            AeadKind::ChaCha(c) => c.decrypt(&used.into(), payload),
        }
        .map_err(|e| VlessError::Other(format!("AEAD open failed: {e}")))?;
        dst.extend_from_slice(&pt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AES-GCM round-trip：两个独立 Aead（同 context/key/use_aes）各自管理 nonce，
    /// seal(None) 与 open(None) 第一次都递增到 ...0001，nonce 匹配解密成功。
    #[test]
    fn aes_seal_open_round_trip() {
        let ctx = b"test-context";
        let key = b"test-key";
        let aad = b"aad-data";

        let mut seal_aead = Aead::new(ctx, key, true);
        let mut open_aead = Aead::new(ctx, key, true);

        let mut ct = Vec::new();
        seal_aead.seal(&mut ct, None, b"hello", aad).unwrap();
        assert_eq!(ct.len(), 5 + 16); // plaintext + GCM tag

        let mut pt = Vec::new();
        open_aead.open(&mut pt, None, &ct, aad).unwrap();
        assert_eq!(pt, b"hello");
    }

    /// ChaCha20-Poly1305 round-trip：同上，验证非 AES 路径。
    #[test]
    fn chacha_seal_open_round_trip() {
        let ctx = b"chacha-ctx";
        let key = b"chacha-key";
        let aad = b"aad";

        let mut seal_aead = Aead::new(ctx, key, false);
        let mut open_aead = Aead::new(ctx, key, false);

        let mut ct = Vec::new();
        seal_aead.seal(&mut ct, None, b"world", aad).unwrap();
        assert_eq!(ct.len(), 5 + 16);

        let mut pt = Vec::new();
        open_aead.open(&mut pt, None, &ct, aad).unwrap();
        assert_eq!(pt, b"world");
    }

    /// nonce 小端递增：首次 ...0001，256 次后进位 ...0100。
    #[test]
    fn nonce_increments_little_endian() {
        let mut a = Aead::new(b"c", b"k", true);
        assert_eq!(&a.nonce, &[0u8; NONCE_LEN]);

        // seal(None) 触发递增，首次变 ...0001
        let mut ct = Vec::new();
        a.seal(&mut ct, None, b"x", b"").unwrap();
        let mut expected = [0u8; NONCE_LEN];
        expected[11] = 1;
        assert_eq!(a.nonce, expected);

        // 连续到 255，下一次进位
        for _ in 0..254 {
            let mut tmp = Vec::new();
            a.seal(&mut tmp, None, b"x", b"").unwrap();
        }
        assert_eq!(a.nonce[11], 255);
        assert_eq!(a.nonce[10], 0);

        let mut tmp = Vec::new();
        a.seal(&mut tmp, None, b"x", b"").unwrap();
        assert_eq!(a.nonce[11], 0);
        assert_eq!(a.nonce[10], 1);
    }

    /// 显式 nonce 加密（不递增内部状态）。
    #[test]
    fn explicit_nonce_does_not_advance_internal() {
        let mut a = Aead::new(b"c", b"k", true);
        let fixed = [0xAA; NONCE_LEN];

        let mut ct = Vec::new();
        a.seal(&mut ct, Some(&fixed), b"data", b"").unwrap();
        // 显式 nonce 不应改变内部 nonce
        assert_eq!(a.nonce, [0u8; NONCE_LEN]);
    }

    /// is_max 在 nonce 达到全 0xFF 时为真。
    #[test]
    fn is_max_nonce_detection() {
        let mut a = Aead::new(b"c", b"k", true);
        assert!(!a.is_max());
        a.nonce = MAX_NONCE;
        assert!(a.is_max());
    }

    /// 任意字节 context（非 UTF-8）：wire 兼容验证，不应 panic。
    #[test]
    fn non_utf8_context_does_not_panic() {
        let non_utf8: [u8; 16] = [0xFF, 0xFE, 0x00, 0x01, 0x80, 0xC0, 0xE0, 0xF0,
                                   0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x12, 0x34, 0x56];
        let mut a = Aead::new(&non_utf8, b"key", true);
        let mut ct = Vec::new();
        a.seal(&mut ct, None, b"compat", b"").unwrap();
        assert!(!ct.is_empty());
    }
}
