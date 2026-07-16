//! # mkcp `aes128gcm` mode（AES-128-GCM AEAD）
//!
//! 对应 Go `transport/internet/finalmask/mkcp/aes128gcm/`。
//!
//! ## 包格式
//!
//! `[12B nonce][ciphertext + 16B GCM tag]`
//!
//! ## 密钥派生
//!
//! `key = SHA256(password)[..16]`（对应 Go `sha256.Sum256` 取前 16 字节）。
//!
//! ## 复用
//!
//! AEAD 实现复用 [`xray_crypto::aead::Aes128Gcm`]（ring 后端）。

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use rand::RngCore;
use ring::digest::{digest, SHA256};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, CryptoError};

use super::super::{UdpIo, Udpmask};

/// AES-128-GCM nonce 长度（12B，GCM 标准）。
pub const AES128GCM_NONCE_SIZE: usize = 12;
/// AES-128-GCM tag 长度（16B，GCM 标准）。
pub const AES128GCM_TAG_SIZE: usize = 16;
/// 总 overhead = nonce + tag = 28B。
pub const AES128GCM_OVERHEAD: usize = AES128GCM_NONCE_SIZE + AES128GCM_TAG_SIZE;

/// mkcp `aes128gcm` 配置（对应 Go `aes128gcm.Config`）。
#[derive(Debug, Clone, Default)]
pub struct Aes128GcmConfig {
    /// 共享密钥（password），经 SHA256 取前 16B 派生 AES-128 key。
    pub password: String,
}

impl Aes128GcmConfig {
    /// 由 password 派生 AES-128 key（对应 Go `sha256.Sum256(c.Password)[:16]`）。
    fn derive_key(&self) -> [u8; 16] {
        let h = digest(&SHA256, self.password.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&h.as_ref()[..16]);
        key
    }

    /// 构造 AEAD cipher 实例。
    fn build_cipher(&self) -> io::Result<Aes128Gcm> {
        let key = self.derive_key();
        Aes128Gcm::new(&key).map_err(map_crypto_err)
    }
}

/// 把 [`CryptoError`] 映射为 `io::Error`。
fn map_crypto_err(e: CryptoError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

/// 加密（对应 Go `aes128gcmConn.WriteTo`）。
///
/// 生成 12B 随机 nonce，返回 `[nonce][ciphertext + tag]`，总长 `plaintext.len() + 28`。
pub fn seal(cipher: &Aes128Gcm, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; AES128GCM_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .seal(&nonce, b"", plaintext)
        .map_err(map_crypto_err)?;
    let mut out = Vec::with_capacity(AES128GCM_NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密（对应 Go `aes128gcmConn.ReadFrom`）。
///
/// 输入 = `[12B nonce][ciphertext + tag]`，返回 plaintext。
///
/// # Errors
/// - `InvalidData`：长度不足或 AEAD 校验失败。
pub fn open(cipher: &Aes128Gcm, packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() < AES128GCM_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aes128gcm: packet too short",
        ));
    }
    let (nonce, ct) = packet.split_at(AES128GCM_NONCE_SIZE);
    cipher.open(nonce, b"", ct).map_err(map_crypto_err)
}

impl Udpmask for Aes128GcmConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let cipher = self.build_cipher()?;
        Ok(Box::new(Aes128GcmConn { inner: raw, cipher }))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        self.wrap_packet_conn_client(raw, level, level_count)
    }
}

/// `aes128gcm` mode PacketConn 包装（对应 Go `aes128gcmConn`）。
struct Aes128GcmConn {
    inner: Box<dyn UdpIo>,
    cipher: Aes128Gcm,
}

#[async_trait]
impl UdpIo for Aes128GcmConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let packet = seal(&self.cipher, buf)?;
        self.inner.send_to(&packet, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut raw = vec![0u8; buf.len() + AES128GCM_OVERHEAD];
        let (n, addr) = self.inner.recv_from(&mut raw).await?;
        let plain = open(&self.cipher, &raw[..n])?;
        let len = plain.len().min(buf.len());
        buf[..len].copy_from_slice(&plain[..len]);
        Ok((len, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> Aes128Gcm {
        let cfg = Aes128GcmConfig {
            password: "test-password".into(),
        };
        cfg.build_cipher().unwrap()
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let cfg = Aes128GcmConfig {
            password: "abc".into(),
        };
        let k1 = cfg.derive_key();
        let k2 = cfg.derive_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_derivation_depends_on_password() {
        let a = Aes128GcmConfig {
            password: "abc".into(),
        };
        let b = Aes128GcmConfig {
            password: "abd".into(),
        };
        assert_ne!(a.derive_key(), b.derive_key());
    }

    #[test]
    fn seal_open_roundtrip() {
        let cipher = test_cipher();
        let plain = b"hello aes128gcm mode";
        let packet = seal(&cipher, plain).unwrap();
        assert_eq!(packet.len(), plain.len() + AES128GCM_OVERHEAD);
        assert_eq!(open(&cipher, &packet).unwrap(), plain);
    }

    #[test]
    fn each_seal_uses_random_nonce() {
        let cipher = test_cipher();
        let p1 = seal(&cipher, b"same").unwrap();
        let p2 = seal(&cipher, b"same").unwrap();
        // nonce 随机 → 两次密文不同
        assert_ne!(&p1[..AES128GCM_NONCE_SIZE], &p2[..AES128GCM_NONCE_SIZE]);
        assert_ne!(p1, p2);
    }

    #[test]
    fn open_rejects_short_packet() {
        let cipher = test_cipher();
        assert!(open(&cipher, &[0u8; 5]).is_err());
    }

    #[test]
    fn open_rejects_tampered() {
        let cipher = test_cipher();
        let mut packet = seal(&cipher, b"hello").unwrap();
        packet[AES128GCM_NONCE_SIZE] ^= 0xFF; // 翻 ciphertext 首位
        assert!(open(&cipher, &packet).is_err());
    }
}
