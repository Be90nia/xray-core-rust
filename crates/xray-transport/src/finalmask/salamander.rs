//! # Salamander UDP 混淆（对应 Go `salamander/`）
//!
//! 基于 BLAKE2b-256 的 UDP 包混淆：`[8-byte salt][XOR(payload, BLAKE2b-256(PSK||salt))]`。
//! 每个包使用随机 salt，加密流不可预测。
//!
//! 参考 clash-rs `clash-lib/src/proxy/hysteria2/salamander.rs`（算法一致）。
//! Gecko 子模式（QUIC 长头部分片重组）待 rpn-B 实现。

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use rand::{rng, RngCore};

use super::{UdpIo, Udpmask};

const SM_PSK_MIN_LEN: usize = 4;
const SM_SALT_LEN: usize = 8;
const SM_KEY_LEN: usize = 32; // blake2b.Size256

/// Salamander 配置（对应 Go `salamander.Config`）。
#[derive(Debug, Clone, Default)]
pub struct SalamanderConfig {
    /// PSK（password），最少 4 字节。
    pub password: String,
}

/// Salamander 混淆器（对应 Go `SalamanderObfuscator`）。
pub struct SalamanderObfuscator {
    psk: Vec<u8>,
}

impl SalamanderObfuscator {
    /// 创建混淆器，PSK 少于 4 字节返回错误（对应 Go `ErrPSKTooShort`）。
    pub fn new(psk: &[u8]) -> Result<Self, String> {
        if psk.len() < SM_PSK_MIN_LEN {
            return Err(format!("PSK must be at least {SM_PSK_MIN_LEN} bytes"));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    /// 混淆：`out = [salt][XOR(input, key)]`，返回写入 `out` 的字节数。
    pub fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        let out_len = input.len() + SM_SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        let mut salt = [0u8; SM_SALT_LEN];
        rng().fill_bytes(&mut salt);
        out[..SM_SALT_LEN].copy_from_slice(&salt);
        let key = self.derive_key(&salt);
        for (i, &b) in input.iter().enumerate() {
            out[SM_SALT_LEN + i] = b ^ key[i % SM_KEY_LEN];
        }
        out_len
    }

    /// 解混淆：`in = [salt][XOR(payload, key)]`，返回 payload 长度。
    pub fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        if input.len() <= SM_SALT_LEN {
            return 0;
        }
        let out_len = input.len() - SM_SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        let key = self.derive_key(&input[..SM_SALT_LEN]);
        for (i, &b) in input[SM_SALT_LEN..].iter().enumerate() {
            out[i] = b ^ key[i % SM_KEY_LEN];
        }
        out_len
    }

    /// `key = BLAKE2b-256(PSK || salt)`（对应 Go `keyLocked`）。
    fn derive_key(&self, salt: &[u8]) -> [u8; SM_KEY_LEN] {
        let mut hasher = Blake2bVar::new(SM_KEY_LEN).expect("32 is valid blake2b output size");
        Update::update(&mut hasher, &self.psk);
        Update::update(&mut hasher, salt);
        let mut key = [0u8; SM_KEY_LEN];
        hasher.finalize_variable(&mut key).expect("finalize_variable");
        key
    }
}

impl Udpmask for SalamanderConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let obfs = SalamanderObfuscator::new(self.password.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Box::new(SalamanderConn::new(obfs, raw)))
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

/// Salamander 包装的 PacketConn（对应 Go `salamanderConn`，非 header 模式）。
struct SalamanderConn {
    inner: Box<dyn UdpIo>,
    obfs: SalamanderObfuscator,
}

impl SalamanderConn {
    fn new(obfs: SalamanderObfuscator, inner: Box<dyn UdpIo>) -> Self {
        Self { inner, obfs }
    }
}

#[async_trait]
impl UdpIo for SalamanderConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let mut out = vec![0u8; buf.len() + SM_SALT_LEN];
        let n = self.obfs.obfuscate(buf, &mut out);
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "salamander obfuscate produced 0 bytes"));
        }
        self.inner.send_to(&out[..n], addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // raw 含 salt，需要更大的缓冲
        let mut raw = vec![0u8; buf.len() + SM_SALT_LEN];
        let (n, addr) = self.inner.recv_from(&mut raw).await?;
        let payload_len = self.obfs.deobfuscate(&raw[..n], buf);
        Ok((payload_len, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_deobfuscate_roundtrip() {
        let obfs = SalamanderObfuscator::new(b"test-password-123").unwrap();
        let payload = b"hello salamander world";
        let mut encoded = vec![0u8; payload.len() + SM_SALT_LEN];
        obfs.obfuscate(payload, &mut encoded);
        assert_ne!(&encoded[SM_SALT_LEN..], payload); // 确实混淆了
        let mut decoded = vec![0u8; payload.len()];
        let n = obfs.deobfuscate(&encoded, &mut decoded);
        assert_eq!(n, payload.len());
        assert_eq!(&decoded[..n], payload);
    }

    #[test]
    fn psk_too_short_errors() {
        assert!(SalamanderObfuscator::new(b"ab").is_err());
        assert!(SalamanderObfuscator::new(b"abc").is_err());
        assert!(SalamanderObfuscator::new(b"abcd").is_ok()); // 4 bytes OK
    }

    #[test]
    fn each_obfuscation_has_random_salt() {
        let obfs = SalamanderObfuscator::new(b"test-key-12345").unwrap();
        let payload = b"same payload";
        let mut e1 = vec![0u8; payload.len() + SM_SALT_LEN];
        let mut e2 = vec![0u8; payload.len() + SM_SALT_LEN];
        obfs.obfuscate(payload, &mut e1);
        obfs.obfuscate(payload, &mut e2);
        // salt 随机 → 两次编码不同
        assert_ne!(&e1[..SM_SALT_LEN], &e2[..SM_SALT_LEN]);
        assert_ne!(e1, e2);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let obfs = SalamanderObfuscator::new(b"four-byte-key").unwrap();
        let payload: &[u8] = b"";
        let mut encoded = vec![0u8; SM_SALT_LEN];
        let n = obfs.obfuscate(payload, &mut encoded);
        assert_eq!(n, SM_SALT_LEN); // 仅 salt
        // 解混淆：input == salt only → out_len = 0
        let mut decoded: [u8; 0] = [];
        let dn = obfs.deobfuscate(&encoded, &mut decoded);
        assert_eq!(dn, 0);
    }

    #[test]
    fn deobfuscate_too_short_input_returns_zero() {
        let obfs = SalamanderObfuscator::new(b"four-byte-key").unwrap();
        let mut out = [0u8; 10];
        assert_eq!(obfs.deobfuscate(&[1, 2, 3], &mut out), 0); // < 8 字节
    }
}
