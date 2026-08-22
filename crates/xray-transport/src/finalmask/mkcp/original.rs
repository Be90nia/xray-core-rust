//! # mkcp `original` mode（XOR 链 + FNV1a-32 认证）
//!
//! 对应 Go `transport/internet/finalmask/mkcp/original/`。
//!
//! ## 包格式
//!
//! `[4B FNV1a-32 hash BE][2B payload-length BE][payload]`，整体做正向 XOR 链混淆。
//! 接收端反向 XOR 还原后校验 FNV1a-32 与 length 字段。
//!
//! ## Overhead
//!
//! 固定 6 字节（对应 Go `simple.Overhead()`）。

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use super::super::{UdpIo, Udpmask};

/// FNV1a-32 offset basis（标准参考值，与 Go `hash/fnv` New32a 一致）。
const FNV32_OFFSET: u32 = 0x811C_9DC5;
/// FNV1a-32 prime。
const FNV32_PRIME: u32 = 0x0100_0193;

/// 加密头开销（4B hash + 2B length = 6B，对应 Go `simple.Overhead()`）。
pub const SIMPLE_OVERHEAD: usize = 6;

/// mkcp `original` 配置（对应 Go `original.Config`，当前无字段）。
#[derive(Debug, Clone, Default)]
pub struct OriginalConfig;

/// 计算 FNV1a-32（与 Go `hash/fnv` New32a、vmess `Authenticate` 一致）。
fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = FNV32_OFFSET;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(FNV32_PRIME);
    }
    h
}

/// 正向 XOR 链：`x[i] ^= x[i-4]`，i 从 4 到 len（对应 Go `xorfwd`，in-place 递归 XOR）。
fn xor_fwd(x: &mut [u8]) {
    for i in 4..x.len() {
        x[i] ^= x[i - 4];
    }
}

/// 反向 XOR 链：`x[i] ^= x[i-4]`，i 从 len-1 倒序到 4（对应 Go `xorbkd`，`xor_fwd` 的逆）。
fn xor_bkd(x: &mut [u8]) {
    for i in (4..x.len()).rev() {
        x[i] ^= x[i - 4];
    }
}

/// 加密（对应 Go `simple.Seal`）。
///
/// 输出 = `[4B FNV1a-32 BE][2B payload-length BE][payload]`，整体做正向 XOR 链混淆。
/// 中间会对齐到 4 字节边界（临时填充），但最终输出已截回原长。
#[must_use]
pub fn seal(plaintext: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(SIMPLE_OVERHEAD + plaintext.len());
    dst.extend_from_slice(&[0u8; 4]); // hash 占位
    dst.extend_from_slice(&(plaintext.len() as u16).to_be_bytes()); // length BE
    dst.extend_from_slice(plaintext);

    // FNV1a-32 覆盖 length + payload（即 dst[4..]）。
    let hash = fnv1a32(&dst[4..]);
    dst[..4].copy_from_slice(&hash.to_be_bytes());

    // 对齐 4 字节边界（temp padding），xorfwd 后截回原长。
    let orig_len = dst.len();
    let pad = (4 - orig_len % 4) % 4;
    if pad > 0 {
        dst.extend(std::iter::repeat_n(0u8, pad));
    }
    xor_fwd(&mut dst);
    dst.truncate(orig_len);
    dst
}

/// 解密（对应 Go `simple.Open`）。
///
/// # Errors
/// - `InvalidData`：FNV1a-32 校验失败，或 length 字段与实际 payload 长度不符，或输入过短。
pub fn open(ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if ciphertext.len() < SIMPLE_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original: ciphertext too short",
        ));
    }
    let mut buf = ciphertext.to_vec();
    let orig_len = buf.len();
    let pad = (4 - orig_len % 4) % 4;
    if pad > 0 {
        buf.extend(std::iter::repeat_n(0u8, pad));
    }
    xor_bkd(&mut buf);
    buf.truncate(orig_len);

    let hash = fnv1a32(&buf[4..]);
    if buf[..4] != hash.to_be_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original: invalid auth (fnv1a-32 mismatch)",
        ));
    }
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if buf.len() - SIMPLE_OVERHEAD != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original: invalid auth (length field mismatch)",
        ));
    }
    Ok(buf[SIMPLE_OVERHEAD..].to_vec())
}

impl Udpmask for OriginalConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        Ok(Box::new(SimpleConn { inner: raw }))
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

impl super::super::PacketCodec for OriginalConfig {
    fn encode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        Ok(seal(pkt))
    }

    fn decode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        open(pkt)
    }
}

/// `original` mode PacketConn 包装（对应 Go `simpleConn`）。
struct SimpleConn {
    inner: Box<dyn UdpIo>,
}

#[async_trait]
impl UdpIo for SimpleConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let cipher = seal(buf);
        self.inner.send_to(&cipher, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // raw 含 overhead，需要更大缓冲。
        let mut raw = vec![0u8; buf.len() + SIMPLE_OVERHEAD];
        let (n, addr) = self.inner.recv_from(&mut raw).await?;
        let plain = open(&raw[..n])?;
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

    #[test]
    fn fnv1a32_known_vectors() {
        // FNV1a-32 标准参考值。
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
        assert_eq!(fnv1a32(b"hello"), 0x4F9F_2CAB);
    }

    #[test]
    fn xor_fwd_bkd_are_inverse() {
        let mut data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let orig = data.clone();
        xor_fwd(&mut data);
        xor_bkd(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn seal_open_roundtrip_short() {
        let plain = b"hi";
        let cipher = seal(plain);
        assert_eq!(cipher.len(), plain.len() + SIMPLE_OVERHEAD);
        assert_eq!(open(&cipher).unwrap(), plain);
    }

    #[test]
    fn seal_open_roundtrip_long() {
        let plain = vec![0x42u8; 1000];
        let cipher = seal(&plain);
        assert_eq!(cipher.len(), plain.len() + SIMPLE_OVERHEAD);
        assert_eq!(open(&cipher).unwrap(), plain);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let cipher = seal(b"");
        assert_eq!(cipher.len(), SIMPLE_OVERHEAD);
        assert!(open(&cipher).unwrap().is_empty());
    }

    #[test]
    fn open_rejects_tampered_payload() {
        let mut cipher = seal(b"hello");
        cipher[6] ^= 0xFF;
        assert!(open(&cipher).is_err());
    }

    #[test]
    fn open_rejects_tampered_hash() {
        let mut cipher = seal(b"hello");
        cipher[0] ^= 0xFF;
        assert!(open(&cipher).is_err());
    }

    #[test]
    fn open_rejects_truncated() {
        let cipher = seal(b"hello");
        assert!(open(&cipher[..3]).is_err());
    }
}
