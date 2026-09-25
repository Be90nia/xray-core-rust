//! # UDP 打洞包协议（对应 Go `transport/internet/finalmask/realm/punch.go`）
//!
//! 包 wire 格式：`[8 salt][8 magic][1 type][16 nonce][0..1024 padding]`
//! 加密：明文段 `magic || type || nonce || padding` XOR `SHA-256(obfsKey || salt)`。
//!
//! 字节级对齐 Go 实现——`EncodePunchPacket` 与 `DecodePunchPacket` 互为逆运算，
//! 与 Go 端互通时 wire 字节完全一致。

use std::io;

use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 最大 padding 字节数（对应 Go `MaxPunchPadding`）。
pub const MAX_PUNCH_PADDING: usize = 1024;

/// Salt 字节长度（对应 Go `punchSaltLen`）。
const PUNCH_SALT_LEN: usize = 8;

/// Header 长度：`magic(8) + type(1) + nonce(16) = 25`（对应 Go `punchHeaderLen`）。
const PUNCH_HEADER_LEN: usize = 25;

/// 最小 wire 长度：`salt(8) + header(25) = 33`（对应 Go `punchMinWireLen`）。
pub const PUNCH_MIN_WIRE_LEN: usize = PUNCH_SALT_LEN + PUNCH_HEADER_LEN;

/// 最大 wire 长度：`min + MaxPunchPadding = 1057`（对应 Go `punchMaxWireLen`）。
pub const PUNCH_MAX_WIRE_LEN: usize = PUNCH_MIN_WIRE_LEN + MAX_PUNCH_PADDING;

/// Punch nonce 字节数（与 [`crate::finalmask::realm::http`] 共享）。
pub const PUNCH_NONCE_SIZE: usize = 16;

/// Punch obfs key 字节数（与 [`crate::finalmask::realm::http`] 共享）。
pub const PUNCH_OBFS_KEY_SIZE: usize = 32;

/// 8 字节 magic：`HYRLMv1\0`（对应 Go `punchMagic`）。
const PUNCH_MAGIC: [u8; 8] = *b"HYRLMv1\0";

/// 打洞包类型（对应 Go `PunchPacketType`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PunchPacketType {
    /// `0x01` Hello（发起方）。
    Hello = 0x01,
    /// `0x02` Ack（应答方）。
    Ack = 0x02,
}

impl PunchPacketType {
    /// 字节 → 枚举，越界返回 `None`。
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Ack),
            _ => None,
        }
    }

    /// 是否为合法类型（对应 Go `validPunchPacketType`）。
    fn is_valid(self) -> bool {
        matches!(self, Self::Hello | Self::Ack)
    }
}

/// 解码结果（对应 Go `PunchPacket`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacket {
    pub packet_type: PunchPacketType,
    pub padding_length: usize,
}

/// PunchMetadata：punch 编解码所需字段（对应 Go `PunchMetadata`）。
///
/// 同时被 [`crate::finalmask::realm::http`] 的 REST 请求/响应/SSE 事件以
/// `#[serde(flatten)]` 嵌入。`Hash + Eq` 让 server 端可按 meta 索引并发 punch 通道。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PunchMetadata {
    /// hex 编码的 nonce（解码后 `PUNCH_NONCE_SIZE` 字节）。
    pub nonce: String,
    /// hex 编码的 obfs key（解码后 `PUNCH_OBFS_KEY_SIZE` 字节）。
    pub obfs: String,
}

impl PunchMetadata {
    #[must_use]
    pub fn new(nonce: String, obfs: String) -> Self {
        Self { nonce, obfs }
    }
}

/// 编码打洞包（对应 Go `EncodePunchPacket`）。
pub fn encode_punch_packet(
    packet_type: PunchPacketType,
    meta: &PunchMetadata,
) -> io::Result<Vec<u8>> {
    if !packet_type.is_valid() {
        return Err(invalid("unknown packet type"));
    }
    let (nonce, obfs_key) = decode_punch_metadata(meta)?;
    let padding_length = random_padding_length();
    let mut plain = vec![0u8; PUNCH_HEADER_LEN + padding_length];
    plain[..PUNCH_MAGIC.len()].copy_from_slice(&PUNCH_MAGIC);
    plain[PUNCH_MAGIC.len()] = packet_type as u8;
    plain[PUNCH_MAGIC.len() + 1..PUNCH_HEADER_LEN].copy_from_slice(&nonce);
    if padding_length > 0 {
        rand::rng().fill_bytes(&mut plain[PUNCH_HEADER_LEN..]);
    }
    let mut packet = vec![0u8; PUNCH_SALT_LEN + plain.len()];
    rand::rng().fill_bytes(&mut packet[..PUNCH_SALT_LEN]);
    packet[PUNCH_SALT_LEN..].copy_from_slice(&plain);
    let (salt, body) = packet.split_at_mut(PUNCH_SALT_LEN);
    xor_punch_packet(body, &obfs_key, salt);
    Ok(packet)
}

/// 解码打洞包（对应 Go `DecodePunchPacket`）。
pub fn decode_punch_packet(packet: &[u8], meta: &PunchMetadata) -> io::Result<PunchPacket> {
    if packet.len() < PUNCH_MIN_WIRE_LEN {
        return Err(invalid("packet too short"));
    }
    if packet.len() > PUNCH_MAX_WIRE_LEN {
        return Err(invalid("packet too long"));
    }
    let (nonce, obfs_key) = decode_punch_metadata(meta)?;
    let salt = &packet[..PUNCH_SALT_LEN];
    let mut plain = packet[PUNCH_SALT_LEN..].to_vec();
    xor_punch_packet(&mut plain, &obfs_key, salt);
    if plain[..PUNCH_MAGIC.len()] != PUNCH_MAGIC {
        return Err(invalid("bad magic"));
    }
    let packet_type = PunchPacketType::from_byte(plain[PUNCH_MAGIC.len()])
        .ok_or_else(|| invalid("unknown packet type"))?;
    if plain[PUNCH_MAGIC.len() + 1..PUNCH_HEADER_LEN] != nonce[..] {
        return Err(invalid("nonce mismatch"));
    }
    Ok(PunchPacket { packet_type, padding_length: plain.len() - PUNCH_HEADER_LEN })
}

/// 从 [`PunchMetadata`] 提取并校验 `nonce + obfsKey`（对应 Go `decodePunchMetadata`）。
fn decode_punch_metadata(meta: &PunchMetadata) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let nonce = decode_hex_size("nonce", &meta.nonce, PUNCH_NONCE_SIZE)?;
    let obfs = decode_hex_size("obfs", &meta.obfs, PUNCH_OBFS_KEY_SIZE)?;
    Ok((nonce, obfs))
}

/// 解码 hex 并校验长度（对应 Go `decodeHexSize`）。
fn decode_hex_size(name: &str, value: &str, size: usize) -> io::Result<Vec<u8>> {
    let b = hex::decode(value).map_err(|_| invalid(&format!("invalid {name}")))?;
    if b.len() != size {
        return Err(invalid(&format!("invalid {name} length")));
    }
    Ok(b)
}

/// 返回 `[0, MAX_PUNCH_PADDING]` 闭区间内均匀分布的随机长度（对应 Go `randomPaddingLength`）。
fn random_padding_length() -> usize {
    rand::rng().random_range(0..=MAX_PUNCH_PADDING)
}

/// `packet XOR SHA-256(obfsKey || salt)`（对应 Go `xorPunchPacket`）。
///
/// mask 长度可能短于 packet，循环复用（`mask[i % mask.len()]`）。
fn xor_punch_packet(packet: &mut [u8], obfs_key: &[u8], salt: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(obfs_key);
    hasher.update(salt);
    let mask = hasher.finalize();
    let mask_len = mask.len();
    for (i, b) in packet.iter_mut().enumerate() {
        *b ^= mask[i % mask_len];
    }
}

/// 构造 `InvalidData` 错误的助手（前缀与 Go 错误信息一致以便日志对照）。
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("invalid punch packet: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> PunchMetadata {
        let nonce = hex::encode([0xabu8; PUNCH_NONCE_SIZE]);
        let obfs = hex::encode([0xcdu8; PUNCH_OBFS_KEY_SIZE]);
        PunchMetadata { nonce, obfs }
    }

    #[test]
    fn punch_packet_roundtrip_hello() {
        let meta = sample_meta();
        let pkt = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        assert!(pkt.len() >= PUNCH_MIN_WIRE_LEN);
        let decoded = decode_punch_packet(&pkt, &meta).unwrap();
        assert_eq!(decoded.packet_type, PunchPacketType::Hello);
        assert_eq!(decoded.padding_length, pkt.len() - PUNCH_HEADER_LEN - PUNCH_SALT_LEN);
    }

    #[test]
    fn punch_packet_roundtrip_ack() {
        let meta = sample_meta();
        let pkt = encode_punch_packet(PunchPacketType::Ack, &meta).unwrap();
        let decoded = decode_punch_packet(&pkt, &meta).unwrap();
        assert_eq!(decoded.packet_type, PunchPacketType::Ack);
    }

    #[test]
    fn punch_packet_xor_symmetry() {
        // 两次 XOR 应恢复原文：encode 与 decode 互逆的密码学基础
        let mut buf = vec![0xaau8; 100];
        let original = buf.clone();
        let key = vec![0x11u8; 32];
        let salt = vec![0x22u8; 8];
        xor_punch_packet(&mut buf, &key, &salt);
        xor_punch_packet(&mut buf, &key, &salt);
        assert_eq!(buf, original);
    }

    #[test]
    fn punch_packet_wrong_nonce_rejected() {
        let meta1 = sample_meta();
        let meta2 = PunchMetadata {
            nonce: hex::encode([0x00u8; PUNCH_NONCE_SIZE]),
            obfs: meta1.obfs.clone(),
        };
        let pkt = encode_punch_packet(PunchPacketType::Hello, &meta1).unwrap();
        let err = decode_punch_packet(&pkt, &meta2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn punch_packet_too_short_rejected() {
        let meta = sample_meta();
        let err = decode_punch_packet(&[0u8; 10], &meta).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn punch_packet_too_long_rejected() {
        let meta = sample_meta();
        let oversized = vec![0u8; PUNCH_MAX_WIRE_LEN + 1];
        let err = decode_punch_packet(&oversized, &meta).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn punch_packet_bad_magic_rejected() {
        let meta = sample_meta();
        let mut pkt = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        // 翻转 salt 后第一字节（落在 XOR 加密后的 magic 区，破坏 magic 校验）
        pkt[PUNCH_SALT_LEN] ^= 0xff;
        let err = decode_punch_packet(&pkt, &meta).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn punch_packet_type_from_byte() {
        assert_eq!(PunchPacketType::from_byte(0x01), Some(PunchPacketType::Hello));
        assert_eq!(PunchPacketType::from_byte(0x02), Some(PunchPacketType::Ack));
        assert!(PunchPacketType::from_byte(0x00).is_none());
        assert!(PunchPacketType::from_byte(0x03).is_none());
    }
}
