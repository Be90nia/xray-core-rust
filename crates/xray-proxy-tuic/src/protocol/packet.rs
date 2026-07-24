//! TUIC v5 Packet 帧（UDP relay 切片2）。
//!
//! 帧布局（VER + TYPE 已由 [`crate::protocol::parse_header`] 消费，本结构只处理负载）：
//! ```text
//! +----------+--------+------------+---------+---------+-------+-------+
//! | ASSOC_ID | PKT_ID | FRAG_TOTAL | FRAG_ID | SIZE(2) | ADDR  | DATA  |
//! | 2B BE    | 2B BE  | 1B         | 1B      | 2B BE   | var   | SIZE  |
//! +----------+--------+------------+---------+---------+-------+-------+
//! ```
//!
//! ## 传输模式
//!
//! TUIC v5 支持两种 UDP relay 模式：
//! - **native**（推荐）：通过 QUIC DATAGRAM 传输，保留 UDP 不可靠语义
//! - **quic**（本切片实现）：通过 BI STREAM 传输，可靠但顺序到达
//!
//! 本切片实现 **quic 模式**：每个 UDP 包独占一个 bi-stream，
//! 客户端发送 Packet 帧后写入 DATA，server 解析 ADDR dial UDP，
//! 收到响应后用同样的 Packet 帧格式回写。
//!
//! ## 分片
//!
//! 当 UDP 负载超过 QUIC datagram MTU（约 1200B）时需要分片。
//! 本切片仅实现非分片路径（`FRAG_TOTAL=1, FRAG_ID=0`），
//! 分片重组留待后续。`FRAG_TOTAL > 1` 时返回 [`TuicError::UnsupportedFragment`]。
//!
//! [`TuicError::UnsupportedFragment`]: crate::error::TuicError::UnsupportedFragment

use bytes::{Buf, BufMut};

use super::address::Address;
use crate::error::{Result, TuicError};

/// UDP 包最大负载（bi-stream 模式下为合理上限，避免恶意 client 请求超大分配）。
pub const MAX_PACKET_PAYLOAD: usize = 16 * 1024;

/// TUIC v5 Packet 帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// UDP 关联 ID（客户端分配，同一关联的包共用一个 UDP socket）。
    pub assoc_id: u16,
    /// 包序号（同 assoc 内递增，用于分片重组排序）。
    pub pkt_id: u16,
    /// 分片总数（1 = 不分片）。
    pub frag_total: u8,
    /// 当前分片序号（0-based）。
    pub frag_id: u8,
    /// 目标地址（响应方向时为 server 实际出口地址）。
    pub addr: Address,
    /// 负载数据。
    pub data: Vec<u8>,
}

impl Packet {
    /// 构造非分片 Packet（最常见路径）。
    #[must_use]
    pub fn new(assoc_id: u16, pkt_id: u16, addr: Address, data: Vec<u8>) -> Self {
        Self {
            assoc_id,
            pkt_id,
            frag_total: 1,
            frag_id: 0,
            addr,
            data,
        }
    }

    /// 序列化（不含 VER + TYPE，由调用方先写）。
    ///
    /// 布局：`ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2) + ADDR + DATA`。
    pub fn write_payload<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.assoc_id);
        buf.put_u16(self.pkt_id);
        buf.put_u8(self.frag_total);
        buf.put_u8(self.frag_id);
        let size = u16::try_from(self.data.len()).unwrap_or(u16::MAX);
        buf.put_u16(size);
        self.addr.write_to(buf);
        buf.put_slice(&self.data[..size as usize]);
    }

    /// 序列化所需字节数（含 VER + TYPE 头部 2 字节）。
    ///
    /// 用于预分配 buffer；DATAGRAM 模式下须小于 QUIC MTU。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        // VER + TYPE + ASSOC + PKT + FRAG_TOTAL + FRAG_ID + SIZE
        let header = 2 + 2 + 2 + 1 + 1 + 2;
        header + self.addr.encoded_len() + self.data.len()
    }

    /// 从 [`Buf`] 解析负载（调用方已用 [`crate::protocol::parse_header`] 消费 VER+TYPE，
    /// 并确认 TYPE 为 [`crate::protocol::Command::type_code`] 中 `PACKET`）。
    ///
    /// # Errors
    ///
    /// - [`TuicError::UnexpectedEof`]：字节不足
    /// - [`TuicError::UnsupportedFragment`]：检测到分片（`FRAG_TOTAL > 1`）
    /// - [`TuicError::PacketTooLarge`]：SIZE 超过 [`MAX_PACKET_PAYLOAD`]
    pub fn read_payload<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(TuicError::UnexpectedEof("packet header (>=8 bytes)"));
        }
        let assoc_id = buf.get_u16();
        let pkt_id = buf.get_u16();
        let frag_total = buf.get_u8();
        let frag_id = buf.get_u8();
        let size = buf.get_u16() as usize;
        if size > MAX_PACKET_PAYLOAD {
            return Err(TuicError::PacketTooLarge(size));
        }
        let addr = Address::read_from(buf)?;
        if buf.remaining() < size {
            return Err(TuicError::UnexpectedEof("packet data"));
        }
        let mut data = vec![0u8; size];
        buf.copy_to_slice(&mut data);
        if frag_total > 1 {
            // 切片2 不实现分片重组；caller 收到分片包直接拒绝。
            return Err(TuicError::UnsupportedFragment { frag_total, frag_id });
        }
        Ok(Self {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            addr,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::VERSION;
    use std::net::Ipv4Addr;

    fn roundtrip(pkt: &Packet) {
        // 完整序列化：VER + TYPE + 负载
        let mut buf = Vec::with_capacity(pkt.encoded_len());
        buf.put_u8(VERSION);
        buf.put_u8(crate::protocol::command::type_code::PACKET);
        pkt.write_payload(&mut buf);
        assert_eq!(buf.len(), pkt.encoded_len());

        // 解析：先消费 VER+TYPE
        let mut cursor = &buf[..];
        let _type_byte = crate::protocol::parse_header(&mut cursor).unwrap();
        let parsed = Packet::read_payload(&mut cursor).unwrap();
        assert_eq!(*pkt, parsed);
        assert!(cursor.is_empty());
    }

    #[test]
    fn packet_roundtrip_ipv4() {
        let pkt = Packet::new(
            0x1234,
            0x0001,
            Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53),
            b"query-dns".to_vec(),
        );
        roundtrip(&pkt);
    }

    #[test]
    fn packet_roundtrip_domain() {
        let pkt = Packet::new(
            0x5678,
            0x0002,
            Address::Domain("example.com".into(), 443),
            vec![0u8; 100],
        );
        roundtrip(&pkt);
    }

    #[test]
    fn packet_roundtrip_empty_data() {
        let pkt = Packet::new(0xffff, 0, Address::None, Vec::new());
        roundtrip(&pkt);
    }

    #[test]
    fn packet_roundtrip_none_addr() {
        // 响应方向常用 None 地址（server 拒绝或无需指定源）
        let pkt = Packet::new(1, 1, Address::None, b"resp".to_vec());
        roundtrip(&pkt);
    }

    #[test]
    fn encoded_len_matches() {
        let pkt = Packet::new(
            1,
            2,
            Address::Ipv4(Ipv4Addr::LOCALHOST, 8080),
            vec![0xab; 50],
        );
        // VER+TYPE(2) + ASSOC(2) + PKT(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
        // + ADDR(1+4+2=7) + DATA(50) = 67
        assert_eq!(pkt.encoded_len(), 2 + 2 + 2 + 1 + 1 + 2 + 7 + 50);
    }

    #[test]
    fn truncated_header_rejected() {
        let mut buf = &b"\x05\x02\x12\x34"[..]; // 仅 4 字节，不足 header(>=8)
        let _ = crate::protocol::parse_header(&mut buf).unwrap();
        let err = Packet::read_payload(&mut buf).unwrap_err();
        assert!(matches!(err, TuicError::UnexpectedEof(_)));
    }

    #[test]
    fn oversized_size_rejected() {
        let mut buf = vec![0x05, crate::protocol::command::type_code::PACKET];
        // 构造 header：assoc=1, pkt=1, frag_total=1, frag_id=0, size=MAX+1
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&((MAX_PACKET_PAYLOAD + 1) as u16).to_be_bytes());
        // None 地址
        buf.push(0xff);
        buf.extend_from_slice(&0u16.to_be_bytes());
        let mut cursor = &buf[..];
        let _ = crate::protocol::parse_header(&mut cursor).unwrap();
        let err = Packet::read_payload(&mut cursor).unwrap_err();
        assert!(matches!(err, TuicError::PacketTooLarge(_)));
    }
}
