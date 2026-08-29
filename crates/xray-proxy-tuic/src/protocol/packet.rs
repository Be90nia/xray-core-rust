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
//! 接收端用 [`FragmentAssembler`]（per-assoc, per-pkt_id 缓存）按
//! `frag_id` 升序拼接为完整 UDP 负载，详见其文档。
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
    /// 分片（`FRAG_TOTAL > 1`）也正常返回 Packet，caller 需自行喂给
    /// [`FragmentAssembler`] 重组（bd 2x5）。
    ///
    /// # Errors
    ///
    /// - [`TuicError::UnexpectedEof`]：字节不足
    /// - [`TuicError::PacketTooLarge`]：SIZE 超过 [`MAX_PACKET_PAYLOAD`]（单分片上限）
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

/// 分片重组器（per-assoc, per-pkt_id 缓存分片）。
///
/// spec：客户端将 >MTU 的 UDP 包拆成 `frag_total` 个分片（同 `pkt_id`），
/// 每个分片带 `frag_id`（0-based）和 `size`（本片字节数）。
/// 接收端缓存分片直到全部到达，按 `frag_id` 升序拼接为完整 UDP 负载。
///
/// ## 行为
/// - 单片（`frag_total=1`）即时返回，不入缓存
/// - 多片：缓存到对应槽位，全部到齐时输出完整包并清理
/// - 重复片（同 `frag_id`）忽略
/// - `frag_id >= frag_total` 或 `frag_total == 0` 视为非法，返回 [`TuicError::UnsupportedFragment`]
/// - 新 `pkt_id` 到达会丢弃旧缓存（同 hysteria `Defragger` 简化策略）
///
/// ponytail: 单 pkt_id 窗口简化（与 hysteria 一致），不维护 GC。
/// 多多并行 pkt_id 时升级为 `HashMap<u16, PendingFrag>`。
#[derive(Debug, Default)]
pub struct FragmentAssembler {
    /// 当前重组的 pkt_id。
    pkt_id: u16,
    /// 已收到的分片槽（None = 未到）。
    frags: Vec<Option<Vec<u8>>>,
    /// 已收到分片数。
    received: u8,
    /// 首个分片的 addr（spec：非首片 ADDR=0xff None）。
    first_addr: Option<Address>,
    /// assoc_id（透传给最终重组包）。
    assoc_id: u16,
}

impl FragmentAssembler {
    /// 构造空重组器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 投入一个分片，若所有分片齐备返回完整 UDP 包；否则返回 None。
    ///
    /// 单片（`frag_total=1`）直接返回 `Some(pkt)` 不缓存。
    /// 多片：缓存到槽位；新 pkt_id 重置状态；同 frag_id 重复忽略。
    ///
    /// # Errors
    /// - [`TuicError::UnsupportedFragment`]: 非法 `frag_total`/`frag_id` 组合
    pub fn feed(&mut self, pkt: Packet) -> Result<Option<Packet>> {
        // 单片直通
        if pkt.frag_total <= 1 {
            return Ok(Some(pkt));
        }
        if pkt.frag_total == 0 || pkt.frag_id >= pkt.frag_total {
            return Err(TuicError::UnsupportedFragment {
                frag_total: pkt.frag_total,
                frag_id: pkt.frag_id,
            });
        }
        // 新 pkt_id 或 frag_total 变化 → 重置
        if pkt.pkt_id != self.pkt_id || self.frags.len() != pkt.frag_total as usize {
            self.pkt_id = pkt.pkt_id;
            self.frags = vec![None; pkt.frag_total as usize];
            self.received = 0;
            self.first_addr = None;
        }
        self.assoc_id = pkt.assoc_id;
        if self.frags[pkt.frag_id as usize].is_none() {
            // 首片记录 addr（spec 非首片 addr=0xff None）
            if pkt.frag_id == 0 {
                self.first_addr = Some(pkt.addr.clone());
            }
            self.frags[pkt.frag_id as usize] = Some(pkt.data);
            self.received = self.received.saturating_add(1);
        }
        if self.received == pkt.frag_total {
            // 全部到齐：按 frag_id 升序拼接
            let mut data = Vec::new();
            for frag in &self.frags {
                if let Some(f) = frag {
                    data.extend_from_slice(f);
                }
            }
            let addr = self
                .first_addr
                .take()
                .unwrap_or(crate::protocol::address::Address::None);
            let completed = Packet {
                assoc_id: self.assoc_id,
                pkt_id: self.pkt_id,
                frag_total: 1,
                frag_id: 0,
                addr,
                data,
            };
            // 重置
            self.frags.clear();
            self.received = 0;
            self.first_addr = None;
            return Ok(Some(completed));
        }
        Ok(None)
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

    /// 构造一个手动分片 Packet（绕过 read_payload 的单片路径）。
    fn make_frag(assoc_id: u16, pkt_id: u16, frag_id: u8, frag_total: u8, data: Vec<u8>) -> Packet {
        Packet {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            addr: if frag_id == 0 {
                Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53)
            } else {
                Address::None
            },
            data,
        }
    }

    #[test]
    fn fragment_single_passthrough() {
        let mut asm = FragmentAssembler::new();
        let p = make_frag(1, 1, 0, 1, b"hello".to_vec());
        let r = asm.feed(p.clone()).unwrap();
        assert_eq!(r.unwrap(), p);
    }

    #[test]
    fn fragment_ordered_assemble() {
        let mut asm = FragmentAssembler::new();
        // 3 片按序到达：0,1,2
        let f0 = make_frag(1, 42, 0, 3, b"AAA".to_vec());
        let f1 = make_frag(1, 42, 1, 3, b"BBB".to_vec());
        let f2 = make_frag(1, 42, 2, 3, b"CCC".to_vec());
        assert!(asm.feed(f0).unwrap().is_none());
        assert!(asm.feed(f1).unwrap().is_none());
        let r = asm.feed(f2).unwrap().expect("3rd should complete");
        assert_eq!(r.frag_total, 1);
        assert_eq!(r.frag_id, 0);
        assert_eq!(r.pkt_id, 42);
        assert_eq!(r.assoc_id, 1);
        assert_eq!(r.data, b"AAABBBCCC");
        // 首片 addr 应保留
        assert_eq!(
            r.addr,
            Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53)
        );
    }

    #[test]
    fn fragment_out_of_order_assemble() {
        let mut asm = FragmentAssembler::new();
        // 3 片乱序：2,0,1
        let f0 = make_frag(2, 7, 0, 3, b"AAA".to_vec());
        let f1 = make_frag(2, 7, 1, 3, b"BBB".to_vec());
        let f2 = make_frag(2, 7, 2, 3, b"CCC".to_vec());
        assert!(asm.feed(f2).unwrap().is_none());
        assert!(asm.feed(f0).unwrap().is_none());
        let r = asm.feed(f1).unwrap().expect("3rd should complete");
        // 拼接顺序必须按 frag_id 升序
        assert_eq!(r.data, b"AAABBBCCC");
    }

    #[test]
    fn fragment_duplicate_ignored() {
        let mut asm = FragmentAssembler::new();
        let f0 = make_frag(1, 1, 0, 2, b"X".to_vec());
        let f1 = make_frag(1, 1, 1, 2, b"Y".to_vec());
        assert!(asm.feed(f0.clone()).unwrap().is_none());
        // 重复 f0 应被忽略（received 不递增）
        assert!(asm.feed(f0).unwrap().is_none());
        let r = asm.feed(f1).unwrap().expect("2nd unique should complete");
        assert_eq!(r.data, b"XY");
    }

    #[test]
    fn fragment_invalid_frag_id() {
        let mut asm = FragmentAssembler::new();
        let bad = make_frag(1, 1, 5, 3, b"oops".to_vec()); // frag_id=5 >= frag_total=3
        let err = asm.feed(bad).unwrap_err();
        assert!(matches!(err, TuicError::UnsupportedFragment { .. }));
    }

    #[test]
    fn fragment_new_pkt_id_resets() {
        let mut asm = FragmentAssembler::new();
        // pkt_id=1 投 1 片
        let f0 = make_frag(1, 1, 0, 2, b"A".to_vec());
        assert!(asm.feed(f0).unwrap().is_none());
        // 新 pkt_id=99 应重置
        let g0 = make_frag(1, 99, 0, 2, b"B".to_vec());
        assert!(asm.feed(g0).unwrap().is_none());
        let g1 = make_frag(1, 99, 1, 2, b"D".to_vec());
        let r = asm.feed(g1).unwrap().expect("2nd pkt complete");
        assert_eq!(r.pkt_id, 99);
        assert_eq!(r.data, b"BD");
    }

    #[test]
    fn fragment_roundtrip_via_write_read() {
        // 验证 wire format：两个分片序列化为 Packet 帧，再喂给 assembler，输出应一致
        let mut asm = FragmentAssembler::new();
        let f0 = make_frag(3, 100, 0, 2, vec![0xAB; 100]);
        let f1 = make_frag(3, 100, 1, 2, vec![0xCD; 100]);

        // 序列化 f0
        let mut buf = vec![VERSION, crate::protocol::command::type_code::PACKET];
        f0.write_payload(&mut buf);
        let mut cur = &buf[..];
        let _ = crate::protocol::parse_header(&mut cur).unwrap();
        let p0 = Packet::read_payload(&mut cur).unwrap();
        assert_eq!(p0.frag_total, 2);
        assert_eq!(p0.frag_id, 0);
        assert!(asm.feed(p0).unwrap().is_none());

        // 序列化 f1
        let mut buf = vec![VERSION, crate::protocol::command::type_code::PACKET];
        f1.write_payload(&mut buf);
        let mut cur = &buf[..];
        let _ = crate::protocol::parse_header(&mut cur).unwrap();
        let p1 = Packet::read_payload(&mut cur).unwrap();
        assert_eq!(p1.frag_total, 2);
        assert_eq!(p1.frag_id, 1);
        let r = asm.feed(p1).unwrap().expect("complete");
        assert_eq!(r.data.len(), 200);
        assert!(r.data[..100].iter().all(|&b| b == 0xAB));
        assert!(r.data[100..].iter().all(|&b| b == 0xCD));
    }
}
