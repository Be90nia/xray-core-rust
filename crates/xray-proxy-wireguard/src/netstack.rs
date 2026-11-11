//! smoltcp 用户态网络栈——**本体已提炼至 [`xray_frame::ipstack`]（B3 净移动，
//! PM 2026-11-11 裁定：移动 + re-export）**。
//!
//! 本模块仅保留 re-export：`WgNetStack` 名称由别名一行保证（`lib.rs` 的对外
//! re-export 签名零变化）；`test_packets` 为本 crate 既有测试消费者的 cfg(test)
//! 副本（主副本在 `xray_frame::ipstack::test_packets`，因 `#[cfg(test)]` 跨
//! crate 不可见而保留；生产构建不携带）。

pub use xray_frame::ipstack::{PacketStack as WgNetStack, *};

/// 隧道内 IP/TCP 测试包构造（wireguard 测试面专用副本，本体已随 netstack 移入
/// `xray_frame::ipstack::test_packets`；此处仅保留 inbound.rs 测试消费的条目，
/// 其余构造器用主副本，避免 dead_code）。
///
/// RX 侧不校验 checksum（VirtualDevice capabilities 仅 Tx），测试包可零校验和。
#[cfg(test)]
pub(crate) mod test_packets {
    use smoltcp::wire::{Ipv4Packet, TcpPacket};

    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_ACK: u8 = 0x10;

    /// 构造 IPv4 + TCP 定长头包（无 payload）。
    pub fn make_tcp_packet(
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 6; // protocol = TCP
        pkt[12..16].copy_from_slice(&src.0);
        pkt[16..20].copy_from_slice(&dst.0);
        pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..32].copy_from_slice(&ack.to_be_bytes());
        pkt[32] = 0x50; // data offset = 5 words
        pkt[33] = flags;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        pkt
    }

    /// 提取 IPv4+TCP 包的 seq（SYN-ACK ISN 用）；非 TCP 包返回 None。
    pub fn tcp_seq_number(pkt: &[u8]) -> Option<u32> {
        let v4 = Ipv4Packet::new_checked(pkt).ok()?;
        if v4.next_header() != smoltcp::wire::IpProtocol::Tcp {
            return None;
        }
        let tcp = TcpPacket::new_checked(v4.payload()).ok()?;
        Some(tcp.seq_number().0 as u32)
    }
}
