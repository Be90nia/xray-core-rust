//! Packet Reader（对应 Go `io.go`）。
//!
//! 从 UDP 包字节流读取多个 segment。

use crate::segment::{read_segment, SegmentKind};

/// 包读取器接口（对应 Go `PacketReader interface`）。
pub trait PacketReader: Send + Sync {
    /// 从字节切片读取所有 segment（对应 Go `Read([]byte) []Segment`）。
    fn read(&self, b: &[u8]) -> Vec<SegmentKind>;
}

/// KCP 包读取器（对应 Go `KCPPacketReader struct{}`）。
#[derive(Debug, Default, Clone, Copy)]
pub struct KCPPacketReader;

impl KCPPacketReader {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PacketReader for KCPPacketReader {
    fn read(&self, mut b: &[u8]) -> Vec<SegmentKind> {
        let mut result = Vec::new();
        while !b.is_empty() {
            match read_segment(b) {
                Some((seg, consumed)) => {
                    if consumed == 0 {
                        break;
                    }
                    result.push(seg);
                    b = &b[consumed..];
                }
                None => break,
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{CmdOnlySegment, Command, Segment};

    #[test]
    fn empty_input_returns_empty() {
        let reader = KCPPacketReader::new();
        assert!(reader.read(&[]).is_empty());
    }

    #[test]
    fn one_byte_input_returns_empty() {
        let reader = KCPPacketReader::new();
        assert!(reader.read(&[1u8]).is_empty());
    }

    #[test]
    fn invalid_cmd_returns_empty() {
        let reader = KCPPacketReader::new();
        assert!(reader.read(&[0, 1, 99, 0]).is_empty());
    }

    #[test]
    fn reads_multiple_segments() {
        let mut seg1 = CmdOnlySegment::new();
        seg1.conv = 1;
        seg1.cmd = Command::Ping;

        let mut seg2 = CmdOnlySegment::new();
        seg2.conv = 2;
        seg2.cmd = Command::Terminate;

        let mut packet = Vec::new();
        packet.resize(seg1.byte_size(), 0);
        seg1.serialize(&mut packet);
        let off = seg1.byte_size();
        packet.resize(off + seg2.byte_size(), 0);
        seg2.serialize(&mut packet[off..]);

        let reader = KCPPacketReader::new();
        let segs = reader.read(&packet);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].conversation(), 1);
        assert_eq!(segs[0].command(), Command::Ping);
        assert_eq!(segs[1].conversation(), 2);
        assert_eq!(segs[1].command(), Command::Terminate);
    }

    #[test]
    fn stops_at_corrupted_segment() {
        let mut seg1 = CmdOnlySegment::new();
        seg1.conv = 1;

        let mut packet = Vec::new();
        packet.resize(seg1.byte_size(), 0);
        seg1.serialize(&mut packet);
        packet.extend_from_slice(&[0, 1, 99, 0]);

        let reader = KCPPacketReader::new();
        let segs = reader.read(&packet);
        assert_eq!(segs.len(), 1);
    }
}
