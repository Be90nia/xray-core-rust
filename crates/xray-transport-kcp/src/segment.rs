//! KCP Segment 协议（对应 Go `segment.go`）。
//!
//! Segment 二进制格式（与 xray Go 端字节级兼容）：
//!
//! ```text
//! 公共头 (4 bytes):
//!   [0..2]  conv: u16 BE
//!   [2]     cmd:  Command (u8)
//!   [3]     opt:  SegmentOption (u8)
//!
//! DataSegment (变长):
//!   +4..8   timestamp:    u32 BE
//!   +8..12  number:       u32 BE
//!   +12..16 sending_next: u32 BE
//!   +16..18 data_len:     u16 BE
//!   +18..   payload (data_len bytes)
//!
//! AckSegment (变长):
//!   +4..8   recv_window:  u32 BE
//!   +8..12  recv_next:    u32 BE
//!   +12..16 timestamp:    u32 BE
//!   +16     count:        u8
//!   +17..   number_list (count × u32 BE)
//!
//! CmdOnlySegment (固定 16 bytes):
//!   +4..8   sending_next:   u32 BE
//!   +8..12  receiving_next: u32 BE
//!   +12..16 peer_rto:       u32 BE
//! ```

use xray_buf::buffer::Buffer;

/// KCP 命令类型（对应 Go `Command byte`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Command {
    /// ACK 确认（对应 `AckSegment`）。
    Ack = 0,
    /// 数据（对应 `DataSegment`）。
    Data = 1,
    /// 对端终止连接。
    Terminate = 2,
    /// 心跳。
    Ping = 3,
}

impl Command {
    /// 从 u8 还原；未知值返回 `None`（Go 直接强转，Rust 更稳健）。
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ack),
            1 => Some(Self::Data),
            2 => Some(Self::Terminate),
            3 => Some(Self::Ping),
            _ => None,
        }
    }
}

/// Segment 选项位（对应 Go `SegmentOption byte`）。
pub type SegmentOption = u8;

/// 关闭连接位（对应 Go `SegmentOptionClose = 1`）。
pub const SEGMENT_OPTION_CLOSE: SegmentOption = 1;

/// DataSegment 头部开销字节数（不含 payload，对应 Go `DataSegmentOverhead = 18`）。
pub const DATA_SEGMENT_OVERHEAD: usize = 18;

/// 兼容旧 API 命名（推荐使用大写常量风格）。
#[allow(non_upper_case_globals)]
pub const DataSegmentOverhead: usize = DATA_SEGMENT_OVERHEAD;

/// Segment trait：所有 segment 类型的统一接口。
///
/// 对应 Go 的 `Segment interface`。
pub trait Segment: Send {
    /// 释放资源（缓冲区回池）。多次调用安全。
    fn release(&mut self);

    /// 当前 segment 所属会话 ID。
    fn conversation(&self) -> u16;

    /// 命令类型。
    fn command(&self) -> Command;

    /// 序列化后的字节数（用于预分配缓冲）。
    fn byte_size(&self) -> usize;

    /// 序列化到给定缓冲（长度必须 ≥ `byte_size()`）。
    fn serialize(&self, buf: &mut [u8]);

    /// 从 `body` 解析（公共头已剥除）。返回 `(valid, consumed)`。
    fn parse(&mut self, conv: u16, cmd: Command, opt: SegmentOption, body: &[u8]) -> (bool, usize);
}

// ============== DataSegment ==============

/// 数据段。
///
/// 对应 Go `DataSegment`，但 payload 用 `xray_buf::Buffer` 替代 Go `*buf.Buffer`。
#[derive(Debug)]
pub struct DataSegment {
    /// 会话 ID。
    pub conv: u16,
    /// 选项位。
    pub option: SegmentOption,
    /// 发送时间戳。
    pub timestamp: u32,
    /// 数据序号。
    pub number: u32,
    /// 对端期望的下一个发送序号（流控）。
    pub sending_next: u32,
    /// 数据负载。
    pub payload: Option<Buffer>,

    /// 内部：超时时间戳（由 sending_window 维护）。
    pub timeout: u32,
    /// 内部：已发送次数（由 sending_window 维护，用于丢包检测）。
    pub transmit: u32,
}

impl DataSegment {
    /// 构造空 payload 的 DataSegment（对应 Go `NewDataSegment`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            conv: 0,
            option: 0,
            timestamp: 0,
            number: 0,
            sending_next: 0,
            payload: None,
            timeout: 0,
            transmit: 0,
        }
    }

    /// 取出 payload，留下 `None`（对应 Go `Detach()`）。
    #[must_use]
    pub fn detach(&mut self) -> Option<Buffer> {
        self.payload.take()
    }

    /// 获取可变 payload（懒分配，对应 Go `Data()`）。
    pub fn data(&mut self) -> &mut Buffer {
        self.payload.get_or_insert_with(Buffer::new)
    }
}

impl Default for DataSegment {
    fn default() -> Self {
        Self::new()
    }
}

impl Segment for DataSegment {
    fn release(&mut self) {
        if let Some(mut b) = self.payload.take() {
            b.release();
        }
    }

    fn conversation(&self) -> u16 {
        self.conv
    }

    fn command(&self) -> Command {
        Command::Data
    }

    fn byte_size(&self) -> usize {
        DATA_SEGMENT_OVERHEAD + self.payload.as_ref().map_or(0, |b| b.len())
    }

    fn serialize(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= self.byte_size());
        buf[0..2].copy_from_slice(&self.conv.to_be_bytes());
        buf[2] = Command::Data as u8;
        buf[3] = self.option;
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.number.to_be_bytes());
        buf[12..16].copy_from_slice(&self.sending_next.to_be_bytes());
        let payload_len: u16 = self.payload.as_ref().map_or(0, |b| b.len()) as u16;
        buf[16..18].copy_from_slice(&payload_len.to_be_bytes());
        if let Some(b) = &self.payload {
            buf[18..18 + b.len()].copy_from_slice(b.bytes());
        }
    }

    fn parse(
        &mut self,
        conv: u16,
        _cmd: Command,
        opt: SegmentOption,
        body: &[u8],
    ) -> (bool, usize) {
        self.conv = conv;
        self.option = opt;
        if body.len() < 14 {
            return (false, 0);
        }
        self.timestamp = u32::from_be_bytes(body[0..4].try_into().unwrap());
        self.number = u32::from_be_bytes(body[4..8].try_into().unwrap());
        self.sending_next = u32::from_be_bytes(body[8..12].try_into().unwrap());
        let data_len = u16::from_be_bytes(body[12..14].try_into().unwrap()) as usize;
        if body.len() < 14 + data_len {
            return (false, 0);
        }
        let payload = self.data();
        payload.clear();
        payload.write_from(&body[14..14 + data_len]);
        (true, 14 + data_len)
    }
}

// ============== AckSegment ==============

/// ACK 段上限（对应 Go `ackNumberLimit = 128`）。
pub const ACK_NUMBER_LIMIT: usize = 128;

/// ACK 段。
#[derive(Debug, Default)]
pub struct AckSegment {
    /// 会话 ID。
    pub conv: u16,
    /// 选项位。
    pub option: SegmentOption,
    /// 接收窗口（flow control：对端发送不应超过此序号）。
    pub receiving_window: u32,
    /// 期望的下一个接收序号。
    pub receiving_next: u32,
    /// 时间戳（对端回 ACK 时回传用于 RTT 计算）。
    pub timestamp: u32,
    /// 已收到的数据序号列表。
    pub number_list: Vec<u32>,
    /// 容量上限（对应 Go `Limit int`）。
    pub limit: usize,
}

impl AckSegment {
    /// 构造（对应 Go `NewAckSegment(limit)`，limit 自动夹紧到 [1, ACK_NUMBER_LIMIT]）。
    #[must_use]
    pub fn new(limit: usize) -> Self {
        let clamped = limit.clamp(1, ACK_NUMBER_LIMIT);
        Self { limit: clamped, ..Self::default() }
    }

    /// 追加一个 number（对应 Go `PutNumber`）。
    pub fn put_number(&mut self, n: u32) {
        self.number_list.push(n);
    }

    /// 更新时间戳（仅在 wrap-safe 增长时更新，对应 Go `PutTimestamp`）。
    pub fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFF_FFFF {
            self.timestamp = timestamp;
        }
    }

    /// 是否满（对应 Go `IsFull`）。
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.number_list.len() == self.limit
    }

    /// 是否空（对应 Go `IsEmpty`）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.number_list.is_empty()
    }
}

impl Segment for AckSegment {
    fn release(&mut self) {
        self.number_list.clear();
    }

    fn conversation(&self) -> u16 {
        self.conv
    }

    fn command(&self) -> Command {
        Command::Ack
    }

    fn byte_size(&self) -> usize {
        // 公共头 4 + recv_window 4 + recv_next 4 + ts 4 + count 1 + number_list×4
        17 + self.number_list.len() * 4
    }

    fn serialize(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= self.byte_size());
        buf[0..2].copy_from_slice(&self.conv.to_be_bytes());
        buf[2] = Command::Ack as u8;
        buf[3] = self.option;
        buf[4..8].copy_from_slice(&self.receiving_window.to_be_bytes());
        buf[8..12].copy_from_slice(&self.receiving_next.to_be_bytes());
        buf[12..16].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[16] = self.number_list.len() as u8;
        let mut n = 17;
        for &num in &self.number_list {
            buf[n..n + 4].copy_from_slice(&num.to_be_bytes());
            n += 4;
        }
    }

    fn parse(
        &mut self,
        conv: u16,
        _cmd: Command,
        opt: SegmentOption,
        body: &[u8],
    ) -> (bool, usize) {
        self.conv = conv;
        self.option = opt;
        if body.len() < 13 {
            return (false, 0);
        }
        self.receiving_window = u32::from_be_bytes(body[0..4].try_into().unwrap());
        self.receiving_next = u32::from_be_bytes(body[4..8].try_into().unwrap());
        self.timestamp = u32::from_be_bytes(body[8..12].try_into().unwrap());
        let count = body[12] as usize;
        if body.len() < 13 + count * 4 {
            return (false, 0);
        }
        self.number_list.clear();
        self.number_list.reserve(count);
        for i in 0..count {
            let off = 13 + i * 4;
            self.number_list.push(u32::from_be_bytes(body[off..off + 4].try_into().unwrap()));
        }
        (true, 13 + count * 4)
    }
}

// ============== CmdOnlySegment ==============

/// CmdOnly 段（Ping / Terminate 等，无 payload）。
#[derive(Debug, Clone, Copy)]
pub struct CmdOnlySegment {
    /// 会话 ID。
    pub conv: u16,
    /// 命令。
    pub cmd: Command,
    /// 选项位。
    pub option: SegmentOption,
    /// 发送侧下一个序号。
    pub sending_next: u32,
    /// 接收侧下一个序号。
    pub receiving_next: u32,
    /// 对端 RTO（用于 peer RTO 同步）。
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    /// 构造（对应 Go `NewCmdOnlySegment`，默认 cmd = `Command::Ping`）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for CmdOnlySegment {
    fn default() -> Self {
        Self {
            conv: 0,
            cmd: Command::Ping,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        }
    }
}

impl Segment for CmdOnlySegment {
    fn release(&mut self) {}

    fn conversation(&self) -> u16 {
        self.conv
    }

    fn command(&self) -> Command {
        self.cmd
    }

    fn byte_size(&self) -> usize {
        16
    }

    fn serialize(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= self.byte_size());
        buf[0..2].copy_from_slice(&self.conv.to_be_bytes());
        buf[2] = self.cmd as u8;
        buf[3] = self.option;
        buf[4..8].copy_from_slice(&self.sending_next.to_be_bytes());
        buf[8..12].copy_from_slice(&self.receiving_next.to_be_bytes());
        buf[12..16].copy_from_slice(&self.peer_rto.to_be_bytes());
    }

    fn parse(&mut self, conv: u16, cmd: Command, opt: SegmentOption, body: &[u8]) -> (bool, usize) {
        self.conv = conv;
        self.cmd = cmd;
        self.option = opt;
        if body.len() < 12 {
            return (false, 0);
        }
        self.sending_next = u32::from_be_bytes(body[0..4].try_into().unwrap());
        self.receiving_next = u32::from_be_bytes(body[4..8].try_into().unwrap());
        self.peer_rto = u32::from_be_bytes(body[8..12].try_into().unwrap());
        (true, 12)
    }
}

// ============== ReadSegment ==============

/// 从字节切片读取一个 segment（对应 Go `ReadSegment`）。
///
/// 返回 `(segment, consumed_bytes)`。无足够数据或 cmd 非法返回 `None`。
pub fn read_segment(buf: &[u8]) -> Option<(SegmentKind, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes([buf[0], buf[1]]);
    let cmd = Command::from_u8(buf[2])?;
    let opt = buf[3];
    let body = &buf[4..];

    let mut seg = match cmd {
        Command::Data => SegmentKind::Data(DataSegment::new()),
        Command::Ack => SegmentKind::Ack(AckSegment::new(ACK_NUMBER_LIMIT)),
        Command::Terminate | Command::Ping => SegmentKind::Cmd(CmdOnlySegment::new()),
    };
    let (valid, consumed_body) = match &mut seg {
        SegmentKind::Data(s) => s.parse(conv, cmd, opt, body),
        SegmentKind::Ack(s) => s.parse(conv, cmd, opt, body),
        SegmentKind::Cmd(s) => s.parse(conv, cmd, opt, body),
    };
    if !valid {
        return None;
    }
    Some((seg, 4 + consumed_body))
}

/// Segment 的 tagged union（避免 `Box<dyn Segment>` 开销，用于 dispatch）。
#[derive(Debug)]
pub enum SegmentKind {
    /// 数据段。
    Data(DataSegment),
    /// ACK 段。
    Ack(AckSegment),
    /// 命令段（Ping / Terminate）。
    Cmd(CmdOnlySegment),
}

impl SegmentKind {
    /// 会话 ID（统一访问）。
    #[must_use]
    pub fn conversation(&self) -> u16 {
        match self {
            Self::Data(s) => s.conv,
            Self::Ack(s) => s.conv,
            Self::Cmd(s) => s.conv,
        }
    }

    /// 命令类型（统一访问）。
    #[must_use]
    pub fn command(&self) -> Command {
        match self {
            Self::Data(_) => Command::Data,
            Self::Ack(_) => Command::Ack,
            Self::Cmd(s) => s.cmd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_segment_returns_none_for_short_input() {
        assert!(read_segment(&[]).is_none());
        assert!(read_segment(&[1u8]).is_none());
        assert!(read_segment(&[1u8, 2, 3]).is_none());
    }

    #[test]
    fn read_segment_returns_none_for_invalid_cmd() {
        assert!(read_segment(&[0, 1, 99, 0]).is_none());
    }

    #[test]
    fn data_segment_round_trip() {
        let mut seg = DataSegment::new();
        seg.conv = 1;
        seg.timestamp = 3;
        seg.number = 4;
        seg.sending_next = 5;
        seg.data().write_from(b"abcd");

        let n = seg.byte_size();
        assert_eq!(n, DATA_SEGMENT_OVERHEAD + 4);
        let mut buf = vec![0u8; n];
        seg.serialize(&mut buf);

        let (parsed, consumed) = read_segment(&buf).expect("parse ok");
        assert_eq!(consumed, n);
        match parsed {
            SegmentKind::Data(s) => {
                assert_eq!(s.conv, 1);
                assert_eq!(s.timestamp, 3);
                assert_eq!(s.number, 4);
                assert_eq!(s.sending_next, 5);
                assert_eq!(s.payload.as_ref().unwrap().bytes(), b"abcd");
            },
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn one_byte_data_segment_round_trip() {
        let mut seg = DataSegment::new();
        seg.conv = 1;
        seg.timestamp = 3;
        seg.number = 4;
        seg.sending_next = 5;
        seg.data().write_byte(b'a');

        let n = seg.byte_size();
        let mut buf = vec![0u8; n];
        seg.serialize(&mut buf);

        let (parsed, consumed) = read_segment(&buf).expect("parse ok");
        assert_eq!(consumed, n);
        match parsed {
            SegmentKind::Data(s) => {
                assert_eq!(s.payload.as_ref().unwrap().bytes(), b"a");
            },
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn ack_segment_round_trip() {
        let mut seg = AckSegment::new(128);
        seg.conv = 1;
        seg.receiving_window = 2;
        seg.receiving_next = 3;
        seg.timestamp = 10;
        seg.number_list = vec![1, 3, 5, 7, 9];

        let n = seg.byte_size();
        let mut buf = vec![0u8; n];
        seg.serialize(&mut buf);

        let (parsed, consumed) = read_segment(&buf).expect("parse ok");
        assert_eq!(consumed, n);
        match parsed {
            SegmentKind::Ack(s) => {
                assert_eq!(s.conv, 1);
                assert_eq!(s.receiving_window, 2);
                assert_eq!(s.receiving_next, 3);
                assert_eq!(s.timestamp, 10);
                assert_eq!(s.number_list, vec![1, 3, 5, 7, 9]);
            },
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[test]
    fn cmd_only_segment_round_trip_ping() {
        let mut seg = CmdOnlySegment::new();
        seg.conv = 1;
        seg.cmd = Command::Ping;
        seg.option = SEGMENT_OPTION_CLOSE;
        seg.sending_next = 11;
        seg.receiving_next = 13;
        seg.peer_rto = 15;

        let n = seg.byte_size();
        assert_eq!(n, 16);
        let mut buf = vec![0u8; n];
        seg.serialize(&mut buf);

        let (parsed, consumed) = read_segment(&buf).expect("parse ok");
        assert_eq!(consumed, 16);
        match parsed {
            SegmentKind::Cmd(s) => {
                assert_eq!(s.conv, 1);
                assert_eq!(s.cmd, Command::Ping);
                assert_eq!(s.option, SEGMENT_OPTION_CLOSE);
                assert_eq!(s.sending_next, 11);
                assert_eq!(s.receiving_next, 13);
                assert_eq!(s.peer_rto, 15);
            },
            other => panic!("expected Cmd, got {other:?}"),
        }
    }

    #[test]
    fn cmd_only_segment_round_trip_terminate() {
        let mut seg = CmdOnlySegment::new();
        seg.conv = 42;
        seg.cmd = Command::Terminate;

        let n = seg.byte_size();
        let mut buf = vec![0u8; n];
        seg.serialize(&mut buf);

        let (parsed, _) = read_segment(&buf).expect("parse ok");
        match parsed {
            SegmentKind::Cmd(s) => {
                assert_eq!(s.conv, 42);
                assert_eq!(s.cmd, Command::Terminate);
            },
            other => panic!("expected Cmd, got {other:?}"),
        }
    }

    #[test]
    fn ack_segment_limit_clamps() {
        assert_eq!(AckSegment::new(0).limit, 1);
        assert_eq!(AckSegment::new(1).limit, 1);
        assert_eq!(AckSegment::new(ACK_NUMBER_LIMIT).limit, ACK_NUMBER_LIMIT);
        assert_eq!(AckSegment::new(ACK_NUMBER_LIMIT + 100).limit, ACK_NUMBER_LIMIT);
    }

    #[test]
    fn ack_segment_is_full_and_empty() {
        let mut seg = AckSegment::new(3);
        assert!(seg.is_empty());
        assert!(!seg.is_full());

        seg.put_number(1);
        seg.put_number(2);
        assert!(!seg.is_empty());
        assert!(!seg.is_full());

        seg.put_number(3);
        assert!(seg.is_full());
        assert!(!seg.is_empty());
    }

    #[test]
    fn put_timestamp_only_grows_wrap_safe() {
        let mut seg = AckSegment::new(1);
        seg.timestamp = 100;
        seg.put_timestamp(50);
        assert_eq!(seg.timestamp, 100);
        seg.put_timestamp(200);
        assert_eq!(seg.timestamp, 200);
    }

    #[test]
    fn data_segment_release_drops_payload() {
        let mut seg = DataSegment::new();
        seg.data().write_byte(b'x');
        assert!(seg.payload.is_some());
        seg.release();
        assert!(seg.payload.is_none());
        seg.release();
    }

    #[test]
    fn data_segment_detach_takes_payload() {
        let mut seg = DataSegment::new();
        seg.data().write_byte(b'x');
        let taken = seg.detach();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().bytes(), b"x");
        assert!(seg.payload.is_none());

        let new_buf = seg.data();
        assert!(new_buf.is_empty());
    }

    #[test]
    fn read_segment_invalid_data_len_returns_none() {
        let mut buf = vec![0u8; 18];
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        buf[2] = Command::Data as u8;
        buf[16..18].copy_from_slice(&1000u16.to_be_bytes());
        assert!(read_segment(&buf).is_none());
    }

    #[test]
    fn command_from_u8_exhaustive() {
        assert_eq!(Command::from_u8(0), Some(Command::Ack));
        assert_eq!(Command::from_u8(1), Some(Command::Data));
        assert_eq!(Command::from_u8(2), Some(Command::Terminate));
        assert_eq!(Command::from_u8(3), Some(Command::Ping));
        assert_eq!(Command::from_u8(4), None);
        assert_eq!(Command::from_u8(255), None);
    }

    #[test]
    fn multiple_segments_in_one_packet() {
        let mut seg1 = DataSegment::new();
        seg1.conv = 1;
        seg1.number = 10;
        seg1.data().write_from(b"hello");

        let mut seg2 = CmdOnlySegment::new();
        seg2.conv = 1;
        seg2.cmd = Command::Ping;

        let mut packet = Vec::new();
        packet.resize(seg1.byte_size(), 0);
        seg1.serialize(&mut packet[0..seg1.byte_size()]);

        let off = seg1.byte_size();
        packet.resize(off + seg2.byte_size(), 0);
        seg2.serialize(&mut packet[off..off + seg2.byte_size()]);

        let (s1, c1) = read_segment(&packet).expect("first ok");
        assert_eq!(c1, seg1.byte_size());
        assert_eq!(s1.command(), Command::Data);

        let (s2, c2) = read_segment(&packet[c1..]).expect("second ok");
        assert_eq!(c2, seg2.byte_size());
        assert_eq!(s2.command(), Command::Ping);
        assert_eq!(s2.conversation(), 1);
        assert_eq!(s2.conversation(), 1);
    }

    // k3kh 留账：Go parse 阈值 len(buf)<15（含 1B 最小 data）与发送端 0-data DataSegment
    // 语义需一并理清才能改 14→15；当前维持与 Go 对端互通验证过的 14 偏移实现。
    #[test]
    fn k3kh_data_segment_zero_payload_accepted_by_rust_parse() {
        // Rust 14 语义：data_len=0 段（body 14B）合法可解析——记录现状，
        // 若未来对齐 Go 15 阈值，此测试与 flush 链需一起改。
        let mut buf = vec![0u8; 18];
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        buf[2] = Command::Data as u8;
        buf[12..14].copy_from_slice(&0u16.to_be_bytes());
        let (parsed, consumed) = read_segment(&buf).expect("ok");
        assert_eq!(consumed, 18);
        match parsed {
            SegmentKind::Data(s) => {
                assert!(s.payload.as_ref().unwrap().is_empty());
            },
            other => panic!("expected Data, got {other:?}"),
        }
    }
}
