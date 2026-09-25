//! Hysteria 协议帧解析 / 序列化（对应 Go `proxy/hysteria/protocol.go`）。
//!
//! 包含：
//! - TCP 请求 / 响应帧（varint 地址 + padding）
//! - UDP 消息帧（session id + packet id + fragment + 地址 + 数据）
//! - UDP 消息分片 / 重组（Defragger）

use std::io::{self, Read, Write};

use xray_transport_hysteria::config::{TcpRequestPadding, TcpResponsePadding};

use crate::error::HysteriaProxyError;

// ===== 常量 =====

/// 地址最大长度（防 DoS）。
///
/// 合法地址是 `host:port`：域名 ≤253 + `:` + 端口 ≤5 = ≤259 字节，271 留少量裕量。
/// 比 Go 基准的 2048 更紧——超过该值必为恶意 varint 声明。
pub const MAX_ADDRESS_LENGTH: u64 = 271;

/// 消息最大长度（64 KiB）。
///
/// Go 基准为 2048；放宽到 64 KiB 上限（超限仍拒绝，接受侧不放大分配）。
pub const MAX_MESSAGE_LENGTH: u64 = 64 * 1024;

/// Padding 最大长度（64 KiB）。
///
/// padding 读取后即丢弃（[`discard_exact`] 按块读，不按声明值预分配）。
pub const MAX_PADDING_LENGTH: u64 = 64 * 1024;

// ===== QUIC varint 读写 =====

/// 读取 QUIC varint（对应 Go `quicvarint.Read`）。
///
/// 从 reader 逐字节读取，解析 1/2/4/8 字节 varint。
pub fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let prefix = first[0] >> 6;
    match prefix {
        0 => Ok(u64::from(first[0])),
        _ => {
            let mask: u8 = 0x3F;
            let len = 1usize << prefix;
            let mut buf = vec![0u8; len - 1];
            r.read_exact(&mut buf)?;
            let mut val = u64::from(first[0] & mask);
            for &b in &buf {
                val = (val << 8) | u64::from(b);
            }
            Ok(val)
        },
    }
}

/// 写入 QUIC varint 到 buf（对应 Go `varintPut`）。
///
/// 返回写入字节数。
pub fn write_varint(buf: &mut [u8], v: u64) -> usize {
    if v < (1 << 6) {
        buf[0] = v as u8;
        1
    } else if v < (1 << 14) {
        buf[0] = (v >> 8) as u8 | 0x40;
        buf[1] = v as u8;
        2
    } else if v < (1 << 30) {
        buf[0] = (v >> 24) as u8 | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        buf[0] = (v >> 56) as u8 | 0xC0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

/// 计算 varint 编码后字节数。
#[must_use]
pub fn varint_len(v: u64) -> usize {
    if v < (1 << 6) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

/// 按块读丢弃 `n` 字节（不按 `n` 预分配堆缓冲）。
///
/// padding 声明值上限 64 KiB 且读后即弃，固定 4 KiB 栈缓冲循环消化即可，
/// 避免按恶意声明值做大额堆分配。
fn discard_exact<R: Read>(r: &mut R, mut n: u64) -> io::Result<()> {
    let mut chunk = [0u8; 4096];
    while n > 0 {
        let want = chunk.len().min(n as usize);
        r.read_exact(&mut chunk[..want])?;
        n -= want as u64;
    }
    Ok(())
}
// ===== TCP 请求 / 响应 =====

/// 读取 TCP 请求帧（对应 Go `ReadTCPRequest`）。
///
/// 格式：varint(addr_len) + addr + varint(padding_len) + padding。
/// 返回目标地址字符串（如 `example.com:443`）。
pub fn read_tcp_request<R: Read>(r: &mut R) -> Result<String, HysteriaProxyError> {
    let addr_len = read_varint(r)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp request addr len: {e}")))?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return Err(HysteriaProxyError::ProtocolParse("invalid address length".into()));
    }
    let mut addr_buf = vec![0u8; addr_len as usize];
    r.read_exact(&mut addr_buf)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp request addr: {e}")))?;
    let padding_len = read_varint(r)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp request padding len: {e}")))?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(HysteriaProxyError::ProtocolParse("invalid padding length".into()));
    }
    if padding_len > 0 {
        discard_exact(r, padding_len)
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp request padding: {e}")))?;
    }
    String::from_utf8(addr_buf)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp request addr utf8: {e}")))
}

/// 写入 TCP 请求帧（对应 Go `WriteTCPRequest`）。
pub fn write_tcp_request<W: Write>(w: &mut W, addr: &str) -> io::Result<()> {
    let padding = TcpRequestPadding.get().generate();
    let addr_bytes = addr.as_bytes();
    let addr_len = addr_bytes.len();
    let padding_len = padding.len();
    let sz = varint_len(addr_len as u64) + addr_len + varint_len(padding_len as u64) + padding_len;
    let mut buf = vec![0u8; sz];
    let mut i = write_varint(&mut buf, addr_len as u64);
    buf[i..i + addr_len].copy_from_slice(addr_bytes);
    i += addr_len;
    i += write_varint(&mut buf[i..], padding_len as u64);
    buf[i..i + padding_len].copy_from_slice(padding.as_bytes());
    w.write_all(&buf)
}

/// 读取 TCP 响应帧（对应 Go `ReadTCPResponse`）。
///
/// 格式：status(1B) + varint(msg_len) + msg + varint(padding_len) + padding。
/// 返回 (ok, message)。
pub fn read_tcp_response<R: Read>(r: &mut R) -> Result<(bool, String), HysteriaProxyError> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response status: {e}")))?;
    let msg_len = read_varint(r)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response msg len: {e}")))?;
    if msg_len > MAX_MESSAGE_LENGTH {
        return Err(HysteriaProxyError::ProtocolParse("invalid message length".into()));
    }
    let msg = if msg_len > 0 {
        let mut buf = vec![0u8; msg_len as usize];
        r.read_exact(&mut buf)
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response msg: {e}")))?;
        String::from_utf8(buf)
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response msg utf8: {e}")))?
    } else {
        String::new()
    };
    let padding_len = read_varint(r)
        .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response padding len: {e}")))?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(HysteriaProxyError::ProtocolParse("invalid padding length".into()));
    }
    if padding_len > 0 {
        discard_exact(r, padding_len)
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("tcp response padding: {e}")))?;
    }
    Ok((status[0] == 0, msg))
}

/// 写入 TCP 响应帧（对应 Go `WriteTCPResponse`）。
pub fn write_tcp_response<W: Write>(w: &mut W, ok: bool, msg: &str) -> io::Result<()> {
    let padding = TcpResponsePadding.get().generate();
    let msg_bytes = msg.as_bytes();
    let msg_len = msg_bytes.len();
    let padding_len = padding.len();
    let sz =
        1 + varint_len(msg_len as u64) + msg_len + varint_len(padding_len as u64) + padding_len;
    let mut buf = vec![0u8; sz];
    buf[0] = if ok { 0 } else { 1 };
    let mut i = 1 + write_varint(&mut buf[1..], msg_len as u64);
    buf[i..i + msg_len].copy_from_slice(msg_bytes);
    i += msg_len;
    i += write_varint(&mut buf[i..], padding_len as u64);
    buf[i..i + padding_len].copy_from_slice(padding.as_bytes());
    w.write_all(&buf)
}
// ===== UDP 消息 =====

/// UDP 消息帧（对应 Go `UDPMessage`）。
///
/// 格式：session_id(4B BE) + packet_id(2B BE) + frag_id(1B) + frag_count(1B)
///       + varint(addr_len) + addr + data。
#[derive(Debug, Clone)]
pub struct UdpMessage {
    /// 会话 ID。
    pub session_id: u32,
    /// 包 ID（用于分片重组）。
    pub packet_id: u16,
    /// 分片 ID。
    pub frag_id: u8,
    /// 分片总数。
    pub frag_count: u8,
    /// 目标地址（如 `8.8.8.8:53`）。
    pub addr: String,
    /// 数据负载。
    pub data: Vec<u8>,
}

impl UdpMessage {
    /// 头部字节数（不含 data）。
    #[must_use]
    pub fn header_size(&self) -> usize {
        let addr_len = self.addr.len();
        4 + 2 + 1 + 1 + varint_len(addr_len as u64) + addr_len
    }

    /// 总字节数。
    #[must_use]
    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// 序列化到 buf，返回写入字节数；buf 不够返回 0。
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        if buf.len() < self.size() {
            return 0;
        }
        // session_id: Go 注释掉写入，但保留 4 字节偏移
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.packet_id.to_be_bytes());
        buf[6] = self.frag_id;
        buf[7] = self.frag_count;
        let addr_bytes = self.addr.as_bytes();
        let addr_len = addr_bytes.len();
        let mut i = 8 + write_varint(&mut buf[8..], addr_len as u64);
        buf[i..i + addr_len].copy_from_slice(addr_bytes);
        i += addr_len;
        buf[i..i + self.data.len()].copy_from_slice(&self.data);
        i += self.data.len();
        i
    }

    /// 从字节切片解析 UDP 消息（对应 Go `ParseUDPMessage`）。
    pub fn parse(msg: &[u8]) -> Result<Self, HysteriaProxyError> {
        if msg.len() < 8 {
            return Err(HysteriaProxyError::ProtocolParse("udp message too short".into()));
        }
        let session_id = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let packet_id = u16::from_be_bytes([msg[4], msg[5]]);
        let frag_id = msg[6];
        let frag_count = msg[7];
        // 从偏移 8 开始读 varint addr_len
        let mut cursor = io::Cursor::new(&msg[8..]);
        let addr_len = read_varint(&mut cursor)
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("udp msg addr len: {e}")))?;
        if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
            return Err(HysteriaProxyError::ProtocolParse("invalid address length".into()));
        }
        let consumed = cursor.position() as usize;
        let rest_start = 8 + consumed;
        let rest = &msg[rest_start..];
        if rest.len() <= addr_len as usize {
            // 需要 addr + 至少 1 字节 data
            return Err(HysteriaProxyError::ProtocolParse("invalid message length".into()));
        }
        let addr = String::from_utf8(rest[..addr_len as usize].to_vec())
            .map_err(|e| HysteriaProxyError::ProtocolParse(format!("udp msg addr utf8: {e}")))?;
        let data = rest[addr_len as usize..].to_vec();
        Ok(Self { session_id, packet_id, frag_id, frag_count, addr, data })
    }
}

/// 分片 UDP 消息（对应 Go `FragUDPMessage`）。
///
/// 若消息 <= max_size 直接返回单元素，否则按 max_payload_size 切片。
pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let header_size = m.header_size();
    let max_payload = max_size.saturating_sub(header_size);
    if max_payload == 0 {
        return vec![];
    }
    let full = &m.data;
    let frag_count = ((full.len() + max_payload - 1) / max_payload) as u8;
    let mut frags = Vec::with_capacity(frag_count as usize);
    let mut off = 0;
    let mut frag_id: u8 = 0;
    while off < full.len() {
        let end = (off + max_payload).min(full.len());
        frags.push(UdpMessage {
            session_id: m.session_id,
            packet_id: m.packet_id,
            frag_id,
            frag_count,
            addr: m.addr.clone(),
            data: full[off..end].to_vec(),
        });
        off = end;
        frag_id = frag_id.saturating_add(1);
    }
    frags
}
/// UDP 消息重组器（对应 Go `Defragger`）。
///
/// 当前实现一次只处理一个 packet_id 的分片。
/// 新 packet_id 到达时丢弃之前状态。
pub struct Defragger {
    /// 当前正在重组的 packet_id。
    pkt_id: u16,
    /// 已收到的分片。
    frags: Vec<Option<UdpMessage>>,
    /// 已收到分片数。
    count: u8,
    /// 已收到数据总长。
    data_size: usize,
}

impl Defragger {
    /// 构造空重组器。
    #[must_use]
    pub fn new() -> Self {
        Self { pkt_id: 0, frags: Vec::new(), count: 0, data_size: 0 }
    }

    /// 投入一个分片，若所有分片齐备返回完整消息。
    ///
    /// 对应 Go `Defragger.Feed`。
    pub fn feed(&mut self, m: &UdpMessage) -> Option<UdpMessage> {
        // 无分片或单分片直接返回
        if m.frag_count <= 1 {
            return Some(m.clone());
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        // 新 packet_id 或 frag_count 不匹配 -> 重置
        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            self.pkt_id = m.packet_id;
            self.frags = vec![None; m.frag_count as usize];
            self.count = 0;
            self.data_size = 0;
        }
        if self.frags[m.frag_id as usize].is_none() {
            self.frags[m.frag_id as usize] = Some(m.clone());
            self.count = self.count.saturating_add(1);
            self.data_size += m.data.len();
        }
        // 所有分片齐备
        if self.count == m.frag_count {
            let mut data = Vec::with_capacity(self.data_size);
            let mut addr = String::new();
            for frag in &self.frags {
                if let Some(f) = frag {
                    data.extend_from_slice(&f.data);
                    if addr.is_empty() {
                        addr = f.addr.clone();
                    }
                }
            }
            let result = UdpMessage {
                session_id: m.session_id,
                packet_id: m.packet_id,
                frag_id: 0,
                frag_count: 1,
                addr,
                data,
            };
            // 重置状态
            self.frags.clear();
            self.count = 0;
            self.data_size = 0;
            return Some(result);
        }
        None
    }
}

impl Default for Defragger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let cases = [0u64, 63, 64, 16383, 16384, 1_073_741_823, 0x401];
        for &v in &cases {
            let mut buf = vec![0u8; 8];
            let n = write_varint(&mut buf, v);
            let mut cursor = io::Cursor::new(&buf[..n]);
            let decoded = read_varint(&mut cursor).expect("varint decode should succeed");
            assert_eq!(decoded, v, "varint roundtrip failed for {v}");
        }
    }

    #[test]
    fn tcp_request_roundtrip() {
        let addr = "example.com:443";
        let mut buf = Vec::new();
        write_tcp_request(&mut buf, addr).expect("write should succeed");
        let mut cursor = io::Cursor::new(&buf);
        let decoded = read_tcp_request(&mut cursor).expect("read should succeed");
        assert_eq!(decoded, addr);
    }

    #[test]
    fn tcp_response_roundtrip_ok() {
        let mut buf = Vec::new();
        write_tcp_response(&mut buf, true, "").expect("write should succeed");
        let mut cursor = io::Cursor::new(&buf);
        let (ok, msg) = read_tcp_response(&mut cursor).expect("read should succeed");
        assert!(ok);
        assert!(msg.is_empty());
    }

    #[test]
    fn tcp_response_roundtrip_err() {
        let mut buf = Vec::new();
        write_tcp_response(&mut buf, false, "rejected").expect("write should succeed");
        let mut cursor = io::Cursor::new(&buf);
        let (ok, msg) = read_tcp_response(&mut cursor).expect("read should succeed");
        assert!(!ok);
        assert_eq!(msg, "rejected");
    }

    #[test]
    fn udp_message_parse_roundtrip() {
        let m = UdpMessage {
            session_id: 42,
            packet_id: 7,
            frag_id: 0,
            frag_count: 1,
            addr: "8.8.8.8:53".into(),
            data: vec![1, 2, 3, 4],
        };
        let sz = m.size();
        let mut buf = vec![0u8; sz + 16];
        let n = m.serialize(&mut buf);
        assert_eq!(n, sz);
        let parsed = UdpMessage::parse(&buf[..n]).expect("parse should succeed");
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.packet_id, 7);
        assert_eq!(parsed.addr, "8.8.8.8:53");
        assert_eq!(parsed.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn frag_and_defrag_roundtrip() {
        let m = UdpMessage {
            session_id: 1,
            packet_id: 100,
            frag_id: 0,
            frag_count: 1,
            addr: "1.2.3.4:53".into(),
            data: vec![0xAA; 200],
        };
        // 强制小 max_size 触发分片
        let frags = frag_udp_message(&m, 80);
        assert!(frags.len() > 1, "should fragment");
        let mut defrag = Defragger::new();
        let mut result = None;
        for frag in &frags {
            if let Some(complete) = defrag.feed(frag) {
                result = Some(complete);
            }
        }
        let complete = result.expect("should defrag");
        assert_eq!(complete.data, vec![0xAA; 200]);
        assert_eq!(complete.addr, "1.2.3.4:53");
    }

    #[test]
    fn defragger_single_frag_returns_immediately() {
        let m = UdpMessage {
            session_id: 0,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: "a:1".into(),
            data: vec![1],
        };
        let mut d = Defragger::new();
        let r = d.feed(&m).expect("single frag should return");
        assert_eq!(r.data, vec![1]);
    }

    #[test]
    fn varint_len_matches_write() {
        let cases = [0u64, 63, 64, 16383, 16384];
        for &v in &cases {
            let mut buf = vec![0u8; 8];
            let n = write_varint(&mut buf, v);
            assert_eq!(varint_len(v), n, "varint_len mismatch for {v}");
        }
    }

    // ===== varint 限幅回归（超限帧被拒） =====

    /// varint → bytes（测试辅助；`write_varint` 需要预分配缓冲，不增长 Vec）。
    fn varint_bytes(v: u64) -> Vec<u8> {
        let mut b = [0u8; 8];
        let n = write_varint(&mut b, v);
        b[..n].to_vec()
    }

    #[test]
    fn tcp_request_rejects_oversize_addr_len() {
        let buf = varint_bytes(MAX_ADDRESS_LENGTH + 1);
        let err = read_tcp_request(&mut io::Cursor::new(&buf)).unwrap_err();
        assert!(err.to_string().contains("invalid address length"), "got {err}");
    }

    #[test]
    fn tcp_request_rejects_oversize_padding_len() {
        let addr = b"example.com:443";
        let mut buf = varint_bytes(addr.len() as u64);
        buf.extend_from_slice(addr);
        buf.extend(varint_bytes(MAX_PADDING_LENGTH + 1));
        let err = read_tcp_request(&mut io::Cursor::new(&buf)).unwrap_err();
        assert!(err.to_string().contains("invalid padding length"), "got {err}");
    }

    #[test]
    fn tcp_request_discards_padding_up_to_limit() {
        // 上限值 64 KiB padding 合法，且被块读完整消化（位置=总长证明无残留）
        let addr = b"example.com:443";
        let mut buf = varint_bytes(addr.len() as u64);
        buf.extend_from_slice(addr);
        buf.extend(varint_bytes(MAX_PADDING_LENGTH));
        buf.extend(std::iter::repeat_n(0u8, MAX_PADDING_LENGTH as usize));
        let mut cursor = io::Cursor::new(&buf);
        let decoded = read_tcp_request(&mut cursor).expect("64KiB padding should be accepted");
        assert_eq!(decoded, "example.com:443");
        assert_eq!(cursor.position() as usize, buf.len(), "padding fully consumed");
    }

    #[test]
    fn tcp_response_rejects_oversize_msg_len() {
        let mut buf = vec![0u8]; // status
        buf.extend(varint_bytes(MAX_MESSAGE_LENGTH + 1));
        buf.extend(varint_bytes(0));
        let err = read_tcp_response(&mut io::Cursor::new(&buf)).unwrap_err();
        assert!(err.to_string().contains("invalid message length"), "got {err}");
    }

    #[test]
    fn tcp_response_accepts_msg_over_legacy_2k_limit() {
        // 旧上限 2048、现上限 64 KiB：2049 字节消息应被接受（放宽不收紧消息面）
        let msg = "x".repeat(2049);
        let mut buf = vec![0u8]; // status
        buf.extend(varint_bytes(msg.len() as u64));
        buf.extend_from_slice(msg.as_bytes());
        buf.extend(varint_bytes(0));
        let (ok, decoded) =
            read_tcp_response(&mut io::Cursor::new(&buf)).expect("2049B msg should be accepted");
        assert!(ok);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn udp_message_rejects_oversize_addr_len() {
        let mut m = vec![0u8; 8];
        m.extend(varint_bytes(MAX_ADDRESS_LENGTH + 1));
        let err = UdpMessage::parse(&m).unwrap_err();
        assert!(err.to_string().contains("invalid address length"), "got {err}");
    }
}
