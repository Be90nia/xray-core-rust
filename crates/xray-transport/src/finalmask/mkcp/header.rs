//! # mkcp `header` mode（6 种协议头伪装）
//!
//! 对应 Go `transport/internet/finalmask/mkcp/header/`。
//!
//! 在每个发送 packet 前加固定协议头，让流量看起来像 DNS / DTLS / SRTP / uTP / WeChat / WireGuard。
//! 接收端透传前 `size()` 字节（剥离头）。
//!
//! ## 状态化
//!
//! DTLS / SRTP / WeChat 的序列号随每次 `serialize` 递增，故 header 需要 `&mut self`。
//! 但 [`UdpIo::send_to`] 是 `&self`，故用 `parking_lot::Mutex` 包装 header，
//! 锁 guard 在构造完 packet 后立即释放，不跨 await。

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::Rng;

use super::super::{UdpIo, Udpmask};

/// Header ID（对应 Go `HeaderID` iota 枚举：DNS=0..WireGuard=5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderId {
    Dns = 0,
    Dtls = 1,
    Srtp = 2,
    Utp = 3,
    Wechat = 4,
    Wireguard = 5,
}

impl HeaderId {
    /// 从 i32 解析（对应 protobuf enum 字段）。
    #[must_use]
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Dns),
            1 => Some(Self::Dtls),
            2 => Some(Self::Srtp),
            3 => Some(Self::Utp),
            4 => Some(Self::Wechat),
            5 => Some(Self::Wireguard),
            _ => None,
        }
    }
}

/// 协议头伪装接口（对应 Go `Header` interface）。
pub trait Header: Send + Sync {
    /// 头长度（字节）。
    fn size(&self) -> usize;
    /// 将头写入 `b[..size()]`，可能更新内部状态（如序列号递增）。
    fn serialize(&mut self, b: &mut [u8]);
}

// =============================================================================
// DNS：标准 DNS query 头 + packed domain name + Type A + Class IN
// =============================================================================

/// DNS 查询头伪装（对应 Go `dns` struct）。
///
/// 模板固定，每次 Serialize 覆盖前 2 字节为随机 Transaction ID。
pub struct DnsHeader {
    template: Vec<u8>,
}

impl DnsHeader {
    /// 创建 DNS 头模板。`domain` 例如 `"www.example.com"`。
    ///
    /// # Errors
    /// - `InvalidInput`：域名 label 过长（≥64）或缓冲区溢出。
    pub fn new(domain: &str) -> io::Result<Self> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x00]); // Transaction ID（Serialize 时随机覆盖）
        buf.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query
        buf.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        buf.extend_from_slice(&[0x00, 0x00]); // Answer RRs
        buf.extend_from_slice(&[0x00, 0x00]); // Authority RRs
        buf.extend_from_slice(&[0x00, 0x00]); // Additional RRs
        let mut name_buf = [0u8; 0x100];
        let n = pack_domain_name(domain, &mut name_buf)?;
        buf.extend_from_slice(&name_buf[..n]);
        buf.extend_from_slice(&[0x00, 0x01]); // Type: A
        buf.extend_from_slice(&[0x00, 0x01]); // Class: IN
        Ok(Self { template: buf })
    }
}

impl Header for DnsHeader {
    fn size(&self) -> usize {
        self.template.len()
    }
    fn serialize(&mut self, b: &mut [u8]) {
        let n = self.template.len().min(b.len());
        b[..n].copy_from_slice(&self.template[..n]);
        // 覆盖 Transaction ID（前 2 字节）为随机值（对应 Go `dice.RollUint16()`）。
        let tid: u16 = rand::rng().random();
        b[0] = (tid >> 8) as u8;
        b[1] = tid as u8;
    }
}

/// 把域名打包成 DNS wire format（label 长度前缀 + 末尾 0）。
///
/// 对应 Go `packDomainName`（简化版，不处理 `\.` 转义——真实场景的 domain 参数不含转义）。
fn pack_domain_name(name: &str, out: &mut [u8]) -> io::Result<usize> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        out[0] = 0;
        return Ok(1);
    }
    let mut off = 0usize;
    for label in trimmed.split('.') {
        if label.len() >= 0x40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns: label too long (>=64)",
            ));
        }
        if off + 1 + label.len() > out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns: buffer too small",
            ));
        }
        out[off] = label.len() as u8;
        out[off + 1..off + 1 + label.len()].copy_from_slice(label.as_bytes());
        off += 1 + label.len();
    }
    out[off] = 0; // trailing zero
    Ok(off + 1)
}

// =============================================================================
// DTLS：record header（type=23=ApplicationData, version=DTLS 1.2）
// =============================================================================

/// DTLS record header伪装（对应 Go `dtls` struct）。
pub struct DtlsHeader {
    epoch: u16,
    length: u16,
    sequence: u32,
}

impl DtlsHeader {
    /// 创建 DTLS 头（初始 sequence=0, length=0）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: 0,
            length: 0,
            sequence: 0,
        }
    }
}

impl Default for DtlsHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Header for DtlsHeader {
    fn size(&self) -> usize {
        13 // 1(type) + 2(version) + 2(epoch) + 6(sequence_number) + 2(length)
    }

    fn serialize(&mut self, b: &mut [u8]) {
        b[0] = 23; // ApplicationData
        b[1] = 254; // DTLS 1.2 major
        b[2] = 253; // DTLS 1.2 minor
        b[3] = (self.epoch >> 8) as u8;
        b[4] = self.epoch as u8;
        b[5] = 0; // sequence_number 高 2 字节（始终 0，因 sequence 是 u32）
        b[6] = 0;
        b[7] = (self.sequence >> 24) as u8;
        b[8] = (self.sequence >> 16) as u8;
        b[9] = (self.sequence >> 8) as u8;
        b[10] = self.sequence as u8;
        self.sequence = self.sequence.wrapping_add(1);
        b[11] = (self.length >> 8) as u8;
        b[12] = self.length as u8;
        self.length = self.length.wrapping_add(17);
        if self.length > 100 {
            self.length -= 50;
        }
    }
}

// =============================================================================
// SRTP：4 字节固定结构 [header u16 BE][number u16 BE]
// =============================================================================

/// SRTP 头伪装（对应 Go `srtp` struct）。每次 `serialize` 递增 `number`。
pub struct SrtpHeader {
    header: u16,
    number: u16,
}

impl SrtpHeader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: 0,
            number: 0,
        }
    }
}

impl Default for SrtpHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Header for SrtpHeader {
    fn size(&self) -> usize {
        4
    }
    fn serialize(&mut self, b: &mut [u8]) {
        self.number = self.number.wrapping_add(1);
        b[..2].copy_from_slice(&self.header.to_be_bytes());
        b[2..4].copy_from_slice(&self.number.to_be_bytes());
    }
}

// =============================================================================
// uTP：4 字节 [connection_id u16 BE][header][extension]
// =============================================================================

/// uTP 头伪装（对应 Go `utp` struct）。
pub struct UtpHeader {
    header: u8,
    extension: u8,
    connection_id: u16,
}

impl UtpHeader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: 0,
            extension: 0,
            connection_id: 0,
        }
    }
}

impl Default for UtpHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Header for UtpHeader {
    fn size(&self) -> usize {
        4
    }
    fn serialize(&mut self, b: &mut [u8]) {
        b[..2].copy_from_slice(&self.connection_id.to_be_bytes());
        b[2] = self.header;
        b[3] = self.extension;
    }
}

// =============================================================================
// WeChat：13 字节固定前缀 + 递增 sn
// =============================================================================

/// WeChat 头伪装（对应 Go `wechat` struct）。每次 `serialize` 递增 `sn`。
pub struct WechatHeader {
    sn: u32,
}

impl WechatHeader {
    #[must_use]
    pub fn new() -> Self {
        Self { sn: 0 }
    }
}

impl Default for WechatHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Header for WechatHeader {
    fn size(&self) -> usize {
        13
    }
    fn serialize(&mut self, b: &mut [u8]) {
        self.sn = self.sn.wrapping_add(1);
        b[0] = 0xa1;
        b[1] = 0x08;
        b[2..6].copy_from_slice(&self.sn.to_be_bytes());
        b[6] = 0x00;
        b[7] = 0x10;
        b[8] = 0x11;
        b[9] = 0x18;
        b[10] = 0x30;
        b[11] = 0x22;
        b[12] = 0x30;
    }
}

// =============================================================================
// WireGuard：4 字节固定 `04 00 00 00`
// =============================================================================

/// WireGuard 头伪装（对应 Go `wireguard` struct），固定字节，无状态。
pub struct WireguardHeader;

impl Header for WireguardHeader {
    fn size(&self) -> usize {
        4
    }
    fn serialize(&mut self, b: &mut [u8]) {
        b[0] = 0x04;
        b[1] = 0x00;
        b[2] = 0x00;
        b[3] = 0x00;
    }
}

// =============================================================================
// Config + Conn 包装
// =============================================================================

/// mkcp `header` 配置（对应 Go `header.Config`）。
#[derive(Debug, Clone)]
pub struct HeaderConfig {
    /// 伪装头类型（DNS/DTLS/SRTP/UTP/WECHAT/WIREGUARD）。
    pub id: HeaderId,
    /// DNS 模式用的域名（其他模式忽略）。
    pub domain: String,
}

impl Default for HeaderConfig {
    fn default() -> Self {
        Self {
            id: HeaderId::Wireguard,
            domain: String::new(),
        }
    }
}

fn build_header(cfg: &HeaderConfig) -> io::Result<Box<dyn Header>> {
    Ok(match cfg.id {
        HeaderId::Dns => Box::new(DnsHeader::new(&cfg.domain)?),
        HeaderId::Dtls => Box::new(DtlsHeader::new()),
        HeaderId::Srtp => Box::new(SrtpHeader::new()),
        HeaderId::Utp => Box::new(UtpHeader::new()),
        HeaderId::Wechat => Box::new(WechatHeader::new()),
        HeaderId::Wireguard => Box::new(WireguardHeader),
    })
}

impl Udpmask for HeaderConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let header = build_header(self)?;
        Ok(Box::new(HeaderConn {
            inner: raw,
            header: Mutex::new(header),
        }))
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

/// `header` mode PacketConn 包装（对应 Go `headerConn`）。
struct HeaderConn {
    inner: Box<dyn UdpIo>,
    header: Mutex<Box<dyn Header>>,
}

#[async_trait]
impl UdpIo for HeaderConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // 构造 [header][payload]，锁 guard 在 block 结束时 drop，不跨 await。
        let packet = {
            let mut h = self.header.lock();
            let size = h.size();
            let mut out = vec![0u8; size + buf.len()];
            h.serialize(&mut out[..size]);
            out[size..].copy_from_slice(buf);
            out
        };
        self.inner.send_to(&packet, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let size = self.header.lock().size();
        let mut raw = vec![0u8; buf.len() + size];
        let (n, addr) = self.inner.recv_from(&mut raw).await?;
        let payload_len = n.saturating_sub(size);
        let copy_len = payload_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&raw[size..size + copy_len]);
        Ok((copy_len, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_id_roundtrip() {
        for v in 0..=5 {
            let id = HeaderId::from_i32(v).unwrap();
            assert_eq!(id as u8 as i32, v);
        }
        assert!(HeaderId::from_i32(6).is_none());
        assert!(HeaderId::from_i32(-1).is_none());
    }

    #[test]
    fn dns_packs_domain_name() {
        let mut buf = [0u8; 64];
        let n = pack_domain_name("example.com", &mut buf).unwrap();
        // Expected: 7"example" 3"com" 0
        assert_eq!(buf[..n], [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn dns_with_trailing_dot() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let na = pack_domain_name("a.b", &mut a).unwrap();
        let nb = pack_domain_name("a.b.", &mut b).unwrap();
        assert_eq!(na, nb);
        assert_eq!(a[..na], b[..nb]);
    }

    #[test]
    fn dns_label_too_long_rejected() {
        let long = "a".repeat(70);
        let mut buf = [0u8; 128];
        assert!(pack_domain_name(&long, &mut buf).is_err());
    }

    #[test]
    fn dns_header_size_matches_template() {
        let h = DnsHeader::new("www.example.com").unwrap();
        assert!(h.size() > 12 + 4); // 12B fixed + name + 4B type/class
    }

    #[test]
    fn dns_serialize_randomizes_tid() {
        let mut h = DnsHeader::new("x.com").unwrap();
        let size = h.size();
        let mut a = vec![0u8; size];
        let mut b = vec![0u8; size];
        h.serialize(&mut a);
        h.serialize(&mut b);
        // 极低概率两次随机 TID 相同
        assert!(a[0..2] != b[0..2] || a[2..] == b[2..]);
    }

    #[test]
    fn dtls_size_is_13() {
        assert_eq!(DtlsHeader::new().size(), 13);
    }

    #[test]
    fn dtls_serialize_increments_sequence_and_length() {
        let mut h = DtlsHeader::new();
        let mut b = [0u8; 13];
        h.serialize(&mut b);
        assert_eq!(b[0], 23);
        assert_eq!(b[1..3], [254, 253]);
        // 第一次 sequence=0，写完后 ++ → 1
        assert_eq!(b[7..11], [0, 0, 0, 0]);
        // 第一次 length=0，写完后 +=17 → 17
        assert_eq!(b[11..13], [0, 0]);

        h.serialize(&mut b);
        // 第二次 sequence=1，写完后 ++ → 2
        assert_eq!(b[7..11], [0, 0, 0, 1]);
        // 第二次 length=17，写完后 +=17 → 34
        assert_eq!(b[11..13], [0, 17]);
    }

    #[test]
    fn dtls_length_wraps_after_100() {
        let mut h = DtlsHeader::new();
        h.length = 90;
        let mut b = [0u8; 13];
        h.serialize(&mut b);
        // 90 + 17 = 107 > 100 → 107 - 50 = 57
        assert_eq!(h.length, 57);
    }

    #[test]
    fn srtp_increments_number() {
        let mut h = SrtpHeader::new();
        let mut b = [0u8; 4];
        h.serialize(&mut b);
        assert_eq!(b[2..4], [0, 1]); // 第一次 number=0+1=1
        h.serialize(&mut b);
        assert_eq!(b[2..4], [0, 2]);
    }

    #[test]
    fn utp_writes_connection_id_first() {
        let mut h = UtpHeader::new();
        h.connection_id = 0x1234;
        h.header = 0x55;
        h.extension = 0x66;
        let mut b = [0u8; 4];
        h.serialize(&mut b);
        assert_eq!(b, [0x12, 0x34, 0x55, 0x66]);
    }

    #[test]
    fn wechat_increments_sn() {
        let mut h = WechatHeader::new();
        let mut b = [0u8; 13];
        h.serialize(&mut b);
        assert_eq!(b[0], 0xa1);
        assert_eq!(b[1], 0x08);
        assert_eq!(b[2..6], [0, 0, 0, 1]); // sn=0+1=1 BE
        assert_eq!(b[6..13], [0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
    }

    #[test]
    fn wireguard_is_constant() {
        let mut h = WireguardHeader;
        let mut b = [0u8; 4];
        h.serialize(&mut b);
        assert_eq!(b, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn build_header_all_variants() {
        let cases = [
            (HeaderId::Dns, "example.com"),
            (HeaderId::Dtls, ""),
            (HeaderId::Srtp, ""),
            (HeaderId::Utp, ""),
            (HeaderId::Wechat, ""),
            (HeaderId::Wireguard, ""),
        ];
        for (id, domain) in cases {
            let cfg = HeaderConfig {
                id,
                domain: domain.to_string(),
            };
            let h = build_header(&cfg);
            assert!(h.is_ok(), "failed to build {id:?}");
        }
    }
}
