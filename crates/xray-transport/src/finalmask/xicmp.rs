//! # xICMP 伪装（对应 Go `transport/internet/finalmask/xicmp/`）
//!
//! 把代理流量伪装成 ICMP echo（ping）——payload 编码在 ICMP 包的 data 字段。
//!
//! ## 协议
//!
//! - client：在 ICMP echo request 的 data 前缀 8 字节 clientID（随机），
//!   后接 payload。server 用 clientID 构造虚拟 IPv6 地址作为 PacketConn addr。
//! - server：收到 echo request 后记录 (clientID → src addr/id/seq)，
//!   回复时用记录的 id/seq 构造 echo reply。
//!
//! ## 范围
//!
//! 本模块实现可测试的纯函数部分：
//! - ICMP echo 包的 marshal/parse + RFC 1071 checksum
//! - clientID ↔ IPv6 地址映射
//! - ring seq 比较
//!
//! raw socket 收发（需 CAP_NET_RAW / root）留给集成层，本模块不依赖平台特权。

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use async_trait::async_trait;

use super::{UdpIo, Udpmask, UDP_SIZE};

/// ICMP Echo Request type（IPv4）。
const ICMP_ECHO_V4: u8 = 8;
/// ICMP Echo Reply type（IPv4）。
const ICMP_ECHO_REPLY_V4: u8 = 0;
/// ICMPv6 Echo Request type。
const ICMP_ECHO_V6: u8 = 128;
/// ICMPv6 Echo Reply type。
const ICMP_ECHO_REPLY_V6: u8 = 129;

/// xICMP 配置（对应 Go `xicmp.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct XicmpConfig {
    /// 目标 IP 列表（client 用于轮换伪装源 IP）。
    pub ips: Vec<String>,
    /// 是否用 ICMP-over-UDP（DGRAM mode，对应 Go `c.DGRAM`）。
    pub dgram: bool,
}

/// ICMP echo 头部（8 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEcho {
    /// ICMP type（8=Echo Request v4, 0=Reply v4, 128=Request v6, 129=Reply v6）。
    pub icmp_type: u8,
    /// ICMP code（echo 通常为 0）。
    pub code: u8,
    /// 校验和（IPv4 必填，IPv6 由下层处理）。
    pub checksum: u16,
    /// Identifier。
    pub id: u16,
    /// Sequence number。
    pub seq: u16,
}

impl IcmpEcho {
    /// 构造 echo request/reply（checksum=0，待 fill_checksum）。
    pub fn new(icmp_type: u8, id: u16, seq: u16) -> Self {
        Self {
            icmp_type,
            code: 0,
            checksum: 0,
            id,
            seq,
        }
    }

    /// 是否为 IPv4 echo（request 或 reply）。
    pub fn is_v4(&self) -> bool {
        self.icmp_type == ICMP_ECHO_V4 || self.icmp_type == ICMP_ECHO_REPLY_V4
    }

    /// 序列化为 8 字节头部（大端）。
    pub fn marshal_header(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        buf[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf
    }

    /// 从 8 字节头部解析。
    pub fn parse_header(buf: &[u8; 8]) -> Self {
        Self {
            icmp_type: buf[0],
            code: buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            id: u16::from_be_bytes([buf[4], buf[5]]),
            seq: u16::from_be_bytes([buf[6], buf[7]]),
        }
    }
}

/// 构造完整 ICMP echo 包（对应 Go `marshal`）。
///
/// 格式：`[type:1][code:1][checksum:2][id:2][seq:2][data:N]`
/// IPv4 会计算并填入 checksum；IPv6 checksum 由下层处理（留 0）。
pub fn marshal_echo(icmp_type: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let echo = IcmpEcho::new(icmp_type, id, seq);
    let header = echo.marshal_header();
    let mut packet = Vec::with_capacity(8 + data.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(data);

    // IPv4 需计算 checksum（覆盖整个包）
    let is_v4 = icmp_type == ICMP_ECHO_V4 || icmp_type == ICMP_ECHO_REPLY_V4;
    if is_v4 {
        let cksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&cksum.to_be_bytes());
    }
    packet
}

/// RFC 1071 Internet checksum（对应 Go `golang.org/x/net/icmp.checksum`）。
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    // 奇数长度尾部字节按高字节处理
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    // 折叠进位
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// clientID → 虚拟 IPv6 地址（对应 Go `clientIDToAddr`）。
///
/// 映射规则：`fd00::clientID`（8 字节 clientID 填入 IPv6 后 8 字节）。
pub fn client_id_to_addr(client_id: [u8; 8]) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[8..16].copy_from_slice(&client_id);
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), 0, 0, 0))
}

/// 虚拟 IPv6 地址 → clientID（`client_id_to_addr` 的逆运算）。
pub fn addr_to_client_id(addr: &SocketAddr) -> Option<[u8; 8]> {
    match addr {
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            if octets[0] != 0xfd || octets[1] != 0x00 {
                return None;
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(&octets[8..16]);
            Some(id)
        }
        SocketAddr::V4(_) => None,
    }
}

/// ring 序列号比较（对应 Go `ring`）。
///
/// 返回 `min(|a-b|, |b-a|)`（wrapping），用于检测近期 vs 过期的 seq。
pub fn ring_diff(a: u16, b: u16) -> u16 {
    a.wrapping_sub(b).min(b.wrapping_sub(a))
}

// ===== Udpmask impl =====

impl Udpmask for XicmpConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        if level != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xicmp requires being at the outermost level",
            ));
        }
        // TODO rpn-future: raw ICMP socket 收发需要 CAP_NET_RAW，
        // 当前透传 raw（仅 marshal/parse 可独立测试）。
        Ok(raw)
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        if level != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xicmp requires being at the outermost level",
            ));
        }
        Ok(raw)
    }
}

// ===== 内部 client/server 包构造（供集成层调用）=====

/// xICMP 客户端发送构造（对应 Go `xicmpConnClient.WriteTo` 的包构造部分）。
///
/// 在 clientID（8B）和 payload 前缀之上构造 ICMP echo request。
/// 实际发送需要 raw socket（集成层负责）。
pub fn build_client_packet(
    client_id: [u8; 8],
    seq: u16,
    id: u16,
    payload: &[u8],
    is_v4: bool,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(&client_id);
    data.extend_from_slice(payload);
    let icmp_type = if is_v4 { ICMP_ECHO_V4 } else { ICMP_ECHO_V6 };
    marshal_echo(icmp_type, id, seq, &data)
}

/// xICMP 服务端回复构造（对应 Go `xicmpConnServer.WriteTo`）。
///
/// 用记录的 client id/seq 构造 echo reply。
pub fn build_server_reply(id: u16, seq: u16, payload: &[u8], is_v4: bool) -> Vec<u8> {
    let icmp_type = if is_v4 {
        ICMP_ECHO_REPLY_V4
    } else {
        ICMP_ECHO_REPLY_V6
    };
    marshal_echo(icmp_type, id, seq, payload)
}

/// 解析收到的 ICMP echo 包，提取 data 部分（对应 Go recv4/recv6 的 echo.Body.Memory 解析）。
///
/// 返回 `(id, seq, data)` 或 `None`（包过短）。
pub fn parse_echo_packet(packet: &[u8]) -> Option<(u16, u16, &[u8])> {
    if packet.len() < 8 {
        return None;
    }
    let mut header = [0u8; 8];
    header.copy_from_slice(&packet[..8]);
    let echo = IcmpEcho::parse_header(&header);
    Some((echo.id, echo.seq, &packet[8..]))
}

/// 最大 payload 大小限制（对应 Go `len(p)+16 > finalmask.UDPSize`）。
pub const MAX_PAYLOAD: usize = UDP_SIZE.saturating_sub(16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_checksum_zero_data() {
        // 空数据 checksum = ~0 = 0xffff
        assert_eq!(icmp_checksum(&[]), 0xffff);
        assert_eq!(icmp_checksum(&[0, 0, 0, 0]), 0xffff);
    }

    #[test]
    fn icmp_checksum_odd_length() {
        // 奇数长度：尾部字节按高字节
        let odd = [0x12u8, 0x34, 0x56];
        let even = [0x12u8, 0x34, 0x56, 0x00];
        assert_eq!(icmp_checksum(&odd), icmp_checksum(&even));
    }

    #[test]
    fn marshal_v4_echo_has_checksum() {
        let pkt = marshal_echo(ICMP_ECHO_V4, 0x1234, 0x5678, b"data");
        assert_eq!(pkt[0], ICMP_ECHO_V4);
        assert_eq!(pkt[1], 0);
        // checksum 非 0（IPv4 必须填）
        let cksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(cksum, 0);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0x5678);
        assert_eq!(&pkt[8..], b"data");
    }

    #[test]
    fn marshal_v6_echo_no_checksum() {
        let pkt = marshal_echo(ICMP_ECHO_V6, 0x1234, 0x5678, b"data");
        let cksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        // IPv6 checksum 留 0（由下层处理）
        assert_eq!(cksum, 0);
    }

    #[test]
    fn marshal_roundtrip_checksum_validates() {
        // 构造 → 用 checksum 验证 → 整体 checksum 应为 0
        let pkt = marshal_echo(ICMP_ECHO_V4, 100, 200, b"hello icmp");
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn client_id_to_addr_roundtrip() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let addr = client_id_to_addr(id);
        let recovered = addr_to_client_id(&addr).unwrap();
        assert_eq!(recovered, id);
    }

    #[test]
    fn client_id_addr_is_fd00_prefix() {
        let addr = client_id_to_addr([0xff; 8]);
        match addr {
            SocketAddr::V6(v6) => {
                let octets = v6.ip().octets();
                assert_eq!(octets[0], 0xfd);
                assert_eq!(octets[1], 0x00);
                assert_eq!(&octets[8..16], &[0xff; 8]);
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn addr_to_client_id_rejects_v4() {
        let v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(addr_to_client_id(&v4).is_none());
    }

    #[test]
    fn addr_to_client_id_rejects_non_fd00() {
        let v6: SocketAddr = "[2001:db8::1]:0".parse().unwrap();
        assert!(addr_to_client_id(&v6).is_none());
    }

    #[test]
    fn ring_diff_wraps() {
        assert_eq!(ring_diff(10, 5), 5);
        assert_eq!(ring_diff(5, 10), 5);
        assert_eq!(ring_diff(u16::MAX, 0), 1);
        assert_eq!(ring_diff(0, u16::MAX), 1);
    }

    #[test]
    fn parse_echo_packet_extracts_fields() {
        let pkt = marshal_echo(ICMP_ECHO_V4, 0xabcd, 0x1234, b"payload here");
        let (id, seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(id, 0xabcd);
        assert_eq!(seq, 0x1234);
        assert_eq!(data, b"payload here");
    }

    #[test]
    fn parse_echo_packet_rejects_short() {
        assert!(parse_echo_packet(&[1, 2, 3]).is_none());
    }

    #[test]
    fn build_client_packet_layout() {
        let client_id = [0xaa; 8];
        let pkt = build_client_packet(client_id, 1, 2, b"hi", true);
        let (_id, _seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(&data[..8], &client_id);
        assert_eq!(&data[8..], b"hi");
    }

    #[test]
    fn build_server_reply_layout() {
        let pkt = build_server_reply(0x1111, 0x2222, b"reply", true);
        assert_eq!(pkt[0], ICMP_ECHO_REPLY_V4);
        let (id, seq, data) = parse_echo_packet(&pkt).unwrap();
        assert_eq!(id, 0x1111);
        assert_eq!(seq, 0x2222);
        assert_eq!(data, b"reply");
    }

    #[tokio::test]
    async fn udpmask_rejects_non_outermost() {
        let config = XicmpConfig::default();

        struct Stub;
        #[async_trait]
        impl UdpIo for Stub {
            async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                Ok(0)
            }
            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }
        let raw: Box<dyn UdpIo> = Box::new(Stub);
        let result = config.wrap_packet_conn_client(raw, 1, 2);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udpmask_outermost_passthrough() {
        let config = XicmpConfig::default();

        struct Stub;
        #[async_trait]
        impl UdpIo for Stub {
            async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                Ok(0)
            }
            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }
        let raw: Box<dyn UdpIo> = Box::new(Stub);
        // level=0（最外层）应透传成功
        let result = config.wrap_packet_conn_client(raw, 0, 2);
        assert!(result.is_ok());
    }
}
