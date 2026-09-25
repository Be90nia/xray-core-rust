//! Trojan 协议帧编解码，对应 Go `proxy/trojan/protocol.go`。
//!
//! # 协议帧格式
//!
//! ## TCP（对应 Go `ConnWriter.writeHeader` / `ConnReader.ParseHeader`）
//!
//! ```text
//! [56 字节 hex(SHA224(password))][CR LF][1 字节 cmd][SOCKS5 addr+port][CR LF][payload...]
//! ```
//! - cmd: `1` = TCP, `3` = UDP（对应 Go `commandTCP` / `commandUDP`）
//!
//! ## UDP（对应 Go `PacketWriter.writePacket` / `PacketReader.ReadMultiBuffer`）
//!
//! 每个包：
//! ```text
//! [SOCKS5 addr+port][2 字节 BE length][CR LF][length 字节 payload]
//! ```
//!
//! # 切片1 范围
//!
//! 提供**字节切片版**的帧编解码（独立可测试，对应 Go `protocol_test.go` 的 roundtrip）。
//! 切片2 待办：包装成 `tokio::io::AsyncRead/AsyncWrite` 的
//! ConnReader/ConnWriter/PacketReader/PacketWriter， 接入 `transport::Link` 与 `internet::Dialer`。
//!
//! # trojan v2 草案（前向兼容接入）
//!
//! **声明**：v1 逐字节对齐 Go `proxy/trojan`（v26.9.9 实码）；v2 **不在任何权威
//! 规范或主流实现中存在**——Go Xray-core v26.9.9 `proxy/trojan` 无 0x02/MD5 逻辑
//! （全仓 grep 零匹配），trojan-gfw 官方协议文档仅 v1。本节格式来自研究草案
//! `docs/research-transport-stack-2026-09-15b.md` §7.1（其引用来源亦不含该格式
//! 定义），按「SOCKS5 风格」语义对齐：
//!
//! ```text
//! [0x02][16 字节 md5(password)][1 字节 ATYP][DST.ADDR][2 字节 BE DST.PORT][payload...]
//! ```
//!
//! 与 v1 的差异：无独立 cmd 字节（仅 TCP CONNECT 语义）、无尾部 CRLF、
//! 密码标识为原始 MD5 摘要。识别分叉：v1 首字节恒为小写 hex（`0x30-0x39`/
//! `0x61-0x66`），v2 前缀 `0x02` 与之零冲突；其余首字节拒绝（→ fallback）。
//! 草案未定义 UDP；ATYP 恒 1 字节（草案原文「2-byte ATYP」系笔误，与其自注
//! 「SOCKS5 风格」矛盾）。

use xray_common::net::address::Address;

use crate::{
    config::MemoryAccount,
    error::{Result, TrojanError},
};

// ============================================================================
// 常量
// ============================================================================

/// TCP 命令字节，对应 Go `commandTCP byte = 1`。
pub const COMMAND_TCP: u8 = 1;
/// UDP 命令字节，对应 Go `commandUDP byte = 3`。
pub const COMMAND_UDP: u8 = 3;
/// UDP 单包 payload 上限，对应 Go `maxLength = 8192`。
pub const MAX_LENGTH: usize = 8192;
/// CRLF（`\r\n`），对应 Go `crlf = []byte{'\r', '\n'}`。
pub const CRLF: [u8; 2] = [b'\r', b'\n'];

/// trojan v2 草案版本前缀字节（TLS 握手后首字节）。
pub const V2_VERSION: u8 = 0x02;
/// trojan v2 草案密码摘要长度（`md5(password)` 原始 16 字节）。
pub const MD5_KEY_LEN: usize = 16;

/// 网络类型，对应 Go `net.Network_TCP` / `net.Network_UDP`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    /// 转为 Trojan 命令字节。
    pub fn to_command(self) -> u8 {
        match self {
            Network::Tcp => COMMAND_TCP,
            Network::Udp => COMMAND_UDP,
        }
    }

    /// 从 Trojan 命令字节构造（未知值视为 TCP，与 Go 行为一致）。
    pub fn from_command(cmd: u8) -> Self {
        if cmd == COMMAND_UDP { Network::Udp } else { Network::Tcp }
    }
}

// ============================================================================
// SOCKS5 地址编解码（0x01=IPv4 / 0x03=Domain / 0x04=IPv6）
// ============================================================================

/// SOCKS5 地址类型字节（Trojan 与 SS 一致，与 V2Ray 通用 1/2/3 不同）。
pub mod addr_type {
    /// IPv4 = 4 字节地址。
    pub const IPV4: u8 = 0x01;
    /// Domain = 1 字节长度 + N 字节域名。
    pub const DOMAIN: u8 = 0x03;
    /// IPv6 = 16 字节地址。
    pub const IPV6: u8 = 0x04;
}

/// 把 `addr + port`（SOCKS5 格式）追加到 `out`，对应 Go `addrParser.WriteAddressPort`。
///
/// # Errors
/// 域名超过 255 字节 → [`TrojanError::WriteAddress`]（对齐 Go
/// `writeAddress` 的 `isDomainTooLong → "Super long domain is not supported"`
/// 硬错；Rust 旧版截断前 255 字节会发出自洽但不可解析的畸形地址，iq1o⑩）。
pub fn write_address_port(out: &mut Vec<u8>, addr: &Address, port: u16) -> Result<()> {
    match addr {
        Address::IPv4(v4) => {
            out.push(addr_type::IPV4);
            out.extend_from_slice(&v4.octets());
        },
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            let Ok(len) = u8::try_from(bytes.len()) else {
                return Err(TrojanError::WriteAddress(format!(
                    "super long domain is not supported: {len_} bytes",
                    len_ = bytes.len()
                )));
            };
            out.push(addr_type::DOMAIN);
            out.push(len);
            out.extend_from_slice(bytes);
        },
        Address::IPv6(v6) => {
            out.push(addr_type::IPV6);
            out.extend_from_slice(&v6.octets());
        },
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// 从 `buf` 起始位置读 `addr + port`，返回 `(addr, port, consumed)`。
///
/// # Errors
/// - [`TrojanError::InsufficientData`]：数据不足。
/// - [`TrojanError::InvalidRemoteAddress`]：未知地址类型或域名 UTF-8 无效。
pub fn read_address_port(buf: &[u8]) -> Result<(Address, u16, usize)> {
    if buf.is_empty() {
        return Err(TrojanError::InsufficientData(1, 0));
    }
    let addr_type = buf[0];
    let mut pos = 1;
    let (addr, consumed) = match addr_type {
        addr_type::IPV4 => {
            if buf.len() < pos + 4 {
                return Err(TrojanError::InsufficientData(pos + 4, buf.len()));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[pos..pos + 4]);
            (Address::IPv4(std::net::Ipv4Addr::from(ip)), 4)
        },
        addr_type::DOMAIN => {
            if buf.len() < pos + 1 {
                return Err(TrojanError::InsufficientData(pos + 1, buf.len()));
            }
            let len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + len {
                return Err(TrojanError::InsufficientData(pos + len, buf.len()));
            }
            let domain = String::from_utf8(buf[pos..pos + len].to_vec())
                .map_err(|_| TrojanError::InvalidRemoteAddress)?;
            (Address::Domain(domain), len)
        },
        addr_type::IPV6 => {
            if buf.len() < pos + 16 {
                return Err(TrojanError::InsufficientData(pos + 16, buf.len()));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[pos..pos + 16]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), 16)
        },
        _ => return Err(TrojanError::InvalidRemoteAddress),
    };
    pos += consumed;
    if buf.len() < pos + 2 {
        return Err(TrojanError::InsufficientData(pos + 2, buf.len()));
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Ok((addr, port, pos + 2))
}

// ============================================================================
// TCP 帧编解码
// ============================================================================

/// 写入 TCP/UDP 请求头：`[56 字节 key][CRLF][cmd][addr+port][CRLF]`。
///
/// 对应 Go `ConnWriter.writeHeader`。`payload` 由调用方在调用此函数后另行写入。
///
/// # Errors
/// 地址编码失败（域名超 255 字节）→ [`TrojanError::WriteAddress`]。
pub fn write_request_header(
    out: &mut Vec<u8>,
    account: &MemoryAccount,
    network: Network,
    addr: &Address,
    port: u16,
) -> Result<()> {
    out.extend_from_slice(&account.key);
    out.extend_from_slice(&CRLF);
    out.push(network.to_command());
    write_address_port(out, addr, port)?;
    out.extend_from_slice(&CRLF);
    Ok(())
}

// ============================================================================
// trojan v2 草案帧编解码
// ============================================================================

/// 判断首字节是否可能是 v1 的 hex(SHA224) key 起始（小写 hex 字符）。
///
/// v1 key 恒为 56 字节小写 hex，首字节 ∈ `0x30-0x39` / `0x61-0x66`；
/// v2 前缀 `0x02` 与之零冲突——inbound 据此做 v1/v2 识别分叉。
#[must_use]
pub const fn is_v1_hex_prefix(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// 写入 trojan v2 草案请求头：
/// `[0x02][16 字节 md5(password)][SOCKS5 addr+port]`，payload 紧随其后。
///
/// 草案无独立 cmd 字节（仅 TCP CONNECT 语义）且无尾部 CRLF——与 v1 不同，
/// 见模块文档「trojan v2 草案」节。
///
/// # Errors
/// 地址编码失败（域名超 255 字节）→ [`TrojanError::WriteAddress`]。
pub fn write_request_header_v2(
    out: &mut Vec<u8>,
    key: &[u8; MD5_KEY_LEN],
    addr: &Address,
    port: u16,
) -> Result<()> {
    out.push(V2_VERSION);
    out.extend_from_slice(key);
    write_address_port(out, addr, port)
}

/// 解析 trojan v2 草案请求头：返回 `(addr, port, consumed)`，网络恒为 TCP。
///
/// `consumed` 指向 header 末尾，payload 从此处开始。
///
/// # Errors
/// - [`TrojanError::InvalidVersionPrefix`]：首字节非 `0x02`。
/// - [`TrojanError::InsufficientData`]：数据不足。
/// - [`TrojanError::InvalidRemoteAddress`]：未知地址类型或域名 UTF-8 无效。
pub fn parse_request_header_v2(buf: &[u8]) -> Result<(Address, u16, usize)> {
    if buf.is_empty() {
        return Err(TrojanError::InsufficientData(1, 0));
    }
    if buf[0] != V2_VERSION {
        return Err(TrojanError::InvalidVersionPrefix(buf[0]));
    }
    let head = 1 + MD5_KEY_LEN;
    if buf.len() < head {
        return Err(TrojanError::InsufficientData(head, buf.len()));
    }
    let (addr, port, addr_consumed) = read_address_port(&buf[head..])?;
    Ok((addr, port, head + addr_consumed))
}

/// 解析 TCP/UDP 请求头：返回 `(network, addr, port, consumed)`。
///
/// 对应 Go `ConnReader.ParseHeader`。`consumed` 指向 header 末尾，payload 从此处开始。
pub fn parse_request_header(buf: &[u8]) -> Result<(Network, Address, u16, usize)> {
    // 1. 读 56 字节 hex key
    let key_need = crate::config::HEX_KEY_LEN;
    if buf.len() < key_need {
        return Err(TrojanError::ReadUserHash(format!(
            "need {key_need} bytes, have {}",
            buf.len()
        )));
    }
    let mut pos = key_need;

    // 2. 读 CRLF
    if buf.len() < pos + 2 {
        return Err(TrojanError::ReadCrlf(format!("need 2 bytes at {pos}, have {}", buf.len())));
    }
    pos += 2;

    // 3. 读 1 字节 command
    if buf.len() < pos + 1 {
        return Err(TrojanError::ReadCommand(format!("need 1 byte at {pos}, have {}", buf.len())));
    }
    let network = Network::from_command(buf[pos]);
    pos += 1;

    // 4. 读 addr+port
    let (addr, port, addr_consumed) =
        read_address_port(&buf[pos..]).map_err(|e| TrojanError::ReadAddressPort(e.to_string()))?;
    pos += addr_consumed;

    // 5. 读结尾 CRLF
    if buf.len() < pos + 2 {
        return Err(TrojanError::ReadCrlf(format!(
            "need 2 bytes (tail) at {pos}, have {}",
            buf.len()
        )));
    }
    pos += 2;

    Ok((network, addr, port, pos))
}

// ============================================================================
// UDP 包编解码
// ============================================================================

/// 写入 UDP 单包：`[addr+port][2 字节 BE length][CRLF][payload]`。
///
/// 对应 Go `PacketWriter.writePacket`。返回写入的总字节数。
///
/// # Errors
/// 地址编码失败（域名超 255 字节）→ [`TrojanError::WriteAddress`]。
///
/// # 注意
/// 调用方应保证 `payload.len() <= MAX_LENGTH`（与 Go 端一致，不在此强制）。
pub fn write_udp_packet(
    out: &mut Vec<u8>,
    addr: &Address,
    port: u16,
    payload: &[u8],
) -> Result<usize> {
    let start = out.len();
    write_address_port(out, addr, port)?;
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&CRLF);
    out.extend_from_slice(payload);
    Ok(out.len() - start)
}

/// 解析 UDP 单包：返回 `(addr, port, payload_slice, consumed)`。
///
/// 对应 Go `PacketReader.ReadMultiBuffer`。`payload_slice` 借用自 `buf`（零拷贝）。
///
/// # Errors
/// - [`TrojanError::OversizePayload`]：payload 长度声明超过 `MAX_LENGTH`。
/// - [`TrojanError::InsufficientData`]：数据不足。
pub fn parse_udp_packet(buf: &[u8]) -> Result<(Address, u16, &[u8], usize)> {
    // 1. 读 addr+port
    let (addr, port, addr_consumed) =
        read_address_port(buf).map_err(|e| TrojanError::ReadAddressPort(e.to_string()))?;
    let mut pos = addr_consumed;

    // 2. 读 2 字节 length（BE）
    if buf.len() < pos + 2 {
        return Err(TrojanError::ReadPayloadLength(format!(
            "need 2 bytes at {pos}, have {}",
            buf.len()
        )));
    }
    let length = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if length > MAX_LENGTH {
        return Err(TrojanError::OversizePayload(length, MAX_LENGTH));
    }

    // 3. 读 CRLF
    if buf.len() < pos + 2 {
        return Err(TrojanError::ReadCrlf(format!("need 2 bytes at {pos}, have {}", buf.len())));
    }
    pos += 2;

    // 4. 读 payload
    if buf.len() < pos + length {
        return Err(TrojanError::ReadPayload(format!(
            "need {length} bytes at {pos}, have {}",
            buf.len()
        )));
    }
    let payload = &buf[pos..pos + length];
    pos += length;

    Ok((addr, port, payload, pos))
}
/// 流式解析 UDP 单包：区分「数据不足」与「致命错误」。
///
/// 与 [`parse_udp_packet`] 的区别：数据不足时返回 `Ok(None)`（调用方应继续读），
/// 而非返回 `TrojanError`。仅在地址类型非法 / payload 超限等致命错误时返回 `Err`。
/// 供 inbound 的 UDP-over-TCP 读取循环使用。
///
/// # Errors
/// - [`TrojanError::InvalidRemoteAddress`]：未知地址类型或域名 UTF-8 无效。
/// - [`TrojanError::OversizePayload`]：payload 长度声明超过 `MAX_LENGTH`。
pub fn parse_udp_packet_stream(buf: &[u8]) -> Result<Option<(Address, u16, &[u8], usize)>> {
    // 1. addr + port（保留 InsufficientData / InvalidRemoteAddress 区分）
    let (addr, port, mut pos) = match read_address_port(buf) {
        Ok(v) => v,
        Err(TrojanError::InsufficientData(_, _)) => return Ok(None),
        Err(e) => return Err(e),
    };
    // 2. length（不足 → None）
    if buf.len() < pos + 2 {
        return Ok(None);
    }
    let length = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if length > MAX_LENGTH {
        return Err(TrojanError::OversizePayload(length, MAX_LENGTH));
    }
    // 3. CRLF（不足 → None）
    if buf.len() < pos + 2 {
        return Ok(None);
    }
    pos += 2;
    // 4. payload（不足 → None）
    if buf.len() < pos + length {
        return Ok(None);
    }
    let payload = &buf[pos..pos + length];
    pos += length;
    Ok(Some((addr, port, payload, pos)))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::config::MemoryAccount;

    fn account() -> MemoryAccount {
        MemoryAccount::new("password")
    }

    // --------------------------------------------------------------------
    // 地址编解码（SOCKS5 0x01/0x03/0x04）
    // --------------------------------------------------------------------

    #[test]
    fn test_write_read_ipv4_port() {
        let mut out = Vec::new();
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        write_address_port(&mut out, &addr, 1234).expect("encode");
        // type(1) + 4 bytes + port(2) = 7
        assert_eq!(out.len(), 7);
        assert_eq!(out[0], addr_type::IPV4);
        let (a, p, c) = read_address_port(&out).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 1234);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_write_read_ipv6_port() {
        let mut out = Vec::new();
        let addr = Address::IPv6(Ipv6Addr::LOCALHOST);
        write_address_port(&mut out, &addr, 443).expect("encode");
        // type(1) + 16 bytes + port(2) = 19
        assert_eq!(out.len(), 19);
        assert_eq!(out[0], addr_type::IPV6);
        let (a, p, c) = read_address_port(&out).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_write_read_domain_port() {
        let mut out = Vec::new();
        let addr = Address::Domain("example.com".into());
        write_address_port(&mut out, &addr, 8080).expect("encode");
        // type(1) + len(1) + 11 bytes + port(2) = 15
        assert_eq!(out.len(), 15);
        assert_eq!(out[0], addr_type::DOMAIN);
        let (a, p, c) = read_address_port(&out).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 8080);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_read_address_unknown_type() {
        assert!(matches!(read_address_port(&[0x99]), Err(TrojanError::InvalidRemoteAddress)));
    }

    /// iq1o⑩ 回归：域名 > 255 字节必须硬错（对齐 Go `writeAddress` 的
    /// isDomainTooLong），不得截断前 255 字节发出畸形地址。
    #[test]
    fn test_write_address_rejects_domain_over_255() {
        let mut out = Vec::new();
        let addr = Address::Domain("d".repeat(256));
        assert!(matches!(
            write_address_port(&mut out, &addr, 443),
            Err(TrojanError::WriteAddress(_))
        ));
        assert!(out.is_empty(), "failed encode must not leave partial bytes");

        // 边界：恰好 255 字节合法
        let mut out = Vec::new();
        let addr = Address::Domain("d".repeat(255));
        write_address_port(&mut out, &addr, 443).expect("255-byte domain is legal");
        assert_eq!(out[0], addr_type::DOMAIN);
        assert_eq!(out[1] as usize, 255);
        let (a, _, _) = read_address_port(&out).expect("parse");
        assert_eq!(a, addr);
    }

    #[test]
    fn test_read_address_insufficient_ipv4() {
        assert!(matches!(
            read_address_port(&[addr_type::IPV4, 1, 2]),
            Err(TrojanError::InsufficientData(_, _))
        ));
    }

    // --------------------------------------------------------------------
    // 网络类型
    // --------------------------------------------------------------------

    #[test]
    fn test_network_roundtrip() {
        for n in [Network::Tcp, Network::Udp] {
            assert_eq!(Network::from_command(n.to_command()), n);
        }
        // 未知 command 视为 TCP（与 Go 行为一致）
        assert_eq!(Network::from_command(0x99), Network::Tcp);
    }

    // --------------------------------------------------------------------
    // TCP 帧 roundtrip（对齐 Go protocol_test.go::TestTCPRequest）
    // --------------------------------------------------------------------

    #[test]
    fn test_tcp_request_roundtrip() {
        let payload = b"test string";
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        let port = 1234;

        // 写：header + payload
        let mut buf = Vec::new();
        write_request_header(&mut buf, &account(), Network::Tcp, &addr, port).expect("encode");
        buf.extend_from_slice(payload);

        // 读：header
        let (net, parsed_addr, parsed_port, consumed) =
            parse_request_header(&buf).expect("parse header");
        assert_eq!(net, Network::Tcp);
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);

        // payload 从 consumed 开始
        let decoded = &buf[consumed..];
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_tcp_request_udp_command() {
        // 即便走 TCP 帧格式，command=UDP 时 network=Udp（对应 Go: cmd 字段决定）
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        let mut buf = Vec::new();
        write_request_header(&mut buf, &account(), Network::Udp, &addr, 53).expect("encode");
        let (net, _, _, _) = parse_request_header(&buf).expect("parse");
        assert_eq!(net, Network::Udp);
    }

    #[test]
    fn test_tcp_request_truncated_key() {
        // 少 1 字节 key 应失败
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        let mut buf = Vec::new();
        write_request_header(&mut buf, &account(), Network::Tcp, &addr, 80).expect("encode");
        buf.truncate(crate::config::HEX_KEY_LEN - 1);
        assert!(parse_request_header(&buf).is_err());
    }

    // --------------------------------------------------------------------
    // UDP 包 roundtrip（对齐 Go protocol_test.go::TestUDPRequest）
    // --------------------------------------------------------------------

    #[test]
    fn test_udp_packet_roundtrip() {
        let payload = b"test string";
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        let port = 1234;

        let mut buf = Vec::new();
        let n = write_udp_packet(&mut buf, &addr, port, payload).expect("encode");
        assert!(n > 0);

        let (parsed_addr, parsed_port, parsed_payload, consumed) =
            parse_udp_packet(&buf).expect("parse udp");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);
        assert_eq!(parsed_payload, payload);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_udp_packet_oversize() {
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        // 构造一个 length 字段 = MAX_LENGTH + 1 的恶意包
        let mut buf = Vec::new();
        write_address_port(&mut buf, &addr, 1234).expect("encode");
        let oversize = (MAX_LENGTH + 1) as u16;
        buf.extend_from_slice(&oversize.to_be_bytes());
        buf.extend_from_slice(&CRLF);
        buf.extend_from_slice(&[0u8; MAX_LENGTH + 1]);
        assert!(matches!(parse_udp_packet(&buf), Err(TrojanError::OversizePayload(_, _))));
    }

    #[test]
    fn test_udp_packet_truncated_payload() {
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        // 写完整包，然后截断 payload
        let mut buf = Vec::new();
        write_udp_packet(&mut buf, &addr, 1234, b"hello world").expect("encode");
        buf.truncate(buf.len() - 3); // 截掉最后 3 字节 payload
        assert!(matches!(parse_udp_packet(&buf), Err(TrojanError::ReadPayload(_))));
    }

    #[test]
    fn test_udp_packet_domain() {
        let payload = b"udp over domain";
        let addr = Address::Domain("trojan.example.com".into());
        let mut buf = Vec::new();
        write_udp_packet(&mut buf, &addr, 443, payload).expect("encode");
        let (a, p, pp, _) = parse_udp_packet(&buf).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
        assert_eq!(pp, payload);
    }

    // --------------------------------------------------------------------
    // trojan v2 草案帧编解码
    // --------------------------------------------------------------------

    #[test]
    fn test_v2_header_ipv4_wire_format() {
        let mut out = Vec::new();
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        write_request_header_v2(&mut out, &[0xAA; MD5_KEY_LEN], &addr, 8080).expect("encode");
        // 逐字节：0x02 + 16B md5 + ATYP(0x01) + 4B IP + 2B BE port，无 CRLF
        assert_eq!(out.len(), 1 + 16 + 1 + 4 + 2);
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[1..17], &[0xAA; 16]);
        assert_eq!(out[17], addr_type::IPV4);
        assert_eq!(&out[18..22], &[127, 0, 0, 1]);
        assert_eq!(&out[22..24], &8080u16.to_be_bytes());

        let (a, p, c) = parse_request_header_v2(&out).expect("parse v2");
        assert_eq!(a, addr);
        assert_eq!(p, 8080);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_v2_header_domain_wire_format() {
        let mut out = Vec::new();
        let addr = Address::Domain("example.com".into());
        write_request_header_v2(&mut out, &[0x11; MD5_KEY_LEN], &addr, 443).expect("encode");
        // 0x02 + 16B md5 + ATYP(0x03) + len(11) + domain + 2B BE port
        assert_eq!(out.len(), 1 + 16 + 1 + 1 + 11 + 2);
        assert_eq!(out[17], addr_type::DOMAIN);
        assert_eq!(out[18], 11);
        assert_eq!(&out[19..30], b"example.com");
        assert_eq!(&out[30..32], &443u16.to_be_bytes());

        let (a, p, c) = parse_request_header_v2(&out).expect("parse v2");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_v2_header_ipv6_wire_format() {
        let mut out = Vec::new();
        let addr = Address::IPv6(Ipv6Addr::LOCALHOST);
        write_request_header_v2(&mut out, &[0x22; MD5_KEY_LEN], &addr, 9).expect("encode");
        assert_eq!(out.len(), 1 + 16 + 1 + 16 + 2);
        assert_eq!(out[17], addr_type::IPV6);

        let (a, p, c) = parse_request_header_v2(&out).expect("parse v2");
        assert_eq!(a, addr);
        assert_eq!(p, 9);
        assert_eq!(c, out.len());
    }

    #[test]
    fn test_v2_parse_rejects_invalid_version_prefix() {
        // 非法前缀（非 0x02）：0x00 / 0xFF / v1 hex 首字符 '3'
        for first in [0x00u8, 0xFF, b'3', b'a'] {
            let buf = [first, 0u8, 1, 127, 0, 0, 1, 0, 80];
            assert!(
                matches!(parse_request_header_v2(&buf), Err(TrojanError::InvalidVersionPrefix(_))),
                "prefix {first:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn test_v2_parse_insufficient_data() {
        assert!(matches!(parse_request_header_v2(&[]), Err(TrojanError::InsufficientData(1, 0))));
        // 版本字节在但 16B md5 不足
        let buf = [0x02u8, 0xAA, 0xBB];
        assert!(matches!(parse_request_header_v2(&buf), Err(TrojanError::InsufficientData(17, 3))));
    }

    #[test]
    fn test_v1_v2_prefix_disjoint() {
        // v1 首字节恒为小写 hex；v2 前缀 0x02 与之零冲突
        assert!(!is_v1_hex_prefix(V2_VERSION));
        assert!(is_v1_hex_prefix(b'0'));
        assert!(is_v1_hex_prefix(b'9'));
        assert!(is_v1_hex_prefix(b'a'));
        assert!(is_v1_hex_prefix(b'f'));
        assert!(!is_v1_hex_prefix(b'g'));
        assert!(!is_v1_hex_prefix(b'F')); // hex_string 输出小写
        assert!(!is_v1_hex_prefix(0x00));
    }

    #[test]
    fn test_md5_key_length_and_determinism() {
        let k1 = crate::config::md5_key("password");
        let k2 = crate::config::md5_key("password");
        assert_eq!(k1.len(), MD5_KEY_LEN);
        assert_eq!(k1, k2);
        assert_ne!(k1, crate::config::md5_key("other"));
    }
}
