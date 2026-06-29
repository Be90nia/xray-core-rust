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
//! - length 上限 `MAX_LENGTH = 8192`，对应 Go `maxLength`
//!
//! # 地址格式（SOCKS5 兼容）
//!
//! 与 SS 完全一致（与 V2Ray 通用格式的 `1/2/3` 不同）：
//! - `0x01` = IPv4 (4 字节)
//! - `0x03` = Domain (1 字节长度 + N 字节)
//! - `0x04` = IPv6 (16 字节)
//!
//! # 切片1 范围
//!
//! 提供**字节切片版**的帧编解码（独立可测试，对应 Go `protocol_test.go` 的 roundtrip）。
//! 切片2 待办：包装成 `tokio::io::AsyncRead/AsyncWrite` 的 ConnReader/ConnWriter/PacketReader/PacketWriter，
//! 接入 `transport::Link` 与 `internet::Dialer`。

use xray_common::net::address::Address;

use crate::config::MemoryAccount;
use crate::error::{Result, TrojanError};

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
        if cmd == COMMAND_UDP {
            Network::Udp
        } else {
            Network::Tcp
        }
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
pub fn write_address_port(out: &mut Vec<u8>, addr: &Address, port: u16) {
    match addr {
        Address::IPv4(v4) => {
            out.push(addr_type::IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Address::Domain(domain) => {
            out.push(addr_type::DOMAIN);
            let bytes = domain.as_bytes();
            // 与 SS 一致：长度超过 255 截断（域名实际不会超）
            let len = u8::try_from(bytes.len()).unwrap_or(255) as usize;
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
        Address::IPv6(v6) => {
            out.push(addr_type::IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
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
        }
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
        }
        addr_type::IPV6 => {
            if buf.len() < pos + 16 {
                return Err(TrojanError::InsufficientData(pos + 16, buf.len()));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[pos..pos + 16]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), 16)
        }
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
/// 仅在 `out.extend_from_slice` 失败时返回 [`TrojanError::WriteHeader`]（实际 Vec 不会失败）。
pub fn write_request_header(
    out: &mut Vec<u8>,
    account: &MemoryAccount,
    network: Network,
    addr: &Address,
    port: u16,
) {
    out.extend_from_slice(&account.key);
    out.extend_from_slice(&CRLF);
    out.push(network.to_command());
    write_address_port(out, addr, port);
    out.extend_from_slice(&CRLF);
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
        return Err(TrojanError::ReadCrlf(format!(
            "need 2 bytes at {pos}, have {}",
            buf.len()
        )));
    }
    pos += 2;

    // 3. 读 1 字节 command
    if buf.len() < pos + 1 {
        return Err(TrojanError::ReadCommand(format!(
            "need 1 byte at {pos}, have {}",
            buf.len()
        )));
    }
    let network = Network::from_command(buf[pos]);
    pos += 1;

    // 4. 读 addr+port
    let (addr, port, addr_consumed) = read_address_port(&buf[pos..])
        .map_err(|e| TrojanError::ReadAddressPort(e.to_string()))?;
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
/// # 注意
/// 调用方应保证 `payload.len() <= MAX_LENGTH`（与 Go 端一致，不在此强制）。
pub fn write_udp_packet(
    out: &mut Vec<u8>,
    addr: &Address,
    port: u16,
    payload: &[u8],
) -> usize {
    let start = out.len();
    write_address_port(out, addr, port);
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&CRLF);
    out.extend_from_slice(payload);
    out.len() - start
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
    let (addr, port, addr_consumed) = read_address_port(buf)
        .map_err(|e| TrojanError::ReadAddressPort(e.to_string()))?;
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
        return Err(TrojanError::ReadCrlf(format!(
            "need 2 bytes at {pos}, have {}",
            buf.len()
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MemoryAccount;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        write_address_port(&mut out, &addr, 1234);
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
        write_address_port(&mut out, &addr, 443);
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
        write_address_port(&mut out, &addr, 8080);
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
        assert!(matches!(
            read_address_port(&[0x99]),
            Err(TrojanError::InvalidRemoteAddress)
        ));
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
        write_request_header(&mut buf, &account(), Network::Tcp, &addr, port);
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
        write_request_header(&mut buf, &account(), Network::Udp, &addr, 53);
        let (net, _, _, _) = parse_request_header(&buf).expect("parse");
        assert_eq!(net, Network::Udp);
    }

    #[test]
    fn test_tcp_request_truncated_key() {
        // 少 1 字节 key 应失败
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        let mut buf = Vec::new();
        write_request_header(&mut buf, &account(), Network::Tcp, &addr, 80);
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
        let n = write_udp_packet(&mut buf, &addr, port, payload);
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
        write_address_port(&mut buf, &addr, 1234);
        let oversize = (MAX_LENGTH + 1) as u16;
        buf.extend_from_slice(&oversize.to_be_bytes());
        buf.extend_from_slice(&CRLF);
        buf.extend_from_slice(&[0u8; MAX_LENGTH + 1]);
        assert!(matches!(
            parse_udp_packet(&buf),
            Err(TrojanError::OversizePayload(_, _))
        ));
    }

    #[test]
    fn test_udp_packet_truncated_payload() {
        let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
        // 写完整包，然后截断 payload
        let mut buf = Vec::new();
        write_udp_packet(&mut buf, &addr, 1234, b"hello world");
        buf.truncate(buf.len() - 3); // 截掉最后 3 字节 payload
        assert!(matches!(
            parse_udp_packet(&buf),
            Err(TrojanError::ReadPayload(_))
        ));
    }

    #[test]
    fn test_udp_packet_domain() {
        let payload = b"udp over domain";
        let addr = Address::Domain("trojan.example.com".into());
        let mut buf = Vec::new();
        write_udp_packet(&mut buf, &addr, 443, payload);
        let (a, p, pp, _) = parse_udp_packet(&buf).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
        assert_eq!(pp, payload);
    }
}
