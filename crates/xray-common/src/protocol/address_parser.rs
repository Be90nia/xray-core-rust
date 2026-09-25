//! 协议地址序列化与解析
//!
//! 对应 Go 版本 `common/protocol/address.go`，实现线格式地址的读写。
//!
//! 线格式定义：
//! - IPv4:  type(1) + 4 bytes
//! - Domain: type(2) + len(1 byte) + domain_bytes
//! - IPv6:  type(3) + 16 bytes
//! - Port:  2 bytes big-endian

use xray_buf::buffer::Buffer;

use crate::net::{address::Address, port::Port};

/// 地址类型标识符。
const ADDR_TYPE_IPV4: u8 = 1;
const ADDR_TYPE_DOMAIN: u8 = 2;
const ADDR_TYPE_IPV6: u8 = 3;

/// 地址序列化器：将地址和端口写入缓冲区。
pub struct AddressSerializer;

impl AddressSerializer {
    /// 将端口和地址写入缓冲区（先端口后地址）。
    ///
    /// 格式：port(2 bytes BE) + address(variable)
    pub fn write_port_address(buf: &mut Buffer, port: Port, addr: &Address) {
        let port_bytes = port.value().to_be_bytes();
        buf.write_from(&port_bytes);
        Self::write_address(buf, addr);
    }

    /// 将地址和端口写入缓冲区（先地址后端口）。
    ///
    /// 格式：address(variable) + port(2 bytes BE)
    pub fn write_address_port(buf: &mut Buffer, addr: &Address, port: Port) {
        Self::write_address(buf, addr);
        let port_bytes = port.value().to_be_bytes();
        buf.write_from(&port_bytes);
    }

    /// 将地址写入缓冲区（不含端口）。
    fn write_address(buf: &mut Buffer, addr: &Address) {
        match addr {
            Address::IPv4(v4) => {
                buf.write_byte(ADDR_TYPE_IPV4);
                buf.write_from(&v4.octets());
            },
            Address::Domain(domain) => {
                buf.write_byte(ADDR_TYPE_DOMAIN);
                let domain_bytes = domain.as_bytes();
                let len = domain_bytes.len() as u8;
                buf.write_byte(len);
                buf.write_from(domain_bytes);
            },
            Address::IPv6(v6) => {
                buf.write_byte(ADDR_TYPE_IPV6);
                buf.write_from(&v6.octets());
            },
        }
    }
}

/// 地址解析器：从字节切片读取地址和端口。
pub struct AddressParser;

impl AddressParser {
    /// 从字节数据读取地址，返回地址和消耗的字节数。
    ///
    /// 返回 `None` 如果数据不足或格式无效。
    pub fn read_address(data: &[u8]) -> Option<(Address, usize)> {
        if data.is_empty() {
            return None;
        }

        match data[0] {
            ADDR_TYPE_IPV4 => {
                if data.len() < 1 + 4 {
                    return None;
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&data[1..5]);
                Some((Address::from_ipv4_bytes(octets), 5))
            },
            ADDR_TYPE_DOMAIN => {
                if data.len() < 2 {
                    return None;
                }
                let domain_len = data[1] as usize;
                if data.len() < 2 + domain_len {
                    return None;
                }
                let domain_str = std::str::from_utf8(&data[2..2 + domain_len]).ok()?;
                Some((Address::new_domain(domain_str), 2 + domain_len))
            },
            ADDR_TYPE_IPV6 => {
                if data.len() < 1 + 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                Some((Address::from_ipv6_bytes(octets), 17))
            },
            _ => None,
        }
    }

    /// 从字节数据读取端口（2 字节大端序）。
    ///
    /// 返回 `None` 如果数据不足 2 字节。
    pub fn read_port(data: &[u8]) -> Option<Port> {
        if data.len() < 2 {
            return None;
        }
        let port = u16::from_be_bytes([data[0], data[1]]);
        Some(Port::new(port))
    }

    /// 从字节数据读取端口和地址（先端口后地址）。
    ///
    /// 返回 `(port, address, consumed_bytes)` 或 `None`。
    pub fn parse_port_address(data: &[u8]) -> Option<(Port, Address, usize)> {
        let port = Self::read_port(data)?;
        let (addr, addr_len) = Self::read_address(&data[2..])?;
        Some((port, addr, 2 + addr_len))
    }

    /// 从字节数据读取地址和端口（先地址后端口）。
    ///
    /// 返回 `(address, port, consumed_bytes)` 或 `None`。
    pub fn parse_address_port(data: &[u8]) -> Option<(Address, Port, usize)> {
        let (addr, addr_len) = Self::read_address(data)?;
        let port = Self::read_port(&data[addr_len..])?;
        Some((addr, port, addr_len + 2))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_write_read_ipv4() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv4(Ipv4Addr::new(192, 168, 1, 1));
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(443));

        let data = buf.bytes();
        let (parsed_addr, parsed_port, consumed) =
            AddressParser::parse_address_port(data).expect("parse should succeed");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, Port::new(443));
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_write_read_ipv6() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(8080));

        let data = buf.bytes();
        let (parsed_addr, parsed_port, consumed) =
            AddressParser::parse_address_port(data).expect("parse should succeed");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, Port::new(8080));
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_write_read_domain() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::new_domain("example.com");
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(443));

        let data = buf.bytes();
        let (parsed_addr, parsed_port, consumed) =
            AddressParser::parse_address_port(data).expect("parse should succeed");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, Port::new(443));
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_write_read_port_address_order() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        AddressSerializer::write_port_address(&mut buf, Port::new(80), &addr);

        let data = buf.bytes();
        let (parsed_port, parsed_addr, consumed) =
            AddressParser::parse_port_address(data).expect("parse should succeed");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, Port::new(80));
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_ipv4_wire_format() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv4(Ipv4Addr::new(127, 0, 0, 1));
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(80));

        let data = buf.bytes();
        // type(1) + 4 bytes + port(2) = 7
        assert_eq!(data.len(), 7);
        assert_eq!(data[0], ADDR_TYPE_IPV4);
        assert_eq!(&data[1..5], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([data[5], data[6]]), 80);
    }

    #[test]
    fn test_domain_wire_format() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::new_domain("test.com");
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(443));

        let data = buf.bytes();
        // type(1) + len(1) + 8 bytes + port(2) = 12
        assert_eq!(data.len(), 12);
        assert_eq!(data[0], ADDR_TYPE_DOMAIN);
        assert_eq!(data[1], 8);
        assert_eq!(&data[2..10], b"test.com");
    }

    #[test]
    fn test_ipv6_wire_format() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv6(Ipv6Addr::LOCALHOST);
        AddressSerializer::write_address_port(&mut buf, &addr, Port::new(443));

        let data = buf.bytes();
        // type(1) + 16 bytes + port(2) = 19
        assert_eq!(data.len(), 19);
        assert_eq!(data[0], ADDR_TYPE_IPV6);
    }

    #[test]
    fn test_read_address_empty() {
        assert!(AddressParser::read_address(&[]).is_none());
    }

    #[test]
    fn test_read_address_truncated_ipv4() {
        assert!(AddressParser::read_address(&[1, 192, 168]).is_none());
    }

    #[test]
    fn test_read_address_truncated_domain() {
        assert!(AddressParser::read_address(&[2, 10, 104, 101]).is_none());
    }

    #[test]
    fn test_read_address_truncated_ipv6() {
        let mut data = vec![3u8];
        data.extend_from_slice(&[0u8; 10]);
        assert!(AddressParser::read_address(&data).is_none());
    }

    #[test]
    fn test_read_address_unknown_type() {
        assert!(AddressParser::read_address(&[99]).is_none());
    }

    #[test]
    fn test_read_port_insufficient() {
        assert!(AddressParser::read_port(&[0]).is_none());
        assert!(AddressParser::read_port(&[]).is_none());
    }

    #[test]
    fn test_read_port_valid() {
        let port = AddressParser::read_port(&[0x01, 0xBB]).expect("port");
        assert_eq!(port, Port::new(443));
    }

    #[test]
    fn test_parse_port_address_insufficient() {
        assert!(AddressParser::parse_port_address(&[0x00]).is_none());
    }

    #[test]
    fn test_parse_address_port_insufficient() {
        assert!(AddressParser::parse_address_port(&[]).is_none());
    }

    #[test]
    fn test_roundtrip_ipv4_port_address() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8));
        let port = Port::new(53);

        AddressSerializer::write_port_address(&mut buf, port, &addr);
        let (p, a, _) = AddressParser::parse_port_address(buf.bytes()).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, port);
    }

    #[test]
    fn test_roundtrip_domain_address_port() {
        let mut buf = Buffer::with_capacity(64);
        let addr = Address::new_domain("www.google.com");
        let port = Port::new(443);

        AddressSerializer::write_address_port(&mut buf, &addr, port);
        let (a, p, _) = AddressParser::parse_address_port(buf.bytes()).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, port);
    }
}
