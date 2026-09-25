//! TUIC v5 Address 编解码（对应 tuic-core protocol/address.rs）。
//!
//! 编码：
//! - `None`：`0xff` + `0x00 0x00`（端口占位）
//! - `Domain`：`0x00` + len(1) + name + port(2)
//! - `IPv4`：`0x01` + addr(4) + port(2)
//! - `IPv6`：`0x02` + addr(16) + port(2)
//!
//! 端口 0 用于 None 地址，符合 tuic-core 约定。

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};

use crate::error::{Result, TuicError};

/// ATYP 类型码。
const ATYP_NONE: u8 = 0xff;
const ATYP_DOMAIN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;

/// TUIC 目标地址。
///
/// 对应 tuic-core 的 `Address` 枚举。None 用于心跳等无目标命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// 无目标地址（Heartbeat 等用）。
    None,
    /// 域名 + 端口。
    Domain(String, u16),
    /// IPv4 + 端口。
    Ipv4(Ipv4Addr, u16),
    /// IPv6 + 端口。
    Ipv6(Ipv6Addr, u16),
}

impl Address {
    /// 端口（None 返 0）。
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::None => 0,
            Self::Domain(_, p) | Self::Ipv4(_, p) | Self::Ipv6(_, p) => *p,
        }
    }

    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Domain(d, _) => d.clone(),
            Self::Ipv4(ip, _) => ip.to_string(),
            Self::Ipv6(ip, _) => ip.to_string(),
        }
    }

    /// 主机地址字符串（None 返空串）。

    /// 序列化到 [`BufMut`]（对应 tuic-core marshal）。
    ///
    /// 长度：None=3, IPv4=7, IPv6=19, Domain=1+len(domain)+2。
    pub fn write_to<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::None => {
                buf.put_u8(ATYP_NONE);
                buf.put_u16(0);
            },
            Self::Domain(name, port) => {
                let bytes = name.as_bytes();
                // 域名长度以单字节表示（与 tuic-core 一致），最长 255。
                debug_assert!(
                    bytes.len() <= u8::MAX as usize,
                    "domain too long: {} bytes",
                    bytes.len()
                );
                buf.put_u8(ATYP_DOMAIN);
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
                buf.put_u16(*port);
            },
            Self::Ipv4(addr, port) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
            },
            Self::Ipv6(addr, port) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
            },
        }
    }

    /// 序列化所需字节数（预分配用）。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::None => 3,
            Self::Domain(name, _) => 1 + 1 + name.as_bytes().len() + 2,
            Self::Ipv4(_, _) => 1 + 4 + 2,
            Self::Ipv6(_, _) => 1 + 16 + 2,
        }
    }

    /// 从 [`Buf`] 解析（对应 tuic-core unmarshal）。
    pub fn read_from<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 3 {
            return Err(TuicError::UnexpectedEof("address atyp+port"));
        }
        let atyp = buf.get_u8();
        match atyp {
            ATYP_NONE => {
                let _port = buf.get_u16();
                Ok(Self::None)
            },
            ATYP_DOMAIN => {
                if buf.remaining() < 1 {
                    return Err(TuicError::UnexpectedEof("domain length"));
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(TuicError::UnexpectedEof("domain body+port"));
                }
                let mut name = vec![0u8; len];
                buf.copy_to_slice(&mut name);
                let name = String::from_utf8(name)
                    .map_err(|_| TuicError::InvalidAddress("domain not utf-8"))?;
                let port = buf.get_u16();
                Ok(Self::Domain(name, port))
            },
            ATYP_IPV4 => {
                if buf.remaining() < 4 + 2 {
                    return Err(TuicError::UnexpectedEof("ipv4 body+port"));
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Self::Ipv4(Ipv4Addr::from(octets), port))
            },
            ATYP_IPV6 => {
                if buf.remaining() < 16 + 2 {
                    return Err(TuicError::UnexpectedEof("ipv6 body+port"));
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Self::Ipv6(Ipv6Addr::from(octets), port))
            },
            _ => Err(TuicError::InvalidAddress("unknown atyp")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(addr: &Address) {
        let mut buf = Vec::with_capacity(addr.encoded_len());
        addr.write_to(&mut buf);
        assert_eq!(buf.len(), addr.encoded_len());
        let mut cursor = &buf[..];
        let parsed = Address::read_from(&mut cursor).unwrap();
        assert_eq!(*addr, parsed);
        assert!(cursor.is_empty());
    }

    #[test]
    fn none_roundtrip() {
        roundtrip(&Address::None);
    }

    #[test]
    fn domain_roundtrip() {
        roundtrip(&Address::Domain("example.com".into(), 443));
    }

    #[test]
    fn ipv4_roundtrip() {
        roundtrip(&Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080));
    }

    #[test]
    fn ipv6_roundtrip() {
        roundtrip(&Address::Ipv6(Ipv6Addr::LOCALHOST, 51820));
    }

    #[test]
    fn domain_length_in_encoding() {
        let addr = Address::Domain("hi".into(), 0);
        assert_eq!(addr.encoded_len(), 1 + 1 + 2 + 2);
        let mut buf = vec![];
        addr.write_to(&mut buf);
        assert_eq!(buf, vec![0x00, 0x02, b'h', b'i', 0x00, 0x00]);
    }

    #[test]
    fn none_port_is_zero() {
        assert_eq!(Address::None.port(), 0);
    }

    #[test]
    fn unknown_atyp_rejected() {
        let buf = [0x99, 0x00, 0x00];
        let mut cursor = &buf[..];
        let err = Address::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, TuicError::InvalidAddress(_)));
    }

    #[test]
    fn truncated_ipv4_rejected() {
        let buf = [0x01, 1, 2, 3]; // 缺 4 字节 + 2 端口
        let mut cursor = &buf[..];
        let err = Address::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, TuicError::UnexpectedEof(_)));
    }
}
