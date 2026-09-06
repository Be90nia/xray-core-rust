//! SOCKS5 地址格式编解码。
//!
//! AnyTLS 协议要求客户端在 stream 第一帧写 SOCKS5 格式目标地址
//! （[RFC 1928 §5](https://tools.ietf.org/html/rfc1928#section-5) ATYP+DST.ADDR+DST.PORT）。
//! 服务端从 stream 第一帧读出目标地址再拨号。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::{AnytlsError, Result};

/// SOCKS5 ATYP 值。
mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// SOCKS5 目标地址（域名或 IP）+ 端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAddr {
    /// 域名形式（ATYP=0x03）。
    Domain(String, u16),
    /// IPv4 形式（ATYP=0x01）。
   Ipv4(SocketAddrV4),
    /// IPv6 形式（ATYP=0x04）。
   Ipv6(SocketAddrV6),
}

impl SocksAddr {
    /// 构造域名地址。
    #[must_use]
    pub fn domain(host: impl Into<String>, port: u16) -> Self {
        Self::Domain(host.into(), port)
    }

    /// 构造 IPv4 地址。
    #[must_use]
    pub fn ipv4(addr: Ipv4Addr, port: u16) -> Self {
        Self::Ipv4(SocketAddrV4::new(addr, port))
    }

    /// 从 `SocketAddr` 构造（域名场景需手动指定）。
    #[must_use]
    pub fn from_socket(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => Self::Ipv4(a),
            SocketAddr::V6(a) => Self::Ipv6(a),
        }
    }

    /// 编码为 SOCKS5 字节流（ATYP+ADDR+PORT，大端端口）。
    ///
    /// 域名超 255 字节返回显式错误（RFC 1928 长度为单字节），不再 panic。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        match self {
            Self::Domain(host, port) => {
                let host_bytes = host.as_bytes();
                let len = u8::try_from(host_bytes.len()).map_err(|_| {
                    AnytlsError::InvalidSocksAddr(format!(
                        "domain too long: {} bytes (max 255)",
                        host_bytes.len()
                    ))
                })?;
                buf.push(atyp::DOMAIN);
                buf.push(len);
                buf.extend_from_slice(host_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv4(addr) => {
                buf.push(atyp::IPV4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Ipv6(addr) => {
                buf.push(atyp::IPV6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        Ok(buf)
    }

    /// 从 SOCKS5 字节流解码（与 `encode` 互逆）。
    ///
    /// 返回 (地址, 消耗字节数)。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(AnytlsError::InvalidSocksAddr("empty buffer".into()));
        }
        let atyp = buf[0];
        match atyp {
            atyp::IPV4 => {
                if buf.len() < 1 + 4 + 2 {
                    return Err(AnytlsError::InvalidSocksAddr("ipv4 too short".into()));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((
                    Self::Ipv4(SocketAddrV4::new(Ipv4Addr::from(ip), port)),
                    7,
                ))
            }
            atyp::DOMAIN => {
                if buf.len() < 2 {
                    return Err(AnytlsError::InvalidSocksAddr("domain length missing".into()));
                }
                let len = usize::from(buf[1]);
                let total = 1 + 1 + len + 2;
                if buf.len() < total {
                    return Err(AnytlsError::InvalidSocksAddr("domain truncated".into()));
                }
                let host = std::str::from_utf8(&buf[2..2 + len])
                    .map_err(|e| AnytlsError::InvalidSocksAddr(format!("non-utf8 domain: {e}")))?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
                Ok((Self::Domain(host, port), total))
            }
            atyp::IPV6 => {
                if buf.len() < 1 + 16 + 2 {
                    return Err(AnytlsError::InvalidSocksAddr("ipv6 too short".into()));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((
                    Self::Ipv6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0)),
                    19,
                ))
            }
            other => Err(AnytlsError::InvalidSocksAddr(format!("unknown atyp: {other}"))),
        }
    }

    /// 解析 `host:port` 字符串为 `SocksAddr`。
    ///
    /// 优先识别 IPv4/IPv6 字面量，否则视为域名。
    pub fn parse(s: &str) -> Result<Self> {
        let (host, port) = parse_host_port(s)?;
        if let Ok(v4) = host.parse::<Ipv4Addr>() {
            return Ok(Self::ipv4(v4, port));
        }
        if let Ok(v6) = host.parse::<Ipv6Addr>() {
            let mut segs = v6.octets();
            segs.reverse();
            return Ok(Self::Ipv6(SocketAddrV6::new(v6, port, 0, 0)));
        }
        Ok(Self::domain(host, port))
    }
}

/// 解析 `host:port`（支持 IPv6 `[::1]:443` 形式）。
fn parse_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 [::1]:443
        let end = rest
            .find(']')
            .ok_or_else(|| AnytlsError::InvalidSocksAddr(format!("missing ']' in {s}")))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| AnytlsError::InvalidSocksAddr(format!("missing port in {s}")))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|e| AnytlsError::InvalidSocksAddr(format!("invalid port {port_str}: {e}")))?;
        return Ok((host.to_string(), port));
    }
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| AnytlsError::InvalidSocksAddr(format!("missing port in {s}")))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|e| AnytlsError::InvalidSocksAddr(format!("invalid port {port_str}: {e}")))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_domain() {
        let addr = SocksAddr::domain("example.com", 443);
        let bytes = addr.encode().unwrap();
        assert_eq!(bytes[0], atyp::DOMAIN);
        let (decoded, n) = SocksAddr::decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        match decoded {
            SocksAddr::Domain(h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn roundtrip_ipv4() {
        let addr = SocksAddr::ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let bytes = addr.encode().unwrap();
        assert_eq!(bytes[0], atyp::IPV4);
        let (decoded, n) = SocksAddr::decode(&bytes).unwrap();
        assert_eq!(n, 7);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn roundtrip_ipv6() {
        let addr = SocksAddr::Ipv6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let bytes = addr.encode().unwrap();
        assert_eq!(bytes[0], atyp::IPV6);
        let (decoded, n) = SocksAddr::decode(&bytes).unwrap();
        assert_eq!(n, 19);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn parse_simple() {
        match SocksAddr::parse("example.com:443").unwrap() {
            SocksAddr::Domain(h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!(),
        }
        match SocksAddr::parse("127.0.0.1:8080").unwrap() {
            SocksAddr::Ipv4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(a.port(), 8080);
            }
            _ => panic!(),
        }
        match SocksAddr::parse("[::1]:443").unwrap() {
            SocksAddr::Ipv6(a) => {
                assert_eq!(a.ip(), &Ipv6Addr::LOCALHOST);
                assert_eq!(a.port(), 443);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert!(SocksAddr::decode(&[]).is_err());
        assert!(SocksAddr::decode(&[0x05]).is_err()); // 未知 ATYP
        assert!(SocksAddr::parse("no_port").is_err());
        assert!(SocksAddr::parse("host:99999").is_err()); // 端口超范围
    }

    /// 域名超 255 字节：显式错误而非 panic（RFC 1928 长度单字节上限）。
    #[test]
    fn encode_rejects_domain_over_255() {
        let addr = SocksAddr::domain("x".repeat(256), 443);
        let err = addr.encode().unwrap_err();
        assert!(err.to_string().contains("domain too long"), "got {err}");
    }
}
