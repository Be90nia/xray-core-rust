//! PROXY protocol v1/v2 解析。
//!
//! 对应 HAProxy PROXY protocol spec。在 TCP accept 后、应用层握手前调用，
//! 提取真实客户端地址（覆盖 TCP peer）。
//!
//! 参考：Go `transport/internet/headers.go` + `proxyproto` 包。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::AsyncReadExt;

/// 读 PROXY protocol v1/v2 header，返回真实客户端地址。
///
/// 在 listener accept 后，若 `accept_proxy_protocol == true`，
/// 在应用层握手前先读 PROXY header 拿真实客户端地址（覆盖 TCP remote）。
pub async fn read_proxy_protocol<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Option<SocketAddr>> {
    // 读前 6 字节判断 v1/v2。
    let mut sig = [0u8; 6];
    reader.read_exact(&mut sig).await?;

    const V2_SIG: [u8; 6] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D];
    const V1_PREFIX: [u8; 6] = *b"PROXY ";

    if sig == V2_SIG {
        // v2：补齐 signature(6) + ver_cmd(1) + fam(1) + length(2)
        let mut rest = [0u8; 10];
        reader.read_exact(&mut rest).await?;
        let fam = rest[7];
        let length = u16::from_be_bytes([rest[8], rest[9]]) as usize;
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;

        let af = fam >> 4; // 地址族：1=INET 2=INET6
        match af {
            1 => {
                if payload.len() < 12 {
                    return Ok(None);
                }
                let src = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let sport = u16::from_be_bytes([payload[8], payload[9]]);
                Ok(Some(SocketAddr::V4(SocketAddrV4::new(src, sport))))
            }
            2 => {
                if payload.len() < 36 {
                    return Ok(None);
                }
                let mut src = [0u8; 16];
                src.copy_from_slice(&payload[0..16]);
                let sport = u16::from_be_bytes([payload[32], payload[33]]);
                Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                    src.into(),
                    sport,
                    0,
                    0,
                ))))
            }
            _ => Ok(None), // UNSPEC/UNIX/UNKNOWN
        }
    } else if sig == V1_PREFIX {
        // v1：已读 "PROXY "，继续读直到 \r\n
        let mut line = Vec::from(&b"PROXY "[..]);
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
            if line.len() > 107 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v1 too long",
                ));
            }
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 not utf8"))?;
        // "PROXY TCP4 src dst sport dport\r\n"
        let parts: Vec<&str> = text.trim_end().split_whitespace().collect();
        if parts.len() >= 6 {
            let sport: u16 = parts[4].parse().unwrap_or(0);
            match parts[1] {
                "TCP4" => {
                    if let Ok(ip) = parts[2].parse::<Ipv4Addr>() {
                        return Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, sport))));
                    }
                }
                "TCP6" => {
                    if let Ok(ip) = parts[2].parse::<Ipv6Addr>() {
                        return Ok(Some(SocketAddr::V6(SocketAddrV6::new(ip, sport, 0, 0))));
                    }
                }
                _ => {}
            }
        }
        Ok(None) // UNKNOWN 或解析失败
    } else {
        // 非 PROXY protocol：调用方保证启用时有 header，当错误处理
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected proxy protocol header",
        ))
    }
}

/// 构造 PROXY protocol v1/v2 header 字节，供 outbound（如 freedom）写入拨号连接。
///
/// 对应 Go `proxyproto.HeaderProxyFromAddrs(version, src, dst)`。
/// `version` 仅接受 1 或 2；其他值返回空 `Vec`（调用方应先校验）。
#[must_use]
pub fn build_proxy_header(version: u8, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match version {
        1 => build_proxy_header_v1(src, dst),
        2 => build_proxy_header_v2(src, dst),
        _ => Vec::new(),
    }
}

/// v1：`PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n`。
fn build_proxy_header_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (proto, src_ip, dst_ip, src_port, dst_port) = match (src, dst) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => {
            ("TCP4", a.ip().to_string(), b.ip().to_string(), a.port(), b.port())
        }
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            ("TCP6", a.ip().to_string(), b.ip().to_string(), a.port(), b.port())
        }
        // 地址族不一致：降级为 UNKNOWN（与 go-proxyproto 一致）。
        _ => return b"PROXY UNKNOWN\r\n".to_vec(),
    };
    format!("PROXY {proto} {src_ip} {dst_ip} {src_port} {dst_port}\r\n").into_bytes()
}

/// v2：12 字节 signature + ver/cmd + family/proto + length + 地址负载。
fn build_proxy_header_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    // version=2 (高 4 bit) | command=PROXY (低 4 bit, 值 1) → 0x21。
    const VER_CMD_PROXY: u8 = 0x21;
    let (fam_proto, addr_bytes) = match (src, dst) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => {
            // address family=INET(1) | transport=STREAM(1) → 0x11。
            let mut v = Vec::with_capacity(12);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&b.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&b.port().to_be_bytes());
            (0x11u8, v)
        }
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            // address family=INET6(2) | transport=STREAM(1) → 0x21。
            let mut v = Vec::with_capacity(36);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&b.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&b.port().to_be_bytes());
            (0x21u8, v)
        }
        // 地址族不一致：AF_UNSPEC | UNSPEC(0) → 0x00，无地址负载。
        _ => (0x00u8, Vec::new()),
    };
    let mut out = Vec::with_capacity(SIG.len() + 4 + addr_bytes.len());
    out.extend_from_slice(&SIG);
    out.push(VER_CMD_PROXY);
    out.push(fam_proto);
    out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&addr_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_proxy_protocol_v1_tcp4() {
        let header = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, Some("1.2.3.4:1234".parse::<SocketAddr>().unwrap()));
    }

    #[tokio::test]
    async fn read_proxy_protocol_v1_tcp6() {
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 1234 80\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, Some("[2001:db8::1]:1234".parse::<SocketAddr>().unwrap()));
    }

    #[tokio::test]
    async fn read_proxy_protocol_v1_unknown_returns_none() {
        let header = b"PROXY UNKNOWN\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, None);
    }

    #[tokio::test]
    async fn read_proxy_protocol_v2_tcp4() {
        let mut header = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // sig(12)
            0x21, // ver(2)+cmd(1=PROXY)
            0x11, // af(1=INET)+proto(1=STREAM)
            0x00, 0x0C, // length=12
        ];
        header.extend_from_slice(&[1, 2, 3, 4]); // src
        header.extend_from_slice(&[5, 6, 7, 8]); // dst
        header.extend_from_slice(&[0x04, 0xD2]); // sport=1234
        header.extend_from_slice(&[0x00, 0x50]); // dport=80
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, Some("1.2.3.4:1234".parse::<SocketAddr>().unwrap()));
    }

    #[tokio::test]
    async fn read_proxy_protocol_v2_tcp6() {
        let mut header = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            0x21, 0x21, // af(2=INET6)+proto(STREAM)
            0x00, 0x24, // length=36
        ];
        let mut src = [0u8; 16];
        src[0] = 0x20; src[1] = 0x01; src[2] = 0x0d; src[3] = 0xb8;
        src[15] = 0x01;
        header.extend_from_slice(&src); // src
        header.extend_from_slice(&[0u8; 16]); // dst
        header.extend_from_slice(&[0x04, 0xD2]); // sport=1234
        header.extend_from_slice(&[0x00, 0x50]); // dport=80
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, Some("[2001:db8::1]:1234".parse::<SocketAddr>().unwrap()));
    }

    #[tokio::test]
    async fn read_proxy_protocol_not_proxy_returns_err() {
        let header = b"GET / HT";
        let mut reader = &header[..];
        let result = read_proxy_protocol(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn build_proxy_header_v1_tcp4_roundtrip() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:80".parse().unwrap();
        let header = build_proxy_header(1, src, dst);
        assert_eq!(header, b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n");
    }

    #[test]
    fn build_proxy_header_v1_family_mismatch_unknown() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let header = build_proxy_header(1, src, dst);
        assert_eq!(header, b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn build_proxy_header_v2_tcp4_parses_back() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:80".parse().unwrap();
        let header = build_proxy_header(2, src, dst);
        let mut reader = &header[..];
        // 同步上下文用 tokio runtime 驱动 read_proxy_protocol。
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(read_proxy_protocol(&mut reader)).unwrap();
        assert_eq!(addr, Some(src));
    }

    #[test]
    fn build_proxy_header_unknown_version_empty() {
        let src: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:80".parse().unwrap();
        assert!(build_proxy_header(3, src, dst).is_empty());
    }
}
