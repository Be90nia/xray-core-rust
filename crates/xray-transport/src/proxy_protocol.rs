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
}
