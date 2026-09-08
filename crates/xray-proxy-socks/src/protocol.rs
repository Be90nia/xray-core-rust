//! SOCKS 协议常量与帧编解码。
//!
//! 对应 Go `proxy/socks/protocol.go` 的协议常量 + UDP 包编解码部分。
//! 完整握手（`ServerSession.handshake4/handshake5`）依赖 io.Reader/Writer，
//! 留切片2。
//!
//! ## SOCKS5 地址格式（RFC 1928 §4）
//!
//! ```text
//! +----+-----+-------+------+----------+----------+
//! |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//! +----+-----+-------+------+----------+----------+
//! | 1  |  1  | X'00' |  1   | Variable |    2     |
//! +----+-----+-------+------+----------+----------+
//! ```
//!
//! ATYP 取值：
//! - `0x01` IPv4（4 字节）
//! - `0x03` Domain（1 字节长度 + 域名）
//! - `0x04` IPv6（16 字节）
//!
//! 端口 2 字节大端。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Result, SocksError};

// ===== 协议版本常量 =====

/// SOCKS5 版本号。对应 Go `socks5Version`。
pub const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS4 版本号。对应 Go `socks4Version`。
pub const SOCKS4_VERSION: u8 = 0x04;

// ===== CMD 常量 =====

/// CMD: TCP CONNECT。对应 Go `cmdTCPConnect`。
pub const CMD_TCP_CONNECT: u8 = 0x01;
/// CMD: TCP BIND。对应 Go `cmdTCPBind`。
pub const CMD_TCP_BIND: u8 = 0x02;
/// CMD: UDP ASSOCIATE。对应 Go `cmdUDPAssociate`。
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// ===== SOCKS4 响应码 =====

/// SOCKS4: 请求已批准。对应 Go `socks4RequestGranted`。
pub const SOCKS4_REQUEST_GRANTED: u8 = 90;
/// SOCKS4: 请求被拒绝。对应 Go `socks4RequestRejected`。
pub const SOCKS4_REQUEST_REJECTED: u8 = 91;

// ===== 认证方法常量 =====

/// 认证方法: 无需认证。对应 Go `authNotRequired`。
pub const AUTH_NOT_REQUIRED: u8 = 0x00;
/// 认证方法: 用户名/密码。对应 Go `authPassword`。
pub const AUTH_PASSWORD: u8 = 0x02;
/// 认证方法: 无匹配方法（拒绝连接）。对应 Go `authNoMatchingMethod`。
pub const AUTH_NO_MATCHING_METHOD: u8 = 0xFF;

// ===== SOCKS5 状态码 =====

/// SOCKS5 响应: 成功。对应 Go `statusSuccess`。
pub const STATUS_SUCCESS: u8 = 0x00;
/// SOCKS5 响应: 命令不支持。对应 Go `statusCmdNotSupport`。
pub const STATUS_CMD_NOT_SUPPORT: u8 = 0x07;

// ===== ATYP（地址类型） =====

/// ATYP: IPv4。对应 Go `AddressFamilyByte(0x01, ...)`。
pub const ATYP_IPV4: u8 = 0x01;
/// ATYP: Domain。对应 Go `AddressFamilyByte(0x03, ...)`。
pub const ATYP_DOMAIN: u8 = 0x03;
/// ATYP: IPv6。对应 Go `AddressFamilyByte(0x04, ...)`。
pub const ATYP_IPV6: u8 = 0x04;

/// 解析后的 SOCKS5 地址 + 端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksAddr {
    /// 主机（IP 或域名）。
    pub host: Host,
    /// 端口（大端 16-bit）。
    pub port: u16,
}

/// SOCKS5 主机类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// IPv4 地址。
   Ipv4(Ipv4Addr),
    /// IPv6 地址。
    Ipv6(Ipv6Addr),
    /// 域名字符串。
    Domain(String),
}

impl Host {
    /// 转换为 `IpAddr`（域名为 `None`）。
    #[must_use]
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self {
            Host::Ipv4(ip) => Some((*ip).into()),
            Host::Ipv6(ip) => Some((*ip).into()),
            Host::Domain(_) => None,
        }
    }

    /// 转换为 `SocketAddr`（域名为 `None`）。
    #[must_use]
    pub fn to_socket_addr(&self, port: u16) -> Option<SocketAddr> {
        self.to_ip_addr().map(|ip| SocketAddr::new(ip, port))
    }
}

impl SocksAddr {
    /// 构造 IPv4 地址。
    #[must_use]
    pub fn ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self { host: Host::Ipv4(ip), port }
    }

    /// 构造 IPv6 地址。
    #[must_use]
    pub fn ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self { host: Host::Ipv6(ip), port }
    }

    /// 构造域名地址。
    #[must_use]
    pub fn domain(domain: impl Into<String>, port: u16) -> Self {
        Self { host: Host::Domain(domain.into()), port }
    }

    /// 从 `SocketAddr` 构造（仅 IP，无域名）。
    #[must_use]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::ipv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::ipv6(*v6.ip(), v6.port()),
        }
    }
}

/// 写入 SOCKS5 addr+port 到字节缓冲。返回写入的字节数。
///
/// 格式：`[ATYP][addr...][port BE 2 字节]`。对应 Go `addrParser.WriteAddressPort`。
///
/// # 返回
///
/// 写入的总字节数。
#[must_use]
pub fn write_address_port(buf: &mut Vec<u8>, addr: &SocksAddr) -> usize {
    let start = buf.len();
    match &addr.host {
        Host::Ipv4(ip) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Ipv6(ip) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            buf.push(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            // 域名长度 1 字节（域名最大 255 字节）
            buf.push(bytes.len().min(255) as u8);
            buf.extend_from_slice(bytes);
        }
    }
    // port BE 2 字节
    buf.push((addr.port >> 8) as u8);
    buf.push((addr.port & 0xFF) as u8);
    buf.len() - start
}

/// 从字节切片解析 SOCKS5 addr+port。返回解析后的 [`SocksAddr`] + 消耗的字节数。
///
/// 对应 Go `addrParser.ReadAddressPort`。
///
/// 81uq：domain 字符集校验——对齐 Go `isValidDomain`
/// （`common/protocol/address.go:159-166`：仅 `0-9 a-z A-Z - . _`）。
/// Rust 旧版仅 `str::from_utf8` 检查 UTF-8 但放过 `/`、`@`、`\x00` 等
/// 非法字符——客户端用这些字符配合 ATYP=Domain 长度字段255可达
/// "域名填满 + port 字节被吞"的错位帧。新增 charset 校验在解析阶段
/// 直接拒绝（InvalidFrame），不再让不可信字节穿透到 DNS/连接层。
#[must_use]
pub fn parse_address_port(bytes: &[u8]) -> Result<(SocksAddr, usize)> {
    if bytes.is_empty() {
        return Err(SocksError::InvalidFrame("empty address buffer".into()));
    }
    let atyp = bytes[0];
    let mut offset = 1;
    let host = match atyp {
        ATYP_IPV4 => {
            if bytes.len() < offset + 4 {
                return Err(SocksError::InvalidFrame(format!(
                    "ipv4 address truncated: need {} bytes, got {}",
                    offset + 4,
                    bytes.len()
                )));
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes[offset..offset + 4]);
            offset += 4;
            Host::Ipv4(Ipv4Addr::from(octets))
        }
        ATYP_IPV6 => {
            if bytes.len() < offset + 16 {
                return Err(SocksError::InvalidFrame(format!(
                    "ipv6 address truncated: need {} bytes, got {}",
                    offset + 16,
                    bytes.len()
                )));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            Host::Ipv6(Ipv6Addr::from(octets))
        }
        ATYP_DOMAIN => {
            if bytes.len() < offset + 1 {
                return Err(SocksError::InvalidFrame("domain length truncated".into()));
            }
            let len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + len {
                return Err(SocksError::InvalidFrame(format!(
                    "domain bytes truncated: need {len} bytes at offset {offset}, got {}",
                    bytes.len()
                )));
            }
            let domain_bytes = &bytes[offset..offset + len];
            // 81uq：字符集校验，对齐 Go isValidDomain（仅 0-9 a-z A-Z - . _）。
            // 见函数 doc。
            if !is_valid_domain_bytes(domain_bytes) {
                return Err(SocksError::InvalidFrame(format!(
                    "invalid domain charset: {len} bytes at offset {offset}"
                )));
            }
            let domain = std::str::from_utf8(domain_bytes)
                .map_err(|e| SocksError::InvalidFrame(format!("domain utf8 error: {e}")))?
                .to_string();
            offset += len;
            Host::Domain(domain)
        }
        other => {
            return Err(SocksError::InvalidFrame(format!(
                "unknown atyp: {other:#x}"
            )));
        }
    };
    if bytes.len() < offset + 2 {
        return Err(SocksError::InvalidFrame(format!(
            "port truncated: need {} bytes, got {}",
            offset + 2,
            bytes.len()
        )));
    }
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    Ok((SocksAddr { host, port }, offset))
}

/// 81uq：domain 字节流是否仅含合法字符（ASCII：`0-9 a-z A-Z - . _`）。
///
/// 对齐 Go `isValidDomain`（`common/protocol/address.go:159-166`），
/// 仅做字符集过滤——长度过滤在 `parse_address_port` 已通过 length byte
/// 钳制在 `[0, 255]`。这里用字节直接比对避免分配 String 副本。
///
/// 返回 `false` 的常见情况：
/// - 客户端用 ATYP=Domain + 含 `/`、`@`、`:`、` ` 的字节流伪装成"域名"
/// - 含 `\` 或 `\0` 等 SOCKS5 解析上下文不该出现的字符
#[must_use]
pub fn is_valid_domain_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|&c| {
        (c >= b'0' && c <= b'9')
            || (c >= b'a' && c <= b'z')
            || (c >= b'A' && c <= b'Z')
            || c == b'-'
            || c == b'.'
            || c == b'_'
    })
}

/// 编码 SOCKS5 UDP 包。对应 Go `EncodeUDPPacket`。
///
/// 格式：`[RSV(2)][FRAGMENT(1)][addr+port][payload]`。
///
/// `payload` 过大时返回空 payload（与 Go `b.Clear()` 一致，丢弃过大包）。
#[must_use]
pub fn encode_udp_packet(addr: &SocksAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + 32 + payload.len());
    // RSV(2) + FRAGMENT=0
    buf.push(0x00);
    buf.push(0x00);
    buf.push(0x00);
    let _ = write_address_port(&mut buf, addr);
    // ponytail: Go 端如果缓冲不足会丢弃数据。Rust 端用 Vec 动态扩展，
    // 不会触发"缓冲不足"丢弃路径。如需限制大小，由调用方在调用前校验。
    buf.extend_from_slice(payload);
    buf
}

/// 解码 SOCKS5 UDP 包。对应 Go `DecodeUDPPacket`。
///
/// 入参 `bytes` 应包含完整 UDP 包（含 RSV+FRAGMENT header）。
/// 返回解析后的 [`SocksAddr`] + payload 切片（零拷贝，引用入参）。
///
/// # 错误
///
/// - 长度不足（< 5 字节）
/// - `fragment != 0`（不支持分片）
/// - addr 解析失败
pub fn decode_udp_packet(bytes: &[u8]) -> Result<(SocksAddr, &[u8])> {
    if bytes.len() < 5 {
        return Err(SocksError::UdpPacketError(format!(
            "insufficient length: {} bytes (need >= 5)",
            bytes.len()
        )));
    }
    // bytes[0..2] = RSV，bytes[2] = FRAGMENT
    let fragment = bytes[2];
    if fragment != 0 {
        return Err(SocksError::UdpPacketError(format!(
            "discarding fragmented payload: fragment={fragment}"
        )));
    }
    // bytes[3..] = addr+port + payload
    let (addr, consumed) = parse_address_port(&bytes[3..])?;
    let payload_start = 3 + consumed;
    let payload = &bytes[payload_start..];
    Ok((addr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== write/parse address_port =====

    #[test]
    fn write_parse_ipv4_roundtrip() {
        let addr = SocksAddr::ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080);
        let mut buf = Vec::new();
        let n = write_address_port(&mut buf, &addr);
        assert_eq!(n, 1 + 4 + 2); // ATYP + IPv4 + port
        assert_eq!(buf[0], ATYP_IPV4);
        let (parsed, consumed) = parse_address_port(&buf).unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(consumed, n);
    }

    #[test]
    fn write_parse_ipv6_roundtrip() {
        let addr = SocksAddr::ipv6(Ipv6Addr::LOCALHOST, 443);
        let mut buf = Vec::new();
        let n = write_address_port(&mut buf, &addr);
        assert_eq!(n, 1 + 16 + 2);
        assert_eq!(buf[0], ATYP_IPV6);
        let (parsed, _) = parse_address_port(&buf).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn write_parse_domain_roundtrip() {
        let addr = SocksAddr::domain("example.com", 443);
        let mut buf = Vec::new();
        let n = write_address_port(&mut buf, &addr);
        assert_eq!(n, 1 + 1 + 11 + 2);
        assert_eq!(buf[0], ATYP_DOMAIN);
        let (parsed, _) = parse_address_port(&buf).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn parse_rejects_unknown_atyp() {
        let bytes = [0xFF, 0, 0, 0, 0, 0];
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
    }

    #[test]
    fn parse_rejects_truncated_ipv4() {
        let bytes = [ATYP_IPV4, 1, 2]; // 缺字节
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
    }

    #[test]
    fn parse_rejects_truncated_domain() {
        let bytes = [ATYP_DOMAIN, 100]; // 声明 100 字节但无后续
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
    }

    #[test]
    fn parse_rejects_truncated_port() {
        let bytes = [ATYP_IPV4, 1, 2, 3, 4]; // 缺 port
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
    }

    /// 81uq：含 `/` / `@` / 空格等非法字符的 ATYP=Domain 帧必须被拒，
    /// 而不是穿透到 DNS/连接层引发"错位端口 + 错位域名"下游故障。
    /// 对齐 Go `isValidDomain`（`common/protocol/address.go:159-166`）：
    /// 仅 `0-9 a-z A-Z - . _`。
    #[test]
    fn parse_rejects_invalid_domain_charset() {
        // ATYP_DOMAIN + length=1 + 字节 0x2F ('/').
        let bytes = [ATYP_DOMAIN, 1, b'/', 0, 80];
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
        // 含 '@' 字符
        let mut bytes = vec![ATYP_DOMAIN, 4, b'a', b'@', b'b', b'c', 0, 80];
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
        // 含 '\\0' 字符（不在合法集）
        let bytes = [ATYP_DOMAIN, 1, 0, 0, 80];
        let err = parse_address_port(&bytes).unwrap_err();
        assert!(matches!(err, SocksError::InvalidFrame(_)));
    }

    /// 81uq：合法字符域名（含 `_` `-` `.`）必须通过校验（round-trip）。
    #[test]
    fn parse_accepts_valid_domain_charset() {
        let mut bytes = vec![ATYP_DOMAIN, 13];
        bytes.extend_from_slice(b"a-b_c.d-e_f.g");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let (parsed, consumed) = parse_address_port(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match parsed.host {
            Host::Domain(d) => assert_eq!(d, "a-b_c.d-e_f.g"),
            other => panic!("expected Domain, got {other:?}"),
        }
        assert_eq!(parsed.port, 443);
    }

    // ===== encode/decode UDP packet =====

    #[test]
    fn encode_decode_udp_roundtrip_ipv4() {
        let addr = SocksAddr::ipv4(Ipv4Addr::new(10, 0, 0, 1), 51820);
        let payload = b"hello world";
        let packet = encode_udp_packet(&addr, payload);
        // 3 header + 7 addr + 11 payload = 21
        assert_eq!(packet.len(), 3 + 7 + payload.len());
        let (parsed_addr, parsed_payload) = decode_udp_packet(&packet).unwrap();
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn encode_decode_udp_roundtrip_domain() {
        let addr = SocksAddr::domain("vpn.example.com", 443);
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let packet = encode_udp_packet(&addr, &payload);
        let (parsed_addr, parsed_payload) = decode_udp_packet(&packet).unwrap();
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn decode_udp_rejects_fragment() {
        let mut packet = encode_udp_packet(
            &SocksAddr::ipv4(Ipv4Addr::LOCALHOST, 80),
            &[],
        );
        packet[2] = 1; // FRAGMENT = 1
        let err = decode_udp_packet(&packet).unwrap_err();
        assert!(matches!(err, SocksError::UdpPacketError(_)));
    }

    #[test]
    fn decode_udp_rejects_short_packet() {
        let err = decode_udp_packet(&[0, 0, 0, 1]).unwrap_err();
        assert!(matches!(err, SocksError::UdpPacketError(_)));
    }

    #[test]
    fn encode_udp_empty_payload() {
        let addr = SocksAddr::ipv4(Ipv4Addr::LOCALHOST, 80);
        let packet = encode_udp_packet(&addr, &[]);
        let (_, payload) = decode_udp_packet(&packet).unwrap();
        assert!(payload.is_empty());
    }

    // ===== SocksAddr helpers =====

    #[test]
    fn socks_addr_from_socket_addr_v4() {
        let sa: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let addr = SocksAddr::from_socket_addr(sa);
        assert_eq!(addr.host, Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(addr.port, 5678);
    }

    #[test]
    fn host_to_socket_addr_only_for_ip() {
        let h = Host::Ipv4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            h.to_socket_addr(80),
            Some("127.0.0.1:80".parse().unwrap())
        );
        let h = Host::Domain("example.com".into());
        assert_eq!(h.to_socket_addr(80), None);
    }

    // ===== 协议常量一致性 =====

    #[test]
    fn socks5_version_constant() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(SOCKS4_VERSION, 0x04);
    }

    #[test]
    fn cmd_constants_match_rfc1928() {
        assert_eq!(CMD_TCP_CONNECT, 0x01);
        assert_eq!(CMD_TCP_BIND, 0x02);
        assert_eq!(CMD_UDP_ASSOCIATE, 0x03);
    }

    #[test]
    fn auth_constants_match_rfc1928() {
        assert_eq!(AUTH_NOT_REQUIRED, 0x00);
        assert_eq!(AUTH_PASSWORD, 0x02);
        assert_eq!(AUTH_NO_MATCHING_METHOD, 0xFF);
    }
}
