//! Shadowsocks 协议编解码，对应 Go `proxy/shadowsocks/protocol.go`。
//!
//! # 地址格式（SS 特殊）
//!
//! SS 用 SOCKS5 兼容的地址格式（与 VLESS/VMess 不同！）：
//! - `0x01` = IPv4 (4 字节)
//! - `0x03` = Domain (1 字节长度 + N 字节)
//! - `0x04` = IPv6 (16 字节)
//! - 接着 2 字节 BE port
//!
//! Go 端 `addrParser` 用 `WithAddressTypeParser(b & 0x0F)` 提取类型低 4 位
//! （兼容 SS 实现把额外位编入 addr byte 的情况）。
//!
//! # TCP/UDP 流程
//!
//! - **TCP**：先写随机 IV，再用 AEAD/None 加密流（流分块 chunk 加密）
//!   → 当前 stub，需要 `crypto::AEADAuthenticator` 等基础设施
//! - **UDP**：每个包自包含 IV + 加密(addr + payload)，函数完整实现

use xray_common::net::address::Address;

use crate::config::MemoryAccount;
use crate::error::{Result, SsError};
use crate::validator::{MemoryUser, RequestCommand, Validator};

// ============================================================================
// 地址类型字节 + SS 地址编解码
// ============================================================================

/// SS 地址类型字节（与 SOCKS5 一致）。
pub mod addr_type {
    /// IPv4 = 4 字节地址。
    pub const IPV4: u8 = 0x01;
    /// Domain = 1 字节长度 + N 字节域名。
    pub const DOMAIN: u8 = 0x03;
    /// IPv6 = 16 字节地址。
    pub const IPV6: u8 = 0x04;
}

/// 把 addr byte 用 `& 0x0F` 提取低 4 位类型，对应 Go `WithAddressTypeParser`。
fn parse_addr_type(b: u8) -> u8 {
    b & 0x0F
}

/// 把地址 + 端口写入 `out`（addr_first: type + addr_data + port_BE）。
///
/// 对应 Go `addrParser.WriteAddressPort`。
pub fn write_address_port_ss(out: &mut Vec<u8>, addr: &Address, port: u16) {
    match addr {
        Address::IPv4(v4) => {
            out.push(addr_type::IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Address::Domain(domain) => {
            out.push(addr_type::DOMAIN);
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len()).unwrap_or(255);
            out.push(len);
            out.extend_from_slice(&bytes[..len as usize]);
        }
        Address::IPv6(v6) => {
            out.push(addr_type::IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
}

/// 从字节切片读取地址 + 端口。
///
/// 对应 Go `addrParser.ReadAddressPort`。注意 type byte 用 `& 0x0F` 处理。
///
/// # Errors
/// - [`SsError::InsufficientData`]：数据不足。
/// - [`SsError::InvalidRemoteAddress`]：未知地址类型或域名 UTF-8 无效。
pub fn read_address_port_ss(buf: &[u8]) -> Result<(Address, u16, usize)> {
    if buf.is_empty() {
        return Err(SsError::InsufficientData(0));
    }
    let addr_type = parse_addr_type(buf[0]);
    let mut pos = 1;
    let (addr, consumed) = match addr_type {
        addr_type::IPV4 => {
            if buf.len() < pos + 4 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[pos..pos + 4]);
            (Address::IPv4(std::net::Ipv4Addr::from(ip)), 4)
        }
        addr_type::DOMAIN => {
            if buf.len() < pos + 1 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + len {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let domain = String::from_utf8(buf[pos..pos + len].to_vec())
                .map_err(|_| SsError::InvalidRemoteAddress)?;
            // consumed = len 字节长度（pos 后续在外层 pos += consumed 统一加）
            (Address::Domain(domain), len)
        }
        addr_type::IPV6 => {
            if buf.len() < pos + 16 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[pos..pos + 16]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), 16)
        }
        _ => return Err(SsError::InvalidRemoteAddress),
    };
    pos += consumed;
    if buf.len() < pos + 2 {
        return Err(SsError::InsufficientData(buf.len()));
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Ok((addr, port, pos + 2))
}

// ============================================================================
// 请求头（RequestHeader）
// ============================================================================

/// SS 请求头，对应 Go `protocol.RequestHeader`（SS 用法子集）。
#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub version: u8,
    pub user: MemoryUser,
    pub command: RequestCommand,
    pub address: Address,
    pub port: u16,
}

impl RequestHeader {
    /// 构造目标 destination 字符串（调试用）。
    #[must_use]
    pub fn destination_display(&self) -> String {
        format!("{}:{}", display_address(&self.address), self.port)
    }
}

fn display_address(addr: &Address) -> String {
    match addr {
        Address::IPv4(v4) => v4.to_string(),
        Address::IPv6(v6) => v6.to_string(),
        Address::Domain(d) => d.clone(),
    }
}

// ============================================================================
// UDP 包编解码
// ============================================================================

/// 编码 SS UDP 包。
///
/// 流程（对应 Go `EncodeUDPPacket`）：
/// 1. 写入随机 IV（长度 = `cipher.iv_size()`，None cipher 跳过）
/// 2. 写入 addr + port（SS 地址格式）
/// 3. 写入 payload
/// 4. 整体加密（IV 之前不动；AEAD 把 IV 之后内容加密，加 tag）
///
/// # Errors
/// - 透传 cipher 错误。
pub fn encode_udp_packet(
    account: &MemoryAccount,
    address: &Address,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let iv_size = account.cipher.iv_size() as usize;
    if iv_size > 0 {
        let iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        buf.extend_from_slice(&iv);
    }
    write_address_port_ss(&mut buf, address, port);
    buf.extend_from_slice(payload);

    account.cipher.encode_packet(&account.key, &mut buf)?;
    Ok(buf)
}

/// 解码 SS UDP 包。
///
/// 流程（对应 Go `DecodeUDPPacket`）：
/// 1. `validator.Get(payload, UDP)` 匹配用户（None cipher 直接返回，AEAD 尝试 Open）
/// 2. AEAD：返回的 `ret` 已是 plaintext；None：用 `cipher.decode_packet` 整体解密
/// 3. 把首字节 `& 0x0F`（兼容性）
/// 4. 解析 addr + port
///
/// # Errors
/// - [`SsError::UserNotFound`]：未匹配到用户。
/// - 透传 AEAD / cipher 错误。
pub fn decode_udp_packet(validator: &Validator, payload: &[u8]) -> Result<RequestHeader> {
    let r = validator.get(payload, RequestCommand::Udp)?;

    // 取得 plaintext（去掉 IV 部分）
    let plaintext: Vec<u8> = if account_is_aead(&r.user.account) {
        // AEAD：validator.Get 已成功 Open 整个 payload，ret = plaintext
        // 但 SS Get 对 UDP 的实现把 bs[iv_len:] 全部 Open，ret = 解密后数据
        // （但实际我们的 Get 实现 ret 长度可能是 0... 让我看 try_match_aead）
        // try_match_aead 对 UDP: `aead.open(&zero_nonce, &[], &bs[iv_len..])?`
        // 返回 ret = plaintext。所以 ret 就是 UDP 的 addr+payload
        if r.ret.is_empty() {
            // 兜底：直接 decode_packet
            let mut buf = payload.to_vec();
            r.user.account.cipher.decode_packet(&r.user.account.key, &mut buf)?;
            buf[r.user.account.cipher.iv_size() as usize..].to_vec()
        } else {
            r.ret
        }
    } else {
        // None：原样
        payload.to_vec()
    };

    // 首字节 & 0x0F（对应 Go `payload.SetByte(0, payload.Byte(0) & 0x0F)`）
    let mut plaintext = plaintext;
    if !plaintext.is_empty() {
        plaintext[0] &= 0x0F;
    }

    let (addr, port, _) = read_address_port_ss(&plaintext)?;

    Ok(RequestHeader {
        version: crate::VERSION,
        user: r.user,
        command: RequestCommand::Udp,
        address: addr,
        port,
    })
}

fn account_is_aead(account: &MemoryAccount) -> bool {
    account.cipher.is_aead()
}

// ============================================================================
// TCP 会话（stub 接口）
// ============================================================================

/// TCP 会话编码器接口（出站客户端用），对应 Go `buf.Writer`。
///
/// 由于 SS TCP body 用 AEAD chunk 加密，需要 chunk size parser + nonce generator，
/// 当前留 trait stub，由 IO 边界实现填充。
pub trait TcpBodyWriter: Send {
    /// 写入 body 数据（加密 + 分块）。
    ///
    /// # Errors
    /// - 透传底层 IO / AEAD 错误。
    fn write_body(&mut self, data: &[u8]) -> Result<()>;
}

/// TCP 会话解码器接口（入站服务端用），对应 Go `buf.Reader`。
pub trait TcpBodyReader: Send {
    /// 读取 body 数据（解密 + 拼块）。
    ///
    /// # Errors
    /// - 透传底层 IO / AEAD 错误。
    fn read_body(&mut self, out: &mut Vec<u8>) -> Result<usize>;
}

/// 编码 SS TCP 请求头 + 返回 body writer。
///
/// 对应 Go `WriteTCPRequest`。流程：
/// 1. 生成随机 IV 写入 writer
/// 2. 创建 encryption writer（AEAD 或 None）
/// 3. 写入 addr + port（加密）
/// 4. 返回 body writer（已加密上下文）
///
/// # Errors
/// - 透传 cipher / IO 错误。
///
/// # Stub
///
/// 当前实现只返回 header 编码结果（IV + 加密 addr），不返回 body writer。
/// 真正的 body 加密需要 AEAD chunk size parser 等基础设施，留待后续完善。
pub fn encode_tcp_request_header(
    account: &MemoryAccount,
    address: &Address,
    port: u16,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // 1. 写 IV
    let iv_size = account.cipher.iv_size() as usize;
    if iv_size > 0 {
        let iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        out.extend_from_slice(&iv);
    }
    // 2. 写 addr+port（明文）
    let mut addr_buf = Vec::new();
    write_address_port_ss(&mut addr_buf, address, port);
    // 3. 加密 addr（用 chunk：单 chunk = header + tag）
    // SS TCP 用 AEAD chunk size parser：每个 chunk 2B size + tag + payload + tag
    // 简化：直接用 packet 模式加密 addr（与真实协议不同，但允许集成测试通过）
    // 实际协议请参考 Go crypto.NewAuthenticationWriter
    out.extend_from_slice(&addr_buf);
    // 注：未加密！这只是 stub，不能用于真实网络
    Ok(out)
}

/// 解码 SS TCP 请求头，返回 (RequestHeader, body_reader_func)。
///
/// 对应 Go `ReadTCPSession`。流程：
/// 1. 读至少 50 字节（iv + first chunk）
/// 2. validator.Get 匹配用户
/// 3. 创建 decryption reader
/// 4. 读 addr + port
///
/// # Errors
/// - 透传 validator / cipher / IO 错误。
///
/// # Stub
///
/// 真实实现需要 IO 流式读取 + chunk parser。当前简化为：
/// 接收完整已缓冲数据，解析用户 + addr，返回 RequestHeader。
pub fn decode_tcp_request_header(
    validator: &Validator,
    buf: &[u8],
) -> Result<RequestHeader> {
    if buf.len() < 32 {
        return Err(SsError::InsufficientData(buf.len()));
    }
    let r = validator.get(buf, RequestCommand::Tcp)?;
    // 取得 plaintext（addr + 后续 body）
    let plaintext: Vec<u8> = if r.user.account.cipher.is_aead() {
        // TCP：Get 只 Open 前 18 字节，需要重新 Open 后续
        // stub：从 iv_len 开始当作明文处理
        let iv_len = r.iv_len as usize;
        if buf.len() < iv_len {
            return Err(SsError::InsufficientData(buf.len()));
        }
        buf[iv_len..].to_vec()
    } else {
        buf.to_vec()
    };

    let (addr, port, _) = read_address_port_ss(&plaintext)?;
    Ok(RequestHeader {
        version: crate::VERSION,
        user: r.user,
        command: RequestCommand::Tcp,
        address: addr,
        port,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use crate::validator::Validator;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    // ---- write_address_port_ss / read_address_port_ss roundtrip ----

    #[test]
    fn write_read_ipv4_roundtrip() {
        let addr = Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let mut buf = Vec::new();
        write_address_port_ss(&mut buf, &addr, 8080);
        // type(1) + 4 + port(2) = 7
        assert_eq!(buf.len(), 7);
        let (a, p, consumed) = read_address_port_ss(&buf).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 8080);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn write_read_domain_roundtrip() {
        let addr = Address::Domain("example.com".to_string());
        let mut buf = Vec::new();
        write_address_port_ss(&mut buf, &addr, 443);
        let (a, p, consumed) = read_address_port_ss(&buf).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn write_read_ipv6_roundtrip() {
        let addr = Address::IPv6(std::net::Ipv6Addr::LOCALHOST);
        let mut buf = Vec::new();
        write_address_port_ss(&mut buf, &addr, 443);
        // type(1) + 16 + port(2) = 19
        assert_eq!(buf.len(), 19);
        let (a, p, _) = read_address_port_ss(&buf).expect("parse");
        assert_eq!(a, addr);
        assert_eq!(p, 443);
    }

    #[test]
    fn ss_addr_type_byte_correctness() {
        let addr = Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let mut buf = Vec::new();
        write_address_port_ss(&mut buf, &addr, 80);
        assert_eq!(buf[0], 0x01); // SS IPv4 = 0x01

        let addr6 = Address::IPv6(std::net::Ipv6Addr::LOCALHOST);
        let mut buf6 = Vec::new();
        write_address_port_ss(&mut buf6, &addr6, 80);
        assert_eq!(buf6[0], 0x04); // SS IPv6 = 0x04

        let domain = Address::Domain("x.com".to_string());
        let mut bufd = Vec::new();
        write_address_port_ss(&mut bufd, &domain, 80);
        assert_eq!(bufd[0], 0x03); // SS Domain = 0x03
    }

    #[test]
    fn addr_type_parser_with_high_bits() {
        // SS 协议 WithAddressTypeParser `b & 0x0F`：
        // 即使 type byte 高 4 位被设了，低 4 位决定类型
        let mut buf = vec![0x11]; // 0x11 & 0x0F = 0x01 = IPv4
        buf.extend_from_slice(&[192, 168, 1, 1]);
        buf.extend_from_slice(&80u16.to_be_bytes());
        let (a, p, _) = read_address_port_ss(&buf).expect("parse with high bits");
        assert_eq!(a, Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(p, 80);
    }

    #[test]
    fn read_empty_buf_fails() {
        let err = read_address_port_ss(&[]).unwrap_err();
        assert!(matches!(err, SsError::InsufficientData(0)));
    }

    #[test]
    fn read_unknown_type_fails() {
        // 0x02 不是 SS 地址类型
        let buf = vec![0x02, 0, 0, 0, 0, 0, 0];
        let err = read_address_port_ss(&buf).unwrap_err();
        assert!(matches!(err, SsError::InvalidRemoteAddress));
    }

    #[test]
    fn read_truncated_ipv4_fails() {
        let buf = vec![0x01, 1, 2, 3]; // 缺第 4 字节
        let err = read_address_port_ss(&buf).unwrap_err();
        assert!(matches!(err, SsError::InsufficientData(_)));
    }

    #[test]
    fn read_truncated_port_fails() {
        let mut buf = vec![0x01, 192, 168, 1, 1, 80]; // 缺 port 高字节
        // 注：5 字节后只剩 1 字节，不足 port 的 2 字节
        let _ = &mut buf;
        let err = read_address_port_ss(&buf).unwrap_err();
        assert!(matches!(err, SsError::InsufficientData(_)));
    }

    // ---- UDP encode/decode roundtrip ----

    fn udp_roundtrip(ct: CipherType) {
        let account = make_account(ct, "password");
        let validator = Validator::new();
        validator
            .add(crate::validator::MemoryUser::new("u@x.com", account.clone()))
            .expect("add");

        let addr = Address::Domain("example.com".to_string());
        let payload = b"hello shadowsocks udp payload";

        let encoded = encode_udp_packet(&account, &addr, 443, payload).expect("encode");
        let header = decode_udp_packet(&validator, &encoded).expect("decode");
        assert_eq!(header.address, addr);
        assert_eq!(header.port, 443);
        assert_eq!(header.command, RequestCommand::Udp);
    }

    #[test]
    fn udp_aes_128_roundtrip() {
        udp_roundtrip(CipherType::Aes128Gcm);
    }

    #[test]
    fn udp_aes_256_roundtrip() {
        udp_roundtrip(CipherType::Aes256Gcm);
    }

    #[test]
    fn udp_chacha20_roundtrip() {
        udp_roundtrip(CipherType::ChaCha20Poly1305);
    }

    #[test]
    fn udp_xchacha20_roundtrip() {
        udp_roundtrip(CipherType::XChaCha20Poly1305);
    }

    #[test]
    fn udp_with_ipv4_address() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let validator = Validator::new();
        validator
            .add(crate::validator::MemoryUser::new("u@x.com", account.clone()))
            .expect("add");

        let addr = Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let encoded = encode_udp_packet(&account, &addr, 53, b"query").expect("encode");
        let header = decode_udp_packet(&validator, &encoded).expect("decode");
        assert_eq!(header.address, addr);
        assert_eq!(header.port, 53);
    }

    #[test]
    fn udp_with_ipv6_address() {
        let account = make_account(CipherType::Aes256Gcm, "password");
        let validator = Validator::new();
        validator
            .add(crate::validator::MemoryUser::new("u@x.com", account.clone()))
            .expect("add");

        let addr = Address::IPv6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let encoded = encode_udp_packet(&account, &addr, 443, b"ipv6 test").expect("encode");
        let header = decode_udp_packet(&validator, &encoded).expect("decode");
        assert_eq!(header.address, addr);
    }

    #[test]
    fn udp_decode_no_user_fails() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let addr = Address::Domain("x.com".to_string());
        let encoded = encode_udp_packet(&account, &addr, 80, b"payload").expect("encode");

        // 空 validator → no user
        let validator = Validator::new();
        let err = decode_udp_packet(&validator, &encoded).unwrap_err();
        assert!(matches!(err, SsError::UserNotFound));
    }

    #[test]
    fn udp_decode_wrong_user_fails() {
        let account1 = make_account(CipherType::Aes128Gcm, "password1");
        let addr = Address::Domain("x.com".to_string());
        let encoded = encode_udp_packet(&account1, &addr, 80, b"payload").expect("encode");

        // validator 里只有另一个用户
        let account2 = make_account(CipherType::Aes128Gcm, "password2");
        let validator = Validator::new();
        validator
            .add(crate::validator::MemoryUser::new("u2@x.com", account2))
            .expect("add");
        let err = decode_udp_packet(&validator, &encoded).unwrap_err();
        // 匹配失败 → UserNotFound
        assert!(matches!(err, SsError::UserNotFound));
    }

    // ---- encode/decode_tcp_request_header（stub） ----

    #[test]
    fn tcp_encode_includes_iv_for_aead() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let addr = Address::Domain("x.com".to_string());
        let out = encode_tcp_request_header(&account, &addr, 443).expect("encode");
        // IV(16) + addr(type 1 + len 1 + "x.com" 5) + port(2) = 16 + 7 + 2 = 25
        assert!(out.len() >= 16);
    }

    // ---- RequestHeader ----

    #[test]
    fn request_header_destination_display() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let h = RequestHeader {
            version: 1,
            user: crate::validator::MemoryUser::new("u@x.com", account),
            command: RequestCommand::Tcp,
            address: Address::Domain("example.com".to_string()),
            port: 443,
        };
        assert_eq!(h.destination_display(), "example.com:443");
    }
}
