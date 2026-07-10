//! VMess 编码：通用辅助 + chunk size parser。
//!
//! 对应 Go 版本 `proxy/vmess/encoding/auth.go`。
//! `ClientSession`/`ServerSession` 在子模块 [`client`] / [`server`] 中。

pub mod body_chunk;
pub mod client;
pub mod server;


use md5::Md5;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;


// ============================================================================
// 常量
// ============================================================================

/// VMess 协议版本（对应 Go `encoding.Version`）。
pub const VERSION: u8 = 1;

/// 数据 chunk 最大长度（2 字节 length 字段，最高位 0x3FFF，VMess 用 0x3FFF）。
pub const CHUNK_SIZE_MAX: usize = 0x3FFF;

/// AEAD tag 长度（AES-GCM / ChaCha20-Poly1305）。
pub const AEAD_TAG_SIZE: usize = 16;

/// AuthenticatedLength 实验的 KDF path 字符串。
pub const AUTHENTICATED_LENGTH_PATH: &str = "auth_len";

// ============================================================================
// Authenticate：FNV1a 32-bit（对应 Go `Authenticate`）
// ============================================================================

/// 计算 FNV1a-32 哈希（对应 Go `Authenticate(b)`）。
///
/// 用于命令 marshalling 的 auth field（4 字节，BE）。
#[must_use]
pub fn authenticate(b: &[u8]) -> u32 {
    // ponytail: 手写 FNV1a-32，不用 fnv crate（它是 64-bit prime，结果不同）
    let mut hash: u32 = 0x811C_9DC5; // FNV1a 32-bit offset basis
    for byte in b {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193); // FNV1a 32-bit prime
    }
    hash
}

// ============================================================================
// GenerateChacha20Poly1305Key（对应 Go 同名函数）
// ============================================================================

/// 从 16 字节 key 生成 32 字节 ChaCha20-Poly1305 key。
///
/// 算法：`key[0..16] = MD5(input)`，`key[16..32] = MD5(MD5(input))`。
#[must_use]
pub fn generate_chacha20poly1305_key(input: &[u8]) -> [u8; 32] {
    use md5::Digest;
    let mut key = [0u8; 32];
    let mut t = Md5::digest(input);
    key[..16].copy_from_slice(&t);
    t = Md5::digest(&t);
    key[16..].copy_from_slice(&t);
    key
}

// ============================================================================
// GenerateChunkNonce（对应 Go `GenerateChunkNonce`）
// ============================================================================

/// Chunk nonce 生成器：每次返回当前 nonce，count 自增。
///
/// 对应 Go `GenerateChunkNonce(nonce, size)`：返回闭包 `Fn() -> Vec<u8>`。
/// Rust 端用结构体 + `RefCell` 持有状态（同步使用；async 场景调用方需自己加锁）。
///
/// # 算法
///
/// ```text
/// nonce_buffer = nonce.to_vec()  // 长度 = nonce_size
/// count = 0
/// 每次调用:
///   nonce_buffer[0..2] = count.to_be_bytes()
///   count += 1
///   返回 nonce_buffer[..nonce_size]
/// ```
pub struct ChunkNonceGenerator {
    buffer: Vec<u8>,
    nonce_size: usize,
    count: u16,
}

impl ChunkNonceGenerator {
    /// 创建生成器。`nonce` 是初始 nonce（长度 = nonce_size）。
    #[must_use]
    pub fn new(nonce: &[u8], nonce_size: usize) -> Self {
        let mut buffer = vec![0u8; nonce.len()];
        buffer.copy_from_slice(nonce);
        Self {
            buffer,
            nonce_size,
            count: 0,
        }
    }

    /// 生成下一个 nonce（自增 count）。
    #[must_use]
    pub fn next(&mut self) -> Vec<u8> {
        let bytes = self.count.to_be_bytes();
        if self.buffer.len() >= 2 {
            self.buffer[0] = bytes[0];
            self.buffer[1] = bytes[1];
        }
        self.count = self.count.wrapping_add(1);
        self.buffer[..self.nonce_size].to_vec()
    }

    /// 当前 count（不递增）。
    #[must_use]
    pub fn current_count(&self) -> u16 {
        self.count
    }
}

// ============================================================================
// ShakeSizeParser（对应 Go `ShakeSizeParser`）
// ============================================================================

/// SHAKE128-based chunk size parser。
///
/// 用于 VMess 的 chunk masking：把 2 字节 length 异或 SHAKE128 派生的 mask。
/// padding 长度由 SHAKE128 派生的 2 字节 mod 64 决定。
pub struct ShakeSizeParser {
    reader: Box<dyn XofReader>,
}

impl ShakeSizeParser {
    /// 创建 parser，初始 seed = nonce。
    #[must_use]
    pub fn new(nonce: &[u8]) -> Self {
        let mut shake = Shake128::default();
        Update::update(&mut shake, nonce);
        Self {
            reader: Box::new(shake.finalize_xof()),
        }
    }

    /// 长度字段的字节数（恒为 2）。
    #[must_use]
    pub const fn size_bytes() -> usize {
        2
    }

    /// 读 2 字节 mask（mut 版本，对应 Go `next()`）。
    pub fn next_mask_mut(&mut self) -> [u8; 2] {
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        buf
    }

    /// 解码 2 字节 size：`mask ^ input`（BE u16）。
    pub fn decode_mut(&mut self, input: &[u8; 2]) -> u16 {
        let mask = self.next_mask_mut();
        let raw = u16::from_be_bytes(*input);
        let masked = u16::from_be_bytes(mask);
        raw ^ masked
    }

    /// 编码 size 到 2 字节 BE：`mask ^ size`。
    pub fn encode_mut(&mut self, size: u16, out: &mut [u8; 2]) {
        let mask = self.next_mask_mut();
        let masked = u16::from_be_bytes(mask) ^ size;
        let bytes = masked.to_be_bytes();
        out[0] = bytes[0];
        out[1] = bytes[1];
    }

    /// 下一个 padding 长度（2 字节 mask mod 64，对应 Go `NextPaddingLen`）。
    pub fn next_padding_len_mut(&mut self) -> u16 {
        let mask = self.next_mask_mut();
        u16::from_be_bytes(mask) % 64
    }

    /// 最大 padding 长度（恒为 64，对应 Go `MaxPaddingLen`）。
    #[must_use]
    pub const fn max_padding_len() -> u16 {
        64
    }
}

// ============================================================================
// NoOpAuthenticator（对应 Go 同名类型，已 DEPRECATED 但保留兼容）
// ============================================================================

/// No-op AEAD：直接复制 plaintext，无加密无 tag。
///
/// 对应 Go `NoOpAuthenticator`，用于 SecurityType::NONE + chunk stream + packet 模式。
pub struct NoOpAuthenticator;

impl NoOpAuthenticator {
    /// Nonce 大小（恒为 0）。
    #[must_use]
    pub const fn nonce_size() -> usize {
        0
    }

    /// Overhead（恒为 0）。
    #[must_use]
    pub const fn overhead() -> usize {
        0
    }

    /// Seal：返回 plaintext 副本（对应 Go `Seal`）。
    #[must_use]
    pub fn seal(plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    /// Open：返回 ciphertext 副本（对应 Go `Open`，永远成功）。
    #[must_use]
    pub fn open(ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.to_vec()
    }
}

// ============================================================================
// PlainChunkSizeParser（对应 Go `crypto.PlainChunkSizeParser`）
// ============================================================================

/// 不加掩码的 chunk size parser（length 字段明文 BE u16）。
pub struct PlainChunkSizeParser;

impl PlainChunkSizeParser {
    /// 长度字段字节数。
    #[must_use]
    pub const fn size_bytes() -> usize {
        2
    }

    /// 解码 size。
    #[must_use]
    pub fn decode(input: &[u8; 2]) -> u16 {
        u16::from_be_bytes(*input)
    }

    /// 编码 size。
    pub fn encode(size: u16, out: &mut [u8; 2]) {
        let bytes = size.to_be_bytes();
        out[0] = bytes[0];
        out[1] = bytes[1];
    }
}

// ============================================================================
// 地址 + Port 编解码（与 VLESS 格式一致）
// ============================================================================

/// 地址类型字节。
pub mod addr_type {
    /// IPv4 = 4 字节地址。
    pub const IPV4: u8 = 1;
    /// Domain = 1 字节长度 + N 字节域名。
    pub const DOMAIN: u8 = 2;
    /// IPv6 = 16 字节地址。
    pub const IPV6: u8 = 3;
}

/// 把地址 + 端口写入 `out`（2B BE port + 1B type + data）。
pub fn write_address_port(
    out: &mut Vec<u8>,
    address: &xray_common::net::address::Address,
    port: u16,
) {
    out.extend_from_slice(&port.to_be_bytes());
    match address {
        xray_common::net::address::Address::IPv4(v4) => {
            out.push(addr_type::IPV4);
            out.extend_from_slice(&v4.octets());
        }
        xray_common::net::address::Address::Domain(domain) => {
            out.push(addr_type::DOMAIN);
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len()).unwrap_or(255);
            out.push(len);
            out.extend_from_slice(&bytes[..len as usize]);
        }
        xray_common::net::address::Address::IPv6(v6) => {
            out.push(addr_type::IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// 从字节切片读取地址 + 端口（同步，对应 Go `addrParser.ReadAddressPort`）。
///
/// 返回 `(address, port, consumed_bytes)`。
pub fn read_address_port(
    buf: &[u8],
) -> Result<(xray_common::net::address::Address, u16, usize), crate::error::VmessError> {
    if buf.len() < 3 {
        return Err(crate::error::VmessError::InsufficientLength);
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let addr_type_byte = buf[2];
    let addr_start = 3;
    let (addr, consumed) = match addr_type_byte {
        addr_type::IPV4 => {
            if buf.len() < addr_start + 4 {
                return Err(crate::error::VmessError::InsufficientLength);
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[addr_start..addr_start + 4]);
            (
                xray_common::net::address::Address::IPv4(std::net::Ipv4Addr::from(ip)),
                4,
            )
        }
        addr_type::DOMAIN => {
            if buf.len() < addr_start + 1 {
                return Err(crate::error::VmessError::InsufficientLength);
            }
            let len = buf[addr_start] as usize;
            if buf.len() < addr_start + 1 + len {
                return Err(crate::error::VmessError::InsufficientLength);
            }
            let domain = String::from_utf8(buf[addr_start + 1..addr_start + 1 + len].to_vec())
                .map_err(|_| crate::error::VmessError::InvalidRemoteAddress)?;
            (
                xray_common::net::address::Address::Domain(domain),
                1 + len,
            )
        }
        addr_type::IPV6 => {
            if buf.len() < addr_start + 16 {
                return Err(crate::error::VmessError::InsufficientLength);
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[addr_start..addr_start + 16]);
            (
                xray_common::net::address::Address::IPv6(std::net::Ipv6Addr::from(ip)),
                16,
            )
        }
        _ => return Err(crate::error::VmessError::InvalidRemoteAddress),
    };
    Ok((addr, port, addr_start + consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_deterministic() {
        let a = authenticate(b"hello");
        let b = authenticate(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn authenticate_different_inputs() {
        let a = authenticate(b"hello");
        let b = authenticate(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn authenticate_empty() {
        let _ = authenticate(b"");
    }

    #[test]
    fn chacha_key_is_32_bytes() {
        let key = generate_chacha20poly1305_key(&[1u8; 16]);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn chacha_key_deterministic() {
        let a = generate_chacha20poly1305_key(&[1u8; 16]);
        let b = generate_chacha20poly1305_key(&[1u8; 16]);
        assert_eq!(a, b);
    }

    #[test]
    fn chacha_key_changes_with_input() {
        let a = generate_chacha20poly1305_key(&[1u8; 16]);
        let b = generate_chacha20poly1305_key(&[2u8; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn chunk_nonce_first_two_bytes_are_zero() {
        let mut g = ChunkNonceGenerator::new(&[0xAA; 16], 16);
        let n = g.next();
        assert_eq!(n.len(), 16);
        assert_eq!(n[0], 0);
        assert_eq!(n[1], 0);
    }

    #[test]
    fn chunk_nonce_increments_count() {
        let mut g = ChunkNonceGenerator::new(&[0xAA; 16], 16);
        let _ = g.next();
        assert_eq!(g.current_count(), 1);
        let _ = g.next();
        assert_eq!(g.current_count(), 2);
    }

    #[test]
    fn chunk_nonce_count_wraps_at_u16_max() {
        let mut g = ChunkNonceGenerator::new(&[0xAA; 16], 16);
        g.count = u16::MAX;
        let _ = g.next();
        assert_eq!(g.current_count(), 0);
    }

    #[test]
    fn chunk_nonce_respects_size() {
        let mut g = ChunkNonceGenerator::new(&[0xAA; 16], 12);
        let n = g.next();
        assert_eq!(n.len(), 12);
    }

    #[test]
    fn shake_parser_roundtrip_encode_decode() {
        let mut parser = ShakeSizeParser::new(&[1, 2, 3, 4]);
        let size = 0x1234u16;
        let mut encoded = [0u8; 2];
        parser.encode_mut(size, &mut encoded);

        let mut parser2 = ShakeSizeParser::new(&[1, 2, 3, 4]);
        let decoded = parser2.decode_mut(&encoded);
        assert_eq!(decoded, size);
    }

    #[test]
    fn shake_parser_different_seeds_produce_different_masks() {
        let mut p1 = ShakeSizeParser::new(&[1, 2, 3]);
        let mut p2 = ShakeSizeParser::new(&[4, 5, 6]);
        let m1 = p1.next_mask_mut();
        let m2 = p2.next_mask_mut();
        assert_ne!(m1, m2);
    }

    #[test]
    fn shake_parser_padding_len_in_range() {
        let mut parser = ShakeSizeParser::new(&[1, 2, 3]);
        for _ in 0..10 {
            let pad = parser.next_padding_len_mut();
            assert!(pad < 64);
        }
    }

    #[test]
    fn plain_parser_roundtrip() {
        let mut out = [0u8; 2];
        PlainChunkSizeParser::encode(0x1234, &mut out);
        assert_eq!(PlainChunkSizeParser::decode(&out), 0x1234);
    }

    #[test]
    fn noop_authenticator_seal_open_roundtrip() {
        let pt = b"hello";
        let sealed = NoOpAuthenticator::seal(pt);
        let opened = NoOpAuthenticator::open(&sealed);
        assert_eq!(pt.as_slice(), opened.as_slice());
        assert_eq!(NoOpAuthenticator::overhead(), 0);
        assert_eq!(NoOpAuthenticator::nonce_size(), 0);
    }

    #[test]
    fn write_address_port_ipv4() {
        let mut out = Vec::new();
        let addr = xray_common::net::address::Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        write_address_port(&mut out, &addr, 8080);
        assert_eq!(out.len(), 7);
        assert_eq!(&out[..2], &8080u16.to_be_bytes());
        assert_eq!(out[2], addr_type::IPV4);
        assert_eq!(&out[3..], &[1, 2, 3, 4]);
    }

    #[test]
    fn write_address_port_domain() {
        let mut out = Vec::new();
        let addr = xray_common::net::address::Address::Domain("example.com".to_string());
        write_address_port(&mut out, &addr, 443);
        assert_eq!(out.len(), 2 + 1 + 1 + 11);
        assert_eq!(out[2], addr_type::DOMAIN);
        assert_eq!(out[3], 11);
    }

    #[test]
    fn read_address_port_ipv4_roundtrip() {
        let mut buf = Vec::new();
        let addr = xray_common::net::address::Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        write_address_port(&mut buf, &addr, 53);
        let (parsed_addr, parsed_port, consumed) = read_address_port(&buf).expect("ok");
        assert_eq!(parsed_port, 53);
        assert_eq!(consumed, buf.len());
        match parsed_addr {
            xray_common::net::address::Address::IPv4(v4) => assert_eq!(v4.octets(), [8, 8, 8, 8]),
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn read_address_port_domain_roundtrip() {
        let mut buf = Vec::new();
        let addr = xray_common::net::address::Address::Domain("test.org".to_string());
        write_address_port(&mut buf, &addr, 443);
        let (parsed_addr, parsed_port, _) = read_address_port(&buf).expect("ok");
        assert_eq!(parsed_port, 443);
        match parsed_addr {
            xray_common::net::address::Address::Domain(d) => assert_eq!(d, "test.org"),
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn read_address_port_short_buffer_fails() {
        let buf = [0u8; 2];
        let err = read_address_port(&buf).unwrap_err();
        assert!(matches!(err, crate::error::VmessError::InsufficientLength));
    }

    #[test]
    fn read_address_port_unknown_type_fails() {
        let buf = [0, 0, 99, 0, 0];
        let err = read_address_port(&buf).unwrap_err();
        assert!(matches!(err, crate::error::VmessError::InvalidRemoteAddress));
    }
}
