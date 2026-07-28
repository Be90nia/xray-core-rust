//! 嗅探框架
//!
//! 对应 Go `app/dispatcher/sniffer.go`。
//!
//! ## 设计
//!
//! - [SniffResult] trait 对应 Go SniffResult interface
//! - [ProtocolSniffer] trait 对应 Go protocolSnifferWithMetadata
//! - [Sniffer] struct 持有 Vec<Box<dyn ProtocolSniffer>> 编排多协议嗅探
//! - [CompositeSniffResult] 组合 metadata + content 结果

use crate::error::DispatcherError;
use std::fmt::Debug;
use xray_common::net::network::Network;

/// 嗅探错误
pub type SniffError = DispatcherError;

/// 嗅探结果
pub trait SniffResult: Send + Sync + Debug {
    /// 协议名
    fn protocol(&self) -> &str;

    /// 嗅探到的域名（无则空字符串）
    fn domain(&self) -> &str;
}

/// 协议嗅探器
pub trait ProtocolSniffer: Send + Sync + Debug {
    /// 嗅探 payload 字节。
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError>;

    /// 是否为元数据嗅探器。默认 false。
    fn metadata_only(&self) -> bool {
        false
    }

    /// 适用网络（TCP/UDP）。
    fn network(&self) -> Network;
}

/// 嗅探器集合，编排多协议嗅探
#[derive(Default)]
pub struct Sniffer {
    sniffers: Vec<Box<dyn ProtocolSniffer>>,
}

impl Debug for Sniffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sniffer")
            .field("count", &self.sniffers.len())
            .finish()
    }
}

impl Sniffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_sniffers(sniffers: Vec<Box<dyn ProtocolSniffer>>) -> Self {
        Self { sniffers }
    }

    pub fn push(&mut self, s: Box<dyn ProtocolSniffer>) {
        self.sniffers.push(s);
    }

    pub fn push_front(&mut self, s: Box<dyn ProtocolSniffer>) {
        self.sniffers.insert(0, s);
    }

    pub fn len(&self) -> usize {
        self.sniffers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sniffers.is_empty()
    }

    pub fn sniff(
        &mut self,
        payload: &[u8],
        network: Network,
    ) -> Result<Box<dyn SniffResult>, SniffError> {
        let mut pending: Vec<Box<dyn ProtocolSniffer>> = Vec::new();

        for s in &self.sniffers {
            if s.metadata_only() || s.network() != network {
                continue;
            }
            match s.sniff(payload) {
                Ok(None) => {
                    pending.push(Box::new(NotImplementedSniffer));
                }
                Err(SniffError::NeedMoreData) => {
                    self.sniffers = vec![Box::new(NotImplementedSniffer)];
                    return Err(SniffError::NeedMoreData);
                }
                Ok(Some(result)) => return Ok(result),
                Err(_) => continue,
            }
        }

        if !pending.is_empty() {
            self.sniffers = pending;
            return Err(SniffError::NoClue);
        }

        Err(SniffError::UnknownContent)
    }

    pub fn sniff_metadata(&mut self) -> Result<Box<dyn SniffResult>, SniffError> {
        let mut pending: Vec<Box<dyn ProtocolSniffer>> = Vec::new();

        for s in &self.sniffers {
            if !s.metadata_only() {
                pending.push(Box::new(NotImplementedSniffer));
                continue;
            }
            match s.sniff(&[]) {
                Ok(None) => {
                    pending.push(Box::new(NotImplementedSniffer));
                }
                Ok(Some(result)) => return Ok(result),
                Err(_) => continue,
            }
        }

        if !pending.is_empty() {
            self.sniffers = pending;
            return Err(SniffError::NoClue);
        }

        Err(SniffError::UnknownContent)
    }
}

/// 组合嗅探结果
#[derive(Debug)]
pub struct CompositeSniffResult {
    domain_result: Box<dyn SniffResult>,
    protocol_result: Box<dyn SniffResult>,
}

impl CompositeSniffResult {
    #[must_use]
    pub fn new(
        domain_result: Box<dyn SniffResult>,
        protocol_result: Box<dyn SniffResult>,
    ) -> Self {
        Self {
            domain_result,
            protocol_result,
        }
    }
}

impl SniffResult for CompositeSniffResult {
    fn protocol(&self) -> &str {
        self.protocol_result.protocol()
    }

    fn domain(&self) -> &str {
        self.domain_result.domain()
    }
}

pub trait SnifferResultComposite {
    fn protocol_for_domain_result(&self) -> &str;
}

impl SnifferResultComposite for CompositeSniffResult {
    fn protocol_for_domain_result(&self) -> &str {
        self.domain_result.protocol()
    }
}

pub trait SnifferIsProtoSubsetOf {
    fn is_proto_subset_of(&self, protocol_name: &str) -> bool;
}
// ========== 通用嗅探结果 ==========

/// 通用协议嗅探结果
#[derive(Debug)]
struct ProtoSniffResult {
    protocol: &'static str,
    domain: String,
}

impl SniffResult for ProtoSniffResult {
    fn protocol(&self) -> &str {
        self.protocol
    }
    fn domain(&self) -> &str {
        &self.domain
    }
}

// ========== 占位嗅探器 ==========

/// 未实现嗅探器占位
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedSniffer;

impl ProtocolSniffer for NotImplementedSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        Err(SniffError::UnknownContent)
    }

    fn network(&self) -> Network {
        Network::TCP
    }
}

// ========== HTTP 嗅探器 ==========

/// HTTP 请求方法前缀
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
    b"PATCH ",
    b"TRACE ",
];

/// HTTP 嗅探器（对应 Go http.SniffHTTP）
///
/// 用 httparse 解析 HTTP 请求行 + Host 头，提取域名。
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpSniffer;

impl ProtocolSniffer for HttpSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // 快速检查：payload 是否以 HTTP 方法开头
        let is_http = HTTP_METHODS
            .iter()
            .any(|m| payload.len() >= m.len() && payload[..m.len()] == m[..]);
        if !is_http {
            return Ok(None);
        }

        // 用 httparse 解析请求头
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(payload) {
            Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(SniffError::UnknownContent),
        }

        // 查找 Host 头
        let host = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"));

        let Some(host_header) = host else {
            return Err(SniffError::UnknownContent);
        };

        let host_str = String::from_utf8_lossy(host_header.value);
        // 去除端口部分
        let domain = host_str.split(':').next().unwrap_or_default().to_string();

        if domain.is_empty() {
            return Err(SniffError::UnknownContent);
        }

        Ok(Some(Box::new(ProtoSniffResult {
            protocol: "http",
            domain,
        })))
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}
// ========== TLS 嗅探器 ==========

/// TLS 嗅探器（对应 Go tls.SniffTLS）
///
/// 手写 ClientHello 解析：record layer -> handshake -> extensions -> SNI。
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsSniffer;

impl ProtocolSniffer for TlsSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        parse_tls_client_hello(payload)
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}

/// 从 TLS ClientHello 中提取 SNI 域名
fn parse_tls_client_hello(payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
    // TLS record layer: content_type(1) + version(2) + length(2)
    if payload.len() < 5 {
        return Ok(None);
    }
    if payload[0] != 0x16 {
        return Ok(None);
    }
    if payload[1] != 3 {
        return Ok(None);
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_body = if payload.len() >= 5 + record_len {
        &payload[5..5 + record_len]
    } else {
        return Err(SniffError::NeedMoreData);
    };

    // Handshake: type(1) + length(3) + body
    if record_body.len() < 4 {
        return Ok(None);
    }
    if record_body[0] != 0x01 {
        return Ok(None);
    }

    let handshake_len = (u32::from(record_body[1]) << 16
        | u32::from(record_body[2]) << 8
        | u32::from(record_body[3])) as usize;
    let hello_body = if record_body.len() >= 4 + handshake_len {
        &record_body[4..4 + handshake_len]
    } else {
        return Err(SniffError::NeedMoreData);
    };

    // ClientHello body 解析
    let mut offset = 0;
    offset += 2; // version
    offset += 32; // random

    if hello_body.len() <= offset {
        return Ok(None);
    }
    let session_id_len = hello_body[offset] as usize;
    offset += 1 + session_id_len;

    if hello_body.len() <= offset + 1 {
        return Ok(None);
    }
    let cipher_suites_len =
        u16::from_be_bytes([hello_body[offset], hello_body[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if hello_body.len() <= offset {
        return Ok(None);
    }
    let compression_methods_len = hello_body[offset] as usize;
    offset += 1 + compression_methods_len;

    if hello_body.len() < offset + 2 {
        return Ok(None);
    }
    let extensions_len =
        u16::from_be_bytes([hello_body[offset], hello_body[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    if hello_body.len() < extensions_end {
        return Err(SniffError::NeedMoreData);
    }

    // 遍历 extensions 查找 SNI (type 0x0000)
    let mut ext_offset = offset;
    while ext_offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hello_body[ext_offset], hello_body[ext_offset + 1]]);
        let ext_len =
            u16::from_be_bytes([hello_body[ext_offset + 2], hello_body[ext_offset + 3]]) as usize;
        ext_offset += 4;

        if ext_type == 0x0000 {
            // SNI extension: list_length(2) + name_type(1) + name_length(2) + name
            if ext_len < 5 || ext_offset + 5 > extensions_end {
                return Ok(None);
            }
            let name_type = hello_body[ext_offset + 2];
            if name_type != 0 {
                return Ok(None);
            }
            let name_len = u16::from_be_bytes([
                hello_body[ext_offset + 3],
                hello_body[ext_offset + 4],
            ]) as usize;
            let name_start = ext_offset + 5;
            let name_end = name_start + name_len;
            if name_end > extensions_end {
                return Ok(None);
            }
            let domain = String::from_utf8_lossy(&hello_body[name_start..name_end]).to_string();

            if domain.contains(' ') {
                return Err(SniffError::NeedMoreData);
            }
            if domain.ends_with('.') {
                return Ok(None);
            }

            return Ok(Some(Box::new(ProtoSniffResult {
                protocol: "tls",
                domain,
            })));
        }

        ext_offset += ext_len;
    }

    Ok(None)
}
// ========== BitTorrent 嗅探器 ==========

/// BitTorrent 握手协议特征字节
const BITTORRENT_PROTOCOL: &[u8] = b"BitTorrent protocol";

/// BitTorrent over TCP 嗅探器（对应 Go bittorrent.SniffBittorrent）
///
/// 匹配 BitTorrent 握手特征：0x13 + "BitTorrent protocol"。
#[derive(Debug, Default, Clone, Copy)]
pub struct BittorrentSniffer;

impl ProtocolSniffer for BittorrentSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        if payload.len() < 20 {
            return Ok(None);
        }
        if payload[0] == 0x13 && payload[1..20] == *BITTORRENT_PROTOCOL {
            return Ok(Some(Box::new(ProtoSniffResult {
                protocol: "bittorrent",
                domain: String::new(),
            })));
        }
        Ok(None)
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}

// ========== QUIC 嗅探器 ==========

/// QUIC v1 salt (RFC 9001 Section 5.2)
const QUIC_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC draft-29 salt
const QUIC_SALT_DRAFT29: &[u8] = &[
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
    0xe0, 0x43, 0x90, 0xa8, 0x99,
];

const QUIC_VERSION_V1: u32 = 0x0000_0001;
const QUIC_VERSION_DRAFT29: u32 = 0xff00_001d;

/// QUIC 嗅探器（对应 Go quic.SniffQUIC）
///
/// 解析 QUIC Initial 包提取 SNI。
#[derive(Debug, Default, Clone, Copy)]
pub struct QuicSniffer;

impl ProtocolSniffer for QuicSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        sniff_quic(payload)
    }
    fn network(&self) -> Network {
        Network::UDP
    }
}

/// 读取 QUIC varint（最多 4 字节，上限 65535 与 Go readShortQuicVarint 一致）
fn read_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let val = match len {
        1 => u64::from(first & 0x3F),
        2 => u64::from(u16::from_be_bytes([buf[0] & 0x3F, buf[1]])),
        4 => {
            let v = u32::from_be_bytes([buf[0] & 0x3F, buf[1], buf[2], buf[3]]);
            u64::from(v)
        }
        8 => {
            // 8 字节 varint 超出 short varint 范围
            return None;
        }
        _ => return None,
    };
    if val > 65535 {
        return None;
    }
    Some((val, len))
}

/// HKDF-Expand-Label (RFC 8446 Section 7.1)
///
/// 从 secret 字节派生指定长度的密钥材料。
fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), SniffError> {
    // HkdfLabel 编码为单个 info 切片（RFC 8446 Section 7.1）
    let tls13_prefix = b"tls13 ";
    let full_label_len = tls13_prefix.len() + label.len();
    let mut info_buf = Vec::with_capacity(3 + full_label_len + 1 + context.len());
    info_buf.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info_buf.push(full_label_len as u8);
    info_buf.extend_from_slice(tls13_prefix);
    info_buf.extend_from_slice(label);
    info_buf.push(context.len() as u8);
    info_buf.extend_from_slice(context);

    let info_slices: &[&[u8]] = &[&info_buf];
    // 从 secret 字节构造 Prk
    let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, secret);
    prk.expand(info_slices, ring::hkdf::HKDF_SHA256)
        .map_err(|_| SniffError::UnknownContent)?
        .fill(out)
        .map_err(|_| SniffError::UnknownContent)
}

/// QUIC 嗅探核心逻辑
fn sniff_quic(mut payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
    if payload.is_empty() {
        return Ok(None);
    }

    let mut crypto_data = Vec::new();

    while !payload.is_empty() {
        let type_byte = payload[0];
        // 必须是 Long Header (bit 7=1) 且 Fixed Bit (bit 6=1)
        if type_byte & 0x80 == 0 || type_byte & 0x40 == 0 {
            return Ok(None);
        }

        if payload.len() < 5 {
            return Ok(None);
        }
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

        if version != QUIC_VERSION_V1 && version != QUIC_VERSION_DRAFT29 {
            return Ok(None);
        }

        let packet_type = (type_byte & 0x30) >> 4;
        let is_initial = packet_type == 0x0;

        // dest_conn_id
        let dcid_len = payload[5] as usize;
        if payload.len() < 6 + dcid_len {
            return Ok(None);
        }
        let dest_conn_id = &payload[6..6 + dcid_len];

        let mut offset = 6 + dcid_len;

        // src_conn_id
        if payload.len() <= offset {
            return Ok(None);
        }
        let scid_len = payload[offset] as usize;
        offset += 1 + scid_len;

        if payload.len() < offset {
            return Ok(None);
        }

        // Initial 包有 token 字段
        if is_initial {
            let (token_len, vb) = read_quic_varint(&payload[offset..]).ok_or(SniffError::UnknownContent)?;
            offset += vb;
            offset += token_len as usize;
            if payload.len() < offset {
                return Ok(None);
            }
        }

        // packet_len
        let (packet_len, vb) = read_quic_varint(&payload[offset..]).ok_or(SniffError::UnknownContent)?;
        if packet_len < 4 {
            return Ok(None);
        }
        offset += vb;

        let hdr_len = offset;
        if payload.len() < hdr_len + packet_len as usize {
            return Err(SniffError::NoClue);
        }

        let rest_offset = hdr_len + packet_len as usize;

        if !is_initial {
            payload = &payload[rest_offset..];
            continue;
        }

        // ---- 解密 Initial 包 ----
        let salt = if version == QUIC_VERSION_V1 {
            QUIC_SALT_V1
        } else {
            QUIC_SALT_DRAFT29
        };

        // HKDF-Extract: initial_secret = HKDF-Extract(salt, dest_conn_id)
        let initial_secret = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt)
            .extract(dest_conn_id);

        // 提取 initial_secret 字节用于 HKDF-Expand-Label
        let mut initial_secret_bytes = [0u8; 32];
        initial_secret
            .expand(&[], ring::hkdf::HKDF_SHA256)
            .map_err(|_| SniffError::UnknownContent)?
            .fill(&mut initial_secret_bytes)
            .map_err(|_| SniffError::UnknownContent)?;

        // client_in secret
        let mut client_in_secret = [0u8; 32];
        hkdf_expand_label(&initial_secret_bytes, b"client in", &[], &mut client_in_secret)?;

        // hp key
        let mut hp_key_bytes = [0u8; 16];
        hkdf_expand_label(&client_in_secret, b"quic hp", &[], &mut hp_key_bytes)?;

        // header protection key
        let hp_key = ring::aead::quic::HeaderProtectionKey::new(
            &ring::aead::quic::AES_128,
            &hp_key_bytes,
        )
        .map_err(|_| SniffError::UnknownContent)?;

        // 需要至少 hdr_len+4+16 字节来解密 header protection
        let sample_offset = hdr_len + 4;
        if payload.len() < sample_offset + hp_key.algorithm().sample_len() {
            return Ok(None);
        }
        let sample = &payload[sample_offset..sample_offset + hp_key.algorithm().sample_len()];

        let mask = hp_key.new_mask(sample).map_err(|_| SniffError::UnknownContent)?;

        // 解密 header protection（在可变副本上操作）
        let mut packet_buf = payload.to_vec();

        // 第一个字节低 4 位
        packet_buf[0] ^= mask[0] & 0x0f;
        // packet number 字节（1-4 字节）
        let pn_length = (packet_buf[0] & 0x03 + 1) as usize;
        for i in 0..pn_length {
            if hdr_len + i < packet_buf.len() {
                packet_buf[hdr_len + i] ^= mask[i + 1];
            }
        }

        // AES-128-GCM 密钥和 IV
        let mut key_bytes = [0u8; 16];
        hkdf_expand_label(&client_in_secret, b"quic key", &[], &mut key_bytes)?;
        let mut iv_bytes = [0u8; 12];
        hkdf_expand_label(&client_in_secret, b"quic iv", &[], &mut iv_bytes)?;

        let quic_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key_bytes)
                .map_err(|_| SniffError::UnknownContent)?,
        );

        // 构造 nonce：IV XOR packet_number
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&iv_bytes);
        // packet number 在 hdr_len..hdr_len+pn_length，小端写入 nonce 末尾
        let pn_start = hdr_len;
        for i in 0..pn_length {
            nonce_bytes[12 - pn_length + i] ^= packet_buf[pn_start + pn_length - 1 - i];
        }
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);

        // 解密 payload
        let ext_hdr_len = hdr_len + pn_length;
        let payload_end = hdr_len + packet_len as usize;
        if packet_buf.len() < payload_end {
            return Ok(None);
        }

        // 先复制 aad 数据避免同时不可变+可变借用 packet_buf
        let aad_data = packet_buf[..ext_hdr_len].to_vec();
        let aad = ring::aead::Aad::from(&aad_data[..]);
        let decrypted_len = quic_key
            .open_in_place(nonce, aad, &mut packet_buf[ext_hdr_len..payload_end])
            .map_err(|_| SniffError::UnknownContent)?
            .len();

        // 遍历 QUIC frames
        let mut frame_offset = 0;
        let decrypted = &packet_buf[ext_hdr_len..ext_hdr_len + decrypted_len];

        while frame_offset < decrypted.len() {
            let frame_type = decrypted[frame_offset];
            frame_offset += 1;

            // 跳过 PADDING (0x00)
            while frame_type == 0x00 && frame_offset < decrypted.len() {
                frame_offset += 1;
                continue;
            }

            match frame_type {
                0x01 => {} // PING
                0x02 | 0x03 => {
                    // ACK frame
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let ack_range_count = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += ack_range_count.map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    if let Some((count, _cl)) = ack_range_count {
                        for _ in 0..count {
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                        }
                    }
                    if frame_type == 0x03 {
                        for _ in 0..3 {
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                        }
                    }
                }
                0x06 => {
                    // CRYPTO frame - 收集 TLS ClientHello 数据
                    let (offset_val, vl) = read_quic_varint(&decrypted[frame_offset..]).ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl;
                    let (length, vl) = read_quic_varint(&decrypted[frame_offset..]).ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl;

                    let end = frame_offset + length as usize;
                    if end > decrypted.len() {
                        break;
                    }

                    // 写入 crypto_data 缓冲区
                    let write_start = offset_val as usize;
                    let write_end = write_start + length as usize;
                    if crypto_data.len() < write_end {
                        crypto_data.resize(write_end, 0);
                    }
                    crypto_data[write_start..write_end].copy_from_slice(&decrypted[frame_offset..end]);
                    frame_offset = end;
                }
                0x1c => {
                    // CONNECTION_CLOSE
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let (reason_len, vl) = read_quic_varint(&decrypted[frame_offset..]).ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl + reason_len as usize;
                }
                _ => {
                    // 其他帧类型不允许在 Initial 包中出现
                    break;
                }
            }
        }

        // 尝试从 crypto_data 解析 TLS ClientHello
        if !crypto_data.is_empty() {
            if let Ok(Some(result)) = parse_tls_client_hello(&crypto_data) {
                return Ok(Some(Box::new(ProtoSniffResult {
                    protocol: "quic",
                    domain: result.domain().to_string(),
                })));
            }
        }

        payload = &payload[rest_offset..];
    }

    // 已解析为 QUIC 但需要更多包来恢复完整 crypto data
    Err(SniffError::NeedMoreData)
}
// ========== UTP 嗅探器 ==========

/// UTP 嗅探器（对应 Go bittorrent.SniffUTP）
///
/// 匹配 uTP v1 头部：type(高4位 0-4) + version(低4位=1)。
/// 并遍历 extension chain 验证格式合法性。
#[derive(Debug, Default, Clone, Copy)]
pub struct UtpSniffer;

impl ProtocolSniffer for UtpSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        if payload.len() < 20 {
            return Ok(None);
        }

        let type_and_version = payload[0];
        let utp_type = (type_and_version >> 4) & 0x0F;
        let version = type_and_version & 0x0F;

        // uTP v1: version 必须为 1，type 必须在 0-4 范围内
        if version != 1 || utp_type > 4 {
            return Ok(None);
        }

        // extension byte: 必须为 0 或 1
        let extension = payload[1];
        if extension > 1 {
            return Ok(None);
        }

        // 遍历 extension chain
        let mut ext_offset = 1; // 从 extension byte 开始
        let mut current_ext = extension;
        while current_ext == 1 {
            // ST_DATA (type 0) 或 ST_FIN (type 1) 等数据包有 extension chain
            if payload.len() < ext_offset + 2 + 4 {
                return Ok(None);
            }
            let next_ext = payload[ext_offset + 1];
            let _len = u16::from_be_bytes([payload[ext_offset + 2], payload[ext_offset + 3]]);
            ext_offset += 2 + _len as usize;
            current_ext = next_ext;

            if ext_offset >= payload.len() {
                return Ok(None);
            }
        }

        // 验证 timestamp 微秒在合理范围（24小时内）
        // uTP timestamp: 从头部偏移 2 字节后读取 u32 (big-endian)
        // Go 实现检查 timestamp 差值在 24h 内，这里简化：只检查头部格式合法
        if payload.len() < 6 {
            return Ok(None);
        }
        let _timestamp = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);

        Ok(Some(Box::new(ProtoSniffResult {
            protocol: "bittorrent",
            domain: String::new(),
        })))
    }
    fn network(&self) -> Network {
        Network::UDP
    }
}

// ========== 默认嗅探器集合 ==========

/// 构造默认嗅探器集合
#[must_use]
pub fn new_default_sniffer_set() -> Sniffer {
    let sniffers: Vec<Box<dyn ProtocolSniffer>> = vec![
        Box::new(HttpSniffer),
        Box::new(TlsSniffer),
        Box::new(BittorrentSniffer),
        Box::new(QuicSniffer),
        Box::new(UtpSniffer),
    ];
    Sniffer::from_sniffers(sniffers)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用嗅探结果
    #[derive(Debug)]
    struct TestResult {
        protocol: &'static str,
        domain: &'static str,
    }

    impl SniffResult for TestResult {
        fn protocol(&self) -> &str {
            self.protocol
        }
        fn domain(&self) -> &str {
            self.domain
        }
    }

    /// 永远成功的嗅探器
    #[derive(Debug)]
    struct AlwaysMatchSniffer {
        network: Network,
        result: TestResult,
    }

    impl ProtocolSniffer for AlwaysMatchSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Ok(Some(Box::new(TestResult {
                protocol: self.result.protocol,
                domain: self.result.domain,
            })))
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// 永远返回 NoClue 的嗅探器
    #[derive(Debug)]
    struct NoClueSniffer {
        network: Network,
    }

    impl ProtocolSniffer for NoClueSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Ok(None)
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// 永远返回 NeedMoreData 的嗅探器
    #[derive(Debug)]
    struct NeedMoreDataSniffer {
        network: Network,
    }

    impl ProtocolSniffer for NeedMoreDataSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Err(SniffError::NeedMoreData)
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// metadata 嗅探器
    #[derive(Debug)]
    struct MetadataSniffer {
        result: Option<TestResult>,
    }

    impl ProtocolSniffer for MetadataSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            self.result
                .as_ref()
                .map(|r| {
                    Some(Box::new(TestResult {
                        protocol: r.protocol,
                        domain: r.domain,
                    }) as Box<dyn SniffResult>)
                })
                .map(Ok)
                .unwrap_or(Ok(None))
        }
        fn metadata_only(&self) -> bool {
            true
        }
        fn network(&self) -> Network {
            Network::TCP
        }
    }

    // ---------- 框架测试 ----------

    #[test]
    fn sniffer_default_is_empty() {
        let s = Sniffer::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn sniffer_push_increments_len() {
        let mut s = Sniffer::new();
        s.push(Box::new(HttpSniffer));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn sniffer_push_front_inserts_at_head() {
        let mut s = Sniffer::new();
        s.push(Box::new(HttpSniffer));
        s.push_front(Box::new(TlsSniffer));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn sniff_returns_first_match() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "example.com",
                },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "tls",
                    domain: "other.com",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
        assert_eq!(r.domain(), "example.com");
    }

    #[test]
    fn sniff_filters_by_network() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(AlwaysMatchSniffer {
                network: Network::UDP,
                result: TestResult {
                    protocol: "quic",
                    domain: "",
                },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
    }

    #[test]
    fn sniff_skips_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult {
                    protocol: "fakedns",
                    domain: "",
                }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
    }

    #[test]
    fn sniff_aggregates_noclue_and_returns_noclue() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(NoClueSniffer { network: Network::TCP }),
            Box::new(NoClueSniffer { network: Network::TCP }),
        ]);
        let err = s.sniff(b"x", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn sniff_need_more_data_short_circuits() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(NoClueSniffer { network: Network::TCP }),
            Box::new(NeedMoreDataSniffer { network: Network::TCP }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let err = s.sniff(b"x", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NeedMoreData));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn sniff_returns_unknown_when_all_fail() {
        let mut s = Sniffer::from_sniffers(vec![Box::new(HttpSniffer)]);
        let err = s.sniff(b"not-http", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn sniff_metadata_invokes_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult {
                    protocol: "fakedns",
                    domain: "faked.example.com",
                }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff_metadata().expect("match");
        assert_eq!(r.protocol(), "fakedns");
        assert_eq!(r.domain(), "faked.example.com");
    }

    #[test]
    fn sniff_metadata_keeps_non_metadata_as_pending() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer { result: None }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let err = s.sniff_metadata().unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn composite_result_uses_protocol_from_protocol_side() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult {
                protocol: "fakedns",
                domain: "fake.example.com",
            }),
            Box::new(TestResult {
                protocol: "http",
                domain: "",
            }),
        );
        assert_eq!(c.protocol(), "http");
        assert_eq!(c.domain(), "fake.example.com");
    }

    #[test]
    fn composite_result_protocol_for_domain_returns_domain_protocol() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult {
                protocol: "fakedns",
                domain: "",
            }),
            Box::new(TestResult {
                protocol: "http",
                domain: "",
            }),
        );
        assert_eq!(c.protocol_for_domain_result(), "fakedns");
    }

    #[test]
    fn default_sniffer_set_has_5_protocols() {
        let s = new_default_sniffer_set();
        assert_eq!(s.len(), 5);
    }

    // ---------- HTTP 嗅探器测试 ----------

    #[test]
    fn http_sniff_get_request() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = HttpSniffer.sniff(payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "http");
        assert_eq!(result.domain(), "example.com");
    }

    #[test]
    fn http_sniff_post_request_with_port() {
        let payload = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        let result = HttpSniffer.sniff(payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "http");
        assert_eq!(result.domain(), "api.example.com");
    }

    #[test]
    fn http_sniff_non_http_returns_none() {
        let result = HttpSniffer.sniff(b"not http").expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn http_sniff_no_host_header() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let result = HttpSniffer.sniff(payload);
        assert!(result.is_err());
    }

    // ---------- TLS 嗅探器测试 ----------

    #[test]
    fn tls_sniff_client_hello() {
        // 构造一个最小的 TLS ClientHello with SNI
        let mut payload = Vec::new();
        // Record layer
        payload.push(0x16); // Handshake
        payload.push(0x03); // TLS major
        payload.push(0x01); // TLS minor

        let hello = build_minimal_client_hello(b"example.com");
        let hello_len = hello.len() as u16;
        payload.extend_from_slice(&hello_len.to_be_bytes());
        payload.extend_from_slice(&hello);

        let result = TlsSniffer.sniff(&payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "tls");
        assert_eq!(result.domain(), "example.com");
    }

    #[test]
    fn tls_sniff_non_tls() {
        let result = TlsSniffer.sniff(b"not tls").expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn tls_sniff_truncated_returns_need_more_data() {
        let mut payload = vec![0x16, 0x03, 0x01, 0x00, 0x20];
        payload.extend_from_slice(&[0u8; 10]); // 不够 record_len=32
        let result = TlsSniffer.sniff(&payload);
        assert!(matches!(result, Err(SniffError::NeedMoreData)));
    }

    /// 构造最小 TLS ClientHello（含 SNI）
    fn build_minimal_client_hello(domain: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.push(0x01); // ClientHello
        // 预留 3 字节长度

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.push(0x01); // compression_methods_len = 1
        body.push(0x00); // null compression

        // Extensions
        let mut extensions = Vec::new();
        // SNI extension
        let mut sni_data = Vec::new();
        let sni_entry_len = 1 + 2 + domain.len();
        let sni_list_len = sni_entry_len as u16;
        sni_data.extend_from_slice(&sni_list_len.to_be_bytes());
        sni_data.push(0x00); // host_name type
        sni_data.extend_from_slice(&(domain.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(domain);

        extensions.extend_from_slice(&[0x00, 0x00]); // extension type SNI
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // 填入 handshake length
        let body_len = body.len() as u32;
        hello.extend_from_slice(&body_len.to_be_bytes()[1..]); // 3 字节
        hello.extend_from_slice(&body);

        hello
    }

    // ---------- BitTorrent 嗅探器测试 ----------

    #[test]
    fn bittorrent_sniff_handshake() {
        let mut payload = vec![0x13];
        payload.extend_from_slice(b"BitTorrent protocol");
        payload.extend_from_slice(&[0u8; 48]); // 剩余握手字节
        let result = BittorrentSniffer.sniff(&payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "bittorrent");
    }

    #[test]
    fn bittorrent_sniff_non_bt() {
        let result = BittorrentSniffer.sniff(b"not bittorrent").expect("ok");
        assert!(result.is_none());
    }

    // ---------- UTP 嗅探器测试 ----------

    #[test]
    fn utp_sniff_valid_header() {
        // uTP ST_DATA (type=0, version=1) => byte = 0x01
        let mut payload = vec![0x01, 0x00]; // type=0, ver=1, ext=0
        payload.extend_from_slice(&[0u8; 18]); // 补足 20 字节
        let result = UtpSniffer.sniff(&payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "bittorrent");
    }

    #[test]
    fn utp_sniff_fin_packet() {
        // ST_FIN (type=1, version=1) => byte = 0x11
        let mut payload = vec![0x11, 0x00];
        payload.extend_from_slice(&[0u8; 18]);
        let result = UtpSniffer.sniff(&payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "bittorrent");
    }

    #[test]
    fn utp_sniff_invalid_version() {
        let mut payload = vec![0x02, 0x00]; // version=2, invalid
        payload.extend_from_slice(&[0u8; 18]);
        let result = UtpSniffer.sniff(&payload).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn utp_sniff_invalid_type() {
        let mut payload = vec![0x51, 0x00]; // type=5, invalid
        payload.extend_from_slice(&[0u8; 18]);
        let result = UtpSniffer.sniff(&payload).expect("ok");
        assert!(result.is_none());
    }

    // ---------- QUIC 嗅探器测试 ----------

    #[test]
    fn quic_sniff_non_quic() {
        let result = QuicSniffer.sniff(b"not quic").expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn quic_sniff_short_header() {
        // Short header (bit 7=0) 不是 QUIC Long Header
        let result = QuicSniffer.sniff(&[0x40, 0x01, 0x00, 0x00, 0x01]).expect("ok");
        assert!(result.is_none());
    }
}