//! 嗅探框架
//!
//! 对应 Go `app/dispatcher/sniffer.go`。
//!
//! ## 设计
//!
//! - [SniffResult] trait 对应 Go SniffResult interface
//! - [ProtocolSniffer] trait 对应 Go protocolSnifferWithMetadata
//! - [`Sniffer`] struct 持有 `Vec<Box<dyn ProtocolSniffer>>` 编排多协议嗅探
//! - [CompositeSniffResult] 组合 metadata + content 结果

use std::fmt::Debug;

use xray_common::net::network::Network;

use crate::error::DispatcherError;

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
        f.debug_struct("Sniffer").field("count", &self.sniffers.len()).finish()
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
        let mut pending: Vec<usize> = Vec::new();
        let mut hit: Option<Box<dyn SniffResult>> = None;
        let mut need_more = false;

        for (i, s) in self.sniffers.iter().enumerate() {
            if s.metadata_only() || s.network() != network {
                continue;
            }
            match s.sniff(payload) {
                Ok(Some(result)) => {
                    hit = Some(result);
                    break;
                },
                // 非本协议（Go result==nil && err==nil）：本轮跳过，不保留
                Ok(None) => {},
                Err(SniffError::NoClue) => {
                    // 无定论：可能后续分段命中，保留待重试（Go sniffer.go:67-69）
                    pending.push(i);
                },
                Err(SniffError::NeedMoreData) => {
                    // 协议命中但需更多数据：集合收缩到该探测器（Go sniffer.go:70-72）
                    pending = vec![i];
                    need_more = true;
                    break;
                },
                Err(_) => {},
            }
        }

        if hit.is_none() {
            Self::retain_at(&mut self.sniffers, &pending);
        }

        if let Some(result) = hit {
            return Ok(result);
        }
        if need_more {
            return Err(SniffError::NeedMoreData);
        }
        if !pending.is_empty() {
            return Err(SniffError::NoClue);
        }
        Err(SniffError::UnknownContent)
    }

    pub fn sniff_metadata(&mut self) -> Result<Box<dyn SniffResult>, SniffError> {
        let mut pending: Vec<usize> = Vec::new();
        let mut hit: Option<Box<dyn SniffResult>> = None;

        for (i, s) in self.sniffers.iter().enumerate() {
            if !s.metadata_only() {
                // 非 metadata 嗅探器保留给后续内容嗅探（Go sniffer.go:92-94）
                pending.push(i);
                continue;
            }
            match s.sniff(&[]) {
                Ok(Some(result)) => {
                    hit = Some(result);
                    break;
                },
                Err(SniffError::NoClue) => pending.push(i),
                _ => {},
            }
        }

        if hit.is_none() {
            Self::retain_at(&mut self.sniffers, &pending);
        }

        if let Some(result) = hit {
            return Ok(result);
        }
        if !pending.is_empty() {
            return Err(SniffError::NoClue);
        }
        Err(SniffError::UnknownContent)
    }

    /// 按 pending 索引收缩探测器集合（Go sniffer.go:71,81）：pending 始终是
    /// 真实探测器（索引升序，nth 跳过的中间项随迭代器丢弃）。
    fn retain_at(sniffers: &mut Vec<Box<dyn ProtocolSniffer>>, indices: &[usize]) {
        let mut it = std::mem::take(sniffers).into_iter();
        *sniffers = indices.iter().filter_map(|&i| it.nth(i)).collect();
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
    pub fn new(domain_result: Box<dyn SniffResult>, protocol_result: Box<dyn SniffResult>) -> Self {
        Self { domain_result, protocol_result }
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

// ========== HTTP 嗅探器 ==========

/// HTTP 请求方法（Go http/sniff.go:42：小写、无尾空格；匹配大小写不敏感）
const HTTP_METHODS: &[&str] = &["get", "post", "head", "put", "delete", "options", "connect"];

/// HTTP 嗅探器（对应 Go http.SniffHTTP）
///
/// 用 httparse 解析 HTTP 请求行 + Host 头，提取域名。
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpSniffer;

impl ProtocolSniffer for HttpSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // Go beginWithHTTPMethod（http/sniff.go:47-59）：大小写不敏感前缀匹配；
        // payload 短于方法名 → ErrNoClue（请求行可能分段到达，无定论）
        let mut is_http = false;
        for m in HTTP_METHODS {
            let mb = m.as_bytes();
            if payload.len() < mb.len() {
                return Err(SniffError::NoClue);
            }
            if payload[..mb.len()].eq_ignore_ascii_case(mb) {
                is_http = true;
                break;
            }
        }
        if !is_http {
            return Ok(None);
        }

        // 用 httparse 解析请求头（va51②：64 头容量，Go 全量扫描无上限，
        // 16 头定长数组在现代浏览器请求规模下 TooManyHeaders 即放弃）
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(payload) {
            Ok(httparse::Status::Complete(_)) => {},
            // 头未到齐 / 畸形：Go 逐行扫描找不到 Host 即 ErrNoClue（可重试）
            Ok(httparse::Status::Partial) | Err(_) => return Err(SniffError::NoClue),
        }

        // ny1g：Host 头未到达 ≠ 放弃（Go http/sniff.go:116 Host 缺失即 ErrNoClue）
        let host = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("host"));
        let Some(host_header) = host else {
            return Err(SniffError::NoClue);
        };

        let host_str = String::from_utf8_lossy(host_header.value);
        // va51③：Go ParseHost → net.SplitHostPort 括号感知（IPv6 字面量）
        let Some(domain) = parse_host_header(host_str.trim()) else {
            return Err(SniffError::UnknownContent);
        };

        if domain.is_empty() {
            return Err(SniffError::UnknownContent);
        }

        Ok(Some(Box::new(ProtoSniffResult {
            // va51⑤：Go SniffHeader.Protocol HTTP1 → "http1"
            protocol: "http1",
            domain,
        })))
    }

    fn network(&self) -> Network {
        Network::TCP
    }
}

/// 按 Go `net.SplitHostPort` + `ParseHost`（headers.go:66-84）语义拆 Host 头。
///
/// 括号感知：`[2001:db8::1]:443` → `2001:db8::1`；无端口视作"missing port"容错
/// （host 原样保留）；非数字端口 / 多冒号（无括号）→ Go 硬错 → 返回 None。
fn parse_host_header(host: &str) -> Option<String> {
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let domain = &rest[..end];
        match rest[end + 1..].strip_prefix(':') {
            // 空端口等价 missing port（Go SplitHostPort 允许，ParseHost 用默认端口）
            Some(port) if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) => {
                return None;
            },
            _ => {},
        }
        Some(domain.to_string())
    } else {
        match host.rsplit_once(':') {
            None => Some(host.to_string()),
            Some((h, port)) if port.is_empty() || port.bytes().all(|b| b.is_ascii_digit()) => {
                Some(h.to_string())
            },
            // 非数字端口（Go strconv.Atoi 失败）或伪 IPv6 多冒号（Go too many colons）
            Some(_) => None,
        }
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
///
/// `payload` 须包含完整 TLS record layer（content_type + version + length）。
fn parse_tls_client_hello(payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
    // TLS record layer: content_type(1) + version(2) + length(2)
    // ny1g：首读 <5B 无法判定是否 TLS → ErrNoClue（Go tls/sniff.go:132-134），可重试
    if payload.len() < 5 {
        return Err(SniffError::NoClue);
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

    parse_client_hello_from_handshake(record_body)
}

/// 从 TLS handshake 消息（type(1) + length(3) + body，**不含** record layer）解析 ClientHello SNI。
///
/// TLS-over-TCP 的 record layer 由 [`parse_tls_client_hello`] 剥离；
/// QUIC 的 CRYPTO 帧直接承载 handshake 消息（无 record layer），故 QUIC 嗅探器直接调用本函数。
fn parse_client_hello_from_handshake(
    handshake: &[u8],
) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
    // Handshake: type(1) + length(3) + body
    if handshake.len() < 4 {
        // ny1g：截断无定论 → ErrNoClue（Go ReadClientHello len<42 同类）
        return Err(SniffError::NoClue);
    }
    if handshake[0] != 0x01 {
        return Ok(None);
    }

    let handshake_len = (u32::from(handshake[1]) << 16
        | u32::from(handshake[2]) << 8
        | u32::from(handshake[3])) as usize;
    let hello_body = if handshake.len() >= 4 + handshake_len {
        &handshake[4..4 + handshake_len]
    } else {
        return Err(SniffError::NeedMoreData);
    };

    // ClientHello body 解析
    let mut offset = 0;
    offset += 2; // version
    offset += 32; // random

    if hello_body.len() <= offset {
        // ny1g：截断 → ErrNoClue（Go ReadClientHello 截断同类）
        return Err(SniffError::NoClue);
    }
    let session_id_len = hello_body[offset] as usize;
    offset += 1 + session_id_len;

    if hello_body.len() <= offset + 1 {
        return Err(SniffError::NoClue);
    }
    let cipher_suites_len =
        u16::from_be_bytes([hello_body[offset], hello_body[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if hello_body.len() <= offset {
        return Err(SniffError::NoClue);
    }
    let compression_methods_len = hello_body[offset] as usize;
    offset += 1 + compression_methods_len;

    if hello_body.len() < offset + 2 {
        return Err(SniffError::NoClue);
    }
    let extensions_len = u16::from_be_bytes([hello_body[offset], hello_body[offset + 1]]) as usize;
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
            // SNI extension: server_name_list = list_length(2) + entry*
            // entry = name_type(1) + name_length(2) + name
            if ext_len < 2 || ext_offset + ext_len > extensions_end {
                return Ok(None);
            }
            // va51⑥：逐条目容错（Go tls/sniff.go:93-123）——首个 host_name
            // 条目取值，非 host_name 条目跳过继续
            let mut d = &hello_body[ext_offset + 2..ext_offset + ext_len];
            while !d.is_empty() {
                if d.len() < 3 {
                    return Ok(None);
                }
                let name_type = d[0];
                let name_len = u16::from_be_bytes([d[1], d[2]]) as usize;
                d = &d[3..];
                if d.len() < name_len {
                    return Ok(None);
                }
                if name_type == 0 {
                    let name = &d[..name_len];
                    // va51⑥：名字含控制字符/空格 → QUIC 分段可能未到齐，
                    // 重试（Go tls/sniff.go:104-111 b <= ' ' → NeedMoreData）
                    if name.iter().any(|&b| b <= b' ') {
                        return Err(SniffError::NeedMoreData);
                    }
                    // RFC 6066 §3：SNI 不得带尾点（Go errNotClientHello，永久放弃）
                    if name.last() == Some(&b'.') {
                        return Ok(None);
                    }
                    return Ok(Some(Box::new(ProtoSniffResult {
                        protocol: "tls",
                        domain: String::from_utf8_lossy(name).to_string(),
                    })));
                }
                d = &d[name_len..];
            }
            return Ok(None);
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

/// QUIC 版本规格（Go `quicVersionSpec`，common/protocol/quic/sniff.go:35-40）
struct QuicVersionSpec {
    ver: u32,
    /// Initial 包的 packet type 期望值（`(type_byte & 0x30) >> 4`）
    type_initial: u8,
    initial_salt: &'static [u8; 20],
    /// HP/key/iv 派生标签前缀（v1/draft29 用 "quic"，v2 用 "quicv2"，sniff.go:155-158）
    label_prefix: &'static [u8],
}

/// QUIC v1 salt (RFC 9001 Section 5.2)
const QUIC_V1: QuicVersionSpec = QuicVersionSpec {
    ver: 0x0000_0001,
    type_initial: 0b00,
    initial_salt: &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    label_prefix: b"quic",
};

/// QUIC draft-29 salt
const QUIC_DRAFT29: QuicVersionSpec = QuicVersionSpec {
    ver: 0xff00_001d,
    type_initial: 0b00,
    initial_salt: &[
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    label_prefix: b"quic",
};

/// QUIC v2（RFC 9369：独立版本号、Initial type=0b01、独立 salt 与 "quicv2" 标签前缀；
/// Go d9c54026 "Sniffing: Support QUICv2"，sniff.go:55-60）
const QUIC_V2: QuicVersionSpec = QuicVersionSpec {
    ver: 0x6b33_43cf,
    type_initial: 0b01,
    initial_salt: &[
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    label_prefix: b"quicv2",
};

/// crypto data 缓冲上限（Go sniff.go:76 `buf.NewWithSize(32767)` 固定容量）
const QUIC_CRYPTO_BUF_MAX: usize = 32767;

fn quic_version_spec(ver: u32) -> Option<&'static QuicVersionSpec> {
    [&QUIC_V1, &QUIC_DRAFT29, &QUIC_V2].into_iter().find(|s| s.ver == ver)
}

/// 拼接版本标签前缀与后缀（" hp"/" key"/" iv"；前缀最长 "quicv2"=6，后缀最长 4，总长 ≤10）
fn versioned_label(prefix: &[u8], suffix: &[u8]) -> ([u8; 10], usize) {
    let mut out = [0u8; 10];
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..prefix.len() + suffix.len()].copy_from_slice(suffix);
    (out, prefix.len() + suffix.len())
}

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
        },
        8 => {
            // 8 字节 varint 超出 short varint 范围
            return None;
        },
        _ => return None,
    };
    if val > 65535 {
        return None;
    }
    Some((val, len))
}

/// HKDF-Expand 输出长度标记（实现 ring::hkdf::KeyType，支持 16/12/32 等任意长度）
struct HkdfLen(usize);

impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
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
    prk.expand(info_slices, HkdfLen(out.len()))
        .map_err(|_| SniffError::UnknownContent)?
        .fill(out)
        .map_err(|_| SniffError::UnknownContent)
}

/// QUIC 嗅探核心逻辑
fn sniff_quic(mut payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
    if payload.is_empty() {
        return Ok(None);
    }

    // Go sniff.go:74-77：单块固定 cryptoDataBuf（32767）跨包复用，帧数据原地写入
    let mut crypto_data = vec![0u8; QUIC_CRYPTO_BUF_MAX];
    let mut crypto_len = 0usize;

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

        let Some(spec) = quic_version_spec(version) else {
            return Ok(None);
        };

        let packet_type = (type_byte & 0x30) >> 4;
        let is_initial = packet_type == spec.type_initial;

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
            let (token_len, vb) =
                read_quic_varint(&payload[offset..]).ok_or(SniffError::UnknownContent)?;
            offset += vb;
            offset += token_len as usize;
            if payload.len() < offset {
                return Ok(None);
            }
        }

        // packet_len
        let (packet_len, vb) =
            read_quic_varint(&payload[offset..]).ok_or(SniffError::UnknownContent)?;
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
        let salt = spec.initial_salt;

        // HKDF-Extract: initial_secret = HMAC-SHA256(salt, dest_conn_id)
        // (RFC 9001 §5.2；ring 不暴露 PRK 原始字节，故用 hmac 手算 extract 得到原始 32 字节 PRK)
        let salt_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
        let mut initial_secret_bytes = [0u8; 32];
        initial_secret_bytes.copy_from_slice(ring::hmac::sign(&salt_key, dest_conn_id).as_ref());

        // client_in secret
        let mut client_in_secret = [0u8; 32];
        hkdf_expand_label(&initial_secret_bytes, b"client in", &[], &mut client_in_secret)?;

        // hp key（v2 用 "quicv2 hp" 标签，Go sniff.go:158）
        let mut hp_key_bytes = [0u8; 16];
        let (hp_label, hp_label_len) = versioned_label(spec.label_prefix, b" hp");
        hkdf_expand_label(&client_in_secret, &hp_label[..hp_label_len], &[], &mut hp_key_bytes)?;

        // header protection key
        let hp_key =
            ring::aead::quic::HeaderProtectionKey::new(&ring::aead::quic::AES_128, &hp_key_bytes)
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
        let pn_length = ((packet_buf[0] & 0x03) + 1) as usize;
        for i in 0..pn_length {
            if hdr_len + i < packet_buf.len() {
                packet_buf[hdr_len + i] ^= mask[i + 1];
            }
        }

        // AES-128-GCM 密钥和 IV（v2 用 "quicv2 key"/"quicv2 iv"，Go sniff.go:175-176）
        let mut key_bytes = [0u8; 16];
        let (key_label, key_label_len) = versioned_label(spec.label_prefix, b" key");
        hkdf_expand_label(&client_in_secret, &key_label[..key_label_len], &[], &mut key_bytes)?;
        let mut iv_bytes = [0u8; 12];
        let (iv_label, iv_label_len) = versioned_label(spec.label_prefix, b" iv");
        hkdf_expand_label(&client_in_secret, &iv_label[..iv_label_len], &[], &mut iv_bytes)?;

        let quic_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key_bytes)
                .map_err(|_| SniffError::UnknownContent)?,
        );

        // 构造 nonce：IV XOR packet_number
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&iv_bytes);
        // packet number 在 hdr_len..hdr_len+pn_length，大端序写入 nonce 末尾（RFC 9001 §5.3）
        let pn_start = hdr_len;
        for i in 0..pn_length {
            nonce_bytes[12 - pn_length + i] ^= packet_buf[pn_start + i];
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

            match frame_type {
                0x00 => continue, // PADDING: 单字节帧，已通过上面的 frame_offset += 1 消耗
                0x01 => {},       // PING
                0x02 | 0x03 => {
                    // ACK frame
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset +=
                        read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset +=
                        read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let ack_range_count = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset += ack_range_count.map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset +=
                        read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    if let Some((count, _cl)) = ack_range_count {
                        for _ in 0..count {
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset +=
                                read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset +=
                                read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                        }
                    }
                    if frame_type == 0x03 {
                        for _ in 0..3 {
                            let _ = read_quic_varint(&decrypted[frame_offset..]);
                            frame_offset +=
                                read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                        }
                    }
                },
                0x06 => {
                    // CRYPTO frame - 收集 TLS ClientHello 数据
                    let (offset_val, vl) = read_quic_varint(&decrypted[frame_offset..])
                        .ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl;
                    let (length, vl) = read_quic_varint(&decrypted[frame_offset..])
                        .ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl;

                    let end = frame_offset + length as usize;
                    if end > decrypted.len() {
                        break;
                    }

                    // 写入固定 crypto_data 缓冲区（Go sniff.go:242-252）
                    let write_start = offset_val as usize;
                    let write_end = write_start + length as usize;
                    if write_end > QUIC_CRYPTO_BUF_MAX {
                        // Go sniff.go:244-246：超出固定容量 → io.ErrShortBuffer，放弃嗅探
                        return Ok(None);
                    }
                    if crypto_len < write_end {
                        crypto_len = write_end;
                    }
                    crypto_data[write_start..write_end]
                        .copy_from_slice(&decrypted[frame_offset..end]);
                    frame_offset = end;
                },
                0x1c => {
                    // CONNECTION_CLOSE
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset +=
                        read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let _ = read_quic_varint(&decrypted[frame_offset..]);
                    frame_offset +=
                        read_quic_varint(&decrypted[frame_offset..]).map_or(0, |(_, l)| l);
                    let (reason_len, vl) = read_quic_varint(&decrypted[frame_offset..])
                        .ok_or(SniffError::UnknownContent)?;
                    frame_offset += vl + reason_len as usize;
                },
                _ => {
                    // 其他帧类型不允许在 Initial 包中出现
                    break;
                },
            }
        }

        // 尝试从 crypto_data 解析 TLS ClientHello
        if crypto_len > 0 {
            if let Ok(Some(result)) = parse_client_hello_from_handshake(&crypto_data[..crypto_len])
            {
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

/// UTP 嗅探器（对应 Go bittorrent.SniffUTP，bittorrent.go:34-81）
///
/// 仅识别 uTP v1 **ST_SYN**（type=4, version=1，`b[0]==0x41`）：
/// timestamp_difference 必须为 0（新连接），extension chain 仅允许
/// selective ack（1，长度 ≥4 且 4 的倍数）与 extension bits（2，长度=8），
/// 且 extension 必须恰好耗尽整个 ST_SYN 载荷。
/// Go 9b373e39 "Sniffer: Fix SniffUTP()"：旧实现放过任意 type/坏 extension。
#[derive(Debug, Default, Clone, Copy)]
pub struct UtpSniffer;

impl ProtocolSniffer for UtpSniffer {
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        if payload.len() < 20 {
            // Go bittorrent.go:35-37：common.ErrNoClue（保留待重试）
            return Err(SniffError::NoClue);
        }

        // type 4 (ST_SYN), version 1（bittorrent.go:39-42）
        if payload[0] != 0x41 {
            return Ok(None);
        }

        // timestamp_difference 在新连接中恒为 0（bittorrent.go:44-47）
        if u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]) != 0 {
            return Ok(None);
        }

        // 遍历 extension chain（bittorrent.go:49-73）
        let mut extension = payload[1];
        let mut offset = 20usize;
        while extension != 0 {
            if payload.len() < offset + 2 {
                return Ok(None);
            }
            let length = payload[offset + 1] as usize;
            match extension {
                1 => {
                    // selective ack
                    if length < 4 || length % 4 != 0 {
                        return Ok(None);
                    }
                },
                2 => {
                    // extension bits：固定 8 字节（µTorrent 在 ST_SYN 发送）
                    if length != 8 {
                        return Ok(None);
                    }
                },
                _ => return Ok(None),
            }
            if payload.len() < offset + 2 + length {
                return Ok(None);
            }
            extension = payload[offset];
            offset += 2 + length;
        }

        // extension 必须恰好耗尽 ST_SYN 载荷（bittorrent.go:75-78）
        if payload.len() != offset {
            return Ok(None);
        }

        Ok(Some(Box::new(ProtoSniffResult { protocol: "bittorrent", domain: String::new() })))
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

    /// 永远返回 Err(NoClue) 的嗅探器（ny1g：无定论进 pending 保留真实探测器）
    #[derive(Debug)]
    struct NoClueSniffer {
        network: Network,
    }

    impl ProtocolSniffer for NoClueSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Err(SniffError::NoClue)
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
                    Some(Box::new(TestResult { protocol: r.protocol, domain: r.domain })
                        as Box<dyn SniffResult>)
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
                result: TestResult { protocol: "http", domain: "example.com" },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult { protocol: "tls", domain: "other.com" },
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
                result: TestResult { protocol: "quic", domain: "" },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult { protocol: "http", domain: "" },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
    }

    #[test]
    fn sniff_skips_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult { protocol: "fakedns", domain: "" }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult { protocol: "http", domain: "" },
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
                result: TestResult { protocol: "http", domain: "" },
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
        // ny1g 新契约：Ok(None)=非本协议直接丢弃，全员无果 → UnknownContent
        assert!(matches!(err, SniffError::UnknownContent));
    }

    /// ny1g：ErrNoClue 进 pending 后收缩保留的是真实探测器，第二轮重试可命中
    /// （旧实现塞 NotImplementedSniffer 死占位，重试架构性不可能成功）
    #[test]
    fn sniff_noclue_pending_keeps_real_sniffer_for_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Debug)]
        struct MatchOnSecondCall {
            network: Network,
            calls: AtomicUsize,
        }
        impl ProtocolSniffer for MatchOnSecondCall {
            fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(SniffError::NoClue);
                }
                Ok(Some(Box::new(TestResult { protocol: "tls", domain: "retry.example.com" })))
            }

            fn network(&self) -> Network {
                self.network
            }
        }

        let delayed = MatchOnSecondCall { network: Network::TCP, calls: AtomicUsize::new(0) };
        let mut s = Sniffer::from_sniffers(vec![Box::new(HttpSniffer), Box::new(delayed)]);
        // 第一轮：HttpSniffer 对非 HTTP payload 丢弃（Ok(None)），delayed 报 NoClue
        let err = s.sniff(b"not-http", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
        assert_eq!(s.len(), 1, "set shrinks to the pending real sniffer");
        // 第二轮：同一探测器（非死占位）正常命中
        let r = s.sniff(b"not-http", Network::TCP).expect("hit");
        assert_eq!(r.domain(), "retry.example.com");
    }

    #[test]
    fn sniff_metadata_invokes_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult { protocol: "fakedns", domain: "faked.example.com" }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult { protocol: "http", domain: "" },
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
                result: TestResult { protocol: "http", domain: "" },
            }),
        ]);
        let err = s.sniff_metadata().unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn composite_result_uses_protocol_from_protocol_side() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult { protocol: "fakedns", domain: "fake.example.com" }),
            Box::new(TestResult { protocol: "http", domain: "" }),
        );
        assert_eq!(c.protocol(), "http");
        assert_eq!(c.domain(), "fake.example.com");
    }

    #[test]
    fn composite_result_protocol_for_domain_returns_domain_protocol() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult { protocol: "fakedns", domain: "" }),
            Box::new(TestResult { protocol: "http", domain: "" }),
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
        // va51⑤：Go SniffHeader.Protocol HTTP1 → "http1"
        assert_eq!(result.protocol(), "http1");
        assert_eq!(result.domain(), "example.com");
    }

    #[test]
    fn http_sniff_post_request_with_port() {
        let payload = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        let result = HttpSniffer.sniff(payload).expect("ok").expect("some");
        assert_eq!(result.protocol(), "http1");
        assert_eq!(result.domain(), "api.example.com");
    }

    /// ny1g：请求行先到、Host 分段在后 → NoClue（可重试），非永久放弃
    #[test]
    fn http_sniff_missing_host_returns_noclue() {
        let result = HttpSniffer.sniff(b"GET / HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(result, SniffError::NoClue));
    }

    /// ny1g：payload 短于方法名（首读 2 字节 "GE"）→ NoClue
    #[test]
    fn http_sniff_short_first_read_returns_noclue() {
        let result = HttpSniffer.sniff(b"GE").unwrap_err();
        assert!(matches!(result, SniffError::NoClue));
    }

    /// va51②：>16 个头不再 TooManyHeaders 放弃
    #[test]
    fn http_sniff_more_than_16_headers() {
        let mut payload = String::from("GET / HTTP/1.1\r\n");
        for i in 0..24 {
            payload.push_str(&format!("X-Pad-{i}: v\r\n"));
        }
        payload.push_str("Host: many.example.com\r\n\r\n");
        let result = HttpSniffer.sniff(payload.as_bytes()).expect("ok").expect("some");
        assert_eq!(result.domain(), "many.example.com");
    }

    /// va51③：IPv6 字面量 Host 括号感知（Go net.SplitHostPort 语义）
    #[test]
    fn http_sniff_ipv6_literal_host() {
        let r = HttpSniffer
            .sniff(b"CONNECT / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n")
            .expect("ok")
            .expect("some");
        assert_eq!(r.domain(), "2001:db8::1");

        let r =
            HttpSniffer.sniff(b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n").expect("ok").expect("some");
        assert_eq!(r.domain(), "::1");
    }

    /// va51③：多冒号伪 IPv6 / 非数字端口 → Go ParseHost 硬错，永久跳过
    #[test]
    fn http_sniff_malformed_host_rejected() {
        let r = HttpSniffer.sniff(b"GET / HTTP/1.1\r\nHost: a:b:c\r\n\r\n").unwrap_err();
        assert!(matches!(r, SniffError::UnknownContent));
        let r =
            HttpSniffer.sniff(b"GET / HTTP/1.1\r\nHost: example.com:notaport\r\n\r\n").unwrap_err();
        assert!(matches!(r, SniffError::UnknownContent));
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

    /// ny1g：TLS 首读 <5B 无法判定 → NoClue（可重试），非 Ok(None) 永久跳过
    #[test]
    fn tls_sniff_short_first_read_returns_noclue() {
        let result = TlsSniffer.sniff(b"\x16\x03").unwrap_err();
        assert!(matches!(result, SniffError::NoClue));
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

    /// va51⑥：首条目非 host_name 时跳过继续，第二个 host_name 条目命中
    #[test]
    fn tls_sniff_sni_skips_non_hostname_entries() {
        let entries: Vec<(u8, &[u8])> = vec![
            (1, b"1.2.3.4"), // name_type=1（非 host_name）
            (0, b"second.example.com"),
        ];
        let result = TlsSniffer
            .sniff(&wrap_record(&build_client_hello_with_sni_entries(&entries)))
            .expect("ok")
            .expect("some");
        assert_eq!(result.domain(), "second.example.com");
    }

    /// va51⑥：SNI 名字含控制字符 → NeedMoreData（QUIC 分段未到齐语义）
    #[test]
    fn tls_sniff_sni_control_char_returns_need_more_data() {
        let entries: Vec<(u8, &[u8])> = vec![(0, b"bad\x00name.example.com")];
        let result = TlsSniffer.sniff(&wrap_record(&build_client_hello_with_sni_entries(&entries)));
        assert!(matches!(result, Err(SniffError::NeedMoreData)));
    }

    /// RFC 6066：尾点 SNI 非法 → 永久放弃（Go errNotClientHello）
    #[test]
    fn tls_sniff_sni_trailing_dot_rejected() {
        let entries: Vec<(u8, &[u8])> = vec![(0, b"dot.example.com.")];
        let result = TlsSniffer
            .sniff(&wrap_record(&build_client_hello_with_sni_entries(&entries)))
            .expect("ok");
        assert!(result.is_none());
    }

    /// TLS record layer 包装（content_type + version + length）
    fn wrap_record(handshake: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x16, 0x03, 0x01];
        payload.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        payload.extend_from_slice(handshake);
        payload
    }

    /// 构造含多条目 SNI extension 的 ClientHello（不含 record layer）
    fn build_client_hello_with_sni_entries(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.push(0x01); // ClientHello

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(0x01); // compression_methods_len = 1
        body.push(0x00); // null compression

        let mut sni_entries = Vec::new();
        for (name_type, name) in entries {
            sni_entries.push(*name_type);
            sni_entries.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni_entries.extend_from_slice(name);
        }
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&(sni_entries.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(&sni_entries);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]); // extension type SNI
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len() as u32;
        hello.extend_from_slice(&body_len.to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
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

    /// 构造 BEP 29 固定 20 字节 uTP 头（Go bittorrent_test.go utpPacket）
    fn utp_packet(packet_type: u8, extension: u8, ts_diff: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = packet_type << 4 | 1;
        b[1] = extension;
        b[2..4].copy_from_slice(&0x4a3f_u16.to_be_bytes()); // connection_id
        b[4..8].copy_from_slice(&0x8c3a91d2_u32.to_be_bytes()); // timestamp_microseconds
        b[8..12].copy_from_slice(&ts_diff.to_be_bytes()); // timestamp_difference
        b[12..16].copy_from_slice(&0x0010_0000_u32.to_be_bytes()); // wnd_size
        b[16..18].copy_from_slice(&0x71ee_u16.to_be_bytes()); // seq_nr
        b[18..20].copy_from_slice(&0x0000_u16.to_be_bytes()); // ack_nr
        b.extend_from_slice(payload);
        b
    }

    /// Go bittorrent_test.go TestSniffUTP 用例表（9b373e39 修复后语义）。
    /// Ok(Some) = 命中；Ok(None) = errNotBittorrent；Err(NoClue) = common.ErrNoClue。
    #[test]
    fn utp_sniff_go_case_table() {
        let wrong_version = {
            let mut p = utp_packet(4, 0, 0, &[]);
            p[0] = 4 << 4 | 2;
            p
        };
        let cases: Vec<(&str, Vec<u8>, usize)> = vec![
            // 2 = Ok(Some) 命中；1 = Ok(None)；0 = Err(NoClue)
            ("syn", utp_packet(4, 0, 0, &[]), 2),
            (
                "syn with selective ack",
                {
                    let mut p = utp_packet(4, 1, 0, &[]);
                    p.extend_from_slice(&[0, 4, 0xff, 0x00, 0xff, 0x00]);
                    p
                },
                2,
            ),
            (
                "syn with extension bits",
                {
                    let mut p = utp_packet(4, 2, 0, &[]);
                    p.extend_from_slice(&[0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
                    p
                },
                2,
            ),
            (
                "extension bits with wrong length",
                {
                    let mut p = utp_packet(4, 2, 0, &[]);
                    p.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
                    p
                },
                1,
            ),
            ("syn with nonzero timestamp_difference", utp_packet(4, 0, 0x1234, &[]), 1),
            ("syn with trailing payload", utp_packet(4, 0, 0, b"x"), 1),
            // txid 0x4100、无 EDNS0：与 uTP 头部撞形的最坏 DNS 查询
            (
                "dns query",
                vec![
                    0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                    b'a', 0x02, b'c', b'o', 0x00, 0x00, 0x01, 0x00, 0x01,
                ],
                1,
            ),
            ("established connection packets", utp_packet(0, 0, 0x5678, b"xyz"), 1),
            ("state", utp_packet(2, 0, 0x5678, &[]), 1),
            ("fin", utp_packet(1, 0, 0x5678, &[]), 1),
            ("wrong version", wrong_version, 1),
            ("unknown packet type", utp_packet(5, 0, 0, &[]), 1),
            ("unknown extension", utp_packet(4, 3, 0, &[]), 1),
            ("extension chain past the datagram", utp_packet(4, 1, 0, &[0, 8, 0xff]), 1),
            (
                "selective ack not in multiples of 4",
                {
                    let mut p = utp_packet(4, 1, 0, &[]);
                    p.extend_from_slice(&[0, 3, 0xff, 0x00, 0xff]);
                    p
                },
                1,
            ),
        ];

        for (name, payload, expect) in cases {
            let result = UtpSniffer.sniff(&payload);
            match expect {
                2 => {
                    let r = result
                        .unwrap_or_else(|_| panic!("{name}: no error"))
                        .unwrap_or_else(|| panic!("{name}: some"));
                    assert_eq!(r.protocol(), "bittorrent", "{name}");
                },
                1 => {
                    assert!(
                        result.unwrap_or_else(|_| panic!("{name}: no error")).is_none(),
                        "{name}"
                    );
                },
                _ => assert!(matches!(result, Err(SniffError::NoClue)), "{name}"),
            }
        }
    }

    #[test]
    fn utp_sniff_shorter_than_header_is_noclue() {
        // Go bittorrent_test.go:53：<20 字节 → common.ErrNoClue
        let payload = &utp_packet(4, 0, 0, &[])[..19];
        assert!(matches!(UtpSniffer.sniff(payload), Err(SniffError::NoClue)));
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
    /// 编码 QUIC varint（与 read_quic_varint 对称，仅用于测试构造数据包）
    fn encode_quic_varint(v: u64) -> Vec<u8> {
        if v < 64 {
            vec![v as u8]
        } else if v < 16384 {
            let mut b = (v as u16).to_be_bytes();
            b[0] |= 0x40;
            b.to_vec()
        } else if v < 1_073_741_824 {
            let mut b = (v as u32).to_be_bytes();
            b[0] |= 0x80;
            b.to_vec()
        } else {
            let mut b = v.to_be_bytes();
            b[0] |= 0xC0;
            b.to_vec()
        }
    }

    /// 测试用 DCID（密钥派生与包头封装必须一致）
    const TEST_DCID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// 按 RFC 9001 §5 派生 Initial 密钥材料（key/iv/hp；v2 用独立 salt 与 "quicv2" 标签）
    fn derive_initial_keys(spec: &'static QuicVersionSpec) -> ([u8; 16], [u8; 12], [u8; 16]) {
        use ring::hmac;

        let salt_key = hmac::Key::new(hmac::HMAC_SHA256, spec.initial_salt);
        let prk = hmac::sign(&salt_key, &TEST_DCID);
        let mut client_in = [0u8; 32];
        hkdf_expand_label(prk.as_ref(), b"client in", &[], &mut client_in).unwrap();
        let (key_label, kl) = versioned_label(spec.label_prefix, b" key");
        let mut key_bytes = [0u8; 16];
        hkdf_expand_label(&client_in, &key_label[..kl], &[], &mut key_bytes).unwrap();
        let (iv_label, il) = versioned_label(spec.label_prefix, b" iv");
        let mut iv_bytes = [0u8; 12];
        hkdf_expand_label(&client_in, &iv_label[..il], &[], &mut iv_bytes).unwrap();
        let (hp_label, hl) = versioned_label(spec.label_prefix, b" hp");
        let mut hp_bytes = [0u8; 16];
        hkdf_expand_label(&client_in, &hp_label[..hl], &[], &mut hp_bytes).unwrap();
        (key_bytes, iv_bytes, hp_bytes)
    }

    /// 构造一个真实可解密的 QUIC Initial 包（含给定 SNI 的 ClientHello）。
    ///
    /// 完整复刻 RFC 9001 §5 的 Initial 密钥派生 + AES-128-GCM 加密 + header protection，
    /// 用于验证 `sniff_quic` 的解密、帧解析与 ClientHello 提取是否与标准客户端互通。
    fn build_quic_initial_packet(spec: &'static QuicVersionSpec, sni: &[u8]) -> Vec<u8> {
        let (key_bytes, iv_bytes, hp_bytes) = derive_initial_keys(spec);

        // ClientHello -> CRYPTO 帧 -> 明文（末尾补 PADDING 至 128 字节）
        let crypto = build_minimal_client_hello(sni);
        let mut crypto_frame = vec![0x06]; // CRYPTO
        crypto_frame.extend_from_slice(&encode_quic_varint(0)); // offset = 0
        crypto_frame.extend_from_slice(&encode_quic_varint(crypto.len() as u64));
        crypto_frame.extend_from_slice(&crypto);
        let mut plaintext = crypto_frame;
        while plaintext.len() < 128 {
            plaintext.push(0x00); // PADDING
        }
        build_quic_initial_from_plaintext(spec, &key_bytes, &iv_bytes, &hp_bytes, &plaintext)
    }

    /// 用给定密钥材料把任意明文封装为可解密的 QUIC Initial 包（加密 + header protection）。
    fn build_quic_initial_from_plaintext(
        spec: &'static QuicVersionSpec,
        key_bytes: &[u8; 16],
        iv_bytes: &[u8; 12],
        hp_bytes: &[u8; 16],
        plaintext: &[u8],
    ) -> Vec<u8> {
        use ring::aead;

        let scid: [u8; 4] = [0xA, 0xB, 0xC, 0xD];
        let pn: u32 = 2; // packet number
        let pn_length: usize = 4;

        // 3. 构造未加掩 header（含 packet number）
        let ciphertext_len = plaintext.len() + 16; // + AEAD tag
        let length_val = (pn_length + ciphertext_len) as u64;
        let mut header = Vec::new();
        header.push(0xC0 | (spec.type_initial << 4) | ((pn_length - 1) as u8 & 0x03)); // Long | type | (pn_len-1)
        header.extend_from_slice(&spec.ver.to_be_bytes());
        header.push(TEST_DCID.len() as u8);
        header.extend_from_slice(&TEST_DCID);
        header.push(scid.len() as u8);
        header.extend_from_slice(&scid);
        header.extend_from_slice(&encode_quic_varint(0)); // token length = 0
        header.extend_from_slice(&encode_quic_varint(length_val));
        header.extend_from_slice(&pn.to_be_bytes()); // packet number (big-endian)
        let hdr_len = header.len();

        // 4. AEAD 加密（AAD = 未加掩 header）
        let key =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes).unwrap());
        let mut nonce_bytes = *iv_bytes;
        let pn_be = pn.to_be_bytes();
        for i in 0..pn_length {
            nonce_bytes[12 - pn_length + i] ^= pn_be[i];
        }
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut packet = header.clone();
        packet.extend_from_slice(plaintext);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(&header[..]), &mut packet[hdr_len..])
            .unwrap();
        packet.extend_from_slice(tag.as_ref());

        // 5. Header protection
        let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, hp_bytes).unwrap();
        // PN 字段位于 header 末尾（helper 的 hdr_len 含 PN）；
        // HP sample 从 PN 偏移 +4 起取（RFC 9001 §5.4.2），与 sniff_quic 内部偏移一致。
        let pn_offset = hdr_len - pn_length;
        let sample_offset = pn_offset + 4;
        let sample = &packet[sample_offset..sample_offset + hp_key.algorithm().sample_len()];
        let mask = hp_key.new_mask(sample).unwrap();
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_length {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn quic_sniff_initial_packet_extracts_sni() {
        let packet = build_quic_initial_packet(&QUIC_V1, b"www.example.com");
        let result = QuicSniffer
            .sniff(&packet)
            .expect("sniff should succeed")
            .expect("should extract a result");
        assert_eq!(result.protocol(), "quic");
        assert_eq!(result.domain(), "www.example.com");
    }

    /// Go TestSniffQUICv2（d9c54026）等价构造：v2 Initial 长头（type=0b01）、
    /// 独立 salt 与 "quicv2" key/iv/hp 标签派生，解密后提取 SNI。
    #[test]
    fn quic_sniff_v2_initial_packet_extracts_sni() {
        let packet = build_quic_initial_packet(&QUIC_V2, b"test.example.com");
        let result = QuicSniffer
            .sniff(&packet)
            .expect("sniff should succeed")
            .expect("should extract a result");
        assert_eq!(result.protocol(), "quic");
        assert_eq!(result.domain(), "test.example.com");
    }

    /// Go sniff.go:244-246：CRYPTO 帧 offset+length 超过固定 cryptoDataBuf
    /// 容量 32767 → io.ErrShortBuffer → 放弃嗅探（Rust 对应 Ok(None)）。
    #[test]
    fn quic_sniff_crypto_offset_exceeds_32767_gives_up() {
        let (key_bytes, iv_bytes, hp_bytes) = derive_initial_keys(&QUIC_V1);

        // CRYPTO 帧：offset=65535（4 字节 varint），length=1 → offset+length=65536 > 32767
        let mut plaintext = vec![0x06];
        plaintext.extend_from_slice(&encode_quic_varint(65535));
        plaintext.extend_from_slice(&encode_quic_varint(1));
        plaintext.push(0x41); // 1 字节 crypto data（长度字段合法，end 不超解密明文）
        while plaintext.len() < 128 {
            plaintext.push(0x00); // PADDING
        }
        let packet = build_quic_initial_from_plaintext(
            &QUIC_V1, &key_bytes, &iv_bytes, &hp_bytes, &plaintext,
        );
        let result = QuicSniffer.sniff(&packet).expect("no hard error");
        assert!(result.is_none(), "crypto offset+length 超限必须放弃嗅探");

        // 对照：同构包 offset=0 不超限 → 不触发放弃路径（ClientHello 不完整 → NeedMoreData）
        let mut plaintext_ok = vec![0x06, 0x00];
        plaintext_ok.extend_from_slice(&encode_quic_varint(1));
        plaintext_ok.push(0x41);
        while plaintext_ok.len() < 128 {
            plaintext_ok.push(0x00);
        }
        let packet_ok = build_quic_initial_from_plaintext(
            &QUIC_V1,
            &key_bytes,
            &iv_bytes,
            &hp_bytes,
            &plaintext_ok,
        );
        assert!(matches!(QuicSniffer.sniff(&packet_ok), Err(SniffError::NeedMoreData)));
    }
}
