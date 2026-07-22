//! # DNS wire format 编解码（对应 Go `xdns/dns.go`）
//!
//! RFC 1035 实现：Name 压缩指针解析、Message 完整结构、TXT RData 编解码。
//! 字节级匹配 Go 版本（包括错误返回语义、压缩指针上限等）。

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};

// ============================================================================
// 常量（对应 Go dns.go 中的 const 块）
// ============================================================================

/// 压缩指针最大跟随次数（防无限循环）。
const COMPRESSION_POINTER_LIMIT: u8 = 10;

// RR 类型（https://tools.ietf.org/html/rfc1035#section-3.2.2 等）
pub const RR_TYPE_A: u16 = 1;
#[allow(dead_code)] // DNS 协议标准常量（RFC 1035），保留作协议参考
pub const RR_TYPE_CNAME: u16 = 5;
pub const RR_TYPE_TXT: u16 = 16;
pub const RR_TYPE_AAAA: u16 = 28;
pub const RR_TYPE_OPT: u16 = 41;

// Class
pub const CLASS_IN: u16 = 1;

// Rcode
pub const RCODE_NO_ERROR: u16 = 0;
pub const RCODE_FORMAT_ERROR: u16 = 1;
pub const RCODE_NAME_ERROR: u16 = 3;
pub const RCODE_NOT_IMPLEMENTED: u16 = 4;
pub const EXTENDED_RCODE_BAD_VERS: u16 = 16;

// ============================================================================
// Name
// ============================================================================

/// 域名：一系列标签（每个 ≤63 字节）。
///
/// 对应 Go `type Name [][]byte`。空 Vec 表示根域名 "."。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Name {
    pub labels: Vec<Vec<u8>>,
}

impl Name {
    /// 从标签切片构造，校验每片非空、≤63 字节、整体编码 ≤255 字节。
    ///
    /// 对应 Go `NewName`。
    pub fn new(labels: Vec<Vec<u8>>) -> io::Result<Self> {
        for label in &labels {
            if label.is_empty() {
                return Err(invalid_data("name contains a zero-length label"));
            }
            if label.len() > 63 {
                return Err(invalid_data("name contains a label longer than 63 octets"));
            }
        }
        // 检查总长：每 label 一个长度字节 + 数据 + 末尾 0 字节
        let mut total: usize = 1;
        for label in &labels {
            total += 1 + label.len();
        }
        if total > 255 {
            return Err(invalid_data("name is longer than 255 octets"));
        }
        Ok(Self { labels })
    }

    /// 从点号分隔的字符串解析（末尾单个点被忽略）。
    ///
    /// 对应 Go `ParseName`。
    pub fn parse(s: &str) -> io::Result<Self> {
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        if trimmed.is_empty() {
            return Self::new(Vec::new());
        }
        let labels: Vec<Vec<u8>> = trimmed.split('.').map(|p| p.as_bytes().to_vec()).collect();
        Self::new(labels)
    }

    /// 可逆的字符串表示：标签以点连接，非 `[0-9A-Za-z-]` 字节用 `\xXX` 转义。
    /// 空 Name 返回 "."。
    ///
    /// 对应 Go `Name.String`。
    pub fn to_string_repr(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        let mut buf = String::new();
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                buf.push('.');
            }
            for &b in label {
                if b == b'-' || b.is_ascii_alphanumeric() {
                    buf.push(b as char);
                } else {
                    buf.push_str(&format!("\\x{b:02x}"));
                }
            }
        }
        buf
    }

    /// 去除后缀（大小写不敏感），返回 `(前缀, 是否匹配)`。
    /// 未匹配时返回 `(空 Name, false)`。
    ///
    /// 对应 Go `Name.TrimSuffix`。
    pub fn trim_suffix(&self, suffix: &Self) -> (Self, bool) {
        if self.labels.len() < suffix.labels.len() {
            return (Self::default(), false);
        }
        let split = self.labels.len() - suffix.labels.len();
        for i in 0..suffix.labels.len() {
            if !eq_ascii_ci(&self.labels[split + i], &suffix.labels[i]) {
                return (Self::default(), false);
            }
        }
        let fore = self.labels[..split].to_vec();
        (Self { labels: fore }, true)
    }
}

/// 大小写不敏感字节比较。
fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b)
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

// ============================================================================
// Message / Question / RR
// ============================================================================

/// DNS 消息（header + 4 个段）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub question: Vec<Question>,
    pub answer: Vec<RR>,
    pub authority: Vec<RR>,
    pub additional: Vec<RR>,
}

impl Message {
    /// 提取 Flags 的 OPCODE 字段（bits 11-14）。
    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0xf
    }

    /// 提取 Flags 的 RCODE 字段（低 4 位）。
    pub fn rcode(&self) -> u16 {
        self.flags & 0x000f
    }

    /// 编码为 DNS wire format 字节。
    ///
    /// 对应 Go `Message.WireFormat`。
    pub fn wire_format(&self) -> io::Result<Vec<u8>> {
        let mut builder = MessageBuilder::new();
        builder.write_message(self)?;
        Ok(builder.bytes())
    }
}

/// Question 段条目。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

/// 资源记录。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RR {
    pub name: Name,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

// ============================================================================
// wire format 解析（读）
// ============================================================================

/// 从字节解析完整 DNS 消息。若 buf 末尾仍有剩余字节返回 `ErrTrailingBytes`。
///
/// 对应 Go `MessageFromWireFormat`。
pub fn message_from_wire_format(buf: &[u8]) -> io::Result<Message> {
    let mut cursor = io::Cursor::new(buf);
    let message = match read_message(&mut cursor) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
        Err(e) => return Err(e),
    };
    // 检查 trailing bytes：能再读一个字节则报错
    let mut trailing = [0u8; 1];
    match cursor.read(&mut trailing) {
        Ok(0) => Ok(message),
        Ok(_) => Err(invalid_data("trailing bytes after message")),
        Err(e) => Err(e),
    }
}

/// 从 reader 读取并构造 Message。
///
/// 对应 Go `readMessage`。
fn read_message<R: Read + Seek>(r: &mut R) -> io::Result<Message> {
    let mut message = Message::default();

    // Header section
    let mut header = [0u8; 12];
    r.read_exact(&mut header)?;
    message.id = u16::from_be_bytes([header[0], header[1]]);
    message.flags = u16::from_be_bytes([header[2], header[3]]);
    let qd_count = u16::from_be_bytes([header[4], header[5]]);
    let an_count = u16::from_be_bytes([header[6], header[7]]);
    let ns_count = u16::from_be_bytes([header[8], header[9]]);
    let ar_count = u16::from_be_bytes([header[10], header[11]]);

    // Question section
    for _ in 0..qd_count {
        message.question.push(read_question(r)?);
    }
    // Answer / Authority / Additional
    for _ in 0..an_count {
        message.answer.push(read_rr(r)?);
    }
    for _ in 0..ns_count {
        message.authority.push(read_rr(r)?);
    }
    for _ in 0..ar_count {
        message.additional.push(read_rr(r)?);
    }
    Ok(message)
}

/// 读取 Question 段一条。
///
/// 对应 Go `readQuestion`。
fn read_question<R: Read + Seek>(r: &mut R) -> io::Result<Question> {
    let name = read_name(r)?;
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(Question {
        name,
        qtype: u16::from_be_bytes([buf[0], buf[1]]),
        qclass: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// 读取 RR 一条。
///
/// 对应 Go `readRR`。
fn read_rr<R: Read + Seek>(r: &mut R) -> io::Result<RR> {
    let name = read_name(r)?;
    let mut head = [0u8; 8];
    r.read_exact(&mut head)?;
    let rtype = u16::from_be_bytes([head[0], head[1]]);
    let rclass = u16::from_be_bytes([head[2], head[3]]);
    let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let mut rd_len_buf = [0u8; 2];
    r.read_exact(&mut rd_len_buf)?;
    let rd_length = u16::from_be_bytes(rd_len_buf) as usize;
    let mut data = vec![0u8; rd_length];
    r.read_exact(&mut data)?;
    Ok(RR {
        name,
        rtype,
        rclass,
        ttl,
        data,
    })
}

/// 读取 Name，支持压缩指针（0xC0 前缀）。
///
/// 对应 Go `readName`。最多跟随 10 个压缩指针。
pub(crate) fn read_name<R: Read + Seek>(r: &mut R) -> io::Result<Name> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut num_pointers = 0u8;
    let mut seek_to: Option<u64> = None;

    loop {
        let mut label_type_buf = [0u8; 1];
        if r.read_exact(&mut label_type_buf).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof reading name",
            ));
        }
        let label_type = label_type_buf[0];

        match label_type & 0xc0 {
            0x00 => {
                // 普通 label
                let length = (label_type & 0x3f) as usize;
                if length == 0 {
                    break;
                }
                let mut label = vec![0u8; length];
                r.read_exact(&mut label)?;
                labels.push(label);
            }
            0xc0 => {
                // 压缩指针
                let mut lower = [0u8; 1];
                r.read_exact(&mut lower)?;
                let upper = label_type & 0x3f;
                let offset = (u16::from(upper) << 8) | u16::from(lower[0]);

                if num_pointers == 0 {
                    // 记录当前游标位置以便后续恢复
                    seek_to = Some(r.stream_position()?);
                }
                num_pointers += 1;
                if num_pointers > COMPRESSION_POINTER_LIMIT {
                    return Err(invalid_data("too many compression pointers"));
                }
                r.seek(SeekFrom::Start(u64::from(offset)))?;
            }
            _ => {
                return Err(invalid_data("reserved label type"));
            }
        }
    }

    // 若跟随过压缩指针，恢复到第一个指针之后
    if num_pointers > 0 {
        if let Some(pos) = seek_to {
            r.seek(SeekFrom::Start(pos))?;
        }
    }
    Name::new(labels)
}

// ============================================================================
// wire format 序列化（写）
// ============================================================================

/// 序列化器：维护已写 Name 的缓存以支持压缩指针。
///
/// 对应 Go `messageBuilder`。
pub(crate) struct MessageBuilder {
    w: Vec<u8>,
    name_cache: HashMap<String, usize>,
}

impl MessageBuilder {
    pub(crate) fn new() -> Self {
        Self {
            w: Vec::new(),
            name_cache: HashMap::new(),
        }
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.w.clone()
    }

    /// 写一个 Name，必要时使用压缩指针（指向之前写过的同 suffix）。
    pub(crate) fn write_name(&mut self, name: &Name) {
        for i in 0..name.labels.len() {
            // 检查从 i 开始的 suffix 是否已缓存
            let suffix = suffix_str(name, i);
            if let Some(&ptr) = self.name_cache.get(&suffix) {
                if ptr & 0x3fff == ptr {
                    self.w.push(0xc0 | ((ptr >> 8) as u8));
                    self.w.push((ptr & 0xff) as u8);
                    return;
                }
            }
            // 未缓存：写完整 label 并记录位置
            let pos = self.w.len();
            self.name_cache.insert(suffix, pos);
            let label = &name.labels[i];
            let length = label.len();
            self.w.push(length as u8);
            self.w.extend_from_slice(label);
        }
        self.w.push(0);
    }

    /// 写一个 Question 段条目。
    pub(crate) fn write_question(&mut self, q: &Question) {
        self.write_name(&q.name);
        self.w.extend_from_slice(&q.qtype.to_be_bytes());
        self.w.extend_from_slice(&q.qclass.to_be_bytes());
    }

    /// 写一个 RR。
    pub(crate) fn write_rr(&mut self, rr: &RR) -> io::Result<()> {
        self.write_name(&rr.name);
        self.w.extend_from_slice(&rr.rtype.to_be_bytes());
        self.w.extend_from_slice(&rr.rclass.to_be_bytes());
        self.w.extend_from_slice(&rr.ttl.to_be_bytes());
        let rd_length = u16::try_from(rr.data.len())
            .map_err(|_| invalid_data("integer overflow"))?;
        self.w.extend_from_slice(&rd_length.to_be_bytes());
        self.w.extend_from_slice(&rr.data);
        Ok(())
    }

    /// 写完整 Message。
    pub(crate) fn write_message(&mut self, m: &Message) -> io::Result<()> {
        // Header
        self.w.extend_from_slice(&m.id.to_be_bytes());
        self.w.extend_from_slice(&m.flags.to_be_bytes());
        for count in [m.question.len(), m.answer.len(), m.authority.len(), m.additional.len()] {
            let c16 = u16::try_from(count)
                .map_err(|_| invalid_data("integer overflow"))?;
            self.w.extend_from_slice(&c16.to_be_bytes());
        }
        // Question
        for q in &m.question {
            self.write_question(q);
        }
        // Answer / Authority / Additional
        for rr in m.answer.iter().chain(m.authority.iter()).chain(m.additional.iter()) {
            self.write_rr(rr)?;
        }
        Ok(())
    }
}

/// 构造从 index i 开始的 suffix 字符串（用于 name_cache key，避免分配 Name 子切片）。
fn suffix_str(name: &Name, i: usize) -> String {
    if i >= name.labels.len() {
        return ".".to_string();
    }
    let mut buf = String::new();
    for (j, label) in name.labels[i..].iter().enumerate() {
        if j > 0 {
            buf.push('.');
        }
        for &b in label {
            if b == b'-' || b.is_ascii_alphanumeric() {
                buf.push(b as char);
            } else {
                buf.push_str(&format!("\\x{b:02x}"));
            }
        }
    }
    buf
}

// ============================================================================
// TXT RData 编解码
// ============================================================================

/// 解码 TXT RDATA：串联多个 `<length><bytes>` 字符串。
///
/// 对应 Go `DecodeRDataTXT`。
pub fn decode_rdata_txt(mut p: &[u8]) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        if p.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof in TXT rdata",
            ));
        }
        let n = p[0] as usize;
        p = &p[1..];
        if p.len() < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof in TXT rdata",
            ));
        }
        buf.extend_from_slice(&p[..n]);
        p = &p[n..];
        if p.is_empty() {
            break;
        }
    }
    Ok(buf)
}

/// 编码为 TXT RDATA：每 255 字节一段，至少输出一段（哪怕空）。
///
/// 对应 Go `EncodeRDataTXT`。
pub fn encode_rdata_txt(mut p: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    while p.len() > 255 {
        buf.push(255);
        buf.extend_from_slice(&p[..255]);
        p = &p[255..];
    }
    // 即使 p 为空也必须写一段（"one or more character-strings"）
    buf.push(p.len() as u8);
    buf.extend_from_slice(p);
    buf
}

// ============================================================================
// Helpers
// ============================================================================

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn lbl(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    #[test]
    fn new_name_validates_labels() {
        // 空标签报错
        assert!(Name::new(vec![lbl(b"a"), lbl(b""), lbl(b"c")]).is_err());
        // 超长标签（64 字节）报错
        let long = lbl(b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF");
        assert_eq!(long.len(), 64);
        assert!(Name::new(vec![long]).is_err());
        // 63 字节 OK
        let ok63 = lbl(b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE");
        assert_eq!(ok63.len(), 63);
        assert!(Name::new(vec![ok63]).is_ok());
    }

    #[test]
    fn parse_name_roundtrip() {
        // 空字符串 → 空 labels
        let n = Name::parse("").unwrap();
        assert!(n.labels.is_empty());
        // 单 dot → 空 labels
        let n = Name::parse(".").unwrap();
        assert!(n.labels.is_empty());
        // 简单域名
        let n = Name::parse("example.com").unwrap();
        assert_eq!(n.labels, vec![lbl(b"example"), lbl(b"com")]);
        // 末尾 dot
        let n = Name::parse("example.com.").unwrap();
        assert_eq!(n.labels, vec![lbl(b"example"), lbl(b"com")]);
    }

    #[test]
    fn name_string_repr_handles_escape() {
        // 空名 → "."
        assert_eq!(Name::default().to_string_repr(), ".");
        // 简单名
        let n = Name::new(vec![lbl(b"a"), lbl(b"b"), lbl(b"c")]).unwrap();
        assert_eq!(n.to_string_repr(), "a.b.c");
        // 含特殊字节 → \xXX 转义
        let n = Name::new(vec![lbl(b"\x00"), lbl(b"a.b")]).unwrap();
        assert_eq!(n.to_string_repr(), "\\x00.a\\x2eb");
    }

    #[test]
    fn name_trim_suffix_case_insensitive() {
        let n = Name::parse("example.com").unwrap();
        let s = Name::parse("COM").unwrap();
        let (fore, ok) = n.trim_suffix(&s);
        assert!(ok);
        assert_eq!(fore.labels, vec![lbl(b"example")]);

        // 不匹配
        let s = Name::parse("net").unwrap();
        let n = Name::parse("example.com").unwrap();
        let (_, ok) = n.trim_suffix(&s);
        assert!(!ok);

        // 整体匹配 → 空 fore
        let n = Name::parse("example.com").unwrap();
        let s = Name::parse("example.com").unwrap();
        let (fore, ok) = n.trim_suffix(&s);
        assert!(ok);
        assert!(fore.labels.is_empty());
    }

    #[test]
    fn read_name_with_compression_pointer() {
        // 构造一条带压缩指针的 wire bytes：
        // offset 0-8: 0x07 + "example" + 0x00 （普通 label）
        // offset 9-10: 0xc0 0x00 （压缩指针，指向 offset 0）
        let mut buf: Vec<u8> = Vec::new();
        buf.push(7);
        buf.extend_from_slice(b"example");
        buf.push(0);
        buf.push(0xc0);
        buf.push(0x00);
        let mut cursor = io::Cursor::new(&buf[..]);
        // 从 offset 9 起读 Name
        cursor.set_position(9);
        let name = read_name(&mut cursor).unwrap();
        assert_eq!(name.labels, vec![lbl(b"example")]);
        // 跟随过指针后游标应回到指针字节之后（offset 11）
        assert_eq!(cursor.position(), 11);
    }

    #[test]
    fn message_wire_format_roundtrip() {
        let msg = Message {
            id: 0x1234,
            flags: 0x8000,
            question: vec![Question {
                name: Name::parse("example.com").unwrap(),
                qtype: RR_TYPE_A,
                qclass: CLASS_IN,
            }],
            answer: vec![RR {
                name: Name::parse("example.com").unwrap(),
                rtype: RR_TYPE_A,
                rclass: CLASS_IN,
                ttl: 60,
                data: vec![1, 2, 3, 4],
            }],
            authority: vec![],
            additional: vec![],
        };
        let wire = msg.wire_format().unwrap();
        let parsed = message_from_wire_format(&wire).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn message_from_wire_format_trailing_bytes_err() {
        let msg = Message {
            id: 1,
            flags: 0,
            question: vec![],
            answer: vec![],
            authority: vec![],
            additional: vec![],
        };
        let mut wire = msg.wire_format().unwrap();
        wire.push(0xff); // 多余字节
        assert!(message_from_wire_format(&wire).is_err());
    }

    #[test]
    fn rdata_txt_roundtrip() {
        // 空数据：编码为单段 0 长度，解码为空
        let enc = encode_rdata_txt(&[]);
        assert_eq!(enc, vec![0]);
        let dec = decode_rdata_txt(&enc).unwrap();
        assert!(dec.is_empty());

        // 短数据
        let data = b"hello world";
        let enc = encode_rdata_txt(data);
        assert_eq!(enc, vec![11, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd']);
        let dec = decode_rdata_txt(&enc).unwrap();
        assert_eq!(dec, data);

        // 长数据：300 字节 → 255 + 45
        let big: Vec<u8> = (0..300).map(|i| (i & 0xff) as u8).collect();
        let enc = encode_rdata_txt(&big);
        let dec = decode_rdata_txt(&enc).unwrap();
        assert_eq!(dec, big);
    }

    #[test]
    fn rdata_txt_decode_truncated_errors() {
        // 只有长度字节
        assert!(decode_rdata_txt(&[3]).is_err());
        // 长度声明 5 但只给 2
        assert!(decode_rdata_txt(&[5, b'a', b'b']).is_err());
    }

    #[test]
    fn read_message_basic_query() {
        // 构造一个简单的 DNS 查询：example.com A IN
        let msg = Message {
            id: 0xabcd,
            flags: 0x0100, // RD=1
            question: vec![Question {
                name: Name::parse("example.com").unwrap(),
                qtype: RR_TYPE_A,
                qclass: CLASS_IN,
            }],
            answer: vec![],
            authority: vec![],
            additional: vec![],
        };
        let wire = msg.wire_format().unwrap();
        let parsed = message_from_wire_format(&wire).unwrap();
        assert_eq!(parsed.id, 0xabcd);
        assert_eq!(parsed.flags, 0x0100);
        assert_eq!(parsed.question.len(), 1);
        assert_eq!(parsed.question[0].qtype, RR_TYPE_A);
        assert_eq!(parsed.question[0].name.labels, vec![lbl(b"example"), lbl(b"com")]);
    }

    #[test]
    fn opcode_and_rcode_extraction() {
        let m = Message {
            flags: 0x8180, // QR=1 OPCODE=0 RD=1 RA=1 RCODE=0
            ..Message::default()
        };
        assert_eq!(m.opcode(), 0);
        assert_eq!(m.rcode(), 0);

        let m = Message {
            flags: 0xF983, // QR=1 OPCODE=15 RD=1 RA=1 RCODE=3
            ..Message::default()
        };
        assert_eq!(m.opcode(), 15);
        assert_eq!(m.rcode(), 3);
    }

    #[test]
    fn name_too_long_validates() {
        // 4 个 64 字节标签 → 总长超 255
        let big = lbl(b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF");
        assert!(big.len() == 64);
        assert!(Name::new(vec![big]).is_err()); // 单个 64 已 >63
    }

    #[test]
    fn compression_pointer_loop_detected() {
        // 构造一个无限循环的压缩指针：0xc0 0x00 指向自己
        let buf = vec![0xc0, 0x00];
        let mut cursor = io::Cursor::new(&buf[..]);
        let result = read_name(&mut cursor);
        // 应该在第 11 个指针时报错（COMPRESSION_POINTER_LIMIT=10）
        assert!(result.is_err());
    }
}
