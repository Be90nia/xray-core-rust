//! # DNS wire format 编解码（对应 Go `xdns/dns.go`）
//!
//! RFC 1035 实现：Name 压缩指针解析、Message 完整结构、TXT RData 编解码。
//! 字节级匹配 Go 版本（包括错误返回语义、压缩指针上限等）。

use std::{
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom},
    sync::Arc,
};

// ============================================================================
// 常量（对应 Go dns.go 中的 const 块）
// ============================================================================

/// 压缩指针最大跟随次数（防无限循环）。
const COMPRESSION_POINTER_LIMIT: u8 = 10;

// RR 类型（https://tools.ietf.org/html/rfc1035#section-3.2.2 等）
#[allow(dead_code)] // DNS 协议标准常量（RFC 1035），保留作协议参考（xdns 测试与未来服务端特性使用）
pub const RR_TYPE_A: u16 = 1;
#[allow(dead_code)] // DNS 协议标准常量（RFC 1035），保留作协议参考
pub const RR_TYPE_CNAME: u16 = 5;
#[allow(dead_code)] // DNS 协议标准常量（RFC 1035），保留作协议参考（xdns 测试与未来服务端特性使用）
pub const RR_TYPE_TXT: u16 = 16;
#[allow(dead_code)] // DNS 协议标准常量（RFC 1035），保留作协议参考（xdns 测试与未来服务端特性使用）
pub const RR_TYPE_AAAA: u16 = 28;
pub const RR_TYPE_OPT: u16 = 41;

// Class
pub const CLASS_IN: u16 = 1;

// Rcode
pub const RCODE_NO_ERROR: u16 = 0;
pub const RCODE_FORMAT_ERROR: u16 = 1;
pub const RCODE_NAME_ERROR: u16 = 3;
pub const RCODE_NOT_IMPLEMENTED: u16 = 4;
#[allow(dead_code)] // DNS 协议标准常量（RFC 6891 EDNS0），保留作协议参考
pub const EXTENDED_RCODE_BAD_VERS: u16 = 16;

// ============================================================================
// Name
// ============================================================================

/// 域名：一系列标签（每个 ≤63 字节）。
///
/// 对应 Go `type Name [][]byte`。空表示根域名 "."。
///
/// 存储为**未压缩 wire 形态**的紧凑字节（逐 label `1 字节长度 + 内容`，不存末尾
/// 0），并以 `Arc<[u8]>` 共享。Go 侧 `Name{Data [255]byte}` 定长内联、零堆分配；
/// 逐 label `Vec<Vec<u8>>` 则把「2 字节压缩指针 → 255 字节展开」再乘上 label 数
/// （bd rbu2k：4KB 报文 978× 放大 / 8.4 万次分配）。扁平 + `Arc` 让同一报文内
/// 同偏移的展开只分配一次，`clone` 退化为引用计数自增。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    data: Arc<[u8]>,
}

impl Default for Name {
    fn default() -> Self {
        // Arc 无零长特例（空名仍要分配头部）；根域名/空名极少，可接受。
        Self { data: Arc::from(Vec::new()) }
    }
}

/// `Name` 的标签迭代器（`Name` 内部是紧凑 flat，索引用迭代替代 `Vec` 下标）。
pub(crate) struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&len, rest) = self.rest.split_first()?;
        let (label, rest) = rest.split_at(usize::from(len).min(rest.len()));
        self.rest = rest;
        Some(label)
    }
}

impl Name {
    /// 从标签切片构造，校验每片非空、≤63 字节、整体编码 ≤255 字节。
    ///
    /// 对应 Go `NewName`。
    pub fn new(labels: Vec<Vec<u8>>) -> io::Result<Self> {
        let mut flat = [0u8; 255];
        let mut len = 0usize;
        for label in &labels {
            if label.is_empty() {
                return Err(invalid_data("name contains a zero-length label"));
            }
            if label.len() > 63 {
                return Err(invalid_data("name contains a label longer than 63 octets"));
            }
            // 每 label 一个长度字节 + 数据 + 末尾 0 字节
            if len + 1 + label.len() + 1 > 255 {
                return Err(invalid_data("name is longer than 255 octets"));
            }
            flat[len] = label.len() as u8;
            len += 1;
            flat[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        Ok(Self::from_flat(&flat[..len]))
    }

    /// 已是未压缩 wire 形态的 flat 字节（逐 label `len + 数据`，无末尾 0）。
    /// 调用方保证形态合法（`new`/`read_name`/`name_from_wire` 都已校验）。
    pub(crate) fn from_flat(flat: &[u8]) -> Self {
        Self { data: Arc::from(flat) }
    }

    /// 未压缩 wire 形态字节（逐 label `len + 数据`，不含末尾 0）。
    pub(crate) fn flat(&self) -> &[u8] {
        &self.data
    }

    /// wire 长度：flat 字节 + 末尾 0（对齐 Go `Name.Length`）。
    pub(crate) fn wire_len(&self) -> usize {
        self.data.len() + 1
    }

    /// 标签迭代器（按出现顺序）。
    pub(crate) fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.data }
    }

    /// 标签数。
    pub(crate) fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// 第 `i` 个标签（越界返回空片）。
    pub(crate) fn label(&self, i: usize) -> &[u8] {
        self.labels().nth(i).unwrap_or(&[])
    }

    /// 前 `count` 个标签的 flat 前缀。
    fn flat_prefix(&self, count: usize) -> &[u8] {
        let mut pos = 0usize;
        for label in self.labels().take(count) {
            pos += 1 + label.len();
        }
        &self.data[..pos.min(self.data.len())]
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
    #[allow(dead_code)] // RFC1035 codec 完整面（dns 单测覆盖；xdns 旧路径消费）
    pub fn to_string_repr(&self) -> String {
        let mut buf = String::new();
        for (i, label) in self.labels().enumerate() {
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
        if buf.is_empty() {
            return ".".to_string();
        }
        buf
    }

    /// 去除后缀（大小写不敏感），返回 `(前缀, 是否匹配)`。
    /// 未匹配时返回 `(空 Name, false)`。
    ///
    /// 对应 Go `Name.TrimSuffix`。
    #[allow(dead_code)] // RFC1035 codec 完整面（dns 单测覆盖；xdns 旧路径消费）
    pub fn trim_suffix(&self, suffix: &Self) -> (Self, bool) {
        let n = self.label_count();
        let m = suffix.label_count();
        if n < m {
            return (Self::default(), false);
        }
        let split = n - m;
        let mut mine = self.labels().skip(split);
        for theirs in suffix.labels() {
            match mine.next() {
                Some(label) if eq_ascii_ci(label, theirs) => {},
                _ => return (Self::default(), false),
            }
        }
        (Self::from_flat(self.flat_prefix(split)), true)
    }
}

/// 大小写不敏感字节比较。
fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
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
    #[allow(dead_code)] // RFC1035 codec 完整面（dns 单测覆盖）
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

    // 全报文 Name 展开预算：输入长度即本函数可用的展开上界基准
    let mut budget = NameBudget::new(HEADER_LEN + remaining_bytes(r)?);

    // Question section
    reserve_section(&mut message.question, qd_count, remaining_bytes(r)?, MIN_QUESTION_BYTES);
    for _ in 0..qd_count {
        message.question.push(read_question(r, &mut budget)?);
    }
    // Answer / Authority / Additional
    reserve_section(&mut message.answer, an_count, remaining_bytes(r)?, MIN_RR_BYTES);
    for _ in 0..an_count {
        message.answer.push(read_rr(r, &mut budget)?);
    }
    reserve_section(&mut message.authority, ns_count, remaining_bytes(r)?, MIN_RR_BYTES);
    for _ in 0..ns_count {
        message.authority.push(read_rr(r, &mut budget)?);
    }
    reserve_section(&mut message.additional, ar_count, remaining_bytes(r)?, MIN_RR_BYTES);
    for _ in 0..ar_count {
        message.additional.push(read_rr(r, &mut budget)?);
    }
    Ok(message)
}

/// 段预分配：`count` 来自报文头（未认证可控），按 count 直接分配就是「声明即
/// 预约」（bd oavzu 同族）；用剩余字节推出的上界裁一次，count 再大也不先付内存。
fn reserve_section<T>(v: &mut Vec<T>, count: u16, remaining: u64, min_unit: u64) {
    let fits = usize::try_from(remaining / min_unit.max(1)).unwrap_or(usize::MAX);
    v.reserve_exact(usize::from(count).min(fits));
}

/// 读取 Question 段一条。
///
/// 对应 Go `readQuestion`。
fn read_question<R: Read + Seek>(r: &mut R, budget: &mut NameBudget) -> io::Result<Question> {
    let name = read_name(r, budget)?;
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
/// 对应 Go `readRR`。CNAME rdata 归一化为未压缩 wire name（Go dnsmessage
/// 解析嵌套名时会跟随压缩指针；xdns Resp.Decode 依赖该语义）。
fn read_rr<R: Read + Seek>(r: &mut R, budget: &mut NameBudget) -> io::Result<RR> {
    let name = read_name(r, budget)?;
    let mut head = [0u8; 8];
    r.read_exact(&mut head)?;
    let rtype = u16::from_be_bytes([head[0], head[1]]);
    let rclass = u16::from_be_bytes([head[2], head[3]]);
    let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let mut rd_len_buf = [0u8; 2];
    r.read_exact(&mut rd_len_buf)?;
    let rd_length = u16::from_be_bytes(rd_len_buf) as usize;
    // 先按声明长度做边界检查再分配（Go unpack 在拷贝前即校验）：零填充式预分配
    // 会让 25B 报文声称 rd_length=65535 时先付 64KB（未认证远程可达）。
    if rd_length as u64 > remaining_bytes(r)? {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof reading rdata"));
    }
    let mut data = vec![0u8; rd_length];
    r.read_exact(&mut data)?;
    let rr = RR { name, rtype, rclass, ttl, data };
    if rtype != RR_TYPE_CNAME || rd_length == 0 {
        return Ok(rr);
    }
    // 回退到 rdata 起始解嵌套名；失败则保留原始字节（resp 侧跳过）
    let after_data = r.stream_position()?;
    r.seek(SeekFrom::Current(-(rd_length as i64)))?;
    let nested = read_name(r, budget);
    // 无条件复位到 rdata 之后：read_name 只在跟随过压缩指针时复位游标，未压缩的
    // 嵌套名会停在 rdata 中部 ⇒ 成功分支若不复位，后续所有 RR 从错位置读。
    r.seek(SeekFrom::Start(after_data))?;
    match nested {
        Ok(cname) => {
            // 归一化为未压缩 wire name：flat 形态 + 根 0 字节
            let mut norm = cname.flat().to_vec();
            norm.push(0);
            Ok(RR { data: norm, ..rr })
        },
        Err(_) => Ok(rr),
    }
}

/// 当前位置到 reader 末尾的剩余字节数（用完复位游标）。
fn remaining_bytes<R: Read + Seek>(r: &mut R) -> io::Result<u64> {
    let cur = r.stream_position()?;
    let end = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(cur))?;
    Ok(end.saturating_sub(cur))
}

/// 报文头长度（字节）。
const HEADER_LEN: u64 = 12;
/// 一条 question 的最小 wire 长度：名至少 1 字节（根）+ type/class 4 字节。
const MIN_QUESTION_BYTES: u64 = 5;
/// 一条 RR 的最小 wire 长度：名 1 字节 + type/class/ttl/rd_length 10 字节。
const MIN_RR_BYTES: u64 = 11;
/// 全报文未共享的 name 展开总量上界（相对输入字节）。互不相同的名字必须自己出现
/// 在报文里，正常报文远低于此；只有压缩别名构造能逼近。
const MAX_NAME_EXPAND_FACTOR: usize = 8;

/// 全报文 Name 展开预算（bd rbu2k）。
///
/// `read_name` 的单名 255 上界只限「一条名」，多条名共享同一 label run 仍是乘性
/// 放大（4KB 报文实测 978× / 8.4 万次分配）。两道闸：
/// - `cache`：同一偏移的展开结果在报文内共享（wire 解析期不变 ⇒ 同偏移必同结果），
///   命中既不计账也不重新分配——正常报文的 answer 段正是「共用同一个 question 名」。
/// - `left`：未共享展开的字节总量 ≤ [`MAX_NAME_EXPAND_FACTOR`] × 输入字节， 挡住「同一 run
///   换不同入口偏移」这种绕过共享的构造。
struct NameBudget {
    left: usize,
    cache: HashMap<u16, Name>,
}

impl NameBudget {
    fn new(input_len: u64) -> Self {
        let factor = u64::try_from(MAX_NAME_EXPAND_FACTOR).unwrap_or(u64::MAX);
        let left = usize::try_from(input_len.saturating_mul(factor)).unwrap_or(usize::MAX);
        Self { left, cache: HashMap::new() }
    }

    /// 记一次新展开；超额即拒绝（未认证输入）。
    fn charge(&mut self, octets: usize) -> io::Result<()> {
        self.left = self
            .left
            .checked_sub(octets)
            .ok_or_else(|| invalid_data("message name expansion exceeds budget"))?;
        Ok(())
    }
}

/// 读取 Name，支持压缩指针（0xC0 前缀）。
///
/// 对应 Go `readName`。最多跟随 10 个压缩指针。
fn read_name<R: Read + Seek>(r: &mut R, budget: &mut NameBudget) -> io::Result<Name> {
    // 展开结果先落定长栈缓冲（对应 Go `Name.Data [255]byte`）：单名 ≤255 在循环里
    // 就拒绝，故不会溢出，且拒绝发生在任何堆分配之前。
    let mut flat = [0u8; 255];
    let mut len = 0usize;
    let mut num_pointers = 0u8;
    let mut seek_to: Option<u64> = None;
    // 名以指针开头时，整条名等价于该偏移的展开 ⇒ 可缓存复用。
    let mut first_target: Option<u16> = None;

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
                // 过程内拒绝与 Name::new 的接受集合一致（对齐 Go 的 errNameTooLong 时机）
                if len + 1 + length > 255 {
                    return Err(invalid_data("name is longer than 255 octets"));
                }
                flat[len] = label_type;
                len += 1;
                r.read_exact(&mut flat[len..len + length])?;
                len += length;
            },
            0xc0 => {
                // 压缩指针
                let mut lower = [0u8; 1];
                r.read_exact(&mut lower)?;
                let offset = (u16::from(label_type & 0x3f) << 8) | u16::from(lower[0]);

                if num_pointers == 0 {
                    // 记录当前游标位置以便后续恢复
                    seek_to = Some(r.stream_position()?);
                    if len == 0 {
                        first_target = Some(offset);
                    }
                }
                num_pointers += 1;
                if num_pointers > COMPRESSION_POINTER_LIMIT {
                    return Err(invalid_data("too many compression pointers"));
                }
                // 命中共享展开：整条名就是该偏移的展开时直接复用（零分配）；带前缀
                // 时把尾巴拷进栈缓冲，随后只分配一次。
                if let Some(cached) = budget.cache.get(&offset) {
                    let tail = cached.flat();
                    if len + tail.len() > 255 {
                        return Err(invalid_data("name is longer than 255 octets"));
                    }
                    if len == 0 {
                        let name = cached.clone();
                        if let Some(pos) = seek_to {
                            r.seek(SeekFrom::Start(pos))?;
                        }
                        return Ok(name);
                    }
                    flat[len..len + tail.len()].copy_from_slice(tail);
                    len += tail.len();
                    break;
                }
                r.seek(SeekFrom::Start(u64::from(offset)))?;
            },
            _ => {
                return Err(invalid_data("reserved label type"));
            },
        }
    }

    // 若跟随过压缩指针，恢复到第一个指针之后
    if num_pointers > 0 {
        if let Some(pos) = seek_to {
            r.seek(SeekFrom::Start(pos))?;
        }
    }
    // 先记账再分配：超额时一个字节都不分配。（纯缓存命中在上面已提前返回，
    // 走到这里的都是要新组装一条 name 的路径——含「前缀 + 缓存尾巴」。）
    budget.charge(len)?;
    let name = Name::from_flat(&flat[..len]);
    if let Some(offset) = first_target {
        budget.cache.insert(offset, name.clone());
    }
    Ok(name)
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
        Self { w: Vec::new(), name_cache: HashMap::new() }
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.w.clone()
    }

    /// 写一个 Name，必要时使用压缩指针（指向之前写过的同 suffix）。
    pub(crate) fn write_name(&mut self, name: &Name) {
        let count = name.label_count();
        for i in 0..count {
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
            let label = name.label(i);
            self.w.push(label.len() as u8);
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
        let rd_length =
            u16::try_from(rr.data.len()).map_err(|_| invalid_data("integer overflow"))?;
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
            let c16 = u16::try_from(count).map_err(|_| invalid_data("integer overflow"))?;
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
    let mut buf = String::new();
    for (j, label) in name.labels().skip(i).enumerate() {
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
    if buf.is_empty() {
        buf.push('.');
    }
    buf
}

// ============================================================================
// TXT RData 编解码
// ============================================================================

/// 解码 TXT RDATA：串联多个 `<length><bytes>` 字符串。
///
/// 对应 Go `DecodeRDataTXT`。
#[allow(dead_code)] // RFC1035 codec 完整面（dns 单测覆盖；xdns 旧路径消费）
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
#[allow(dead_code)] // RFC1035 codec 完整面（dns 单测覆盖；xdns 旧路径消费）
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

    /// `Name` 的标签列表（扁平表示下用迭代器还原，供断言比对）。
    fn labels_of(n: &Name) -> Vec<Vec<u8>> {
        n.labels().map(<[u8]>::to_vec).collect()
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
        assert_eq!(n.label_count(), 0);
        // 单 dot → 空 labels
        let n = Name::parse(".").unwrap();
        assert_eq!(n.label_count(), 0);
        // 简单域名
        let n = Name::parse("example.com").unwrap();
        assert_eq!(labels_of(&n), vec![lbl(b"example"), lbl(b"com")]);
        // 末尾 dot
        let n = Name::parse("example.com.").unwrap();
        assert_eq!(labels_of(&n), vec![lbl(b"example"), lbl(b"com")]);
        // flat 形态即未压缩 wire name（末尾 0 之前的部分）
        assert_eq!(n.flat(), b"\x07example\x03com");
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
        assert_eq!(labels_of(&fore), vec![lbl(b"example")]);

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
        assert_eq!(fore.label_count(), 0);
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
        let mut budget = NameBudget::new(buf.len() as u64);
        let name = read_name(&mut cursor, &mut budget).unwrap();
        assert_eq!(labels_of(&name), vec![lbl(b"example")]);
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
        assert_eq!(parsed.question[0].name.flat(), b"\x07example\x03com");
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
        let buf = [0xc0, 0x00];
        let mut cursor = io::Cursor::new(&buf[..]);
        let mut budget = NameBudget::new(buf.len() as u64);
        let result = read_name(&mut cursor, &mut budget);
        // 应该在第 11 个指针时报错（COMPRESSION_POINTER_LIMIT=10）
        assert!(result.is_err());
    }

    // ── 加固回归（bd c6z6q / oavzu / a1pfm）──

    fn hdr(qd: u16, an: u16) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        h[0] = 0xab;
        h[1] = 0xcd;
        h[2] = 0x01; // RD
        h[4..6].copy_from_slice(&qd.to_be_bytes());
        h[6..8].copy_from_slice(&an.to_be_bytes());
        h
    }

    /// 一条 RR 的 wire 形态（name 直接给字节，rdata 给未压缩字节）。
    fn rr_wire(name: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(name);
        w.extend_from_slice(&rtype.to_be_bytes());
        w.extend_from_slice(&CLASS_IN.to_be_bytes());
        w.extend_from_slice(&ttl.to_be_bytes());
        w.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        w.extend_from_slice(rdata);
        w
    }

    /// bd c6z6q：压缩指针只限跳数不限累积 ⇒ 2000 个 1 字节 label + 指回报文开头的
    /// 压缩指针（4KB 输入）会重复展开同一区域。累计到 255 就拒绝后分配与峰值均有界
    /// （修复前实测 22018 次分配 / 1.6MB 峰值）。
    #[test]
    fn compression_pointer_amplification_is_bounded() {
        let mut msg = hdr(1, 0);
        for _ in 0..2000 {
            msg.extend_from_slice(&[0x01, b'a']);
        }
        msg.extend_from_slice(&[0xc0, 0x0c]); // 压缩指针 → offset 12（回到报文自身区域）
        msg.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // qtype TXT / qclass IN
        assert_eq!(msg.len(), 4018);

        let (res, c) = alloc_probe::measure(|| message_from_wire_format(&msg));
        let err = res.expect_err("超长 name 必须拒绝，不得返回 Ok");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "name is longer than 255 octets");
        assert!(c.allocs < 500, "allocs={} 未压到有界（上限 500）", c.allocs);
        assert!(c.peak < 64 * 1024, "peak={}B 未压到 64KB 内", c.peak);
    }

    /// qd 段最坏形态：偏移 12 处一条 126 label 的 run，其余 question 只用 2 字节
    /// 压缩指针引用它（每条 question 6 字节 = 指针 2 + qtype/qclass 4）。
    fn shared_run_query(limit: usize) -> (Vec<u8>, u16) {
        let mut m = hdr(0, 0);
        let run = m.len();
        for _ in 0..126 {
            m.extend_from_slice(&[0x01, b'a']);
        }
        m.push(0x00);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // 首条 question 的 qtype/qclass
        let mut qd = 1u16;
        while m.len() + 6 <= limit {
            m.push(0xc0);
            m.push(run as u8);
            m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            qd += 1;
        }
        m[4..6].copy_from_slice(&qd.to_be_bytes());
        (m, qd)
    }

    /// bd rbu2k（NEW-S1）：多条 2 字节压缩名共享**同一** label run —— 单名 255
    /// 上界挡不住「名字条数 × 展开量」的乘性放大（修复前 4091B 报文 978× /
    /// 8.4 万次分配 / 4.6ms）。同偏移的展开只做一次，其余命中共享缓存 ⇒
    /// 分配量与输入同阶。
    #[test]
    fn shared_compression_run_amplification_is_bounded() {
        let (msg, qd) = shared_run_query(4096);
        let (res, c) = alloc_probe::measure(|| message_from_wire_format(&msg));
        let m = res.expect("共享 run 的报文必须解析成功（形态本身合法）");
        assert_eq!(m.question.len(), usize::from(qd));
        assert!(
            c.bytes < 10 * msg.len(),
            "in={}B alloc_bytes={} 放大 {:.1}x 仍超 10x（共享展开未复用）",
            msg.len(),
            c.bytes,
            c.bytes as f64 / msg.len() as f64
        );
        assert!(c.allocs < msg.len() / 4, "allocs={} 未压到输入同阶", c.allocs);
    }

    /// 合法形态不误伤：真实 xdns 响应 = 1 条 question + N 条 answer，answer 名全
    /// 部是同一个 question 名的压缩指针（展开量可达输入的数倍至十几倍）。共享缓存
    /// 让它们零重复分配，且不计入展开预算。
    #[test]
    fn shared_answer_names_stay_cheap() {
        let mut msg = hdr(1, 0);
        let name_at = msg.len();
        for _ in 0..3 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(61); // 3×64 + 62 = 254 flat 字节 ⇒ wire 255
        msg.extend_from_slice(&[b'a'; 61]);
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let mut an = 0u16;
        while msg.len() + 12 <= 4096 {
            msg.push(0xc0);
            msg.push(name_at as u8);
            msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00]);
            an += 1;
        }
        msg[6..8].copy_from_slice(&an.to_be_bytes());

        let (res, c) = alloc_probe::measure(|| message_from_wire_format(&msg));
        let m = res.expect("合法报文必须解析（预算只计未共享的展开）");
        assert_eq!(m.answer.len(), usize::from(an));
        assert!(
            c.bytes < 8 * msg.len(),
            "in={}B alloc_bytes={}：共享名仍在逐条重复分配",
            msg.len(),
            c.bytes
        );
    }

    /// 绕过共享缓存的形态：每条名 = 1 字节 label + 指向共享 run 的指针（首条
    /// question 内联 run 建立缓存后，每条 8 字节线上换 254 字节展开）。共享命中
    /// 只省重读、不省组装 ⇒ 由全报文预算拒绝。
    #[test]
    fn prefixed_pointer_names_are_budget_bounded() {
        // 首条 question 的名就是内联的 run（与 qd 段最坏形态同布局），其后每条
        // question = [1B label][2B 指针][qtype/qclass]。
        let mut msg = hdr(0, 0);
        let run = msg.len() as u8;
        for _ in 0..126 {
            msg.extend_from_slice(&[0x01, b'a']);
        }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // 首条 question 的 qtype/qclass
        let mut qd = 1u16;
        while msg.len() + 8 <= 4096 {
            msg.push(0x01);
            msg.push(b'x'); // 前缀 label
            msg.push(0xc0);
            msg.push(run);
            msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            qd += 1;
        }
        msg[4..6].copy_from_slice(&qd.to_be_bytes());

        let (res, c) = alloc_probe::measure(|| message_from_wire_format(&msg));
        let err = res.expect_err("前缀 + 共享尾巴的乘性放大必须被预算拒绝");
        assert_eq!(err.to_string(), "message name expansion exceeds budget");
        // 上界 = 预算 8×输入（name 字节）+ 段条目结构开销（每条 question 24B，
        // 按剩余字节预分配 ≈ 输入/5×24 ≈ 4.8×）。被拒报文的总分配必须是**输入的
        // 常数倍**（修复前该形态是 ~500×）。
        assert!(
            c.bytes < 16 * msg.len(),
            "in={}B alloc_bytes={} 放大 {:.1}x 超上界（预算或段预分配失效）",
            msg.len(),
            c.bytes,
            c.bytes as f64 / msg.len() as f64
        );
    }

    /// 预算闸：未共享展开超过 `MAX_NAME_EXPAND_FACTOR × 输入字节` 即拒绝
    /// （「同一 run 换不同入口偏移」这类绕过共享缓存的构造由它兜底）。
    #[test]
    fn name_expansion_budget_rejects_oversized_expansion() {
        let (msg, _) = shared_run_query(4096);
        // 第 2 条 question 的指针字节：头 12 + run 252 + 根 1 + qtype/qclass 4
        let second_question = 12 + 126 * 2 + 1 + 4;
        let mut cursor = io::Cursor::new(&msg[..]);
        cursor.set_position(second_question as u64);
        // 预算 100B < 该 run 展开的 253B
        let mut budget = NameBudget { left: 100, cache: HashMap::new() };
        let err = read_name(&mut cursor, &mut budget).expect_err("预算耗尽必须拒绝");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message name expansion exceeds budget");
    }

    /// bd oavzu：rd_length 必须按剩余字节先校验再分配（Go unpack 的顺序）。
    /// 25B 报文声称 rd_length=65535 ⇒ 拒绝且不预分配 64KB。
    #[test]
    fn rdata_overclaim_allocates_nothing() {
        let mut msg = hdr(0, 1);
        msg.push(0x00); // RR name = root
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // A / IN / ttl
        msg.extend_from_slice(&[0xff, 0xff]); // rd_length = 65535
        msg.extend_from_slice(&[0xaa, 0xbb]); // 实际只有 2 字节
        assert_eq!(msg.len(), 25);

        let (res, c) = alloc_probe::measure(|| message_from_wire_format(&msg));
        let err = res.expect_err("rd_length 越界必须拒绝");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(c.bytes < 4096, "alloc_bytes={} 仍按声明长度预分配", c.bytes);
        assert!(c.peak < 4096, "peak={}B 仍按声明长度预分配", c.peak);
    }

    /// bd a1pfm：CNAME rdata 解嵌套名**成功**后也必须复位游标 —— 5 种 rdata 形态
    /// 逐一验证后续 RR 字段全对（`[CNAME][A][TXT]`，第 2/3 条错位即失败）。
    #[test]
    fn cname_rdata_forms_keep_cursor_aligned() {
        const ROOT: &[u8] = &[0x00];
        // offset 12 起的未压缩名 "example.com"（形态 2/5 的指针目标）
        const EXAMPLE_COM: &[u8] =
            &[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00];
        // 归一化后的未压缩 "t.example.com"
        const T_EXAMPLE_COM: &[u8] = &[
            0x01, b't', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00,
        ];
        // 形态 3：嵌套名只占 3 字节，其余按 rd_length 补零（rdata 内无指针 ⇒
        // read_name 不会自行复位游标，正是错位触发面）
        let mut short_padded: Vec<u8> = vec![0x01, b'a', 0x00];
        short_padded.resize(15, 0x00);

        // (形态, CNAME RR 的 name, CNAME rdata, 期望的归一化 rdata)
        type WireForm<'a> = (&'a str, &'a [u8], Vec<u8>, &'a [u8]);
        let forms: [WireForm; 5] = [
            (
                "未压缩嵌套名",
                ROOT,
                vec![1, b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0],
                T_EXAMPLE_COM,
            ),
            ("尾随压缩指针", EXAMPLE_COM, vec![1, b't', 0xc0, 0x0c], T_EXAMPLE_COM),
            ("短名 + 补齐", ROOT, short_padded, &[0x01, b'a', 0x00]),
            ("纯压缩指针", EXAMPLE_COM, vec![0xc0, 0x0c], EXAMPLE_COM),
            ("非 name rdata（Err 分支）", ROOT, vec![0x80], &[0x80]),
        ];

        for (form, rr_name, rdata, expected) in forms {
            let mut msg = hdr(0, 3);
            msg.extend_from_slice(&rr_wire(rr_name, RR_TYPE_CNAME, 60, &rdata));
            msg.extend_from_slice(&rr_wire(ROOT, RR_TYPE_A, 60, &[1, 2, 3, 4]));
            msg.extend_from_slice(&rr_wire(ROOT, RR_TYPE_TXT, 61, &[2, b'h', b'i']));

            let m = message_from_wire_format(&msg)
                .unwrap_or_else(|e| panic!("形态 {form}: 解析失败 {e}"));
            assert_eq!(m.answer.len(), 3, "形态 {form}");
            assert_eq!(m.answer[0].rtype, RR_TYPE_CNAME, "形态 {form}");
            assert_eq!(m.answer[0].data, expected, "形态 {form}: CNAME rdata 归一化");
            // 后续 RR 必须字段全对（游标未复位的指纹：第 2/3 条整体错位）
            assert_eq!(
                (m.answer[1].name.clone(), m.answer[1].rtype, m.answer[1].ttl),
                (Name::default(), RR_TYPE_A, 60),
                "形态 {form}: 第 2 条 RR 错位"
            );
            assert_eq!(m.answer[1].data, vec![1, 2, 3, 4], "形态 {form}: 第 2 条 rdata");
            assert_eq!(
                (m.answer[2].name.clone(), m.answer[2].rtype, m.answer[2].ttl),
                (Name::default(), RR_TYPE_TXT, 61),
                "形态 {form}: 第 3 条 RR 错位"
            );
            assert_eq!(m.answer[2].data, vec![2, b'h', b'i'], "形态 {form}: 第 3 条 rdata");
        }
    }

    /// 分配取证：线程局部计数分配器（libtest 并行下他线程分配不串扰；本 crate lib
    /// 目标仅此一处 `#[global_allocator]`，与 `udp_session` 同款做法）。
    mod alloc_probe {
        use std::{
            alloc::{GlobalAlloc, Layout, System},
            cell::Cell,
        };

        #[derive(Clone, Copy, Default)]
        pub(super) struct Counts {
            pub allocs: usize,
            pub bytes: usize,
            live: usize,
            pub peak: usize,
        }

        thread_local! {
            // const 初始化：分配器内读取无惰性分配、无析构注册
            static COUNTS: Cell<Counts> = const { Cell::new(Counts {
                allocs: 0,
                bytes: 0,
                live: 0,
                peak: 0,
            }) };
        }

        fn note_alloc(size: usize, freed: usize) {
            // try_with：TLS 析构期分配无归属线程，跳过记账（分配器内禁 panic）
            let _ = COUNTS.try_with(|c| {
                let mut n = c.get();
                n.allocs += 1;
                n.bytes += size;
                n.live = n.live.saturating_sub(freed) + size;
                n.peak = n.peak.max(n.live);
                c.set(n);
            });
        }

        fn note_dealloc(size: usize) {
            let _ = COUNTS.try_with(|c| {
                let mut n = c.get();
                n.live = n.live.saturating_sub(size);
                c.set(n);
            });
        }

        struct CountingAlloc;

        unsafe impl GlobalAlloc for CountingAlloc {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                note_alloc(layout.size(), 0);
                // SAFETY: 透传 System，布局合法性由 GlobalAlloc 契约保证
                unsafe { System.alloc(layout) }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                note_alloc(layout.size(), 0);
                // SAFETY: 同上
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                note_alloc(new_size, layout.size());
                // SAFETY: 指针/布局配对由 GlobalAlloc 契约保证
                unsafe { System.realloc(ptr, layout, new_size) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                note_dealloc(layout.size());
                // SAFETY: 同上
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        #[global_allocator]
        static PROBE_ALLOC: CountingAlloc = CountingAlloc;

        /// 在独立计数窗口内跑 `f`，返回结果与窗口内的分配统计。
        pub(super) fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
            COUNTS.with(|c| c.set(Counts::default()));
            let out = f();
            (out, COUNTS.with(|c| c.get()))
        }
    }
}
