//! # 响应编解码与发送管理（对应 Go `xdns/resp.go`，v26.9.30）
//!
//! `Resp` 按查询 qtype 把 payload 编码为 answer 段（A/CNAME/TXT/AAAA 四形态，
//! 首条携带 [fragIdx, fragN] 头）；`SendManager` 按 clientID 暂存待发响应包。

use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    dns::{CLASS_IN, Message, Name, RR, RR_TYPE_OPT},
    domain::{Domain, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_TXT},
    frag::ClientID,
};

pub(crate) const SEND_TTL: Duration = Duration::from_secs(4);
const CH_CAP: usize = 128;
const STASH_CAP: usize = 1;

/// 单条响应的编解码器（对应 Go `Resp`）。
pub(crate) struct Resp {
    /// 原始查询（encode/decode 复用其 question/header）。
    msg: Message,
    domain: Domain,
    edns0: u16,
    /// 响应体可用容量（Go `cap`）。
    pub(crate) cap: isize,
}

impl Resp {
    /// 对应 Go `NewResp`：响应查询（client 解码路径）不计算容量；查询构造
    /// 按缓存大小（edns0 与 domain.edns0 的较小者，下限 512）推各 qtype 容量。
    pub(crate) fn new(msg: Message, domain: Domain, edns0: u16) -> Self {
        if msg.flags & 0x8000 != 0 {
            return Self { msg, domain, edns0, cap: 0 };
        }

        let q = &msg.question[0];
        let name_len = name_wire_len(&q.name);
        let size =
            isize::from(edns0.max(512) as i16).min(isize::from(domain.edns0().max(512) as i16));
        let mut left = size - 12 - name_len as isize - 1 - 2 - 2;
        if edns0 > 0 {
            left -= 1 + 2 + 2 + 4 + 2;
        }
        let cap: isize = match q.qtype {
            TYPE_A => {
                let single = 2 + 2 + 2 + 4 + 2 + 4;
                let n = (left / single).min(255);
                4 * n - n - 1
            },
            TYPE_CNAME => {
                let single = 2 + 2 + 2 + 4 + 2 + domain.len_max as isize;
                let n = (left / single).min(255);
                domain.cap as isize * n - n - 1
            },
            TYPE_TXT => {
                left -= 2 + 2 + 2 + 4 + 2;
                let n = left / 255;
                let m = left % 255;
                let mut cap = 255 * n - n;
                if m > 1 {
                    cap += m - 1;
                }
                cap
            },
            TYPE_AAAA => {
                let single = 2 + 2 + 2 + 4 + 2 + 16;
                let n = (left / single).min(255);
                16 * n - n - 1
            },
            _ => 0,
        };

        Self { msg, domain, edns0, cap }
    }

    /// payload → answer 段 → 完整响应 wire bytes，对应 Go `Resp.Encode`。
    pub(crate) fn encode(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut msg = self.msg.clone();
        // Header：ID 保留，置 Response(0x8000)+Authoritative(0x0400)+Success
        msg.flags = 0x8000 | 0x0400;
        msg.answer.clear();
        msg.authority.clear();
        msg.additional.clear();
        let q = msg.question[0].clone();
        let mut data = data;

        let mk_rr = |rdata: Vec<u8>| RR {
            name: q.name.clone(),
            rtype: q.qtype,
            rclass: CLASS_IN,
            ttl: 60,
            data: rdata,
        };

        match q.qtype {
            TYPE_A => {
                // frag 头：首条 [0, fragN, data..2]，后续 [i, data..3]
                let frag_n = frag_count(data.len(), 4);
                for i in 0..frag_n {
                    let (hdr, first) = if i == 0 { (2usize, true) } else { (1usize, false) };
                    let mut a = [0u8; 4];
                    a[0] = i as u8;
                    if first {
                        a[1] = frag_n as u8;
                    }
                    let n = data.len().min(4 - hdr);
                    a[hdr..hdr + n].copy_from_slice(&data[..n]);
                    data = &data[n..];
                    msg.answer.push(mk_rr(a.to_vec()));
                }
            },
            TYPE_AAAA => {
                let frag_n = frag_count(data.len(), 16);
                for i in 0..frag_n {
                    let (hdr, first) = if i == 0 { (2usize, true) } else { (1usize, false) };
                    let mut aaaa = [0u8; 16];
                    aaaa[0] = i as u8;
                    if first {
                        aaaa[1] = frag_n as u8;
                    }
                    let n = data.len().min(16 - hdr);
                    aaaa[hdr..hdr + n].copy_from_slice(&data[..n]);
                    data = &data[n..];
                    msg.answer.push(mk_rr(aaaa.to_vec()));
                }
            },
            TYPE_CNAME => {
                let cap = self.domain.cap;
                let frag_n = frag_count(data.len(), cap);
                let mut chunk: Vec<u8> = vec![0u8; cap];
                for i in 0..frag_n {
                    let (hdr, first) = if i == 0 { (2usize, true) } else { (1usize, false) };
                    chunk[0] = i as u8;
                    if first {
                        chunk[1] = frag_n as u8;
                    }
                    let n = data.len().min(cap - hdr);
                    chunk[hdr..hdr + n].copy_from_slice(&data[..n]);
                    data = &data[n..];
                    let name = self.domain.encode(&chunk[..hdr + n])?;
                    msg.answer.push(mk_rr(name_to_rdata(&name)));
                }
            },
            TYPE_TXT => {
                // 单条 answer，多 string（每段 ≤255）
                let mut rdata: Vec<u8> = Vec::new();
                let mut rest = data;
                while !rest.is_empty() {
                    let size = rest.len().min(255);
                    rdata.push(size as u8);
                    rdata.extend_from_slice(&rest[..size]);
                    rest = &rest[size..];
                }
                msg.answer.push(mk_rr(rdata));
            },
            _ => {},
        }
        if self.edns0 > 0 {
            msg.additional.push(RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: self.edns0,
                ttl: 0,
                data: Vec::new(),
            });
        }
        msg.wire_format()
    }

    /// answer 段 → payload，对应 Go `Resp.Decode`。
    ///
    /// CNAME rdata 已由 dns 层归一化为未压缩 wire name。
    pub(crate) fn decode(&self) -> Vec<u8> {
        let msg = &self.msg;
        let mut decoded: Vec<u8> = Vec::new();
        if msg.question[0].qtype == TYPE_TXT {
            if msg.answer.len() == 1
                && self.domain.is_domain(&msg.answer[0].name)
                && msg.answer[0].rtype == TYPE_TXT
            {
                // rdata = [len1][str1][len2][str2]...
                let rdata = &msg.answer[0].data;
                let mut pos = 0usize;
                while pos < rdata.len() {
                    let slen = rdata[pos] as usize;
                    pos += 1;
                    if pos + slen > rdata.len() {
                        break;
                    }
                    decoded.extend_from_slice(&rdata[pos..pos + slen]);
                    pos += slen;
                }
            }
            return decoded;
        }

        let mut frags: Vec<Vec<u8>> = Vec::new();
        for answer in &msg.answer {
            if !self.domain.is_domain(&answer.name) || answer.rtype != msg.question[0].qtype {
                continue;
            }
            match msg.question[0].qtype {
                TYPE_A if answer.data.len() == 4 => frags.push(answer.data.clone()),
                TYPE_AAAA if answer.data.len() == 16 => frags.push(answer.data.clone()),
                TYPE_CNAME => {
                    let Ok(name) = name_from_wire(&answer.data) else { continue };
                    let part = self.domain.decode(&name);
                    if part.is_empty() {
                        continue;
                    }
                    frags.push(part);
                },
                _ => {},
            }
        }
        frags.sort_by_key(|f| f[0]);
        if frags.is_empty() || frags[0].len() < 2 || frags[0][1] as usize > frags.len() {
            return decoded;
        }
        decoded.extend_from_slice(&frags[0][2..]);
        for i in 1..frags.len() {
            if frags[i][0] == frags[i - 1][0] {
                return Vec::new();
            }
            decoded.extend_from_slice(&frags[i][1..]);
        }
        decoded
    }
}

/// A/AAAA/CNAME 分片计数：首条 2B 头、其余 1B 头（Go Encode 内联算式）。
fn frag_count(data_len: usize, unit: usize) -> isize {
    let mut n: isize = 0;
    if data_len > 0 {
        n = 1;
    }
    let head = unit as isize - 2;
    if data_len as isize - head > 0 {
        n += (data_len as isize - head) / (unit as isize - 1);
        if (data_len as isize - head) % (unit as isize - 1) > 0 {
            n += 1;
        }
    }
    n
}

/// Name → 未压缩 wire name 字节（len 前缀 labels + 根 0）。
fn name_to_rdata(name: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    for label in &name.labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// 从 wire name 字节（未压缩形态）解析 Name；CNAME rdata 由 dns 层归一化为此形态。
pub(crate) fn name_from_wire(buf: &[u8]) -> io::Result<Name> {
    let mut labels = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(&len) = buf.get(pos) else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "name eof"));
        };
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed name"));
        }
        let Some(label) = buf.get(pos..pos + len as usize) else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "label eof"));
        };
        labels.push(label.to_vec());
        pos += len as usize;
    }
    Name::new(labels)
}

/// Name 的 wire 长度（len 前缀逐 label + 根 0 字节），对齐 Go `name.Length`。
pub(crate) fn name_wire_len(name: &Name) -> usize {
    let mut total = 1;
    for label in &name.labels {
        total += 1 + label.len();
    }
    total
}

/// 待发响应包队列（对应 Go `SendManager`/`SendInfo`）。
///
/// 字段经 parking_lot::Mutex 内部可变：服务端循环持有 `Arc<SendInfo>` 即可读写。
pub(crate) struct SendInfo {
    stash: parking_lot::Mutex<VecDeque<Vec<u8>>>,
    ch: parking_lot::Mutex<VecDeque<Vec<u8>>>,
    deadline: parking_lot::Mutex<Instant>,
    notify: tokio::sync::Notify,
}

impl SendInfo {
    // 尾表达式位不可挂语句属性（E0658），allow 上移 fn 级。
    #[allow(clippy::disallowed_methods, reason = "发送 TTL 锚点；Clock 端口注入待 bd 39hko")]
    fn now_deadline() -> Instant {
        Instant::now() + SEND_TTL
    }

    /// 非阻塞取包：stash 优先（对齐 Go select 优先级）。
    pub(crate) fn try_pop(&self) -> Option<Vec<u8>> {
        if let Some(p) = self.stash.lock().pop_front() {
            return Some(p);
        }
        self.ch.lock().pop_front()
    }

    fn push_ch(&self, p: Vec<u8>) {
        let mut ch = self.ch.lock();
        if ch.len() < CH_CAP {
            ch.push_back(p);
            self.notify.notify_one();
        }
    }

    fn push_stash(&self, p: Vec<u8>) {
        let mut stash = self.stash.lock();
        if stash.len() < STASH_CAP {
            stash.push_back(p);
            self.notify.notify_one();
        }
    }

    pub(crate) fn refresh(&self) {
        *self.deadline.lock() = Self::now_deadline();
    }

    /// 等待新包通知（调用方须先 try_pop 再挂 notified，防漏通知）。
    pub(crate) fn notified(&self) -> impl Future<Output = ()> + '_ {
        self.notify.notified()
    }

    fn expired(&self, now: Instant) -> bool {
        now > *self.deadline.lock()
    }
}

pub(crate) struct SendManager {
    m: parking_lot::Mutex<HashMap<ClientID, Arc<SendInfo>>>,
}

impl SendManager {
    pub(crate) fn new() -> Self {
        Self { m: parking_lot::Mutex::new(HashMap::new()) }
    }

    /// 取发送句柄并刷新 deadline（含缺省创建，对齐 Go `Pop`）。
    pub(crate) fn get(&self, id: ClientID) -> Arc<SendInfo> {
        let mut m = self.m.lock();
        m.entry(id)
            .or_insert_with(|| {
                Arc::new(SendInfo {
                    stash: parking_lot::Mutex::new(VecDeque::new()),
                    ch: parking_lot::Mutex::new(VecDeque::new()),
                    deadline: parking_lot::Mutex::new(SendInfo::now_deadline()),
                    notify: tokio::sync::Notify::new(),
                })
            })
            .clone()
    }

    /// 入队待发响应包（满则丢弃），对齐 Go `Push`。
    pub(crate) fn push(&self, id: ClientID, p: &[u8]) {
        let info = self.get(id);
        info.refresh();
        info.push_ch(p.to_vec());
    }

    /// 暂存超容量包（下轮优先发出），对齐 Go `Stash`。
    pub(crate) fn stash(&self, id: ClientID, p: &[u8]) {
        let m = self.m.lock();
        if let Some(info) = m.get(&id) {
            info.refresh();
            info.push_stash(p.to_vec());
        }
    }

    /// TTL 清扫（对应 Go gc），过期 entry 移除并唤醒等待方。
    pub(crate) fn sweep_expired(&self) {
        let mut m = self.m.lock();
        #[allow(
            clippy::disallowed_methods,
            reason = "SendInfo GC 墙钟取时；Clock 端口注入待 bd 39hko"
        )]
        let now = Instant::now();
        m.retain(|_, info| {
            if info.expired(now) {
                info.notify.notify_waiters();
                false
            } else {
                true
            }
        });
    }

    /// 对应 Go `Close`（服务端关停时清空并唤醒等待方）。
    pub(crate) fn close(&self) {
        let mut m = self.m.lock();
        for (_, info) in m.drain() {
            info.notify.notify_waiters();
        }
    }
}
