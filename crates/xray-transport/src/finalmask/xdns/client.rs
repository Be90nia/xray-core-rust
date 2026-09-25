//! # xdns 客户端 transport（对应 Go `xdns/client.go`）
//!
//! `XdnsConnClient` 包装底层 UDP conn，实现 `UdpIo`：
//! - send_to：把 payload 编码为 DNS 查询 wire format，发往 resolver。
//! - recv_from：从 resolver 收到的 DNS 响应中解码 payload。
//!
//! 隧道协议：payload → base32 编码 → 切成 ≤63 字节 label → 拼到 domain 前 →
//! 构造 DNS 查询；轮询包（payload 空）用更长 padding 区分。

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use rand::RngCore;
use tokio::sync::{Mutex, mpsc};

use super::{
    UdpIo,
    base32::encode_lower,
    dns::{CLASS_IN, Message, Name, Question, RR, RR_TYPE_OPT, message_from_wire_format},
    record_transport::decode_response_payload,
};

/// payload 长度上限（对应 Go encode 中的 224 上限校验）。
const PAYLOAD_MAX: usize = 224;

const NUM_PADDING: u8 = 3;
const NUM_PADDING_FOR_POLL: u8 = 8;
const INIT_POLL_DELAY: Duration = Duration::from_millis(500);
const READ_QUEUE_CAP: usize = 256;
const WRITE_QUEUE_CAP: usize = 256;

/// 把一段 payload 编码为 DNS 查询 wire format。
///
/// 对应 Go `encode`。
pub(crate) fn encode(
    p: &[u8],
    client_id: &[u8; 8],
    domain: &Name,
    qtype: u16,
) -> io::Result<Vec<u8>> {
    if p.len() >= PAYLOAD_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload too long for xdns encoding",
        ));
    }

    let n = if p.is_empty() { NUM_PADDING_FOR_POLL } else { NUM_PADDING };
    let mut decoded: Vec<u8> = Vec::with_capacity(8 + 1 + n as usize + 1 + p.len());
    decoded.extend_from_slice(client_id);
    decoded.push(224 + n);
    let mut padding = vec![0u8; n as usize];
    rand::rng().fill_bytes(&mut padding);
    decoded.extend_from_slice(&padding);
    if !p.is_empty() {
        decoded.push(p.len() as u8);
        decoded.extend_from_slice(p);
    }

    let encoded = encode_lower(&decoded);
    let mut labels = chunks(&encoded, 63);
    labels.extend_from_slice(&domain.labels);
    let name = Name::new(labels)?;

    let id: u16 = (rand::rng().next_u32() & 0xffff) as u16;
    let query = Message {
        id,
        flags: 0x0100, // RD=1
        question: vec![Question { name, qtype, qclass: CLASS_IN }],
        answer: vec![],
        authority: vec![],
        additional: vec![RR {
            name: Name::default(),
            rtype: RR_TYPE_OPT,
            rclass: 4096,
            ttl: 0,
            data: vec![],
        }],
    };

    query.wire_format()
}

/// 把字节切片按 n 字节切分为多片。
///
/// 对应 Go `chunks`。
pub(crate) fn chunks(p: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < p.len() {
        let end = (start + n).min(p.len());
        result.push(p[start..end].to_vec());
        start = end;
    }
    result
}

/// 从 payload 流中读取一个 `[len(2 BE)][bytes]` 包。
fn next_packet(r: &mut &[u8]) -> Option<Vec<u8>> {
    if r.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([r[0], r[1]]) as usize;
    *r = &r[2..];
    if r.len() < n {
        return None;
    }
    let p = r[..n].to_vec();
    *r = &r[n..];
    Some(p)
}

/// 从 DNS 响应提取 payload 流：校验 QR=1 / RCODE=0 / answer.name 匹配已知 domain。
///
/// 对应 Go `dnsResponsePayload`。
pub(crate) fn dns_response_payload(resp: &Message, domains: &[Name]) -> Option<Vec<u8>> {
    if resp.flags & 0x8000 != 0x8000 {
        return None;
    }
    if resp.flags & 0x000f != 0 {
        return None;
    }
    if resp.answer.is_empty() {
        return None;
    }
    for answer in &resp.answer {
        let mut matched = false;
        for domain in domains {
            if answer.name.trim_suffix(domain).1 {
                matched = true;
                break;
            }
        }
        if !matched {
            return None;
        }
    }
    decode_response_payload(&resp.answer)
}

/// 内部数据包。
struct Packet {
    data: Vec<u8>,
    addr: Option<SocketAddr>,
}

/// resolver 共享状态。
struct ResolverState {
    addrs: Vec<SocketAddr>,
    types: Vec<u16>,
    domains: Vec<Name>,
    sends: Vec<Arc<AtomicU32>>,
    idx: AtomicU32,
}

/// xdns 客户端：包装底层 UDP conn，按 DNS-over-UDP 隧道协议转发。
pub(crate) struct XdnsConnClient {
    inner: Arc<dyn UdpIo>,
    state: Arc<ResolverState>,
    client_id: Arc<[u8; 8]>,
    closed: Arc<AtomicBool>,
    write_tx: mpsc::Sender<Packet>,
    read_rx: Mutex<mpsc::Receiver<Packet>>,
}

impl XdnsConnClient {
    pub(crate) fn new(inner: Box<dyn UdpIo>, resolvers: Vec<String>) -> io::Result<Self> {
        if resolvers.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty resolvers"));
        }

        let mut domains = Vec::new();
        let mut types = Vec::new();
        let mut addrs = Vec::new();
        let mut sends = Vec::new();
        for rs in &resolvers {
            let (name, server, rr_type) = super::spec::parse_resolver(rs)?;
            let addr: SocketAddr = server.parse().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid resolver addr: {e}"))
            })?;
            domains.push(name);
            types.push(rr_type);
            addrs.push(addr);
            sends.push(Arc::new(AtomicU32::new(0)));
        }

        let mut client_id = [0u8; 8];
        rand::rng().fill_bytes(&mut client_id);

        let state =
            Arc::new(ResolverState { addrs, types, domains, sends, idx: AtomicU32::new(0) });

        let (write_tx, write_rx) = mpsc::channel(WRITE_QUEUE_CAP);
        let (poll_tx, poll_rx) = mpsc::channel(super::POLL_LIMIT);
        let (read_tx, read_rx) = mpsc::channel(READ_QUEUE_CAP);

        let closed = Arc::new(AtomicBool::new(false));
        let inner_arc: Arc<dyn UdpIo> = Arc::from(inner);

        tokio::spawn(recv_loop(state.clone(), inner_arc.clone(), closed.clone(), read_tx, poll_tx));
        let state_clone = state.clone();
        let inner_clone = inner_arc.clone();
        tokio::spawn(send_loop(
            state_clone,
            inner_clone,
            write_rx,
            poll_rx,
            closed.clone(),
            Arc::new(client_id),
        ));

        Ok(Self {
            inner: inner_arc,
            state,
            client_id: Arc::new(client_id),
            closed,
            write_tx,
            read_rx: tokio::sync::Mutex::new(read_rx),
        })
    }
}

/// recv loop：读 UDP → 解码 DNS 响应 → 拆分 payload 包 → 入 read_queue。
async fn recv_loop(
    state: Arc<ResolverState>,
    inner: Arc<dyn UdpIo>,
    closed: Arc<AtomicBool>,
    read_tx: mpsc::Sender<Packet>,
    poll_tx: mpsc::Sender<()>,
) {
    let mut buf = vec![0u8; super::UDP_SIZE];
    loop {
        if closed.load(Ordering::Relaxed) {
            break;
        }
        let (n, addr) = match inner.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let Some(send_idx) = find_resolver(&state, addr) else {
            continue;
        };

        let resp = match message_from_wire_format(&buf[..n]) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let Some(payload) = dns_response_payload(&resp, &state.domains) else {
            continue;
        };

        let mut reader = &payload[..];
        let mut any_packet = false;
        while let Some(p) = next_packet(&mut reader) {
            any_packet = true;
            let pkt = Packet { data: p, addr: Some(addr) };
            // 队列满则丢弃（与 Go default case 一致）
            let _ = read_tx.try_send(pkt);
        }

        if any_packet {
            state.sends[send_idx].store(0, Ordering::Relaxed);
            let _ = poll_tx.try_send(());
        }
    }
}

/// 在 resolver 列表中找到对应 addr 的索引。
fn find_resolver(state: &ResolverState, addr: SocketAddr) -> Option<usize> {
    state.addrs.iter().position(|a| *a == addr)
}

/// send loop：writeQueue / pollChan / pollTimer 多路 select。
async fn send_loop(
    state: Arc<ResolverState>,
    inner: Arc<dyn UdpIo>,
    mut write_rx: mpsc::Receiver<Packet>,
    mut poll_rx: mpsc::Receiver<()>,
    closed: Arc<AtomicBool>,
    client_id: Arc<[u8; 8]>,
) {
    let mut poll_delay = INIT_POLL_DELAY;
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }

        let (pkt, timer_expired) = tokio::select! {
            biased;
            p = write_rx.recv() => (p, false),
            _ = poll_rx.recv() => (None, false),
            _ = tokio::time::sleep(poll_delay) => (None, true),
        };

        let data = if let Some(p) = pkt {
            let _ = poll_rx.try_recv();
            p.data
        } else {
            let idx = state.idx.load(Ordering::Relaxed) as usize % state.addrs.len();
            match encode(&[], &client_id, &state.domains[idx], state.types[idx]) {
                Ok(b) => b,
                Err(_) => continue,
            }
        };

        poll_delay = if timer_expired {
            (poll_delay.mul_f32(2.0)).min(super::MAX_POLL_DELAY)
        } else {
            INIT_POLL_DELAY
        };

        let cur = pick_next_resolver(&state);
        let _ = state.sends[cur].fetch_add(1, Ordering::Relaxed);
        let _ = inner.send_to(&data, state.addrs[cur]).await;
    }
}

/// 从当前 resolver 开始，找到第一个 send 计数 < cur_send 的 resolver。
fn pick_next_resolver(state: &ResolverState) -> usize {
    let cur = state.idx.fetch_add(1, Ordering::Relaxed) as usize % state.addrs.len();
    let cur_send = state.sends[cur].load(Ordering::Relaxed);
    for i in 1..state.addrs.len() {
        let idx = (cur + i) % state.addrs.len();
        if state.sends[idx].load(Ordering::Relaxed) < cur_send {
            return idx;
        }
    }
    cur
}

#[async_trait]
impl UdpIo for XdnsConnClient {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::other("xdns client closed"));
        }

        let idx = self.state.idx.load(Ordering::Relaxed) as usize % self.state.addrs.len();
        let encoded =
            encode(buf, &self.client_id, &self.state.domains[idx], self.state.types[idx])?;
        let pkt = Packet { data: encoded, addr: Some(addr) };
        let _ = self.write_tx.try_send(pkt);
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let pkt = {
            let mut rx = self.read_rx.lock().await;
            rx.recv().await
        };
        let Some(pkt) = pkt else {
            return Err(io::Error::other("xdns client closed"));
        };
        let n = pkt.data.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt.data[..n]);
        let addr = pkt.addr.unwrap_or_else(|| SocketAddr::from(([0u8, 0, 0, 0], 0)));
        Ok((n, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl Drop for XdnsConnClient {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xdns::base32::decode_upper;

    #[test]
    fn chunks_basic() {
        let data = b"abcdef";
        let result = chunks(data, 2);
        assert_eq!(result, vec![vec![b'a', b'b'], vec![b'c', b'd'], vec![b'e', b'f']]);

        let data = b"abc";
        let result = chunks(data, 5);
        assert_eq!(result, vec![vec![b'a', b'b', b'c']]);

        let result = chunks(b"", 5);
        assert!(result.is_empty());
    }

    #[test]
    fn encode_payload_too_long_rejected() {
        let client_id = [0u8; 8];
        let domain = Name::parse("t.example.com").unwrap();
        let big = vec![0u8; PAYLOAD_MAX];
        let err = encode(&big, &client_id, &domain, super::super::dns::RR_TYPE_TXT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn encode_empty_poll_packet_produces_valid_message() {
        let client_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let domain = Name::parse("t.example.com").unwrap();
        let wire = encode(&[], &client_id, &domain, super::super::dns::RR_TYPE_TXT).unwrap();
        let msg = message_from_wire_format(&wire).unwrap();
        assert_eq!(msg.question.len(), 1);
        assert_eq!(msg.additional.len(), 1);
        assert_eq!(msg.additional[0].rtype, RR_TYPE_OPT);
    }

    #[test]
    fn encode_then_decode_payload_in_query_name() {
        let client_id = [0xaa; 8];
        let domain = Name::parse("t.example.com").unwrap();
        let payload = b"hello xdns";
        let wire = encode(payload, &client_id, &domain, super::super::dns::RR_TYPE_TXT).unwrap();
        let msg = message_from_wire_format(&wire).unwrap();

        let (prefix, ok) = msg.question[0].name.trim_suffix(&domain);
        assert!(ok);
        let mut joined: Vec<u8> = Vec::new();
        for label in &prefix.labels {
            joined.extend_from_slice(label);
        }
        joined.iter_mut().for_each(|b| b.make_ascii_uppercase());
        let decoded = decode_upper(&joined).unwrap();
        assert_eq!(&decoded[..8], &client_id);
        let pad_n = decoded[8] - 224;
        assert!(pad_n >= NUM_PADDING);
        let off = 9 + pad_n as usize;
        assert_eq!(decoded[off] as usize, payload.len());
        assert_eq!(&decoded[off + 1..off + 1 + payload.len()], payload);
    }

    #[test]
    fn next_packet_decodes_stream() {
        let stream = vec![0u8, 3, b'a', b'b', b'c', 0, 2, b'd', b'e'];
        let mut reader = &stream[..];
        let p1 = next_packet(&mut reader).unwrap();
        assert_eq!(p1, b"abc");
        let p2 = next_packet(&mut reader).unwrap();
        assert_eq!(p2, b"de");
        assert!(next_packet(&mut reader).is_none());
    }
}
