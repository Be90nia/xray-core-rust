//! # xdns 服务端 transport（对应 Go `xdns/server.go`）
//!
//! `XdnsConnServer` 包装底层 UDP conn，实现 `UdpIo`：
//! - recv_from：从客户端 DNS 查询中解码 payload，写入 read_queue。
//! - send_to：把 payload 编码为 DNS response answers，发回客户端。
//!
//! 每个 client（按 clientID 区分）映射到一个稳定的 IPv6 地址（`fd00::clientID`）。
//! 服务端维护 client_addr → 真实 UDP addr 的映射，使 send_to 能把响应回送到正确客户端。

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};

use super::{
    UdpIo,
    base32::decode_upper,
    dns::{
        Message, Name, Question, RR, RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_OPT, RR_TYPE_TXT,
        message_from_wire_format,
    },
    record_transport::{
        MAX_UDP_PAYLOAD, RESPONSE_TTL, answers_for_payload, max_encoded_payload_for_type,
        max_encoded_payload_txt,
    },
    spec::{DomainSpec, parse_domain_spec},
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_QUEUE_CAP: usize = 512;

/// 把 8 字节 clientID 映射到稳定的 IPv6 UDP addr（`fd00::clientID`，端口 0）。
///
/// 对应 Go `clientIDToAddr`。
pub(crate) fn client_id_to_addr(client_id: [u8; 8]) -> SocketAddr {
    let mut ip = [0u8; 16];
    ip[0] = 0xfd;
    ip[8..].copy_from_slice(&client_id);
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), 0)
}

/// `client_id_to_addr` 的逆操作；非 xdns-derived addr 返回 None。
fn addr_to_client_id(addr: SocketAddr) -> Option<[u8; 8]> {
    let IpAddr::V6(v6) = addr.ip() else {
        return None;
    };
    let octets = v6.octets();
    if octets[0] != 0xfd || octets[1..8].iter().any(|b| *b != 0) {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&octets[8..]);
    Some(id)
}

/// 内部读队列数据包。
struct Packet {
    data: Vec<u8>,
    addr: SocketAddr,
}

/// 已建立过会话的客户端信息（用于 send_to 反查真实 UDP addr）。
struct ClientInfo {
    real_addr: SocketAddr,
    qtype: u16,
    last_seen: Instant,
}

/// 服务端共享状态。
struct ServerState {
    domains: Vec<DomainSpec>,
    read_tx: mpsc::Sender<Packet>,
    /// client_addr 字符串 → 客户端信息。
    clients: Mutex<HashMap<String, ClientInfo>>,
}

/// xdns 服务端：包装底层 UDP conn，作为 DNS-over-UDP 隧道服务端。
pub(crate) struct XdnsConnServer {
    inner: Arc<dyn UdpIo>,
    state: Arc<ServerState>,
    closed: Arc<AtomicBool>,
    read_rx: Mutex<mpsc::Receiver<Packet>>,
}

impl XdnsConnServer {
    pub(crate) fn new(inner: Box<dyn UdpIo>, domains: Vec<String>) -> io::Result<Self> {
        if domains.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty domains"));
        }
        let mut specs = Vec::with_capacity(domains.len());
        for d in &domains {
            specs.push(parse_domain_spec(d, "")?);
        }

        let (read_tx, read_rx) = mpsc::channel(READ_QUEUE_CAP);

        let closed = Arc::new(AtomicBool::new(false));
        let inner_arc: Arc<dyn UdpIo> = Arc::from(inner);
        let state =
            Arc::new(ServerState { domains: specs, read_tx, clients: Mutex::new(HashMap::new()) });

        // recv loop：解析 DNS 查询 → 入 read_queue + 记录 client 信息
        {
            let state = state.clone();
            let inner = inner_arc.clone();
            let closed = closed.clone();
            tokio::spawn(recv_loop(state, inner, closed));
        }
        // clean loop：定期清理过期 client
        {
            let state = state.clone();
            let closed = closed.clone();
            tokio::spawn(clean_loop(state, closed));
        }

        Ok(Self { inner: inner_arc, state, closed, read_rx: Mutex::new(read_rx) })
    }
}

/// clean loop：定期清理 IDLE_TIMEOUT 未活动的 client 信息。
async fn clean_loop(state: Arc<ServerState>, closed: Arc<AtomicBool>) {
    loop {
        tokio::time::sleep(IDLE_TIMEOUT / 2).await;
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let now = Instant::now();
        let mut map = state.clients.lock().await;
        let to_remove: Vec<String> = map
            .iter()
            .filter_map(|(k, c)| {
                if now.duration_since(c.last_seen) >= IDLE_TIMEOUT { Some(k.clone()) } else { None }
            })
            .collect();
        for k in to_remove {
            map.remove(&k);
        }
    }
}

/// recv loop：解析 DNS 查询 → 调 responseFor → 解码 payload 包 → 入 read_queue，
/// 同时记录 client_addr → 真实 addr 的映射。
async fn recv_loop(state: Arc<ServerState>, inner: Arc<dyn UdpIo>, closed: Arc<AtomicBool>) {
    let mut buf = vec![0u8; super::UDP_SIZE];
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let (n, addr) = match inner.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let query = match message_from_wire_format(&buf[..n]) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let payload = decode_payload_from_query(&query, &state.domains).unwrap_or_default();
        let Some(resp) = response_for(&query, &state.domains) else {
            continue;
        };

        let mut client_id = [0u8; 8];
        let copied = payload.len().min(8);
        client_id[..copied].copy_from_slice(&payload[..copied]);
        let rest = payload.get(copied..).unwrap_or(&[]);
        let client_addr = client_id_to_addr(client_id);

        // 记录 client 信息（即使 clientID 不完整，也保留以备后续 send_to 失败时发 NXDOMAIN）
        let qtype = query.question.first().map(|q| q.qtype).unwrap_or(RR_TYPE_TXT);
        {
            let mut map = state.clients.lock().await;
            map.insert(
                client_addr.to_string(),
                ClientInfo { real_addr: addr, qtype, last_seen: Instant::now() },
            );
        }

        // 解析 payload 包入 read_queue（仅当完整 clientID 时）
        if copied == 8 {
            let mut reader = rest;
            while let Some(p) = next_packet_server(&mut reader) {
                let pkt = Packet { data: p, addr: client_addr };
                let _ = state.read_tx.try_send(pkt);
            }
        }

        // 立即发送初始响应（无 answer payload；后续 WriteTo 触发的响应才带 payload）
        let mut modified = resp;
        if copied != 8 && modified.rcode() == super::dns::RCODE_NO_ERROR {
            modified.flags |= super::dns::RCODE_NAME_ERROR;
        }
        match modified.wire_format() {
            Ok(out) => {
                let _ = inner.send_to(&out, addr).await;
            },
            Err(_) => continue,
        }
    }
}

/// 从字节流中读取一个数据包（与客户端 nextPacket 互逆，支持 padding 跳过）。
///
/// 对应 Go `nextPacketServer`。
pub(crate) fn next_packet_server(r: &mut &[u8]) -> Option<Vec<u8>> {
    loop {
        let &prefix = r.first()?;
        *r = &r[1..];
        if prefix >= 224 {
            // padding：跳过 prefix-224 字节
            let pad = (prefix - 224) as usize;
            if r.len() < pad {
                return None;
            }
            *r = &r[pad..];
        } else {
            // 普通包：读 prefix 字节
            let n = prefix as usize;
            if r.len() < n {
                return None;
            }
            let p = r[..n].to_vec();
            *r = &r[n..];
            return Some(p);
        }
    }
}

/// 从 query.name 中解码 base32 payload。
fn decode_payload_from_query(query: &Message, domains: &[DomainSpec]) -> Option<Vec<u8>> {
    let q = query.question.first()?;
    for d in domains {
        let (prefix, ok) = q.name.trim_suffix(&d.name);
        if !ok {
            continue;
        }
        let mut joined: Vec<u8> = Vec::new();
        for label in &prefix.labels {
            joined.extend_from_slice(label);
        }
        joined.iter_mut().for_each(|b| b.make_ascii_uppercase());
        return decode_upper(&joined).ok();
    }
    None
}

/// 根据查询构造响应消息模板。返回 None 表示不回复（QR=1 查询）。
///
/// 对应 Go `responseFor`。
pub(crate) fn response_for(query: &Message, domains: &[DomainSpec]) -> Option<Message> {
    let mut resp = Message {
        id: query.id,
        flags: 0x8000, // QR=1
        question: query.question.clone(),
        answer: vec![],
        authority: vec![],
        additional: vec![],
    };

    // QR=1 查询（其实是响应）不回复
    if query.flags & 0x8000 != 0 {
        return None;
    }

    // 处理 OPT EDNS
    let mut payload_size = 0u16;
    for rr in &query.additional {
        if rr.rtype != RR_TYPE_OPT {
            continue;
        }
        if !resp.additional.is_empty() {
            resp.flags |= super::dns::RCODE_FORMAT_ERROR;
            return Some(resp);
        }
        resp.additional.push(RR {
            name: Name::default(),
            rtype: RR_TYPE_OPT,
            rclass: 4096,
            ttl: 0,
            data: vec![],
        });
        let version = (rr.ttl >> 16) & 0xff;
        if version != 0 {
            resp.flags |= super::dns::EXTENDED_RCODE_BAD_VERS & 0xf;
            resp.additional[0].ttl = (u32::from(super::dns::EXTENDED_RCODE_BAD_VERS) >> 4) << 24;
            return Some(resp);
        }
        payload_size = rr.rclass;
    }
    if payload_size < 512 {
        payload_size = 512;
    }

    if query.question.len() != 1 {
        resp.flags |= super::dns::RCODE_FORMAT_ERROR;
        return Some(resp);
    }
    let question = query.question[0].clone();

    // 匹配 domain
    let mut matched: Option<&DomainSpec> = None;
    for d in domains {
        if question.name.trim_suffix(&d.name).1 {
            matched = Some(d);
            break;
        }
    }
    let matched = match matched {
        Some(m) => m,
        None => {
            resp.flags |= super::dns::RCODE_NAME_ERROR;
            return Some(resp);
        },
    };
    resp.flags |= 0x0400; // AA=1

    if query.opcode() != 0 {
        resp.flags |= super::dns::RCODE_NOT_IMPLEMENTED;
        return Some(resp);
    }

    // 校验 qtype
    match question.qtype {
        RR_TYPE_TXT | RR_TYPE_A | RR_TYPE_AAAA => {},
        _ => {
            resp.flags |= super::dns::RCODE_NAME_ERROR;
            return Some(resp);
        },
    }
    if matched.rr_type != 0 && question.qtype != matched.rr_type {
        resp.flags |= super::dns::RCODE_NAME_ERROR;
        return Some(resp);
    }

    // 校验 payload 可解码（失败 → NXDOMAIN）
    let prefix = question.name.trim_suffix(&matched.name).0;
    let mut joined: Vec<u8> = Vec::new();
    for label in &prefix.labels {
        joined.extend_from_slice(label);
    }
    joined.iter_mut().for_each(|b| b.make_ascii_uppercase());
    if decode_upper(&joined).is_err() {
        resp.flags |= super::dns::RCODE_NAME_ERROR;
        return Some(resp);
    }

    // payload_size 必须 ≥ MAX_UDP_PAYLOAD
    if (payload_size as usize) < MAX_UDP_PAYLOAD {
        resp.flags |= super::dns::RCODE_FORMAT_ERROR;
        return Some(resp);
    }

    Some(resp)
}

#[async_trait]
impl UdpIo for XdnsConnServer {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::other("xdns server closed"));
        }

        let Some(_client_id) = addr_to_client_id(addr) else {
            return Ok(0); // 非 xdns addr：静默丢弃
        };

        // 反查 client 真实 addr + qtype
        let (real_addr, qtype) = {
            let map = self.state.clients.lock().await;
            let Some(info) = map.get(&addr.to_string()) else {
                return Ok(0); // 未建立过会话：丢弃
            };
            (info.real_addr, info.qtype)
        };

        let qtype = if qtype == 0 { RR_TYPE_TXT } else { qtype };
        let limit = if qtype == RR_TYPE_TXT {
            max_encoded_payload_txt()
        } else {
            max_encoded_payload_for_type(qtype)
        };
        if buf.len() + 2 > limit {
            return Ok(0); // 超限：静默丢弃
        }

        // 用 domain 第一项作为 question.name
        let domain_name = self.state.domains.first().map(|d| d.name.clone()).unwrap_or_default();

        let answer = answers_for_payload(
            &Question { name: domain_name.clone(), qtype, qclass: super::dns::CLASS_IN },
            RESPONSE_TTL,
            buf,
        )?;

        let resp = Message {
            id: 0,
            flags: 0x8000,
            question: vec![Question { name: domain_name, qtype, qclass: super::dns::CLASS_IN }],
            answer,
            authority: vec![],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 0,
                data: vec![],
            }],
        };

        let mut wire = resp.wire_format()?;
        if wire.len() > MAX_UDP_PAYLOAD {
            wire.truncate(MAX_UDP_PAYLOAD);
            if wire.len() >= 3 {
                wire[2] |= 0x02; // TC=1
            }
        }
        self.inner.send_to(&wire, real_addr).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let pkt = {
            let mut rx = self.read_rx.lock().await;
            rx.recv().await
        };
        let Some(pkt) = pkt else {
            return Err(io::Error::other("xdns server closed"));
        };
        let n = pkt.data.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt.data[..n]);
        Ok((n, pkt.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl Drop for XdnsConnServer {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xdns::dns::{
        EXTENDED_RCODE_BAD_VERS, RCODE_FORMAT_ERROR, RCODE_NAME_ERROR, RCODE_NO_ERROR,
        RCODE_NOT_IMPLEMENTED,
    };

    #[test]
    fn client_id_to_addr_roundtrip() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let addr = client_id_to_addr(id);
        let decoded = addr_to_client_id(addr).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn addr_to_client_id_rejects_non_xdns() {
        let addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        assert!(addr_to_client_id(addr).is_none());
        let addr: SocketAddr = "[2001::1]:53".parse().unwrap();
        assert!(addr_to_client_id(addr).is_none());
    }

    #[test]
    fn next_packet_server_skips_padding() {
        // [padding_count=224+3][3 pad][2][ab][padding=224+1][1 pad][3][cde]
        let stream: Vec<u8> =
            vec![224 + 3, 0xaa, 0xbb, 0xcc, 2, b'a', b'b', 224 + 1, 0xdd, 3, b'c', b'd', b'e'];
        let mut reader = &stream[..];
        let p1 = next_packet_server(&mut reader).unwrap();
        assert_eq!(p1, b"ab");
        let p2 = next_packet_server(&mut reader).unwrap();
        assert_eq!(p2, b"cde");
        assert!(next_packet_server(&mut reader).is_none());
    }

    #[test]
    fn next_packet_server_eof_in_padding() {
        let stream: Vec<u8> = vec![224 + 5, 1, 2];
        let mut reader = &stream[..];
        assert!(next_packet_server(&mut reader).is_none());
    }

    #[test]
    fn response_for_empty_query_returns_formerr() {
        let query = Message { id: 1, flags: 0, question: vec![], ..Message::default() };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.flags & 0x000f, RCODE_FORMAT_ERROR);
    }

    #[test]
    fn response_for_qr_query_returns_none() {
        let query = Message {
            id: 1,
            flags: 0x8000,
            question: vec![Question {
                name: Name::parse("x.t.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            ..Message::default()
        };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        assert!(response_for(&query, &domains).is_none());
    }

    #[test]
    fn response_for_unmatched_domain_nxdomain() {
        let query = Message {
            id: 1,
            flags: 0,
            question: vec![Question {
                name: Name::parse("x.other.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 0,
                data: vec![],
            }],
            ..Message::default()
        };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.flags & 0x8000, 0x8000); // QR=1
        assert_eq!(resp.flags & 0x0400, 0); // AA=0
        assert_eq!(resp.flags & 0x000f, RCODE_NAME_ERROR);
    }

    #[test]
    fn response_for_method_restriction_violated_nxdomain() {
        // domainSpec 指定 a，但查询 txt → NXDOMAIN
        let query = Message {
            id: 1,
            flags: 0,
            question: vec![Question {
                name: Name::parse("x.t.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 0,
                data: vec![],
            }],
            ..Message::default()
        };
        let domains =
            vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: RR_TYPE_A }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.flags & 0x000f, RCODE_NAME_ERROR);
    }

    #[test]
    fn response_for_opcode_nonzero_notimpl() {
        let query = Message {
            id: 1,
            flags: 0x0800, // OPCODE=1 (IQUERY)
            question: vec![Question {
                name: Name::parse("x.t.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 0,
                data: vec![],
            }],
            ..Message::default()
        };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.flags & 0x0400, 0x0400); // AA=1
        assert_eq!(resp.flags & 0x000f, RCODE_NOT_IMPLEMENTED);
    }

    #[test]
    fn response_for_valid_txt_query_noerror() {
        let query = Message {
            id: 0x1234,
            flags: 0x0100, // RD=1
            question: vec![Question {
                name: Name::parse("x.t.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 0,
                data: vec![],
            }],
            ..Message::default()
        };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.flags & 0x8000, 0x8000); // QR=1
        assert_eq!(resp.flags & 0x0400, 0x0400); // AA=1
        assert_eq!(resp.flags & 0x000f, RCODE_NO_ERROR);
        assert_eq!(resp.additional.len(), 1);
        assert_eq!(resp.additional[0].rtype, RR_TYPE_OPT);
        assert_eq!(resp.answer.len(), 0); // 由 sendLoop 后续填
    }

    #[test]
    fn response_for_edns_bad_version() {
        let query = Message {
            id: 1,
            flags: 0,
            question: vec![Question {
                name: Name::parse("x.t.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: super::super::dns::CLASS_IN,
            }],
            additional: vec![RR {
                name: Name::default(),
                rtype: RR_TYPE_OPT,
                rclass: 4096,
                ttl: 1 << 16, // version=1
                data: vec![],
            }],
            ..Message::default()
        };
        let domains = vec![DomainSpec { name: Name::parse("t.example.com").unwrap(), rr_type: 0 }];
        let resp = response_for(&query, &domains).unwrap();
        assert_eq!(resp.flags & 0x000f, EXTENDED_RCODE_BAD_VERS & 0xf);
    }
}
