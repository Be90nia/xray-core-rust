//! # xdns 服务端 transport（对应 Go `xdns/server.go`，v26.9.30 重构版）
//!
//! 查询名后缀匹配 domain → base32 解码 payload（校验首字节 qtype 标识与
//! [8]&0x3F ∈ {3,8}）→ 交上层；分片经 [`FragManager`] 重组。响应经
//! [`SendManager`] 按 clientID 攒包，拼 [len2|0xC0] 帧后编码为 answer 段。
//! 错误查询即时回错误响应（dr 通道）。
//!
//! bd 2ktp ④：对齐 Xray-core fc8f8a45。

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use skeleton_infra::fx::FxScope;
use tokio::sync::{Mutex, mpsc};

use super::{
    Config, UdpIo,
    dns::{
        Message, RCODE_FORMAT_ERROR, RCODE_NAME_ERROR, RCODE_NO_ERROR, RCODE_NOT_IMPLEMENTED,
        RR_TYPE_OPT, message_from_wire_format,
    },
    domain::{Domain, type_map_},
    frag::{ClientID, FragManager},
    resp::{Resp, SendManager},
};

// log-hot-path-exempt: xdns 每包读路径错误记录 —— 数据面泵/每包循环内的诊断留痕，LogFacade
// emit（Mutex+掩码）开销不可入热路径，保留原样
const MAX_RESPONSE_DELAY: Duration = Duration::from_secs(1);
const REC_QUEUE_CAP: usize = 255;
const UDP_READ_BUF: usize = 4096;

/// 错误即时响应（Go `resp` struct in server.go）。
struct DrResp {
    msg: Message,
    addr: SocketAddr,
}

/// 已解码待响应的记录（Go `Rec`）。
struct Rec {
    resp: Resp,
    client_id: ClientID,
    addr: SocketAddr,
}

/// 服务端共享状态。
struct ServerState {
    inner: Arc<dyn UdpIo>,
    domains: Vec<Domain>,
    frag: Arc<FragManager>,
    send_mgr: Arc<SendManager>,
    read_tx: mpsc::Sender<Packet>,
    rec_tx: mpsc::Sender<Rec>,
    dr_tx: mpsc::Sender<DrResp>,
}

/// 上层数据包：payload + clientID 派生的 fd 地址（Go `clientID.Addr()`）。
struct Packet {
    data: Vec<u8>,
    addr: SocketAddr,
}

/// clientID → 稳定 fd IPv6 地址（对齐 Go `ClientID.Addr`：ip[0]=0xFD, ip[8:]=id）。
fn client_id_to_addr(client_id: ClientID) -> SocketAddr {
    let mut ip = [0u8; 16];
    ip[0] = 0xFD;
    ip[8..].copy_from_slice(&client_id);
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), 0)
}

/// fd 地址 → clientID（对齐 Go `ClientIDFromAddr`：取 IP[8:]）。
fn client_id_from_addr(addr: &SocketAddr) -> ClientID {
    match addr.ip() {
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]]
        },
        IpAddr::V4(_) => [0u8; 8],
    }
}

/// xdns 服务端：包装底层 UDP conn，作为 DNS-over-UDP 隧道服务端。
pub(crate) struct XdnsConnServer {
    state: Arc<ServerState>,
    closed: Arc<AtomicBool>,
    read_rx: Mutex<mpsc::Receiver<Packet>>,
    /// B6（bd t975）：maintain_loop 唯一托管口（坑约束 5）。recv/send/dr 为
    /// 数据面泵热路径豁免（约束⑫）；scope 随 conn drop 兜底 abort，
    /// 协作停机仍走 `closed`。
    // fx 仅经 drop glue 生效（JoinSet 兜底 abort），无显式读点——同 uot/TcpWorker 先例。
    #[allow(dead_code)]
    fx: Arc<FxScope>,
}

impl XdnsConnServer {
    pub(crate) fn new(inner: Arc<dyn UdpIo>, config: &Config) -> io::Result<Self> {
        if config.domains.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty domains"));
        }
        let mut domains = Vec::with_capacity(config.domains.len());
        for d in &config.domains {
            let edns0 = u16::try_from(d.edns0)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xdns: invalid edns0"))?;
            domains.push(Domain::new(
                &d.name,
                d.len_limit as usize,
                d.label_limit as usize,
                &d.types,
                edns0,
            )?);
        }

        // cap=1 + send().await 等效 Go 无缓冲阻塞语义（tokio mpsc 无 0 容量）
        let (read_tx, read_rx) = mpsc::channel::<Packet>(1);
        let (rec_tx, rec_rx) = mpsc::channel::<Rec>(REC_QUEUE_CAP);
        let (dr_tx, dr_rx) = mpsc::channel::<DrResp>(1);

        let closed = Arc::new(AtomicBool::new(false));
        let frag = Arc::new(FragManager::new());
        let send_mgr = Arc::new(SendManager::new());

        let state = Arc::new(ServerState {
            inner,
            domains,
            frag: frag.clone(),
            send_mgr: send_mgr.clone(),
            read_tx,
            rec_tx,
            dr_tx,
        });

        let this = Self {
            state: Arc::clone(&state),
            closed: Arc::clone(&closed),
            read_rx: Mutex::new(read_rx),
            fx: Arc::new(FxScope::new()),
        };

        // 数据面泵热路径豁免（约束⑫）：recv/send/dr 三循环不加托管口。
        tokio::spawn(recv_loop(state.clone(), closed.clone()));
        tokio::spawn(send_loop(state.clone(), rec_rx, closed.clone()));
        tokio::spawn(dr_loop(state.clone(), dr_rx, closed.clone()));
        // 闸关不可达：内部 scope 无 close 调用（分片维护管理任务随 scope 收口）。
        this.fx
            .spawn(maintain_loop(frag, send_mgr, closed))
            .expect("internal FxScope is never closed");

        Ok(this)
    }
}

/// 即时错误响应投递（对应 Go `decref`：忙则丢弃）。
fn decref(state: &ServerState, msg: Message, addr: SocketAddr) {
    let _ = state.dr_tx.try_send(DrResp { msg, addr });
}

/// 空成功响应应答头（Response + Authoritative + Success）。
fn ok_header(mut msg: Message) -> Message {
    msg.flags = 0x8000 | 0x0400;
    msg.answer.clear();
    msg.authority.clear();
    msg.additional.clear();
    msg
}

/// 查询处理（对应 Go `xdnsServer.read`），逐级校验并即时回错误响应。
async fn server_read(state: &ServerState, buf: &[u8], addr: SocketAddr) {
    let Ok(mut msg) = message_from_wire_format(buf) else { return };
    if msg.flags & 0x8000 != 0 {
        return; // 响应不处理
    }

    if msg.opcode() != 0 {
        msg.flags = 0x8000 | (RCODE_NOT_IMPLEMENTED & 0xf);
        decref(state, msg, addr);
        return;
    }

    if msg.question.len() != 1 {
        msg.flags = 0x8000 | (RCODE_FORMAT_ERROR & 0xf);
        decref(state, msg, addr);
        return;
    }

    // OPT/EDNS0：重复 OPT → FormatError（Go 此分支仅置 RCode 即回）；版本非 0 → BADVERS
    let mut opt = false;
    let mut edns0: u16 = 0;
    for rr in &msg.additional {
        if rr.rtype == RR_TYPE_OPT {
            if opt {
                msg.flags = (msg.flags & !0x000f) | (RCODE_FORMAT_ERROR & 0xf);
                decref(state, msg, addr);
                return;
            }
            opt = true;
            edns0 = rr.rclass;
            if (rr.ttl >> 16) & 0xFF != 0 {
                msg.flags = (msg.flags & !0x000f) | (RCODE_NO_ERROR & 0xf);
                if let Some(rr_mut) = msg.additional.iter_mut().find(|r| r.rtype == RR_TYPE_OPT) {
                    rr_mut.ttl = 1 << 24;
                }
                decref(state, msg, addr);
                return;
            }
        }
    }
    if opt {
        edns0 = edns0.clamp(512, 4096);
    }

    let Some(domain) = state.domains.iter().find(|d| d.is_domain(&msg.question[0].name)) else {
        msg.flags = 0x8000 | (RCODE_NAME_ERROR & 0xf);
        decref(state, msg, addr);
        return;
    };
    if !domain.has_type(msg.question[0].qtype) {
        decref(state, ok_header(msg), addr);
        return;
    }

    let decoded = domain.decode(&msg.question[0].name);
    let n = decoded.len();
    if n < 9 {
        decref(state, ok_header(msg), addr);
        return;
    }
    // 首字节低 2bit qtype 匹配 + [8]&0x3F ∈ {3,8} + 形态长度校验
    let flag8 = decoded[8] & 0x3F;
    if type_map_(decoded[0] & 3) != msg.question[0].qtype
        || (flag8 != 3 && flag8 != 8)
        || (flag8 == 3 && n < 9 + 3 + 1)
        || (flag8 == 8 && n != 9 + 8)
    {
        decref(state, ok_header(msg), addr);
        return;
    }
    let client_id: ClientID = decoded[..8].try_into().expect("n >= 9");

    let resp = Resp::new(msg.clone(), domain.clone(), edns0);
    let rec = Rec { resp, client_id, addr };
    if state.rec_tx.try_send(rec).is_err() {
        // recCh 满（Go default 分支）：回空成功响应
        decref(state, ok_header(msg), addr);
        return;
    }

    if flag8 == 8 {
        return; // poll 包无 payload
    }
    let payload: Vec<u8> = if decoded[8] & 0xC0 == 0xC0 {
        // 分片：[12]fragID [13]idx [14]n + 数据
        let key = super::frag::FragKey::new(client_id, decoded[12]);
        let out = state.frag.feed(key, decoded[13], decoded[14], &decoded[15..n]).await;
        if out.is_empty() {
            return;
        }
        out
    } else {
        decoded[12..n].to_vec()
    };

    let pkt = Packet { data: payload, addr: client_id_to_addr(client_id) };
    // 读端已关（关闭中）＝无后续消费，忽略发送结果
    let _ = state.read_tx.send(pkt).await;
}

/// recv 循环：读隧道 → 处理查询（对应 Go `recv` goroutine）。
async fn recv_loop(state: Arc<ServerState>, closed: Arc<AtomicBool>) {
    let mut buf = vec![0u8; UDP_READ_BUF];
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let (n, addr) = match state.inner.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        server_read(&state, &buf[..n], addr).await;
    }
}

/// 响应发送循环（对应 Go `send` goroutine）：按 rec 攒包、超时/抢占切包。
///
/// 与 Go 的偏差：Go 的 `timer.Reset(0)` 与就绪 channel 随机竞争会随机提前
/// 截断攒包；本实现确定性排空队列（协议合法，攒包更满）。
async fn send_loop(
    state: Arc<ServerState>,
    mut rec_rx: mpsc::Receiver<Rec>,
    closed: Arc<AtomicBool>,
) {
    let mut next_rec: Option<Rec> = None;
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let rec = match next_rec.take() {
            Some(r) => r,
            None => match rec_rx.recv().await {
                Some(r) => r,
                None => return,
            },
        };

        let info = state.send_mgr.get(rec.client_id);
        info.refresh();
        let mut left = rec.resp.cap;
        let mut ps: Vec<Vec<u8>> = Vec::new();
        let mut got_any = false;
        loop {
            if let Some(p) = info.try_pop() {
                let il = 2 + p.len() as isize;
                left -= il;
                if left < 0 {
                    if ps.is_empty() {
                        tracing::error!(len = p.len(), "xdns server: err size");
                    } else {
                        state.send_mgr.stash(rec.client_id, &p);
                    }
                    break;
                }
                ps.push(p);
                got_any = true;
                continue;
            }
            // 队列空：挂通知前注册（防漏），再 select 通知/超时/抢占
            let wait = if got_any { Duration::ZERO } else { MAX_RESPONSE_DELAY };
            let notified_fut = info.notified();
            tokio::select! {
                _ = notified_fut => { continue; }
                _ = tokio::time::sleep(wait) => break,
                r = rec_rx.recv() => {
                    next_rec = r;
                    break;
                }
            }
        }

        // [len2|0xC0 终帧][bytes] 拼接 → 编码响应 → 回客户端
        let mut d: Vec<u8> = Vec::with_capacity(rec.resp.cap.max(0) as usize + 16);
        let n = ps.len();
        for (i, p) in ps.iter().enumerate() {
            let mut l = p.len();
            if i == n - 1 {
                l |= 0xC000;
            }
            d.extend_from_slice(&(l as u16).to_be_bytes());
            d.extend_from_slice(p);
        }
        if let Ok(pack) = rec.resp.encode(&d) {
            let _ = state.inner.send_to(&pack, rec.addr).await;
        }
    }
}

/// dr 循环：错误即时响应写出（对应 Go `dr` goroutine）。
async fn dr_loop(
    state: Arc<ServerState>,
    mut dr_rx: mpsc::Receiver<DrResp>,
    closed: Arc<AtomicBool>,
) {
    loop {
        let r = tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if closed.load(Ordering::Relaxed) { return; }
                continue;
            },
            r = dr_rx.recv() => r,
        };
        let Some(r) = r else { return };
        if let Ok(pack) = r.msg.wire_format() {
            let _ = state.inner.send_to(&pack, r.addr).await;
        }
    }
}

/// 维护循环：分片/SendManager TTL 清扫 + 关停时释放（对应 Go gc/Close）。
async fn maintain_loop(
    frag: Arc<FragManager>,
    send_mgr: Arc<SendManager>,
    closed: Arc<AtomicBool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2)); // 覆盖 fragTTL/2 粒度
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if closed.load(Ordering::Relaxed) {
            frag.close().await;
            send_mgr.close();
            return;
        }
        frag.sweep_expired().await;
        send_mgr.sweep_expired();
    }
}

#[async_trait]
impl UdpIo for XdnsConnServer {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::other("xdns server closed"));
        }
        if buf.is_empty() || buf.len() > UDP_READ_BUF {
            tracing::error!(len = buf.len(), "xdns server: err size");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "err size"));
        }
        self.state.send_mgr.push(client_id_from_addr(&addr), buf);
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let pkt = { self.read_rx.lock().await.recv().await };
        let Some(pkt) = pkt else {
            return Err(io::Error::other("xdns server closed"));
        };
        let n = pkt.data.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt.data[..n]);
        Ok((n, pkt.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([0u8, 0, 0, 0], 0)))
    }
}
