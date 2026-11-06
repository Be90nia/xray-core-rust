//! # xdns 客户端 transport（对应 Go `xdns/client.go`，v26.9.30 重构版）
//!
//! payload 编码为 DNS 查询发往 resolver（经 finalmask 隧道）：
//! - poll 包（17B）：clientID[0]|qtype标识 + [8]=8 + 8B 随机；
//! - 小包（≤cap-12）：[8]=3 + 3B 随机 + payload；
//! - 分片（≤255×(cap-15)）：[8]=3|0xC0 + [12]fragID/[13]idx/[14]n + 数据。
//!
//! 响应按 [len2|0xC0][bytes] 帧拆包投递上层。
//!
//! bd 2ktp ④：对齐 Xray-core fc8f8a45；resolver 形态见 [`Resolver`]：`udp://` 走
//! wrap 期拿到的隧道 conn，`https://`（DoH）走独立 TLS+h2 请求（[`super::doh`]）。
//! `tcp://` 在本栈运行期拒绝（隧道为 UDP-only，无 TCP 拨号句柄）。

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
use skeleton_infra::fx::FxScope;
use tokio::sync::{Mutex, mpsc};

use super::{
    Config, ResolverKind, UdpIo,
    dns::{CLASS_IN, Message, Question, RR, RR_TYPE_OPT, message_from_wire_format},
    doh,
    domain::{DEFAULT_CLIENT_TYPES, Domain, type_map},
    resp::Resp,
};

// hot-log 归口（能力收敛方案 §2 面 4）: xdns 每包 send/编码路径错误记录
// —— 经 crate::HOT_LOG 栈缓冲门面（先过滤后格式化，级别未命中零格式化零分配）
const INIT_POLL_DELAY: Duration = Duration::from_millis(500);
const MAX_POLL_DELAY: Duration = Duration::from_secs(10);
const SEND_QUEUE_CAP: usize = 16;
const UDP_READ_BUF: usize = 4096;

/// 内部数据包：payload + 来源 resolver 地址标签。
struct Packet {
    data: Vec<u8>,
    addr: SocketAddr,
}

/// 客户端共享状态。
struct ClientState {
    client_id: [u8; 8],
    domains: Vec<Domain>,
    resolvers: Vec<Resolver>,
    /// 各 resolver 连续未命中计数（Go `resolverSends`）。
    sends: Vec<AtomicU32>,
    /// 轮转游标（Go `resolverIndex`）。
    index: AtomicU32,
    /// 分片 ID 计数（Go `fragID`）。
    frag_id: AtomicU32,
    extra_poll: i32,
}

/// resolver 运行形态（Go `Resolver` 接口的两种实现，`resolver.go:17-27`）。
enum Resolver {
    /// `udp://`：经 wrap 期隧道 conn 发往解析器地址（Go `UDPResolver`）。
    Udp(SocketAddr),
    /// `https://`：DoH worker 组（Go `DOHResolver`）。
    Doh(doh::DohResolver),
}

/// xdns 客户端：包装底层 UDP conn，按 DNS-over-UDP 隧道协议转发。
pub(crate) struct XdnsConnClient {
    closed: Arc<AtomicBool>,
    write_tx: mpsc::Sender<Vec<u8>>,
    read_rx: Mutex<mpsc::Receiver<Packet>>,
    /// ar3tf：三泵（recv/doh_recv/send）的唯一托管口（server.rs 同款）。
    /// 全部走 `spawn_tracked` ⇒ 进 `JoinSet`，scope 随 conn drop 时 **abort 全组**
    /// 才成立（`tokio::spawn` 句柄丢弃 ⇒ drop 后 recv 泵永阻塞在 `recv_from` 上
    /// 持有 `Arc<dyn UdpIo>` ⇒ fd 不释放）。协作停机另走 `closed`（见 [`Drop`]）。
    // fx 仅经 drop glue 生效（JoinSet 兜底 abort），生产无显式读点——同
    // server.rs / uot/TcpWorker 先例。
    #[allow(dead_code)]
    fx: Arc<FxScope>,
}

impl XdnsConnClient {
    pub(crate) fn new(inner: Arc<dyn UdpIo>, config: &Config) -> io::Result<Self> {
        if config.domains.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty domains"));
        }
        if config.resolvers.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty resolvers"));
        }
        if config.extra_poll < 0 || config.extra_poll > 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "extraPoll < 0 || > 3"));
        }
        let mut domains = Vec::with_capacity(config.domains.len());
        for d in &config.domains {
            let edns0 = u16::try_from(d.edns0)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xdns: invalid edns0"))?;
            // Go client.go:72-74：Types 为空取 [16]
            let types = if d.types.is_empty() { &DEFAULT_CLIENT_TYPES[..] } else { &d.types[..] };
            domains.push(Domain::new(
                &d.name,
                d.len_limit as usize,
                d.label_limit as usize,
                types,
                edns0,
            )?);
        }
        let mut resolvers = Vec::with_capacity(config.resolvers.len());
        // DoH worker → 解码环（无 DoH resolver 时 channel 无人使用，随 state 落空）。
        let (doh_tx, doh_rx) = mpsc::channel::<(usize, Vec<u8>)>(SEND_QUEUE_CAP);
        for (idx, r) in config.resolvers.iter().enumerate() {
            match r.kind {
                ResolverKind::Udp => {
                    let addr: SocketAddr = r.addr.parse().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid resolver addr: {e}"),
                        )
                    })?;
                    resolvers.push(Resolver::Udp(addr));
                },
                ResolverKind::Tcp => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "xdns: TCP resolver not supported (UDP-only stack)",
                    ));
                },
                ResolverKind::Doh => {
                    let params = r.doh.as_ref().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "xdns: DoH resolver missing validated tls params",
                        )
                    })?;
                    resolvers.push(Resolver::Doh(doh::DohResolver::new(
                        params,
                        r.worker,
                        idx,
                        doh_tx.clone(),
                    )?));
                },
            }
        }
        // 所有 DoH worker 的发送端都在 resolvers 里；这里只留读端。
        drop(doh_tx);

        let mut client_id = [0u8; 8];
        rand::rng().fill_bytes(&mut client_id);
        client_id[0] &= 0xFC;

        let state = Arc::new(ClientState {
            client_id,
            sends: (0..resolvers.len()).map(|_| AtomicU32::new(0)).collect(),
            domains,
            resolvers,
            index: AtomicU32::new(0),
            frag_id: AtomicU32::new(0),
            extra_poll: config.extra_poll,
        });

        let (write_tx, write_rx) = mpsc::channel(SEND_QUEUE_CAP);
        let (poll_tx, poll_rx) = mpsc::channel::<()>(super::POLL_LIMIT);
        // tokio mpsc 无 0 容量：cap=1 + send().await 等效 Go 无缓冲阻塞语义
        let (read_tx, read_rx) = mpsc::channel::<Packet>(1);

        let closed = Arc::new(AtomicBool::new(false));
        let fx = Arc::new(FxScope::new());

        let this = Self { closed: closed.clone(), write_tx, read_rx: Mutex::new(read_rx), fx };

        // 三个数据面泵走**记账托管**（ar3tf，server.rs 同款）：`tokio::spawn` 句柄
        // 丢弃 = detach ⇒ conn drop 后 recv 泵继续阻塞在 `recv_from` 上、持有
        // `Arc<dyn UdpIo>` ⇒ fd 不释放。进 JoinSet 后 `fx` drop ⇒ JoinSet drop ⇒
        // abort 全组，「scope 随 conn drop 兜底 abort」才成立。DoH worker 在
        // doh.rs 内部 spawn（本层拿不到句柄），随 `state` drop ⇒ `DohResolver.tx`
        // drop ⇒ worker `rx.recv()` 返 None 级联退出（探针 `after_drop == base`
        // 实测覆盖该闭环）。
        this.fx
            .spawn_tracked(recv_loop(
                state.clone(),
                inner.clone(),
                closed.clone(),
                read_tx.clone(),
                poll_tx.clone(),
            ))
            .expect("internal FxScope is never closed");
        this.fx
            .spawn_tracked(doh_recv_loop(state.clone(), doh_rx, read_tx, poll_tx, closed.clone()))
            .expect("internal FxScope is never closed");
        this.fx
            .spawn_tracked(send_loop(state.clone(), inner, closed.clone(), write_rx, poll_rx))
            .expect("internal FxScope is never closed");

        Ok(this)
    }
}

impl Drop for XdnsConnClient {
    fn drop(&mut self) {
        // ar3tf：置协作停机位（对齐 Go `Close` 的 close(closeCh)，client.go:383-392
        // ——此前 `closed` 全仓无 store(true)，协作停机路径完全失效）。三泵 abort
        // 由 `fx` 字段 drop glue 完成；本字段 drop 后 `write_tx`/`read_rx` 随之
        // 关闭（send_loop 见 None 即退、client_read 投递短路）。
        self.closed.store(true, Ordering::Relaxed);
    }
}

/// 响应读取：校验 + Resp 解码 + [len2|0xC0] 帧拆包，对应 Go `xdnsClient.read`。
/// 返回是否有有效包投递。
async fn client_read(
    state: &ClientState,
    buf: &[u8],
    addr: SocketAddr,
    read_tx: &mpsc::Sender<Packet>,
) -> bool {
    let Ok(msg) = message_from_wire_format(buf) else { return false };
    // Response + 非 Truncated + RCodeSuccess + 单 question
    if msg.flags & 0x8000 == 0
        || msg.flags & 0x0200 != 0
        || msg.flags & 0x000f != 0
        || msg.question.len() != 1
    {
        return false;
    }

    let Some(domain) = state.domains.iter().find(|d| d.is_domain(&msg.question[0].name)) else {
        return false;
    };
    if !domain.has_type(msg.question[0].qtype) {
        return false;
    }

    // 上层（server）回显的 EDNS0 宣告值（additional OPT class）
    let _ = msg.additional.iter().find(|rr| rr.rtype == RR_TYPE_OPT).map(|rr| rr.rclass);

    let resp = Resp::new(msg, domain.clone(), 0);
    let payload = resp.decode();

    // [len2|0xC0 终帧标志][bytes] 帧拆包（Go read 内联逻辑，含 len 超界清空 quirk）
    let mut bs: Vec<Vec<u8>> = Vec::new();
    let mut b: &[u8] = &payload;
    while b.len() > 1 {
        let last = b[0] & 0xC0 == 0xC0;
        let length = ((b[0] & 0x3F) as usize) << 8 | b[1] as usize;
        b = &b[2..];
        if length > b.len() {
            bs.clear();
            break;
        }
        // i86yo / B-11：0 长度帧不投递。Go 同点（client.go:265-267）会产出空条目，
        // 但 Go `ReadFrom` 交付的是 `n=0, err=nil` 的空数据报（net.PacketConn 无
        // EOF 语义）；Rust 侧 `UdpIo::recv_from` 的 Ok(0) 会被上层 AsyncRead 消费
        // 方读成 EOF ⇒ 隧道被误判断链。空包对上层无信息量 ⇒ 跳过；其余拆包
        // quirk（超界清批 / 非终帧尾残清批）逐字节保留。
        if length > 0 {
            bs.push(b[..length].to_vec());
        }
        if last {
            break;
        }
        b = &b[length..];
        if b.len() < 2 {
            bs.clear();
        }
    }

    let packet_count = bs.len();
    for data in bs {
        if read_tx.send(Packet { data, addr }).await.is_err() {
            return true; // 读端已关（关闭中）
        }
    }
    packet_count > 0
}

/// recv 循环：读隧道 UDP → 解码响应 → 投递（对应 Go `recv` goroutine 组）。
async fn recv_loop(
    state: Arc<ClientState>,
    inner: Arc<dyn UdpIo>,
    closed: Arc<AtomicBool>,
    read_tx: mpsc::Sender<Packet>,
    poll_tx: mpsc::Sender<()>,
) {
    let mut buf = vec![0u8; UDP_READ_BUF];
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let (n, addr) = match inner.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // 对齐 Go `client.go:308-314`：closed 先查（静默退），否则记日志后
                // **退出泵**（Go 为 LogErrorInner + return）。旧 `Err(_) => continue`
                // = 持续 recv 错误零日志紧循环（bd ar3tf / CQ-02 / B-06）。用 WARN
                // 不用 DEBUG：生产默认 loglevel=warn 下失败必须留痕。
                // rjaxs-②（`ConnectionReset` 容忍，评估不加）：server.rs（bd quznp）
                // 的 `ConnectionReset => continue` 是**服务端角色**的有意发散（多
                // 客户端服务面 + 兜没走 no-connreset 口的 socket，server.rs 头注
                // 「有意差异」）。客户端对齐 Go：任何 recv 错误即退泵。且 Windows
                // 假错误已在 socket 层根治（bd d597w ioctl，`tools/check_udp_binds.py`
                // 静态门守「生产裸 bind 即红」⇒ 隧道 socket 不可能上报
                // ConnectionReset）；Linux 无连接 UDP 不产 ConnectionReset；
                // `Interrupted` 由 tokio/mio 吞（同 Go netpoll）⇒ 此处加容忍 =
                // 永不命中的死代码，且 Go 同点也 `return`（对拍不判 bug）。
                if closed.load(Ordering::Relaxed) {
                    return;
                }
                crate::hot_log!(tracing::Level::WARN, "error={e} xdns client: recv failed");
                break;
            },
        };
        let Some(idx) =
            state.resolvers.iter().position(|r| matches!(r, Resolver::Udp(a) if *a == addr))
        else {
            continue;
        };
        if client_read(&state, &buf[..n], addr, &read_tx).await {
            state.sends[idx].store(0, Ordering::Relaxed);
            let _ = poll_tx.try_send(());
        }
    }
}

/// 构造查询 message 并按轮转选择 resolver 发送，对应 Go `sendMsg`。
async fn send_msg(
    state: &ClientState,
    inner: &dyn UdpIo,
    p: &[u8],
    domain: &Domain,
    qtype: u16,
) -> io::Result<()> {
    let name = domain.encode(p)?;
    let mut msg = Message {
        id: (rand::rng().next_u32() & 0xffff) as u16,
        flags: 0x0100, // RD=1（Go Header.RecursionDesired）
        question: vec![Question { name, qtype, qclass: CLASS_IN }],
        answer: vec![],
        authority: vec![],
        additional: vec![],
    };
    if domain.edns0() > 0 {
        msg.additional.push(RR {
            name: super::dns::Name::default(),
            rtype: RR_TYPE_OPT,
            rclass: domain.edns0(),
            ttl: 0,
            data: Vec::new(),
        });
    }
    let pack = msg.wire_format()?;
    // Go: pack 后覆写随机 ID 两字节——等价于 id 直接随机（上面已随机）

    // resolver 轮转：从 index 出发找首个 sends[i] < cur，发送仍用 index
    let n = state.resolvers.len();
    let index = state.index.load(Ordering::Relaxed) as usize % n;
    let cur = state.sends[index].fetch_add(1, Ordering::Relaxed) + 1;
    let mut i = index;
    loop {
        i = (i + 1) % n;
        if i == index {
            break;
        }
        if cur > state.sends[i].load(Ordering::Relaxed) {
            break;
        }
    }
    state.index.store(i as u32, Ordering::Relaxed);
    match &state.resolvers[index] {
        Resolver::Udp(addr) => inner.send_to(&pack, *addr).await.map(|_| ()),
        Resolver::Doh(doh) => doh.send(&pack).await,
    }
}

/// DoH 响应解码环：worker 取回的原始 DNS 响应 → 与 UDP 路径同一套解码/拆包
/// （Go `DOHResolver.Read` → `xdnsClient.recv`）。
async fn doh_recv_loop(
    state: Arc<ClientState>,
    mut resp_rx: mpsc::Receiver<(usize, Vec<u8>)>,
    read_tx: mpsc::Sender<Packet>,
    poll_tx: mpsc::Sender<()>,
    closed: Arc<AtomicBool>,
) {
    while let Some((idx, body)) = resp_rx.recv().await {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let addr = match state.resolvers.get(idx) {
            Some(Resolver::Doh(doh)) => doh.remote_addr(),
            // 下标不变量：worker 只回投本 client 的 resolver 下标
            _ => continue,
        };
        if client_read(&state, &body, addr, &read_tx).await {
            state.sends[idx].store(0, Ordering::Relaxed);
            let _ = poll_tx.try_send(());
        }
    }
}

/// 单次 send：随机 domain/qtype，按 poll/small/frag 三形态编码，对应 Go `send`。
async fn send_once(state: &ClientState, inner: &dyn UdpIo, p: &[u8]) -> io::Result<()> {
    let n_domains = state.domains.len();
    let domain_idx = if n_domains == 1 { 0 } else { rand::rng().next_u32() as usize % n_domains };
    let domain = &state.domains[domain_idx];
    let n_types = domain.types_len();
    let qtype = if n_types == 1 {
        domain.qtype_at(0)
    } else {
        domain.qtype_at(rand::rng().next_u32() as usize % n_types)
    };

    let mut data = vec![0u8; 255];
    data[..8].copy_from_slice(&state.client_id);
    data[0] |= type_map(qtype)?;

    if p.is_empty() {
        // poll：17B = clientID + flag + 8B 随机
        data[8] = 8;
        rand::rng().fill_bytes(&mut data[9..17]);
        return send_msg(state, inner, &data[..17], domain, qtype).await;
    }

    if p.len() <= domain.cap - 12 {
        // 小包：clientID + flag + [8]=3 + 3B 随机 + payload
        data[8] = 3;
        rand::rng().fill_bytes(&mut data[9..12]);
        data[12..12 + p.len()].copy_from_slice(p);
        return send_msg(state, inner, &data[..12 + p.len()], domain, qtype).await;
    }

    if p.len() <= 255 * (domain.cap - 15) {
        // 分片：[12]fragID [13]idx [14]fragN + 数据块（≤cap-15）
        data[8] = 3 | 0xC0;
        rand::rng().fill_bytes(&mut data[9..12]);
        let frag_id = state.frag_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u8;
        let unit = domain.cap - 15;
        let frag_n = p.len().div_ceil(unit);
        let mut rest = p;
        for i in 0..frag_n {
            data[12] = frag_id;
            data[13] = i as u8;
            data[14] = frag_n as u8;
            let size = rest.len().min(unit);
            data[15..15 + size].copy_from_slice(&rest[..size]);
            send_msg(state, inner, &data[..15 + size], domain, qtype).await?;
            rest = &rest[size..];
        }
        return Ok(());
    }

    crate::hot_log!(
        tracing::Level::ERROR,
        "len={} xdns client: payload size exceeds domain capacity",
        p.len()
    );
    Ok(())
}

/// send 循环：writeCh / pollCh / pollTimer 多路驱动，对应 Go `send` goroutine。
async fn send_loop(
    state: Arc<ClientState>,
    inner: Arc<dyn UdpIo>,
    closed: Arc<AtomicBool>,
    mut write_rx: mpsc::Receiver<Vec<u8>>,
    mut poll_rx: mpsc::Receiver<()>,
) {
    let mut delay = INIT_POLL_DELAY;
    // DNS 查询发送失败 = 解析面断（查询发不出去 = DNS 全断），必须在生产默认
    // warn 门下可见（Go 同点恒 error 级；DEBUG 不可见，bd u0pe2 ①）。限频：
    // 故障窗首条 + 每 32 条，防上游不可达时随 poll/写入节奏刷屏。
    let mut send_fails = 0u64;
    loop {
        if closed.load(Ordering::Relaxed) {
            return;
        }
        let mut timeout = false;
        let pkt: Option<Vec<u8>> = tokio::select! {
            p = write_rx.recv() => match p {
                Some(p) => Some(p),
                None => return, // 写端关闭（连接关闭）
            },
            _ = poll_rx.recv() => None,
            _ = tokio::time::sleep(delay) => {
                timeout = true;
                None
            },
        };

        // 有真实 payload 时排空积压 poll 通知（Go select default 排空 poolCh）
        if pkt.as_ref().is_some_and(|p| !p.is_empty()) {
            while poll_rx.try_recv().is_ok() {}
        }

        if let Err(e) = send_once(&state, inner.as_ref(), pkt.as_deref().unwrap_or(&[])).await {
            send_fails += 1;
            if send_fails == 1 || send_fails % 32 == 0 {
                crate::hot_log!(
                    tracing::Level::WARN,
                    "fails={send_fails} error={e} xdns client: send failed"
                );
            }
        } else {
            send_fails = 0;
        }
        // extraPoll：真实包后追加的空 poll 包
        for _ in 0..state.extra_poll {
            if let Err(e) = send_once(&state, inner.as_ref(), &[]).await {
                send_fails += 1;
                if send_fails == 1 || send_fails % 32 == 0 {
                    crate::hot_log!(
                        tracing::Level::WARN,
                        "fails={send_fails} error={e} xdns client: extra poll send failed"
                    );
                }
            }
        }

        delay = if timeout { (delay * 2).min(MAX_POLL_DELAY) } else { INIT_POLL_DELAY };
    }
}

#[async_trait]
impl UdpIo for XdnsConnClient {
    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::other("xdns client closed"));
        }
        if buf.is_empty() || buf.len() > UDP_READ_BUF {
            crate::hot_log!(tracing::Level::ERROR, "len={} xdns client: err size", buf.len());
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "err size"));
        }
        let _ = self.write_tx.try_send(buf.to_vec());
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let pkt = { self.read_rx.lock().await.recv().await };
        let Some(pkt) = pkt else {
            return Err(io::Error::other("xdns client closed"));
        };
        let n = pkt.data.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt.data[..n]);
        Ok((n, pkt.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([0u8, 0, 0, 0], 0)))
    }
}
