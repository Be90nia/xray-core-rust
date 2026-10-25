//! # RealmConnClient/Server + UdpIo 桥接（对应 Go `realm/client.go` + `realm/server.go`）
//!
//! 设计要点：
//! - `Arc<dyn UdpIo>` 共享 raw 给 dispatcher + 业务 tasks
//! - dispatcher 长期运行，分类入站 UDP 包（STUN/punch/data）
//! - 业务任务（client init / server session）通过 channels 与 dispatcher 通信
//! - UdpIo::send_to 直接走 raw；UdpIo::recv_from 从 data channel 拉

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use skeleton_infra::fx::FxScope;
use tokio::sync::{Mutex, mpsc};

use crate::finalmask::{
    UDP_SIZE, UdpIo,
    realm::{
        http::{self, Client, ConnectRequest},
        portmap::{PortMapConfig, PortMapper, PortMapping, port_map_loop},
        punch::{PunchMetadata, PunchPacketType, decode_punch_packet, encode_punch_packet},
        stun::{
            DEFAULT_PUNCH_INTERVAL, DEFAULT_PUNCH_TIMEOUT, DEFAULT_STUN_TIMEOUT, TransactionId,
            addr_port_strings, build_binding_request, candidate_punch_addrs,
            expand_symmetric_nat_candidates, is_stun_message, parse_addr_ports,
            parse_stun_binding_response, resolve_stun_servers,
        },
        tls,
    },
};

/// UDP 包通道容量（data 通道 + stun 通道 + punch 通道都按此值）。
const CHANNEL_BUFFER: usize = 64;

/// realm 共享配置（对应 Go `realm.Config`）。
///
/// `tls` = [`tls::TlsConfig`]（Go `TlsConfig *tls.Config` → `GetTLSConfig()` 消费
/// 的字段子集，见 `tls.rs` 对齐表）；`None` = reqwest 默认 rustls 路径。
/// `port_mapping` = 网关 UDP 端口映射（Go `Config.PortMapping`）；`None` = 不开。
#[derive(Debug, Clone, Default)]
pub struct RealmConfig {
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub token: String,
    pub id: String,
    pub stun_servers: Vec<String>,
    pub tls: Option<tls::TlsConfig>,
    pub port_mapping: Option<PortMapping>,
}

/// STUN 反射事件（dispatcher → init task）。
struct StunEvent {
    tx_id: TransactionId,
    addr: SocketAddr,
}

/// Punch 接收事件（dispatcher → punch loop）。
struct PunchEvent {
    addr: SocketAddr,
    packet_type: PunchPacketType,
}

/// 共享状态：dispatcher + 业务 task 都访问。
struct Shared {
    raw: Arc<dyn UdpIo>,
    stun_tx: mpsc::Sender<StunEvent>,
    /// 按 metadata 索引的 punch 接收通道（同一时刻可能有多个 punch 会话）。
    punch_channels: Mutex<HashMap<PunchMetadata, mpsc::Sender<PunchEvent>>>,
    data_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    cancel: Arc<AtomicBool>,
    /// B6（bd t975）：dispatcher/init/punch/heartbeat 后台任务唯一托管口
    /// （坑约束 5）。scope 归 Client/Server conn 持有，conn drop 兜底 abort；
    /// 协作停机仍走 `cancel`。
    fx: Arc<FxScope>,
}

impl Shared {
    /// 托管 spawn 唯一口：内部 scope 无 close 调用（fail-visible 不可达分支）。
    fn spawn<F, T>(&self, fut: F) -> skeleton_infra::fx::Spawned<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.fx.spawn(fut).expect("internal FxScope is never closed")
    }

    /// dispatcher 是否应退出。
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

/// realm 客户端连接（对应 Go `realmConnClient`）。
pub struct RealmConnClient {
    raw: Arc<dyn UdpIo>,
    data_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    peer: Arc<tokio::sync::OnceCell<SocketAddr>>,
    cancel: Arc<AtomicBool>,
}

impl RealmConnClient {
    /// 构造并立即发起后台 STUN/HTTP/punch 流程。
    ///
    /// 所有 init 工作在独立 tokio task 内异步进行；构造本身不阻塞。
    /// peer 确定前 `send_to` 返回 `NotConnected`，确定后透传给 raw。
    pub fn new(config: &RealmConfig, raw: Box<dyn UdpIo>) -> io::Result<Self> {
        let raw: Arc<dyn UdpIo> = Arc::from(raw);
        let (data_tx, data_rx) = mpsc::channel(CHANNEL_BUFFER);
        let (stun_tx, stun_rx) = mpsc::channel(CHANNEL_BUFFER);
        let peer = Arc::new(tokio::sync::OnceCell::new());
        let cancel = Arc::new(AtomicBool::new(false));

        let shared = Arc::new(Shared {
            raw: Arc::clone(&raw),
            stun_tx,
            punch_channels: Mutex::new(HashMap::new()),
            data_tx,
            cancel: Arc::clone(&cancel),
            fx: Arc::new(FxScope::new()),
        });

        shared.spawn(dispatcher_loop(Arc::clone(&shared)));

        let shared_init = Arc::clone(&shared);
        let peer_init = Arc::clone(&peer);
        let config_init = config.clone();
        shared.spawn(async move {
            let _ = client_init(shared_init, stun_rx, config_init, peer_init).await;
            // init 失败：peer 保持 None；send_to 后续返回 NotConnected
        });

        Ok(Self { raw, data_rx: Mutex::new(data_rx), peer, cancel })
    }
}

#[async_trait]
impl UdpIo for RealmConnClient {
    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        // 客户端始终发给已确定的 peer（addr 参数被忽略，与 Go 行为一致）
        let peer = self.peer.get().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "realm: peer not yet determined")
        })?;
        self.raw.send_to(buf, *peer).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut guard = self.data_rx.lock().await;
        match guard.recv().await {
            Some((data, addr)) => {
                if data.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "realm: packet too large for buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                Ok((data.len(), addr))
            },
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "realm: dispatcher closed")),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.raw.local_addr()
    }
}

impl Drop for RealmConnClient {
    fn drop(&mut self) {
        // 触发 dispatcher 退出：下一次 recv_from 出错或 select 触发 cancel
        self.cancel.store(true, Ordering::Release);
    }
}

/// realm 服务端连接（对应 Go `realmConnServer`）。
pub struct RealmConnServer {
    raw: Arc<dyn UdpIo>,
    data_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    cancel: Arc<AtomicBool>,
}

impl RealmConnServer {
    /// 构造并启动 register/heartbeat/events/punch 后台任务。
    pub fn new(config: &RealmConfig, raw: Box<dyn UdpIo>) -> io::Result<Self> {
        let raw: Arc<dyn UdpIo> = Arc::from(raw);
        let (data_tx, data_rx) = mpsc::channel(CHANNEL_BUFFER);
        let (stun_tx, stun_rx) = mpsc::channel(CHANNEL_BUFFER);
        let cancel = Arc::new(AtomicBool::new(false));

        let shared = Arc::new(Shared {
            raw: Arc::clone(&raw),
            stun_tx,
            punch_channels: Mutex::new(HashMap::new()),
            data_tx,
            cancel: Arc::clone(&cancel),
            fx: Arc::new(FxScope::new()),
        });

        shared.spawn(dispatcher_loop(Arc::clone(&shared)));

        let shared_init = Arc::clone(&shared);
        let config_init = config.clone();
        let cancel_clone = Arc::clone(&cancel);
        shared.spawn(async move {
            server_loop(shared_init, stun_rx, config_init, cancel_clone).await;
        });

        Ok(Self { raw, data_rx: Mutex::new(data_rx), cancel })
    }
}

#[async_trait]
impl UdpIo for RealmConnServer {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // 服务端透传给指定 addr
        self.raw.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut guard = self.data_rx.lock().await;
        match guard.recv().await {
            Some((data, addr)) => {
                if data.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "realm: packet too large for buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                Ok((data.len(), addr))
            },
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "realm: dispatcher closed")),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.raw.local_addr()
    }
}

impl Drop for RealmConnServer {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// UDP 包分发循环（对应 Go 各 conn.ReadFrom 内联分发逻辑）。
///
/// 分类规则：
/// 1. STUN 消息（magic cookie 校验）→ stun_tx
/// 2. 与已注册 meta 匹配的 punch 包 → 对应 punch channel
/// 3. 其他 → data_tx（真实代理数据）
async fn dispatcher_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; UDP_SIZE];
    loop {
        if shared.cancelled() {
            break;
        }
        let read_result = shared.raw.recv_from(&mut buf).await;
        let (n, addr) = match read_result {
            Ok(pair) => pair,
            Err(_) => break, // raw 关闭或出错
        };
        let packet = &buf[..n];
        if is_stun_message(packet) {
            if let Ok((tx_id, mapped)) = parse_stun_binding_response(packet) {
                let _ = shared.stun_tx.try_send(StunEvent { tx_id, addr: mapped });
            }
            continue;
        }
        // 尝试匹配已注册 meta（punch 包）
        let punch_channels = shared.punch_channels.lock().await;
        let mut matched = false;
        for (meta, tx) in punch_channels.iter() {
            if let Ok(p) = decode_punch_packet(packet, meta) {
                let _ = tx.try_send(PunchEvent { addr, packet_type: p.packet_type });
                matched = true;
                break;
            }
        }
        drop(punch_channels);
        if matched {
            continue;
        }
        // 真实代理数据包
        let _ = shared.data_tx.try_send((packet.to_vec(), addr));
    }
}

/// 客户端 init：STUN 反射 → HTTP Connect → 注册 punch channel → spawn punch loop。
async fn client_init(
    shared: Arc<Shared>,
    mut stun_rx: mpsc::Receiver<StunEvent>,
    config: RealmConfig,
    peer: Arc<tokio::sync::OnceCell<SocketAddr>>,
) -> io::Result<()> {
    let client = http::new_client(
        &config.scheme,
        &config.host,
        &config.port,
        &config.token,
        config.tls.as_ref(),
    )?;
    let local_ip = shared.raw.local_addr().ok().map(|sa| sa.ip());
    let servers = resolve_stun_servers(local_ip, &config.stun_servers);
    if servers.is_empty() {
        return Err(io::Error::other("realm: no stun servers"));
    }

    // 1. 向所有 STUN 服务器发 Binding Request
    let mut tx_ids: std::collections::HashSet<TransactionId> = std::collections::HashSet::new();
    for server in &servers {
        let (req, tx_id) = build_binding_request();
        tx_ids.insert(tx_id);
        let _ = shared.raw.send_to(&req, *server).await;
    }

    // 2. 收集 STUN 反射地址（直到所有 tx_id 都响应或超时）
    let mut locals: Vec<SocketAddr> = Vec::new();
    let deadline = tokio::time::sleep(DEFAULT_STUN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = stun_rx.recv() => match ev {
                Some(ev) if tx_ids.contains(&ev.tx_id) => {
                    locals.push(ev.addr);
                    tx_ids.remove(&ev.tx_id);
                    if tx_ids.is_empty() { break; }
                }
                _ => {}
            }
        }
    }
    if locals.is_empty() {
        return Err(io::Error::other("realm: no stun locals"));
    }

    // 3. HTTP Connect 获取 peers
    let meta = http::new_punch_metadata()?;
    let req = ConnectRequest { addresses: addr_port_strings(&locals), metadata: meta.clone() };
    let resp =
        client.connect(&config.id, &req).await.map_err(|e| io::Error::other(e.to_string()))?;
    let peers = parse_addr_ports(&resp.addresses).unwrap_or_default();

    // 4. NAT 端口预测扩展
    let (filtered, mut seen) = candidate_punch_addrs(&locals, &peers);
    let expanded = expand_symmetric_nat_candidates(filtered, &mut seen);
    if expanded.is_empty() {
        return Err(io::Error::other("realm: no peers after expansion"));
    }

    // 5. 注册 punch channel，启动 punch loop
    let (punch_tx, punch_rx) = mpsc::channel(CHANNEL_BUFFER);
    shared.punch_channels.lock().await.insert(meta.clone(), punch_tx);

    let raw = Arc::clone(&shared.raw);
    let meta_loop = meta.clone();
    shared.spawn(client_punch_loop(
        Arc::clone(&shared),
        raw,
        meta_loop,
        expanded,
        punch_rx,
        peer,
        config.port_mapping,
    ));
    Ok(())
}

/// 客户端 punch 循环：周期性发 Hello，收到任意 punch 包则确定 peer 退出；
/// punch 成功后按配置启动网关端口映射续租循环（Go `client.go:123-124` 同序）。
async fn client_punch_loop(
    shared: Arc<Shared>,
    raw: Arc<dyn UdpIo>,
    meta: PunchMetadata,
    peers: Vec<SocketAddr>,
    mut punch_rx: mpsc::Receiver<PunchEvent>,
    peer: Arc<tokio::sync::OnceCell<SocketAddr>>,
    port_mapping: Option<PortMapping>,
) {
    let deadline = tokio::time::Instant::now() + DEFAULT_PUNCH_TIMEOUT;
    let mut ticker = tokio::time::interval(DEFAULT_PUNCH_INTERVAL);
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        // 发送 Hello 给所有候选 peer
        match encode_punch_packet(PunchPacketType::Hello, &meta) {
            Ok(packet) => {
                for p in &peers {
                    let _ = raw.send_to(&packet, *p).await;
                }
            },
            Err(_) => break,
        }
        tokio::select! {
            _ = ticker.tick() => continue,
            ev = punch_rx.recv() => {
                if let Some(ev) = ev {
                    // 收到 Hello → 回 Ack；任意 punch → peer 已确定
                    if ev.packet_type == PunchPacketType::Hello {
                        if let Ok(packet) = encode_punch_packet(PunchPacketType::Ack, &meta) {
                            let _ = raw.send_to(&packet, ev.addr).await;
                        }
                    }
                    let _ = peer.set(ev.addr);
                    break;
                }
            }
        }
    }
    if peer.get().is_some()
        && let Some(port_mapping) = port_mapping
        && port_mapping.enabled
    {
        start_port_mapping(&shared, port_mapping);
    }
}

/// 网关端口映射：初始化失败只记 warn、不中断连接（Go `client.go:52-54`）；
/// 成功后进入续租循环，conn cancel 时删映射。
///
/// `shortcut:` conn 被 drop（FxScope abort）时不会发删除报文，映射留待网关按
/// lifetime 到期回收；升级点 = 需要「drop 即回收」时改由显式 shutdown 路径 await close。
fn start_port_mapping(shared: &Arc<Shared>, port_mapping: PortMapping) {
    let config =
        match PortMapConfig::from_secs(port_mapping.timeout_secs, port_mapping.lifetime_secs) {
            Ok(config) => config,
            Err(e) => {
                crate::LOG.warn(format!("[realm] [port mapping] config rejected: {e}"));
                return;
            },
        };
    let local_port = match shared.raw.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            crate::LOG.warn(format!("[realm] [port mapping] local addr unavailable: {e}"));
            return;
        },
    };
    let cancel = Arc::clone(&shared.cancel);
    shared.spawn(async move {
        match PortMapper::new(local_port, config).await {
            Ok(mapper) => {
                crate::LOG.debug(format!(
                    "[realm] [port mapping] [{local_port}] gateway {}, external {:?}",
                    mapper.gateway_type(),
                    mapper.external_addr()
                ));
                port_map_loop(&mapper, &cancel).await;
            },
            Err(e) => {
                crate::LOG.warn(format!("[realm] [port mapping] [{local_port}] init failed: {e}"))
            },
        }
    });
}

/// 服务端主循环：register → heartbeat/events/punch 并发 → 失败重连。
///
/// ponytail: 完整 server 需要并发 heartbeat + events 流 + 多 punch 会话；
/// 当前为骨架版本（register 成功后等待 cancel 或 session 异常）。
/// 业务级端到端测试不覆盖，留作后续迭代。
async fn server_loop(
    shared: Arc<Shared>,
    mut stun_rx: mpsc::Receiver<StunEvent>,
    config: RealmConfig,
    cancel: Arc<AtomicBool>,
) {
    let client = match http::new_client(
        &config.scheme,
        &config.host,
        &config.port,
        &config.token,
        config.tls.as_ref(),
    ) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut backoff = Duration::from_secs(1);
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }

        // STUN 反射（用于 register 的 addresses 字段）
        let locals = collect_stun_locals(Arc::clone(&shared), &mut stun_rx, &config).await;

        // register
        let resp = match client.register(&config.id, locals).await {
            Ok(r) => r,
            Err(_) => {
                if wait_or_cancel(&cancel, backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            },
        };
        backoff = Duration::from_secs(1);
        let session_id = resp.session_id;
        let ttl = resp.ttl.max(1) as u64;

        // 进入 session：heartbeat + events + per-event ConnectResponse + punch
        let session_cancel = Arc::new(AtomicBool::new(false));
        let session_cancel_clone = Arc::clone(&session_cancel);

        // heartbeat 子任务
        let client_hb = client.clone();
        let config_hb = config.clone();
        let sid_hb = session_id.clone();
        let session_cancel_hb = Arc::clone(&session_cancel);
        shared.spawn(async move {
            heartbeat_loop(client_hb, config_hb, sid_hb, ttl, session_cancel_hb).await;
        });

        // events + punch 主循环（在 session_cancel 之前持续）
        server_session(
            Arc::clone(&shared),
            client.clone(),
            config.clone(),
            session_id.clone(),
            session_cancel_clone,
        )
        .await;

        // session 结束：重连前退避
        if wait_or_cancel(&cancel, backoff).await {
            break;
        }
    }
}

/// 收集 STUN 反射地址（服务端 register 前调用）。
async fn collect_stun_locals(
    shared: Arc<Shared>,
    stun_rx: &mut mpsc::Receiver<StunEvent>,
    config: &RealmConfig,
) -> Vec<String> {
    let local_ip = shared.raw.local_addr().ok().map(|sa| sa.ip());
    let servers = resolve_stun_servers(local_ip, &config.stun_servers);
    if servers.is_empty() {
        return Vec::new();
    }
    let mut tx_ids: std::collections::HashSet<TransactionId> = std::collections::HashSet::new();
    for server in &servers {
        let (req, tx_id) = build_binding_request();
        tx_ids.insert(tx_id);
        let _ = shared.raw.send_to(&req, *server).await;
    }
    let mut locals = Vec::new();
    let deadline = tokio::time::sleep(DEFAULT_STUN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = stun_rx.recv() => match ev {
                Some(ev) if tx_ids.contains(&ev.tx_id) => {
                    locals.push(ev.addr);
                    tx_ids.remove(&ev.tx_id);
                    if tx_ids.is_empty() { break; }
                }
                _ => {}
            }
        }
    }
    addr_port_strings(&locals)
}

/// heartbeat 循环（对应 Go `server.(*realmConnServer).heartbeat`）。
async fn heartbeat_loop(
    client: Client,
    config: RealmConfig,
    session_id: String,
    ttl_secs: u64,
    cancel: Arc<AtomicBool>,
) {
    let interval = Duration::from_secs(ttl_secs.max(1) / 2).max(Duration::from_secs(1));
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let req = crate::finalmask::realm::http::HeartbeatRequest::default();
        if client.heartbeat(&config.id, &session_id, &req).await.is_err() {
            break;
        }
    }
}

/// 服务端单次 session 主体（events 流 + punch 响应）。
///
/// ponytail: 完整实现需要处理 SSE 多事件类型 + 多并发 punch 会话；
/// 当前为简化骨架，仅维持 session 直到 cancel。
async fn server_session(
    _shared: Arc<Shared>,
    _client: Client,
    _config: RealmConfig,
    _session_id: String,
    cancel: Arc<AtomicBool>,
) {
    // 完整实现（后续迭代）：
    //   let mut stream = client.events(&config.id, &session_id).await?;
    //   while let Some(ev) = stream.next_event().await? {
    //       spawn ConnectResponse + register punch channel + spawn server_punch_loop
    //   }
    // 简化：等待 cancel
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// 在 cancel 信号或超时上等待；返回 true 表示被 cancel，false 表示超时。
async fn wait_or_cancel(cancel: &Arc<AtomicBool>, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        () = wait_cancel(cancel.clone()) => true,
    }
}

/// 等待 cancel 标志翻转为 true（轮询模式，1s 间隔）。
async fn wait_cancel(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_constructs_without_stun_servers_returns_error_via_init() {
        // 无 STUN 服务器：构造成功（不阻塞），但 init task 会失败。
        // peer 应保持 None，send_to 返回 NotConnected。
        let config = RealmConfig {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: "1".into(),
            token: "tok".into(),
            id: "test".into(),
            stun_servers: vec![],
            tls: None,
            port_mapping: None,
        };
        let raw: Box<dyn UdpIo> =
            Box::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = RealmConnClient::new(&config, raw).expect("construct");
        // 等待 init task 跑完（无 STUN 服务器应几乎立即失败）
        tokio::time::sleep(Duration::from_millis(100)).await;
        let err = client.send_to(b"hello", "127.0.0.1:9999".parse().unwrap()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_constructs_and_drop_signals_cancel() {
        let config = RealmConfig::default();
        let raw: Box<dyn UdpIo> =
            Box::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = RealmConnServer::new(&config, raw).expect("construct");
        // 简单验证：drop 不 panic
        drop(server);
    }

    #[test]
    fn realm_config_default_is_empty() {
        let c = RealmConfig::default();
        assert!(c.scheme.is_empty());
        assert!(c.stun_servers.is_empty());
        assert!(c.tls.is_none());
    }
}
