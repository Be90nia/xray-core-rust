//! 入站 worker 实现
//!
//! 对应 Go `app/proxyman/inbound/worker.go`：tcpWorker / udpWorker / dsWorker。
//!
//! 每个 worker 持有一个 transport listener（TCP/UDP/Unix），accept 后构造
//! `Session` 并调用 `ProxyInbound::process()` 交给具体代理协议处理。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::RwLock;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tracing::{info, warn};
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    session::{Inbound, Outbound, Session},
    signal::ActivityTimer,
};
use xray_features::{policy::DEFAULT_CONN_IDLE_TIMEOUT, stats::Counter};
use xray_mux::worker::Dispatcher;
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    listener_registry::{ConnHandler, TransportListener, listen_tcp},
    sockopt::SocketOptions,
    udp::hub::{Capacity, HubOption, UdpHub, UdpPacket},
};

use crate::{config::SniffingRequest, error::ProxymanError};

// ===== ProxyInbound trait =====

/// 入站代理处理 trait。对应 Go `proxy.Inbound`。
///
/// 具体代理协议（HTTP/SOCKS/VLESS/VMess/Trojan 等）实现此 trait，
/// 在 `process` 中完成协议握手 + 流量转发。
#[async_trait::async_trait]
pub trait ProxyInbound: Send + Sync {
    /// 处理入站连接。
    ///
    /// `network` 区分 TCP/UDP；`conn` 承载实际 IO；`session` 携带路由元数据；
    /// `dispatcher` 用于出站分发。
    async fn process(
        &self,
        network: Network,
        conn: InboundConn,
        session: Session,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<(), ProxymanError>;
}

// ===== InboundConn enum =====

/// 入站连接载体。TCP 用 `Box<dyn Connection>`，UDP 用 `Arc<UdpSession>`。
pub enum InboundConn {
    Tcp(Box<dyn Connection>),
    Udp(Arc<UdpSession>),
}

// ===== Worker trait =====

/// 入站 worker trait。对应 Go `worker interface`。
///
/// 每个 worker 绑定一个监听地址，`start` 创建 listener + accept 循环，
/// `close` 通知退出 + 关闭 listener。
#[async_trait::async_trait]
pub trait Worker: Send + Sync {
    /// 启动监听。
    ///
    /// 要求 `Arc<Self>`：accept/收包闭包须持有 worker 引用才能回调
    /// `on_conn`/`on_packet`（对齐 Go `worker.go` 中 `tcpWorker.Start`
    /// 直接访问 receiver 的形态；`&self` 无法安全升级为共享引用）。
    async fn start(self: Arc<Self>) -> Result<(), ProxymanError>;
    /// 关闭监听。
    async fn close(&self) -> Result<(), ProxymanError>;
    /// 监听端口。
    fn port(&self) -> u16;
}

// ===== UdpSession =====

/// UDP 会话。对应 Go `udpConn`。
///
/// 每个 UDP source 地址对应一个 `UdpSession`，通过 mpsc channel 读写包。
/// 空闲超时后标记 inactive，由 cleanup task 清理。
#[allow(dead_code)] // uplink/downlink used by proxy implementations
pub struct UdpSession {
    last_activity: AtomicI64,
    /// 入方向（hub 收到的客户端包）。proxy 经 [`Self::recv`] 消费。
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// 入方向消费端；`Mutex` 为 `recv(&self)` 提供内部可变性。
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// 出方向（proxy 回包）。worker 响应泵消费后 `hub.send_to(source)`。
    outbound_tx: mpsc::Sender<Vec<u8>>,
    source: SocketAddr,
    local: SocketAddr,
    uplink: Option<Arc<dyn Counter>>,
    downlink: Option<Arc<dyn Counter>>,
    inactive: AtomicBool,
}

impl UdpSession {
    /// 创建 UDP 会话，返回 `(Arc<Self>, 出方向 Receiver)`。
    ///
    /// Go `udpConn` 双 channel 同构（worker.go）：
    /// - 入方向：hub 收包 `push_inbound` 写入，proxy 经 `recv()` 消费；
    /// - 出方向：proxy `write_packet` 写入，**返回的 Receiver** 由 worker 响应泵消费后
    ///   `hub.send_to(source)` 回包（Go `for p := range conn.writing`）。
    ///
    /// 修复（audit ojcy）：旧实现 `(tx, _rx)` 将消费端随 new 返回即丢弃，
    /// write_packet 恒失败且无人可达——收发端就此全断。
    pub fn new(
        source: SocketAddr,
        local: SocketAddr,
        uplink: Option<Arc<dyn Counter>>,
        downlink: Option<Arc<dyn Counter>>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let session = Arc::new(Self {
            last_activity: AtomicI64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ),
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            outbound_tx,
            source,
            local,
            uplink,
            downlink,
            inactive: AtomicBool::new(false),
        });
        (session, outbound_rx)
    }

    /// 更新最后活动时间戳。
    pub fn update_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// 标记为不活跃。
    pub fn set_inactive(&self) {
        self.inactive.store(true, Ordering::Relaxed);
    }

    /// 是否已标记不活跃。
    pub fn is_inactive(&self) -> bool {
        self.inactive.load(Ordering::Relaxed)
    }

    /// 最后活动时间（秒级 UNIX 时间戳）。
    pub fn last_activity_secs(&self) -> i64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// 来源地址。
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// 本地地址。
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// 入方向：hub 收到的客户端包入队（Go worker.go `conn.channel <- p`）。
    ///
    /// channel 满时丢弃（与 Go `select { case c <- payload: default: }` 一致）。
    pub fn push_inbound(&self, data: Vec<u8>) {
        if self.inactive.load(Ordering::Relaxed) {
            return;
        }
        // ponytail: channel 满时丢弃，与 Go 行为一致
        let _ = self.inbound_tx.try_send(data);
    }

    /// proxy 消费客户端包（Go `udpConn.Read`：`p := <-c.channel`）。
    ///
    /// 返回 `None` = 会话已关闭（所有入方向发送端丢弃）。
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.inbound_rx.lock().await.recv().await
    }

    /// 出方向：proxy 回包（Go `udpConn.Write`：`c.writing <- p`，阻塞语义）。
    ///
    /// 包由 worker 响应泵消费后经 `hub.send_to` 发回客户端。
    pub async fn write_packet(&self, data: Vec<u8>) {
        if self.inactive.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.outbound_tx.send(data).await;
    }
}

// ===== TcpWorker =====

/// TCP 入站 worker。对应 Go `tcpWorker`。
///
/// 使用 `Arc<TcpWorker>` 模式避免 self-referential 生命周期问题：
/// `start()` 要求 `Arc<Self>` 以便将引用传入 ConnHandler 闭包。
#[allow(dead_code)] // recv_orig_dest/sniffing_request/counters used by future features
pub struct TcpWorker {
    address: SocketAddr,
    port: u16,
    proxy: Arc<dyn ProxyInbound>,
    stream_settings: StreamSettings,
    sockopt: SocketOptions,
    recv_orig_dest: bool,
    tag: String,
    dispatcher: Arc<dyn Dispatcher>,
    sniffing_request: SniffingRequest,
    uplink_counter: Option<Arc<dyn Counter>>,
    downlink_counter: Option<Arc<dyn Counter>>,
    listener: Mutex<Option<Box<dyn TransportListener>>>,
    close_notify: Arc<Notify>,
    closed: AtomicBool,
}

impl std::fmt::Debug for TcpWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpWorker")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("tag", &self.tag)
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl TcpWorker {
    /// 构造 TCP worker。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: SocketAddr,
        port: u16,
        proxy: Arc<dyn ProxyInbound>,
        stream_settings: StreamSettings,
        sockopt: SocketOptions,
        recv_orig_dest: bool,
        tag: impl Into<String>,
        dispatcher: Arc<dyn Dispatcher>,
        sniffing_request: SniffingRequest,
        uplink_counter: Option<Arc<dyn Counter>>,
        downlink_counter: Option<Arc<dyn Counter>>,
    ) -> Self {
        Self {
            address,
            port,
            proxy,
            stream_settings,
            sockopt,
            recv_orig_dest,
            tag: tag.into(),
            dispatcher,
            sniffing_request,
            uplink_counter,
            downlink_counter,
            listener: Mutex::new(None),
            close_notify: Arc::new(Notify::new()),
            closed: AtomicBool::new(false),
        }
    }

    fn on_conn(self: &Arc<Self>, conn: Box<dyn Connection>) {
        self.spawn_conn(conn, DEFAULT_CONN_IDLE_TIMEOUT);
    }

    /// 启动单连接处理。`idle_timeout` 为测试缝（生产取 policy 默认值）。
    ///
    /// 返回 JoinHandle 供测试等待连接任务结束；`on_conn` 生产路径丢弃之。
    fn spawn_conn(
        self: &Arc<Self>,
        conn: Box<dyn Connection>,
        idle_timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        if self.closed.load(Ordering::SeqCst) {
            return tokio::spawn(async {});
        }

        let tag = self.tag.clone();
        let address = self.address;
        let port = self.port;
        let proxy = Arc::clone(&self.proxy);
        let dispatcher = Arc::clone(&self.dispatcher);

        let inbound = Inbound::new().with_tag(&tag).with_network(Network::TCP);

        let gateway = Destination::new(Address::from(address.ip()), Port::new(port), Network::TCP);

        let session = Session::new()
            .with_inbound(inbound)
            .with_outbound(Outbound::new().with_destination_override(gateway));

        // 不活动计时器（Go CancelAfterInactivity）：Arc 共享——run 循环 task
        // 与 IO 装饰器同时持引用，读写路径经装饰器持续 update_activity。
        // （audit 95ar：旧实现 timer 为局部值，全文件无 update_activity 调用，
        // 滑动窗口退化为固定总寿命——满速下载 300s 即被杀。）
        let activity_timer = Arc::new(ActivityTimer::new(idle_timeout));
        let mut done_signal = activity_timer.done_signal();

        let timer_loop = Arc::clone(&activity_timer);
        tokio::spawn(async move {
            timer_loop.run().await;
        });

        // IO 活动装饰器：每次读/写就绪即重置空闲窗口（Go 代理 IO 循环 Update）。
        // proxy 是黑盒 trait，活动信号在 Connection 层拦截——有 IO 即有活动。
        let tracked: Box<dyn Connection> =
            Box::new(ActivityTrackingConn { inner: conn, timer: activity_timer });
        // bd mvsc：task 挂 worker 生命周期信号（同构响应泵 close_notify 先例），
        // worker close 唤醒后连接 task 随 select 退出——无孤儿。
        let close_notify = Arc::clone(&self.close_notify);
        let handle = tokio::spawn(async move {
            let inbound_conn = InboundConn::Tcp(tracked);
            tokio::select! {
                result = proxy.process(Network::TCP, inbound_conn, session, dispatcher) => {
                    if let Err(e) = result {
                        warn!(tag = %tag, error = %e, "proxy process failed");
                    }
                    // 正常结束，无需额外操作
                }
                _ = done_signal.wait() => {
                    // 不活动超时，连接被半关闭
                    warn!(tag = %tag, timeout = ?idle_timeout, "connection cancelled after inactivity");
                }
                _ = close_notify.notified() => {
                    // worker close：结构化收尾
                }
            }
        });
        handle
    }
}

/// IO 活动感知连接装饰器（audit 95ar）。
///
/// 委托内部连接并在每次读/写就绪时调用 `timer.update_activity()`，
/// 对齐 Go `CancelAfterInactivity` + IO 路径持续 `Update` 的滑动窗口语义。
struct ActivityTrackingConn {
    inner: Box<dyn Connection>,
    timer: Arc<ActivityTimer>,
}

impl AsyncRead for ActivityTrackingConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            if !buf.filled().is_empty() {
                this.timer.update_activity();
            }
        }
        res
    }
}

impl AsyncWrite for ActivityTrackingConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if res.is_ready() {
            this.timer.update_activity();
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl Connection for ActivityTrackingConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    fn close_read(&mut self) -> io::Result<()> {
        self.inner.close_read()
    }

    fn close_write(&mut self) -> io::Result<()> {
        self.inner.close_write()
    }

    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        self.inner.raw_tcp_clone()
    }
}

#[async_trait::async_trait]
impl Worker for TcpWorker {
    async fn start(self: Arc<Self>) -> Result<(), ProxymanError> {
        let this = Arc::clone(&self);
        let handler: ConnHandler = Arc::new(move |conn| {
            this.on_conn(conn);
        });

        let listener =
            listen_tcp(self.address, self.stream_settings.clone(), self.sockopt.clone(), handler)
                .await
                .map_err(|e| ProxymanError::ListenSocketFailed(e.to_string()))?;

        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(self.port);

        info!(
            tag = %self.tag,
            address = %self.address,
            port = actual_port,
            "TCP worker started"
        );

        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener);

        // ponytail: port 字段在 port=0 时应更新为 actual_port，
        // 但 self.port 非 mut。当前用 AtomicU16 或外部更新替代，
        // 暂保留初始值——实际场景 port 通常由配置指定。
        let _ = actual_port;

        Ok(())
    }

    async fn close(&self) -> Result<(), ProxymanError> {
        self.closed.store(true, Ordering::SeqCst);
        self.close_notify.notify_waiters();

        let listener = self.listener.lock().unwrap_or_else(|e| e.into_inner()).take();

        if let Some(l) = listener {
            l.close().map_err(|e| ProxymanError::CloseAllFailed(e.to_string()))?;
        }

        info!(tag = %self.tag, "TCP worker closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

// ===== UdpWorker =====

/// UDP 入站 worker。对应 Go `udpWorker`。
///
/// 使用 `Arc<UdpWorker>` 模式，与 TcpWorker 一致。
#[allow(dead_code)] // stream_settings/sockopt/sniffing_request used by future features
pub struct UdpWorker {
    proxy: Arc<dyn ProxyInbound>,
    address: SocketAddr,
    port: u16,
    tag: String,
    stream_settings: StreamSettings,
    sockopt: SocketOptions,
    dispatcher: Arc<dyn Dispatcher>,
    sniffing_request: SniffingRequest,
    uplink_counter: Option<Arc<dyn Counter>>,
    downlink_counter: Option<Arc<dyn Counter>>,
    hub: Mutex<Option<Arc<UdpHub>>>,
    active_sessions: RwLock<HashMap<SocketAddr, Arc<UdpSession>>>,
    close_notify: Arc<Notify>,
    closed: AtomicBool,
    recv_handle: Mutex<Option<JoinHandle<()>>>,
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for UdpWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpWorker")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("tag", &self.tag)
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl UdpWorker {
    /// 构造 UDP worker。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy: Arc<dyn ProxyInbound>,
        address: SocketAddr,
        port: u16,
        tag: impl Into<String>,
        stream_settings: StreamSettings,
        sockopt: SocketOptions,
        dispatcher: Arc<dyn Dispatcher>,
        sniffing_request: SniffingRequest,
        uplink_counter: Option<Arc<dyn Counter>>,
        downlink_counter: Option<Arc<dyn Counter>>,
    ) -> Self {
        Self {
            proxy,
            address,
            port,
            tag: tag.into(),
            stream_settings,
            sockopt,
            dispatcher,
            sniffing_request,
            uplink_counter,
            downlink_counter,
            hub: Mutex::new(None),
            active_sessions: RwLock::new(HashMap::new()),
            close_notify: Arc::new(Notify::new()),
            closed: AtomicBool::new(false),
            recv_handle: Mutex::new(None),
            cleanup_handle: Mutex::new(None),
        }
    }

    fn on_packet(self: &Arc<Self>, packet: &UdpPacket, local_addr: SocketAddr) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        let source = packet.source;

        // 查找已有 session：入方向包入队（Go `conn.channel <- p`）
        if let Some(session) = self.active_sessions.read().get(&source).cloned() {
            session.update_activity();
            session.push_inbound(packet.payload.clone());
            return;
        }

        // 创建新 session；outbound_rx 交给响应泵（audit ojcy：旧实现
        // `_sender`/`_rx` 双双丢弃，收发两端全断，包进 channel 即消亡）。
        let (session, outbound_rx) = UdpSession::new(
            source,
            local_addr,
            self.uplink_counter.clone(),
            self.downlink_counter.clone(),
        );

        // 写入首包
        session.push_inbound(packet.payload.clone());

        // 注册 session
        self.active_sessions.write().insert(source, Arc::clone(&session));

        // spawn proxy.process()
        let tag = self.tag.clone();
        let address = self.address;
        let port = self.port;
        let proxy = Arc::clone(&self.proxy);
        let dispatcher = Arc::clone(&self.dispatcher);

        let inbound = Inbound::new().with_tag(&tag).with_network(Network::UDP);

        let gateway = Destination::new(Address::from(address.ip()), Port::new(port), Network::UDP);

        let session_ctx = Session::new()
            .with_inbound(inbound)
            .with_outbound(Outbound::new().with_destination_override(gateway));

        let pump_session = Arc::clone(&session);
        // bd mvsc：process task 挂 close_notify，worker close 时随 select 退出
        let close_notify = Arc::clone(&self.close_notify);
        tokio::spawn(async move {
            let inbound_conn = InboundConn::Udp(session);
            tokio::select! {
                r = proxy.process(Network::UDP, inbound_conn, session_ctx, dispatcher) => {
                    if let Err(e) = r {
                        warn!(tag = %tag, error = %e, "UDP proxy process failed");
                    }
                }
                _ = close_notify.notified() => {
                    // worker close：结构化收尾
                }
            }
        });

        // 响应泵（Go worker.go `for p := range conn.writing { hub.WriteTo }`）：
        // proxy write_packet → 本循环 → hub.send_to(session.source) 回客户端。
        let hub = self.hub.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(Arc::clone);
        if let Some(hub) = hub {
            let close_notify = Arc::clone(&self.close_notify);
            tokio::spawn(async move {
                let mut outbound_rx = outbound_rx;
                loop {
                    tokio::select! {
                        resp = outbound_rx.recv() => {
                            match resp {
                                Some(data) => {
                                    if let Err(e) = hub.send_to(&data, pump_session.source()).await {
                                        warn!(error = %e, "UDP hub send_to failed");
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = close_notify.notified() => {
                            break;
                        }
                    }
                }
            });
        }
    }

    /// 清理空闲超过 policy timeout 的 UDP session。
    fn cleanup_inactive(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut sessions = self.active_sessions.write();
        let before = sessions.len();
        let timeout_secs = DEFAULT_CONN_IDLE_TIMEOUT.as_secs() as i64;
        sessions.retain(|_addr, s| {
            let idle_secs = now - s.last_activity_secs();
            if idle_secs > timeout_secs {
                s.set_inactive();
                false
            } else {
                true
            }
        });
        let removed = before - sessions.len();
        if removed > 0 {
            info!(tag = %self.tag, removed, "cleaned up inactive UDP sessions");
        }
    }
}

#[async_trait::async_trait]
impl Worker for UdpWorker {
    async fn start(self: Arc<Self>) -> Result<(), ProxymanError> {
        let options: Vec<Box<dyn HubOption>> = vec![Box::new(Capacity(256))];
        let hub = UdpHub::listen(self.address, &options, None)
            .await
            .map_err(|e| ProxymanError::ListenSocketFailed(e.to_string()))?;

        let actual_port = hub.local_addr().map(|a| a.port()).unwrap_or(self.port);

        info!(
            tag = %self.tag,
            address = %self.address,
            port = actual_port,
            "UDP worker started"
        );

        // split：收包 rx 由本 worker 消费，共享发送端（send_to/close/local_addr）
        // 留在 Arc<UdpHub>——audit ojcy：旧实现 receive() 消费 hub 后 worker 不再
        // 持有任何发送端，hub.WriteTo 回包通道不可达。
        let (mut rx, hub) = hub.split();
        let local_addr = hub.local_addr().unwrap_or(self.address);
        *self.hub.lock().unwrap_or_else(|e| e.into_inner()) = Some(hub);

        // Spawn recv loop
        let close_notify = Arc::clone(&self.close_notify);
        let this = Arc::clone(&self);

        let recv_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    packet = rx.recv() => {
                        match packet {
                            Some(p) => {
                                this.on_packet(&p, local_addr);
                            }
                            None => break,
                        }
                    }
                    _ = close_notify.notified() => {
                        break;
                    }
                }
            }
        });

        // Spawn cleanup task (every 60s)
        let close_notify2 = Arc::clone(&self.close_notify);
        let this2 = Arc::clone(&self);
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        this2.cleanup_inactive();
                    }
                    _ = close_notify2.notified() => {
                        break;
                    }
                }
            }
        });

        *self.recv_handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(recv_handle);
        *self.cleanup_handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(cleanup_handle);

        Ok(())
    }

    async fn close(&self) -> Result<(), ProxymanError> {
        self.closed.store(true, Ordering::SeqCst);
        self.close_notify.notify_waiters();

        // Close hub
        let hub = self.hub.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = hub {
            h.close().map_err(|e| ProxymanError::CloseAllFailed(e.to_string()))?;
        }

        // Abort handles
        let recv = self.recv_handle.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = recv {
            h.abort();
        }

        let cleanup = self.cleanup_handle.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = cleanup {
            h.abort();
        }

        // Mark all sessions inactive
        let sessions = self.active_sessions.read();
        for s in sessions.values() {
            s.set_inactive();
        }

        info!(tag = %self.tag, "UDP worker closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

// ===== DsWorker =====

/// Unix domain socket 入站 worker。对应 Go `dsWorker`。
///
/// 当前为 stub——Unix domain socket 监听需要平台特定实现。
pub struct DsWorker {
    tag: String,
    closed: AtomicBool,
}

impl std::fmt::Debug for DsWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsWorker")
            .field("tag", &self.tag)
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl DsWorker {
    /// 构造 Unix domain socket worker。
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into(), closed: AtomicBool::new(false) }
    }
}

#[async_trait::async_trait]
impl Worker for DsWorker {
    async fn start(self: Arc<Self>) -> Result<(), ProxymanError> {
        // ponytail: Unix domain socket not yet supported, stub
        Err(ProxymanError::ListenSocketFailed("Unix domain socket not yet supported".to_string()))
    }

    async fn close(&self) -> Result<(), ProxymanError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn port(&self) -> u16 {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct NoopProxy;

    #[async_trait::async_trait]
    impl ProxyInbound for NoopProxy {
        async fn process(
            &self,
            _network: Network,
            _conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            Ok(())
        }
    }

    struct NoopDispatcher;

    #[async_trait::async_trait]
    impl Dispatcher for NoopDispatcher {
        async fn dispatch(
            &self,
            _dest: Destination,
        ) -> Result<xray_mux::client::Link, xray_mux::worker::DispatchError> {
            Err(xray_mux::worker::DispatchError::NoRoute("test".to_string()))
        }
    }

    fn make_proxy() -> Arc<dyn ProxyInbound> {
        Arc::new(NoopProxy)
    }

    fn make_dispatcher() -> Arc<dyn Dispatcher> {
        Arc::new(NoopDispatcher)
    }

    #[test]
    fn tcp_worker_construction() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let worker = TcpWorker::new(
            addr,
            1080,
            make_proxy(),
            StreamSettings::tcp(),
            SocketOptions::default(),
            false,
            "http-in",
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        );
        assert_eq!(worker.port(), 1080);
        assert!(!worker.closed.load(Ordering::SeqCst));
    }

    #[test]
    fn tcp_worker_debug_format() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let worker = TcpWorker::new(
            addr,
            1080,
            make_proxy(),
            StreamSettings::tcp(),
            SocketOptions::default(),
            false,
            "test-tag",
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        );
        let debug = format!("{worker:?}");
        assert!(debug.contains("test-tag"));
        assert!(debug.contains("1080"));
    }

    #[test]
    fn udp_worker_construction() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let worker = UdpWorker::new(
            make_proxy(),
            addr,
            1080,
            "socks-in",
            StreamSettings::tcp(),
            SocketOptions::default(),
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        );
        assert_eq!(worker.port(), 1080);
        assert!(!worker.closed.load(Ordering::SeqCst));
    }

    #[test]
    fn udp_worker_debug_format() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let worker = UdpWorker::new(
            make_proxy(),
            addr,
            1080,
            "udp-tag",
            StreamSettings::tcp(),
            SocketOptions::default(),
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        );
        let debug = format!("{worker:?}");
        assert!(debug.contains("udp-tag"));
    }

    #[test]
    fn ds_worker_construction() {
        let worker = DsWorker::new("unix-in");
        assert_eq!(worker.port(), 0);
        assert!(!worker.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn ds_worker_start_returns_error() {
        let worker = DsWorker::new("unix-in");
        let result = Arc::new(worker).start().await;
        assert!(result.is_err());
        match result {
            Err(ProxymanError::ListenSocketFailed(msg)) => {
                assert!(msg.contains("Unix domain socket"));
            },
            Err(e) => panic!("expected ListenSocketFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn ds_worker_close_ok() {
        let worker = DsWorker::new("unix-in");
        assert!(worker.close().await.is_ok());
        assert!(worker.closed.load(Ordering::SeqCst));
    }

    #[test]
    fn udp_session_new_and_accessors() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _out_rx) = UdpSession::new(source, local, None, None);

        assert_eq!(session.source(), source);
        assert_eq!(session.local(), local);
        assert!(!session.is_inactive());
        assert!(session.last_activity_secs() > 0);
    }

    #[test]
    fn udp_session_inactive_transition() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _out_rx) = UdpSession::new(source, local, None, None);

        assert!(!session.is_inactive());
        session.set_inactive();
        assert!(session.is_inactive());
    }

    #[test]
    fn udp_session_update_activity() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _out_rx) = UdpSession::new(source, local, None, None);

        let before = session.last_activity_secs();
        session.update_activity();
        let after = session.last_activity_secs();
        assert!(after >= before);
    }

    /// 入方向：push_inbound 写入的包经 recv 可达消费端（audit ojcy）。
    #[tokio::test]
    async fn udp_session_inbound_reaches_consumer() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _out_rx) = UdpSession::new(source, local, None, None);

        session.push_inbound(vec![1, 2, 3]);
        assert_eq!(session.recv().await.as_deref(), Some(&[1, 2, 3][..]));
    }

    /// 出方向：write_packet 写入的包经返回的 Receiver 可达（响应泵消费端）。
    #[tokio::test]
    async fn udp_session_outbound_reaches_receiver() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, mut out_rx) = UdpSession::new(source, local, None, None);

        session.write_packet(vec![4, 5]).await;
        assert_eq!(out_rx.recv().await.as_deref(), Some(&[4, 5][..]));
    }

    /// inactive 会话丢弃双向包（channel 中不应出现数据）。
    #[tokio::test]
    async fn udp_session_inactive_drops_packets() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, mut out_rx) = UdpSession::new(source, local, None, None);

        session.set_inactive();
        session.push_inbound(vec![1]);
        session.write_packet(vec![2]).await;

        let in_got = tokio::time::timeout(Duration::from_millis(50), session.recv()).await;
        let out_got = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
        assert!(in_got.is_err(), "inactive session must drop inbound packets");
        assert!(out_got.is_err(), "inactive session must drop outbound packets");
    }

    #[test]
    fn inbound_conn_enum_variants() {
        // Verify the enum compiles with correct type parameters
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (udp_session, _) = UdpSession::new(source, local, None, None);
        let _udp_conn = InboundConn::Udp(udp_session);
        // Tcp variant requires a real Connection impl, skip in unit test
    }

    // ===== 集成测试桩 =====

    /// 最小 Connection 桩：包装 duplex 流（tests 专用）。
    struct DuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            Pin::new(&mut this.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            Pin::new(&mut this.0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            Pin::new(&mut this.0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            Pin::new(&mut this.0).poll_shutdown(cx)
        }
    }

    impl Connection for DuplexConn {
        fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }
    }

    /// TCP 命中计数 proxy（audit 79ma：accept 打穿即 +1）。
    struct HitProxy {
        hits: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ProxyInbound for HitProxy {
        async fn process(
            &self,
            _network: Network,
            _conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// UDP 回声 proxy：读首包 → 转发给测试断言 → write_packet 回 pong
    /// （audit ojcy：入方向 recv + 出方向 write_packet 双路径打穿）。
    struct UdpEchoProxy {
        got: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl ProxyInbound for UdpEchoProxy {
        async fn process(
            &self,
            network: Network,
            conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            if let (Network::UDP, InboundConn::Udp(s)) = (network, conn) {
                if let Some(data) = s.recv().await {
                    let _ = self.got.send(data).await;
                    s.write_packet(b"pong".to_vec()).await;
                }
            }
            Ok(())
        }
    }

    /// 挂起 proxy：通知 started 后永挂（idle 超时经 select 丢弃该 future）。
    struct HangingProxy {
        started: mpsc::Sender<()>,
    }

    #[async_trait::async_trait]
    impl ProxyInbound for HangingProxy {
        async fn process(
            &self,
            _network: Network,
            _conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            let _ = self.started.send(()).await;
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    /// 持续读写的 proxy（echo 循环）——audit 95ar 正向：活跃连接不被杀。
    struct EchoIoProxy;

    #[async_trait::async_trait]
    impl ProxyInbound for EchoIoProxy {
        async fn process(
            &self,
            network: Network,
            conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let (Network::TCP, InboundConn::Tcp(mut c)) = (network, conn) {
                let mut buf = [0u8; 64];
                while let Ok(n) = c.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if c.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
            Ok(())
        }
    }

    fn tcp_worker_for_test(proxy: Arc<dyn ProxyInbound>, tag: &str) -> Arc<TcpWorker> {
        Arc::new(TcpWorker::new(
            "127.0.0.1:0".parse().unwrap(),
            0,
            proxy,
            StreamSettings::tcp(),
            SocketOptions::default(),
            false,
            tag,
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        ))
    }

    fn udp_worker_for_test(proxy: Arc<dyn ProxyInbound>, tag: &str) -> Arc<UdpWorker> {
        Arc::new(UdpWorker::new(
            proxy,
            "127.0.0.1:0".parse().unwrap(),
            0,
            tag,
            StreamSettings::tcp(),
            SocketOptions::default(),
            make_dispatcher(),
            SniffingRequest::default(),
            None,
            None,
        ))
    }

    // ===== audit 79ma：TcpWorker::start（trait）accept 打穿 =====

    #[tokio::test]
    async fn tcp_worker_start_accepts_and_dispatches() {
        // listen_tcp 走 registry：需先注册 tcp TransportListenFn（幂等，忽略 AlreadyExists）。
        let _ = xray_transport::tcp::register_tcp_transport();

        let hits = Arc::new(AtomicUsize::new(0));
        let worker =
            tcp_worker_for_test(Arc::new(HitProxy { hits: Arc::clone(&hits) }), "tcp-accept-test");

        // 旧实现 trait start 为 unreachable!——start 即 panic；且 hub 不 spawn
        // accept loop——bind 后永不 accept。此测试同时覆盖两条修复。
        Arc::clone(&worker).start().await.expect("tcp worker start");

        let addr = {
            let listener = worker.listener.lock().unwrap_or_else(|e| e.into_inner());
            listener
                .as_ref()
                .expect("listener stored after start")
                .local_addr()
                .expect("local_addr")
        };

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        tokio::io::AsyncWriteExt::write_all(&mut client, b"ping").await.expect("write");

        tokio::time::timeout(Duration::from_secs(2), async {
            while hits.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("proxy never hit — accept loop not spawned or handler not wired");
    }

    // ===== audit ojcy：UdpWorker 端到端（客户端包达 proxy + 回包达客户端）=====

    #[tokio::test]
    async fn udp_worker_start_delivers_and_replies() {
        let (got_tx, mut got_rx) = mpsc::channel::<Vec<u8>>(8);
        let worker = udp_worker_for_test(Arc::new(UdpEchoProxy { got: got_tx }), "udp-e2e");

        Arc::clone(&worker).start().await.expect("udp worker start");

        let hub_addr = {
            let hub = worker.hub.lock().unwrap_or_else(|e| e.into_inner());
            hub.as_ref().expect("hub stored after start").local_addr().expect("local_addr")
        };

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client.send_to(b"ping", hub_addr).await.expect("send");

        // 入方向：hub → session → proxy 消费
        let got = tokio::time::timeout(Duration::from_secs(2), got_rx.recv())
            .await
            .expect("client packet never reached proxy")
            .expect("got channel closed");
        assert_eq!(got.as_slice(), b"ping");

        // 出方向：proxy write_packet → 响应泵 → hub.send_to → 客户端
        let mut buf = [0u8; 16];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("no reply from worker")
            .expect("recv_from");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(src, hub_addr);
    }

    // ===== audit 95ar：ActivityTimer 滑动窗口 =====

    #[tokio::test]
    async fn tcp_worker_idle_conn_cancelled_without_io() {
        let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
        let worker =
            tcp_worker_for_test(Arc::new(HangingProxy { started: started_tx }), "idle-test");

        let (_client, server) = tokio::io::duplex(64);
        let handle = worker.spawn_conn(Box::new(DuplexConn(server)), Duration::from_millis(150));

        started_rx.recv().await.expect("proxy never started");

        // proxy 不做任何 IO → 空闲窗口到期 → done 分支 → 连接任务结束。
        // 旧实现此路径 select 恒等 done_signal 且 timer 无人重置——行为相同；
        // 本测试锁定"无 IO 被杀"语义在 spawn_conn 拆分后仍然成立。
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("idle connection was not cancelled")
            .expect("task join");
    }

    #[tokio::test]
    async fn tcp_worker_active_conn_survives_idle_window() {
        let worker = tcp_worker_for_test(Arc::new(EchoIoProxy), "active-test");
        let (mut client, server) = tokio::io::duplex(64);

        let handle = worker.spawn_conn(Box::new(DuplexConn(server)), Duration::from_millis(100));

        // 每 50ms 一轮 echo ×4 = 200ms+，两倍于 100ms 空闲窗口：
        // 装饰器在读写路径持续 update_activity → 计时器永不到期。
        // 旧实现（timer 无 update 接线）连接活不过 100ms——必挂。
        for i in 0..4 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let msg = [b'x'; 8];
            tokio::io::AsyncWriteExt::write_all(&mut client, &msg).await.expect("write");
            let mut echo = [0u8; 8];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut echo)
                .await
                .unwrap_or_else(|e| panic!("echo #{i}: {e}"));
            assert_eq!(&echo, &msg, "echo #{i}");
        }

        assert!(!handle.is_finished(), "active connection killed despite continuous IO");

        drop(client); // EOF → proxy 退出 → 连接任务结束
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("conn task hang after EOF")
            .expect("task join");
    }

    /// mvsc 探针：future 持有的 drop 标记——task 被 abort（future drop）时置位。
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 挂起 proxy：把 probe clone 进 process future；被 abort 时 probe 置位。
    struct ProbeHangingProxy {
        started: mpsc::Sender<()>,
        probe: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl ProxyInbound for ProbeHangingProxy {
        async fn process(
            &self,
            _network: Network,
            _conn: InboundConn,
            _session: Session,
            _dispatcher: Arc<dyn Dispatcher>,
        ) -> Result<(), ProxymanError> {
            let _probe = DropProbe(Arc::clone(&self.probe));
            let _ = self.started.send(()).await;
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    /// mvsc：TcpWorker close 必须结构化收尾——abort 全部在途连接 task，
    /// 不允许 fire-and-forget 孤儿存活。修复前 close 只关 listener → 红。
    #[tokio::test]
    async fn tcp_worker_close_aborts_conn_tasks() {
        let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
        let probe = Arc::new(AtomicBool::new(false));
        let worker = tcp_worker_for_test(
            Arc::new(ProbeHangingProxy { started: started_tx, probe: Arc::clone(&probe) }),
            "tcp-close-abort",
        );
        let (_client, server) = tokio::io::duplex(64);
        worker.spawn_conn(Box::new(DuplexConn(server)), Duration::from_secs(60));
        started_rx.recv().await.expect("conn task started");

        worker.close().await.expect("close ok");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            probe.load(std::sync::atomic::Ordering::SeqCst),
            "conn task must be aborted by worker close (orphan task)"
        );
    }

    /// mvsc：UdpWorker close 必须 abort 全部 per-session task（process/响应泵）。
    #[tokio::test]
    async fn udp_worker_close_aborts_session_tasks() {
        let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
        let probe = Arc::new(AtomicBool::new(false));
        let worker = udp_worker_for_test(
            Arc::new(ProbeHangingProxy { started: started_tx, probe: Arc::clone(&probe) }),
            "udp-close-abort",
        );
        let packet = UdpPacket {
            payload: vec![1, 2, 3],
            source: "127.0.0.1:5555".parse().unwrap(),
            target: None,
        };
        worker.on_packet(&packet, "127.0.0.1:5555".parse().unwrap());
        started_rx.recv().await.expect("session task started");

        worker.close().await.expect("close ok");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            probe.load(std::sync::atomic::Ordering::SeqCst),
            "session task must be aborted by worker close (orphan task)"
        );
    }
}
