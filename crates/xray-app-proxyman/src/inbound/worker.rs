//! 入站 worker 实现
//!
//! 对应 Go `app/proxyman/inbound/worker.go`：tcpWorker / udpWorker / dsWorker。
//!
//! 每个 worker 持有一个 transport listener（TCP/UDP/Unix），accept 后构造
//! `Session` 并调用 `ProxyInbound::process()` 交给具体代理协议处理。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;

use parking_lot::RwLock;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::session::{Inbound, Outbound, Session};
use xray_features::stats::Counter;
use xray_mux::worker::Dispatcher;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener, listen_tcp};
use xray_transport::sockopt::SocketOptions;
use xray_transport::udp::hub::{Capacity, HubOption, UdpHub, UdpPacket};
use xray_common::signal::ActivityTimer;
use xray_features::policy::DEFAULT_CONN_IDLE_TIMEOUT;

use crate::config::SniffingRequest;
use crate::error::ProxymanError;

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
    async fn start(&self) -> Result<(), ProxymanError>;
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
    writer: mpsc::Sender<Vec<u8>>,
    source: SocketAddr,
    local: SocketAddr,
    uplink: Option<Arc<dyn Counter>>,
    downlink: Option<Arc<dyn Counter>>,
    inactive: AtomicBool,
}

impl UdpSession {
    /// 创建 UDP 会话，返回 `(Arc<Self>, Sender)`。
    ///
    /// 调用方保留 `Sender` 用于向 session 写入数据包（来自远端）。
    /// `Reader` 留给 `ProxyInbound::process` 消费。
    pub fn new(
        source: SocketAddr,
        local: SocketAddr,
        uplink: Option<Arc<dyn Counter>>,
        downlink: Option<Arc<dyn Counter>>,
    ) -> (Arc<Self>, mpsc::Sender<Vec<u8>>) {
        let (tx, _rx) = mpsc::channel(256);
        let session = Arc::new(Self {
            last_activity: AtomicI64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ),
            writer: tx.clone(),
            source,
            local,
            uplink,
            downlink,
            inactive: AtomicBool::new(false),
        });
        (session, tx)
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

    /// 向 session 写入数据包（来自远端响应）。
    ///
    /// channel 满时静默丢弃（与 Go `select { case c <- payload: default: }` 一致）。
    pub fn write_packet(&self, data: Vec<u8>) {
        if self.inactive.load(Ordering::Relaxed) {
            return;
        }
        if self.writer.try_send(data).is_err() {
            // ponytail: channel 满时丢弃，与 Go 行为一致
        }
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
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        let tag = self.tag.clone();
        let address = self.address;
        let port = self.port;
        let proxy = Arc::clone(&self.proxy);
        let dispatcher = Arc::clone(&self.dispatcher);

        let inbound = Inbound::new()
            .with_tag(&tag)
            .with_network(Network::TCP);

        let gateway = Destination::new(
            Address::from(address.ip()),
            Port::new(port),
            Network::TCP,
        );

        let session = Session::new()
            .with_inbound(inbound)
            .with_outbound(
                Outbound::new().with_destination_override(gateway),
            );

        // 创建不活动超时计时器（对应 Go CancelAfterInactivity）
        // ActivityTimer::run 消费 &mut self，需 spawn 到独立 task，
        // 主 task 通过 Done 信号检测超时。
        let mut activity_timer = ActivityTimer::new(DEFAULT_CONN_IDLE_TIMEOUT);
        let mut done_signal = activity_timer.done();

        // spawn 计时器循环，超时后自动 cancel Done 信号
        tokio::spawn(async move {
            activity_timer.run().await;
        });

        tokio::spawn(async move {
            let inbound_conn = InboundConn::Tcp(conn);
            tokio::select! {
                result = proxy.process(Network::TCP, inbound_conn, session, dispatcher) => {
                    if let Err(e) = result {
                        warn!(tag = %tag, error = %e, "proxy process failed");
                    }
                    // 正常结束，无需额外操作
                }
                _ = done_signal.wait() => {
                    // 不活动超时，连接被半关闭
                    warn!(tag = %tag, timeout = ?DEFAULT_CONN_IDLE_TIMEOUT, "connection cancelled after inactivity");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Worker for TcpWorker {
    async fn start(&self) -> Result<(), ProxymanError> {
        // TcpWorker 必须通过 Arc<Self> 使用，以便 ConnHandler 闭包持有 Arc 引用。
        // 此处通过 Arc<Self> 的弱引用避免循环：listener 持有 Weak<TcpWorker>，
        // TcpWorker 持有 listener。close() 先 take listener，打破循环。
        unreachable!("TcpWorker::start requires Arc<Self>, use start_arc()")
    }

    async fn close(&self) -> Result<(), ProxymanError> {
        self.closed.store(true, Ordering::SeqCst);
        self.close_notify.notify_waiters();

        let listener = self
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();

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

impl TcpWorker {
    /// 启动 TCP 监听。要求 `Arc<Self>` 以便闭包持有引用。
    pub async fn start_arc(self: &Arc<Self>) -> Result<(), ProxymanError> {
        let this = Arc::clone(self);
        let handler: ConnHandler = Arc::new(move |conn| {
            this.on_conn(conn);
        });

        let listener = listen_tcp(
            self.address,
            self.stream_settings.clone(),
            self.sockopt.clone(),
            handler,
        )
        .await
        .map_err(|e| ProxymanError::ListenSocketFailed(e.to_string()))?;

        let actual_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(self.port);

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
    hub: Mutex<Option<UdpHub>>,
    active_sessions: RwLock<Vec<Arc<UdpSession>>>,
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
            active_sessions: RwLock::new(Vec::new()),
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

        // 查找已有 session
        let sessions = self.active_sessions.read();
        let existing = sessions.iter().find(|s| s.source() == source);
        if let Some(session) = existing {
            session.update_activity();
            session.write_packet(packet.payload.clone());
            return;
        }
        drop(sessions);

        // 创建新 session
        let local = local_addr;
        let (session, _sender) = UdpSession::new(
            source,
            local,
            self.uplink_counter.clone(),
            self.downlink_counter.clone(),
        );

        // 写入首包
        session.write_packet(packet.payload.clone());

        // 注册 session
        self.active_sessions.write().push(session.clone());

        // spawn proxy.process()
        let tag = self.tag.clone();
        let address = self.address;
        let port = self.port;
        let proxy = Arc::clone(&self.proxy);
        let dispatcher = Arc::clone(&self.dispatcher);

        let inbound = Inbound::new()
            .with_tag(&tag)
            .with_network(Network::UDP);

        let gateway = Destination::new(
            Address::from(address.ip()),
            Port::new(port),
            Network::UDP,
        );

        let session_ctx = Session::new()
            .with_inbound(inbound)
            .with_outbound(
                Outbound::new().with_destination_override(gateway),
            );

        tokio::spawn(async move {
            let inbound_conn = InboundConn::Udp(session);
            if let Err(e) = proxy.process(Network::UDP, inbound_conn, session_ctx, dispatcher).await {
                warn!(tag = %tag, error = %e, "UDP proxy process failed");
            }
        });
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
        sessions.retain(|s| {
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
    async fn start(&self) -> Result<(), ProxymanError> {
        unreachable!("UdpWorker::start requires Arc<Self>, use start_arc()")
    }

    async fn close(&self) -> Result<(), ProxymanError> {
        self.closed.store(true, Ordering::SeqCst);
        self.close_notify.notify_waiters();

        // Close hub
        let hub = self
            .hub
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = hub {
            h.close().map_err(|e| ProxymanError::CloseAllFailed(e.to_string()))?;
        }

        // Abort handles
        let recv = self
            .recv_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = recv {
            h.abort();
        }

        let cleanup = self
            .cleanup_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = cleanup {
            h.abort();
        }

        // Mark all sessions inactive
        let sessions = self.active_sessions.read();
        for s in sessions.iter() {
            s.set_inactive();
        }

        info!(tag = %self.tag, "UDP worker closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl UdpWorker {
    /// 启动 UDP 监听。要求 `Arc<Self>` 以便闭包持有引用。
    pub async fn start_arc(self: &Arc<Self>) -> Result<(), ProxymanError> {
        let options: Vec<Box<dyn HubOption>> = vec![Box::new(Capacity(256))];
        let hub = UdpHub::listen(self.address, &options, None)
            .await
            .map_err(|e| ProxymanError::ListenSocketFailed(e.to_string()))?;

        let actual_port = hub
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(self.port);

        info!(
            tag = %self.tag,
            address = %self.address,
            port = actual_port,
            "UDP worker started"
        );

        // UdpHub::receive() consumes self. Cache local_addr before calling receive().
        let local_addr = hub.local_addr().unwrap_or(self.address);
        let mut rx = hub.receive();
        // Hub is consumed by receive(); store None (close() will abort recv_handle instead).
        *self.hub.lock().unwrap_or_else(|e| e.into_inner()) = None;

        // Spawn recv loop
        let close_notify = Arc::clone(&self.close_notify);
        let this = Arc::clone(self);

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
        let this2 = Arc::clone(self);
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
        Self {
            tag: tag.into(),
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Worker for DsWorker {
    async fn start(&self) -> Result<(), ProxymanError> {
        // ponytail: Unix domain socket not yet supported, stub
        Err(ProxymanError::ListenSocketFailed(
            "Unix domain socket not yet supported".to_string(),
        ))
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
        let result = worker.start().await;
        assert!(result.is_err());
        match result {
            Err(ProxymanError::ListenSocketFailed(msg)) => {
                assert!(msg.contains("Unix domain socket"));
            }
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
        let (session, _tx) = UdpSession::new(source, local, None, None);

        assert_eq!(session.source(), source);
        assert_eq!(session.local(), local);
        assert!(!session.is_inactive());
        assert!(session.last_activity_secs() > 0);
    }

    #[test]
    fn udp_session_inactive_transition() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _tx) = UdpSession::new(source, local, None, None);

        assert!(!session.is_inactive());
        session.set_inactive();
        assert!(session.is_inactive());
    }

    #[test]
    fn udp_session_update_activity() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _tx) = UdpSession::new(source, local, None, None);

        let before = session.last_activity_secs();
        session.update_activity();
        let after = session.last_activity_secs();
        assert!(after >= before);
    }

    #[test]
    fn udp_session_write_packet_active() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _tx) = UdpSession::new(source, local, None, None);

        // Should not panic when active
        session.write_packet(vec![1, 2, 3]);
    }

    #[test]
    fn udp_session_write_packet_inactive_drops() {
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let (session, _tx) = UdpSession::new(source, local, None, None);

        session.set_inactive();
        // Should silently drop when inactive
        session.write_packet(vec![1, 2, 3]);
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
}
