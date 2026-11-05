//! 入站 worker 实现
//!
//! 对应 Go `app/proxyman/inbound/worker.go`：tcpWorker / udpWorker。
//!
//! Go 的第三类 worker `dsWorker`（Unix domain socket）在本仓**不在本 crate**：
//! 生产 UDS 入站由 `xray-core::inbound::spawn_unix_inbound` 直接接线
//! （`inbound.rs` 的 `is_unix_listen_path` 分派 → `listen_unix_system`），
//! 故本模块不提供 dsWorker 变体（保留只会是一条无调用方的第二套 UDS 路径）。
//!
//! 生产入站表是 `xray-core` 的 `InboundRuntime`；Go 的 tcpWorker / udpWorker
//! 两个具体 worker 在本仓零生产消费（构造点只在自测里），已随死码清理删除。
//! 本模块保留的是 worker 契约面（[`ProxyInbound`] / [`Worker`]）与
//! [`UdpSession`]——UDP 会话载体由代理协议经 [`ProxyInbound::process`] 消费。

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

use skeleton::clock::{Clock, SystemClock};
use tokio::sync::mpsc;
use xray_common::{net::network::Network, session::Session};
use xray_features::stats::Counter;
use xray_mux::worker::Dispatcher;
use xray_transport::connection::Connection;

use crate::error::ProxymanError;

/// 713x6：Clock 契约取挂钟秒（会话活动时间戳统一入口；observatory 同款助手）。
fn unix_secs_of(clock: &dyn Clock) -> i64 {
    clock
        .now_system()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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
    /// 713x6：活动时间戳时间源（挂钟秒）；生产 `SystemClock`。
    clock: Arc<dyn Clock>,
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
        Self::with_clock(source, local, uplink, downlink, Arc::new(SystemClock))
    }

    /// 713x6：注入时钟（`new` 缺省 `SystemClock`，行为不变）。
    pub fn with_clock(
        source: SocketAddr,
        local: SocketAddr,
        uplink: Option<Arc<dyn Counter>>,
        downlink: Option<Arc<dyn Counter>>,
        clock: Arc<dyn Clock>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let session = Arc::new(Self {
            // 713x6：初始活动时刻取自注入时钟（原 std 直通语义）。
            last_activity: AtomicI64::new(unix_secs_of(clock.as_ref())),
            clock,
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
        // 713x6：挂钟秒取自注入时钟（原 std 直通语义）。
        let now = unix_secs_of(self.clock.as_ref());
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——测试取时/等待窗口保持原语义，时钟禁令只约束生产路径"
    )]
    use std::time::Duration;

    use super::*;

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
}
