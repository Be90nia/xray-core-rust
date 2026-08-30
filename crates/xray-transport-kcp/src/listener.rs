//! Listener（对应 Go `listener.go`）。
//!
//! IO 边界 stub：实际 UDP hub bind + TLS server 留 trait 注入。
//! 核心会话路由逻辑（OnReceive + sessions map）可测。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::connection::{ConnMetadata, Connection, ConnectionCloser};
use crate::error::Result;
use crate::io::PacketReader;
use crate::output::SegmentWriter;
use crate::segment::Command;

/// 会话标识（对应 Go `ConnectionID`）。
///
/// 由远端地址 + conv 唯一确定一个 KCP 会话。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    /// 远端 socket 地址。
    pub remote: SocketAddr,
    /// 会话 ID。
    pub conv: u16,
}

impl ConnectionId {
    #[must_use]
    pub fn new(remote: SocketAddr, conv: u16) -> Self {
        Self { remote, conv }
    }
}

/// 新连接 handler（对应 Go `internet.ConnHandler`）。
///
/// 每当 listener 接收到新 conv 的首包时调用，把构造的 Connection 交给上层。
pub trait ConnHandler: Send + Sync {
    fn add_conn(&self, conn: Arc<Connection>);
}

/// UDP hub trait（对应 Go `udp.Hub`）。
///
/// 生产实现包装 UDP socket + 接收循环；测试用 mock。
pub trait UdpHub: Send + Sync {
    /// 阻塞读一个 UDP 包，返回 (payload, source_addr)。关闭/EOF 返回 None。
    fn receive(&self) -> Option<(Vec<u8>, SocketAddr)>;

    /// 向指定目标写 UDP 包。
    fn write_to(&self, payload: &[u8], dest: SocketAddr) -> std::io::Result<()>;

    /// 关闭 hub。
    fn close(&self);

    /// 本地绑定地址。
    fn local_addr(&self) -> Option<SocketAddr>;
}

/// KCP Listener（对应 Go `Listener struct`）。
///
/// 维护 sessions map，接收 UDP 包后路由到对应 Connection。
pub struct Listener {
    inner: Mutex<ListenerInner>,
    reader: Arc<dyn PacketReader>,
    hub: Arc<dyn UdpHub>,
    config: Arc<crate::config::Config>,
    add_conn: Arc<dyn ConnHandler>,
}

struct ListenerInner {
    sessions: HashMap<ConnectionId, Arc<Connection>>,
    closed: bool,
}

impl Listener {
    /// 构造（对应 Go `NewListener`，但不 spawn 接收循环）。
    ///
    /// 接收循环由调用方负责（生产用 tokio::spawn 调 `handle_one_packet`）。
    #[must_use]
    pub fn new(
        hub: Arc<dyn UdpHub>,
        reader: Arc<dyn PacketReader>,
        config: Arc<crate::config::Config>,
        add_conn: Arc<dyn ConnHandler>,
    ) -> Self {
        Self {
            inner: Mutex::new(ListenerInner {
                sessions: HashMap::new(),
                closed: false,
            }),
            hub,
            reader,
            config,
            add_conn,
        }
    }

    /// 处理一个 UDP 包（对应 Go `Listener.OnReceive`）。
    ///
    /// 解析 segments，查/建 Connection，调 `conn.input(segments)`。
    /// 返回是否成功处理（false = 丢弃/包无效）。
    pub fn on_receive(&self, payload: &[u8], src: SocketAddr) -> bool {
        let segments = self.reader.read(payload);
        if segments.is_empty() {
            return false;
        }

        let conv = segments[0].conversation();
        let cmd = segments[0].command();
        let id = ConnectionId::new(src, conv);

        let mut inner = self.inner.lock();
        let existing = inner.sessions.get(&id).cloned();

        let conn = match existing {
            Some(c) => c,
            None => {
                // 新会话：Terminate 包直接丢弃（对应 Go 逻辑）
                if cmd == Command::Terminate {
                    return false;
                }
                let local = self.hub.local_addr();
                let writer = Arc::new(ListenerWriter::new(
                    id.clone(),
                    Arc::clone(&self.hub),
                ));
                let closer = writer.clone();
                let meta = ConnMetadata {
                    conv,
                    local_addr: local,
                    remote_addr: Some(src),
                };
                let new_conn = Arc::new(Connection::new(
                    meta,
                    writer,
                    closer,
                    Arc::clone(&self.config),
                ));
                self.add_conn.add_conn(Arc::clone(&new_conn));
                inner.sessions.insert(id, Arc::clone(&new_conn));
                new_conn
            }
        };
        drop(inner);

        conn.input(segments);
        true
    }

    /// 从 hub 读一个包并处理（对应 Go `handlePackets` 单次迭代）。
    ///
    /// 返回 false 表示 hub 已关闭。
    pub fn handle_one_packet(&self) -> bool {
        let (payload, src) = match self.hub.receive() {
            Some(p) => p,
            None => return false,
        };
        self.on_receive(&payload, src);
        true
    }

    /// 移除会话（对应 Go `Listener.Remove`）。
    pub fn remove(&self, id: &ConnectionId) {
        let mut inner = self.inner.lock();
        inner.sessions.remove(id);
    }

    /// 活跃会话数（对应 Go `Listener.ActiveConnections`）。
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.inner.lock().sessions.len()
    }

    /// 关闭 listener（对应 Go `Listener.Close`）。
    ///
    /// 关闭 hub + terminate 所有会话。已建立的连接不会被关闭（Go 同样）。
    pub fn close(&self) -> Result<()> {
        self.hub.close();
        let mut inner = self.inner.lock();
        inner.closed = true;
        let sessions: Vec<Arc<Connection>> = inner.sessions.drain().map(|(_, v)| v).collect();
        drop(inner);
        // terminate 所有会话（Go 用 goroutine，这里同步调）
        for conn in sessions {
            conn.terminate();
        }
        Ok(())
    }

    /// 本地绑定地址（对应 Go `Listener.Addr`）。
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.hub.local_addr()
    }
}

/// Listener 会话 writer（对应 Go `Writer struct`）。
///
/// 每个会话一个，写 UDP + close 时从 listener 移除自己。
/// 注意：当前简化为只写 UDP，不自动 remove（remove 由 Connection terminate 触发）。
pub struct ListenerWriter {
    id: ConnectionId,
    hub: Arc<dyn UdpHub>,
}

impl ListenerWriter {
    #[must_use]
    pub fn new(id: ConnectionId, hub: Arc<dyn UdpHub>) -> Self {
        Self { id, hub }
    }
}

impl SegmentWriter for ListenerWriter {
    fn write_segment(&self, seg: &dyn crate::segment::Segment) -> std::io::Result<()> {
        let size = seg.byte_size();
        let mut buf = vec![0u8; size];
        seg.serialize(&mut buf);
        self.hub.write_to(&buf, self.id.remote)
    }
}

impl ConnectionCloser for ListenerWriter {
    fn close(&self) {
        // 实际 remove 需要访问 Listener（Go 中 writer 持有 listener 引用）。
        // 简化：close 时仅 hub.close 由 Listener.close 统一处理。
        // 若需精细 remove，上层可调 listener.remove(&self.id)。
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config;
    use crate::segment::{CmdOnlySegment, DataSegment, Segment};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock hub：预填包队列，写计数。
    struct MockHub {
        incoming: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        written: AtomicUsize,
        closed: AtomicUsize,
    }

    impl MockHub {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                incoming: Mutex::new(Vec::new()),
                written: AtomicUsize::new(0),
                closed: AtomicUsize::new(0),
            })
        }
        fn push(&self, payload: Vec<u8>, src: SocketAddr) {
            self.incoming.lock().push((payload, src));
        }
    }

    impl UdpHub for MockHub {
        fn receive(&self) -> Option<(Vec<u8>, SocketAddr)> {
            self.incoming.lock().pop()
        }
        fn write_to(&self, _payload: &[u8], _dest: SocketAddr) -> std::io::Result<()> {
            self.written.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn close(&self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    struct CountingHandler {
        count: AtomicUsize,
        conns: Mutex<Vec<Arc<Connection>>>,
    }
    impl CountingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: AtomicUsize::new(0),
                conns: Mutex::new(Vec::new()),
            })
        }
    }
    impl ConnHandler for CountingHandler {
        fn add_conn(&self, conn: Arc<Connection>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.conns.lock().push(conn);
        }
    }

    fn make_listener() -> (Listener, Arc<MockHub>, Arc<CountingHandler>) {
        let hub = MockHub::new();
        let reader = Arc::new(crate::io::KCPPacketReader::new());
        let config = Arc::new(default_config());
        let handler = CountingHandler::new();
        let listener = Listener::new(
            Arc::clone(&hub) as Arc<dyn UdpHub>,
            reader,
            config,
            Arc::clone(&handler) as Arc<dyn ConnHandler>,
        );
        (listener, hub, handler)
    }

    fn make_data_packet(conv: u16, number: u32) -> Vec<u8> {
        let mut seg = DataSegment::new();
        seg.conv = conv;
        seg.number = number;
        let mut buf = vec![0u8; seg.byte_size()];
        seg.serialize(&mut buf);
        buf
    }

    fn make_cmd_packet(conv: u16, cmd: Command) -> Vec<u8> {
        let mut seg = CmdOnlySegment::new();
        seg.conv = conv;
        seg.cmd = cmd;
        let mut buf = vec![0u8; seg.byte_size()];
        seg.serialize(&mut buf);
        buf
    }

    #[test]
    fn connection_id_equality() {
        let addr = "127.0.0.1:8080".parse().unwrap();
        let a = ConnectionId::new(addr, 1);
        let b = ConnectionId::new(addr, 1);
        let c = ConnectionId::new(addr, 2);
        let d = ConnectionId::new("127.0.0.1:9090".parse().unwrap(), 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn on_receive_empty_payload_returns_false() {
        let (listener, _, handler) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        assert!(!listener.on_receive(&[], src));
        assert_eq!(handler.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn on_receive_new_conv_creates_connection() {
        let (listener, _, handler) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        let payload = make_data_packet(42, 0);
        assert!(listener.on_receive(&payload, src));
        assert_eq!(handler.count.load(Ordering::SeqCst), 1);
        assert_eq!(listener.active_connections(), 1);
    }

    #[tokio::test]
    async fn on_receive_existing_conv_reuses_connection() {
        let (listener, _, handler) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        let payload1 = make_data_packet(42, 0);
        let payload2 = make_data_packet(42, 1);
        listener.on_receive(&payload1, src);
        listener.on_receive(&payload2, src);
        // 同 conv 同 src 复用
        assert_eq!(handler.count.load(Ordering::SeqCst), 1);
        assert_eq!(listener.active_connections(), 1);
    }

    #[tokio::test]
    async fn on_receive_different_conv_creates_separate_connections() {
        let (listener, _, handler) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        listener.on_receive(&make_data_packet(1, 0), src);
        listener.on_receive(&make_data_packet(2, 0), src);
        assert_eq!(handler.count.load(Ordering::SeqCst), 2);
        assert_eq!(listener.active_connections(), 2);
    }

    #[test]
    fn on_receive_terminate_for_new_session_discarded() {
        let (listener, _, handler) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        let payload = make_cmd_packet(42, Command::Terminate);
        assert!(!listener.on_receive(&payload, src));
        assert_eq!(handler.count.load(Ordering::SeqCst), 0);
        assert_eq!(listener.active_connections(), 0);
    }

    #[tokio::test]
    async fn remove_drops_session() {
        let (listener, _, _) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        listener.on_receive(&make_data_packet(42, 0), src);
        assert_eq!(listener.active_connections(), 1);
        let id = ConnectionId::new(src, 42);
        listener.remove(&id);
        assert_eq!(listener.active_connections(), 0);
    }

    #[tokio::test]
    async fn close_terminates_all_sessions() {
        let (listener, hub, _) = make_listener();
        let src = "127.0.0.1:8080".parse().unwrap();
        listener.on_receive(&make_data_packet(1, 0), src);
        listener.on_receive(&make_data_packet(2, 0), src);
        assert_eq!(listener.active_connections(), 2);
        listener.close().unwrap();
        assert_eq!(hub.closed.load(Ordering::SeqCst), 1);
        assert_eq!(listener.active_connections(), 0);
    }

    #[test]
    fn handle_one_packet_returns_false_when_hub_empty() {
        let (listener, _, _) = make_listener();
        assert!(!listener.handle_one_packet());
    }
}
