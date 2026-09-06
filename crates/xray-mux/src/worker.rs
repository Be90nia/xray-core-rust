//! Mux 服务端
//!
//! 对应 Go 版本 `common/mux/server.go`，实现 Mux 服务端帧处理、KeepAlive 和空闲超时。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tokio::time::Duration;
use tracing::warn;
use xray_buf::io::{Reader, Writer};
use xray_buf::reader::BufferedReader;
use xray_buf::writer::BufferedWriter;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;

use crate::client::{Link, MUX_COOL_ADDRESS};
use crate::frame::{FrameMetadata, SessionStatus, MAX_METADATA_LEN};
use crate::session::{Session, SessionManager, TransferType, XUDP, XUDPManager, XudpStatus};
use crate::writer::MuxWriter;
use xray_buf::buffer::Buffer;
use xray_buf::multi::MultiBuffer;

/// 服务端 KeepAlive 间隔（60 秒）。
pub const SERVER_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

#[async_trait::async_trait]
pub trait Dispatcher: Send + Sync {
    async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError>;
}

#[derive(thiserror::Error, Debug)]
pub enum DispatchError {
    #[error("no route to destination: {0}")]
    NoRoute(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("dispatch timeout: {0}")]
    Timeout(String),
}

/// 将 `DispatchHandler`（消费 link）适配为 `Dispatcher`（返回 link）。
///
/// 实现：创建 pipe pair → 一端包装为 transport::Link 传给 DispatchHandler →
/// 另一端包装为 mux::Link 返回。
/// 对应 Go `mux.Server.Dispatch` 内部调用 `proxy.Dispatch` 的桥接逻辑。
pub struct DispatchHandlerAdapter {
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
}

impl DispatchHandlerAdapter {
    pub fn new(handler: Arc<dyn xray_app_dispatcher::DispatchHandler>) -> Self {
        Self { handler }
    }
}

#[async_trait::async_trait]
impl Dispatcher for DispatchHandlerAdapter {
    async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
        // 两个 pipe：pipe_a + pipe_b
        // DispatchHandler 写到 write_a → 我们从 read_a 读
        // 我们写到 write_b → DispatchHandler 从 read_b 读
        let (read_a, write_a) = xray_buf::pipe::new();
        let (read_b, write_b) = xray_buf::pipe::new();

        // DispatchHandler 接收 transport::Link
        let dispatch_link = xray_transport::link::Link::new(
            Box::new(read_b),
            Box::new(write_a),
        );
        // 返回 mux::Link
        let return_link = Link {
            reader: Box::new(read_a),
            writer: Box::new(write_b),
        };

        let handler = Arc::clone(&self.handler);
        let dest_clone = dest.clone();
        tokio::spawn(async move {
            handler.dispatch(&dest_clone, dispatch_link).await;
        });

        Ok(return_link)
    }
}

pub struct Server {
    dispatcher: Arc<dyn Dispatcher>,
}

impl Server {
    pub fn new(dispatcher: Arc<dyn Dispatcher>) -> Self {
        Self { dispatcher }
    }

    pub async fn dispatch(&self, dest: &Destination) -> Result<Link, DispatchError> {
        if !Self::is_mux_destination(dest) {
            return self.dispatcher.dispatch(dest.clone()).await;
        }
        Err(DispatchError::NoRoute("mux server not fully initialized".to_string()))
    }

    pub fn is_mux_destination(dest: &Destination) -> bool {
        match dest.address() {
            xray_common::net::address::Address::Domain(domain) => domain == MUX_COOL_ADDRESS,
            _ => false,
        }
    }
}

pub struct ServerWorker {
    dispatcher: Arc<dyn Dispatcher>,
    session_manager: Arc<SessionManager>,
    xudp_manager: Arc<XUDPManager>,
    closed: AtomicBool,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
}

impl ServerWorker {
    pub fn new(dispatcher: Arc<dyn Dispatcher>) -> Self {
        let (done_tx, done_rx) = watch::channel(false);
        Self {
            dispatcher,
            session_manager: Arc::new(SessionManager::new()),
            xudp_manager: Arc::new(XUDPManager::new()),
            closed: AtomicBool::new(false),
            done_tx,
            done_rx,
        }
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.done_tx.send(true);
    }

    #[must_use]
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    pub async fn active_connections(&self) -> u32 {
        self.session_manager.size().await as u32
    }

    pub fn done_rx(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }

    /// 启动 KeepAlive 定时发送和空闲超时检查任务。
    ///
    /// 返回两个 JoinHandle：keepalive 任务和 idle_timeout 任务。
    /// 调用方负责在适当时机 abort。
    pub fn spawn_keepalive_and_idle_timeout(
        &self,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let session_manager = Arc::clone(&self.session_manager);
        let done_rx = self.done_rx.clone();
        let lw_keepalive = link_writer.clone();

        // KeepAlive 定时发送
        let keepalive_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(SERVER_KEEPALIVE_INTERVAL);
            let mut done = done_rx;
            loop {
                tokio::select! {
                    _ = done.changed() => break,
                    _ = interval.tick() => {
                        // 向所有活跃 session 发送 KeepAlive 帧
                        let sessions = session_manager.active_sessions().await;
                        for session in sessions {
                            if session.is_closed() { continue; }
                            let meta = FrameMetadata::keep_alive(session.id());
                            let mut vec = Vec::new();
                            if meta.write_to(&mut vec).is_err() { continue; }
                            let mb = MultiBuffer::from_buffer(Buffer::from_vec(vec));
                            let mut wg = lw_keepalive.lock().await;
                            if let Some(ref mut writer) = *wg {
                                let _ = writer.write_multi_buffer(mb).await;
                            }
                        }
                    }
                }
            }
        });

        let session_manager2 = Arc::clone(&self.session_manager);
        let done_rx2 = self.done_rx.clone();

        // 空闲超时检查
        let idle_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            let mut done = done_rx2;
            loop {
                tokio::select! {
                    _ = done.changed() => break,
                    _ = interval.tick() => {
                        let sessions = session_manager2.active_sessions().await;
                        for session in sessions {
                            if session.is_closed() { continue; }
                            if session.is_idle_timeout(crate::session::SESSION_IDLE_TIMEOUT).await {
                                warn!("session {} idle timeout, closing", session.id());
                                session.close().await;
                            }
                        }
                    }
                }
            }
        });

        (keepalive_handle, idle_handle)
    }

    /// Handle normal New frame (non-XUDP).
    pub async fn handle_normal_new(
        &self, meta: &FrameMetadata,
        data: Vec<u8>,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> Result<(), ServerError> {
        let target = meta.target().cloned().ok_or_else(|| {
            ServerError::InvalidFrame("new session without target".to_string())
        })?;
        let link = self.dispatcher.dispatch(target.clone()).await.map_err(|e| {
            ServerError::DispatchFailed(format!("dispatch to {}: {}", target, e))
        })?;
        let tt = if target.network() == Network::UDP { TransferType::Packet } else { TransferType::Stream };
        let session = Session::new(meta.session_id(), tt);
        session.set_input(BufferedReader::new(link.reader)).await;
        // Packet 会话禁用 BufferedWriter 缓冲（直写）：包边界保持 + 小包即时
        // 送达（Go server.go:271-277 直接使用 link.Writer，无缓冲包装）。
        let mut output = BufferedWriter::new(link.writer);
        if tt == TransferType::Packet {
            output.set_buffered(false);
        }
        // 写入 New frame 的 data 到 session.output（在 spawn 反向 task 前同步完成，
        // 对齐 Go handleStatusNew 中 `buf.Copy(rr, s.output)` 的语义）
        if !data.is_empty() {
            output
                .write_multi_buffer_impl(MultiBuffer::from_buffer(Buffer::from_vec(data)))
                .await
                .map_err(|e| ServerError::DispatchFailed(format!("initial data: {e}")))?;
            output.flush().await.ok();
        }
        session.set_output(output).await;
        let Some(session) = self.session_manager.add(session).await else {
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        };
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }
    /// Handle XUDP New frame.
    ///
    /// `data` 为 New 帧内联数据——Go `handleStatusNew`（server.go:196-240）先经
    /// `NewPacketReader` 读出，dispatch 后 `link.Writer.WriteMultiBuffer(mb)` 转发，
    /// **不得丢弃**（bd 6z8 回归）。
    ///
    /// 会话装配对齐 Go server.go:247-260：`x.Mux` 即加入 sessionManager 的那个
    /// 会话——input=link.Reader（真实上游 I/O）、output=link.Writer（Keep 帧
    /// 下行转发目标），`handle()` 泵任务读真 I/O 回写 carrier。旧实现的孤儿
    /// ms 使泵任务读空 input 立即退出，上游数据永远回不来。
    pub async fn handle_xudp_new(
        &self, meta: &FrameMetadata,
        data: Vec<u8>,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
        global_id: [u8; 8],
    ) -> Result<(), ServerError> {
        let target = meta.target().cloned().ok_or_else(|| {
            ServerError::InvalidFrame("XUDP session without target".to_string())
        })?;
        let xmgr = &self.xudp_manager;
        let mut xudp = match xmgr.get(&global_id).await {
            None => { let x = XUDP::new(global_id); xmgr.register(x.clone()).await; x }
            Some(mut ex) => {
                if ex.status == XudpStatus::Initializing {
                    warn!("XUDP conflict {:?}", global_id);
                    return Ok(());
                }
                ex.status = XudpStatus::Initializing;
                xmgr.register(ex.clone()).await; // Go 指针原地改状态的 Rust 等价
                ex
            }
        };
        let link = match self.dispatcher.dispatch(target.clone()).await {
            Ok(l) => l,
            Err(e) => {
                xmgr.unregister(&global_id).await;
                return Err(ServerError::DispatchFailed(format!("XUDP dispatch: {}", e)));
            }
        };
        // XUDP 恒为 Packet：直写（禁缓冲），New 帧内联 data 转发到 dispatch 目标
        // （Go server.go:240 `link.Writer.WriteMultiBuffer(mb)`）。
        // ponytail: Go hit 路径（同 GlobalID 复用）把 data 写旧 mux output 保持
        // 旧 UDP 流；此处统一写新 session output——数据不丢，流身份不保留，
        // 需要流连续性时再复用 xudp.mux 的 input/output。
        let mut output = BufferedWriter::new(link.writer);
        output.set_buffered(false);
        if !data.is_empty() {
            output
                .write_multi_buffer_impl(MultiBuffer::from_buffer(Buffer::from_vec(data)))
                .await
                .map_err(|e| ServerError::DispatchFailed(format!("XUDP initial data: {e}")))?;
        }
        let session = Session::new(meta.session_id(), TransferType::Packet);
        session.set_input(BufferedReader::new(link.reader)).await;
        session.set_output(output).await;
        let Some(session) = self.session_manager.add(session).await else {
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        };
        xudp.set_mux(&session);
        xudp.status = XudpStatus::Active;
        // 注册表条目与 session 内快照都取 Active+mux（注册表存 clone，需重注册
        // 写回）：close 时 Active→Expiring，后续同 GlobalID New 可命中复用。
        session.set_xudp(xudp.clone()).await;
        xmgr.register(xudp).await;
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }

    /// Handle session output (upstream data back to mux).
    ///
    /// 多 session 经 [`SharedWriter`] 共写 carrier 写端（旧实现 `take()`
    /// 独占写端，第二个 session 会拿到 None 直接关闭，无法多路复用）。
    async fn handle_session_output(
        session: Arc<Session>,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) {
        let mut rw = MuxWriter::new_response_writer(
            session.id(),
            Box::new(crate::writer::SharedWriter::new(Arc::clone(&link_writer))),
            session.transfer_type(),
        );
        let mut done = session.done_receiver();
        loop {
            let mut input = session.input().await;
            let Some(reader) = input.as_mut() else { break };
            // select session done：Session::close 需先拿 input 锁才能中断，
            // 持锁阻塞读期间必须可被 done 打断，否则与 close 互相等待死锁
            let read = tokio::select! {
                r = reader.read_multi_buffer() => Some(r),
                _ = crate::client::wait_done(done.clone()) => None,
            };
            let mb = match read {
                Some(Ok(mb)) => mb,
                Some(Err(_)) => {
                    rw.set_error();
                    break;
                }
                None => break,
            };
            if mb.is_empty() {
                break;
            }
            let byte_count = mb.len() as u64;
            session.add_downlink_bytes(byte_count);
            session.touch_active().await;
            if rw.write(mb).await.is_err() {
                rw.set_error();
                break;
            }
        }
        let _ = rw.close().await;
        session.close().await;
    }

    /// 处理主连接的下一帧（frame dispatcher 主循环单步）。
    ///
    /// 从 `reader` 读取一个完整的 Mux 帧（metadata + optional data），
    /// 按 session_status 分发到对应 handler。
    /// 返回 `Ok(true)` 表示成功处理可继续，`Ok(false)` 表示干净 EOF。
    ///
    /// 对应 Go 版本 `ServerWorker.handleFrame`，单次调用不 spawn 长任务，
    /// 适合测试与可控制并发的场景。
    pub async fn process_frame(
        &self,
        reader: &mut BufferedReader,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> Result<bool, ServerError> {
        // 1. 读 2B length（EOF 返 Ok(false) 表示干净关闭）
        let len_buf = match Self::read_exact_async(reader, 2).await {
            Ok(b) => b,
            Err(ServerError::InvalidFrame(msg)) if msg.starts_with("EOF") => return Ok(false),
            Err(e) => return Err(e),
        };
        let meta_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        if meta_len > MAX_METADATA_LEN {
            return Err(ServerError::InvalidFrame(format!("meta_len too large: {}", meta_len)));
        }
        // 2. 读 body
        let body = Self::read_exact_async(reader, meta_len).await?;
        // 3. 解析 metadata（拼回完整 bytes 调 read_from_bytes，因为它需 length 前缀）
        let mut full = Vec::with_capacity(2 + meta_len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);
        let (meta, _) = FrameMetadata::read_from_bytes(&full)
            .map_err(|e| ServerError::InvalidFrame(format!("parse meta: {:?}", e)))?;
        // 4. 如有 data，读 data（2B size + payload）
        let data = if meta.has_data() {
            let size_buf = Self::read_exact_async(reader, 2).await?;
            let size = u16::from_be_bytes([size_buf[0], size_buf[1]]) as usize;
            Self::read_exact_async(reader, size).await?
        } else {
            Vec::new()
        };
        // 5. 按 status 分发
        match meta.session_status() {
            SessionStatus::New => {
                if meta.is_udp_target() && meta.global_id().is_some() {
                    let gid = *meta.global_id().unwrap();
                    self.handle_xudp_new(&meta, data, link_writer, gid).await?;
                } else {
                    self.handle_normal_new(&meta, data, link_writer).await?;
                }
            }
            SessionStatus::Keep => self.handle_status_keep(&meta, data).await?,
            SessionStatus::End => self.handle_status_end(&meta).await?,
            SessionStatus::KeepAlive => {}, // data 已读出丢弃
        }
        Ok(true)
    }

    /// 处理 Keep 帧：把 data 写到对应 session.output（转发到上游 dispatcher 目标）。
    ///
    /// 未知 session_id 静默丢弃（对端可能已 End）。
    pub async fn handle_status_keep(
        &self,
        meta: &FrameMetadata,
        data: Vec<u8>,
    ) -> Result<(), ServerError> {
        if data.is_empty() {
            return Ok(());
        }
        let data_len = data.len() as u64;
        let session = match self.session_manager.get(meta.session_id()).await {
            Some(s) => s,
            None => return Ok(()),
        };
        // 更新流量统计和活跃时间
        session.add_uplink_bytes(data_len);
        session.touch_active().await;
        let mut guard = session.output().await;
        if let Some(ref mut writer) = *guard {
            let mb = MultiBuffer::from_buffer(Buffer::from_vec(data));
            let _ = writer.write_multi_buffer_impl(mb).await;
        }
        Ok(())
    }

    /// 处理 End 帧：关闭并移除对应 session。
    pub async fn handle_status_end(&self, meta: &FrameMetadata) -> Result<(), ServerError> {
        if let Some(session) = self.session_manager.get(meta.session_id()).await {
            session.close().await;
        }
        Ok(())
    }

    /// 异步精确读取 n 字节，EOF 时返回带 "EOF" 前缀的 InvalidFrame 错误。
    async fn read_exact_async(reader: &mut BufferedReader, n: usize) -> Result<Vec<u8>, ServerError> {
        let mut buf = vec![0u8; n];
        let mut read = 0;
        while read < n {
            let r = reader.read(&mut buf[read..]).await;
            if r == 0 {
                return Err(ServerError::InvalidFrame(format!(
                    "EOF reading {} bytes at offset {}",
                    n, read
                )));
            }
            read += r;
        }
        Ok(buf)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("dispatch failed: {0}")]
    DispatchFailed(String),
    #[error("failed to add session {0}")]
    SessionAddFailed(u16),
    #[error("XUDP conflict: {0}")]
    XudpConflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;

    struct MockDispatcher;
    #[async_trait::async_trait]
    impl Dispatcher for MockDispatcher {
        async fn dispatch(&self, _dest: Destination) -> Result<Link, DispatchError> {
            Err(DispatchError::NoRoute("mock".to_string()))
        }
    }

    #[test]
    fn test_server_keepalive_interval() {
        assert_eq!(SERVER_KEEPALIVE_INTERVAL, Duration::from_secs(60));
    }

    #[test]
    fn test_dispatch_error_display() {
        assert_eq!(format!("{}", DispatchError::NoRoute("1.2.3.4".to_string())), "no route to destination: 1.2.3.4");
    }

    #[test]
    fn test_server_error_display() {
        assert_eq!(format!("{}", ServerError::InvalidFrame("bad".to_string())), "invalid frame: bad");
    }

    #[tokio::test]
    async fn test_server_worker_new() {
        let worker = ServerWorker::new(Arc::new(MockDispatcher));
        assert!(!worker.is_closed());
        assert_eq!(worker.active_connections().await, 0);
    }

    #[tokio::test]
    async fn test_server_worker_close() {
        let worker = ServerWorker::new(Arc::new(MockDispatcher));
        worker.close();
        assert!(worker.is_closed());
    }

    #[test]
    fn test_server_is_mux_destination() {
        let d = Destination::new(Address::new_domain(MUX_COOL_ADDRESS), Port::new(9527), Network::TCP);
        assert!(Server::is_mux_destination(&d));
    }

    #[tokio::test]
    async fn test_server_dispatch_non_mux() {
        let server = Server::new(Arc::new(MockDispatcher));
        let d = Destination::new(Address::new_domain("example.com".to_string()), Port::new(443), Network::TCP);
        assert!(server.dispatch(&d).await.is_err());
    }

    #[test]
    fn test_dispatch_error_is_std_error() {
        let err = DispatchError::NoRoute("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_server_error_is_std_error() {
        let err = ServerError::InvalidFrame("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_server_keepalive_interval_60s() {
        assert_eq!(SERVER_KEEPALIVE_INTERVAL, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_session_manager_active_sessions() {
        let worker = ServerWorker::new(Arc::new(MockDispatcher));
        let sm = worker.session_manager();
        assert_eq!(sm.active_sessions().await.len(), 0);
        let strategy = crate::session::ClientStrategy::default();
        let _s = sm.allocate(&strategy).await;
        assert_eq!(sm.active_sessions().await.len(), 1);
    }

    #[tokio::test]
    async fn test_dispatch_handler_adapter_creates_link() {
        use xray_app_dispatcher::default::DispatchHandler;
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;

        #[derive(Debug)]
        struct NopHandler;
        impl DispatchHandler for NopHandler {
            fn tag(&self) -> &str { "nop" }
            fn dispatch(
                &self,
                _dest: &xray_common::net::destination::Destination,
                _link: xray_transport::link::Link,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
                Box::pin(async {})
            }
        }

        let adapter = DispatchHandlerAdapter::new(Arc::new(NopHandler));
        let dest = Destination::new(Address::new_domain("example.com".to_string()), Port::new(443), Network::TCP);
        let result = adapter.dispatch(dest).await;
        assert!(result.is_ok(), "adapter should return a link");
    }

    // ===== bd 6z8：XUDP gate 触发 + New 帧内联 data 转发 + 首帧即时送达 =====

    mod gate_tests {
        use super::*;
        use std::sync::Arc;
        use tokio::sync::Mutex as AsyncMutex;
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::pipe;
        use xray_buf::reader::BufferedReader;
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;
        use xray_common::serial;

        /// 捕获 dispatcher：记录 dispatch dest，交出 payload 读端
        /// （ret writer 保活，防 session input 立即 EOF）。
        #[derive(Clone)]
        struct CaptureDispatcher {
            tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Reader)>,
            keepers: Arc<parking_lot::Mutex<Vec<pipe::Writer>>>,
        }

        #[async_trait::async_trait]
        impl Dispatcher for CaptureDispatcher {
            async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
                let (ret_r, ret_w) = pipe::new();
                let (pay_r, pay_w) = pipe::new();
                self.keepers.lock().push(ret_w);
                let _ = self.tx.send((dest.clone(), pay_r));
                Ok(Link {
                    reader: Box::new(ret_r),
                    writer: Box::new(pay_w),
                })
            }
        }

        fn udp_dest() -> Destination {
            Destination::new(
                Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                Port::new(53),
                Network::UDP,
            )
        }

        fn tcp_dest() -> Destination {
            Destination::new(
                Address::new_domain("example.com".to_string()),
                Port::new(443),
                Network::TCP,
            )
        }

        /// New 帧 + 内联 data 的线格式（meta + 2B size + payload）。
        fn new_frame_with_data(meta: FrameMetadata, payload: &[u8]) -> Vec<u8> {
            let mut buf = meta.to_bytes();
            buf.extend_from_slice(&serial::write_uint16(payload.len() as u16));
            buf.extend_from_slice(payload);
            buf
        }

        /// 喂一帧到 ServerWorker，返回 dispatch 结果 (dest, payload reader)。
        async fn process_one_frame(
            frame: Vec<u8>,
        ) -> (Destination, pipe::Reader, Arc<ServerWorker>) {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let dispatcher = CaptureDispatcher {
                tx,
                keepers: Arc::new(parking_lot::Mutex::new(Vec::new())),
            };
            let server = Arc::new(ServerWorker::new(Arc::new(dispatcher)));
            let (_lw_r, lw_w) = pipe::new();
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(lw_w))));
            let mut reader = BufferedReader::new(xray_buf::io::new_reader(
                std::io::Cursor::new(frame),
            ));
            let ok = server
                .process_frame(&mut reader, &link_writer)
                .await
                .expect("frame processed");
            assert!(ok, "frame should be processed");
            let (dest, pay) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("dispatch captured")
                .expect("channel open");
            (dest, pay, server)
        }

        /// 从 payload 读端读出全部字节（短超时：验证即时送达，非缓冲滞留）。
        async fn read_payload(pay: &mut pipe::Reader) -> Vec<u8> {
            let mb = tokio::time::timeout(std::time::Duration::from_millis(1500), pay.read_multi_buffer())
                .await
                .expect("payload must arrive without further writes (no buffer stall)")
                .expect("read ok");
            let mut out = Vec::new();
            for b in mb.iter() {
                out.extend_from_slice(b.bytes());
            }
            out
        }

        /// XUDP gate：New + UDP + global_id → handle_xudp_new 路径，
        /// 内联 data 必须转发到 dispatch 目标（Go server.go:240）。bd 6z8。
        #[tokio::test]
        async fn xudp_new_frame_forwards_inline_data() {
            let gid = [9u8; 8];
            let mut meta = FrameMetadata::new_session(7, udp_dest());
            meta.set_global_id(gid);
            let frame = new_frame_with_data(meta, b"first-udp-packet");

            let (dest, mut pay, _server) = process_one_frame(frame).await;

            assert_eq!(dest.network(), Network::UDP);
            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"first-udp-packet");
        }

        /// 普通路径：New + UDP（无 global_id）→ handle_normal_new Packet 会话，
        /// 小包首帧即时送达（不得滞留 BufferedWriter 缓冲）。bd 6z8。
        #[tokio::test]
        async fn udp_new_small_first_frame_immediate() {
            let meta = FrameMetadata::new_session(8, udp_dest());
            let frame = new_frame_with_data(meta, b"tiny");

            let (_dest, mut pay, _server) = process_one_frame(frame).await;

            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"tiny");
        }

        /// 普通路径：New + TCP Stream 会话小首帧也即时送达。bd 6z8。
        #[tokio::test]
        async fn tcp_new_small_first_frame_immediate() {
            let meta = FrameMetadata::new_session(9, tcp_dest());
            let frame = new_frame_with_data(meta, b"GET /");

            let (_dest, mut pay, _server) = process_one_frame(frame).await;

            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"GET /");
        }
    }

    /// XUDP e2e：client GlobalID 接线 + server 装配 + 双向收发。
    mod xudp_e2e_tests {
        use super::*;
        use crate::client::{ClientWorker, Link as ClientLink};
        use crate::session::ClientStrategy;
        use tokio::sync::Mutex as AsyncMutex;
        use xray_buf::pipe;

        /// UDP 捕获 dispatcher：交出"注入上游响应"的写端与"观察客户端
        /// 上行"的读端（Go 等价：真 UDP socket 两方向）。
        struct UdpCaptureDispatcher {
            tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Writer, pipe::Reader)>,
        }

        #[async_trait::async_trait]
        impl Dispatcher for UdpCaptureDispatcher {
            async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
                let (r_down, w_down) = pipe::new(); // 上游→客户端：测试持 w_down 注入
                let (up_r, up_w) = pipe::new(); // 客户端→上游：测试持 up_r 观察
                let _ = self.tx.send((dest, w_down, up_r));
                Ok(Link {
                    reader: Box::new(r_down),
                    writer: Box::new(up_w),
                })
            }
        }

        fn udp_target() -> Destination {
            Destination::new(
                Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                Port::new(53),
                Network::UDP,
            )
        }

        /// ClientWorker ↔ ServerWorker 直连管道拓扑 + UDP 捕获 dispatcher。
        async fn spawn_topology()
        -> (Arc<ClientWorker>, Arc<ServerWorker>, tokio::sync::mpsc::UnboundedReceiver<(Destination, pipe::Writer, pipe::Reader)>) {
            let (c_read, s_write) = pipe::new(); // server → client
            let (s_read, c_write) = pipe::new(); // client → server
            let client = ClientWorker::new(
                ClientLink {
                    reader: Box::new(c_read),
                    writer: Box::new(c_write),
                },
                ClientStrategy::default(),
            );
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let server = Arc::new(ServerWorker::new(Arc::new(UdpCaptureDispatcher { tx })));
            let mut reader = BufferedReader::new(Box::new(s_read));
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(s_write))));
            let (ka, idle) = server.spawn_keepalive_and_idle_timeout(Arc::clone(&link_writer));
            let frame_server = Arc::clone(&server);
            tokio::spawn(async move {
                loop {
                    match frame_server.process_frame(&mut reader, &link_writer).await {
                        Ok(true) => continue,
                        _ => break,
                    }
                }
                frame_server.close();
                ka.abort();
                idle.abort();
            });
            (client, server, rx)
        }

        async fn read_all(r: &mut pipe::Reader) -> Vec<u8> {
            let mb = tokio::time::timeout(std::time::Duration::from_secs(3), r.read_multi_buffer())
                .await
                .expect("payload within timeout")
                .expect("read ok");
            let mut out = Vec::new();
            for b in mb.iter() {
                out.extend_from_slice(b.bytes());
            }
            out
        }

        /// 验收：XUDP New 后能收发。客户端 dispatch_with_source 按 cone 入站源
        /// 计算 GlobalID（Go client.go:271），服务端装配 XUDP 会话（Go
        /// server.go:247-260：manager session 直绑 dispatch I/O，泵任务读真
        /// I/O 回写 carrier——旧实现孤儿 ms 使上游响应永远回不来）。
        #[tokio::test]
        async fn xudp_new_bidirectional_send_receive() {
            use xray_xudp::GlobalIdInput;

            let (client, server, mut rx) = spawn_topology().await;

            // 客户端：UDP dest + cone 入站源 → GlobalID 随 New 帧下发
            let input = GlobalIdInput {
                source: "udp:10.0.0.1:5400".to_string(),
                source_network: Network::UDP,
                cone: true,
            };
            let gid = xray_xudp::global_id(&input);
            assert_ne!(gid, [0u8; 8], "cone UDP source must yield nonzero GlobalID");

            let (req_rd, req_wr) = pipe::new();
            let (resp_rd, resp_wr) = pipe::new();
            // 先写上行 payload（探针窗口内就绪）→ fetch_input 首读即得数据，
            // New 帧携带内联 data + GlobalID 同批下发（Go XUDP 线形态；空 New
            // 按 Go frame.go:216 语义不带 GlobalID，服务端按普通 packet 路径）。
            let mut req = req_wr;
            req.write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                b"dns-query".to_vec(),
            )))
            .await
            .expect("write uplink");

            let w = Arc::clone(&client);
            let d = udp_target();
            let task = tokio::spawn(async move {
                w.dispatch_with_source(&d, ClientLink {
                    reader: Box::new(req_rd),
                    writer: Box::new(resp_wr),
                }, Some(&input))
                .await
            });

            // 服务端 dispatch UDP 目标 + XUDP 装配完成（Active + mux 接线）
            let (dest, w_down, mut up_r) =
                tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
                    .await
                    .expect("dispatch within timeout")
                    .expect("channel open");
            assert_eq!(dest.network(), Network::UDP);
            assert_eq!(server.active_connections().await, 1, "XUDP session registered");
            let entry = server
                .xudp_manager
                .get(&gid)
                .await
                .expect("XUDP entry keyed by client GlobalID");
            assert_eq!(entry.status, XudpStatus::Active, "entry must be Active after assembly");

            // 上行：New 内联 data → 到达"上游"读端
            let got = read_all(&mut up_r).await;
            assert_eq!(got, b"dns-query", "uplink must reach dispatch target");

            // 下行：上游响应 → 泵任务读真 I/O → Keep 帧 → 客户端 resp 读端
            let mut resp = resp_rd;
            let mut pong = w_down;
            pong.write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                b"dns-answer".to_vec(),
            )))
            .await
            .expect("write downlink");
            let _ = pong.close();
            let back = tokio::time::timeout(std::time::Duration::from_secs(3), resp.read_multi_buffer())
                .await
                .expect("downlink within timeout")
                .expect("read ok");
            assert_eq!(back.to_vec(), b"dns-answer", "upstream response must flow back via pump");

            // 收尾：客户端半关闭 → End → server session 摘除
            let _ = req.close();
            let _ = task.await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), resp.read_multi_buffer()).await;
        }
    }
}