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
        let session = Arc::new(Session::new(meta.session_id(), tt));
        session.set_input(BufferedReader::new(link.reader)).await;
        session.set_output(BufferedWriter::new(link.writer)).await;
        if !self.session_manager.add(session.clone()).await {
            session.close().await;
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        }
        // 写入 New frame 的 data 到 session.output（在 spawn 反向 task 前同步完成，
        // 对齐 Go handleStatusNew 中 `buf.Copy(rr, s.output)` 的语义）
        if !data.is_empty() {
            let mut guard = session.output().await;
            if let Some(ref mut writer) = *guard {
                let mb = MultiBuffer::from_buffer(Buffer::from_vec(data));
                let _ = writer.write_multi_buffer_impl(mb).await;
            }
        }
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }

    /// Handle XUDP New frame.
    pub async fn handle_xudp_new(
        &self, meta: &FrameMetadata,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
        global_id: [u8; 8],
    ) -> Result<(), ServerError> {
        let target = meta.target().cloned().ok_or_else(|| {
            ServerError::InvalidFrame("XUDP session without target".to_string())
        })?;
        let xmgr = &self.xudp_manager;
        let existing = xmgr.get(&global_id).await;
        let mut xudp = match existing {
            None => { let x = XUDP::new(global_id); xmgr.register(x.clone()).await; x }
            Some(mut ex) => {
                if ex.status == XudpStatus::Initializing {
                    warn!("XUDP conflict {:?}", global_id);
                    return Ok(());
                }
                ex.status = XudpStatus::Initializing;
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
        let ms = Arc::new(Session::new(meta.session_id(), TransferType::Packet));
        ms.set_input(BufferedReader::new(link.reader)).await;
        ms.set_output(BufferedWriter::new(link.writer)).await;
        xudp.set_mux(&ms);
        let session = Arc::new(Session::new(meta.session_id(), TransferType::Packet));
        session.set_xudp(xudp.clone()).await;
        if !self.session_manager.add(session.clone()).await {
            session.close().await;
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        }
        xudp.status = XudpStatus::Active;
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }

    /// Handle session output (upstream data back to mux).
    async fn handle_session_output(
        session: Arc<Session>,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) {
        let writer = {
            let mut wg = link_writer.lock().await;
            wg.take()
        };
        let writer = match writer {
            Some(w) => w,
            None => { session.close().await; return; }
        };
        let mut rw = MuxWriter::new_response_writer(session.id(), writer, session.transfer_type());
        loop {
            let mut input = session.input().await;
            match input.as_mut() {
                Some(reader) => match reader.read_multi_buffer().await {
                    Ok(mb) => {
                        if mb.is_empty() { break; }
                        let byte_count = mb.len() as u64;
                        session.add_downlink_bytes(byte_count);
                        session.touch_active().await;
                        if rw.write(mb).await.is_err() { rw.set_error(); break; }
                    }
                    Err(_) => { rw.set_error(); break; }
                },
                None => break,
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
                    self.handle_xudp_new(&meta, link_writer, gid).await?;
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
}