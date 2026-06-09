//! Mux server
//!
//! Corresponds to Go version `common/mux/server.go`.

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
use crate::frame::FrameMetadata;
use crate::session::{Session, SessionManager, TransferType, XUDP, XUDPManager, XudpStatus};
use crate::writer::MuxWriter;

/// Server keepalive interval (60 seconds).
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

    /// Handle normal New frame (non-XUDP).
    pub async fn handle_normal_new(
        &self, meta: &FrameMetadata,
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
}