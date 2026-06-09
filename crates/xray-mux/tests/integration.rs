//! Mux 集成测试
//!
//! 端到端测试: 帧格式序列化/反序列化、SessionManager 并发安全、
//! ServerWorker 与 Dispatcher 集成、ClientWorker 会话分配。

use std::sync::Arc;

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_mux::session::{ClientStrategy, SessionManager, TransferType};
use xray_mux::frame::{FrameMetadata, SessionStatus};
use xray_mux::client::{ClientWorker, ClientManager, Link, MUX_COOL_ADDRESS, WorkerPicker};
use xray_mux::worker::{Dispatcher, DispatchError, Server, ServerWorker};
use xray_buf::io::Writer;

// ========== Mock Dispatcher ==========

struct MockDispatcher;

#[async_trait::async_trait]
impl Dispatcher for MockDispatcher {
    async fn dispatch(&self, _dest: Destination) -> Result<Link, DispatchError> {
        Err(DispatchError::NoRoute("mock no route".to_string()))
    }
}

// ========== 常量验证 ==========

#[test]
fn test_mux_constants() {
    assert_eq!(MUX_COOL_ADDRESS, "v1.mux.cool");
    assert_eq!(xray_mux::client::MUX_COOL_PORT, 9527);
    assert_eq!(xray_mux::client::MAX_DISPATCH_RETRY, 16);
    assert_eq!(xray_mux::worker::SERVER_KEEPALIVE_INTERVAL, std::time::Duration::from_secs(60));
}

// ========== SessionManager 集成 ==========

#[tokio::test]
async fn test_session_manager_allocate_and_size() {
    let mgr = Arc::new(SessionManager::new());
    let strategy = ClientStrategy::default();

    let s1 = mgr.allocate(&strategy).await;
    assert!(s1.is_some(), "should allocate a session");
    let s1 = s1.unwrap();
    assert_eq!(s1.id(), 1);
    assert_eq!(mgr.size().await, 1);

    let s2 = mgr.allocate(&strategy).await;
    assert!(s2.is_some());
    assert_eq!(mgr.size().await, 2);
}

#[tokio::test]
async fn test_session_manager_get_and_remove() {
    let mgr = Arc::new(SessionManager::new());
    let strategy = ClientStrategy::default();
    let s = mgr.allocate(&strategy).await.unwrap();
    assert_eq!(mgr.size().await, 1);

    let got = mgr.get(s.id()).await;
    assert!(got.is_some());

    mgr.remove(s.id()).await;
    assert_eq!(mgr.size().await, 0);
    assert!(mgr.get(s.id()).await.is_none());
}

#[tokio::test]
async fn test_session_manager_max_concurrency() {
    let mgr = Arc::new(SessionManager::new());
    let strategy = ClientStrategy {
        max_concurrency: 2,
        max_connection: 0,
    };

    let s1 = mgr.allocate(&strategy).await;
    assert!(s1.is_some());
    let s2 = mgr.allocate(&strategy).await;
    assert!(s2.is_some());
    let s3 = mgr.allocate(&strategy).await;
    assert!(s3.is_none(), "should fail when max concurrency reached");
}

#[tokio::test]
async fn test_session_manager_close_if_no_session() {
    let mgr = Arc::new(SessionManager::new());
    let closed = mgr.close_if_no_session_and_idle(0, 0).await;
    assert!(closed);
    assert!(mgr.is_closed());
}

// ========== FrameMetadata 往返 ==========

#[test]
fn test_frame_metadata_roundtrip_new_session() {
    let dest = Destination::new(
        Address::new_domain("example.com".to_string()),
        Port::new(443),
        Network::TCP,
    );
    let meta = FrameMetadata::new_session(42, dest);
    let bytes = meta.to_bytes();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 42);
    assert_eq!(parsed.session_status(), SessionStatus::New);
    assert!(parsed.target().is_some());
}

#[test]
fn test_frame_metadata_roundtrip_end_session() {
    let meta = FrameMetadata::end_session(7);
    let bytes = meta.to_bytes();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 7);
    assert_eq!(parsed.session_status(), SessionStatus::End);
}

#[test]
fn test_frame_metadata_roundtrip_keep_alive() {
    let meta = FrameMetadata::keep_alive(99);
    let bytes = meta.to_bytes();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 99);
    assert_eq!(parsed.session_status(), SessionStatus::KeepAlive);
}

#[test]
fn test_frame_metadata_udp_target() {
    let dest = Destination::new(
        Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        Port::new(53),
        Network::UDP,
    );
    let meta = FrameMetadata::new_session(10, dest);
    let bytes = meta.to_bytes();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 10);
    assert!(parsed.is_udp_target());
}

// ========== ServerWorker 集成 ==========

#[tokio::test]
async fn test_server_worker_new_and_close() {
    let worker = ServerWorker::new(Arc::new(MockDispatcher));
    assert!(!worker.is_closed());
    assert_eq!(worker.active_connections().await, 0);
    worker.close();
    assert!(worker.is_closed());
}

#[tokio::test]
async fn test_server_worker_dispatch_fails_with_mock() {
    let worker = ServerWorker::new(Arc::new(MockDispatcher));
    let dest = Destination::new(
        Address::new_domain("example.com".to_string()),
        Port::new(443),
        Network::TCP,
    );
    let link_writer = Arc::new(tokio::sync::Mutex::new(None::<Box<dyn Writer>>));
    let meta = FrameMetadata::new_session(1, dest);
    let result = worker.handle_normal_new(&meta, &link_writer).await;
    assert!(result.is_err());
}

#[test]
fn test_server_is_mux_destination() {
    let d_mux = Destination::new(
        Address::new_domain(MUX_COOL_ADDRESS.to_string()),
        Port::new(9527),
        Network::TCP,
    );
    assert!(Server::is_mux_destination(&d_mux));

    let d_normal = Destination::new(
        Address::new_domain("example.com".to_string()),
        Port::new(443),
        Network::TCP,
    );
    assert!(!Server::is_mux_destination(&d_normal));
}

// ========== ClientWorker 集成 ==========

#[tokio::test]
async fn test_client_worker_allocate_session() {
    let worker = Arc::new(ClientWorker::new(ClientStrategy::default()));
    let session = worker.allocate_session().await;
    assert!(session.is_some());
    let s = session.unwrap();
    assert!(!s.is_closed());
    assert_eq!(worker.session_count(), 1);
}

#[tokio::test]
async fn test_client_worker_max_concurrency() {
    let strategy = ClientStrategy {
        max_concurrency: 1,
        max_connection: 0,
    };
    let worker = Arc::new(ClientWorker::new(strategy));
    let s1 = worker.allocate_session().await;
    assert!(s1.is_some());
    let s2 = worker.allocate_session().await;
    assert!(s2.is_none(), "should fail when max concurrency reached");
}

#[tokio::test]
async fn test_client_worker_close() {
    let worker = Arc::new(ClientWorker::new(ClientStrategy::default()));
    assert!(!worker.is_closed());
    worker.close();
    assert!(worker.is_closed());
}

#[tokio::test]
async fn test_client_worker_is_full_with_max_connection() {
    let strategy = ClientStrategy {
        max_concurrency: 0,
        max_connection: 1,
    };
    let worker = Arc::new(ClientWorker::new(strategy));
    assert!(!worker.is_full());
    assert!(!worker.is_closing());

    let _s = worker.allocate_session().await;
    assert!(worker.is_closing());
    assert!(worker.is_full());
}

// ========== ClientManager 集成 ==========

struct AlwaysFailPicker;

impl WorkerPicker for AlwaysFailPicker {
    fn pick_available(&self) -> Option<Arc<ClientWorker>> {
        None
    }
}

#[tokio::test]
async fn test_client_manager_dispatch_fails() {
    let mgr = ClientManager::new(false, Box::new(AlwaysFailPicker));
    let result = mgr.dispatch();
    assert!(result.is_err());
}

struct SingleWorkerPicker {
    worker: Arc<ClientWorker>,
}

impl WorkerPicker for SingleWorkerPicker {
    fn pick_available(&self) -> Option<Arc<ClientWorker>> {
        Some(self.worker.clone())
    }
}

#[tokio::test]
async fn test_client_manager_dispatch_success() {
    let worker = Arc::new(ClientWorker::new(ClientStrategy::default()));
    let mgr = ClientManager::new(true, Box::new(SingleWorkerPicker { worker }));
    let result = mgr.dispatch();
    assert!(result.is_ok());
}

// ========== Session 关闭信号 ==========

#[tokio::test]
async fn test_session_close_signal() {
    let mgr = Arc::new(SessionManager::new());
    let strategy = ClientStrategy::default();
    let s = mgr.allocate(&strategy).await.unwrap();

    let mut rx = s.done_receiver();
    assert!(!s.is_closed());

    s.close().await;
    assert!(s.is_closed());

    let changed = rx.changed().await;
    assert!(changed.is_ok());
    assert!(*rx.borrow_and_update());
}

// ========== IncrementalWorkerPicker 集成 ==========

#[tokio::test]
async fn test_incremental_picker_empty_initially() {
    use xray_mux::client::{DialingWorkerFactory, IncrementalWorkerPicker};

    let factory = Arc::new(DialingWorkerFactory::new(ClientStrategy::default()));
    let picker = IncrementalWorkerPicker::new(factory);
    assert_eq!(picker.worker_count().await, 0);
}
