//! Mux 集成测试
//!
//! 端到端测试: 帧格式序列化/反序列化、SessionManager 并发安全、
//! ServerWorker 与 Dispatcher 集成、ClientWorker 会话分配。

use std::sync::Arc;

use xray_buf::io::Writer;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_mux::{
    client::{ClientManager, ClientWorker, Link, MUX_COOL_ADDRESS, WorkerPicker},
    frame::{FrameMetadata, SessionStatus},
    session::{ClientStrategy, SessionManager},
    worker::{DispatchError, Dispatcher, Server, ServerWorker},
};

/// 回环 carrier 的测试 worker。
fn loop_worker(strategy: ClientStrategy) -> Arc<ClientWorker> {
    let (r, w) = xray_buf::pipe::new();
    ClientWorker::new(Link { reader: Box::new(r), writer: Box::new(w) }, strategy)
}

/// 空底层 handler（dispatch 立即返回）。
#[derive(Debug)]
struct NopUnderlying;
impl xray_app_dispatcher::DispatchHandler for NopUnderlying {
    fn tag(&self) -> &str {
        "nop"
    }

    fn dispatch(
        &self,
        _dest: &Destination,
        _link: xray_transport::link::Link,
    ) -> xray_app_dispatcher::default::PinFuture<()> {
        Box::pin(async {})
    }
}
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
    assert_eq!(xray_mux::worker::SERVER_MONITOR_INTERVAL, std::time::Duration::from_secs(60));
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
    let strategy = ClientStrategy { max_concurrency: 2, max_connection: 0 };

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
    let bytes = meta.to_bytes().unwrap();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 42);
    assert_eq!(parsed.session_status(), SessionStatus::New);
    assert!(parsed.target().is_some());
}

#[test]
fn test_frame_metadata_roundtrip_end_session() {
    let meta = FrameMetadata::end_session(7);
    let bytes = meta.to_bytes().unwrap();
    let (parsed, _) = FrameMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.session_id(), 7);
    assert_eq!(parsed.session_status(), SessionStatus::End);
}

#[test]
fn test_frame_metadata_roundtrip_keep_alive() {
    let meta = FrameMetadata::keep_alive(99);
    let bytes = meta.to_bytes().unwrap();
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
    let bytes = meta.to_bytes().unwrap();
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
    let result = worker
        .handle_normal_new(&meta, xray_buf::buffer::Buffer::with_capacity(0), &link_writer)
        .await;
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
    let worker = loop_worker(ClientStrategy::default());
    let session = worker.allocate_session().await;
    assert!(session.is_some());
    let s = session.unwrap();
    assert!(!s.is_closed());
    assert_eq!(worker.session_count(), 1);
}

#[tokio::test]
async fn test_client_worker_max_concurrency() {
    let strategy = ClientStrategy { max_concurrency: 1, max_connection: 0 };
    let worker = loop_worker(strategy);
    let s1 = worker.allocate_session().await;
    assert!(s1.is_some());
    let s2 = worker.allocate_session().await;
    assert!(s2.is_none(), "should fail when max concurrency reached");
}

#[tokio::test]
async fn test_client_worker_close() {
    let worker = loop_worker(ClientStrategy::default());
    assert!(!worker.is_closed());
    worker.close();
    assert!(worker.is_closed());
}

#[tokio::test]
async fn test_client_worker_is_full_with_max_connection() {
    let strategy = ClientStrategy { max_concurrency: 0, max_connection: 1 };
    let worker = loop_worker(strategy);
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
    let worker = loop_worker(ClientStrategy::default());
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

    let factory =
        Arc::new(DialingWorkerFactory::new(Arc::new(NopUnderlying), ClientStrategy::default()));
    let picker = IncrementalWorkerPicker::new(factory);
    assert_eq!(picker.worker_count().await, 0);
}

// ========== process_frame E2E 多路复用 ==========

/// 成功 Dispatcher：返回空 Cursor 包装的 Link，记录所有 dispatch 的 dest。
struct SuccessDispatcher {
    dests: Arc<tokio::sync::Mutex<Vec<Destination>>>,
}

#[async_trait::async_trait]
impl Dispatcher for SuccessDispatcher {
    async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
        self.dests.lock().await.push(dest);
        // ponytail: 返回空 Cursor，反向 task 立即 EOF 退出（多 session 反向回写另见 follow-up）
        let reader: Box<dyn xray_buf::io::Reader> =
            xray_buf::io::new_reader(std::io::Cursor::new(Vec::<u8>::new()));
        let writer: Box<dyn Writer> =
            xray_buf::io::new_writer(std::io::Cursor::new(Vec::<u8>::new()));
        Ok(Link { reader, writer })
    }
}

/// 端到端验证：单 TCP 字节流上多 session frame 复用 → process_frame 分发。
///
/// 构造 2 个 session 的 New + data + End 序列，调 process_frame 循环，验证：
/// - 4 个 metadata 帧全部正确解析
/// - dispatcher 收到 2 个不同 dest（顺序保留）
/// - EOF 干净退出（Ok(false)）
#[tokio::test]
async fn test_e2e_multi_session_dispatch_via_process_frame() {
    use xray_buf::{io::new_reader, reader::BufferedReader};
    use xray_common::serial;

    let dests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let dispatcher = Arc::new(SuccessDispatcher { dests: dests.clone() });
    let worker = ServerWorker::new(dispatcher);

    let dest1 =
        Destination::new(Address::new_domain("a.com".to_string()), Port::new(80), Network::TCP);
    let dest2 =
        Destination::new(Address::new_domain("b.com".to_string()), Port::new(80), Network::TCP);

    // 构造字节流：session 1 New + data + End, session 2 New + data + End
    let mut bytes = Vec::new();
    FrameMetadata::new_session(1, dest1.clone()).write_to(&mut bytes).unwrap();
    bytes.extend_from_slice(&serial::write_uint16(5));
    bytes.extend_from_slice(b"hello");
    FrameMetadata::end_session(1).write_to(&mut bytes).unwrap();
    FrameMetadata::new_session(2, dest2.clone()).write_to(&mut bytes).unwrap();
    bytes.extend_from_slice(&serial::write_uint16(5));
    bytes.extend_from_slice(b"world");
    FrameMetadata::end_session(2).write_to(&mut bytes).unwrap();

    let reader = new_reader(std::io::Cursor::new(bytes));
    let mut br = BufferedReader::new(reader);
    let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let mut frame_count = 0;
    loop {
        match worker.process_frame(&mut br, &link_writer).await {
            Ok(true) => frame_count += 1,
            Ok(false) => break,
            Err(e) => panic!("process_frame error: {:?}", e),
        }
    }

    // 4 个 metadata 帧：New(s1) + End(s1) + New(s2) + End(s2)
    // data 是 New frame 的伴随 payload（OPTION_DATA），不是独立 metadata 帧
    assert_eq!(frame_count, 4);

    let dests_guard = dests.lock().await;
    assert_eq!(dests_guard.len(), 2);
    assert_eq!(dests_guard[0].address().to_string(), "a.com");
    assert_eq!(dests_guard[1].address().to_string(), "b.com");
}

/// 验证 process_frame 处理 Keep 帧：data 路由到已注册 session.output 不 panic。
#[tokio::test]
async fn test_e2e_keep_frame_routes_to_existing_session() {
    use xray_buf::{io::new_reader, reader::BufferedReader};
    use xray_common::bitmask::Bitmask;
    use xray_mux::frame::OPTION_DATA;

    let dests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let dispatcher = Arc::new(SuccessDispatcher { dests });
    let worker = ServerWorker::new(dispatcher);

    // 通过 SessionManager.allocate 创建 session（Session::new 为 pub(crate)）
    let strategy = ClientStrategy::default();
    let session = worker.session_manager().allocate(&strategy).await.unwrap();
    let sid = session.id();

    // 构造 Keep + data 帧（session.output 为 None，写入是 no-op，但不 panic）
    let mut bytes = Vec::new();
    let mut option = Bitmask::default();
    option.set(OPTION_DATA);
    let keep_meta = FrameMetadata::new(sid, SessionStatus::Keep, option);
    keep_meta.write_to(&mut bytes).unwrap();
    bytes.extend_from_slice(&xray_common::serial::write_uint16(5));
    bytes.extend_from_slice(b"keep!");

    let reader = new_reader(std::io::Cursor::new(bytes));
    let mut br = BufferedReader::new(reader);
    let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let result = worker.process_frame(&mut br, &link_writer).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
    assert!(!session.is_closed());
}

/// 验证空输入时 process_frame 干净返 Ok(false)。
#[tokio::test]
async fn test_e2e_process_frame_clean_eof() {
    use xray_buf::{io::new_reader, reader::BufferedReader};

    let dests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let dispatcher = Arc::new(SuccessDispatcher { dests });
    let worker = ServerWorker::new(dispatcher);

    let reader = new_reader(std::io::Cursor::new(Vec::<u8>::new()));
    let mut br = BufferedReader::new(reader);
    let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let result = worker.process_frame(&mut br, &link_writer).await;
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Ok(false) = EOF
}
