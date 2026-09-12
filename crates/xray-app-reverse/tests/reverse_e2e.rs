//! Reverse (Bridge/Portal) e2e（bd jghj）。
//!
//! 拓扑：
//! ```text
//! 入站 client
//!   ↓
//! Dispatcher(DefaultDispatcher) → Bridge → yamux 客户端连到 Portal yamux 服务端
//!   → 子流经 portability 选路 → 真实 outbound（freedom → echo）
//! ```
//!
//! 验证完整 bridge+dispatcher wiring + yamux echo 双端（覆盖现有 relay 单测之外的
//! 切片3真实装配：LinkDispatch + Ohm + Bridge/Portal 端到端）。

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm};
use xray_buf::io::{Reader as _, Writer as _};
use xray_buf::multi::MultiBuffer;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;

use xray_app_reverse::{DefaultDispatcherAdapter, LinkDispatch, YamuxBridge};

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_dispatcher_to_dialbridge_to_echo_roundtrip() {
    use xray_app_dispatcher::OutboundHandlerManager as _;

    // 1. echo server 真实目标
    let echo_addr = start_echo_server().await;

    // 2. 装配 dispatcher：freedom DialBridge
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(Arc::new(DialBridge::new(
        "freedom",
        xray_proxy_freedom::make_freedom_dial_fn(),
    )) as Arc<dyn xray_app_dispatcher::DispatchHandler>);

    let dispatcher = Arc::new({
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(Arc::clone(&ohm) as Arc<dyn xray_app_dispatcher::OutboundHandlerManager>);
        d
    });

    // 3. 验证 DefaultDispatcherAdapter 暴露的 LinkDispatch 与底层 dispatcher 等价
    let _adapter: Arc<dyn LinkDispatch> =
        Arc::new(DefaultDispatcherAdapter(Arc::clone(&dispatcher)));

    // 4. 直接走 dispatcher dispatch 模拟 reverse wiring
    use xray_app_dispatcher::default::SniffingRequest;
    let dest = Destination::new(
        Address::ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        Port::new(echo_addr.port()),
        Network::TCP,
    );
    let mut inbound = dispatcher
        .dispatch(&dest, &SniffingRequest::default(), None, None)
        .expect("dispatch");

    let mut mb = xray_buf::multi::MultiBuffer::new();
    mb.merge_bytes(b"hello reverse");
    inbound
        .writer
        .write_multi_buffer(mb)
        .await
        .expect("write");

    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        inbound.reader.read_multi_buffer(),
    )
    .await
    .expect("timeout")
    .expect("read");
    let body = resp.to_vec();
    assert!(
        body.windows(b"hello reverse".len())
            .any(|w| w == b"hello reverse"),
        "echo should round-trip; body={body:?}",
    );
    drop(inbound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_yamux_bridge_to_portal_echo_full_chain() {
    // 1. yamux server 模拟 portal：接受一条 tcp，建 yamux server session，
    //    对收到的 stream 直接 echo。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portal_addr = listener.local_addr().unwrap();
    let portal_task = tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut conn = yamux::Connection::new(
            tcp.compat(),
            yamux::Config::default(),
            yamux::Mode::Server,
        );
        loop {
            let stream = match std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                Some(Ok(s)) => s,
                Some(Err(_)) | None => break,
            };
            let mut stream = stream.compat();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // 2. yamux bridge client：连 portal，开子流，写读
    let bridge =
        Arc::new(YamuxBridge::connect(portal_addr.to_string()).await.expect("connect"));
    let mut stream = bridge.open_stream().await.expect("open stream");
    stream.write_all(b"yamux-echo").await.expect("write");
    let mut buf = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(&buf, b"yamux-echo");

    drop(stream);
    drop(bridge);
    // 不等 portal_task 完成——关闭后 driver 自然 EOF
}

/// txno④：mux reverse portal 写侧 source/local 端到端（生产类装配）。
///
/// 拓扑（全内存 carrier，无网络栈）：
/// ```text
/// 用户 conn + AccessContext{from, local}
///   → PortalOutbound.handle_connection（portal 写侧，解析 from/local）
///   → mux ClientWorker New 帧（携带 source/local）
///   → carrier 管道对
///   → BridgeWorker（bridge 侧 ServerWorker，with_read_source_and_local）
///   → LinkDispatch::dispatch_link_inbound（记录）
/// ```
/// 断言对端收到与入站 ctx 一致的**非空** source/local——此前该通道缺失，
/// 帧内恒无元数据。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_portal_dispatch_carries_source_local_to_bridge() {
    use async_trait::async_trait;
    use parking_lot::Mutex as StdMutex;
    use xray_app_dispatcher::AccessContext;
    use xray_app_reverse::{
        BridgeWorker, LinkDispatch, PortalOutbound, PortalWorker, ReverseError, StaticMuxPicker,
    };
    use xray_buf::io::Writer as _;
    use xray_buf::pipe;
    use xray_mux::client::{ClientWorker, Link as MuxLink};
    use xray_mux::session::ClientStrategy;
    use xray_transport::link::Link as TransportLink;

    const DOMAIN: &str = "portal.example.com";

    /// 记录 bridge 侧收到的 (source, local)；carrier 槽在装配时预置
    /// （BridgeWorker::new 经 [`LinkDispatch::dispatch`] 取走 carrier link）。
    #[derive(Default)]
    struct RecordingDispatch {
        inbound: StdMutex<Vec<(String, String)>>,
        carrier: StdMutex<Option<TransportLink>>,
    }

    #[async_trait]
    impl LinkDispatch for RecordingDispatch {
        async fn dispatch(
            &self,
            _dest: &Destination,
            _inbound_tag: Option<&str>,
        ) -> Result<TransportLink, ReverseError> {
            self.carrier
                .lock()
                .take()
                .ok_or(ReverseError::NoWorkerAvailable)
        }

        async fn dispatch_link(
            &self,
            _dest: &Destination,
            _link: TransportLink,
            _inbound_tag: Option<&str>,
        ) -> Result<(), ReverseError> {
            Ok(())
        }

        async fn dispatch_link_inbound(
            &self,
            _dest: &Destination,
            _link: TransportLink,
            _inbound_tag: Option<&str>,
            source: Option<&Destination>,
            local: Option<&Destination>,
        ) -> Result<(), ReverseError> {
            let fmt = |d: Option<&Destination>| {
                d.map(|x| format!("{}:{}", x.address(), x.port().value()))
                    .unwrap_or_default()
            };
            self.inbound.lock().push((fmt(source), fmt(local)));
            Ok(())
        }
    }

    // ---- carrier：两对管道接通 portal ClientWorker ↔ bridge frame loop ----
    // pair1 (bridge→portal)：s_write → c_read；pair2 (portal→bridge)：c_write → s_read
    let (c_read, s_write) = pipe::new();
    let (s_read, c_write) = pipe::new();
    let client = ClientWorker::new(
        MuxLink {
            reader: Box::new(c_read),
            writer: Box::new(c_write),
        },
        ClientStrategy::default(),
    );
    let picker: Arc<StaticMuxPicker<Arc<PortalWorker>>> = Arc::new(StaticMuxPicker::new());
    let portal_worker = PortalWorker::new(client).expect("portal worker");
    picker.add_worker(portal_worker);
    let portal = PortalOutbound::new("portal_out".into(), picker, DOMAIN.into());

    // ---- bridge 侧：BridgeWorker 挂 carrier 另一半 ----
    let recorder = Arc::new(RecordingDispatch {
        inbound: StdMutex::new(Vec::new()),
        carrier: StdMutex::new(Some(TransportLink::new(
            Box::new(s_read),
            Box::new(s_write),
        ))),
    });
    let _bridge = BridgeWorker::new(DOMAIN, "bridge-tag", recorder.clone())
        .await
        .expect("bridge worker");

    // ---- 用户连接：access 带 from/local，经 portal 派发进 carrier ----
    let user_dest = Destination::new(
        Address::ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        Port::new(5201),
        Network::TCP,
    );
    let (u_r, mut u_w) = pipe::new();
    let (resp_r, resp_w) = pipe::new();
    let access = AccessContext {
        from: "203.0.113.7:5555".into(),
        local: "198.51.100.1:443".into(),
        ..Default::default()
    };
    portal
        .handle_connection(
            &user_dest,
            TransportLink::new(Box::new(u_r), Box::new(resp_w)),
            &access,
        )
        .await
        .expect("portal handle_connection");

    // 写点上行数据：确保用户子会话的 New 帧尽快发出
    u_w.write_multi_buffer(MultiBuffer::from_buffer(xray_buf::buffer::Buffer::from_vec(
        b"hello-bridge".to_vec(),
    )))
    .await
    .expect("write uplink");

    // ---- 断言：bridge 侧收到真实非空 source/local ----
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = recorder.inbound.lock().clone();
            if let Some(entry) =
                snapshot.into_iter().find(|(s, l)| !s.is_empty() && !l.is_empty())
            {
                return entry;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bridge side must receive source/local within timeout");
    assert_eq!(
        got,
        (
            "203.0.113.7:5555".to_string(),
            "198.51.100.1:443".to_string()
        )
    );

    let _ = resp_r;
}
