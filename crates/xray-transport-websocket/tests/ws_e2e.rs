//! WebSocket 传输层端到端测试。
//!
//! 测试矩阵：
//! 1. **client ↔ server roundtrip**：客户端拨号 → 服务端 accept → 双向 echo
//! 2. **early data (0-RTT)**：客户端发 ed → 服务端 first-read 拿到 ed 字节
//! 3. **大数据多帧**：客户端发 100 KiB → 服务端 echo 完整返回
//! 4. **path 校验**：客户端拨错 path → 服务端拒绝（握手失败）
//! 5. **custom host header**：客户端发自定义 Host → 服务端接受
//!
//! 全部走明文 `ws://`（TLS 包装留集成测试 follow-up）。
//! 测试用 `tokio::io::{AsyncReadExt, AsyncWriteExt}` 直接读写 `WsConnection`，
//! 验证 `Connection` trait + `AsyncRead/AsyncWrite` supertrait 链路。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;

use xray_transport_websocket::client::{dial, DialOptions};
use xray_transport_websocket::config::Config;
use xray_transport_websocket::server::WsListener;

use xray_transport::connection::Connection;
use xray_transport_websocket::client::{DialFactory, DelayDialConn};

/// 拨号到本地 listener 的辅助：用 IP 127.0.0.1 + 端口。
fn local_dest(port: u16) -> Destination {
    Destination::new(
        Address::new_domain("127.0.0.1"),
        Port::new(port),
        Network::TCP,
    )
}

/// 起一个 echo 服务端：accept 后把读到的字节原样写回，循环直到客户端断开。
async fn spawn_echo_server(
    addr: std::net::SocketAddr,
    config: Arc<Config>,
) -> (
    oneshot::Receiver<std::net::SocketAddr>, // 实际 bound 地址
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let listener = WsListener::bind(addr, config).await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let _ = tx.send(bound);
        // 仅接受一条连接（测试场景），多连接测试单独 spawn。
        let accepted = listener.accept().await.expect("accept");
        let mut conn = accepted.conn;
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (rx, handle)
}

#[tokio::test]
async fn client_server_roundtrip_echo() {
    let cfg = Arc::new(Config::default());
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr_rx, server_handle) = spawn_echo_server(bind_addr, cfg.clone()).await;
    let bound = addr_rx.await.expect("server bound");

    let dest = local_dest(bound.port());
    let opts = DialOptions { config: &cfg,
    destination: &dest,
    early_data: None,
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let mut client = dial(opts).await.expect("dial");

    // 发 hello → 收 hello 回来
    client.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"hello");

    // 关闭：drop client → 服务端 read 返 0 → 退出
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn large_payload_multi_frame_roundtrip() {
    // 100 KiB 触发多帧（单帧上限通常 ≤ 16 KiB）。
    let cfg = Arc::new(Config::default());
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr_rx, server_handle) = spawn_echo_server(bind_addr, cfg.clone()).await;
    let bound = addr_rx.await.expect("server bound");

    let dest = local_dest(bound.port());
    let opts = DialOptions { config: &cfg,
    destination: &dest,
    early_data: None,
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let mut client = dial(opts).await.expect("dial");

    // 构造 100 KiB 已知模式数据。
    let payload: Vec<u8> = (0..100 * 1024).map(|i| (i & 0xFF) as u8).collect();
    client.write_all(&payload).await.expect("write all");

    // 收回完整 echo。
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).await.expect("read back");
    assert_eq!(got, payload);

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn early_data_delivered_to_server_first_read() {
    // 客户端在握手时发 ed=255 字节 → 服务端 accept 返回的 conn 首次 read 应拿到这些字节。
    let cfg = Arc::new(Config::default());
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 服务端：accept 后直接读，验证首批字节是 early data。
    let (tx_bound, rx_bound) = oneshot::channel();
    let server_cfg = cfg.clone();
    let server_handle = tokio::spawn(async move {
        let listener = WsListener::bind(bind_addr, server_cfg).await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let _ = tx_bound.send(bound);
        let mut accepted = listener.accept().await.expect("accept");
        // early data 应已注入到 read_buf，首次 read 即可拿到。
        assert!(!accepted.early_data.is_empty(), "early data should be present");
        let mut buf = [0u8; 64];
        let n = accepted.conn.read(&mut buf).await.expect("read early");
        assert_eq!(&buf[..n], b"early-payload");
    });

    let bound = rx_bound.await.expect("server bound");
    let dest = local_dest(bound.port());
    let ed = b"early-payload".to_vec();
    let opts = DialOptions { config: &cfg,
    destination: &dest,
    early_data: Some(&ed),
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let _client = dial(opts).await.expect("dial");

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}

#[tokio::test]
async fn server_rejects_wrong_path() {
    // 服务端期望 path=/ws，客户端拨 /wrong → 服务端拒绝握手，accept 返回 Err。
    let server_cfg = Arc::new(Config {
        path: "/ws".into(),
        ..Default::default()
    });
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (tx_bound, rx_bound) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        let listener = WsListener::bind(bind_addr, server_cfg).await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let _ = tx_bound.send(bound);
        // 错误 path 应导致 accept 返回 Err。
        let result = listener.accept().await;
        assert!(
            result.is_err(),
            "expected accept to fail on wrong path"
        );
    });

    let bound = rx_bound.await.expect("server bound");
    let dest = local_dest(bound.port());
    // 客户端用错误 path。
    let client_cfg = Config {
        path: "/wrong".into(),
        ..Default::default()
    };
    let opts = DialOptions { config: &client_cfg,
    destination: &dest,
    early_data: None,
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let result = dial(opts).await;
    assert!(result.is_err(), "client dial should fail with 404");

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}

#[tokio::test]
async fn server_validates_custom_host_header() {
    // 服务端期望 host=front.example.com，客户端发该 host → 接受。
    // 同时校验：地址用 127.0.0.1，但 host 是 CDN 域名（典型反向代理场景）。
    let server_cfg = Arc::new(Config {
        host: "front.example.com".into(),
        ..Default::default()
    });
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (tx_bound, rx_bound) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        let listener = WsListener::bind(bind_addr, server_cfg).await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let _ = tx_bound.send(bound);
        let accepted = listener.accept().await.expect("accept");
        let mut conn = accepted.conn;
        // 简单 roundtrip 证明握手成功。
        let mut buf = [0u8; 5];
        let _ = conn.read_exact(&mut buf).await;
        let _ = conn.write_all(&buf).await;
    });

    let bound = rx_bound.await.expect("server bound");
    let dest = local_dest(bound.port());
    let client_cfg = Config {
        host: "front.example.com".into(),
        ..Default::default()
    };
    let opts = DialOptions { config: &client_cfg,
    destination: &dest,
    early_data: None,
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let mut client = dial(opts).await.expect("dial should succeed with matching host");

    client.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"hello");

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn server_rejects_mismatched_host() {
    // 服务端期望 host=expected.com，客户端发不同 host → 服务端拒绝。
    let server_cfg = Arc::new(Config {
        host: "expected.com".into(),
        ..Default::default()
    });
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (tx_bound, rx_bound) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        let listener = WsListener::bind(bind_addr, server_cfg).await.expect("bind");
        let bound = listener.local_addr().expect("local_addr");
        let _ = tx_bound.send(bound);
        let _ = listener.accept().await; // 预期 Err
    });

    let bound = rx_bound.await.expect("server bound");
    let dest = local_dest(bound.port());
    let client_cfg = Config {
        host: "wrong.com".into(),
        ..Default::default()
    };
    let opts = DialOptions { config: &client_cfg,
    destination: &dest,
    early_data: None,
    tls_config: None,
    fingerprint: None, tls_server_name: None };
    let result = dial(opts).await;
    assert!(result.is_err(), "mismatched host should be rejected");

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}

/// delayDial 0-RTT 端到端：Ed>0 时拨号推迟到首次 Write，首包 ≤ Ed 以
/// early data 进握手头（Sec-WebSocket-Protocol），服务端 first-read 即得。
/// 对应 Go dialer.go:20-34（Dial 分支）+ 168-221（delayDialConn）。
#[tokio::test]
async fn delay_dial_early_data_zero_rtt_roundtrip() {
    let cfg = Arc::new(Config::default());
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr_rx, server_handle) = spawn_echo_server(bind_addr, cfg.clone()).await;
    let bound = addr_rx.await.expect("server bound");
    let dest = local_dest(bound.port());

    // delayDialConn 的拨号工厂：真实 WS 拨号，early data 走握手头。
    let port = dest.port().value();
    let factory: DialFactory = Arc::new(move |ed| {
        Box::pin(async move {
            let cfg = Config::default();
            let dest = local_dest(port);
            let conn = dial(DialOptions {
                config: &cfg,
                destination: &dest,
                early_data: ed.as_deref(),
                tls_config: None,
                tls_server_name: None,
                fingerprint: None,
            })
            .await
            .map_err(std::io::Error::other)?;
            Ok(Box::new(conn) as Box<dyn Connection>)
        })
    });

    let mut client = DelayDialConn::new(2048, factory);
    // 首写 ≤ Ed=2048：整包进握手头（0-RTT），echo 服务端 first-read 即得并回写。
    client.write_all(b"early-payload").await.expect("write");
    let mut buf = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .expect("read echo");
    assert_eq!(&buf, b"early-payload");

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}
