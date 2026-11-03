//! bd s8eio 证据锚：**服务端 accept 计数**（不是客户端日志）。
//!
//! 断言三件事：
//! 1. 默认配置（无 `poolSize`）⇒ 缺省 12 = 开池 ⇒ 后台补拨让服务端 accept 数 **> 1** （省后续会话 1
//!    个握手 RTT）。
//! 2. 显式 `poolSize: 0` ⇒ 关池 ⇒ 一条代理链路 = **1 条**服务端连接（每次 Dial 现拨， 严格对齐 Go
//!    26.10.17 `websocket/dialer.go` 无池）。
//! 3. 显式 `poolSize: 12` ⇒ 池可用（与缺省同效，此条测的是显式配置路径）。
//!
//! 历史：s8eio 曾把缺省改成 0（理由「Go 无池」），本文件当时以「默认配置 ⇒ 1 条」作反证锚；
//! 2026-11-02 复议把缺省恢复 12（缺省 0 关池实测 TTFB 慢 33%），该断言随之改为测
//! 显式 `poolSize: 0`，新的「默认 ⇒ 开池」断言见测试 1。

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::tungstenite::Message;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{
    dialer::{StreamSettings, dial_with_settings},
    sockopt::SocketOptions,
};
use xray_transport_websocket::register_dialer;

/// 计数型 ws echo server：每条 TCP accept 计数 +1（= 服务端可见连接数）。
async fn spawn_counting_ws_echo() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr of bound listener").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    #[allow(clippy::disallowed_methods, reason = "测试：计数型 echo server accept 循环")]
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            #[allow(clippy::disallowed_methods, reason = "测试：单连接 ws echo 任务")]
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Binary(b) => {
                            let b: Vec<u8> = b.into();
                            if ws.send(Message::binary(b)).await.is_err() {
                                break;
                            }
                        },
                        Message::Close(_) => break,
                        _ => {},
                    }
                }
            });
        }
    });
    (port, accepts)
}

/// 拨一条链路、echo 一轮、关连接，再留一个补拨窗口（开池时 burst 在此期间跑到服务端）。
async fn run_one_session(port: u16, settings: &StreamSettings) {
    let dest = Destination::new(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(port), Network::TCP);
    let mut conn = tokio::time::timeout(
        Duration::from_secs(5),
        dial_with_settings("ws", &dest, &SocketOptions::default(), settings),
    )
    .await
    .expect("dial should not time out")
    .expect("dial should succeed");

    conn.write_all(b"ping").await.expect("write ping");
    conn.flush().await.expect("flush ping");
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("echo should not time out")
        .expect("echo should be readable");
    assert_eq!(&buf, b"ping");
    drop(conn);
    tokio::time::sleep(Duration::from_millis(700)).await;
}

/// 默认配置（无 `poolSize`）⇒ 缺省 12 = 开池 ⇒ 后台补拨让服务端 accept 数 > 1。
#[tokio::test]
async fn default_config_preconnects() {
    register_dialer().unwrap();
    let (port, accepts) = spawn_counting_ws_echo().await;
    let settings = StreamSettings { protocol: "ws".into(), ..StreamSettings::tcp() };

    run_one_session(port, &settings).await;

    let seen = accepts.load(Ordering::SeqCst);
    assert!(
        seen > 1,
        "默认配置（缺省 poolSize=12）必须开池：后台补拨让服务端 accept > 1，实际 {seen}"
    );
}

/// 显式 `poolSize: 0` ⇒ 关池 ⇒ 服务端只见 1 条连接（对齐 Go 26.10.17 ws 无池）。
#[tokio::test]
async fn explicit_pool_size_zero_opens_exactly_one_server_connection() {
    register_dialer().unwrap();
    let (port, accepts) = spawn_counting_ws_echo().await;
    let settings = StreamSettings {
        protocol: "ws".into(),
        transport_json: Some(serde_json::json!({"path": "/ws", "poolSize": 0})),
        ..StreamSettings::tcp()
    };

    run_one_session(port, &settings).await;

    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "显式 poolSize=0 必须关池：只开 1 条服务端连接；多出即池未被关"
    );
}

/// 显式 `poolSize>0` ⇒ 池仍可用：后台补拨让服务端 accept 数 > 1。
#[tokio::test]
async fn explicit_pool_size_still_preconnects() {
    register_dialer().unwrap();
    let (port, accepts) = spawn_counting_ws_echo().await;
    let settings = StreamSettings {
        protocol: "ws".into(),
        transport_json: Some(serde_json::json!({"path": "/ws", "poolSize": 12})),
        ..StreamSettings::tcp()
    };

    run_one_session(port, &settings).await;

    let seen = accepts.load(Ordering::SeqCst);
    assert!(seen > 1, "显式 poolSize=12 必须触发后台补拨（服务端 accept > 1），实际 {seen}");
}
